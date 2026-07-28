//! Store-owned child-agent turn, recovery, terminal, and overlap APIs.

use super::{
    CHILD_MODEL_EVIDENCE_MEDIA_TYPE, CHILD_MODEL_UNKNOWN_MEDIA_TYPE,
    CHILD_REPOSITORY_EXPLORER_OBSERVATION_PRODUCER, CHILD_REPOSITORY_EXPLORER_PREPARATION_PRODUCER,
    CHILD_REPOSITORY_EXPLORER_UNKNOWN_PRODUCER, ChildAttemptId, ChildExecutionId,
    ChildExecutionOverlap, ChildPendingEffectProjection, ChildRecoveryState,
    ChildRepositoryExplorerObservationAuthority, ChildRepositoryExplorerPreparationAuthority,
    ChildRepositoryExplorerPreparationOutcome, ChildRepositoryExplorerPreparedMaterial,
    ChildRepositoryExplorerTerminalOutcome, ChildRepositoryExplorerUnknownAuthority,
    ChildWorkOrderId, ChildWorkOrderProjection, EventId, EventPayload, IdempotentAppendOutcome,
    IdentifiedNewEvent, MAX_SQLITE_INTEGER_U64, NewEvent, Provenance, RunId, Store, StoreError,
    append_outcome_event, build_child_repository_explorer_prepared_event,
    child_model_observed_payload, child_model_terminal_context, child_model_unknown_payload,
    child_repository_explorer_committed_material,
    child_repository_explorer_current_prepared_material, derive_child_model_evidence_record,
    derive_child_model_unknown_record, derive_child_overlap, load_event_by_id,
    project_child_work_order, put_json_artifact,
    validate_existing_child_repository_explorer_observation,
    validate_existing_child_repository_explorer_unknown, work_order_for_execution,
};

impl Store {
    /// Replays the bounded typed history for one child work order.
    ///
    /// The returned state is derived solely from authoritative events. Any
    /// duplicate identity, invalid transition, broken causal edge, or static
    /// binding mismatch fails closed instead of producing a partial view.
    ///
    /// # Errors
    ///
    /// Returns an error when history, artifact integrity, or an identity or
    /// transition binding is invalid.
    pub fn child_work_order_projection(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
    ) -> Result<Option<ChildWorkOrderProjection>, StoreError> {
        project_child_work_order(&self.connection, &self.artifact_root, run_id, work_order_id)
    }

    /// Derives the complete repository-explorer turn from authoritative child
    /// history, persists the compiled prompt/request/manifest, and commits the
    /// Prepared-v2 event before returning material that may reach a backend.
    ///
    /// The caller supplies only fresh lifecycle identities, a bounded token
    /// reservation, and the runtime clock reading. Work order, context,
    /// cumulative tool transcript, supplied-once results, model selection,
    /// causal parent, actor, and provenance cannot be overridden.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale child boundary, reused identities, invalid
    /// reservation or clock authority, exhausted budget, artifact drift, or a
    /// child history that does not replay exactly.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh runtime authority"
    )]
    pub fn prepare_child_repository_explorer_turn(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: ChildRepositoryExplorerPreparationAuthority,
    ) -> Result<ChildRepositoryExplorerPreparationOutcome, StoreError> {
        if let Some(existing) = load_event_by_id(&self.connection, authority.event_id)? {
            let EventPayload::ChildModelInferencePreparedV2(prepared_v2) = &existing.payload else {
                return Err(StoreError::IdentifiedEventConflict);
            };
            if existing.run_id != Some(run_id)
                || prepared_v2.prepared.binding.work_order_id != work_order_id
                || prepared_v2.prepared.model_call_id != authority.model_call_id
                || prepared_v2.prepared.token_reservation != authority.token_reservation
                || prepared_v2.prepared.prepared_at != authority.prepared_at
                || existing.provenance.producer != CHILD_REPOSITORY_EXPLORER_PREPARATION_PRODUCER
            {
                return Err(StoreError::IdentifiedEventConflict);
            }
            let material = child_repository_explorer_current_prepared_material(
                &self.connection,
                &self.artifact_root,
                existing.clone(),
            )?;
            return Ok(ChildRepositoryExplorerPreparationOutcome {
                append: IdempotentAppendOutcome::AlreadyPresent { event: existing },
                material,
            });
        }

        let identified = build_child_repository_explorer_prepared_event(
            self,
            run_id,
            work_order_id,
            &authority,
        )?;
        let append = self.append_identified_event(identified)?;
        let prepared_event = match &append {
            IdempotentAppendOutcome::Appended { event }
            | IdempotentAppendOutcome::AlreadyPresent { event } => event.clone(),
        };
        let material = child_repository_explorer_current_prepared_material(
            &self.connection,
            &self.artifact_root,
            prepared_event,
        )?;
        Ok(ChildRepositoryExplorerPreparationOutcome { append, material })
    }

    /// Recovers the exact committed repository-explorer request only while it
    /// is the current pre-effect Prepared-v2 boundary for this child.
    ///
    /// This recovery material is evidence for reconciliation, not dispatch
    /// authority. A runtime that did not itself receive the freshly appended
    /// [`ChildRepositoryExplorerPreparationOutcome`] must close this boundary
    /// through [`Self::reconcile_child_repository_explorer_turn_unknown`] and
    /// must never send the recovered backend request again.
    ///
    /// # Errors
    ///
    /// Returns an error for contradictory child replay, retained artifact
    /// drift, or a Prepared event that no longer recompiles exactly.
    pub fn recover_child_repository_explorer_turn(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
    ) -> Result<Option<ChildRepositoryExplorerPreparedMaterial>, StoreError> {
        let Some(projection) = self.child_work_order_projection(run_id, work_order_id)? else {
            return Ok(None);
        };
        let ChildRecoveryState::PendingEffect(ChildPendingEffectProjection::Model {
            prepared_event,
        }) = projection.recovery
        else {
            return Ok(None);
        };
        if !matches!(
            prepared_event.payload,
            EventPayload::ChildModelInferencePreparedV2(_)
        ) {
            return Ok(None);
        }
        child_repository_explorer_current_prepared_material(
            &self.connection,
            &self.artifact_root,
            prepared_event,
        )
        .map(Some)
    }

    /// Reconstructs one exact committed Prepared-v2 turn, including after its
    /// effect has reached an Observed or Unknown terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if the identity names a different run/work order or
    /// if its pre-event replay and retained request no longer attest exactly.
    pub fn child_repository_explorer_turn_material(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        prepared_event_id: EventId,
    ) -> Result<Option<ChildRepositoryExplorerPreparedMaterial>, StoreError> {
        let Some(event) = load_event_by_id(&self.connection, prepared_event_id)? else {
            return Ok(None);
        };
        if event.run_id != Some(run_id)
            || !matches!(
                &event.payload,
                EventPayload::ChildModelInferencePreparedV2(prepared)
                    if prepared.prepared.binding.work_order_id == work_order_id
            )
        {
            return Err(StoreError::InvalidStateEvent);
        }
        child_repository_explorer_committed_material(&self.connection, &self.artifact_root, event)
            .map(Some)
    }

    /// Retains one exact adapter result and closes the current child
    /// repository-explorer Prepared-v2 boundary as Observed.
    ///
    /// Store re-derives the work-order binding, exact backend instance,
    /// provenance, semantic response, and durable failure projection. A
    /// response that substitutes transport/model identity or violates the
    /// structured child contract is retained exactly and becomes a typed
    /// non-retryable failure; callers cannot label it as success.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or mismatched Prepared boundary, invalid
    /// clock/cancellation authority, artifact failure, or contradictory
    /// idempotent replay.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh terminal authority"
    )]
    pub fn observe_child_repository_explorer_turn(
        &mut self,
        run_id: RunId,
        authority: ChildRepositoryExplorerObservationAuthority,
    ) -> Result<ChildRepositoryExplorerTerminalOutcome, StoreError> {
        if let Some(existing) = load_event_by_id(&self.connection, authority.event_id)? {
            validate_existing_child_repository_explorer_observation(
                &self.connection,
                &self.artifact_root,
                run_id,
                &authority,
                &existing,
            )?;
            return Ok(ChildRepositoryExplorerTerminalOutcome {
                append: IdempotentAppendOutcome::AlreadyPresent {
                    event: existing.clone(),
                },
                event: existing,
            });
        }

        let context = child_model_terminal_context(
            &self.connection,
            &self.artifact_root,
            run_id,
            authority.prepared_event_id,
            true,
        )?;
        let record = derive_child_model_evidence_record(
            &self.connection,
            &context,
            &authority.evidence,
            &authority.finished_at,
            MAX_SQLITE_INTEGER_U64,
        )?;
        let evidence_artifact = put_json_artifact(self, &record, CHILD_MODEL_EVIDENCE_MEDIA_TYPE)?;
        let payload = child_model_observed_payload(&context, &record, evidence_artifact.clone())?;
        let append = self.append_identified_event(IdentifiedNewEvent {
            event_id: authority.event_id,
            event: NewEvent {
                session_id: context.prepared_event.session_id,
                run_id: Some(run_id),
                actor_id: context.spec.child_event_actor_id,
                causal_parent: Some(context.current_tail_event_id),
                provenance: Provenance {
                    producer: CHILD_REPOSITORY_EXPLORER_OBSERVATION_PRODUCER.to_owned(),
                    backend: Some(context.spec.backend.clone()),
                    raw_artifact: Some(evidence_artifact),
                },
                payload: EventPayload::ChildModelInferenceObserved(payload),
            },
        })?;
        let event = append_outcome_event(&append).clone();
        Ok(ChildRepositoryExplorerTerminalOutcome { append, event })
    }

    /// Closes the current child repository-explorer Prepared-v2 boundary when
    /// its external outcome is mechanically unknowable. Store maps the typed
    /// boundary to the durable reason/retry disposition and derives any exact
    /// cancellation cause from authoritative history.
    ///
    /// This is the only valid next step for a Prepared boundary discovered by
    /// recovery; recovered backend material must never be redispatched.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale Prepared identity, inapplicable boundary,
    /// invalid clock/cancellation history, artifact failure, or contradictory
    /// idempotent replay.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh terminal authority"
    )]
    pub fn reconcile_child_repository_explorer_turn_unknown(
        &mut self,
        run_id: RunId,
        authority: ChildRepositoryExplorerUnknownAuthority,
    ) -> Result<ChildRepositoryExplorerTerminalOutcome, StoreError> {
        if let Some(existing) = load_event_by_id(&self.connection, authority.event_id)? {
            validate_existing_child_repository_explorer_unknown(
                &self.connection,
                &self.artifact_root,
                run_id,
                &authority,
                &existing,
            )?;
            return Ok(ChildRepositoryExplorerTerminalOutcome {
                append: IdempotentAppendOutcome::AlreadyPresent {
                    event: existing.clone(),
                },
                event: existing,
            });
        }

        let context = child_model_terminal_context(
            &self.connection,
            &self.artifact_root,
            run_id,
            authority.prepared_event_id,
            true,
        )?;
        let record = derive_child_model_unknown_record(
            &self.connection,
            &context,
            authority.boundary,
            &authority.boundary_at,
            MAX_SQLITE_INTEGER_U64,
        )?;
        let boundary_artifact = put_json_artifact(self, &record, CHILD_MODEL_UNKNOWN_MEDIA_TYPE)?;
        let payload = child_model_unknown_payload(&context, &record, boundary_artifact.clone())?;
        let append = self.append_identified_event(IdentifiedNewEvent {
            event_id: authority.event_id,
            event: NewEvent {
                session_id: context.prepared_event.session_id,
                run_id: Some(run_id),
                actor_id: context.spec.child_event_actor_id,
                causal_parent: Some(context.current_tail_event_id),
                provenance: Provenance {
                    producer: CHILD_REPOSITORY_EXPLORER_UNKNOWN_PRODUCER.to_owned(),
                    backend: Some(context.spec.backend.clone()),
                    raw_artifact: Some(boundary_artifact),
                },
                payload: EventPayload::ChildModelInferenceOutcomeUnknown(payload),
            },
        })?;
        let event = append_outcome_event(&append).clone();
        Ok(ChildRepositoryExplorerTerminalOutcome { append, event })
    }

    /// Derives whether two child attempts overlapped on one comparable
    /// runtime-local monotonic clock.
    ///
    /// Different runtime instances and nonterminal attempts produce typed
    /// `Unknown` evidence. UTC wall time is retained for reproduction but is
    /// never used as a fallback concurrency proof.
    ///
    /// # Errors
    ///
    /// Returns an error when either execution or attempt is unknown, duplicated,
    /// or has a history that fails deterministic replay.
    pub fn child_execution_overlap(
        &self,
        run_id: RunId,
        left_execution_id: ChildExecutionId,
        left_attempt_id: ChildAttemptId,
        right_execution_id: ChildExecutionId,
        right_attempt_id: ChildAttemptId,
    ) -> Result<ChildExecutionOverlap, StoreError> {
        let left_work_order =
            work_order_for_execution(&self.connection, run_id, left_execution_id)?;
        let right_work_order =
            work_order_for_execution(&self.connection, run_id, right_execution_id)?;
        let left = project_child_work_order(
            &self.connection,
            &self.artifact_root,
            run_id,
            left_work_order,
        )?
        .ok_or(StoreError::InvalidStateEvent)?;
        let right = project_child_work_order(
            &self.connection,
            &self.artifact_root,
            run_id,
            right_work_order,
        )?
        .ok_or(StoreError::InvalidStateEvent)?;
        derive_child_overlap(
            &left,
            left_execution_id,
            left_attempt_id,
            &right,
            right_execution_id,
            right_attempt_id,
        )
    }
}
