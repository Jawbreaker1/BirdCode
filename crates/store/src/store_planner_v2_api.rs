//! Store-owned planner-v2 preparation, recovery, terminal, and finalization APIs.

use super::{
    CANCELLATION_BOUNDARY_MEDIA_TYPE, EventId, EventPayload, INFERENCE_EVIDENCE_MEDIA_TYPE,
    IdempotentAppendOutcome, IdentifiedNewEvent, NewEvent, PLANNER_V2_OBSERVATION_PRODUCER,
    PLANNER_V2_UNKNOWN_PRODUCER, PlannerNextAction, PlannerTurnRecoveryState,
    PlannerV2FinalizationAuthority, PlannerV2FinalizationOutcome, PlannerV2ObservationAuthority,
    PlannerV2PreparationAuthority, PlannerV2PreparationOutcome, PlannerV2PreparedMaterial,
    PlannerV2TerminalOutcome, PlannerV2UnknownAuthority, Provenance,
    RetainedCancellationBoundaryEvidence, RunId, Store, StoreError, append_outcome_event,
    build_planner_v2_decision_event, build_planner_v2_prepared_event,
    build_planner_v2_run_terminal_event, expected_backend_selection, load_event_by_id,
    planner_v2_cancellation_cause, planner_v2_committed_material,
    planner_v2_current_prepared_material, planner_v2_observation_from_evidence,
    planner_v2_unknown_reason, put_json_artifact, retained_planner_v2_evidence,
    validate_existing_planner_v2_finalization, validate_existing_planner_v2_observation,
    validate_existing_planner_v2_unknown,
};

impl Store {
    /// Builds semantic planner material from durable history, persists every
    /// exact request artifact, and commits Prepared before returning anything
    /// that may be sent to a model backend.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, missing new evidence, invalid
    /// caller-owned identities or budgets, artifact failure, or replay drift.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh planner authority"
    )]
    pub fn prepare_planner_v2_turn(
        &mut self,
        run_id: RunId,
        authority: PlannerV2PreparationAuthority,
    ) -> Result<PlannerV2PreparationOutcome, StoreError> {
        let identified = build_planner_v2_prepared_event(self, run_id, &authority)?;
        self.commit_prebuilt_planner_v2_turn(identified)
    }

    /// Low-level verified seam for importing an already-materialized Prepared
    /// event. Live daemon code should use [`Self::prepare_planner_v2_turn`].
    ///
    /// # Errors
    ///
    /// Returns an error unless every retained artifact and authority binding
    /// is exact and the event is still the current pre-effect boundary.
    pub fn commit_prebuilt_planner_v2_turn(
        &mut self,
        identified: IdentifiedNewEvent,
    ) -> Result<PlannerV2PreparationOutcome, StoreError> {
        if !matches!(
            &identified.event.payload,
            EventPayload::PlannerTurnPreparedV1(_)
        ) {
            return Err(StoreError::InvalidStateEvent);
        }
        let event_id = identified.event_id;
        let append = self.append_identified_event(identified)?;
        let prepared_event =
            load_event_by_id(&self.connection, event_id)?.ok_or(StoreError::InvalidStateEvent)?;
        let material = planner_v2_current_prepared_material(
            &self.connection,
            &self.artifact_root,
            prepared_event,
        )?;
        Ok(PlannerV2PreparationOutcome { append, material })
    }

    /// Recovers the exact committed request only while the latest planner turn
    /// is still at its pre-effect Prepared boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for contradictory replay or request/artifact drift.
    pub fn recover_planner_v2_turn(
        &self,
        run_id: RunId,
    ) -> Result<Option<PlannerV2PreparedMaterial>, StoreError> {
        let Some(projection) = self.recon_run_projection(run_id)? else {
            return Ok(None);
        };
        let PlannerTurnRecoveryState::Prepared { prepared_event } = projection.planner.recovery
        else {
            return Ok(None);
        };
        planner_v2_current_prepared_material(&self.connection, &self.artifact_root, prepared_event)
            .map(Some)
    }

    /// Reconstructs the exact authoritative material for any committed turn
    /// in the bounded planner-v2 history, including the Observed-to-decision
    /// recovery boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the turn is absent, duplicated, or its retained
    /// material no longer attests against the shared builder.
    pub fn planner_v2_turn_material(
        &self,
        run_id: RunId,
        prepared_event_id: EventId,
    ) -> Result<Option<PlannerV2PreparedMaterial>, StoreError> {
        let Some(projection) = self.recon_run_projection(run_id)? else {
            return Ok(None);
        };
        if projection.run_id != run_id {
            return Err(StoreError::InvalidStateEvent);
        }
        let event = load_event_by_id(&self.connection, prepared_event_id)?;
        let Some(event) = event else {
            return Ok(None);
        };
        if event.run_id != Some(run_id)
            || !matches!(event.payload, EventPayload::PlannerTurnPreparedV1(_))
        {
            return Err(StoreError::InvalidStateEvent);
        }
        planner_v2_committed_material(&self.artifact_root, event).map(Some)
    }

    /// Retains one exact adapter result and closes the named Prepared-v2
    /// boundary as Observed. The semantic outcome is derived by Store from
    /// the retained typed response/error and the committed backend identity.
    ///
    /// A committed terminal is never redispatched. Retrying the same event
    /// identity is idempotent only when every authority field and retained
    /// evidence byte is exact.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or mismatched Prepared boundary, invalid
    /// retained evidence, artifact failure, or contradictory durable replay.
    pub fn observe_planner_v2_turn(
        &mut self,
        run_id: RunId,
        authority: PlannerV2ObservationAuthority,
    ) -> Result<PlannerV2TerminalOutcome, StoreError> {
        let retained = retained_planner_v2_evidence(&authority.evidence);
        if let Some(existing) = load_event_by_id(&self.connection, authority.event_id)? {
            validate_existing_planner_v2_observation(
                &self.connection,
                &self.artifact_root,
                run_id,
                &authority,
                &retained,
                &existing,
            )?;
            return Ok(PlannerV2TerminalOutcome {
                append: IdempotentAppendOutcome::AlreadyPresent {
                    event: existing.clone(),
                },
                event: existing,
            });
        }

        let projection = self
            .recon_run_projection(run_id)?
            .ok_or(StoreError::InvalidStateEvent)?;
        let PlannerTurnRecoveryState::Prepared { prepared_event } = projection.planner.recovery
        else {
            return Err(StoreError::InvalidStateEvent);
        };
        if prepared_event.id != authority.prepared_event_id {
            return Err(StoreError::InvalidStateEvent);
        }
        let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        let outcome = planner_v2_observation_from_evidence(prepared, &retained)?;
        let evidence_artifact = put_json_artifact(self, &retained, INFERENCE_EVIDENCE_MEDIA_TYPE)?;
        let run = self.get_run(run_id)?.ok_or(StoreError::InvalidStateEvent)?;
        let backend = expected_backend_selection(&run, &prepared.backend_model);
        let actor_id = projection
            .guard
            .latest_claim
            .as_ref()
            .map(|claim| claim.event.actor_id)
            .ok_or(StoreError::InvalidStateEvent)?;
        let append = self.append_identified_event(IdentifiedNewEvent {
            event_id: authority.event_id,
            event: NewEvent {
                session_id: projection.session_id,
                run_id: Some(run_id),
                actor_id,
                causal_parent: Some(prepared_event.id),
                provenance: Provenance {
                    producer: PLANNER_V2_OBSERVATION_PRODUCER.to_owned(),
                    backend: Some(backend),
                    raw_artifact: Some(evidence_artifact.clone()),
                },
                payload: EventPayload::PlannerTurnObservedV1(
                    birdcode_protocol::PlannerTurnObservedV1 {
                        turn_id: prepared.turn_id,
                        prepared_event_id: prepared_event.id,
                        normalized_complete_evidence_artifact: evidence_artifact,
                        outcome,
                        observed_at: authority.observed_at,
                    },
                ),
            },
        })?;
        let event = append_outcome_event(&append).clone();
        Ok(PlannerV2TerminalOutcome { append, event })
    }

    /// Closes a Prepared-v2 boundary whose external effect can no longer be
    /// established. Store maps the typed runtime boundary to the durable
    /// coarse reason and derives cancellation authority from run history.
    ///
    /// # Errors
    ///
    /// Returns an error for an inapplicable boundary, stale Prepared identity,
    /// invalid runtime clock, artifact failure, or contradictory replay.
    pub fn reconcile_planner_v2_turn_unknown(
        &mut self,
        run_id: RunId,
        authority: PlannerV2UnknownAuthority,
    ) -> Result<PlannerV2TerminalOutcome, StoreError> {
        if let Some(existing) = load_event_by_id(&self.connection, authority.event_id)? {
            validate_existing_planner_v2_unknown(
                &self.connection,
                &self.artifact_root,
                run_id,
                &authority,
                &existing,
            )?;
            return Ok(PlannerV2TerminalOutcome {
                append: IdempotentAppendOutcome::AlreadyPresent {
                    event: existing.clone(),
                },
                event: existing,
            });
        }

        let projection = self
            .recon_run_projection(run_id)?
            .ok_or(StoreError::InvalidStateEvent)?;
        let PlannerTurnRecoveryState::Prepared { prepared_event } = projection.planner.recovery
        else {
            return Err(StoreError::InvalidStateEvent);
        };
        if prepared_event.id != authority.prepared_event_id {
            return Err(StoreError::InvalidStateEvent);
        }
        let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        let cancellation = planner_v2_cancellation_cause(
            &self.connection,
            projection.session_id,
            run_id,
            authority.boundary,
        )?;
        let cancellation_generation = cancellation
            .as_ref()
            .map_or(prepared.cancellation_generation, |cause| {
                cause.cancellation_generation
            });
        let retained = RetainedCancellationBoundaryEvidence {
            reason: authority.boundary,
            prepared_event_id: prepared_event.id,
            cancellation_generation,
        };
        let artifact = put_json_artifact(self, &retained, CANCELLATION_BOUNDARY_MEDIA_TYPE)?;
        let run = self.get_run(run_id)?.ok_or(StoreError::InvalidStateEvent)?;
        let backend = expected_backend_selection(&run, &prepared.backend_model);
        let actor_id = projection
            .guard
            .latest_claim
            .as_ref()
            .map(|claim| claim.event.actor_id)
            .ok_or(StoreError::InvalidStateEvent)?;
        let append = self.append_identified_event(IdentifiedNewEvent {
            event_id: authority.event_id,
            event: NewEvent {
                session_id: projection.session_id,
                run_id: Some(run_id),
                actor_id,
                causal_parent: Some(prepared_event.id),
                provenance: Provenance {
                    producer: PLANNER_V2_UNKNOWN_PRODUCER.to_owned(),
                    backend: Some(backend),
                    raw_artifact: Some(artifact.clone()),
                },
                payload: EventPayload::PlannerTurnUnknownV1(
                    birdcode_protocol::PlannerTurnUnknownV1 {
                        turn_id: prepared.turn_id,
                        prepared_event_id: prepared_event.id,
                        boundary_evidence_artifact: artifact,
                        reason: planner_v2_unknown_reason(authority.boundary),
                        boundary: authority.boundary,
                        cancellation,
                        boundary_at: authority.boundary_at,
                    },
                ),
            },
        })?;
        let event = append_outcome_event(&append).clone();
        Ok(PlannerV2TerminalOutcome { append, event })
    }

    /// Deterministically finalizes the latest Observed/Unknown planner-v2
    /// turn from retained evidence only. Successful observations become an
    /// Accepted or typed Rejected decision; failed/unknown observations end
    /// the run, with a durable cancellation taking precedence.
    ///
    /// # Errors
    ///
    /// Returns an error unless the named terminal is the current durable
    /// planner boundary and its retained evidence finalizes exactly.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh finalization authority"
    )]
    pub fn finalize_planner_v2_turn(
        &mut self,
        run_id: RunId,
        authority: PlannerV2FinalizationAuthority,
    ) -> Result<PlannerV2FinalizationOutcome, StoreError> {
        if let Some(existing) = load_event_by_id(&self.connection, authority.event_id)? {
            let disposition = validate_existing_planner_v2_finalization(
                &self.artifact_root,
                run_id,
                &authority,
                &existing,
            )?;
            return Ok(PlannerV2FinalizationOutcome {
                append: IdempotentAppendOutcome::AlreadyPresent {
                    event: existing.clone(),
                },
                event: existing,
                disposition,
            });
        }

        let projection = self
            .recon_run_projection(run_id)?
            .ok_or(StoreError::InvalidStateEvent)?;
        if matches!(
            projection.planner.next_action,
            PlannerNextAction::RetryPrepared { .. }
        ) {
            return Err(StoreError::InvalidStateEvent);
        }
        let (prepared_event, terminal_event, observed_success) = match &projection.planner.recovery
        {
            PlannerTurnRecoveryState::Observed {
                prepared_event,
                observed_event,
            } => {
                let EventPayload::PlannerTurnObservedV1(observed) = &observed_event.payload else {
                    return Err(StoreError::InvalidStateEvent);
                };
                (
                    prepared_event.clone(),
                    observed_event.clone(),
                    matches!(
                        observed.outcome,
                        birdcode_protocol::PlannerTurnObservationV1::Succeeded { .. }
                    ),
                )
            }
            PlannerTurnRecoveryState::Unknown {
                prepared_event,
                unknown_event,
            } => (prepared_event.clone(), unknown_event.clone(), false),
            _ => return Err(StoreError::InvalidStateEvent),
        };
        let cancelled = projection.guard.cancellation_event.is_some();
        let (append, disposition) = if observed_success && !cancelled {
            build_planner_v2_decision_event(
                self,
                &projection,
                &prepared_event,
                &terminal_event,
                &authority,
            )?
        } else {
            build_planner_v2_run_terminal_event(
                self,
                &projection,
                &prepared_event,
                &terminal_event,
                &authority,
                cancelled,
            )?
        };
        let event = append_outcome_event(&append).clone();
        Ok(PlannerV2FinalizationOutcome {
            append,
            event,
            disposition,
        })
    }
}
