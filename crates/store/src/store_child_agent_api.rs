//! Store-owned child-agent turn, recovery, terminal, and overlap APIs.

use super::{
    CHILD_MODEL_EVIDENCE_MEDIA_TYPE, CHILD_MODEL_UNKNOWN_MEDIA_TYPE,
    CHILD_REPOSITORY_EXPLORER_OBSERVATION_PRODUCER, CHILD_REPOSITORY_EXPLORER_PREPARATION_PRODUCER,
    CHILD_REPOSITORY_EXPLORER_UNKNOWN_PRODUCER, ChildAttemptId, ChildExecutionBinding,
    ChildExecutionId, ChildExecutionOverlap, ChildPendingEffectProjection, ChildRecoveryState,
    ChildRepositoryExplorerObservationAuthority, ChildRepositoryExplorerPreparationAuthority,
    ChildRepositoryExplorerPreparationOutcome, ChildRepositoryExplorerPreparedMaterial,
    ChildRepositoryExplorerTerminalOutcome, ChildRepositoryExplorerUnknownAuthority,
    ChildWorkOrderId, ChildWorkOrderProjection, EventAdmission, EventEnvelope, EventId,
    EventPayload, IdempotentAppendOutcome, IdentifiedNewEvent, MAX_SQLITE_INTEGER_U64, NewEvent,
    Provenance, RunId, RunPurpose, SessionId, Store, StoreError, append_outcome_event,
    build_child_repository_explorer_prepared_event, child_model_observed_payload,
    child_model_terminal_context, child_model_unknown_payload,
    child_repository_explorer_committed_material,
    child_repository_explorer_current_prepared_material, derive_child_model_evidence_record,
    derive_child_model_unknown_record, derive_child_overlap, durable_run_for_claim_refresh,
    load_event_by_id, project_child_work_order, put_json_artifact,
    validate_existing_child_repository_explorer_observation,
    validate_existing_child_repository_explorer_unknown, work_order_for_execution,
};
#[cfg(test)]
use super::{
    apply_exact_event_envelope_with_admission, load_child_replay,
    preallocate_identified_event_envelope,
};
use rusqlite::Connection;
#[cfg(test)]
use rusqlite::TransactionBehavior;

const CHILD_REPOSITORY_EXPLORER_ATTEMPT_START_PRODUCER: &str =
    "birdcode-store-child-repository-explorer-attempt-start-v1";

/// Durable evidence that one exact child model Prepared boundary exists.
///
/// The normal preparation and recovery APIs return no compiled prompt,
/// backend-ready request, or adapter authority alongside this evidence.
/// Callers can use it to identify the boundary that must be reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildModelPreparedEvidence {
    pub prepared_event: EventEnvelope,
}

/// Fresh, affine authority for dispatching one Store-committed child model
/// request.
///
/// The handoff is intentionally neither `Clone` nor serializable. It is issued
/// only when this call appended the Prepared boundary and must be consumed by
/// the daemon's model-effect lane. A recovered or idempotently replayed
/// Prepared boundary never recreates this authority.
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// fn duplicate(value: ChildModelDispatchHandoff) {
///     let _copy = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// let _forged = ChildModelDispatchHandoff::default();
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// fn serialize(value: &ChildModelDispatchHandoff) {
///     let _encoded = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// let _decoded: ChildModelDispatchHandoff = serde_json::from_str("{}").unwrap();
/// ```
#[must_use = "a fresh child model dispatch handoff must be consumed or explicitly discarded"]
pub struct ChildModelDispatchHandoff {
    material: Box<ChildRepositoryExplorerPreparedMaterial>,
}

const _: () =
    assert!(std::mem::size_of::<ChildModelDispatchHandoff>() == std::mem::size_of::<usize>());

impl ChildModelDispatchHandoff {
    /// Returns the exact durable boundary that authorized this one dispatch.
    #[must_use]
    pub const fn prepared_event(&self) -> &EventEnvelope {
        &self.material.prepared_event
    }

    /// Consumes the affine handoff and releases the exact compiled provider
    /// request to the trusted model-effect lane.
    #[must_use]
    pub fn into_backend_request(self) -> birdcode_backends::StructuredInferenceRequest {
        let ChildRepositoryExplorerPreparedMaterial {
            backend_request, ..
        } = *self.material;
        backend_request
    }
}

/// Closed preparation result that distinguishes fresh effect authority from
/// replay-only evidence.
#[must_use = "child model preparation must either dispatch once or reconcile durable evidence"]
pub enum ChildModelDispatchPreparationOutcome {
    Appended {
        evidence: ChildModelPreparedEvidence,
        dispatch: ChildModelDispatchHandoff,
    },
    AlreadyPresent {
        evidence: ChildModelPreparedEvidence,
    },
}

fn child_model_dispatch_outcome(
    outcome: ChildRepositoryExplorerPreparationOutcome,
) -> Result<ChildModelDispatchPreparationOutcome, StoreError> {
    let prepared_event = outcome.material.prepared_event.clone();
    let evidence = ChildModelPreparedEvidence {
        prepared_event: prepared_event.clone(),
    };
    match outcome.append {
        IdempotentAppendOutcome::Appended { event } if event == prepared_event => {
            Ok(ChildModelDispatchPreparationOutcome::Appended {
                evidence,
                dispatch: ChildModelDispatchHandoff {
                    material: Box::new(outcome.material),
                },
            })
        }
        IdempotentAppendOutcome::AlreadyPresent { event } if event == prepared_event => {
            Ok(ChildModelDispatchPreparationOutcome::AlreadyPresent { evidence })
        }
        IdempotentAppendOutcome::Appended { .. }
        | IdempotentAppendOutcome::AlreadyPresent { .. } => Err(StoreError::InvalidStateEvent),
    }
}

fn exact_existing_child_repository_explorer_prepared_event(
    store: &Store,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
    authority: &ChildRepositoryExplorerPreparationAuthority,
) -> Result<Option<EventEnvelope>, StoreError> {
    let Some(existing) = load_event_by_id(&store.connection, authority.event_id)? else {
        return Ok(None);
    };
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
    Ok(Some(existing))
}

fn existing_child_repository_explorer_preparation(
    store: &Store,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
    authority: &ChildRepositoryExplorerPreparationAuthority,
) -> Result<Option<ChildModelPreparedEvidence>, StoreError> {
    let Some(existing) = exact_existing_child_repository_explorer_prepared_event(
        store,
        run_id,
        work_order_id,
        authority,
    )?
    else {
        return Ok(None);
    };
    child_repository_explorer_committed_material(
        &store.connection,
        &store.artifact_root,
        existing.clone(),
    )?;
    Ok(Some(ChildModelPreparedEvidence {
        prepared_event: existing,
    }))
}

enum ChildRepositoryExplorerPreparationBeforeAppend {
    Existing(Box<ChildRepositoryExplorerPreparationOutcome>),
    Identified(Box<IdentifiedNewEvent>),
}

/// Runtime-owned identities and clock authority for starting one bounded
/// repository-explorer attempt. Store derives the complete execution binding,
/// retry ancestry, actor, backend/model identity, and provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildRepositoryExplorerAttemptStartAuthority {
    pub event_id: EventId,
    pub attempt_id: ChildAttemptId,
    pub local_plan_id: birdcode_protocol::ChildLocalPlanId,
    pub started_at: birdcode_protocol::RuntimeClockReading,
}

pub(super) fn child_execution_binding(
    replay: &super::ChildReplay,
    attempt: &super::ReplayedChildAttempt,
) -> ChildExecutionBinding {
    ChildExecutionBinding {
        work_order_id: replay.issued.spec.work_order_id,
        execution_id: replay.issued.spec.execution_id,
        attempt_id: attempt.projection.attempt_id,
        child_actor_id: replay.issued.spec.child_actor_id,
        context_id: replay.issued.spec.context_id,
        work_order_digest: replay.issued.work_order_digest.clone(),
        context_manifest_digest: replay.issued.context_manifest_digest.clone(),
    }
}

pub(super) fn reject_parallel_recon_public_attempt_start(
    connection: &Connection,
    event: &EventEnvelope,
    admission: EventAdmission,
) -> Result<(), StoreError> {
    let run_id = event.run_id.ok_or(StoreError::InvalidStateEvent)?;
    let run = durable_run_for_claim_refresh(connection, run_id)?;
    if run.spec.purpose == RunPurpose::ParallelRepositoryReconnaissanceV1
        && admission != EventAdmission::ParallelReconBootstrap
    {
        Err(StoreError::InvalidStateEvent)
    } else {
        Ok(())
    }
}

pub(super) fn child_repository_explorer_attempt_start_event(
    session_id: SessionId,
    run_id: RunId,
    replay: &super::ChildReplay,
    attempt_index: usize,
    attempt_id: ChildAttemptId,
    local_plan_id: birdcode_protocol::ChildLocalPlanId,
    started_at: birdcode_protocol::RuntimeClockReading,
) -> Result<NewEvent, StoreError> {
    if attempt_index > replay.attempts.len() {
        return Err(StoreError::InvalidStateEvent);
    }
    let (causal_parent, parent_attempt_id) = if attempt_index == 0 {
        (replay.pre_attempt_tail_event_id, None)
    } else {
        let previous = replay
            .attempts
            .get(attempt_index - 1)
            .ok_or(StoreError::InvalidStateEvent)?;
        (previous.tail_event_id, Some(previous.projection.attempt_id))
    };
    Ok(NewEvent {
        session_id,
        run_id: Some(run_id),
        actor_id: replay.issued.spec.child_event_actor_id,
        causal_parent: Some(causal_parent),
        provenance: Provenance {
            producer: CHILD_REPOSITORY_EXPLORER_ATTEMPT_START_PRODUCER.to_owned(),
            backend: Some(replay.issued.spec.backend.clone()),
            raw_artifact: None,
        },
        payload: EventPayload::ChildExecutionStarted(birdcode_protocol::ChildExecutionStarted {
            binding: ChildExecutionBinding {
                work_order_id: replay.issued.spec.work_order_id,
                execution_id: replay.issued.spec.execution_id,
                attempt_id,
                child_actor_id: replay.issued.spec.child_actor_id,
                context_id: replay.issued.spec.context_id,
                work_order_digest: replay.issued.work_order_digest.clone(),
                context_manifest_digest: replay.issued.context_manifest_digest.clone(),
            },
            parent_attempt_id,
            local_plan_id,
            backend_model: replay.issued.spec.resolved_model.clone(),
            model_lineage: replay.issued.spec.model_lineage.clone(),
            started_at,
        }),
    })
}

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

    #[cfg(test)]
    pub(crate) fn start_child_repository_explorer_attempt(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: ChildRepositoryExplorerAttemptStartAuthority,
    ) -> Result<EventEnvelope, StoreError> {
        let artifact_root = self.artifact_root.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = durable_run_for_claim_refresh(&transaction, run_id)?;
        let (replay, _, _, _) =
            load_child_replay(&transaction, &artifact_root, run_id, work_order_id)?;
        let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
        let event = child_repository_explorer_attempt_start_event(
            run.spec.session_id,
            run_id,
            &replay,
            replay.attempts.len(),
            authority.attempt_id,
            authority.local_plan_id,
            authority.started_at,
        )?;
        let envelope =
            preallocate_identified_event_envelope(&transaction, authority.event_id, event)?;
        apply_exact_event_envelope_with_admission(
            &transaction,
            &artifact_root,
            &envelope,
            EventAdmission::ParallelReconBootstrap,
        )?;
        transaction.commit()?;
        Ok(envelope)
    }

    /// Commits one exact repository-explorer model preparation and returns
    /// fresh dispatch authority only to the writer that appended it.
    ///
    /// Exact replay returns the same durable evidence without a handoff. The
    /// normal public preparation and recovery paths do not directly return a
    /// backend-ready request unless this call owns the fresh append.
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
    pub fn prepare_child_repository_explorer_dispatch(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: ChildRepositoryExplorerPreparationAuthority,
    ) -> Result<ChildModelDispatchPreparationOutcome, StoreError> {
        self.prepare_child_repository_explorer_dispatch_after_initial_miss(
            run_id,
            work_order_id,
            &authority,
            || {},
            || {},
        )
    }

    fn prepare_child_repository_explorer_dispatch_after_initial_miss<F, G>(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: &ChildRepositoryExplorerPreparationAuthority,
        after_initial_miss: F,
        after_build_before_append: G,
    ) -> Result<ChildModelDispatchPreparationOutcome, StoreError>
    where
        F: FnOnce(),
        G: FnOnce(),
    {
        let before_append = match self.child_repository_explorer_preparation_before_append(
            run_id,
            work_order_id,
            authority,
            after_initial_miss,
        ) {
            Ok(before_append) => before_append,
            Err(error) => {
                return match existing_child_repository_explorer_preparation(
                    self,
                    run_id,
                    work_order_id,
                    authority,
                )? {
                    Some(evidence) => {
                        Ok(ChildModelDispatchPreparationOutcome::AlreadyPresent { evidence })
                    }
                    None => Err(error),
                };
            }
        };
        if matches!(
            &before_append,
            ChildRepositoryExplorerPreparationBeforeAppend::Identified(_)
        ) {
            after_build_before_append();
        }
        child_model_dispatch_outcome(
            self.commit_child_repository_explorer_preparation(before_append)?,
        )
    }

    /// Returns replay-only evidence for the current pending child model
    /// boundary. Recovery never recreates model dispatch authority.
    ///
    /// # Errors
    ///
    /// Returns an error for contradictory child replay, retained artifact
    /// drift, or a Prepared event that no longer recompiles exactly.
    pub fn recover_child_repository_explorer_dispatch(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
    ) -> Result<Option<ChildModelPreparedEvidence>, StoreError> {
        self.recover_child_repository_explorer_turn(run_id, work_order_id)
            .map(|material| {
                material.map(|material| ChildModelPreparedEvidence {
                    prepared_event: material.prepared_event,
                })
            })
    }

    /// Derives the complete repository-explorer turn from authoritative child
    /// history, persists the compiled prompt/request/manifest, and commits the
    /// Prepared-v2 event before returning crate-internal compiled material.
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
    #[cfg(test)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh runtime authority"
    )]
    pub(crate) fn prepare_child_repository_explorer_turn(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: ChildRepositoryExplorerPreparationAuthority,
    ) -> Result<ChildRepositoryExplorerPreparationOutcome, StoreError> {
        let before_append = self.child_repository_explorer_preparation_before_append(
            run_id,
            work_order_id,
            &authority,
            || {},
        )?;
        self.commit_child_repository_explorer_preparation(before_append)
    }

    fn child_repository_explorer_preparation_before_append<F>(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: &ChildRepositoryExplorerPreparationAuthority,
        after_initial_miss: F,
    ) -> Result<ChildRepositoryExplorerPreparationBeforeAppend, StoreError>
    where
        F: FnOnce(),
    {
        if let Some(existing) = exact_existing_child_repository_explorer_prepared_event(
            self,
            run_id,
            work_order_id,
            authority,
        )? {
            let material = child_repository_explorer_current_prepared_material(
                &self.connection,
                &self.artifact_root,
                existing.clone(),
            )?;
            return Ok(ChildRepositoryExplorerPreparationBeforeAppend::Existing(
                Box::new(ChildRepositoryExplorerPreparationOutcome {
                    append: IdempotentAppendOutcome::AlreadyPresent { event: existing },
                    material,
                }),
            ));
        }
        after_initial_miss();

        let identified =
            build_child_repository_explorer_prepared_event(self, run_id, work_order_id, authority)?;
        Ok(ChildRepositoryExplorerPreparationBeforeAppend::Identified(
            Box::new(identified),
        ))
    }

    fn commit_child_repository_explorer_preparation(
        &mut self,
        before_append: ChildRepositoryExplorerPreparationBeforeAppend,
    ) -> Result<ChildRepositoryExplorerPreparationOutcome, StoreError> {
        let identified = match before_append {
            ChildRepositoryExplorerPreparationBeforeAppend::Existing(outcome) => {
                return Ok(*outcome);
            }
            ChildRepositoryExplorerPreparationBeforeAppend::Identified(identified) => *identified,
        };
        let append = self.append_identified_event(identified)?;
        let material = match &append {
            IdempotentAppendOutcome::Appended { event } => {
                child_repository_explorer_current_prepared_material(
                    &self.connection,
                    &self.artifact_root,
                    event.clone(),
                )?
            }
            IdempotentAppendOutcome::AlreadyPresent { event } => {
                child_repository_explorer_committed_material(
                    &self.connection,
                    &self.artifact_root,
                    event.clone(),
                )?
            }
        };
        Ok(ChildRepositoryExplorerPreparationOutcome { append, material })
    }

    /// Reconstructs the exact committed repository-explorer request only for
    /// crate-internal validation while it is the current pre-effect boundary.
    ///
    /// Product recovery uses
    /// [`Self::recover_child_repository_explorer_dispatch`], which cannot
    /// expose these provider request bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for contradictory child replay, retained artifact
    /// drift, or a Prepared event that no longer recompiles exactly.
    pub(crate) fn recover_child_repository_explorer_turn(
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

#[cfg(test)]
#[path = "tests/child_model_dispatch_authority.rs"]
mod tests;
