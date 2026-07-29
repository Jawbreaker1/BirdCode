//! Store-owned child-agent lifecycle, projection, and overlap APIs.

use super::{
    CHILD_MODEL_EVIDENCE_MEDIA_TYPE, CHILD_MODEL_UNKNOWN_MEDIA_TYPE,
    CHILD_REPOSITORY_EXPLORER_OBSERVATION_PRODUCER, CHILD_REPOSITORY_EXPLORER_UNKNOWN_PRODUCER,
    ChildAttemptId, ChildExecutionBinding, ChildExecutionId, ChildExecutionOverlap,
    ChildRepositoryExplorerObservationAuthority, ChildRepositoryExplorerTerminalOutcome,
    ChildRepositoryExplorerUnknownAuthority, ChildWorkOrderId, ChildWorkOrderProjection,
    EventAdmission, EventEnvelope, EventId, EventPayload, IdempotentAppendOutcome,
    IdentifiedNewEvent, MAX_SQLITE_INTEGER_U64, NewEvent, Provenance, RunId, RunPurpose, SessionId,
    Store, StoreError, append_outcome_event, child_model_observed_payload,
    child_model_terminal_context, child_model_unknown_payload, derive_child_model_evidence_record,
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
