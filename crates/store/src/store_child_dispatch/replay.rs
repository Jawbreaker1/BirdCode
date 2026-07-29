//! Child repository-tool pending state and broker-v2 replay transitions.

use super::super::{
    ChildPreviousToolContextV1, ChildReplay, EventEnvelope, EventPayload, StoreError,
    binding_matches_order, child_attempt_clock_accepts, child_tool_call_seen,
    latest_broker_epoch_before, require_child_event_provenance, validate_child_broker_sequence_v2,
    validate_child_cancellation_cause, validate_child_tool_observed_document_v2,
    validate_child_tool_prepared_document_v2, validate_child_tool_unknown_document_v2,
};
use birdcode_protocol::{
    ArtifactRef, ChildToolCallId, ChildToolObservedV2, ChildToolOperation,
    ChildToolOutcomeUnknownV2, ChildToolPreparedV2, ChildValidatedActionBindingV1,
    RepositoryBrokerClockV1, RepositoryBrokerInstanceId, RepositoryToolAuthorizationDecisionV1,
    RepositoryToolAuthorizationDecisionV2, RepositoryToolObservedTerminalV2, RuntimeClockReading,
    Sha256Digest,
};
use rusqlite::Connection;
use std::path::Path;

#[derive(Clone)]
pub(crate) enum PendingChildToolAuthorization {
    V1(RepositoryToolAuthorizationDecisionV1),
    V2(RepositoryToolAuthorizationDecisionV2),
}

#[derive(Clone)]
pub(crate) struct PendingChildTool {
    pub(crate) prepared_event_id: super::super::EventId,
    pub(crate) tool_call_id: ChildToolCallId,
    pub(crate) action_binding: ChildValidatedActionBindingV1,
    pub(crate) operation: ChildToolOperation,
    pub(crate) authorization: PendingChildToolAuthorization,
    pub(crate) prepared_receipt_artifact: ArtifactRef,
    pub(crate) broker_instance_id: RepositoryBrokerInstanceId,
    pub(crate) broker_prepared_at: RepositoryBrokerClockV1,
    pub(crate) prepared_receipt_digest: Sha256Digest,
    pub(crate) prepared_at: RuntimeClockReading,
}

pub(crate) fn replay_child_tool_prepared_v2(
    connection: &Connection,
    artifact_root: &Path,
    replay: &mut Option<ChildReplay>,
    event: &EventEnvelope,
    prepared: &ChildToolPreparedV2,
) -> Result<(), StoreError> {
    let replay_ref = replay.as_ref().ok_or(StoreError::InvalidStateEvent)?;
    if child_tool_call_seen(replay_ref, prepared.tool_call_id) {
        return Err(StoreError::InvalidStateEvent);
    }
    let replay = replay.as_mut().ok_or(StoreError::InvalidStateEvent)?;
    if !binding_matches_order(&prepared.binding, &replay.issued)
        || prepared.prepared_at.runtime_instance_id != replay.active_claim.runtime_instance_id
        || replay.issued.spec.run_deadline.is_some_and(|deadline| {
            event.occurred_at > deadline || prepared.prepared_at.observed_at > deadline
        })
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_child_event_provenance(
        event,
        &replay.issued,
        Some(&prepared.prepared_receipt_artifact),
    )?;
    let issued = replay.issued.clone();
    let attempt = replay
        .attempts
        .last_mut()
        .ok_or(StoreError::InvalidStateEvent)?;
    if prepared.binding.attempt_id != attempt.projection.attempt_id
        || attempt.projection.outcome.is_some()
        || attempt.pending_model.is_some()
        || attempt.pending_tool.is_some()
        || attempt.projection.handoff_event_id.is_some()
        || attempt.model_turn_required
        || attempt.required_model_terminal_retry.is_some()
        || event.causal_parent != Some(attempt.tail_event_id)
        || prepared.tool_ordinal
            != attempt
                .projection
                .completed_tool_calls
                .checked_add(1)
                .ok_or(StoreError::InvalidStateEvent)?
        || prepared.tool_ordinal > issued.spec.max_tool_calls_per_attempt
        || !child_attempt_clock_accepts(attempt, &prepared.prepared_at)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let pending = validate_child_tool_prepared_document_v2(
        connection,
        artifact_root,
        event,
        prepared,
        &issued,
        attempt,
    )?;
    let run_id = event.run_id.ok_or(StoreError::InvalidStateEvent)?;
    let epoch_event =
        latest_broker_epoch_before(connection, event.session_id, run_id, event.sequence)?
            .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::RepositoryBrokerEpochActivatedV1(epoch) = epoch_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    validate_child_broker_sequence_v2(attempt, prepared, &epoch.state)?;
    if attempt.last_broker_terminal_clock.is_some_and(|last| {
        last.broker_instance_id != pending.broker_prepared_at.broker_instance_id
            || last.monotonic_nanos > pending.broker_prepared_at.monotonic_nanos
    }) {
        return Err(StoreError::InvalidStateEvent);
    }
    attempt.repository_broker_instance_id = Some(prepared.broker_instance_id);
    attempt.last_broker_call_sequence = prepared.broker_call_sequence;
    attempt.broker_reset_authorized_from = None;
    attempt.projection.repository_broker_instance_id = Some(prepared.broker_instance_id);
    attempt.projection.last_broker_call_sequence = prepared.broker_call_sequence;
    attempt.pending_tool = Some(pending);
    attempt.tail_event_id = event.id;
    attempt.tail_clock = prepared.prepared_at.clone();
    Ok(())
}

pub(crate) fn replay_child_tool_observed_v2(
    artifact_root: &Path,
    replay: &mut Option<ChildReplay>,
    event: &EventEnvelope,
    observed: &ChildToolObservedV2,
) -> Result<(), StoreError> {
    let replay = replay.as_mut().ok_or(StoreError::InvalidStateEvent)?;
    if !binding_matches_order(&observed.binding, &replay.issued) {
        return Err(StoreError::InvalidStateEvent);
    }
    if observed.finished_at.runtime_instance_id != replay.active_claim.runtime_instance_id {
        return Err(StoreError::InvalidStateEvent);
    }
    require_child_event_provenance(
        event,
        &replay.issued,
        Some(&observed.terminal_receipt_artifact),
    )?;
    let authority = replay.issued.spec.repository_authority.clone();
    let attempt = replay
        .attempts
        .last_mut()
        .ok_or(StoreError::InvalidStateEvent)?;
    let pending = attempt
        .pending_tool
        .clone()
        .ok_or(StoreError::InvalidStateEvent)?;
    if observed.binding.attempt_id != attempt.projection.attempt_id
        || attempt.projection.outcome.is_some()
        || attempt.pending_effect_requires_unknown
        || event.causal_parent != Some(attempt.tail_event_id)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let (result_artifact, broker_terminal_clock) =
        validate_child_tool_observed_document_v2(artifact_root, observed, &pending, &authority)?;
    attempt.last_broker_terminal_clock = Some(broker_terminal_clock);
    if let Some(result_artifact) = result_artifact {
        attempt
            .observed_results
            .insert(observed.tool_call_id, (event.id, result_artifact));
    }
    attempt.tool_failure_terminal = match &observed.terminal {
        RepositoryToolObservedTerminalV2::Succeeded { .. } => None,
        RepositoryToolObservedTerminalV2::Failed { .. }
        | RepositoryToolObservedTerminalV2::AuthorizationDenied { .. } => {
            Some((event.id, observed.tool_call_id))
        }
    };
    attempt.projection.completed_tool_calls = attempt
        .projection
        .completed_tool_calls
        .checked_add(1)
        .ok_or(StoreError::InvalidStateEvent)?;
    attempt.pending_tool = None;
    attempt.pending_effect_requires_unknown = false;
    attempt.latest_effect_event_id = Some(event.id);
    attempt
        .completed_tool_call_ids
        .insert(observed.tool_call_id);
    let tool_context = ChildPreviousToolContextV1::Observed {
        tool_call_id: observed.tool_call_id,
        terminal_event_id: event.id,
        terminal_receipt_artifact: observed.terminal_receipt_artifact.clone(),
        terminal_receipt_digest: observed.terminal_receipt_digest.clone(),
    };
    attempt
        .model_visible_tool_transcript
        .push(tool_context.clone());
    attempt.previous_tool_context = Some(tool_context);
    attempt.last_successful_model = None;
    attempt.tail_event_id = event.id;
    attempt.tail_clock = observed.finished_at.clone();
    attempt.model_turn_required = true;
    Ok(())
}

pub(crate) fn replay_child_tool_unknown_v2(
    connection: &Connection,
    artifact_root: &Path,
    replay: &mut Option<ChildReplay>,
    event: &EventEnvelope,
    unknown: &ChildToolOutcomeUnknownV2,
) -> Result<(), StoreError> {
    let replay = replay.as_mut().ok_or(StoreError::InvalidStateEvent)?;
    if !binding_matches_order(&unknown.binding, &replay.issued) {
        return Err(StoreError::InvalidStateEvent);
    }
    if unknown.boundary_at.runtime_instance_id != replay.active_claim.runtime_instance_id {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(cause) = &unknown.cancellation {
        validate_child_cancellation_cause(connection, event, cause)?;
    }
    require_child_event_provenance(
        event,
        &replay.issued,
        Some(&unknown.terminal_receipt_artifact),
    )?;
    let attempt = replay
        .attempts
        .last_mut()
        .ok_or(StoreError::InvalidStateEvent)?;
    let pending = attempt
        .pending_tool
        .clone()
        .ok_or(StoreError::InvalidStateEvent)?;
    if unknown.binding.attempt_id != attempt.projection.attempt_id
        || attempt.projection.outcome.is_some()
        || event.causal_parent != Some(attempt.tail_event_id)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let (became_incomparable, broker_terminal_clock) = validate_child_tool_unknown_document_v2(
        connection,
        artifact_root,
        event,
        unknown,
        &pending,
    )?;
    attempt.last_broker_terminal_clock = broker_terminal_clock;
    if became_incomparable {
        attempt.broker_reset_authorized_from = Some(pending.broker_instance_id);
    }
    attempt.clock_became_incomparable |= became_incomparable;
    attempt.projection.monotonic_clock_contiguous &= !became_incomparable;
    attempt.projection.completed_tool_calls = attempt
        .projection
        .completed_tool_calls
        .checked_add(1)
        .ok_or(StoreError::InvalidStateEvent)?;
    attempt.pending_tool = None;
    attempt.pending_effect_requires_unknown = false;
    attempt.latest_effect_event_id = Some(event.id);
    attempt.completed_tool_call_ids.insert(unknown.tool_call_id);
    let tool_context = ChildPreviousToolContextV1::Unknown {
        tool_call_id: unknown.tool_call_id,
        terminal_event_id: event.id,
        terminal_receipt_artifact: unknown.terminal_receipt_artifact.clone(),
        terminal_receipt_digest: unknown.terminal_receipt_digest.clone(),
    };
    attempt
        .model_visible_tool_transcript
        .push(tool_context.clone());
    attempt.previous_tool_context = Some(tool_context);
    attempt.last_successful_model = None;
    attempt.tool_failure_terminal = Some((event.id, unknown.tool_call_id));
    attempt.tail_event_id = event.id;
    attempt.tail_clock = unknown.boundary_at.clone();
    attempt.model_turn_required = true;
    Ok(())
}
