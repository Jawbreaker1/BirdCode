//! Child work-order history loading, replay recovery, and public projection.

use super::super::{
    ActiveChildClaim, ChildClaimAdoptionKindV1, ChildExecutionId, ChildExecutionOutcome,
    ChildPendingEffectProjection, ChildRecoveryState, ChildReplay, ChildWorkOrderId,
    ChildWorkOrderProjection, EventEnvelope, EventPayload, MAX_CHILD_REPLAY_EVENTS,
    ReplayedChildAttempt, RetryDisposition, Run, RunId, SessionId, StoreError,
    decode_canonical_event, decode_stored_run, replay_child_event, stored_event_for_run,
    validate_typed_artifact_refs,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

pub(crate) fn child_recovery_state(
    connection: &Connection,
    session_id: SessionId,
    run_id: RunId,
    attempt: &ReplayedChildAttempt,
    terminal_event: Option<EventEnvelope>,
    retry_capacity: bool,
) -> Result<ChildRecoveryState, StoreError> {
    if let Some(outcome) = &attempt.projection.outcome {
        let terminal_event = terminal_event.ok_or(StoreError::InvalidStateEvent)?;
        if !matches!(
            &terminal_event.payload,
            EventPayload::ChildExecutionFinished(finished)
                if finished.binding.attempt_id == attempt.projection.attempt_id
                    && &finished.outcome == outcome
        ) {
            return Err(StoreError::InvalidStateEvent);
        }
        return if retry_capacity
            && matches!(
                outcome,
                ChildExecutionOutcome::Failed {
                    retry: RetryDisposition::RequiresNewAttempt,
                    ..
                }
            ) {
            Ok(ChildRecoveryState::Retryable {
                terminal_event,
                outcome: outcome.clone(),
            })
        } else {
            Ok(ChildRecoveryState::Terminal {
                terminal_event,
                outcome: outcome.clone(),
            })
        };
    }
    if terminal_event.is_some() {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(pending) = &attempt.pending_model {
        let event =
            stored_event_for_run(connection, session_id, run_id, pending.prepared_event_id)?;
        let exact = match &event.payload {
            EventPayload::ChildModelInferencePrepared(prepared) => {
                prepared.binding.attempt_id == attempt.projection.attempt_id
                    && prepared.model_call_id == pending.model_call_id
            }
            EventPayload::ChildModelInferencePreparedV2(prepared) => {
                prepared.prepared.binding.attempt_id == attempt.projection.attempt_id
                    && prepared.prepared.model_call_id == pending.model_call_id
            }
            _ => false,
        };
        if !exact || attempt.pending_tool.is_some() {
            return Err(StoreError::InvalidStateEvent);
        }
        return Ok(ChildRecoveryState::PendingEffect(
            ChildPendingEffectProjection::Model {
                prepared_event: event,
            },
        ));
    }
    if let Some(pending) = &attempt.pending_tool {
        let event =
            stored_event_for_run(connection, session_id, run_id, pending.prepared_event_id)?;
        let exact = match &event.payload {
            EventPayload::ChildToolPrepared(prepared) => {
                prepared.binding.attempt_id == attempt.projection.attempt_id
                    && prepared.tool_call_id == pending.tool_call_id
            }
            EventPayload::ChildToolPreparedV2(prepared) => {
                prepared.binding.attempt_id == attempt.projection.attempt_id
                    && prepared.tool_call_id == pending.tool_call_id
            }
            _ => false,
        };
        if !exact {
            return Err(StoreError::InvalidStateEvent);
        }
        return Ok(ChildRecoveryState::PendingEffect(
            ChildPendingEffectProjection::Tool {
                prepared_event: event,
            },
        ));
    }
    if attempt.projection.handoff_event_id.is_some()
        || attempt.required_model_terminal_retry.is_some()
    {
        return Ok(ChildRecoveryState::ReadyToFinishAttempt);
    }
    if attempt.model_turn_required {
        return Ok(ChildRecoveryState::ReadyForModel);
    }
    let successful = attempt
        .last_successful_model
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    if successful.proposed_action.tool_operation().is_some() {
        Ok(ChildRecoveryState::ReadyForTool)
    } else if matches!(
        successful.proposed_action,
        super::super::ChildActionV1::Finish { .. }
    ) {
        Ok(ChildRecoveryState::ReadyForHandoff)
    } else {
        Err(StoreError::InvalidStateEvent)
    }
}

pub(crate) fn work_order_for_execution(
    connection: &Connection,
    run_id: RunId,
    execution_id: ChildExecutionId,
) -> Result<ChildWorkOrderId, StoreError> {
    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1
           AND json_extract(value_json, '$.payload.type') = 'child_work_order_issued'
           AND json_extract(value_json, '$.payload.data.spec.execution_id') = ?2
         ORDER BY sequence ASC LIMIT 2",
    )?;
    let rows = statement
        .query_map(
            params![run_id.to_string(), execution_id.to_string()],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let [json] = rows.as_slice() else {
        return Err(StoreError::InvalidStateEvent);
    };
    let event = decode_canonical_event(json)?;
    let EventPayload::ChildWorkOrderIssued(issued) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if issued.spec.execution_id != execution_id {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(issued.spec.work_order_id)
}

pub(crate) fn child_history(
    connection: &Connection,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
) -> Result<Vec<EventEnvelope>, StoreError> {
    let session_id = connection
        .query_row(
            "SELECT session_id FROM runs WHERE id = ?1",
            [run_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND (
                (json_extract(value_json, '$.payload.type') = 'child_work_order_issued'
                 AND json_extract(value_json, '$.payload.data.spec.work_order_id') = ?3)
             OR (json_extract(value_json, '$.payload.type') = 'child_execution_claim_adopted'
                 AND json_extract(value_json, '$.payload.data.work_order_id') = ?3)
             OR (json_extract(value_json, '$.payload.type') IN (
                    'child_execution_started',
                    'child_model_inference_prepared',
                    'child_model_inference_prepared_v2',
                    'child_model_inference_observed',
                    'child_model_inference_outcome_unknown',
                    'child_tool_prepared',
                    'child_tool_observed',
                    'child_tool_outcome_unknown',
                    'child_tool_prepared_v2',
                    'child_tool_observed_v2',
                    'child_tool_outcome_unknown_v2',
                    'child_handoff_committed',
                    'child_execution_finished'
                 )
                 AND COALESCE(
                       json_extract(value_json, '$.payload.data.binding.work_order_id'),
                       json_extract(value_json, '$.payload.data.prepared.binding.work_order_id')
                     ) = ?3)
           )
         ORDER BY sequence ASC LIMIT ?4",
    )?;
    let rows = statement
        .query_map(
            params![
                run_id.to_string(),
                session_id,
                work_order_id.to_string(),
                u64::from(MAX_CHILD_REPLAY_EVENTS) + 1,
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > MAX_CHILD_REPLAY_EVENTS as usize {
        return Err(StoreError::InvalidStateEvent);
    }
    rows.iter()
        .map(|json| decode_canonical_event(json))
        .collect()
}

pub(crate) struct NonterminalChildClaimReplay {
    pub(crate) work_order_id: ChildWorkOrderId,
    pub(crate) replay: ChildReplay,
    pub(crate) prior_adoption_count: usize,
}

pub(crate) fn durable_run_for_claim_refresh(
    connection: &Connection,
    run_id: RunId,
) -> Result<Run, StoreError> {
    let json = connection
        .query_row(
            "SELECT value_json FROM runs WHERE id = ?1",
            [run_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    decode_stored_run(&json)
}

fn child_replay_is_nonterminal(replay: &ChildReplay) -> bool {
    match replay
        .attempts
        .last()
        .and_then(|attempt| attempt.projection.outcome.as_ref())
    {
        None => true,
        Some(ChildExecutionOutcome::Failed {
            retry: RetryDisposition::RequiresNewAttempt,
            ..
        }) => replay.attempts.len() < replay.issued.spec.max_attempts as usize,
        Some(
            ChildExecutionOutcome::Succeeded { .. }
            | ChildExecutionOutcome::Failed { .. }
            | ChildExecutionOutcome::Cancelled { .. },
        ) => false,
    }
}

pub(crate) fn nonterminal_child_replays_for_claim_refresh(
    connection: &Connection,
    artifact_root: &Path,
    run: &Run,
) -> Result<Vec<NonterminalChildClaimReplay>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'child_work_order_issued'
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(
        params![run.id.to_string(), run.spec.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?;
    let mut work_orders = Vec::new();
    for row in rows {
        let event = decode_canonical_event(&row?)?;
        let EventPayload::ChildWorkOrderIssued(issued) = event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        if event.run_id != Some(run.id) || event.session_id != run.spec.session_id {
            return Err(StoreError::InvalidStateEvent);
        }
        work_orders.push(issued.spec.work_order_id);
    }
    if work_orders.len() > run.spec.limits.max_subagents as usize {
        return Err(StoreError::InvalidStateEvent);
    }
    work_orders.sort_unstable_by_key(ToString::to_string);
    if work_orders.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::InvalidStateEvent);
    }

    let mut children = Vec::with_capacity(work_orders.len());
    for work_order_id in work_orders {
        let (replay, _, prior_adoption_count, _) =
            load_child_replay(connection, artifact_root, run.id, work_order_id)?;
        let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
        if replay.issued.spec.work_order_id != work_order_id
            || work_order_for_execution(connection, run.id, replay.issued.spec.execution_id)?
                != work_order_id
        {
            return Err(StoreError::InvalidStateEvent);
        }
        if child_replay_is_nonterminal(&replay) {
            children.push(NonterminalChildClaimReplay {
                work_order_id,
                replay,
                prior_adoption_count,
            });
        }
    }
    Ok(children)
}

pub(crate) fn child_claim_matches(
    child: &ActiveChildClaim,
    claim_event: &EventEnvelope,
    claim: &birdcode_protocol::RunClaimed,
) -> bool {
    child.event_id == claim_event.id
        && child.claim_id == claim.claim_id
        && child.generation == claim.claim_generation
        && child.runtime_instance_id == claim.runtime_instance_id
        && child.cancellation_generation == claim.cancellation_generation
        && child.lease_expires_at == claim.lease_expires_at
}

pub(crate) fn load_child_replay(
    connection: &Connection,
    artifact_root: &Path,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
) -> Result<(Option<ChildReplay>, usize, usize, usize), StoreError> {
    let events = child_history(connection, run_id, work_order_id)?;
    let event_count = events.len();
    let adoption_count = events
        .iter()
        .filter(|event| matches!(event.payload, EventPayload::ChildExecutionClaimAdopted(_)))
        .count();
    let takeover_count = events
        .iter()
        .filter(|event| {
            matches!(
                event.payload,
                EventPayload::ChildExecutionClaimAdopted(
                    birdcode_protocol::ChildExecutionClaimAdoptedV1 {
                        kind: ChildClaimAdoptionKindV1::Takeover,
                        ..
                    }
                )
            )
        })
        .count();
    let mut replay = None;
    for event in events {
        validate_typed_artifact_refs(artifact_root, &event.provenance, &event.payload)?;
        replay_child_event(connection, artifact_root, &mut replay, &event)?;
    }
    Ok((replay, event_count, adoption_count, takeover_count))
}

pub(crate) fn project_child_work_order(
    connection: &Connection,
    artifact_root: &Path,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
) -> Result<Option<ChildWorkOrderProjection>, StoreError> {
    let (replay, _, _, _) = load_child_replay(connection, artifact_root, run_id, work_order_id)?;
    let Some(replay) = replay else {
        return Ok(None);
    };
    if work_order_for_execution(connection, run_id, replay.issued.spec.execution_id)?
        != work_order_id
    {
        return Err(StoreError::InvalidStateEvent);
    }
    replay.into_projection(connection, run_id).map(Some)
}
