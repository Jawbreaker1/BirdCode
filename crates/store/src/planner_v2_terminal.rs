//! Planner-v2 terminal clock, claim continuity, and durable outcome validation.

use super::{
    BackendOperation, CANCELLATION_BOUNDARY_MEDIA_TYPE, Connection, EventEnvelope, EventId,
    EventPayload, INFERENCE_EVIDENCE_MEDIA_TYPE, PARALLEL_RECON_PLANNER_TERMINAL_MAX_CLAIM_EVENTS,
    PLANNER_V2_FINALIZATION_EVIDENCE_MEDIA_TYPE, PLANNER_V2_FINALIZATION_PRODUCER,
    PLANNER_V2_OBSERVATION_PRODUCER, PLANNER_V2_UNKNOWN_PRODUCER, Path,
    PlannerV2FinalizationAuthority, PlannerV2FinalizationDisposition,
    PlannerV2ObservationAuthority, PlannerV2UnknownAuthority, RetainedCancellationBoundaryEvidence,
    RetainedInferenceEvidence, RetainedPlannerV2FinalizationEvidence,
    RetainedPlannerV2TerminalDisposition, RetryDisposition, RunId, RunState, RuntimeClockReading,
    StoreError, Transaction, UnknownInferenceBoundary, backend_error_kind_for_observation,
    decode_canonical_event, decode_stored_run, error_matches_protocol_backend_instance,
    expected_backend_selection, latest_cancellation_generation_before, latest_claim_for_run_before,
    normalized_response_usage, params, planner_run_id, planner_turn_terminal_count,
    planner_v2_cancellation_cause_before, planner_v2_not_dispatched_failure,
    planner_v2_unknown_reason, read_canonical_json_artifact, require_exact_model_provenance,
    require_running_run, response_matches_protocol_backend_instance, retry_for_backend_error,
    same_runtime_not_before, stored_event_for_run, valid_child_token_usage,
    validate_child_cancellation_cause,
};

fn planner_prepared_for_terminal(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    turn_id: birdcode_protocol::PlannerTurnId,
    prepared_event_id: EventId,
) -> Result<(EventEnvelope, birdcode_protocol::PlannerTurnPreparedV1), StoreError> {
    let run_id = planner_run_id(event)?;
    let prepared_event =
        stored_event_for_run(transaction, event.session_id, run_id, prepared_event_id)?;
    let EventPayload::PlannerTurnPreparedV1(prepared) = prepared_event.payload.clone() else {
        return Err(StoreError::InvalidStateEvent);
    };
    if prepared_event.sequence >= event.sequence
        || prepared.turn_id != turn_id
        || event.causal_parent != Some(prepared_event_id)
        || planner_turn_terminal_count(transaction, turn_id)? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok((prepared_event, prepared))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlannerTerminalClaimContinuity {
    Contiguous,
    Discontinuous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlannerTerminalClockBoundary {
    Observed,
    Unknown(UnknownInferenceBoundary),
}

pub(super) fn planner_terminal_clock_follows_prepared(
    prepared_at: &RuntimeClockReading,
    terminal_at: &RuntimeClockReading,
    boundary: PlannerTerminalClockBoundary,
) -> bool {
    if prepared_at.observed_at > terminal_at.observed_at {
        return false;
    }
    if prepared_at.runtime_instance_id == terminal_at.runtime_instance_id {
        return same_runtime_not_before(prepared_at, terminal_at);
    }
    matches!(
        boundary,
        PlannerTerminalClockBoundary::Unknown(
            UnknownInferenceBoundary::Restart
                | UnknownInferenceBoundary::Shutdown
                | UnknownInferenceBoundary::ClaimRenewalFailed
        )
    )
}

/// Replays the exact, bounded claim chain from Prepared to a terminal. A
/// terminal always needs a live latest owner. Authority gaps and takeovers are
/// retained as typed discontinuity so Observed can reject them while Unknown
/// can close the indeterminate effect without pretending continuity.
#[allow(
    clippy::too_many_lines,
    reason = "one bounded replay keeps anchor, transitions, and terminal authority in one closed proof"
)]
pub(super) fn planner_terminal_claim_continuity(
    connection: &Connection,
    terminal_event: &EventEnvelope,
    prepared_event: &EventEnvelope,
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    terminal_clock: &RuntimeClockReading,
) -> Result<PlannerTerminalClaimContinuity, StoreError> {
    let run_id = terminal_event
        .run_id
        .filter(|run_id| prepared_event.run_id == Some(*run_id))
        .ok_or(StoreError::InvalidStateEvent)?;
    let prepared_claim_event = stored_event_for_run(
        connection,
        terminal_event.session_id,
        run_id,
        prepared.claim_event_id,
    )?;
    let EventPayload::RunClaimed(prepared_claim) = &prepared_claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let latest_claim_at_prepared = latest_claim_for_run_before(
        connection,
        terminal_event.session_id,
        run_id,
        prepared_event.sequence,
    )?
    .ok_or(StoreError::InvalidStateEvent)?;
    if prepared_claim_event.sequence >= prepared_event.sequence
        || latest_claim_at_prepared.id != prepared_claim_event.id
        || prepared_claim_event.actor_id != prepared_event.actor_id
        || prepared_claim.claim_id != prepared.claim_id
        || prepared_claim.claim_generation != prepared.claim_generation
        || prepared_claim.runtime_instance_id != prepared.claim_runtime_instance_id
        || prepared_claim.cancellation_generation != prepared.cancellation_generation
        || prepared.prepared_at.runtime_instance_id != prepared_claim.runtime_instance_id
        || prepared.prepared_at.observed_at > prepared_event.occurred_at
        || prepared_claim.lease_expires_at <= prepared_event.occurred_at
        || prepared_claim.lease_expires_at <= prepared.prepared_at.observed_at
    {
        return Err(StoreError::InvalidStateEvent);
    }

    let query_limit = i64::try_from(PARALLEL_RECON_PLANNER_TERMINAL_MAX_CLAIM_EVENTS + 1)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND sequence >= ?3 AND sequence < ?4
           AND json_extract(value_json, '$.payload.type') = 'run_claimed'
         ORDER BY sequence ASC LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![
            run_id.to_string(),
            terminal_event.session_id.to_string(),
            prepared_claim_event.sequence,
            terminal_event.sequence,
            query_limit,
        ],
        |row| row.get::<_, String>(0),
    )?;
    let mut claims = Vec::new();
    for row in rows {
        claims.push(decode_canonical_event(&row?)?);
    }
    if claims.is_empty()
        || claims.len() > PARALLEL_RECON_PLANNER_TERMINAL_MAX_CLAIM_EVENTS
        || claims.first() != Some(&prepared_claim_event)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let latest_claim = latest_claim_for_run_before(
        connection,
        terminal_event.session_id,
        run_id,
        terminal_event.sequence,
    )?
    .ok_or(StoreError::InvalidStateEvent)?;
    if claims.last() != Some(&latest_claim) {
        return Err(StoreError::InvalidStateEvent);
    }

    let mut continuity = PlannerTerminalClaimContinuity::Contiguous;
    let mut prior_event = &claims[0];
    let EventPayload::RunClaimed(first_claim) = &prior_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let mut prior_claim = first_claim;
    for next_event in claims.iter().skip(1) {
        let EventPayload::RunClaimed(next_claim) = &next_event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        let expected_generation = prior_claim
            .claim_generation
            .checked_add(1)
            .ok_or(StoreError::InvalidStateEvent)?;
        if next_claim.claim_generation != expected_generation
            || next_claim.lease_expires_at <= next_event.occurred_at
            || prior_event.sequence >= next_event.sequence
        {
            return Err(StoreError::InvalidStateEvent);
        }
        if next_event.actor_id != prior_event.actor_id
            || next_claim.runtime_instance_id != prior_claim.runtime_instance_id
            || next_claim.cancellation_generation != prior_claim.cancellation_generation
            || prior_claim.lease_expires_at <= next_event.occurred_at
        {
            continuity = PlannerTerminalClaimContinuity::Discontinuous;
        }
        prior_event = next_event;
        prior_claim = next_claim;
    }
    if latest_cancellation_generation_before(
        connection,
        terminal_event.session_id,
        run_id,
        terminal_event.sequence,
    )? != prepared.cancellation_generation
    {
        continuity = PlannerTerminalClaimContinuity::Discontinuous;
    }
    if terminal_event.actor_id != prior_event.actor_id
        || terminal_clock.runtime_instance_id != prior_claim.runtime_instance_id
        || terminal_clock.observed_at > terminal_event.occurred_at
        || prior_claim.lease_expires_at <= terminal_event.occurred_at
        || prior_claim.lease_expires_at <= terminal_clock.observed_at
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(continuity)
}

fn planner_v2_protocol_failure() -> birdcode_protocol::PlannerTurnObservationV1 {
    birdcode_protocol::PlannerTurnObservationV1::Failed {
        error: birdcode_protocol::PlannerInferenceError {
            kind: birdcode_protocol::PlannerInferenceErrorKind::ProtocolViolation,
            retry: RetryDisposition::Never,
        },
    }
}

pub(super) fn planner_v2_observation_from_evidence(
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    retained: &RetainedInferenceEvidence,
) -> Result<birdcode_protocol::PlannerTurnObservationV1, StoreError> {
    Ok(match retained {
        RetainedInferenceEvidence::Response { response } => {
            let usage = normalized_response_usage(response);
            let exact = response.model_id.as_str() == prepared.backend_model.model_id
                && response.evidence.backend_id.as_str() == prepared.backend_model.backend_id
                && response_matches_protocol_backend_instance(&prepared.backend_instance, response)
                && serde_json::from_str::<serde_json::Value>(&response.raw_text)
                    .is_ok_and(|value| value == response.value)
                && usage.as_ref().is_some_and(|usage| {
                    valid_child_token_usage(usage, &prepared.token_reservation)
                });
            if exact {
                birdcode_protocol::PlannerTurnObservationV1::Succeeded {
                    reported_backend_model: prepared.backend_model.clone(),
                    token_usage: usage.ok_or(StoreError::InvalidStateEvent)?,
                }
            } else {
                planner_v2_protocol_failure()
            }
        }
        RetainedInferenceEvidence::Error { error } => {
            if error.backend_id.as_str() == prepared.backend_model.backend_id
                && error_matches_protocol_backend_instance(&prepared.backend_instance, error)
                && error.operation == BackendOperation::StructuredInference
            {
                birdcode_protocol::PlannerTurnObservationV1::Failed {
                    error: birdcode_protocol::PlannerInferenceError {
                        kind: backend_error_kind_for_observation(&error.kind),
                        retry: retry_for_backend_error(&error.kind),
                    },
                }
            } else {
                planner_v2_protocol_failure()
            }
        }
        RetainedInferenceEvidence::CancelledBeforeCall => {
            birdcode_protocol::PlannerTurnObservationV1::Failed {
                error: birdcode_protocol::PlannerInferenceError {
                    kind: birdcode_protocol::PlannerInferenceErrorKind::Cancelled,
                    retry: RetryDisposition::Never,
                },
            }
        }
        RetainedInferenceEvidence::NotDispatched { reason } => {
            birdcode_protocol::PlannerTurnObservationV1::Failed {
                error: planner_v2_not_dispatched_failure(*reason),
            }
        }
    })
}

pub(super) fn validate_existing_planner_v2_observation(
    connection: &Connection,
    artifact_root: &Path,
    run_id: RunId,
    authority: &PlannerV2ObservationAuthority,
    supplied: &RetainedInferenceEvidence,
    event: &EventEnvelope,
) -> Result<(), StoreError> {
    let EventPayload::PlannerTurnObservedV1(observed) = &event.payload else {
        return Err(StoreError::IdentifiedEventConflict);
    };
    if event.run_id != Some(run_id)
        || observed.prepared_event_id != authority.prepared_event_id
        || observed.observed_at != authority.observed_at
        || event.provenance.producer != PLANNER_V2_OBSERVATION_PRODUCER
        || event.causal_parent != Some(authority.prepared_event_id)
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    let retained = read_canonical_json_artifact::<RetainedInferenceEvidence>(
        artifact_root,
        &observed.normalized_complete_evidence_artifact,
        INFERENCE_EVIDENCE_MEDIA_TYPE,
    )?;
    let prepared_event = stored_event_for_run(
        connection,
        event.session_id,
        run_id,
        authority.prepared_event_id,
    )?;
    let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let run = decode_stored_run(&connection.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?)?;
    let continuity = planner_terminal_claim_continuity(
        connection,
        event,
        &prepared_event,
        prepared,
        &observed.observed_at,
    )?;
    if &retained != supplied
        || observed.turn_id != prepared.turn_id
        || observed.outcome != planner_v2_observation_from_evidence(prepared, &retained)?
        || continuity != PlannerTerminalClaimContinuity::Contiguous
        || !planner_terminal_clock_follows_prepared(
            &prepared.prepared_at,
            &observed.observed_at,
            PlannerTerminalClockBoundary::Observed,
        )
        || event.provenance.backend.as_ref()
            != Some(&expected_backend_selection(&run, &prepared.backend_model))
        || event.provenance.raw_artifact.as_ref()
            != Some(&observed.normalized_complete_evidence_artifact)
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    Ok(())
}

pub(super) fn validate_existing_planner_v2_unknown(
    connection: &Connection,
    artifact_root: &Path,
    run_id: RunId,
    authority: &PlannerV2UnknownAuthority,
    event: &EventEnvelope,
) -> Result<(), StoreError> {
    let EventPayload::PlannerTurnUnknownV1(unknown) = &event.payload else {
        return Err(StoreError::IdentifiedEventConflict);
    };
    if event.run_id != Some(run_id)
        || unknown.prepared_event_id != authority.prepared_event_id
        || unknown.boundary != authority.boundary
        || unknown.boundary_at != authority.boundary_at
        || unknown.reason != planner_v2_unknown_reason(authority.boundary)
        || event.provenance.producer != PLANNER_V2_UNKNOWN_PRODUCER
        || event.causal_parent != Some(authority.prepared_event_id)
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    let prepared_event = stored_event_for_run(
        connection,
        event.session_id,
        run_id,
        authority.prepared_event_id,
    )?;
    let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let cancellation = planner_v2_cancellation_cause_before(
        connection,
        event.session_id,
        run_id,
        authority.boundary,
        event.sequence,
    )?;
    let expected_generation = cancellation
        .as_ref()
        .map_or(prepared.cancellation_generation, |cause| {
            cause.cancellation_generation
        });
    let retained = read_canonical_json_artifact::<RetainedCancellationBoundaryEvidence>(
        artifact_root,
        &unknown.boundary_evidence_artifact,
        CANCELLATION_BOUNDARY_MEDIA_TYPE,
    )?;
    let run = decode_stored_run(&connection.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?)?;
    planner_terminal_claim_continuity(
        connection,
        event,
        &prepared_event,
        prepared,
        &unknown.boundary_at,
    )?;
    if unknown.turn_id != prepared.turn_id
        || unknown.cancellation != cancellation
        || !planner_terminal_clock_follows_prepared(
            &prepared.prepared_at,
            &unknown.boundary_at,
            PlannerTerminalClockBoundary::Unknown(unknown.boundary),
        )
        || retained
            != (RetainedCancellationBoundaryEvidence {
                reason: authority.boundary,
                prepared_event_id: authority.prepared_event_id,
                cancellation_generation: expected_generation,
            })
        || event.provenance.backend.as_ref()
            != Some(&expected_backend_selection(&run, &prepared.backend_model))
        || event.provenance.raw_artifact.as_ref() != Some(&unknown.boundary_evidence_artifact)
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    Ok(())
}

pub(super) fn validate_existing_planner_v2_finalization(
    artifact_root: &Path,
    run_id: RunId,
    authority: &PlannerV2FinalizationAuthority,
    event: &EventEnvelope,
) -> Result<PlannerV2FinalizationDisposition, StoreError> {
    if event.run_id != Some(run_id) || event.provenance.producer != PLANNER_V2_FINALIZATION_PRODUCER
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    match &event.payload {
        EventPayload::PlannerTurnAcceptedV1(accepted)
            if accepted.accepted_at == authority.finalized_at =>
        {
            Ok(PlannerV2FinalizationDisposition::Accepted)
        }
        EventPayload::PlannerTurnRejectedV1(rejected)
            if rejected.rejected_at == authority.finalized_at =>
        {
            Ok(PlannerV2FinalizationDisposition::Rejected(rejected.reason))
        }
        EventPayload::RunStateChanged {
            from: RunState::Running,
            to,
        } if matches!(to, RunState::Failed | RunState::Cancelled) => {
            let artifact = event
                .provenance
                .raw_artifact
                .as_ref()
                .ok_or(StoreError::IdentifiedEventConflict)?;
            let evidence = read_canonical_json_artifact::<RetainedPlannerV2FinalizationEvidence>(
                artifact_root,
                artifact,
                PLANNER_V2_FINALIZATION_EVIDENCE_MEDIA_TYPE,
            )?;
            let expected_disposition = if *to == RunState::Cancelled {
                RetainedPlannerV2TerminalDisposition::Cancelled
            } else {
                RetainedPlannerV2TerminalDisposition::Failed
            };
            if evidence.finalized_at != authority.finalized_at
                || evidence.disposition != expected_disposition
                || event.causal_parent != Some(evidence.terminal_event_id)
            {
                return Err(StoreError::IdentifiedEventConflict);
            }
            Ok(if *to == RunState::Cancelled {
                PlannerV2FinalizationDisposition::RunCancelled
            } else {
                PlannerV2FinalizationDisposition::RunFailed
            })
        }
        _ => Err(StoreError::IdentifiedEventConflict),
    }
}

pub(super) fn validate_planner_turn_observed_v1(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    observed: &birdcode_protocol::PlannerTurnObservedV1,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let (prepared_event, prepared) = planner_prepared_for_terminal(
        transaction,
        event,
        observed.turn_id,
        observed.prepared_event_id,
    )?;
    let continuity = planner_terminal_claim_continuity(
        transaction,
        event,
        &prepared_event,
        &prepared,
        &observed.observed_at,
    )?;
    let run = decode_stored_run(&transaction.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?)?;
    let expected_backend = expected_backend_selection(&run, &prepared.backend_model);
    require_exact_model_provenance(
        event,
        &expected_backend,
        Some(&observed.normalized_complete_evidence_artifact),
    )?;
    let retained = read_canonical_json_artifact::<RetainedInferenceEvidence>(
        artifact_root,
        &observed.normalized_complete_evidence_artifact,
        INFERENCE_EVIDENCE_MEDIA_TYPE,
    )?;
    let expected_outcome = planner_v2_observation_from_evidence(&prepared, &retained)?;
    if continuity != PlannerTerminalClaimContinuity::Contiguous
        || !planner_terminal_clock_follows_prepared(
            &prepared.prepared_at,
            &observed.observed_at,
            PlannerTerminalClockBoundary::Observed,
        )
        || observed.outcome != expected_outcome
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

pub(super) fn validate_planner_turn_unknown_v1(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    unknown: &birdcode_protocol::PlannerTurnUnknownV1,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let (prepared_event, prepared) = planner_prepared_for_terminal(
        transaction,
        event,
        unknown.turn_id,
        unknown.prepared_event_id,
    )?;
    planner_terminal_claim_continuity(
        transaction,
        event,
        &prepared_event,
        &prepared,
        &unknown.boundary_at,
    )?;
    let run = decode_stored_run(&transaction.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?)?;
    let expected_backend = expected_backend_selection(&run, &prepared.backend_model);
    require_exact_model_provenance(
        event,
        &expected_backend,
        Some(&unknown.boundary_evidence_artifact),
    )?;
    if let Some(cause) = &unknown.cancellation {
        validate_child_cancellation_cause(transaction, event, cause)?;
    }
    if unknown.cancellation.is_some()
        != matches!(unknown.boundary, UnknownInferenceBoundary::Cancelled)
        || !planner_terminal_clock_follows_prepared(
            &prepared.prepared_at,
            &unknown.boundary_at,
            PlannerTerminalClockBoundary::Unknown(unknown.boundary),
        )
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let boundary = read_canonical_json_artifact::<RetainedCancellationBoundaryEvidence>(
        artifact_root,
        &unknown.boundary_evidence_artifact,
        CANCELLATION_BOUNDARY_MEDIA_TYPE,
    )?;
    let expected_cancellation_generation = unknown
        .cancellation
        .as_ref()
        .map_or(prepared.cancellation_generation, |cause| {
            cause.cancellation_generation
        });
    let reason_matches = matches!(
        (unknown.reason, unknown.boundary),
        (
            birdcode_protocol::UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
            UnknownInferenceBoundary::Restart | UnknownInferenceBoundary::Shutdown,
        ) | (
            birdcode_protocol::UnknownInferenceOutcomeReason::ClaimExpiredBeforeObservation,
            UnknownInferenceBoundary::ClaimRenewalFailed,
        ) | (
            birdcode_protocol::UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate,
            UnknownInferenceBoundary::Deadline | UnknownInferenceBoundary::Cancelled,
        )
    );
    if boundary.reason != unknown.boundary
        || boundary.prepared_event_id != unknown.prepared_event_id
        || boundary.cancellation_generation != expected_cancellation_generation
        || !reason_matches
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}
