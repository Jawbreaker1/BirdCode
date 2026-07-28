//! Planner-v2 replay projection, recovery state, and next-action derivation.
//!
//! See `planner_v2_preparation` for the retained-request validation dependency
//! that makes the two private modules one deliberate component.

use super::{
    BTreeMap, BTreeSet, ChildRecoveryState, ChildWorkOrderState, Connection,
    DurableRunClaimProjection, EventEnvelope, EventId, EventPayload, MAX_SQLITE_INTEGER_U64,
    OptionalExtension, PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_TURNS,
    PARALLEL_RECONNAISSANCE_V1_PLANNER_ATTEMPTS_PER_STAGE, Path,
    PlannerAcceptedDirectiveProjection, PlannerEvidenceProjection, PlannerNextAction,
    PlannerRunProjection, PlannerTerminalClaimContinuity, PlannerTerminalClockBoundary,
    PlannerTurnRecoveryState, PlannerV2PreparedMaterial, ReconRunGuardProjection,
    ReconRunProjection, RetryDisposition, RunId, RunPurpose, RunState, SessionId, StoreError,
    UnknownInferenceBoundary, accepted_root_plan_projection,
    all_model_reserved_output_tokens_for_run, decode_canonical_event, decode_run_state,
    decode_stored_run, is_terminal_run_state, latest_cancellation_for_run_before,
    latest_claim_for_run, latest_run_event, params, planner_terminal_claim_continuity,
    planner_terminal_clock_follows_prepared, planner_v2_prepared_turn_count,
    planner_v2_prepared_turn_count_for_purpose, project_child_work_order,
    read_planner_base_snapshot, recon_completion_gate_projection, validate_planner_base_authority,
    validate_planner_durable_evidence_material, validate_planner_v2_retained_prompt,
    validate_typed_artifact_refs,
};

pub(super) fn planner_v2_current_prepared_material(
    connection: &Connection,
    artifact_root: &Path,
    prepared_event: EventEnvelope,
) -> Result<PlannerV2PreparedMaterial, StoreError> {
    let run_id = prepared_event.run_id.ok_or(StoreError::InvalidStateEvent)?;
    let projection = project_recon_run(connection, artifact_root, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    if !matches!(
        &projection.planner.recovery,
        PlannerTurnRecoveryState::Prepared { prepared_event: active }
            if active.id == prepared_event.id && active == &prepared_event
    ) {
        return Err(StoreError::InvalidStateEvent);
    }
    planner_v2_committed_material(artifact_root, prepared_event)
}

pub(super) fn planner_v2_committed_material(
    artifact_root: &Path,
    prepared_event: EventEnvelope,
) -> Result<PlannerV2PreparedMaterial, StoreError> {
    let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let base = read_planner_base_snapshot(artifact_root, &prepared.base_plan)?;
    let validated = validate_planner_v2_retained_prompt(artifact_root, prepared, &base)?;
    Ok(PlannerV2PreparedMaterial {
        prepared_event,
        build_input: validated.input,
        request: validated.authoritative,
    })
}

const MAX_PLANNER_V2_REPLAY_EVENTS: u32 = PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_TURNS * 3;

#[allow(
    clippy::struct_field_names,
    reason = "the event suffix distinguishes complete envelopes from decoded payloads"
)]
#[derive(Clone)]
struct ReplayedPlannerTurn {
    prepared_event: EventEnvelope,
    observed_event: Option<EventEnvelope>,
    unknown_event: Option<EventEnvelope>,
    decision_event: Option<EventEnvelope>,
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded replay keeps the planner turn state machine closed and auditable"
)]
fn planner_v2_history(
    connection: &Connection,
    artifact_root: &Path,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Vec<ReplayedPlannerTurn>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') IN (
               'planner_turn_prepared_v1',
               'planner_turn_observed_v1',
               'planner_turn_unknown_v1',
               'planner_turn_accepted_v1',
               'planner_turn_rejected_v1'
           )
         ORDER BY sequence ASC LIMIT ?3",
    )?;
    let rows = statement
        .query_map(
            params![
                run_id.to_string(),
                session_id.to_string(),
                u64::from(MAX_PLANNER_V2_REPLAY_EVENTS) + 1,
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > MAX_PLANNER_V2_REPLAY_EVENTS as usize {
        return Err(StoreError::InvalidStateEvent);
    }

    let mut turns = Vec::<ReplayedPlannerTurn>::new();
    for json in rows {
        let event = decode_canonical_event(&json)?;
        if event.session_id != session_id || event.run_id != Some(run_id) {
            return Err(StoreError::InvalidStateEvent);
        }
        validate_typed_artifact_refs(artifact_root, &event.provenance, &event.payload)?;
        match &event.payload {
            EventPayload::PlannerTurnPreparedV1(prepared) => {
                let expected_noninitial_purpose = turns.last().and_then(|previous_turn| {
                    let EventPayload::PlannerTurnPreparedV1(previous_prepared) =
                        &previous_turn.prepared_event.payload
                    else {
                        return None;
                    };
                    let retry_terminal = previous_turn
                        .observed_event
                        .as_ref()
                        .or(previous_turn.unknown_event.as_ref())
                        .filter(|terminal| {
                            previous_turn.decision_event.is_none()
                                && planner_v2_terminal_authorizes_retry(
                                    terminal,
                                    previous_turn.prepared_event.id,
                                )
                        });
                    Some(if retry_terminal.is_some() {
                        previous_prepared.purpose
                    } else {
                        birdcode_protocol::PlannerTurnPurposeV1::EvidenceReplan
                    })
                });
                if turns.len() >= PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_TURNS as usize
                    || turns.iter().any(|turn| {
                        matches!(
                            &turn.prepared_event.payload,
                            EventPayload::PlannerTurnPreparedV1(existing)
                                if existing.turn_id == prepared.turn_id
                        )
                    })
                    || (turns.is_empty()
                        && prepared.purpose
                            != birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation)
                    || (!turns.is_empty() && Some(prepared.purpose) != expected_noninitial_purpose)
                {
                    return Err(StoreError::InvalidStateEvent);
                }
                let base = read_planner_base_snapshot(artifact_root, &prepared.base_plan)?;
                validate_planner_base_authority(connection, &event, prepared, &base)?;
                let _ = validate_planner_v2_retained_prompt(artifact_root, prepared, &base)?;
                for entry in &prepared.durable_evidence_packet.entries {
                    validate_planner_durable_evidence_material(
                        connection,
                        &event,
                        &entry.material,
                    )?;
                }
                turns.push(ReplayedPlannerTurn {
                    prepared_event: event,
                    observed_event: None,
                    unknown_event: None,
                    decision_event: None,
                });
            }
            EventPayload::PlannerTurnObservedV1(observed) => {
                let turn = turns
                    .iter_mut()
                    .find(|turn| {
                        matches!(
                            &turn.prepared_event.payload,
                            EventPayload::PlannerTurnPreparedV1(prepared)
                                if prepared.turn_id == observed.turn_id
                                    && turn.prepared_event.id == observed.prepared_event_id
                        )
                    })
                    .ok_or(StoreError::InvalidStateEvent)?;
                if turn.observed_event.is_some()
                    || turn.unknown_event.is_some()
                    || turn.decision_event.is_some()
                    || event.causal_parent != Some(turn.prepared_event.id)
                    || event.sequence <= turn.prepared_event.sequence
                {
                    return Err(StoreError::InvalidStateEvent);
                }
                let EventPayload::PlannerTurnPreparedV1(prepared) = &turn.prepared_event.payload
                else {
                    return Err(StoreError::InvalidStateEvent);
                };
                if planner_terminal_claim_continuity(
                    connection,
                    &event,
                    &turn.prepared_event,
                    prepared,
                    &observed.observed_at,
                )? != PlannerTerminalClaimContinuity::Contiguous
                    || !planner_terminal_clock_follows_prepared(
                        &prepared.prepared_at,
                        &observed.observed_at,
                        PlannerTerminalClockBoundary::Observed,
                    )
                {
                    return Err(StoreError::InvalidStateEvent);
                }
                turn.observed_event = Some(event);
            }
            EventPayload::PlannerTurnUnknownV1(unknown) => {
                let turn = turns
                    .iter_mut()
                    .find(|turn| {
                        matches!(
                            &turn.prepared_event.payload,
                            EventPayload::PlannerTurnPreparedV1(prepared)
                                if prepared.turn_id == unknown.turn_id
                                    && turn.prepared_event.id == unknown.prepared_event_id
                        )
                    })
                    .ok_or(StoreError::InvalidStateEvent)?;
                if turn.observed_event.is_some()
                    || turn.unknown_event.is_some()
                    || turn.decision_event.is_some()
                    || event.causal_parent != Some(turn.prepared_event.id)
                    || event.sequence <= turn.prepared_event.sequence
                {
                    return Err(StoreError::InvalidStateEvent);
                }
                let EventPayload::PlannerTurnPreparedV1(prepared) = &turn.prepared_event.payload
                else {
                    return Err(StoreError::InvalidStateEvent);
                };
                planner_terminal_claim_continuity(
                    connection,
                    &event,
                    &turn.prepared_event,
                    prepared,
                    &unknown.boundary_at,
                )?;
                if !planner_terminal_clock_follows_prepared(
                    &prepared.prepared_at,
                    &unknown.boundary_at,
                    PlannerTerminalClockBoundary::Unknown(unknown.boundary),
                ) {
                    return Err(StoreError::InvalidStateEvent);
                }
                turn.unknown_event = Some(event);
            }
            EventPayload::PlannerTurnAcceptedV1(accepted) => {
                let turn_id = accepted.turn_id;
                attach_planner_decision(&mut turns, event, turn_id, true)?;
            }
            EventPayload::PlannerTurnRejectedV1(rejected) => {
                let turn_id = rejected.turn_id;
                attach_planner_decision(&mut turns, event, turn_id, false)?;
            }
            _ => return Err(StoreError::InvalidStateEvent),
        }
    }
    Ok(turns)
}

fn attach_planner_decision(
    turns: &mut [ReplayedPlannerTurn],
    decision_event: EventEnvelope,
    turn_id: birdcode_protocol::PlannerTurnId,
    accepted: bool,
) -> Result<(), StoreError> {
    let turn = turns
        .iter_mut()
        .find(|turn| {
            matches!(
                &turn.prepared_event.payload,
                EventPayload::PlannerTurnPreparedV1(prepared) if prepared.turn_id == turn_id
            )
        })
        .ok_or(StoreError::InvalidStateEvent)?;
    let observed_event = turn
        .observed_event
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    let exact = match (&decision_event.payload, &observed_event.payload) {
        (
            EventPayload::PlannerTurnAcceptedV1(decision),
            EventPayload::PlannerTurnObservedV1(observed),
        ) if accepted => {
            decision.prepared_event_id == turn.prepared_event.id
                && decision.observed_event_id == observed_event.id
                && observed.turn_id == turn_id
                && matches!(
                    observed.outcome,
                    birdcode_protocol::PlannerTurnObservationV1::Succeeded { .. }
                )
        }
        (
            EventPayload::PlannerTurnRejectedV1(decision),
            EventPayload::PlannerTurnObservedV1(observed),
        ) if !accepted => {
            decision.prepared_event_id == turn.prepared_event.id
                && decision.observed_event_id == observed_event.id
                && observed.turn_id == turn_id
                && matches!(
                    observed.outcome,
                    birdcode_protocol::PlannerTurnObservationV1::Succeeded { .. }
                )
        }
        _ => false,
    };
    if !exact
        || turn.unknown_event.is_some()
        || turn.decision_event.is_some()
        || decision_event.causal_parent != Some(observed_event.id)
        || decision_event.sequence <= observed_event.sequence
    {
        return Err(StoreError::InvalidStateEvent);
    }
    turn.decision_event = Some(decision_event);
    Ok(())
}

pub(super) fn latest_child_terminal_sequence(
    connection: &Connection,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<u64>, StoreError> {
    connection
        .query_row(
            "SELECT MAX(sequence) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'child_execution_finished'",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

#[allow(
    clippy::too_many_lines,
    reason = "the projection keeps run guard, exact turn envelopes, and next action atomic"
)]
pub(super) fn project_recon_run(
    connection: &Connection,
    artifact_root: &Path,
    run_id: RunId,
) -> Result<Option<ReconRunProjection>, StoreError> {
    let row = connection
        .query_row(
            "SELECT runs.value_json, run_state_projection.state,
                    run_state_projection.state_sequence
             FROM runs
             JOIN run_state_projection
               ON run_state_projection.run_id = runs.id
              AND run_state_projection.session_id = runs.session_id
             WHERE runs.id = ?1",
            [run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((run_json, state, state_sequence)) = row else {
        return Ok(None);
    };
    let run = decode_stored_run(&run_json)?;
    if run.id != run_id || run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1 {
        return Err(StoreError::InvalidStateEvent);
    }
    let session_id = run.spec.session_id;
    let run_state = decode_run_state(&state)?;
    let last_event = latest_run_event(connection, session_id, run_id)?;
    let latest_claim = latest_claim_for_run(connection, session_id, run_id)?
        .map(|event| {
            let EventPayload::RunClaimed(claim) = &event.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            Ok(DurableRunClaimProjection {
                event: event.clone(),
                claim: claim.clone(),
            })
        })
        .transpose()?;
    let cancellation_event =
        latest_cancellation_for_run_before(connection, session_id, run_id, MAX_SQLITE_INTEGER_U64)?;
    let cancellation_generation =
        cancellation_event
            .as_ref()
            .map_or(0, |event| match &event.payload {
                EventPayload::CancellationRequested(requested) => requested.cancellation_generation,
                _ => 0,
            });
    if cancellation_event.is_some() && cancellation_generation == 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    let claim_matches_cancellation_generation = latest_claim
        .as_ref()
        .is_some_and(|claim| claim.claim.cancellation_generation == cancellation_generation);
    let terminal_state_event = if is_terminal_run_state(run_state) {
        let json = connection
            .query_row(
                "SELECT value_json FROM events
                 WHERE run_id = ?1 AND session_id = ?2 AND sequence = ?3",
                params![run_id.to_string(), session_id.to_string(), state_sequence],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(StoreError::InvalidStateEvent)?;
        let event = decode_canonical_event(&json)?;
        if !matches!(
            &event.payload,
            EventPayload::RunStateChanged { to, .. } if *to == run_state
        ) {
            return Err(StoreError::InvalidStateEvent);
        }
        Some(event)
    } else {
        None
    };

    let accepted_root_plan = accepted_root_plan_projection(connection, session_id, run_id)?;
    let completion_gate =
        recon_completion_gate_projection(connection, artifact_root, session_id, run_id)?;
    let turns = planner_v2_history(connection, artifact_root, session_id, run_id)?;
    let prepared_turn_count =
        u32::try_from(turns.len()).map_err(|_| StoreError::InvalidStateEvent)?;
    let latest_turn = turns.last();
    let latest_prepared = latest_turn
        .map(|turn| match &turn.prepared_event.payload {
            EventPayload::PlannerTurnPreparedV1(prepared) => Ok(prepared),
            _ => Err(StoreError::InvalidStateEvent),
        })
        .transpose()?;
    let latest_accepted = turns
        .iter()
        .rev()
        .filter_map(|turn| turn.decision_event.as_ref())
        .find_map(|event| match &event.payload {
            EventPayload::PlannerTurnAcceptedV1(accepted) => Some((event, accepted)),
            _ => None,
        });
    let latest_accepted_plan = latest_accepted.map(|(_, accepted)| accepted.resulting_plan.clone());
    let current_base_plan = latest_accepted_plan
        .clone()
        .or_else(|| latest_prepared.map(|prepared| prepared.base_plan.clone()));
    let latest_evidence = latest_turn
        .map(|turn| match &turn.prepared_event.payload {
            EventPayload::PlannerTurnPreparedV1(prepared) => Ok(PlannerEvidenceProjection {
                prepared_event_id: turn.prepared_event.id,
                packet: prepared.durable_evidence_packet.clone(),
                packet_artifact: prepared.durable_evidence_packet_artifact.clone(),
                packet_digest: prepared.durable_evidence_packet_digest.clone(),
                delta: prepared.durable_evidence_delta.clone(),
                delta_artifact: prepared.durable_evidence_delta_artifact.clone(),
                delta_digest: prepared.durable_evidence_delta_digest.clone(),
            }),
            _ => Err(StoreError::InvalidStateEvent),
        })
        .transpose()?;
    let accepted_directive =
        latest_accepted.map(|(event, accepted)| PlannerAcceptedDirectiveProjection {
            event: event.clone(),
            accepted: accepted.clone(),
        });
    let recovery = latest_turn.map_or(Ok(PlannerTurnRecoveryState::Idle), |turn| {
        match (
            turn.observed_event.as_ref(),
            turn.unknown_event.as_ref(),
            turn.decision_event.as_ref(),
        ) {
            (None, None, None) => Ok(PlannerTurnRecoveryState::Prepared {
                prepared_event: turn.prepared_event.clone(),
            }),
            (Some(observed), None, None) => Ok(PlannerTurnRecoveryState::Observed {
                prepared_event: turn.prepared_event.clone(),
                observed_event: observed.clone(),
            }),
            (None, Some(unknown), None) => Ok(PlannerTurnRecoveryState::Unknown {
                prepared_event: turn.prepared_event.clone(),
                unknown_event: unknown.clone(),
            }),
            (Some(observed), None, Some(decision)) => match &decision.payload {
                EventPayload::PlannerTurnAcceptedV1(_) => Ok(PlannerTurnRecoveryState::Accepted {
                    prepared_event: turn.prepared_event.clone(),
                    observed_event: observed.clone(),
                    accepted_event: decision.clone(),
                }),
                EventPayload::PlannerTurnRejectedV1(_) => Ok(PlannerTurnRecoveryState::Rejected {
                    prepared_event: turn.prepared_event.clone(),
                    observed_event: observed.clone(),
                    rejected_event: decision.clone(),
                }),
                _ => Err(StoreError::InvalidStateEvent),
            },
            _ => Err(StoreError::InvalidStateEvent),
        }
    })?;

    let next_action = if let Some(terminal) = &terminal_state_event {
        PlannerNextAction::Terminal {
            state: run_state,
            state_event_id: terminal.id,
        }
    } else if let Some(cancellation) = &cancellation_event {
        PlannerNextAction::CancellationRequested {
            cancellation_event_id: cancellation.id,
            cancellation_generation,
        }
    } else if run_state != RunState::Running || !claim_matches_cancellation_generation {
        PlannerNextAction::AwaitRunClaim
    } else if let Some(gate) = &completion_gate {
        PlannerNextAction::FinalizeCompletionGate {
            gate_event_id: gate.event.id,
        }
    } else if accepted_root_plan.is_none() {
        PlannerNextAction::AwaitAcceptedRootPlan
    } else {
        planner_next_action(
            connection,
            artifact_root,
            session_id,
            run_id,
            latest_turn,
            latest_prepared,
        )?
    };

    Ok(Some(ReconRunProjection {
        session_id,
        run_id,
        run_state,
        last_event,
        guard: ReconRunGuardProjection {
            latest_claim,
            cancellation_event,
            cancellation_generation,
            claim_matches_cancellation_generation,
            terminal_state_event,
        },
        planner: PlannerRunProjection {
            accepted_root_plan,
            current_base_plan,
            latest_accepted_plan,
            latest_evidence,
            accepted_directive,
            recovery,
            next_action,
            prepared_turn_count,
        },
        completion_gate,
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed action projection enumerates every durable planner boundary"
)]
fn planner_next_action(
    connection: &Connection,
    artifact_root: &Path,
    session_id: SessionId,
    run_id: RunId,
    latest_turn: Option<&ReplayedPlannerTurn>,
    latest_prepared: Option<&birdcode_protocol::PlannerTurnPreparedV1>,
) -> Result<PlannerNextAction, StoreError> {
    let Some(turn) = latest_turn else {
        return Ok(PlannerNextAction::ReadyToPrepare {
            purpose: birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation,
            base_plan: None,
        });
    };
    let prepared = latest_prepared.ok_or(StoreError::InvalidStateEvent)?;
    let run = decode_stored_run(&connection.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?)?;
    let prepared_turn_count = planner_v2_prepared_turn_count(connection, session_id, run_id)?;
    let prepared_stage_turn_count = planner_v2_prepared_turn_count_for_purpose(
        connection,
        session_id,
        run_id,
        prepared.purpose,
    )?;
    let already_reserved_output =
        all_model_reserved_output_tokens_for_run(connection, session_id, run_id)?;
    let retry_capacity = planner_v2_retry_has_capacity(
        prepared_turn_count,
        prepared_stage_turn_count,
        already_reserved_output,
        prepared.token_reservation.max_output_tokens,
        run.spec.limits.max_output_tokens,
    );
    if let Some(unknown) = &turn.unknown_event {
        let EventPayload::PlannerTurnUnknownV1(unknown_payload) = &unknown.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        return Ok(
            if retry_capacity
                && matches!(
                    unknown_payload.boundary,
                    UnknownInferenceBoundary::Restart
                        | UnknownInferenceBoundary::Shutdown
                        | UnknownInferenceBoundary::ClaimRenewalFailed
                )
            {
                PlannerNextAction::RetryPrepared {
                    purpose: prepared.purpose,
                    base_plan: prepared.base_plan.clone(),
                    prior_prepared_event_id: turn.prepared_event.id,
                    terminal_event_id: unknown.id,
                }
            } else {
                PlannerNextAction::ReconcileUnknown {
                    turn_id: prepared.turn_id,
                    unknown_event_id: unknown.id,
                }
            },
        );
    }
    let Some(observed) = &turn.observed_event else {
        return Ok(PlannerNextAction::RecoverPrepared {
            turn_id: prepared.turn_id,
            prepared_event_id: turn.prepared_event.id,
        });
    };
    let EventPayload::PlannerTurnObservedV1(observed_payload) = &observed.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let Some(decision) = &turn.decision_event else {
        return Ok(match &observed_payload.outcome {
            birdcode_protocol::PlannerTurnObservationV1::Succeeded { .. } => {
                PlannerNextAction::ValidateObserved {
                    turn_id: prepared.turn_id,
                    observed_event_id: observed.id,
                }
            }
            birdcode_protocol::PlannerTurnObservationV1::Failed { error }
                if error.retry == RetryDisposition::RequiresNewAttempt && retry_capacity =>
            {
                PlannerNextAction::RetryPrepared {
                    purpose: prepared.purpose,
                    base_plan: prepared.base_plan.clone(),
                    prior_prepared_event_id: turn.prepared_event.id,
                    terminal_event_id: observed.id,
                }
            }
            birdcode_protocol::PlannerTurnObservationV1::Failed { .. } => {
                PlannerNextAction::FinalizeObservedFailure {
                    turn_id: prepared.turn_id,
                    observed_event_id: observed.id,
                }
            }
        });
    };
    match &decision.payload {
        EventPayload::PlannerTurnAcceptedV1(accepted) => {
            let has_new_child_evidence = match (accepted.purpose, &accepted.resolved_directive) {
                (
                    birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation,
                    birdcode_protocol::PlannerAcceptedDirectiveV1::Delegate { delegations },
                ) => accepted_delegate_children_are_terminal(
                    connection,
                    artifact_root,
                    session_id,
                    run_id,
                    decision.id,
                    decision.sequence,
                    accepted.turn_id,
                    delegations,
                )?,
                _ => latest_child_terminal_sequence(connection, session_id, run_id)?
                    .is_some_and(|sequence| sequence > turn.prepared_event.sequence),
            };
            if has_new_child_evidence {
                Ok(PlannerNextAction::ReadyToPrepare {
                    purpose: birdcode_protocol::PlannerTurnPurposeV1::EvidenceReplan,
                    base_plan: Some(accepted.resulting_plan.clone()),
                })
            } else {
                Ok(PlannerNextAction::ApplyAcceptedDirective {
                    accepted_event_id: decision.id,
                    directive: accepted.resolved_directive.clone(),
                })
            }
        }
        EventPayload::PlannerTurnRejectedV1(rejected) => {
            Ok(PlannerNextAction::ResolveRejectedTurn {
                rejected_event_id: decision.id,
                reason: rejected.reason,
            })
        }
        _ => Err(StoreError::InvalidStateEvent),
    }
}

/// Returns true only when every work order in one accepted initial Delegate
/// has been consumed by one exact v2 child authorization, one exact issuance,
/// and a terminal Store-derived child projection. Missing authorization,
/// issuance, or terminal state is ordinary incomplete work; duplicate or
/// mismatched durable authority fails closed.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the closed planner-to-child terminal join keeps every durable authority anchor explicit"
)]
pub(super) fn accepted_delegate_children_are_terminal(
    connection: &Connection,
    artifact_root: &Path,
    session_id: SessionId,
    run_id: RunId,
    accepted_event_id: EventId,
    accepted_event_sequence: u64,
    planner_turn_id: birdcode_protocol::PlannerTurnId,
    delegations: &[birdcode_protocol::PlannerAcceptedDelegationV1],
) -> Result<bool, StoreError> {
    let mut expected = BTreeMap::new();
    for delegation in delegations {
        for work_order in &delegation.work_orders {
            if expected
                .insert(
                    work_order.work_order_id.clone(),
                    (delegation.directive_id, work_order),
                )
                .is_some()
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
    }
    if expected.is_empty() {
        return Err(StoreError::InvalidStateEvent);
    }

    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type')
                 = 'child_delegation_authorized_v2'
           AND json_extract(
                 value_json,
                 '$.payload.data.accepted_planner_turn_event_id'
               ) = ?3
         ORDER BY sequence ASC",
    )?;
    let authorization_rows = statement
        .query_map(
            params![
                run_id.to_string(),
                session_id.to_string(),
                accepted_event_id.to_string(),
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut matched_work_orders = BTreeSet::new();
    for json in authorization_rows {
        let authorization_event = decode_canonical_event(&json)?;
        let EventPayload::ChildDelegationAuthorizedV2(authorization) = &authorization_event.payload
        else {
            return Err(StoreError::InvalidStateEvent);
        };
        let Some((expected_directive_id, expected_work_order)) =
            expected.get(&authorization.planner_work_order.work_order_id)
        else {
            return Err(StoreError::InvalidStateEvent);
        };
        if authorization_event.session_id != session_id
            || authorization_event.run_id != Some(run_id)
            || authorization_event.sequence <= accepted_event_sequence
            || authorization.accepted_planner_turn_event_id != accepted_event_id
            || authorization.planner_turn_id != planner_turn_id
            || authorization.delegate_directive_id != *expected_directive_id
            || authorization.planner_work_order != **expected_work_order
            || !matched_work_orders.insert(authorization.planner_work_order.work_order_id.clone())
        {
            return Err(StoreError::InvalidStateEvent);
        }

        let mut issued_statement = connection.prepare(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'child_work_order_issued'
               AND json_extract(value_json, '$.payload.data.authorization_event_id') = ?3
             ORDER BY sequence ASC LIMIT 2",
        )?;
        let issued_rows = issued_statement
            .query_map(
                params![
                    run_id.to_string(),
                    session_id.to_string(),
                    authorization_event.id.to_string(),
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let [issued_json] = issued_rows.as_slice() else {
            return if issued_rows.is_empty() {
                Ok(false)
            } else {
                Err(StoreError::InvalidStateEvent)
            };
        };
        let issued_event = decode_canonical_event(issued_json)?;
        let EventPayload::ChildWorkOrderIssued(issued) = &issued_event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        if issued_event.sequence <= authorization_event.sequence
            || issued.authorization_event_id != authorization_event.id
            || issued.spec != authorization.spec
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let Some(projection) = project_child_work_order(
            connection,
            artifact_root,
            run_id,
            authorization.spec.work_order_id,
        )?
        else {
            return Ok(false);
        };
        if projection.issued_event != issued_event
            || projection.spec != authorization.spec
            || !matches!(
                projection.state,
                ChildWorkOrderState::Succeeded
                    | ChildWorkOrderState::Failed
                    | ChildWorkOrderState::Cancelled
            )
            || !matches!(projection.recovery, ChildRecoveryState::Terminal { .. })
        {
            return Ok(false);
        }
    }
    Ok(matched_work_orders.len() == expected.len())
}

pub(super) fn planner_v2_retry_has_capacity(
    prepared_turn_count: u64,
    prepared_stage_turn_count: u64,
    already_reserved_output: u64,
    next_reserved_output: u64,
    aggregate_limit: Option<u64>,
) -> bool {
    prepared_turn_count < u64::from(PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_TURNS)
        && prepared_stage_turn_count
            < u64::from(PARALLEL_RECONNAISSANCE_V1_PLANNER_ATTEMPTS_PER_STAGE)
        && aggregate_limit.is_none_or(|limit| {
            already_reserved_output
                .checked_add(next_reserved_output)
                .is_some_and(|required| required <= limit)
        })
}

pub(super) fn planner_v2_terminal_authorizes_retry(
    terminal: &EventEnvelope,
    prepared_event_id: EventId,
) -> bool {
    match &terminal.payload {
        EventPayload::PlannerTurnObservedV1(observed) => {
            observed.prepared_event_id == prepared_event_id
                && matches!(
                    &observed.outcome,
                    birdcode_protocol::PlannerTurnObservationV1::Failed { error }
                        if error.retry == RetryDisposition::RequiresNewAttempt
                )
        }
        EventPayload::PlannerTurnUnknownV1(unknown) => {
            unknown.prepared_event_id == prepared_event_id
                && matches!(
                    unknown.boundary,
                    UnknownInferenceBoundary::Restart
                        | UnknownInferenceBoundary::Shutdown
                        | UnknownInferenceBoundary::ClaimRenewalFailed
                )
        }
        _ => false,
    }
}
