//! Typed planner-terminal mapping at the daemon/Store boundary.

use super::{ReconRuntimeClock, observe_planner_turn, recon_projection, reconcile_planner_unknown};
use crate::supervisor::{
    RunSupervisorConfig, SupervisorRunError, ensure_durable_cancellation, transition_run,
};
use birdcode_protocol::{
    EventEnvelope, EventId, EventPayload, PlannerAcceptedDirectiveV1, PlannerTurnPurposeV1, RunId,
    RunState, RuntimeInstanceId,
};
use birdcode_runtime::RuntimePaths;
use birdcode_store::{
    PlannerAcceptedDirectiveProjection, PlannerNextAction, PlannerTurnRecoveryState,
    PlannerV2FinalizationAuthority, PlannerV2FinalizationDisposition, PlannerV2NotDispatchedReason,
    PlannerV2ObservationAuthority, PlannerV2ObservedEvidence, PlannerV2UnknownAuthority,
    ReconRunProjection, Store,
};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PlannerTurnExecution {
    Accepted {
        event: EventEnvelope,
        accepted: birdcode_protocol::PlannerTurnAcceptedV1,
    },
    Rejected {
        event: EventEnvelope,
        reason: birdcode_protocol::PlannerTurnRejectionReasonV1,
    },
    Terminal {
        event: EventEnvelope,
        state: RunState,
    },
    /// The old Prepared boundary is durably terminal and Store authorizes a
    /// fresh attempt, but the current runtime/claim/scheduler must not launch
    /// it. A later supervisor pass resumes from `RetryPrepared`.
    DeferredRetry { event: EventEnvelope },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlannerRetryMode {
    Immediate,
    Deferred,
}

pub(super) enum PlannerTerminalResolution {
    RetryPrepared,
    Reproject,
    Execution(PlannerTurnExecution),
}

pub(super) enum PlannerFinalizationResolution {
    Reproject,
    Execution(PlannerTurnExecution),
}

pub(super) async fn resolve_planner_terminal_boundary(
    paths: RuntimePaths,
    run_id: RunId,
    terminal_event: EventEnvelope,
    runtime_instance_id: RuntimeInstanceId,
    retry_mode: PlannerRetryMode,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTerminalResolution, SupervisorRunError> {
    let projection = recon_projection(paths.clone(), run_id).await?;
    if matches!(
        projection.planner.next_action,
        PlannerNextAction::RetryPrepared { .. }
    ) {
        return Ok(match retry_mode {
            PlannerRetryMode::Immediate => PlannerTerminalResolution::RetryPrepared,
            PlannerRetryMode::Deferred => {
                PlannerTerminalResolution::Execution(PlannerTurnExecution::DeferredRetry {
                    event: terminal_event,
                })
            }
        });
    }
    Ok(
        match finalize_planner_turn(paths, run_id, runtime_instance_id, clock).await? {
            PlannerFinalizationResolution::Reproject => PlannerTerminalResolution::Reproject,
            PlannerFinalizationResolution::Execution(execution) => {
                PlannerTerminalResolution::Execution(execution)
            }
        },
    )
}

pub(super) async fn close_planner_not_dispatched(
    paths: RuntimePaths,
    run_id: RunId,
    prepared_event_id: EventId,
    runtime_instance_id: RuntimeInstanceId,
    reason: PlannerV2NotDispatchedReason,
    retry_mode: PlannerRetryMode,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTerminalResolution, SupervisorRunError> {
    let event = observe_planner_turn(
        paths.clone(),
        run_id,
        PlannerV2ObservationAuthority {
            event_id: EventId::new(),
            prepared_event_id,
            evidence: PlannerV2ObservedEvidence::NotDispatched { reason },
            observed_at: clock.reading(runtime_instance_id),
        },
    )
    .await?;
    resolve_planner_terminal_boundary(paths, run_id, event, runtime_instance_id, retry_mode, clock)
        .await
}

pub(super) async fn close_planner_unknown(
    paths: RuntimePaths,
    run_id: RunId,
    prepared_event_id: EventId,
    runtime_instance_id: RuntimeInstanceId,
    boundary: birdcode_protocol::UnknownInferenceBoundary,
    retry_mode: PlannerRetryMode,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTerminalResolution, SupervisorRunError> {
    let event = reconcile_planner_unknown(
        paths.clone(),
        run_id,
        PlannerV2UnknownAuthority {
            event_id: EventId::new(),
            prepared_event_id,
            boundary,
            boundary_at: clock.reading(runtime_instance_id),
        },
    )
    .await?;
    resolve_planner_terminal_boundary(paths, run_id, event, runtime_instance_id, retry_mode, clock)
        .await
}

pub(super) async fn resolve_planner_cancellation(
    paths: RuntimePaths,
    run_id: RunId,
    projection: &ReconRunProjection,
    config: &RunSupervisorConfig,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTerminalResolution, SupervisorRunError> {
    ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
    match &projection.planner.recovery {
        PlannerTurnRecoveryState::Prepared { prepared_event } => {
            let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "planner cancellation lost its Prepared event".to_owned(),
                ));
            };
            close_planner_not_dispatched(
                paths,
                run_id,
                prepared_event.id,
                prepared.claim_runtime_instance_id,
                PlannerV2NotDispatchedReason::CancellationRequested,
                PlannerRetryMode::Immediate,
                clock,
            )
            .await
        }
        PlannerTurnRecoveryState::Observed { prepared_event, .. }
        | PlannerTurnRecoveryState::Unknown { prepared_event, .. } => {
            if !matches!(
                &prepared_event.payload,
                EventPayload::PlannerTurnPreparedV1(_)
            ) {
                return Err(SupervisorRunError::InvalidState(
                    "planner cancellation lost its Prepared event".to_owned(),
                ));
            }
            let runtime_instance_id = current_claim_runtime_instance_id(projection)?;
            Ok(
                match finalize_planner_turn(paths, run_id, runtime_instance_id, clock).await? {
                    PlannerFinalizationResolution::Reproject => {
                        PlannerTerminalResolution::Reproject
                    }
                    PlannerFinalizationResolution::Execution(execution) => {
                        PlannerTerminalResolution::Execution(execution)
                    }
                },
            )
        }
        PlannerTurnRecoveryState::Accepted { .. }
        | PlannerTurnRecoveryState::Rejected { .. }
        | PlannerTurnRecoveryState::Idle => {
            transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                RunState::Cancelled,
            )
            .await?;
            Ok(PlannerTerminalResolution::Reproject)
        }
    }
}

fn current_claim_runtime_instance_id(
    projection: &ReconRunProjection,
) -> Result<RuntimeInstanceId, SupervisorRunError> {
    projection
        .guard
        .latest_claim
        .as_ref()
        .map(|claim| claim.claim.runtime_instance_id)
        .ok_or_else(|| {
            SupervisorRunError::InvalidState(
                "recon planner recovery has no current durable claim".to_owned(),
            )
        })
}

fn planner_resolution_from_finalization(
    outcome: birdcode_store::PlannerV2FinalizationOutcome,
) -> Result<PlannerFinalizationResolution, SupervisorRunError> {
    match outcome.disposition {
        PlannerV2FinalizationDisposition::Accepted => {
            if !matches!(
                &outcome.event.payload,
                EventPayload::PlannerTurnAcceptedV1(_)
            ) {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner acceptance without an accepted event".to_owned(),
                ));
            }
            Ok(PlannerFinalizationResolution::Reproject)
        }
        PlannerV2FinalizationDisposition::Rejected(reason) => {
            let EventPayload::PlannerTurnRejectedV1(rejected) = &outcome.event.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner rejection without a rejected event".to_owned(),
                ));
            };
            if rejected.reason != reason {
                return Err(SupervisorRunError::InvalidState(
                    "Store planner rejection disagrees with its rejected event".to_owned(),
                ));
            }
            Ok(PlannerFinalizationResolution::Reproject)
        }
        PlannerV2FinalizationDisposition::RunFailed
        | PlannerV2FinalizationDisposition::RunCancelled => {
            let EventPayload::RunStateChanged { to, .. } = &outcome.event.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner terminalization without a run-state event".to_owned(),
                ));
            };
            let expected = match outcome.disposition {
                PlannerV2FinalizationDisposition::RunFailed => RunState::Failed,
                PlannerV2FinalizationDisposition::RunCancelled => RunState::Cancelled,
                _ => unreachable!("terminal disposition was matched above"),
            };
            if *to != expected {
                return Err(SupervisorRunError::InvalidState(
                    "Store planner terminal disposition disagrees with run state".to_owned(),
                ));
            }
            Ok(PlannerFinalizationResolution::Execution(
                PlannerTurnExecution::Terminal {
                    event: outcome.event,
                    state: expected,
                },
            ))
        }
    }
}

pub(super) async fn finalize_planner_turn(
    paths: RuntimePaths,
    run_id: RunId,
    runtime_instance_id: RuntimeInstanceId,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerFinalizationResolution, SupervisorRunError> {
    tokio::task::spawn_blocking(
        move || -> Result<PlannerFinalizationResolution, SupervisorRunError> {
            let outcome = Store::open(paths.database(), paths.artifacts())?
                .finalize_planner_v2_turn(
                    run_id,
                    PlannerV2FinalizationAuthority {
                        event_id: EventId::new(),
                        finalized_at: clock.reading(runtime_instance_id),
                    },
                )?;
            planner_resolution_from_finalization(outcome)
        },
    )
    .await
    .map_err(|error| {
        SupervisorRunError::Background(format!("planner finalization worker failed: {error}"))
    })?
}

pub(super) fn accepted_planner_recovery(
    action: &PlannerNextAction,
    evidence: &PlannerAcceptedDirectiveProjection,
    purpose: PlannerTurnPurposeV1,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    let event = &evidence.event;
    let EventPayload::PlannerTurnAcceptedV1(accepted) = &event.payload else {
        return Err(SupervisorRunError::InvalidState(
            "accepted planner recovery carries the wrong event".to_owned(),
        ));
    };
    require_projected_accepted(action, event.id, &accepted.resolved_directive)?;
    if accepted != &evidence.accepted {
        return Err(SupervisorRunError::InvalidState(
            "accepted planner projection disagrees with its event".to_owned(),
        ));
    }
    if accepted.purpose != purpose {
        return Err(SupervisorRunError::InvalidState(
            "accepted planner turn has the wrong purpose".to_owned(),
        ));
    }
    Ok(PlannerTurnExecution::Accepted {
        event: event.clone(),
        accepted: accepted.clone(),
    })
}

pub(super) fn rejected_planner_recovery(
    action: &PlannerNextAction,
    event: &EventEnvelope,
    purpose: PlannerTurnPurposeV1,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    let EventPayload::PlannerTurnRejectedV1(rejected) = &event.payload else {
        return Err(SupervisorRunError::InvalidState(
            "rejected planner recovery carries the wrong event".to_owned(),
        ));
    };
    require_projected_rejected(action, event.id, rejected.reason)?;
    if rejected.purpose != purpose {
        return Err(SupervisorRunError::InvalidState(
            "rejected planner turn has the wrong purpose".to_owned(),
        ));
    }
    Ok(PlannerTurnExecution::Rejected {
        event: event.clone(),
        reason: rejected.reason,
    })
}

fn require_projected_accepted(
    action: &PlannerNextAction,
    event_id: EventId,
    directive: &PlannerAcceptedDirectiveV1,
) -> Result<(), SupervisorRunError> {
    match action {
        PlannerNextAction::ApplyAcceptedDirective {
            accepted_event_id,
            directive: projected_directive,
        } if *accepted_event_id == event_id && projected_directive == directive => Ok(()),
        _ => Err(SupervisorRunError::InvalidState(
            "accepted planner terminal does not match Store's projected action".to_owned(),
        )),
    }
}

fn require_projected_rejected(
    action: &PlannerNextAction,
    event_id: EventId,
    reason: birdcode_protocol::PlannerTurnRejectionReasonV1,
) -> Result<(), SupervisorRunError> {
    match action {
        PlannerNextAction::ResolveRejectedTurn {
            rejected_event_id,
            reason: projected_reason,
        } if *rejected_event_id == event_id && *projected_reason == reason => Ok(()),
        _ => Err(SupervisorRunError::InvalidState(
            "rejected planner terminal does not match Store's projected action".to_owned(),
        )),
    }
}

#[cfg(test)]
#[path = "planner_terminal_tests.rs"]
mod tests;
