//! Typed planner-terminal mapping at the daemon/Store boundary.

use super::ReconRuntimeClock;
use crate::supervisor::SupervisorRunError;
use birdcode_protocol::{
    EventEnvelope, EventId, EventPayload, PlannerTurnPurposeV1, RunId, RunState, RuntimeInstanceId,
};
use birdcode_runtime::RuntimePaths;
use birdcode_store::{PlannerV2FinalizationAuthority, PlannerV2FinalizationDisposition, Store};
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

fn planner_execution_from_finalization(
    outcome: birdcode_store::PlannerV2FinalizationOutcome,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    match outcome.disposition {
        PlannerV2FinalizationDisposition::Accepted => {
            let EventPayload::PlannerTurnAcceptedV1(accepted) = &outcome.event.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner acceptance without an accepted event".to_owned(),
                ));
            };
            Ok(PlannerTurnExecution::Accepted {
                event: outcome.event.clone(),
                accepted: accepted.clone(),
            })
        }
        PlannerV2FinalizationDisposition::Rejected(reason) => {
            if !matches!(
                &outcome.event.payload,
                EventPayload::PlannerTurnRejectedV1(_)
            ) {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner rejection without a rejected event".to_owned(),
                ));
            }
            Ok(PlannerTurnExecution::Rejected {
                event: outcome.event,
                reason,
            })
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
            let state = *to;
            Ok(PlannerTurnExecution::Terminal {
                event: outcome.event,
                state,
            })
        }
    }
}

pub(super) async fn finalize_planner_turn(
    paths: RuntimePaths,
    run_id: RunId,
    runtime_instance_id: RuntimeInstanceId,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    tokio::task::spawn_blocking(move || {
        let outcome = Store::open(paths.database(), paths.artifacts())?.finalize_planner_v2_turn(
            run_id,
            PlannerV2FinalizationAuthority {
                event_id: EventId::new(),
                finalized_at: clock.reading(runtime_instance_id),
            },
        )?;
        planner_execution_from_finalization(outcome)
    })
    .await
    .map_err(|error| {
        SupervisorRunError::Background(format!("planner finalization worker failed: {error}"))
    })?
}

pub(super) fn accepted_planner_recovery(
    event: &EventEnvelope,
    purpose: PlannerTurnPurposeV1,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    let EventPayload::PlannerTurnAcceptedV1(accepted) = &event.payload else {
        return Err(SupervisorRunError::InvalidState(
            "accepted planner recovery carries the wrong event".to_owned(),
        ));
    };
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
    event: &EventEnvelope,
    purpose: PlannerTurnPurposeV1,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    let EventPayload::PlannerTurnRejectedV1(rejected) = &event.payload else {
        return Err(SupervisorRunError::InvalidState(
            "rejected planner recovery carries the wrong event".to_owned(),
        ));
    };
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
