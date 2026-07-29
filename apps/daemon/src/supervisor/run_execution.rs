//! Typed per-run route selection and top-level route execution.

use super::{
    RunCompletion, RunSupervisorConfig, SupervisorRunError, acquire_run_lock, is_terminal,
    store_phase, supervise_plan_only_run,
};
use crate::backend_registry::BackendRegistry;
#[cfg(test)]
use crate::backend_registry::BackendRouteKey;
use crate::model_call_scheduler::ModelCallScheduler;
use birdcode_backends::ModelBackend;
use birdcode_protocol::{PlanAcceptanceContract, Run, RunId, RunPurpose, RunState};
use birdcode_runtime::RuntimePaths;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SupervisorRunRoute {
    PlanOnlyIndependentSemanticReviewV1,
    PlanOnlyLegacyMechanicalOnlyV4,
    ParallelRepositoryReconnaissanceV1,
}

pub(super) fn supervisor_run_route(
    purpose: RunPurpose,
    plan_acceptance: PlanAcceptanceContract,
) -> Result<SupervisorRunRoute, SupervisorRunError> {
    match purpose {
        RunPurpose::PlanOnly => match plan_acceptance {
            PlanAcceptanceContract::IndependentSemanticReviewV1 => {
                Ok(SupervisorRunRoute::PlanOnlyIndependentSemanticReviewV1)
            }
            PlanAcceptanceContract::LegacyMechanicalOnlyV4 => {
                Ok(SupervisorRunRoute::PlanOnlyLegacyMechanicalOnlyV4)
            }
            PlanAcceptanceContract::NotApplicable => Err(SupervisorRunError::InvalidState(
                "PlanOnly run cannot use the not_applicable acceptance contract".to_owned(),
            )),
        },
        RunPurpose::ParallelRepositoryReconnaissanceV1 => match plan_acceptance {
            PlanAcceptanceContract::IndependentSemanticReviewV1 => {
                Ok(SupervisorRunRoute::ParallelRepositoryReconnaissanceV1)
            }
            PlanAcceptanceContract::LegacyMechanicalOnlyV4
            | PlanAcceptanceContract::NotApplicable => Err(SupervisorRunError::InvalidState(
                "parallel repository reconnaissance requires independent semantic review"
                    .to_owned(),
            )),
        },
        RunPurpose::Execute => Err(SupervisorRunError::UnsupportedRunPurpose(
            RunPurpose::Execute,
        )),
    }
}

pub(crate) const fn purpose_has_executable_supervisor(
    purpose: RunPurpose,
    parallel_reconnaissance_available: bool,
) -> bool {
    matches!(purpose, RunPurpose::PlanOnly)
        || (parallel_reconnaissance_available
            && matches!(purpose, RunPurpose::ParallelRepositoryReconnaissanceV1))
}

async fn load_run_for_supervisor_dispatch(
    paths: RuntimePaths,
    run_id: RunId,
) -> Result<Run, SupervisorRunError> {
    store_phase(paths, move |store| {
        store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))
    })
    .await
}

/// Drives the independent root-planning prerequisite, then pauses at the
/// still-disabled reconnaissance product boundary. Root-planning replay is
/// itself durable, so an accepted root plan is observed rather than repeated
/// on every subsequent supervisor pass.
async fn supervise_parallel_repository_reconnaissance_v1(
    paths: RuntimePaths,
    backend_registry: BackendRegistry,
    backend: Arc<dyn ModelBackend>,
    run_id: RunId,
    model_calls: ModelCallScheduler,
    config: RunSupervisorConfig,
    cancellation: CancellationToken,
    shutdown: CancellationToken,
) -> Result<RunCompletion, SupervisorRunError> {
    let run = load_run_for_supervisor_dispatch(paths.clone(), run_id).await?;
    crate::recon::preflight_recon_budget(&run)?;
    crate::recon::preflight_recon_claim_adoption_budget(&run, config.claim_lease)?;
    if is_terminal(run.state) {
        return Ok(RunCompletion::AlreadyTerminal(run.state));
    }

    let completion = Box::pin(supervise_plan_only_run(
        paths.clone(),
        backend_registry,
        backend,
        model_calls,
        config,
        run_id,
        cancellation,
        shutdown,
    ))
    .await?;
    if completion != RunCompletion::Paused {
        return Ok(completion);
    }
    let projection = store_phase(paths, move |store| {
        store
            .recon_run_projection(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState("recon run is missing".to_owned()))
    })
    .await?;
    if projection.run_state != RunState::Running || projection.planner.accepted_root_plan.is_none()
    {
        return Err(SupervisorRunError::InvalidState(
            "recon root-planning phase paused without an accepted durable root plan".to_owned(),
        ));
    }

    // Snapshot/planner/child/gate execution remains fail-closed until its
    // Store-total vertical and deterministic E2E proof are complete.
    Ok(RunCompletion::Paused)
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
pub(super) async fn supervise_run(
    paths: RuntimePaths,
    backend: Arc<dyn ModelBackend>,
    model_calls: ModelCallScheduler,
    config: RunSupervisorConfig,
    run_id: RunId,
    cancellation: CancellationToken,
    shutdown: CancellationToken,
    parallel_reconnaissance_available: bool,
) -> Result<RunCompletion, SupervisorRunError> {
    let primary = BackendRouteKey::from_instance(backend.instance_identity());
    let backend_registry = BackendRegistry::new([Arc::clone(&backend)], Some(primary))
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    supervise_run_with_registry(
        paths,
        backend_registry,
        backend,
        model_calls,
        config,
        run_id,
        cancellation,
        shutdown,
        parallel_reconnaissance_available,
    )
    .await
}

#[allow(clippy::too_many_lines)]
pub(super) async fn supervise_run_with_registry(
    paths: RuntimePaths,
    backend_registry: BackendRegistry,
    backend: Arc<dyn ModelBackend>,
    model_calls: ModelCallScheduler,
    config: RunSupervisorConfig,
    run_id: RunId,
    cancellation: CancellationToken,
    shutdown: CancellationToken,
    parallel_reconnaissance_available: bool,
) -> Result<RunCompletion, SupervisorRunError> {
    let Some(_lock) = acquire_run_lock(paths.clone(), run_id).await? else {
        return Ok(RunCompletion::Contended);
    };

    let run = load_run_for_supervisor_dispatch(paths.clone(), run_id).await?;
    let route = supervisor_run_route(run.spec.purpose, run.spec.plan_acceptance)?;
    match route {
        SupervisorRunRoute::PlanOnlyIndependentSemanticReviewV1
        | SupervisorRunRoute::PlanOnlyLegacyMechanicalOnlyV4 => {
            Box::pin(supervise_plan_only_run(
                paths,
                backend_registry,
                backend,
                model_calls,
                config,
                run_id,
                cancellation,
                shutdown,
            ))
            .await
        }
        SupervisorRunRoute::ParallelRepositoryReconnaissanceV1 => {
            if !parallel_reconnaissance_available {
                return if is_terminal(run.state) {
                    Ok(RunCompletion::AlreadyTerminal(run.state))
                } else {
                    Ok(RunCompletion::Paused)
                };
            }
            supervise_parallel_repository_reconnaissance_v1(
                paths,
                backend_registry,
                backend,
                run_id,
                model_calls,
                config,
                cancellation,
                shutdown,
            )
            .await
        }
    }
}
