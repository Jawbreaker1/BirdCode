//! Bounded model discovery and exact model-selection validation.

use super::{
    PreInferenceFailure, RunSupervisorConfig, protocol_backend_instance, wait_for_deadline,
};
use crate::backend_registry::BackendRegistry;
use birdcode_backends::{ModelBackend, ModelCatalog, ModelId, ModelLoadState, ReasoningSetting};
use birdcode_protocol::{
    BackendInstanceIdentityV1, BackendKind, ModelLineage, RootPlanningExecutionPolicy,
    RootPlanningFailurePhase, RootPlanningFailureReason, RootPlanningModelRole, RootPlanningStage,
    Run,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub(super) struct ResolvedModel {
    pub(super) model_id: ModelId,
    pub(super) backend_instance: BackendInstanceIdentityV1,
    pub(super) max_output_tokens: u32,
    pub(super) total_token_budget: u64,
    pub(super) reasoning: Option<ReasoningSetting>,
}

#[derive(Clone)]
pub(super) struct ResolvedSemanticModel {
    pub(super) backend: Arc<dyn ModelBackend>,
    pub(super) backend_instance: BackendInstanceIdentityV1,
    pub(super) model_id: ModelId,
    pub(super) total_token_budget: u64,
    pub(super) reasoning: Option<ReasoningSetting>,
}

#[derive(Clone)]
pub(super) struct ResolvedSemanticModels {
    pub(super) producer: ResolvedSemanticModel,
    pub(super) critic: ResolvedSemanticModel,
}

impl ResolvedSemanticModels {
    pub(super) fn for_stage(&self, stage: RootPlanningStage) -> &ResolvedSemanticModel {
        match stage {
            RootPlanningStage::InitialPlan | RootPlanningStage::Repair => &self.producer,
            RootPlanningStage::InitialReview | RootPlanningStage::FinalReview => &self.critic,
        }
    }
}

pub(super) enum DiscoveryEnd {
    Cancelled,
    Shutdown,
    Deadline,
    Failed(PreInferenceFailure),
}

pub(super) async fn discover_model(
    backend: Arc<dyn ModelBackend>,
    run: &Run,
    config: &RunSupervisorConfig,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
    deadline: Option<DateTime<Utc>>,
) -> Result<ResolvedModel, DiscoveryEnd> {
    if run.spec.backend.kind != BackendKind::Model {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "root planning requires a model backend",
        )));
    }
    if run.spec.backend.backend_id.as_bytes() != backend.backend_id().as_str().as_bytes() {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            format!(
                "selected backend {:?} does not match configured backend {:?}",
                run.spec.backend.backend_id,
                backend.backend_id().as_str()
            ),
        )));
    }
    let discovery = tokio::time::timeout(config.discovery_timeout, backend.discover_models());
    let catalog = tokio::select! {
        biased;
        result = discovery => match result {
            Ok(Ok(catalog)) => catalog,
            Ok(Err(error)) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::BackendDiscoveryFailed,
                error.to_string(),
            ))),
            Err(_) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::DiscoveryTimedOut,
                "model discovery timed out",
            ))),
        },
        () = cancellation.cancelled() => return Err(DiscoveryEnd::Cancelled),
        () = shutdown.cancelled() => return Err(DiscoveryEnd::Shutdown),
        () = wait_for_deadline(deadline) => return Err(DiscoveryEnd::Deadline),
    };
    if catalog.backend_id != *backend.backend_id()
        || catalog.backend_instance != *backend.instance_identity()
    {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            "model discovery returned another backend instance",
        )));
    }
    let backend_instance =
        protocol_backend_instance(&catalog.backend_instance).map_err(|detail| {
            DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidDiscoveryCatalog,
                detail,
            ))
        })?;
    resolve_catalog(&catalog, backend_instance, run, config)
}

pub(super) async fn discover_semantic_models(
    backend_registry: &BackendRegistry,
    run: &Run,
    policy: &RootPlanningExecutionPolicy,
    config: &RunSupervisorConfig,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
    deadline: Option<DateTime<Utc>>,
) -> Result<ResolvedSemanticModels, DiscoveryEnd> {
    validate_semantic_selection(run, policy)?;
    let producer_backend = backend_registry
        .resolve_lineage(&policy.producer)
        .map_err(|error| {
            DiscoveryEnd::Failed(PreInferenceFailure::for_model(
                RootPlanningFailurePhase::Preflight,
                RootPlanningFailureReason::InvalidRunConfiguration,
                RootPlanningModelRole::Producer,
                &policy.producer,
                format!("trusted producer backend route is unavailable: {error}"),
            ))
        })?;
    let critic_backend = backend_registry
        .resolve_lineage(&policy.critic)
        .map_err(|error| {
            DiscoveryEnd::Failed(PreInferenceFailure::for_model(
                RootPlanningFailurePhase::Preflight,
                RootPlanningFailureReason::InvalidRunConfiguration,
                RootPlanningModelRole::IndependentCritic,
                &policy.critic,
                format!("trusted critic backend route is unavailable: {error}"),
            ))
        })?;
    let budgets = &policy.stage_budgets;
    let producer_required = budgets
        .initial_plan_output_tokens
        .max(budgets.repair_output_tokens);
    let critic_required = budgets
        .initial_review_output_tokens
        .max(budgets.final_review_output_tokens);
    let reasoning = parse_reasoning(run.spec.backend.reasoning_effort.as_deref())?;
    let producer_discovery = discover_semantic_lineage_model(
        producer_backend,
        &policy.producer,
        producer_required,
        reasoning,
        RootPlanningModelRole::Producer,
        config,
        cancellation,
        shutdown,
        deadline,
    );
    let critic_discovery = discover_semantic_lineage_model(
        critic_backend,
        &policy.critic,
        critic_required,
        reasoning,
        RootPlanningModelRole::IndependentCritic,
        config,
        cancellation,
        shutdown,
        deadline,
    );
    // Discovery is side-effect-free, so both exact routes can be checked in
    // parallel. Results are consumed producer-first for deterministic failure
    // attribution when both complete with errors in the same poll.
    let (producer, critic) = tokio::join!(producer_discovery, critic_discovery);
    Ok(ResolvedSemanticModels {
        producer: producer?,
        critic: critic?,
    })
}

#[allow(clippy::too_many_arguments)]
async fn discover_semantic_lineage_model(
    backend: Arc<dyn ModelBackend>,
    lineage: &ModelLineage,
    required_output_tokens: u64,
    reasoning: Option<ReasoningSetting>,
    role: RootPlanningModelRole,
    config: &RunSupervisorConfig,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
    deadline: Option<DateTime<Utc>>,
) -> Result<ResolvedSemanticModel, DiscoveryEnd> {
    let discovery = tokio::time::timeout(config.discovery_timeout, backend.discover_models());
    let catalog = tokio::select! {
        biased;
        result = discovery => match result {
            Ok(Ok(catalog)) => catalog,
            Ok(Err(error)) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::for_model(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::BackendDiscoveryFailed,
                role,
                lineage,
                error.to_string(),
            ))),
            Err(_) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::for_model(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::DiscoveryTimedOut,
                role,
                lineage,
                "model discovery timed out",
            ))),
        },
        () = cancellation.cancelled() => return Err(DiscoveryEnd::Cancelled),
        () = shutdown.cancelled() => return Err(DiscoveryEnd::Shutdown),
        () = wait_for_deadline(deadline) => return Err(DiscoveryEnd::Deadline),
    };
    if catalog.backend_id != *backend.backend_id()
        || catalog.backend_instance != *backend.instance_identity()
        || catalog.models.len() > config.max_discovered_models
    {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::for_model(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            role,
            lineage,
            "semantic planning discovery returned an invalid bounded backend-instance catalog",
        )));
    }
    let backend_instance =
        protocol_backend_instance(&catalog.backend_instance).map_err(|detail| {
            DiscoveryEnd::Failed(PreInferenceFailure::for_model(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidDiscoveryCatalog,
                role,
                lineage,
                detail,
            ))
        })?;
    resolve_semantic_lineage_model(
        &catalog,
        lineage,
        required_output_tokens,
        reasoning,
        role,
        backend,
        backend_instance,
    )
}

fn validate_semantic_selection(
    run: &Run,
    policy: &RootPlanningExecutionPolicy,
) -> Result<(), DiscoveryEnd> {
    let budgets = &policy.stage_budgets;
    let aggregate = [
        budgets.initial_plan_output_tokens,
        budgets.initial_review_output_tokens,
        budgets.repair_output_tokens,
        budgets.final_review_output_tokens,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
    .ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "semantic planning stage budget overflow",
        ))
    })?;
    let run_model = run.spec.backend.model.as_deref();
    if run.spec.backend.kind != BackendKind::Model
        || run.spec.backend.backend_id != policy.producer.backend_id
        || run_model != Some(policy.producer.model_id.as_str())
        || policy.producer.model_id == policy.critic.model_id
        || policy.producer.deployment_id == policy.critic.deployment_id
        || policy.producer.independence_domain_id == policy.critic.independence_domain_id
        || run
            .spec
            .limits
            .max_output_tokens
            .is_some_and(|limit| limit < aggregate)
    {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "run selection, independent lineage, backend, or aggregate output budget does not match the trusted semantic-planning policy",
        )));
    }
    Ok(())
}

fn resolve_semantic_lineage_model(
    catalog: &ModelCatalog,
    lineage: &ModelLineage,
    required_output_tokens: u64,
    reasoning: Option<ReasoningSetting>,
    role: RootPlanningModelRole,
    backend: Arc<dyn ModelBackend>,
    backend_instance: BackendInstanceIdentityV1,
) -> Result<ResolvedSemanticModel, DiscoveryEnd> {
    let role_name = match role {
        RootPlanningModelRole::Producer => "producer",
        RootPlanningModelRole::IndependentCritic => "independent critic",
    };
    let mut matches = catalog.models.iter().filter(|model| {
        model.load_state == ModelLoadState::Loaded
            && model.id.as_str().as_bytes() == lineage.model_id.as_bytes()
    });
    let descriptor = matches.next().ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::for_model(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::SelectedModelUnavailable,
            role,
            lineage,
            format!(
                "configured {role_name} model {:?} is not loaded",
                lineage.model_id
            ),
        ))
    })?;
    if matches.next().is_some() {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::for_model(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            role,
            lineage,
            format!(
                "configured {role_name} model {:?} is ambiguous",
                lineage.model_id
            ),
        )));
    }
    let total_token_budget = resolved_total_token_budget(descriptor, &lineage.model_id)
        .ok_or_else(|| {
            DiscoveryEnd::Failed(PreInferenceFailure::for_model(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidRunConfiguration,
                role,
                lineage,
                format!("configured {role_name} model has no bounded context-window metadata"),
            ))
        })?;
    if total_token_budget < required_output_tokens {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::for_model(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            role,
            lineage,
            format!(
                "configured {role_name} context budget {total_token_budget} is below its stage output ceiling {required_output_tokens}"
            ),
        )));
    }
    Ok(ResolvedSemanticModel {
        backend,
        backend_instance,
        model_id: descriptor.id.clone(),
        total_token_budget,
        reasoning,
    })
}

pub(super) fn resolve_catalog(
    catalog: &ModelCatalog,
    backend_instance: BackendInstanceIdentityV1,
    run: &Run,
    config: &RunSupervisorConfig,
) -> Result<ResolvedModel, DiscoveryEnd> {
    if catalog.models.len() > config.max_discovered_models {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            format!(
                "model catalog exceeds {} entries",
                config.max_discovered_models
            ),
        )));
    }
    let selected = run.spec.backend.model.as_deref().ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "run has no selected model",
        ))
    })?;
    let mut matches = catalog.models.iter().filter(|model| {
        model.load_state == ModelLoadState::Loaded
            && model.id.as_str().as_bytes() == selected.as_bytes()
    });
    let descriptor = matches.next().ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::SelectedModelUnavailable,
            format!("selected model {selected:?} not found"),
        ))
    })?;
    if matches.next().is_some() {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            format!("selected model {selected:?} is ambiguous"),
        )));
    }
    let max_output_tokens = run.spec.limits.max_output_tokens.map_or_else(
        || config.default_max_output_tokens,
        |limit| u32::try_from(limit).unwrap_or(u32::MAX),
    );
    if max_output_tokens == 0 {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "resolved output token ceiling is zero",
        )));
    }
    let total_token_budget =
        resolved_total_token_budget(descriptor, selected).ok_or_else(|| {
            DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidRunConfiguration,
                format!("selected model {selected:?} has no bounded context-window metadata"),
            ))
        })?;
    if total_token_budget < u64::from(max_output_tokens) {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            format!(
                "selected model {selected:?} has context budget {total_token_budget}, below the requested output ceiling {max_output_tokens}"
            ),
        )));
    }
    let reasoning = parse_reasoning(run.spec.backend.reasoning_effort.as_deref())?;
    Ok(ResolvedModel {
        model_id: descriptor.id.clone(),
        backend_instance,
        max_output_tokens,
        total_token_budget,
        reasoning,
    })
}

/// Resolves the tightest provider-reported upper bound for total input and
/// output usage. An exact loaded-instance bound is authoritative; otherwise a
/// single loaded instance, the largest explicitly configured loaded instance,
/// or finally the model-level maximum provides a conservative finite ceiling.
pub(super) fn resolved_total_token_budget(
    descriptor: &birdcode_backends::ModelDescriptor,
    selected_model_id: &str,
) -> Option<u64> {
    let exact_instance = descriptor
        .loaded_instances
        .iter()
        .find(|instance| instance.id.as_bytes() == selected_model_id.as_bytes())
        .and_then(|instance| instance.context_length)
        .filter(|context| *context > 0);
    let loaded_instance_bound = exact_instance.or_else(|| {
        if descriptor.loaded_instances.len() == 1 {
            descriptor.loaded_instances[0].context_length
        } else {
            descriptor
                .loaded_instances
                .iter()
                .filter_map(|instance| instance.context_length)
                .max()
        }
        .filter(|context| *context > 0)
    });
    let model_bound = descriptor
        .maximum_context_tokens
        .filter(|context| *context > 0);
    match (loaded_instance_bound, model_bound) {
        (Some(instance), Some(model)) => Some(instance.min(model)),
        (Some(instance), None) => Some(instance),
        (None, Some(model)) => Some(model),
        (None, None) => None,
    }
}

pub(super) fn parse_reasoning(
    value: Option<&str>,
) -> Result<Option<ReasoningSetting>, DiscoveryEnd> {
    value
        .map(|value| match value {
            "off" => Ok(ReasoningSetting::Off),
            "on" => Ok(ReasoningSetting::On),
            "low" => Ok(ReasoningSetting::Low),
            "medium" => Ok(ReasoningSetting::Medium),
            "high" => Ok(ReasoningSetting::High),
            _ => Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidRunConfiguration,
                format!("unsupported reasoning setting {value:?}"),
            ))),
        })
        .transpose()
}
