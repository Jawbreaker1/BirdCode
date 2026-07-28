//! Root-planning-v1 stage contracts, policy validation, and artifact accounting.

use super::{
    ActorId, ArtifactRef, ArtifactValidationCost, BTreeSet, EventEnvelope, EventPayload,
    InferenceAttemptId, Path, PlanAcceptanceContract, PlanCandidateBinding,
    PlanSemanticReviewRejectionDisposition, PlannerStageContext, PlannerStageKind,
    ROOT_PLANNING_EXECUTION_POLICY_MEDIA_TYPE,
    ROOT_PLANNING_POLICY_V1_FINAL_REVIEW_MAX_OUTPUT_TOKENS,
    ROOT_PLANNING_POLICY_V1_INITIAL_PLAN_MAX_OUTPUT_TOKENS,
    ROOT_PLANNING_POLICY_V1_INITIAL_REVIEW_MAX_OUTPUT_TOKENS,
    ROOT_PLANNING_POLICY_V1_MAX_MODEL_CALLS, ROOT_PLANNING_POLICY_V1_MAX_REPAIRS,
    ROOT_PLANNING_POLICY_V1_MAX_REVIEW_ROUNDS, ROOT_PLANNING_POLICY_V1_REPAIR_MAX_OUTPUT_TOKENS,
    ROOT_PLANNING_POLICY_V1_SCHEMA_VERSION, RootPlanningExecutionPolicy,
    RootPlanningPromptContracts, RunId, SessionId, Sha256Digest, StoreError, Transaction,
    artifact_path_at, builtin_registry, event_by_id_for_run, plan_critic_key, plan_repair_key,
    prepared_events_for_run, prepared_inference_for_attempt, read_verified_artifact,
    require_artifact_media_type, root_planner_key, run_plan_acceptance_contract, stage_identity,
    stage_kind, valid_lineage, verify_artifact_at_root,
};

pub(super) fn stage_candidate(stage: &PlannerStageContext) -> Option<&PlanCandidateBinding> {
    match stage {
        PlannerStageContext::InitialPlan { .. } => None,
        PlannerStageContext::InitialReview { candidate, .. }
        | PlannerStageContext::Repair { candidate, .. }
        | PlannerStageContext::FinalReview { candidate, .. } => Some(candidate),
    }
}

pub(super) fn validate_candidate_binding(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    run_id: RunId,
    candidate: &PlanCandidateBinding,
) -> Result<birdcode_protocol::PlanProposalAccepted, StoreError> {
    let proposal_event = event_by_id_for_run(
        transaction,
        event.session_id,
        run_id,
        candidate.proposal_event_id,
    )?;
    let EventPayload::PlanProposalAccepted(accepted) = proposal_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if accepted.accepted_plan_revision != candidate.plan_revision
        || accepted.accepted_plan_digest != candidate.plan_digest
        || accepted.accepted_plan_artifact != candidate.plan_artifact
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(accepted)
}

fn prepared_stage_for_attempt(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    attempt_id: InferenceAttemptId,
) -> Result<PlannerStageContext, StoreError> {
    let prepared = prepared_inference_for_attempt(transaction, session_id, run_id, attempt_id)?;
    let EventPayload::PlannerInferencePrepared(prepared) = prepared.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    prepared.stage_context.ok_or(StoreError::InvalidStateEvent)
}

fn validate_reviewer_independence(
    reviewer_actor: ActorId,
    reviewer_lineage: &birdcode_protocol::ModelLineage,
    producer_stage: &PlannerStageContext,
) -> Result<(), StoreError> {
    let (producer_actor, producer_lineage, _) = stage_identity(producer_stage);
    if reviewer_actor == *producer_actor
        || reviewer_lineage.independence_domain_id == producer_lineage.independence_domain_id
        || (reviewer_lineage.backend_id == producer_lineage.backend_id
            && reviewer_lineage.model_id == producer_lineage.model_id)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_planner_stage_context(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    run_id: RunId,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
) -> Result<(), StoreError> {
    let acceptance = run_plan_acceptance_contract(transaction, event.session_id, run_id)?;
    let previous = prepared_events_for_run(transaction, event.session_id, run_id)?;
    match (acceptance, &prepared.stage_context) {
        (PlanAcceptanceContract::LegacyMechanicalOnlyV4, None) => {
            if previous.iter().any(|event| {
                matches!(
                    &event.payload,
                    EventPayload::PlannerInferencePrepared(previous)
                        if previous.stage_context.is_some()
                )
            }) {
                return Err(StoreError::InvalidStateEvent);
            }
            return Ok(());
        }
        (PlanAcceptanceContract::IndependentSemanticReviewV1, Some(_)) => {}
        _ => return Err(StoreError::InvalidStateEvent),
    }
    let Some(stage) = &prepared.stage_context else {
        return Err(StoreError::InvalidStateEvent);
    };
    if previous.len() >= 4
        || previous.iter().any(|event| {
            matches!(
                &event.payload,
                EventPayload::PlannerInferencePrepared(previous)
                    if previous.stage_context.is_none()
            )
        })
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let previous_kinds = previous
        .iter()
        .map(|event| match &event.payload {
            EventPayload::PlannerInferencePrepared(prepared) => prepared
                .stage_context
                .as_ref()
                .map(stage_kind)
                .ok_or(StoreError::InvalidStateEvent),
            _ => Err(StoreError::InvalidStateEvent),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let required_prefix: &[PlannerStageKind] = match stage {
        PlannerStageContext::InitialPlan { .. } => &[],
        PlannerStageContext::InitialReview { .. } => &[PlannerStageKind::InitialPlan],
        PlannerStageContext::Repair { .. } => &[
            PlannerStageKind::InitialPlan,
            PlannerStageKind::InitialReview,
        ],
        PlannerStageContext::FinalReview { .. } => &[
            PlannerStageKind::InitialPlan,
            PlannerStageKind::InitialReview,
            PlannerStageKind::Repair,
        ],
    };
    if previous_kinds != required_prefix {
        return Err(StoreError::InvalidStateEvent);
    }
    let (model_actor_id, lineage, execution_policy_artifact) = stage_identity(stage);
    if !valid_lineage(lineage)
        || lineage.backend_id != prepared.backend_model.backend_id
        || lineage.model_id != prepared.backend_model.model_id
        || previous.iter().any(|event| {
            matches!(
                &event.payload,
                EventPayload::PlannerInferencePrepared(previous)
                    if previous
                        .stage_context
                        .as_ref()
                        .is_some_and(|stage| stage_identity(stage).0 == model_actor_id)
            )
        })
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(first) = previous.first() {
        let EventPayload::PlannerInferencePrepared(first) = &first.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        let first_policy = first
            .stage_context
            .as_ref()
            .map(|stage| stage_identity(stage).2)
            .ok_or(StoreError::InvalidStateEvent)?;
        if first_policy != execution_policy_artifact {
            return Err(StoreError::InvalidStateEvent);
        }
    }

    match stage {
        PlannerStageContext::InitialPlan { .. } => {
            if !previous.is_empty()
                || prepared.parent_attempt_id.is_some()
                || prepared.plan_revision != 0
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        PlannerStageContext::InitialReview {
            review_round,
            candidate,
            ..
        } => {
            let parent_attempt_id = prepared
                .parent_attempt_id
                .ok_or(StoreError::InvalidStateEvent)?;
            let parent_stage = prepared_stage_for_attempt(
                transaction,
                event.session_id,
                run_id,
                parent_attempt_id,
            )?;
            let accepted = validate_candidate_binding(transaction, event, run_id, candidate)?;
            if *review_round != 1
                || !matches!(parent_stage, PlannerStageContext::InitialPlan { .. })
                || accepted.inference_attempt_id != parent_attempt_id
                || prepared.plan_revision != candidate.plan_revision
                || prepared.plan_digest != candidate.plan_digest
            {
                return Err(StoreError::InvalidStateEvent);
            }
            validate_reviewer_independence(*model_actor_id, lineage, &parent_stage)?;
        }
        PlannerStageContext::Repair {
            repair_ordinal,
            candidate,
            triggering_review_event_id,
            required_finding_ids,
            ..
        } => {
            let parent_attempt_id = prepared
                .parent_attempt_id
                .ok_or(StoreError::InvalidStateEvent)?;
            let parent_stage = prepared_stage_for_attempt(
                transaction,
                event.session_id,
                run_id,
                parent_attempt_id,
            )?;
            let PlannerStageContext::InitialReview { .. } = parent_stage else {
                return Err(StoreError::InvalidStateEvent);
            };
            let review_event = event_by_id_for_run(
                transaction,
                event.session_id,
                run_id,
                *triggering_review_event_id,
            )?;
            let EventPayload::PlanSemanticReviewRejected(review) = review_event.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            validate_candidate_binding(transaction, event, run_id, candidate)?;
            let unique_findings = required_finding_ids.iter().collect::<BTreeSet<_>>();
            let initial_stage = previous
                .first()
                .and_then(|event| match &event.payload {
                    EventPayload::PlannerInferencePrepared(prepared) => {
                        prepared.stage_context.as_ref()
                    }
                    _ => None,
                })
                .ok_or(StoreError::InvalidStateEvent)?;
            if *repair_ordinal != 1
                || review.inference_attempt_id != parent_attempt_id
                || review.disposition
                    != PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
                || review.candidate != *candidate
                || review.required_finding_ids != *required_finding_ids
                || required_finding_ids.is_empty()
                || required_finding_ids.len() > 32
                || unique_findings.len() != required_finding_ids.len()
                || required_finding_ids.iter().any(String::is_empty)
                || prepared.plan_revision != candidate.plan_revision
                || prepared.plan_digest != candidate.plan_digest
                || !matches!(initial_stage, PlannerStageContext::InitialPlan { .. })
            {
                return Err(StoreError::InvalidStateEvent);
            }
            let (_, producer_lineage, _) = stage_identity(initial_stage);
            if lineage != producer_lineage {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        PlannerStageContext::FinalReview {
            review_round,
            repair_ordinal,
            candidate,
            ..
        } => {
            let parent_attempt_id = prepared
                .parent_attempt_id
                .ok_or(StoreError::InvalidStateEvent)?;
            let parent_stage = prepared_stage_for_attempt(
                transaction,
                event.session_id,
                run_id,
                parent_attempt_id,
            )?;
            let accepted = validate_candidate_binding(transaction, event, run_id, candidate)?;
            let initial_reviewer_stage = previous
                .get(1)
                .and_then(|event| match &event.payload {
                    EventPayload::PlannerInferencePrepared(prepared) => {
                        prepared.stage_context.as_ref()
                    }
                    _ => None,
                })
                .ok_or(StoreError::InvalidStateEvent)?;
            let (_, configured_reviewer_lineage, _) = stage_identity(initial_reviewer_stage);
            if *review_round != 2
                || *repair_ordinal != 1
                || !matches!(parent_stage, PlannerStageContext::Repair { .. })
                || accepted.inference_attempt_id != parent_attempt_id
                || prepared.plan_revision != candidate.plan_revision
                || prepared.plan_digest != candidate.plan_digest
                || lineage != configured_reviewer_lineage
            {
                return Err(StoreError::InvalidStateEvent);
            }
            validate_reviewer_independence(*model_actor_id, lineage, &parent_stage)?;
        }
    }
    Ok(())
}

pub(super) fn add_stage_artifacts(
    cost: &mut ArtifactValidationCost,
    stage: &PlannerStageContext,
) -> Result<(), StoreError> {
    match stage {
        PlannerStageContext::InitialPlan {
            execution_policy_artifact,
            ..
        } => cost.add(execution_policy_artifact),
        PlannerStageContext::InitialReview {
            execution_policy_artifact,
            critic_policy_artifact,
            candidate,
            ..
        }
        | PlannerStageContext::FinalReview {
            execution_policy_artifact,
            critic_policy_artifact,
            candidate,
            ..
        } => {
            cost.add(execution_policy_artifact)?;
            cost.add(critic_policy_artifact)?;
            cost.add(&candidate.plan_artifact)
        }
        PlannerStageContext::Repair {
            execution_policy_artifact,
            candidate,
            ..
        } => {
            cost.add(execution_policy_artifact)?;
            cost.add(&candidate.plan_artifact)
        }
    }
}

pub(super) fn verify_stage_artifacts(
    artifact_root: &Path,
    stage: &PlannerStageContext,
) -> Result<(), StoreError> {
    match stage {
        PlannerStageContext::InitialPlan {
            execution_policy_artifact,
            ..
        } => verify_artifact_at_root(artifact_root, execution_policy_artifact),
        PlannerStageContext::InitialReview {
            execution_policy_artifact,
            critic_policy_artifact,
            candidate,
            ..
        }
        | PlannerStageContext::FinalReview {
            execution_policy_artifact,
            critic_policy_artifact,
            candidate,
            ..
        } => {
            verify_artifact_at_root(artifact_root, execution_policy_artifact)?;
            verify_artifact_at_root(artifact_root, critic_policy_artifact)?;
            verify_artifact_at_root(artifact_root, &candidate.plan_artifact)
        }
        PlannerStageContext::Repair {
            execution_policy_artifact,
            candidate,
            ..
        } => {
            verify_artifact_at_root(artifact_root, execution_policy_artifact)?;
            verify_artifact_at_root(artifact_root, &candidate.plan_artifact)
        }
    }
}

pub(super) fn validate_stage_execution_policy(
    artifact_root: &Path,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    stage: &PlannerStageContext,
    run_max_output_tokens: Option<u64>,
) -> Result<(), StoreError> {
    let (_, _, execution_policy_artifact) = stage_identity(stage);
    require_artifact_media_type(
        execution_policy_artifact,
        ROOT_PLANNING_EXECUTION_POLICY_MEDIA_TYPE,
    )?;
    let bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &execution_policy_artifact.sha256)?,
        execution_policy_artifact,
    )?;
    let policy = serde_json::from_slice::<RootPlanningExecutionPolicy>(&bytes)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let canonical_policy =
        serde_json::to_vec(&policy).map_err(|_| StoreError::InvalidStateEvent)?;
    let budgets = &policy.stage_budgets;
    let total_budget = [
        budgets.initial_plan_output_tokens,
        budgets.initial_review_output_tokens,
        budgets.repair_output_tokens,
        budgets.final_review_output_tokens,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
    .ok_or(StoreError::InvalidStateEvent)?;
    let expected_prompt_contracts = builtin_root_planning_prompt_contracts()?;
    if canonical_policy != bytes
        || policy.schema_version != ROOT_PLANNING_POLICY_V1_SCHEMA_VERSION
        || policy.max_model_calls != ROOT_PLANNING_POLICY_V1_MAX_MODEL_CALLS
        || policy.max_repairs != ROOT_PLANNING_POLICY_V1_MAX_REPAIRS
        || policy.max_review_rounds != ROOT_PLANNING_POLICY_V1_MAX_REVIEW_ROUNDS
        || total_budget == 0
        || budgets.initial_plan_output_tokens == 0
        || budgets.initial_plan_output_tokens
            > u64::from(ROOT_PLANNING_POLICY_V1_INITIAL_PLAN_MAX_OUTPUT_TOKENS)
        || budgets.initial_review_output_tokens == 0
        || budgets.initial_review_output_tokens
            > u64::from(ROOT_PLANNING_POLICY_V1_INITIAL_REVIEW_MAX_OUTPUT_TOKENS)
        || budgets.repair_output_tokens == 0
        || budgets.repair_output_tokens
            > u64::from(ROOT_PLANNING_POLICY_V1_REPAIR_MAX_OUTPUT_TOKENS)
        || budgets.final_review_output_tokens == 0
        || budgets.final_review_output_tokens
            > u64::from(ROOT_PLANNING_POLICY_V1_FINAL_REVIEW_MAX_OUTPUT_TOKENS)
        || run_max_output_tokens.is_some_and(|maximum| total_budget > maximum)
        || policy.prompt_contracts != expected_prompt_contracts
        || !valid_lineage(&policy.producer)
        || !valid_lineage(&policy.critic)
        || policy.producer.model_id == policy.critic.model_id
        || policy.producer.deployment_id == policy.critic.deployment_id
        || policy.producer.independence_domain_id == policy.critic.independence_domain_id
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let (expected_lineage, expected_output_tokens, expected_manifest) = match stage {
        PlannerStageContext::InitialPlan { critic_lineage, .. } => {
            if critic_lineage != &policy.critic {
                return Err(StoreError::InvalidStateEvent);
            }
            (
                &policy.producer,
                budgets.initial_plan_output_tokens,
                &policy.prompt_contracts.initial_plan_manifest_sha256,
            )
        }
        PlannerStageContext::InitialReview { .. } => (
            &policy.critic,
            budgets.initial_review_output_tokens,
            &policy.prompt_contracts.critic_manifest_sha256,
        ),
        PlannerStageContext::Repair { .. } => (
            &policy.producer,
            budgets.repair_output_tokens,
            &policy.prompt_contracts.repair_manifest_sha256,
        ),
        PlannerStageContext::FinalReview { .. } => (
            &policy.critic,
            budgets.final_review_output_tokens,
            &policy.prompt_contracts.critic_manifest_sha256,
        ),
    };
    let (_, actual_lineage, _) = stage_identity(stage);
    if actual_lineage != expected_lineage
        || prepared.backend_model.kind != birdcode_protocol::BackendKind::Model
        || prepared.backend_model.backend_id != expected_lineage.backend_id
        || prepared.backend_model.model_id != expected_lineage.model_id
        || prepared.token_reservation.max_output_tokens != expected_output_tokens
        || &prepared.prompt_manifest_digest != expected_manifest
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn builtin_root_planning_prompt_contracts() -> Result<RootPlanningPromptContracts, StoreError> {
    let registry = builtin_registry().map_err(|_| StoreError::InvalidStateEvent)?;
    let manifest_digest = |key: birdcode_prompting::PromptKey| {
        let manifest = registry.get(&key).ok_or(StoreError::InvalidStateEvent)?;
        Sha256Digest::parse(
            manifest
                .content_sha256()
                .map_err(|_| StoreError::InvalidStateEvent)?,
        )
        .map_err(|_| StoreError::InvalidStateEvent)
    };
    Ok(RootPlanningPromptContracts {
        initial_plan_manifest_sha256: manifest_digest(root_planner_key())?,
        critic_manifest_sha256: manifest_digest(plan_critic_key())?,
        repair_manifest_sha256: manifest_digest(plan_repair_key())?,
    })
}

pub(super) fn review_critic_policy_artifact(stage: &PlannerStageContext) -> Option<&ArtifactRef> {
    match stage {
        PlannerStageContext::InitialReview {
            critic_policy_artifact,
            ..
        }
        | PlannerStageContext::FinalReview {
            critic_policy_artifact,
            ..
        } => Some(critic_policy_artifact),
        PlannerStageContext::InitialPlan { .. } | PlannerStageContext::Repair { .. } => None,
    }
}
