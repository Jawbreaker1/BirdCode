//! Root-planning-v1 proposal decisions and repair-invocation validation.

use super::{
    ACCEPTED_PLAN_MEDIA_TYPE, DataProvenance, DataSection, EventEnvelope, EventId, EventPayload,
    PLAN_CRITIC_POLICY_MEDIA_TYPE, PLAN_CRITIQUE_MEDIA_TYPE, PLAN_PROPOSAL_MEDIA_TYPE,
    PLAN_VALIDATION_MEDIA_TYPE, Path, PlanAcceptanceContract, PlanCandidateBinding,
    PlanCriticOutput, PlanCriticPolicy, PlanProposalRejectionReason, PlannerStageContext,
    PromptError, PromptInvocation, RETAINED_PROMPT_MEDIA_TYPE, RetainedPlanValidation,
    RetainedPromptEvidence, RootPlannerOutput, RootPlannerPolicy, RootPlannerRejectionClass, Run,
    RunId, Session, Sha256Digest, SourceKind, StoreError, Transaction, TrustLevel,
    artifact_path_at, builtin_registry, candidate_plan_section, classify_root_planner_rejection,
    current_plan_base, decode_observed_response, durable_reasoning_setting,
    durable_session_and_run, event_by_id_for_run, event_count_by_json_identity,
    first_prepared_inference, invocation_with_constraint, plan_decision_count, plan_repair_key,
    planner_run_id, prepared_inference_for_attempt, read_canonical_json_artifact,
    read_verified_artifact, reconstruct_root_bindings, repository_identity_section,
    require_artifact_media_type, require_current_claim_owner, require_running_run,
    review_critic_policy_artifact, root_planner_key, root_policy_from_invocation,
    run_input_section, run_plan_acceptance_contract, sha256_hex, successful_observed_for_decision,
    validate_candidate_binding, validate_retained_prompt_and_request,
    validate_stage_execution_policy,
};

pub(super) fn validate_plan_proposal_rejected(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    rejected: &birdcode_protocol::PlanProposalRejected,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let observed_event = successful_observed_for_decision(
        transaction,
        event,
        run_id,
        rejected.observed_event_id,
        rejected.inference_attempt_id,
    )?;
    let prepared = prepared_inference_for_attempt(
        transaction,
        event.session_id,
        run_id,
        rejected.inference_attempt_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = &prepared.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if prepared.stage_context.as_ref().is_some_and(|stage| {
        !matches!(
            stage,
            PlannerStageContext::InitialPlan { .. } | PlannerStageContext::Repair { .. }
        )
    }) {
        return Err(StoreError::InvalidStateEvent);
    }
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    if rejected.base_plan_revision != prepared.plan_revision
        || rejected.base_plan_digest != prepared.plan_digest
        || plan_decision_count(
            transaction,
            event.session_id,
            run_id,
            rejected.inference_attempt_id,
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_rejected",
            "$.payload.data.proposal_id",
            &rejected.proposal_id.to_string(),
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_accepted",
            "$.payload.data.proposal_id",
            &rejected.proposal_id.to_string(),
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let current = current_plan_base(transaction, event.session_id, run_id)?
        .unwrap_or((0, prepared.plan_digest.clone()));
    let reason_matches_cas = match rejected.reason {
        PlanProposalRejectionReason::StaleBaseRevision => current.0 != rejected.base_plan_revision,
        PlanProposalRejectionReason::StaleBaseDigest => {
            current.0 == rejected.base_plan_revision && current.1 != rejected.base_plan_digest
        }
        _ => current.0 == rejected.base_plan_revision && current.1 == rejected.base_plan_digest,
    };
    if !reason_matches_cas {
        return Err(StoreError::InvalidStateEvent);
    }
    if run_plan_acceptance_contract(transaction, event.session_id, run_id)?
        == PlanAcceptanceContract::IndependentSemanticReviewV1
    {
        validate_semantic_plan_rejection_artifacts(
            transaction,
            event,
            run_id,
            prepared,
            &observed_event,
            rejected,
            artifact_root,
        )?;
    }
    Ok(())
}

pub(super) fn validate_plan_proposal_accepted(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    accepted: &birdcode_protocol::PlanProposalAccepted,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let observed_event = successful_observed_for_decision(
        transaction,
        event,
        run_id,
        accepted.observed_event_id,
        accepted.inference_attempt_id,
    )?;
    let prepared = prepared_inference_for_attempt(
        transaction,
        event.session_id,
        run_id,
        accepted.inference_attempt_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = prepared.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if prepared.stage_context.as_ref().is_some_and(|stage| {
        !matches!(
            stage,
            PlannerStageContext::InitialPlan { .. } | PlannerStageContext::Repair { .. }
        )
    }) {
        return Err(StoreError::InvalidStateEvent);
    }
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    let current = current_plan_base(transaction, event.session_id, run_id)?
        .unwrap_or((0, prepared.plan_digest.clone()));
    if accepted.previous_plan_revision != prepared.plan_revision
        || accepted.previous_plan_digest != prepared.plan_digest
        || current.0 != accepted.previous_plan_revision
        || current.1 != accepted.previous_plan_digest
        || accepted.accepted_plan_revision
            != accepted
                .previous_plan_revision
                .checked_add(1)
                .ok_or(StoreError::InvalidStateEvent)?
        || accepted.accepted_plan_digest.as_str() != accepted.accepted_plan_artifact.sha256.as_str()
        || plan_decision_count(
            transaction,
            event.session_id,
            run_id,
            accepted.inference_attempt_id,
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_rejected",
            "$.payload.data.proposal_id",
            &accepted.proposal_id.to_string(),
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_accepted",
            "$.payload.data.proposal_id",
            &accepted.proposal_id.to_string(),
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if run_plan_acceptance_contract(transaction, event.session_id, run_id)?
        == PlanAcceptanceContract::IndependentSemanticReviewV1
    {
        validate_semantic_plan_proposal_artifacts(
            transaction,
            event,
            run_id,
            &prepared,
            &observed_event,
            accepted,
            artifact_root,
        )?;
    }
    Ok(())
}

fn validate_semantic_plan_proposal_artifacts(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    run_id: RunId,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    observed_event: &EventEnvelope,
    accepted: &birdcode_protocol::PlanProposalAccepted,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let ReconstructedProducerObservation {
        raw_response,
        decoded_output,
    } = reconstruct_semantic_producer_observation(
        transaction,
        event,
        run_id,
        prepared,
        observed_event,
        artifact_root,
    )?;
    let output = decoded_output.map_err(|_| StoreError::InvalidStateEvent)?;
    require_artifact_media_type(&accepted.proposal_artifact, PLAN_PROPOSAL_MEDIA_TYPE)?;
    let proposal_bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &accepted.proposal_artifact.sha256)?,
        &accepted.proposal_artifact,
    )?;
    require_artifact_media_type(&accepted.accepted_plan_artifact, ACCEPTED_PLAN_MEDIA_TYPE)?;
    let accepted_bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &accepted.accepted_plan_artifact.sha256)?,
        &accepted.accepted_plan_artifact,
    )?;
    let canonical_output =
        serde_json::to_vec(&output).map_err(|_| StoreError::InvalidStateEvent)?;
    let validation = read_canonical_json_artifact::<RetainedPlanValidation>(
        artifact_root,
        &accepted.validation_evidence_artifact,
        PLAN_VALIDATION_MEDIA_TYPE,
    )?;
    if proposal_bytes != raw_response.as_bytes()
        || accepted_bytes != canonical_output
        || accepted.proposal_artifact.sha256 != sha256_hex(raw_response.as_bytes())
        || validation
            != (RetainedPlanValidation {
                status: "accepted".to_owned(),
                violations: Vec::new(),
            })
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the rejection gate binds the same exact durable producer observation as acceptance"
)]
fn validate_semantic_plan_rejection_artifacts(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    run_id: RunId,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    observed_event: &EventEnvelope,
    rejected: &birdcode_protocol::PlanProposalRejected,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let ReconstructedProducerObservation {
        raw_response,
        decoded_output,
    } = reconstruct_semantic_producer_observation(
        transaction,
        event,
        run_id,
        prepared,
        observed_event,
        artifact_root,
    )?;
    let error = decoded_output.err().ok_or(StoreError::InvalidStateEvent)?;
    require_artifact_media_type(&rejected.proposal_artifact, PLAN_PROPOSAL_MEDIA_TYPE)?;
    let proposal_bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &rejected.proposal_artifact.sha256)?,
        &rejected.proposal_artifact,
    )?;
    let validation = read_canonical_json_artifact::<RetainedPlanValidation>(
        artifact_root,
        &rejected.validation_evidence_artifact,
        PLAN_VALIDATION_MEDIA_TYPE,
    )?;
    if rejected.reason != root_planner_rejection_reason(&error)
        || rejected.proposal_artifact.sha256 != sha256_hex(raw_response.as_bytes())
        || proposal_bytes != raw_response.as_bytes()
        || validation
            != (RetainedPlanValidation {
                status: "rejected".to_owned(),
                violations: vec![error.to_string()],
            })
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

struct ReconstructedProducerObservation {
    raw_response: String,
    decoded_output: Result<RootPlannerOutput, PromptError>,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "producer decisions reconstruct every durable prompt, request, policy, and response identity"
)]
fn reconstruct_semantic_producer_observation(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    run_id: RunId,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    observed_event: &EventEnvelope,
    artifact_root: &Path,
) -> Result<ReconstructedProducerObservation, StoreError> {
    let stage = prepared
        .stage_context
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    if !matches!(
        stage,
        PlannerStageContext::InitialPlan { .. } | PlannerStageContext::Repair { .. }
    ) {
        return Err(StoreError::InvalidStateEvent);
    }
    let (session, run) = durable_session_and_run(transaction, event.session_id, run_id)?;
    validate_stage_execution_policy(
        artifact_root,
        prepared,
        stage,
        run.spec.limits.max_output_tokens,
    )?;
    let retained_prompt = read_canonical_json_artifact::<RetainedPromptEvidence>(
        artifact_root,
        &prepared.prompt_artifact,
        RETAINED_PROMPT_MEDIA_TYPE,
    )?;
    let root_policy = root_policy_from_invocation(&retained_prompt.prompt_invocation)?;
    let initial = first_prepared_inference(transaction, event.session_id, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let authoritative = reconstruct_root_bindings(&session, &run, &initial)?;
    if root_policy != authoritative.policy
        || initial.plan_revision != 0
        || initial.plan_digest != authoritative.root_snapshot_sha256
        || initial.obligation_snapshot_digest != authoritative.obligation_snapshot_sha256
        || initial.acceptance_policy_digest != authoritative.acceptance_policy_sha256
        || initial.context_manifest_digest != authoritative.context_manifest_sha256
        || initial.planner_policy_digest != authoritative.planner_policy_sha256
        || prepared.obligation_snapshot_digest != authoritative.obligation_snapshot_sha256
        || prepared.acceptance_policy_digest != authoritative.acceptance_policy_sha256
        || prepared.context_manifest_digest != authoritative.context_manifest_sha256
        || prepared.planner_policy_digest != authoritative.planner_policy_sha256
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let (expected_invocation, expected_prompt, output_schema_name) = match stage {
        PlannerStageContext::InitialPlan { .. } => (
            invocation_with_constraint(
                vec![
                    run_input_section(&session, &run)?,
                    repository_identity_section(&session)?,
                ],
                "planner_policy",
                &authoritative.policy,
            )?,
            root_planner_key(),
            "birdcode_root_planner_turn_v1",
        ),
        PlannerStageContext::Repair {
            candidate,
            triggering_review_event_id,
            required_finding_ids,
            ..
        } => (
            expected_repair_invocation(
                transaction,
                event,
                run_id,
                &session,
                &run,
                &authoritative.policy,
                candidate,
                *triggering_review_event_id,
                required_finding_ids,
                artifact_root,
            )?,
            plan_repair_key(),
            "birdcode_root_plan_repair_v1",
        ),
        PlannerStageContext::InitialReview { .. } | PlannerStageContext::FinalReview { .. } => {
            return Err(StoreError::InvalidStateEvent);
        }
    };
    validate_retained_prompt_and_request(
        artifact_root,
        prepared,
        &retained_prompt,
        &expected_invocation,
        &expected_prompt,
        output_schema_name,
        durable_reasoning_setting(&run)?,
    )?;
    let response = decode_observed_response(artifact_root, prepared, observed_event)?;
    let registry = builtin_registry().map_err(|_| StoreError::InvalidStateEvent)?;
    let decoded_output = registry.decode_output::<RootPlannerOutput>(
        &retained_prompt.compiled_prompt,
        &expected_invocation,
        response.raw_text.as_bytes(),
    );
    Ok(ReconstructedProducerObservation {
        raw_response: response.raw_text,
        decoded_output,
    })
}

pub(super) fn root_planner_rejection_reason(error: &PromptError) -> PlanProposalRejectionReason {
    match classify_root_planner_rejection(error) {
        RootPlannerRejectionClass::InvalidSchema => PlanProposalRejectionReason::InvalidSchema,
        RootPlannerRejectionClass::ProtectedAuthorityMutation => {
            PlanProposalRejectionReason::ProtectedAuthorityMutation
        }
        RootPlannerRejectionClass::ObligationCoverageIncomplete => {
            PlanProposalRejectionReason::ObligationCoverageIncomplete
        }
        RootPlannerRejectionClass::DependencyCycle => PlanProposalRejectionReason::DependencyCycle,
        RootPlannerRejectionClass::PolicyLimitExceeded => {
            PlanProposalRejectionReason::PolicyLimitExceeded
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "repair authority is reconstructed from its exact durable candidate and review"
)]
fn expected_repair_invocation(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    run_id: RunId,
    session: &Session,
    run: &Run,
    root_policy: &RootPlannerPolicy,
    candidate: &PlanCandidateBinding,
    triggering_review_event_id: EventId,
    required_finding_ids: &[String],
    artifact_root: &Path,
) -> Result<PromptInvocation, StoreError> {
    validate_candidate_binding(transaction, event, run_id, candidate)?;
    let candidate_output = read_canonical_json_artifact::<RootPlannerOutput>(
        artifact_root,
        &candidate.plan_artifact,
        ACCEPTED_PLAN_MEDIA_TYPE,
    )?;
    let review_event = event_by_id_for_run(
        transaction,
        event.session_id,
        run_id,
        triggering_review_event_id,
    )?;
    let EventPayload::PlanSemanticReviewRejected(review) = review_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let critique = read_canonical_json_artifact::<PlanCriticOutput>(
        artifact_root,
        &review.critique_artifact,
        PLAN_CRITIQUE_MEDIA_TYPE,
    )?;
    let review_prepared = prepared_inference_for_attempt(
        transaction,
        event.session_id,
        run_id,
        review.inference_attempt_id,
    )?;
    let EventPayload::PlannerInferencePrepared(review_prepared) = review_prepared.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let review_stage = review_prepared
        .stage_context
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    let critic_policy_artifact =
        review_critic_policy_artifact(review_stage).ok_or(StoreError::InvalidStateEvent)?;
    let critic_policy = read_canonical_json_artifact::<PlanCriticPolicy>(
        artifact_root,
        critic_policy_artifact,
        PLAN_CRITIC_POLICY_MEDIA_TYPE,
    )?;
    let critique_sha256 = Sha256Digest::parse(review.critique_artifact.sha256.clone())
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let mut sections = vec![
        run_input_section(session, run)?,
        repository_identity_section(session)?,
        candidate_plan_section(run, &candidate_output, &candidate.plan_digest)?,
    ];
    sections.push(DataSection {
        name: "committed_critique".to_owned(),
        trust: TrustLevel::Tool,
        provenance: DataProvenance {
            source_kind: SourceKind::Tool,
            source_id: format!("event:{triggering_review_event_id}:critique"),
            artifact_sha256: Some(critique_sha256.as_str().to_owned()),
            event_id: Some(triggering_review_event_id.to_string()),
        },
        payload: serde_json::json!({
            "critique_sha256": critique_sha256.as_str(),
            "critique": critique,
        }),
    });
    let assignment = serde_json::json!({
        "schema_version": 1,
        "triggering_review_event_id": triggering_review_event_id.to_string(),
        "candidate_plan_sha256": candidate.plan_digest.as_str(),
        "critique_sha256": critique_sha256.as_str(),
        "critic_policy_sha256": critic_policy.critic_policy_sha256,
        "required_finding_ids": required_finding_ids,
    });
    sections.push(DataSection {
        name: "repair_assignment".to_owned(),
        trust: TrustLevel::Tool,
        provenance: DataProvenance {
            source_kind: SourceKind::Tool,
            source_id: format!("event:{triggering_review_event_id}:repair-assignment"),
            artifact_sha256: None,
            event_id: Some(triggering_review_event_id.to_string()),
        },
        payload: assignment,
    });
    invocation_with_constraint(sections, "planner_policy", root_policy)
}
