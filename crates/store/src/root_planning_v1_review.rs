//! Root-planning-v1 independent semantic-review validation.

use super::{
    ACCEPTED_PLAN_MEDIA_TYPE, ArtifactRef, BTreeSet, EventEnvelope, EventId, EventPayload,
    InferenceAttemptId, PLAN_CRITIC_POLICY_MEDIA_TYPE, PLAN_CRITIQUE_MEDIA_TYPE,
    PLAN_CRITIQUE_VALIDATION_MEDIA_TYPE, Path, PlanCandidateBinding, PlanCriticOutput,
    PlanCriticPolicy, PlanCriticVerdict, PlanSemanticReviewRejectionDisposition,
    PlanSemanticReviewValidatedVerdict, PlanSemanticReviewValidationReceipt, PlannerStageContext,
    RETAINED_PROMPT_MEDIA_TYPE, RetainedPromptEvidence, RootPlannerOutput, Run, RunId, Session,
    SessionId, Sha256Digest, StoreError, Transaction, artifact_path_at, builtin_registry,
    candidate_plan_section, current_plan_base, decode_observed_response, durable_reasoning_setting,
    durable_session_and_run, event_count_by_json_identity, invocation_with_constraint, params,
    planner_run_id, prepared_inference_for_attempt, read_canonical_json_artifact,
    read_verified_artifact, repository_identity_section, require_artifact_media_type,
    require_current_claim_owner, require_running_run, review_critic_policy_artifact,
    run_input_section, stage_candidate, successful_observed_for_decision,
    validate_candidate_binding, validate_critic_policy_artifact,
    validate_retained_prompt_and_request, validate_stage_execution_policy,
};

fn semantic_review_decision_count(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    attempt_id: InferenceAttemptId,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') IN
                   ('plan_semantic_review_accepted', 'plan_semantic_review_rejected')
               AND json_extract(value_json, '$.payload.data.inference_attempt_id') = ?3",
            params![
                run_id.to_string(),
                session_id.to_string(),
                attempt_id.to_string()
            ],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn semantic_review_id_count(
    transaction: &Transaction<'_>,
    review_id: birdcode_protocol::PlanSemanticReviewId,
) -> Result<u64, StoreError> {
    let accepted = event_count_by_json_identity(
        transaction,
        "plan_semantic_review_accepted",
        "$.payload.data.review_id",
        &review_id.to_string(),
    )?;
    let rejected = event_count_by_json_identity(
        transaction,
        "plan_semantic_review_rejected",
        "$.payload.data.review_id",
        &review_id.to_string(),
    )?;
    accepted
        .checked_add(rejected)
        .ok_or(StoreError::InvalidStateEvent)
}

#[allow(
    clippy::too_many_arguments,
    reason = "every durable semantic-decision identity is passed explicitly for cross-binding"
)]
fn validate_semantic_review_common(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    inference_attempt_id: InferenceAttemptId,
    observed_event_id: EventId,
    candidate: &PlanCandidateBinding,
    critique_artifact: &ArtifactRef,
    validation_evidence_artifact: &ArtifactRef,
    artifact_root: &Path,
) -> Result<(PlannerStageContext, PlanSemanticReviewValidationReceipt), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let observed_event = successful_observed_for_decision(
        transaction,
        event,
        run_id,
        observed_event_id,
        inference_attempt_id,
    )?;
    let prepared_event = prepared_inference_for_attempt(
        transaction,
        event.session_id,
        run_id,
        inference_attempt_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let stage = prepared
        .stage_context
        .clone()
        .ok_or(StoreError::InvalidStateEvent)?;
    if !matches!(
        stage,
        PlannerStageContext::InitialReview { .. } | PlannerStageContext::FinalReview { .. }
    ) || stage_candidate(&stage) != Some(candidate)
        || prepared.plan_revision != candidate.plan_revision
        || prepared.plan_digest != candidate.plan_digest
        || semantic_review_decision_count(
            transaction,
            event.session_id,
            run_id,
            inference_attempt_id,
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    validate_candidate_binding(transaction, event, run_id, candidate)?;
    let (session, run) = durable_session_and_run(transaction, event.session_id, run_id)?;
    validate_stage_execution_policy(
        artifact_root,
        prepared,
        &stage,
        run.spec.limits.max_output_tokens,
    )?;
    let current = current_plan_base(transaction, event.session_id, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    if current.0 != candidate.plan_revision || current.1 != candidate.plan_digest {
        return Err(StoreError::InvalidStateEvent);
    }
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    let critic_policy_artifact =
        review_critic_policy_artifact(&stage).ok_or(StoreError::InvalidStateEvent)?;
    validate_critic_policy_artifact(
        transaction,
        event.session_id,
        run_id,
        artifact_root,
        prepared,
        &stage,
        critic_policy_artifact,
    )?;
    let receipt = validate_semantic_review_artifacts(
        artifact_root,
        prepared,
        &observed_event,
        &stage,
        candidate,
        &session,
        &run,
        critique_artifact,
        validation_evidence_artifact,
    )?;
    Ok((stage, receipt))
}

#[allow(clippy::too_many_arguments)]
fn validate_semantic_review_artifacts(
    artifact_root: &Path,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    observed_event: &EventEnvelope,
    stage: &PlannerStageContext,
    candidate: &PlanCandidateBinding,
    session: &Session,
    run: &Run,
    critique_artifact: &ArtifactRef,
    validation_evidence_artifact: &ArtifactRef,
) -> Result<PlanSemanticReviewValidationReceipt, StoreError> {
    let EventPayload::PlannerInferenceObserved(observed) = &observed_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    require_artifact_media_type(
        validation_evidence_artifact,
        PLAN_CRITIQUE_VALIDATION_MEDIA_TYPE,
    )?;
    require_artifact_media_type(critique_artifact, PLAN_CRITIQUE_MEDIA_TYPE)?;
    let receipt_bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &validation_evidence_artifact.sha256)?,
        validation_evidence_artifact,
    )?;
    let receipt = serde_json::from_slice::<PlanSemanticReviewValidationReceipt>(&receipt_bytes)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let canonical_receipt =
        serde_json::to_vec(&receipt).map_err(|_| StoreError::InvalidStateEvent)?;
    let critic_policy_artifact =
        review_critic_policy_artifact(stage).ok_or(StoreError::InvalidStateEvent)?;
    require_artifact_media_type(critic_policy_artifact, PLAN_CRITIC_POLICY_MEDIA_TYPE)?;
    let critic_policy_bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &critic_policy_artifact.sha256)?,
        critic_policy_artifact,
    )?;
    let critic_policy = serde_json::from_slice::<PlanCriticPolicy>(&critic_policy_bytes)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let canonical_critic_policy =
        serde_json::to_vec(&critic_policy).map_err(|_| StoreError::InvalidStateEvent)?;
    let critic_policy_sha256 = Sha256Digest::parse(critic_policy.critic_policy_sha256.clone())
        .map_err(|_| StoreError::InvalidStateEvent)?;
    if canonical_critic_policy != critic_policy_bytes
        || canonical_receipt != receipt_bytes
        || receipt.schema_version != 1
        || receipt.inference_attempt_id != prepared.attempt_id
        || receipt.observed_event_id != observed_event.id
        || receipt.candidate != *candidate
        || receipt.prompt_manifest_sha256 != prepared.prompt_manifest_digest
        || receipt.prompt_artifact_sha256.as_str() != prepared.prompt_artifact.sha256
        || receipt.request_artifact_sha256.as_str() != prepared.request_artifact.sha256
        || receipt.normalized_evidence_sha256.as_str()
            != observed.normalized_complete_evidence_artifact.sha256
        || receipt.critic_policy_sha256 != critic_policy_sha256
        || receipt.critique_sha256.as_str() != critique_artifact.sha256
    {
        return Err(StoreError::InvalidStateEvent);
    }

    let critique_bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &critique_artifact.sha256)?,
        critique_artifact,
    )?;
    let decoded = decode_observed_critic_output(
        artifact_root,
        prepared,
        observed_event,
        &critic_policy,
        candidate,
        session,
        run,
    )?;
    let critique = match decoded {
        Ok(critique) => critique,
        Err(raw_text) => {
            if receipt.verdict != PlanSemanticReviewValidatedVerdict::ContractInvalid
                || !receipt.finding_ids.is_empty()
                || critique_bytes != raw_text.as_bytes()
            {
                return Err(StoreError::InvalidStateEvent);
            }
            return Ok(receipt);
        }
    };
    let canonical_critique =
        serde_json::to_vec(&critique).map_err(|_| StoreError::InvalidStateEvent)?;
    let expected_verdict = match critique.verdict {
        PlanCriticVerdict::Accept => PlanSemanticReviewValidatedVerdict::Accept,
        PlanCriticVerdict::Revise => PlanSemanticReviewValidatedVerdict::Revise,
        PlanCriticVerdict::Clarify => PlanSemanticReviewValidatedVerdict::Clarify,
        PlanCriticVerdict::Escalate => PlanSemanticReviewValidatedVerdict::Escalate,
    };
    let expected_finding_ids = critique
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    if canonical_critique != critique_bytes
        || receipt.verdict != expected_verdict
        || receipt.finding_ids != expected_finding_ids
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(receipt)
}

/// Decodes the exact content-addressed response attached to Observed and
/// applies the bundled critic schema plus its authoritative invariant checks.
/// `Err(raw_text)` is a model output-contract failure; malformed retained
/// provenance/prompt material fails the store operation instead.
fn decode_observed_critic_output(
    artifact_root: &Path,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    observed_event: &EventEnvelope,
    critic_policy: &PlanCriticPolicy,
    candidate: &PlanCandidateBinding,
    session: &Session,
    run: &Run,
) -> Result<Result<PlanCriticOutput, String>, StoreError> {
    let response = decode_observed_response(artifact_root, prepared, observed_event)?;
    let retained_prompt = read_canonical_json_artifact::<RetainedPromptEvidence>(
        artifact_root,
        &prepared.prompt_artifact,
        RETAINED_PROMPT_MEDIA_TYPE,
    )?;
    let candidate_output = read_canonical_json_artifact::<RootPlannerOutput>(
        artifact_root,
        &candidate.plan_artifact,
        ACCEPTED_PLAN_MEDIA_TYPE,
    )?;
    let expected_invocation = invocation_with_constraint(
        vec![
            run_input_section(session, run)?,
            repository_identity_section(session)?,
            candidate_plan_section(run, &candidate_output, &candidate.plan_digest)?,
        ],
        "critic_policy",
        critic_policy,
    )?;
    let registry = builtin_registry().map_err(|_| StoreError::InvalidStateEvent)?;
    let critic_key = birdcode_prompting::plan_critic_key();
    validate_retained_prompt_and_request(
        artifact_root,
        prepared,
        &retained_prompt,
        &expected_invocation,
        &critic_key,
        "birdcode_plan_semantic_critic_v1",
        durable_reasoning_setting(run)?,
    )?;

    Ok(registry
        .decode_output::<PlanCriticOutput>(
            &retained_prompt.compiled_prompt,
            &expected_invocation,
            response.raw_text.as_bytes(),
        )
        .map_err(|_| response.raw_text.clone()))
}

pub(super) fn validate_plan_semantic_review_accepted(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    accepted: &birdcode_protocol::PlanSemanticReviewAccepted,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let (_, receipt) = validate_semantic_review_common(
        transaction,
        event,
        accepted.inference_attempt_id,
        accepted.observed_event_id,
        &accepted.candidate,
        &accepted.critique_artifact,
        &accepted.validation_evidence_artifact,
        artifact_root,
    )?;
    if receipt.verdict != PlanSemanticReviewValidatedVerdict::Accept
        || !receipt.finding_ids.is_empty()
        || semantic_review_id_count(transaction, accepted.review_id)? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

pub(super) fn validate_plan_semantic_review_rejected(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    rejected: &birdcode_protocol::PlanSemanticReviewRejected,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let (stage, receipt) = validate_semantic_review_common(
        transaction,
        event,
        rejected.inference_attempt_id,
        rejected.observed_event_id,
        &rejected.candidate,
        &rejected.critique_artifact,
        &rejected.validation_evidence_artifact,
        artifact_root,
    )?;
    if semantic_review_id_count(transaction, rejected.review_id)? != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    let unique_findings = rejected
        .required_finding_ids
        .iter()
        .collect::<BTreeSet<_>>();
    let valid_findings = rejected.required_finding_ids.len() <= 32
        && unique_findings.len() == rejected.required_finding_ids.len()
        && rejected
            .required_finding_ids
            .iter()
            .all(|finding| !finding.is_empty() && finding.len() <= 128);
    let valid_disposition = match rejected.disposition {
        PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized => {
            matches!(stage, PlannerStageContext::InitialReview { .. })
                && !rejected.required_finding_ids.is_empty()
                && receipt.verdict == PlanSemanticReviewValidatedVerdict::Revise
                && receipt.finding_ids == rejected.required_finding_ids
        }
        PlanSemanticReviewRejectionDisposition::TerminalReject => {
            rejected.required_finding_ids.is_empty()
                && match stage {
                    PlannerStageContext::InitialReview { .. } => matches!(
                        receipt.verdict,
                        PlanSemanticReviewValidatedVerdict::Clarify
                            | PlanSemanticReviewValidatedVerdict::Escalate
                    ),
                    PlannerStageContext::FinalReview { .. } => matches!(
                        receipt.verdict,
                        PlanSemanticReviewValidatedVerdict::Revise
                            | PlanSemanticReviewValidatedVerdict::Clarify
                            | PlanSemanticReviewValidatedVerdict::Escalate
                    ),
                    PlannerStageContext::InitialPlan { .. }
                    | PlannerStageContext::Repair { .. } => false,
                }
        }
        PlanSemanticReviewRejectionDisposition::ReviewContractInvalid => {
            rejected.required_finding_ids.is_empty()
                && receipt.finding_ids.is_empty()
                && receipt.verdict == PlanSemanticReviewValidatedVerdict::ContractInvalid
        }
    };
    if !valid_findings || !valid_disposition {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}
