//! Root-planning-v1 prepared and terminal inference validation.

use super::{
    BackendOperation, CANCELLATION_BOUNDARY_MEDIA_TYPE, EventEnvelope, EventPayload,
    INFERENCE_EVIDENCE_MEDIA_TYPE, InferenceAttemptId, Path, PlannerStageContext,
    RetainedCancellationBoundaryEvidence, RetainedInferenceEvidence, RetryDisposition, RunId,
    SessionId, Sha256Digest, StoreError, StructuredInferenceResponse, Transaction,
    UnknownInferenceBoundary, all_model_reserved_output_tokens_for_run,
    backend_error_kind_for_observation, decode_stored_run, durable_run_for_event,
    error_matches_protocol_backend_instance, event_by_id_for_run, event_count_by_json_identity,
    expected_backend_selection, first_prepared_inference, latest_cancellation_generation,
    model_token_reservation_identity_count, normalized_response_usage, params,
    parent_attempt_is_terminal, planner_run_id, planner_v2_not_dispatched_failure,
    read_canonical_json_artifact, require_active_claim_owner, require_current_claim_owner,
    require_current_plan_base, require_exact_model_provenance, require_latest_run_parent,
    require_running_run, response_matches_protocol_backend_instance, retry_for_backend_error,
    review_critic_policy_artifact, stage_identity, supports_root_planning,
    validate_critic_policy_artifact, validate_planner_stage_context,
    validate_stage_execution_policy,
};

#[allow(
    clippy::too_many_lines,
    reason = "Prepared is the atomic gate for claim, budget, plan, and stage identities"
)]
pub(super) fn validate_planner_inference_prepared(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    if latest_cancellation_generation(transaction, event.session_id, run_id)? != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    require_latest_run_parent(transaction, event, run_id)?;
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    validate_planner_stage_context(transaction, event, run_id, prepared)?;
    if let Some(stage) = &prepared.stage_context
        && let Some(critic_policy_artifact) = review_critic_policy_artifact(stage)
    {
        validate_critic_policy_artifact(
            transaction,
            event.session_id,
            run_id,
            artifact_root,
            prepared,
            stage,
            critic_policy_artifact,
        )?;
    }
    if prepared.token_reservation.reserved_tokens == 0
        || prepared.token_reservation.max_output_tokens == 0
        || prepared.token_reservation.reserved_tokens < prepared.token_reservation.max_output_tokens
        || prepared.backend_instance.as_ref().is_none_or(|identity| {
            identity.validate_integrity().is_err()
                || identity.backend_id != prepared.backend_model.backend_id
        })
        || prepared.stage_context.as_ref().is_some_and(|stage| {
            let (_, lineage, _) = stage_identity(stage);
            prepared
                .backend_instance
                .as_ref()
                .is_none_or(|identity| identity.configured_deployment_id != lineage.deployment_id)
        })
        || event_count_by_json_identity(
            transaction,
            "planner_inference_prepared",
            "$.payload.data.attempt_id",
            &prepared.attempt_id.to_string(),
        )? != 0
        || model_token_reservation_identity_count(transaction, prepared.token_reservation.id)? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if prepared.parent_attempt_id.is_none()
        && prepared_attempts_for_plan(
            transaction,
            event.session_id,
            run_id,
            prepared.plan_revision,
            &prepared.plan_digest,
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(parent_attempt_id) = prepared.parent_attempt_id
        && (parent_attempt_id == prepared.attempt_id
            || !parent_attempt_is_terminal(
                transaction,
                event.session_id,
                run_id,
                parent_attempt_id,
            )?)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(first) = first_prepared_inference(transaction, event.session_id, run_id)?
        && (first.obligation_snapshot_digest != prepared.obligation_snapshot_digest
            || first.acceptance_policy_digest != prepared.acceptance_policy_digest
            || first.planner_policy_digest != prepared.planner_policy_digest)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_current_plan_base(
        transaction,
        event.session_id,
        run_id,
        prepared.plan_revision,
        &prepared.plan_digest,
        true,
    )?;
    let run_json = transaction.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?;
    let run = decode_stored_run(&run_json)?;
    if let Some(stage) = &prepared.stage_context {
        validate_stage_execution_policy(
            artifact_root,
            prepared,
            stage,
            run.spec.limits.max_output_tokens,
        )?;
    }
    let enhanced_stage = prepared.stage_context.is_some();
    let producer_stage = prepared.stage_context.as_ref().is_none_or(|stage| {
        matches!(
            stage,
            PlannerStageContext::InitialPlan { .. } | PlannerStageContext::Repair { .. }
        )
    });
    let expected_backend = expected_backend_selection(&run, &prepared.backend_model);
    if !supports_root_planning(run.spec.purpose)
        || (producer_stage
            && (run.spec.backend.backend_id != prepared.backend_model.backend_id
                || run.spec.backend.kind != prepared.backend_model.kind
                || run
                    .spec
                    .backend
                    .model
                    .as_ref()
                    .is_some_and(|model| model != &prepared.backend_model.model_id)))
        || run
            .spec
            .limits
            .max_output_tokens
            .is_some_and(|limit| prepared.token_reservation.max_output_tokens > limit)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if enhanced_stage {
        require_exact_model_provenance(event, &expected_backend, None)?;
    }
    if let Some(limit) = run.spec.limits.max_output_tokens {
        let already_reserved =
            all_model_reserved_output_tokens_for_run(transaction, event.session_id, run_id)?;
        if already_reserved
            .checked_add(prepared.token_reservation.max_output_tokens)
            .ok_or(StoreError::InvalidStateEvent)?
            > limit
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    Ok(())
}

fn prepared_attempts_for_plan(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    plan_revision: u64,
    plan_digest: &Sha256Digest,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
               AND json_extract(value_json, '$.payload.data.plan_revision') = ?3
               AND json_extract(value_json, '$.payload.data.plan_digest') = ?4",
            params![
                run_id.to_string(),
                session_id.to_string(),
                plan_revision,
                plan_digest.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn inference_terminal_count(
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
                   ('planner_inference_observed', 'planner_inference_outcome_unknown')
               AND json_extract(value_json, '$.payload.data.attempt_id') = ?3",
            params![
                run_id.to_string(),
                session_id.to_string(),
                attempt_id.to_string()
            ],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn response_matches_prepared(
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    response: &StructuredInferenceResponse,
) -> bool {
    let Some(usage) = normalized_response_usage(response) else {
        return false;
    };
    let Some(backend_instance) = prepared.backend_instance.as_ref() else {
        return false;
    };
    response.model_id.as_str().as_bytes() == prepared.backend_model.model_id.as_bytes()
        && response.evidence.backend_id.as_str().as_bytes()
            == prepared.backend_model.backend_id.as_bytes()
        && response_matches_protocol_backend_instance(backend_instance, response)
        && serde_json::from_str::<serde_json::Value>(&response.raw_text)
            .is_ok_and(|value| value == response.value)
        && usage.output_tokens <= prepared.token_reservation.max_output_tokens
        && usage.total_tokens <= prepared.token_reservation.reserved_tokens
        && usage.input_tokens.checked_add(usage.output_tokens) == Some(usage.total_tokens)
}

fn expected_observation_from_evidence(
    prepared: &birdcode_protocol::PlannerInferencePrepared,
    evidence: &RetainedInferenceEvidence,
) -> Result<birdcode_protocol::PlannerInferenceObservation, StoreError> {
    Ok(match evidence {
        RetainedInferenceEvidence::Response { response }
            if response_matches_prepared(prepared, response) =>
        {
            birdcode_protocol::PlannerInferenceObservation::Succeeded {
                reported_backend_model: prepared.backend_model.clone(),
                token_usage: normalized_response_usage(response)
                    .ok_or(StoreError::InvalidStateEvent)?,
            }
        }
        RetainedInferenceEvidence::Response { .. } => {
            birdcode_protocol::PlannerInferenceObservation::Failed {
                error: birdcode_protocol::PlannerInferenceError {
                    kind: birdcode_protocol::PlannerInferenceErrorKind::ProtocolViolation,
                    retry: RetryDisposition::Never,
                },
            }
        }
        RetainedInferenceEvidence::Error { error } => {
            if error.backend_id.as_str() != prepared.backend_model.backend_id
                || prepared.backend_instance.as_ref().is_none_or(|identity| {
                    !error_matches_protocol_backend_instance(identity, error)
                })
                || error.operation != BackendOperation::StructuredInference
            {
                return Ok(birdcode_protocol::PlannerInferenceObservation::Failed {
                    error: birdcode_protocol::PlannerInferenceError {
                        kind: birdcode_protocol::PlannerInferenceErrorKind::ProtocolViolation,
                        retry: RetryDisposition::Never,
                    },
                });
            }
            birdcode_protocol::PlannerInferenceObservation::Failed {
                error: birdcode_protocol::PlannerInferenceError {
                    kind: backend_error_kind_for_observation(&error.kind),
                    retry: retry_for_backend_error(&error.kind),
                },
            }
        }
        RetainedInferenceEvidence::CancelledBeforeCall => {
            birdcode_protocol::PlannerInferenceObservation::Failed {
                error: birdcode_protocol::PlannerInferenceError {
                    kind: birdcode_protocol::PlannerInferenceErrorKind::Cancelled,
                    retry: RetryDisposition::Never,
                },
            }
        }
        RetainedInferenceEvidence::NotDispatched { reason } => {
            birdcode_protocol::PlannerInferenceObservation::Failed {
                error: planner_v2_not_dispatched_failure(*reason),
            }
        }
    })
}

pub(super) fn validate_planner_inference_observed(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    observed: &birdcode_protocol::PlannerInferenceObserved,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let prepared_event = event_by_id_for_run(
        transaction,
        event.session_id,
        run_id,
        observed.prepared_event_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if event.causal_parent != Some(prepared_event.id)
        || event.actor_id != prepared_event.actor_id
        || observed.attempt_id != prepared.attempt_id
        || observed.token_reservation_id != prepared.token_reservation.id
        || inference_terminal_count(transaction, event.session_id, run_id, observed.attempt_id)?
            != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_active_claim_owner(transaction, event, run_id)?;
    if prepared.stage_context.is_some() {
        let run = durable_run_for_event(transaction, event, run_id)?;
        let expected_backend = expected_backend_selection(&run, &prepared.backend_model);
        if prepared_event.provenance.backend.as_ref() != Some(&expected_backend)
            || prepared_event.provenance.raw_artifact.is_some()
        {
            return Err(StoreError::InvalidStateEvent);
        }
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
        if observed.outcome != expected_observation_from_evidence(prepared, &retained)? {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    if let birdcode_protocol::PlannerInferenceObservation::Succeeded {
        reported_backend_model,
        token_usage,
    } = &observed.outcome
        && (reported_backend_model != &prepared.backend_model
            || token_usage.output_tokens > prepared.token_reservation.max_output_tokens
            || token_usage.total_tokens > prepared.token_reservation.reserved_tokens
            || token_usage.total_tokens
                != token_usage
                    .input_tokens
                    .checked_add(token_usage.output_tokens)
                    .ok_or(StoreError::InvalidStateEvent)?
            || token_usage
                .cached_input_tokens
                .is_some_and(|cached| cached > token_usage.input_tokens))
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

pub(super) fn validate_planner_inference_unknown(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    unknown: &birdcode_protocol::PlannerInferenceOutcomeUnknown,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let prepared_event = event_by_id_for_run(
        transaction,
        event.session_id,
        run_id,
        unknown.prepared_event_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    require_current_claim_owner(transaction, event, run_id, unknown.cancellation_generation)?;
    if event.causal_parent != Some(prepared_event.id)
        || unknown.attempt_id != prepared.attempt_id
        || unknown.token_reservation_id != prepared.token_reservation.id
        || inference_terminal_count(transaction, event.session_id, run_id, unknown.attempt_id)? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if prepared.stage_context.is_some() {
        let run = durable_run_for_event(transaction, event, run_id)?;
        let expected_backend = expected_backend_selection(&run, &prepared.backend_model);
        if prepared_event.provenance.backend.as_ref() != Some(&expected_backend)
            || prepared_event.provenance.raw_artifact.is_some()
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let boundary_artifact = event
            .provenance
            .raw_artifact
            .as_ref()
            .ok_or(StoreError::InvalidStateEvent)?;
        require_exact_model_provenance(event, &expected_backend, Some(boundary_artifact))?;
        let boundary = read_canonical_json_artifact::<RetainedCancellationBoundaryEvidence>(
            artifact_root,
            boundary_artifact,
            CANCELLATION_BOUNDARY_MEDIA_TYPE,
        )?;
        let reason_matches = matches!(
            (unknown.reason, boundary.reason),
            (
                birdcode_protocol::UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
                UnknownInferenceBoundary::Restart
                    | UnknownInferenceBoundary::Shutdown
                    | UnknownInferenceBoundary::Cancelled,
            ) | (
                birdcode_protocol::UnknownInferenceOutcomeReason::ClaimExpiredBeforeObservation,
                UnknownInferenceBoundary::ClaimRenewalFailed,
            ) | (
                birdcode_protocol::UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate,
                UnknownInferenceBoundary::Deadline | UnknownInferenceBoundary::Cancelled,
            )
        );
        if boundary.prepared_event_id != prepared_event.id
            || boundary.cancellation_generation != unknown.cancellation_generation
            || !reason_matches
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    Ok(())
}
