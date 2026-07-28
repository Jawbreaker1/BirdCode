//! Root-planning-v1 failure fences and durable failure validation.

use super::{
    BackendSelection, EventEnvelope, EventPayload, Path, PlanAcceptanceContract,
    PlanSemanticReviewRejectionDisposition, PlannerStageContext, PlannerStageKind,
    ROOT_PLANNING_FAILURE_MEDIA_TYPE, ROOT_PLANNING_STAGE_FAILURE_MEDIA_TYPE,
    RetainedRootPlanningFailureEvidence, RetainedRootPlanningStageFailureEvidence,
    RootPlanningFailed, RootPlanningFailurePhase, RootPlanningFailureReason, RootPlanningModelRole,
    RootPlanningModelSubject, RootPlanningStage, RootPlanningStageFailed,
    RootPlanningStageFailureReason, Run, RunId, SessionId, Sha256Digest, StoreError, Transaction,
    durable_run_for_event, event_count_by_json_identity, latest_cancellation_generation,
    latest_non_claim_event, params, planner_run_id, prepared_events_for_run,
    read_canonical_json_artifact, require_current_claim_owner, require_exact_model_provenance,
    require_latest_run_parent, require_running_run, stage_identity, stage_kind,
    stage_model_subject, supports_root_planning,
};

pub(super) fn validate_root_planning_failure_fence(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<(), StoreError> {
    let Some(run_id) = event.run_id else {
        return Ok(());
    };
    if root_planning_failure_count(transaction, event.session_id, run_id)? == 0
        && root_planning_stage_failure_count(transaction, event.session_id, run_id)? == 0
    {
        return Ok(());
    }
    if matches!(
        event.payload,
        EventPayload::RunClaimed(_)
            | EventPayload::CancellationRequested(_)
            | EventPayload::RunStateChanged { .. }
    ) {
        Ok(())
    } else {
        Err(StoreError::InvalidStateEvent)
    }
}

pub(super) fn root_planning_failure_count(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'root_planning_failed'",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

pub(super) fn root_planning_stage_failure_count(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'root_planning_stage_failed'",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn expected_lineage_backend_selection(
    run: &Run,
    lineage: &birdcode_protocol::ModelLineage,
) -> BackendSelection {
    BackendSelection {
        backend_id: lineage.backend_id.clone(),
        kind: birdcode_protocol::BackendKind::Model,
        model: Some(lineage.model_id.clone()),
        reasoning_effort: run.spec.backend.reasoning_effort.clone(),
    }
}

pub(super) fn validate_root_planning_failed(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    failure: &RootPlanningFailed,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    require_latest_run_parent(transaction, event, run_id)?;
    if failure.cancellation_generation != 0
        || root_planning_failure_count(transaction, event.session_id, run_id)? != 0
        || !valid_root_planning_failure_classification(failure.phase, failure.reason)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let inference_count = transaction.query_row(
        "SELECT COUNT(*) FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, u64>(0),
    )?;
    if inference_count != 0 {
        return Err(StoreError::InvalidStateEvent);
    }

    let claim_event =
        require_current_claim_owner(transaction, event, run_id, failure.cancellation_generation)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if failure.claim_event_id != claim_event.id
        || failure.claim_id != claim.claim_id
        || event.provenance.raw_artifact.as_ref() != Some(&failure.evidence_artifact)
    {
        return Err(StoreError::InvalidStateEvent);
    }

    let run = durable_run_for_event(transaction, event, run_id)?;
    let expected_backend = failure.model_subject.as_ref().map_or_else(
        || run.spec.backend.clone(),
        |subject| expected_lineage_backend_selection(&run, &subject.lineage),
    );
    let semantic_subject_is_valid = run.spec.plan_acceptance
        != PlanAcceptanceContract::IndependentSemanticReviewV1
        || failure.reason != RootPlanningFailureReason::SelectedModelUnavailable
        || failure.model_subject.as_ref().is_some_and(|subject| {
            subject.role != RootPlanningModelRole::Producer
                || (subject.lineage.backend_id == run.spec.backend.backend_id
                    && Some(subject.lineage.model_id.as_str()) == run.spec.backend.model.as_deref())
        });
    if !supports_root_planning(run.spec.purpose) || !semantic_subject_is_valid {
        return Err(StoreError::InvalidStateEvent);
    }
    require_exact_model_provenance(event, &expected_backend, Some(&failure.evidence_artifact))?;
    if run.spec.plan_acceptance == PlanAcceptanceContract::IndependentSemanticReviewV1 {
        let evidence = read_canonical_json_artifact::<RetainedRootPlanningFailureEvidence>(
            artifact_root,
            &failure.evidence_artifact,
            ROOT_PLANNING_FAILURE_MEDIA_TYPE,
        )?;
        if evidence.schema_version != 1
            || evidence.run_id != run_id
            || evidence.claim_event_id != failure.claim_event_id
            || evidence.claim_id != failure.claim_id
            || evidence.phase != failure.phase
            || evidence.reason != failure.reason
            || evidence.model_subject != failure.model_subject
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the durable stage-failure gate checks one closed event contract in one place"
)]
pub(super) fn validate_root_planning_stage_failed(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    failure: &RootPlanningStageFailed,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    let run = durable_run_for_event(transaction, event, run_id)?;
    if !supports_root_planning(run.spec.purpose) {
        return Err(StoreError::InvalidStateEvent);
    }
    require_running_run(transaction, event, run_id)?;
    require_latest_run_parent(transaction, event, run_id)?;
    let semantic_predecessor = latest_non_claim_event(transaction, event.session_id, run_id)?;
    if failure.predecessor_event_id != semantic_predecessor.id
        || failure.cancellation_generation != 0
        || latest_cancellation_generation(transaction, event.session_id, run_id)? != 0
        || root_planning_failure_count(transaction, event.session_id, run_id)? != 0
        || root_planning_stage_failure_count(transaction, event.session_id, run_id)? != 0
        || event_count_by_json_identity(
            transaction,
            "root_planning_stage_failed",
            "$.payload.data.failure_id",
            &failure.failure_id.to_string(),
        )? != 0
        || !valid_stage_failure_classification(failure.failed_stage, failure.reason)
        || event.provenance.raw_artifact.as_ref() != Some(&failure.evidence_artifact)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_current_claim_owner(transaction, event, run_id, failure.cancellation_generation)?;

    let prepared_events = prepared_events_for_run(transaction, event.session_id, run_id)?;
    let prepared_kinds = prepared_events
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
    let exact_next_stage_predecessor = match failure.failed_stage {
        RootPlanningStage::InitialPlan => false,
        RootPlanningStage::InitialReview => {
            prepared_kinds == [PlannerStageKind::InitialPlan]
                && matches!(
                    &semantic_predecessor.payload,
                    EventPayload::PlanProposalAccepted(accepted)
                        if prepared_events.first().is_some_and(|prepared_event| {
                            matches!(
                                &prepared_event.payload,
                                EventPayload::PlannerInferencePrepared(prepared)
                                    if prepared.attempt_id == accepted.inference_attempt_id
                            )
                        })
                )
        }
        RootPlanningStage::Repair => {
            prepared_kinds
                == [
                    PlannerStageKind::InitialPlan,
                    PlannerStageKind::InitialReview,
                ]
                && matches!(
                    &semantic_predecessor.payload,
                    EventPayload::PlanSemanticReviewRejected(rejected)
                        if rejected.disposition
                            == PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
                            && prepared_events.get(1).is_some_and(|prepared_event| {
                                matches!(
                                    &prepared_event.payload,
                                    EventPayload::PlannerInferencePrepared(prepared)
                                        if prepared.attempt_id == rejected.inference_attempt_id
                                )
                            })
                )
        }
        RootPlanningStage::FinalReview => {
            prepared_kinds
                == [
                    PlannerStageKind::InitialPlan,
                    PlannerStageKind::InitialReview,
                    PlannerStageKind::Repair,
                ]
                && matches!(
                    &semantic_predecessor.payload,
                    EventPayload::PlanProposalAccepted(accepted)
                        if prepared_events.get(2).is_some_and(|prepared_event| {
                            matches!(
                                &prepared_event.payload,
                                EventPayload::PlannerInferencePrepared(prepared)
                                    if prepared.attempt_id == accepted.inference_attempt_id
                            )
                        })
                )
        }
    };
    let observed_replay_stage = match &semantic_predecessor.payload {
        EventPayload::PlannerInferenceObserved(observed)
            if matches!(
                observed.outcome,
                birdcode_protocol::PlannerInferenceObservation::Succeeded { .. }
            ) =>
        {
            prepared_events.iter().find_map(|prepared_event| {
                let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload
                else {
                    return None;
                };
                if prepared_event.id != observed.prepared_event_id
                    || prepared.attempt_id != observed.attempt_id
                {
                    return None;
                }
                prepared
                    .stage_context
                    .as_ref()
                    .map(|stage| (stage, prepared_event.provenance.backend.clone()))
            })
        }
        _ => None,
    };
    let first_stage = prepared_events
        .first()
        .and_then(|event| match &event.payload {
            EventPayload::PlannerInferencePrepared(prepared) => prepared.stage_context.as_ref(),
            _ => None,
        })
        .ok_or(StoreError::InvalidStateEvent)?;
    let (_, _, expected_policy_artifact) = stage_identity(first_stage);
    let mut replay_prepared_backend = None;
    let expected_subject = if let Some((replay_stage, prepared_backend)) = observed_replay_stage {
        replay_prepared_backend = prepared_backend;
        let (replay_stage_kind, subject) = stage_model_subject(replay_stage);
        let (_, _, replay_policy_artifact) = stage_identity(replay_stage);
        let exact_replay_prefix = match replay_stage_kind {
            RootPlanningStage::InitialPlan => prepared_kinds == [PlannerStageKind::InitialPlan],
            RootPlanningStage::InitialReview => {
                prepared_kinds
                    == [
                        PlannerStageKind::InitialPlan,
                        PlannerStageKind::InitialReview,
                    ]
            }
            RootPlanningStage::Repair => {
                prepared_kinds
                    == [
                        PlannerStageKind::InitialPlan,
                        PlannerStageKind::InitialReview,
                        PlannerStageKind::Repair,
                    ]
            }
            RootPlanningStage::FinalReview => {
                prepared_kinds
                    == [
                        PlannerStageKind::InitialPlan,
                        PlannerStageKind::InitialReview,
                        PlannerStageKind::Repair,
                        PlannerStageKind::FinalReview,
                    ]
            }
        };
        if replay_stage_kind != failure.failed_stage
            || !exact_replay_prefix
            || !matches!(
                failure.reason,
                RootPlanningStageFailureReason::InvalidCommittedArtifact
                    | RootPlanningStageFailureReason::ArtifactPersistenceFailed
                    | RootPlanningStageFailureReason::WallDeadlineExceeded
                    | RootPlanningStageFailureReason::DurableStateConflict
            )
            || &failure.execution_policy_artifact != replay_policy_artifact
            || replay_policy_artifact != expected_policy_artifact
        {
            return Err(StoreError::InvalidStateEvent);
        }
        // This boundary must remain appendable even when the execution-policy
        // file itself is the corrupt committed artifact. Prepared already
        // authenticated the exact ref and lineage when it was appended.
        subject
    } else {
        if !exact_next_stage_predecessor
            || &failure.execution_policy_artifact != expected_policy_artifact
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let PlannerStageContext::InitialPlan {
            model_lineage: producer_lineage,
            critic_lineage,
            ..
        } = first_stage
        else {
            return Err(StoreError::InvalidStateEvent);
        };
        // The two lineages were authenticated against the intact execution
        // policy when InitialPlan Prepared was appended. A next-stage failure
        // must remain appendable if that content-addressed file is later lost
        // or corrupted, so recovery reads only this typed durable snapshot.
        match failure.reason {
            RootPlanningStageFailureReason::IndependentReviewerUnavailable => {
                RootPlanningModelSubject {
                    role: RootPlanningModelRole::IndependentCritic,
                    lineage: critic_lineage.clone(),
                }
            }
            RootPlanningStageFailureReason::SelectedModelUnavailable => RootPlanningModelSubject {
                role: RootPlanningModelRole::Producer,
                lineage: producer_lineage.clone(),
            },
            _ => match failure.failed_stage {
                RootPlanningStage::InitialPlan | RootPlanningStage::Repair => {
                    RootPlanningModelSubject {
                        role: RootPlanningModelRole::Producer,
                        lineage: producer_lineage.clone(),
                    }
                }
                RootPlanningStage::InitialReview | RootPlanningStage::FinalReview => {
                    RootPlanningModelSubject {
                        role: RootPlanningModelRole::IndependentCritic,
                        lineage: critic_lineage.clone(),
                    }
                }
            },
        }
    };
    let expected_backend = expected_lineage_backend_selection(&run, &expected_subject.lineage);
    if failure.model_subject != expected_subject {
        return Err(StoreError::InvalidStateEvent);
    }
    require_exact_model_provenance(event, &expected_backend, Some(&failure.evidence_artifact))?;
    if replay_prepared_backend.is_some()
        && (replay_prepared_backend.as_ref() != Some(&expected_backend)
            || semantic_predecessor.provenance.backend.as_ref() != Some(&expected_backend))
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let evidence = read_canonical_json_artifact::<RetainedRootPlanningStageFailureEvidence>(
        artifact_root,
        &failure.evidence_artifact,
        ROOT_PLANNING_STAGE_FAILURE_MEDIA_TYPE,
    )?;
    let execution_policy_sha256 =
        Sha256Digest::parse(failure.execution_policy_artifact.sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?;
    if evidence.schema_version != 1
        || evidence.run_id != run_id
        || evidence.failed_stage != failure.failed_stage
        || evidence.predecessor_event_id != failure.predecessor_event_id
        || evidence.execution_policy_sha256 != execution_policy_sha256
        || evidence.reason != failure.reason
        || evidence.model_subject != failure.model_subject
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

const fn valid_stage_failure_classification(
    stage: RootPlanningStage,
    reason: RootPlanningStageFailureReason,
) -> bool {
    match reason {
        RootPlanningStageFailureReason::IndependentReviewerUnavailable => matches!(
            stage,
            RootPlanningStage::InitialReview | RootPlanningStage::FinalReview
        ),
        RootPlanningStageFailureReason::WallDeadlineExceeded
        | RootPlanningStageFailureReason::ArtifactPersistenceFailed
        | RootPlanningStageFailureReason::InvalidCommittedArtifact
        | RootPlanningStageFailureReason::DurableStateConflict => true,
        RootPlanningStageFailureReason::SelectedModelUnavailable
        | RootPlanningStageFailureReason::AggregateBudgetExhausted
        | RootPlanningStageFailureReason::PromptCompilationFailed
        | RootPlanningStageFailureReason::ConfigurationDrift => {
            !matches!(stage, RootPlanningStage::InitialPlan)
        }
    }
}

const fn valid_root_planning_failure_classification(
    phase: RootPlanningFailurePhase,
    reason: RootPlanningFailureReason,
) -> bool {
    matches!(
        (phase, reason),
        (
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidWallDeadline
                | RootPlanningFailureReason::InvalidRunConfiguration
                | RootPlanningFailureReason::WallDeadlineExceeded
        ) | (
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration
                | RootPlanningFailureReason::BackendDiscoveryFailed
                | RootPlanningFailureReason::DiscoveryTimedOut
                | RootPlanningFailureReason::InvalidDiscoveryCatalog
                | RootPlanningFailureReason::SelectedModelUnavailable
                | RootPlanningFailureReason::WallDeadlineExceeded
        ) | (
            RootPlanningFailurePhase::PromptPreparation,
            RootPlanningFailureReason::InvalidRunConfiguration
                | RootPlanningFailureReason::ArtifactPersistenceFailed
                | RootPlanningFailureReason::WallDeadlineExceeded
                | RootPlanningFailureReason::PromptCompilationFailed
                | RootPlanningFailureReason::DurableStateConflict
        )
    )
}
