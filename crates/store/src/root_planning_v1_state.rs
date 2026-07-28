//! Root-planning-v1 replay state, stage identity, and plan-base projection.

use super::{
    ActorId, ArtifactRef, EventEnvelope, EventPayload, InferenceAttemptId, OptionalExtension,
    PlannerStageContext, RetryDisposition, RootPlanningModelRole, RootPlanningModelSubject,
    RootPlanningStage, RunId, SessionId, Sha256Digest, StoreError, Transaction,
    decode_canonical_event, params,
};

pub(super) fn prepared_inference_for_attempt(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    attempt_id: InferenceAttemptId,
) -> Result<EventEnvelope, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
               AND json_extract(value_json, '$.payload.data.attempt_id') = ?3
             ORDER BY sequence ASC LIMIT 1",
            params![
                run_id.to_string(),
                session_id.to_string(),
                attempt_id.to_string()
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    decode_canonical_event(&json)
}

pub(super) fn current_plan_base(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<(u64, Sha256Digest)>, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'plan_proposal_accepted'
             ORDER BY sequence DESC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let event = decode_canonical_event(&json)?;
    let EventPayload::PlanProposalAccepted(accepted) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(Some((
        accepted.accepted_plan_revision,
        accepted.accepted_plan_digest,
    )))
}

fn genesis_plan_digest(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<Sha256Digest>, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
             ORDER BY sequence ASC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let event = decode_canonical_event(&json)?;
    let EventPayload::PlannerInferencePrepared(prepared) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if prepared.plan_revision != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(Some(prepared.plan_digest))
}

pub(super) fn first_prepared_inference(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<birdcode_protocol::PlannerInferencePrepared>, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
             ORDER BY sequence ASC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let event = decode_canonical_event(&json)?;
    let EventPayload::PlannerInferencePrepared(prepared) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(Some(prepared))
}

pub(super) fn require_current_plan_base(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    revision: u64,
    digest: &Sha256Digest,
    allow_first_genesis: bool,
) -> Result<(), StoreError> {
    if let Some((current_revision, current_digest)) =
        current_plan_base(transaction, session_id, run_id)?
    {
        if current_revision != revision || &current_digest != digest {
            return Err(StoreError::InvalidStateEvent);
        }
        return Ok(());
    }
    if revision != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    match genesis_plan_digest(transaction, session_id, run_id)? {
        Some(genesis) if &genesis == digest => Ok(()),
        None if allow_first_genesis => Ok(()),
        _ => Err(StoreError::InvalidStateEvent),
    }
}

pub(super) fn parent_attempt_is_terminal(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    parent_attempt_id: InferenceAttemptId,
) -> Result<bool, StoreError> {
    let parent =
        prepared_inference_for_attempt(transaction, session_id, run_id, parent_attempt_id)?;
    let terminal_json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2 AND sequence > ?3
               AND (
                    (json_extract(value_json, '$.payload.type') = 'planner_inference_outcome_unknown'
                     AND json_extract(value_json, '$.payload.data.attempt_id') = ?4)
                 OR (json_extract(value_json, '$.payload.type') IN
                        ('plan_proposal_accepted', 'plan_proposal_rejected')
                     AND json_extract(value_json, '$.payload.data.inference_attempt_id') = ?4)
                 OR (json_extract(value_json, '$.payload.type') IN
                        ('plan_semantic_review_accepted', 'plan_semantic_review_rejected')
                     AND json_extract(value_json, '$.payload.data.inference_attempt_id') = ?4)
                 OR (json_extract(value_json, '$.payload.type') = 'planner_inference_observed'
                     AND json_extract(value_json, '$.payload.data.attempt_id') = ?4)
               )
             ORDER BY sequence DESC LIMIT 1",
            params![
                run_id.to_string(),
                session_id.to_string(),
                parent.sequence,
                parent_attempt_id.to_string()
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = terminal_json else {
        return Ok(false);
    };
    let terminal = decode_canonical_event(&json)?;
    match terminal.payload {
        EventPayload::PlannerInferenceOutcomeUnknown(_)
        | EventPayload::PlanProposalAccepted(_)
        | EventPayload::PlanProposalRejected(_)
        | EventPayload::PlanSemanticReviewAccepted(_)
        | EventPayload::PlanSemanticReviewRejected(_) => Ok(true),
        EventPayload::PlannerInferenceObserved(observed) => Ok(matches!(
            observed.outcome,
            birdcode_protocol::PlannerInferenceObservation::Failed {
                error: birdcode_protocol::PlannerInferenceError {
                    retry: RetryDisposition::RequiresNewAttempt,
                    ..
                }
            }
        )),
        _ => Err(StoreError::InvalidStateEvent),
    }
}

pub(super) fn prepared_events_for_run(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Vec<EventEnvelope>, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(params![run_id.to_string(), session_id.to_string()], |row| {
        row.get::<_, String>(0)
    })?;
    rows.map(|row| decode_canonical_event(&row?)).collect()
}

pub(super) fn stage_identity(
    stage: &PlannerStageContext,
) -> (&ActorId, &birdcode_protocol::ModelLineage, &ArtifactRef) {
    match stage {
        PlannerStageContext::InitialPlan {
            model_actor_id,
            model_lineage,
            execution_policy_artifact,
            ..
        }
        | PlannerStageContext::InitialReview {
            model_actor_id,
            model_lineage,
            execution_policy_artifact,
            ..
        }
        | PlannerStageContext::Repair {
            model_actor_id,
            model_lineage,
            execution_policy_artifact,
            ..
        }
        | PlannerStageContext::FinalReview {
            model_actor_id,
            model_lineage,
            execution_policy_artifact,
            ..
        } => (model_actor_id, model_lineage, execution_policy_artifact),
    }
}

pub(super) fn stage_model_subject(
    stage: &PlannerStageContext,
) -> (RootPlanningStage, RootPlanningModelSubject) {
    let (_, lineage, _) = stage_identity(stage);
    match stage {
        PlannerStageContext::InitialPlan { .. } => (
            RootPlanningStage::InitialPlan,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::Producer,
                lineage: lineage.clone(),
            },
        ),
        PlannerStageContext::InitialReview { .. } => (
            RootPlanningStage::InitialReview,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::IndependentCritic,
                lineage: lineage.clone(),
            },
        ),
        PlannerStageContext::Repair { .. } => (
            RootPlanningStage::Repair,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::Producer,
                lineage: lineage.clone(),
            },
        ),
        PlannerStageContext::FinalReview { .. } => (
            RootPlanningStage::FinalReview,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::IndependentCritic,
                lineage: lineage.clone(),
            },
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlannerStageKind {
    InitialPlan,
    InitialReview,
    Repair,
    FinalReview,
}

pub(super) fn stage_kind(stage: &PlannerStageContext) -> PlannerStageKind {
    match stage {
        PlannerStageContext::InitialPlan { .. } => PlannerStageKind::InitialPlan,
        PlannerStageContext::InitialReview { .. } => PlannerStageKind::InitialReview,
        PlannerStageContext::Repair { .. } => PlannerStageKind::Repair,
        PlannerStageContext::FinalReview { .. } => PlannerStageKind::FinalReview,
    }
}
