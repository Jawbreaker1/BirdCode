//! Child lifecycle identity and append-admission classifiers.

use super::durable_run_for_claim_refresh;
use super::{
    ChildExecutionOutcome, ChildModelInferenceObservation, ChildWorkOrderId, EventEnvelope,
    EventPayload, RepositorySnapshotLifecycleReplay, RunPurpose, RunState, StoreError,
    decode_stored_run, reject_parallel_recon_public_attempt_start,
    replay_repository_snapshot_lifecycle, validate_cancellation,
    validate_child_delegation_authorized, validate_child_delegation_authorized_v2,
    validate_child_reconnaissance_event, validate_plan_proposal_accepted,
    validate_plan_proposal_rejected, validate_plan_semantic_review_accepted,
    validate_plan_semantic_review_rejected, validate_planner_inference_observed,
    validate_planner_inference_prepared, validate_planner_inference_unknown,
    validate_planner_turn_accepted_v1, validate_planner_turn_observed_v1,
    validate_planner_turn_prepared_v1, validate_planner_turn_rejected_v1,
    validate_planner_turn_unknown_v1, validate_read_operation_observed,
    validate_read_operation_prepared, validate_recon_completion_gate_accepted_v1,
    validate_repository_broker_epoch_activated_v1,
    validate_repository_snapshot_capture_claim_adopted, validate_repository_snapshot_lease_issued,
    validate_repository_snapshot_lease_released, validate_repository_writer_lease_revoked,
    validate_root_planning_failed, validate_root_planning_failure_fence,
    validate_root_planning_stage_failed, validate_run_claim, validate_run_state_change,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventAdmission {
    PublicAppend,
    ParallelReconBootstrap,
    ParallelReconClaimRefresh,
}

pub(crate) fn child_work_order_id(payload: &EventPayload) -> Option<ChildWorkOrderId> {
    match payload {
        EventPayload::ChildWorkOrderIssued(issued) => Some(issued.spec.work_order_id),
        EventPayload::ChildExecutionClaimAdopted(adopted) => Some(adopted.work_order_id),
        EventPayload::ChildExecutionStarted(started) => Some(started.binding.work_order_id),
        EventPayload::ChildModelInferencePrepared(prepared) => Some(prepared.binding.work_order_id),
        EventPayload::ChildModelInferencePreparedV2(prepared) => {
            Some(prepared.prepared.binding.work_order_id)
        }
        EventPayload::ChildModelInferenceObserved(observed) => Some(observed.binding.work_order_id),
        EventPayload::ChildModelInferenceOutcomeUnknown(unknown) => {
            Some(unknown.binding.work_order_id)
        }
        EventPayload::ChildToolPrepared(prepared) => Some(prepared.binding.work_order_id),
        EventPayload::ChildToolObserved(observed) => Some(observed.binding.work_order_id),
        EventPayload::ChildToolOutcomeUnknown(unknown) => Some(unknown.binding.work_order_id),
        EventPayload::ChildToolPreparedV2(prepared) => Some(prepared.binding.work_order_id),
        EventPayload::ChildToolDispatchStartedV2(started) => Some(started.binding.work_order_id),
        EventPayload::ChildToolObservedV2(observed) => Some(observed.binding.work_order_id),
        EventPayload::ChildToolOutcomeUnknownV2(unknown) => Some(unknown.binding.work_order_id),
        EventPayload::ChildHandoffCommitted(handoff) => Some(handoff.binding.work_order_id),
        EventPayload::ChildExecutionFinished(finished) => Some(finished.binding.work_order_id),
        _ => None,
    }
}

pub(crate) fn is_child_terminal_reconciliation(payload: &EventPayload) -> bool {
    match payload {
        EventPayload::ChildModelInferenceObserved(observed) => matches!(
            &observed.outcome,
            ChildModelInferenceObservation::Failed { error }
                if error.kind == birdcode_protocol::ChildModelInferenceErrorKind::Cancelled
                    && error.cancellation.is_some()
        ),
        EventPayload::ChildModelInferenceOutcomeUnknown(unknown) => unknown.cancellation.is_some(),
        EventPayload::ChildToolObserved(_) | EventPayload::ChildToolObservedV2(_) => true,
        EventPayload::ChildToolOutcomeUnknown(unknown) => unknown.cancellation.is_some(),
        EventPayload::ChildToolOutcomeUnknownV2(unknown) => unknown.cancellation.is_some(),
        EventPayload::ChildExecutionFinished(finished) => {
            matches!(finished.outcome, ChildExecutionOutcome::Cancelled { .. })
        }
        EventPayload::SessionCreated { .. }
        | EventPayload::UserInput { .. }
        | EventPayload::RunCreated { .. }
        | EventPayload::RunStateChanged { .. }
        | EventPayload::RunClaimed(_)
        | EventPayload::CancellationRequested(_)
        | EventPayload::RootPlanningFailed(_)
        | EventPayload::RootPlanningStageFailed(_)
        | EventPayload::PlannerInferencePrepared(_)
        | EventPayload::PlannerInferenceObserved(_)
        | EventPayload::PlannerInferenceOutcomeUnknown(_)
        | EventPayload::ReadOperationPrepared(_)
        | EventPayload::ReadOperationObserved(_)
        | EventPayload::PlanProposalRejected(_)
        | EventPayload::PlanProposalAccepted(_)
        | EventPayload::PlanSemanticReviewAccepted(_)
        | EventPayload::PlanSemanticReviewRejected(_)
        | EventPayload::PlannerTurnPreparedV1(_)
        | EventPayload::PlannerTurnObservedV1(_)
        | EventPayload::PlannerTurnUnknownV1(_)
        | EventPayload::PlannerTurnAcceptedV1(_)
        | EventPayload::PlannerTurnRejectedV1(_)
        | EventPayload::ReconCompletionGateAcceptedV1(_)
        | EventPayload::RepositoryWriterLeaseRevoked(_)
        | EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(_)
        | EventPayload::RepositorySnapshotCaptureAbandonedV1(_)
        | EventPayload::RepositorySnapshotCleanupGrantedV1(_)
        | EventPayload::RepositorySnapshotCaptureAbandonedV2(_)
        | EventPayload::RepositorySnapshotLeaseIssued(_)
        | EventPayload::RepositorySnapshotLeaseReleased(_)
        | EventPayload::RepositorySnapshotReleaseReconciledV1(_)
        | EventPayload::RepositorySnapshotReleaseReconciledV2(_)
        | EventPayload::WorkspaceRecoveryFinalizedV1(_)
        | EventPayload::RepositoryBrokerEpochActivatedV1(_)
        | EventPayload::ChildDelegationAuthorized(_)
        | EventPayload::ChildDelegationAuthorizedV2(_)
        | EventPayload::ChildWorkOrderIssued(_)
        | EventPayload::ChildExecutionClaimAdopted(_)
        | EventPayload::ChildExecutionStarted(_)
        | EventPayload::ChildModelInferencePrepared(_)
        | EventPayload::ChildModelInferencePreparedV2(_)
        | EventPayload::ChildToolPrepared(_)
        | EventPayload::ChildToolPreparedV2(_)
        | EventPayload::ChildToolDispatchStartedV2(_)
        | EventPayload::ChildHandoffCommitted(_)
        | EventPayload::BackendEvent { .. }
        | EventPayload::ArtifactStored { .. } => false,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive event vocabulary is intentionally routed through one closed match"
)]
pub(crate) fn validate_generic_event(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    artifact_root: &Path,
    admission: EventAdmission,
) -> Result<(), StoreError> {
    validate_pending_cleanup_authority_fence(transaction, event, artifact_root)?;
    validate_root_planning_failure_fence(transaction, event)?;
    match &event.payload {
        EventPayload::SessionCreated { .. }
        | EventPayload::RunCreated { .. }
        | EventPayload::RepositorySnapshotCaptureAbandonedV1(_)
        | EventPayload::RepositorySnapshotReleaseReconciledV1(_)
        | EventPayload::RepositorySnapshotCleanupGrantedV1(_)
        | EventPayload::RepositorySnapshotCaptureAbandonedV2(_)
        | EventPayload::RepositorySnapshotReleaseReconciledV2(_)
        | EventPayload::WorkspaceRecoveryFinalizedV1(_)
        | EventPayload::ChildToolDispatchStartedV2(_) => Err(StoreError::InvalidStateEvent),
        EventPayload::RunStateChanged { from, to } => {
            validate_run_state_change(transaction, event, *from, *to, artifact_root)
        }
        EventPayload::RunClaimed(claim) => {
            validate_run_claim(transaction, event, claim, artifact_root, admission)
        }
        EventPayload::CancellationRequested(cancellation) => {
            validate_cancellation(transaction, event, cancellation)
        }
        EventPayload::RootPlanningFailed(failure) => {
            validate_root_planning_failed(transaction, event, failure, artifact_root)
        }
        EventPayload::RootPlanningStageFailed(failure) => {
            validate_root_planning_stage_failed(transaction, event, failure, artifact_root)
        }
        EventPayload::PlannerInferencePrepared(prepared) => {
            validate_planner_inference_prepared(transaction, event, prepared, artifact_root)
        }
        EventPayload::PlannerInferenceObserved(observed) => {
            validate_planner_inference_observed(transaction, event, observed, artifact_root)
        }
        EventPayload::PlannerInferenceOutcomeUnknown(unknown) => {
            validate_planner_inference_unknown(transaction, event, unknown, artifact_root)
        }
        EventPayload::ReadOperationPrepared(prepared) => {
            validate_read_operation_prepared(transaction, event, prepared)
        }
        EventPayload::ReadOperationObserved(observed) => {
            validate_read_operation_observed(transaction, event, observed)
        }
        EventPayload::PlanProposalRejected(rejected) => {
            validate_plan_proposal_rejected(transaction, event, rejected, artifact_root)
        }
        EventPayload::PlanProposalAccepted(accepted) => {
            validate_plan_proposal_accepted(transaction, event, accepted, artifact_root)
        }
        EventPayload::PlanSemanticReviewAccepted(accepted) => {
            validate_plan_semantic_review_accepted(transaction, event, accepted, artifact_root)
        }
        EventPayload::PlanSemanticReviewRejected(rejected) => {
            validate_plan_semantic_review_rejected(transaction, event, rejected, artifact_root)
        }
        EventPayload::PlannerTurnPreparedV1(prepared) => {
            validate_planner_turn_prepared_v1(transaction, event, prepared, artifact_root)
        }
        EventPayload::PlannerTurnObservedV1(observed) => {
            validate_planner_turn_observed_v1(transaction, event, observed, artifact_root)
        }
        EventPayload::PlannerTurnUnknownV1(unknown) => {
            validate_planner_turn_unknown_v1(transaction, event, unknown, artifact_root)
        }
        EventPayload::PlannerTurnAcceptedV1(accepted) => {
            validate_planner_turn_accepted_v1(transaction, event, accepted, artifact_root)
        }
        EventPayload::PlannerTurnRejectedV1(rejected) => {
            validate_planner_turn_rejected_v1(transaction, event, rejected, artifact_root)
        }
        EventPayload::ReconCompletionGateAcceptedV1(accepted) => {
            validate_recon_completion_gate_accepted_v1(transaction, event, accepted, artifact_root)
        }
        EventPayload::RepositoryWriterLeaseRevoked(revoked) => {
            validate_repository_writer_lease_revoked(transaction, event, revoked, artifact_root)
        }
        EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(adopted) => {
            if admission != EventAdmission::ParallelReconClaimRefresh {
                return Err(StoreError::InvalidStateEvent);
            }
            validate_repository_snapshot_capture_claim_adopted(
                transaction,
                event,
                adopted,
                artifact_root,
            )
        }
        EventPayload::RepositorySnapshotLeaseIssued(issued) => {
            validate_repository_snapshot_lease_issued(transaction, event, issued, artifact_root)
        }
        EventPayload::RepositorySnapshotLeaseReleased(released) => {
            validate_repository_snapshot_lease_released(transaction, event, released, artifact_root)
        }
        EventPayload::RepositoryBrokerEpochActivatedV1(activated) => {
            validate_repository_broker_epoch_activated_v1(transaction, event, activated)
        }
        EventPayload::ChildDelegationAuthorized(authorized) => {
            reject_parallel_recon_generic_child_append(transaction, event, admission)?;
            validate_child_delegation_authorized(transaction, event, authorized, artifact_root)
        }
        EventPayload::ChildDelegationAuthorizedV2(authorized) => {
            reject_parallel_recon_generic_child_append(transaction, event, admission)?;
            validate_child_delegation_authorized_v2(transaction, event, authorized, artifact_root)
        }
        EventPayload::ChildWorkOrderIssued(_) => {
            reject_parallel_recon_generic_child_append(transaction, event, admission)?;
            validate_child_reconnaissance_event(transaction, event, artifact_root)
        }
        EventPayload::ChildExecutionClaimAdopted(_) => {
            reject_parallel_recon_generic_claim_adoption(transaction, event, admission)?;
            validate_child_reconnaissance_event(transaction, event, artifact_root)
        }
        EventPayload::ChildExecutionStarted(_) => {
            reject_parallel_recon_public_attempt_start(transaction, event, admission)?;
            validate_child_reconnaissance_event(transaction, event, artifact_root)
        }
        EventPayload::ChildModelInferencePrepared(_)
        | EventPayload::ChildModelInferencePreparedV2(_)
        | EventPayload::ChildModelInferenceObserved(_)
        | EventPayload::ChildModelInferenceOutcomeUnknown(_)
        | EventPayload::ChildToolPrepared(_)
        | EventPayload::ChildToolObserved(_)
        | EventPayload::ChildToolOutcomeUnknown(_)
        | EventPayload::ChildToolPreparedV2(_)
        | EventPayload::ChildToolObservedV2(_)
        | EventPayload::ChildToolOutcomeUnknownV2(_)
        | EventPayload::ChildHandoffCommitted(_)
        | EventPayload::ChildExecutionFinished(_) => {
            validate_child_reconnaissance_event(transaction, event, artifact_root)
        }
        EventPayload::BackendEvent { .. } => {
            if event.run_id.is_none() {
                Err(StoreError::InvalidStateEvent)
            } else {
                Ok(())
            }
        }
        EventPayload::UserInput { .. } | EventPayload::ArtifactStored { .. } => Ok(()),
    }
}

pub(crate) fn pending_cleanup_blocks_payload(payload: &EventPayload) -> bool {
    matches!(
        payload,
        EventPayload::RunClaimed(_)
            | EventPayload::RunStateChanged {
                to: RunState::Completed | RunState::Failed | RunState::Cancelled,
                ..
            }
            | EventPayload::RepositoryWriterLeaseRevoked(_)
            | EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(_)
            | EventPayload::RepositorySnapshotCaptureAbandonedV1(_)
            | EventPayload::RepositorySnapshotLeaseIssued(_)
            | EventPayload::RepositorySnapshotLeaseReleased(_)
            | EventPayload::RepositorySnapshotReleaseReconciledV1(_)
            | EventPayload::RepositorySnapshotCleanupGrantedV1(_)
            | EventPayload::RepositorySnapshotCaptureAbandonedV2(_)
            | EventPayload::RepositorySnapshotReleaseReconciledV2(_)
            | EventPayload::WorkspaceRecoveryFinalizedV1(_)
            | EventPayload::RepositoryBrokerEpochActivatedV1(_)
            | EventPayload::ChildDelegationAuthorized(_)
            | EventPayload::ChildDelegationAuthorizedV2(_)
            | EventPayload::ChildWorkOrderIssued(_)
            | EventPayload::ChildExecutionClaimAdopted(_)
            | EventPayload::ChildExecutionStarted(_)
            | EventPayload::ChildModelInferencePrepared(_)
            | EventPayload::ChildModelInferencePreparedV2(_)
            | EventPayload::ChildModelInferenceObserved(_)
            | EventPayload::ChildModelInferenceOutcomeUnknown(_)
            | EventPayload::ChildToolPrepared(_)
            | EventPayload::ChildToolObserved(_)
            | EventPayload::ChildToolOutcomeUnknown(_)
            | EventPayload::ChildToolPreparedV2(_)
            | EventPayload::ChildToolDispatchStartedV2(_)
            | EventPayload::ChildToolObservedV2(_)
            | EventPayload::ChildToolOutcomeUnknownV2(_)
            | EventPayload::ChildHandoffCommitted(_)
            | EventPayload::ChildExecutionFinished(_)
    )
}

pub(crate) fn validate_pending_cleanup_authority_fence(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let Some(run_id) = event.run_id else {
        return Ok(());
    };
    if !pending_cleanup_blocks_payload(&event.payload) {
        return Ok(());
    }
    let run = durable_run_for_claim_refresh(transaction, run_id)?;
    if run.spec.purpose == RunPurpose::ParallelRepositoryReconnaissanceV1
        && matches!(
            replay_repository_snapshot_lifecycle(transaction, artifact_root, &run)?,
            RepositorySnapshotLifecycleReplay::PendingCleanup { .. }
        )
    {
        Err(StoreError::InvalidStateEvent)
    } else {
        Ok(())
    }
}

pub(crate) fn reject_parallel_recon_generic_child_append(
    transaction: &Connection,
    event: &EventEnvelope,
    admission: EventAdmission,
) -> Result<(), StoreError> {
    if admission == EventAdmission::ParallelReconBootstrap {
        return Ok(());
    }
    let run_id = event.run_id.ok_or(StoreError::InvalidStateEvent)?;
    let run_json = transaction
        .query_row(
            "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
            params![run_id.to_string(), event.session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    let run = decode_stored_run(&run_json)?;
    if run.spec.purpose == RunPurpose::ParallelRepositoryReconnaissanceV1 {
        Err(StoreError::InvalidStateEvent)
    } else {
        Ok(())
    }
}

pub(crate) fn reject_parallel_recon_generic_claim_adoption(
    transaction: &Connection,
    event: &EventEnvelope,
    admission: EventAdmission,
) -> Result<(), StoreError> {
    let run_id = event.run_id.ok_or(StoreError::InvalidStateEvent)?;
    let run = durable_run_for_claim_refresh(transaction, run_id)?;
    if run.spec.purpose == RunPurpose::ParallelRepositoryReconnaissanceV1
        && admission != EventAdmission::ParallelReconClaimRefresh
    {
        Err(StoreError::InvalidStateEvent)
    } else {
        Ok(())
    }
}
