//! Durable event payload vocabulary.

use super::{
    ArtifactRef, CancellationRequested, ChildDelegationAuthorized, ChildDelegationAuthorizedV2,
    ChildExecutionClaimAdoptedV1, ChildExecutionFinished, ChildExecutionStarted,
    ChildHandoffCommitted, ChildModelInferenceObserved, ChildModelInferenceOutcomeUnknown,
    ChildModelInferencePrepared, ChildModelInferencePreparedV2, ChildToolObserved,
    ChildToolObservedV2, ChildToolOutcomeUnknown, ChildToolOutcomeUnknownV2, ChildToolPrepared,
    ChildToolPreparedV2, ChildWorkOrderIssued, InputItem, PlanProposalAccepted,
    PlanProposalRejected, PlanSemanticReviewAccepted, PlanSemanticReviewRejected,
    PlannerInferenceObserved, PlannerInferenceOutcomeUnknown, PlannerInferencePrepared,
    PlannerTurnAcceptedV1, PlannerTurnObservedV1, PlannerTurnPreparedV1, PlannerTurnRejectedV1,
    PlannerTurnUnknownV1, ReadOperationObserved, ReadOperationPrepared,
    ReconCompletionGateAcceptedV1, RepositoryBrokerEpochActivatedV1,
    RepositorySnapshotCaptureAbandonedV1, RepositorySnapshotCaptureAbandonedV2,
    RepositorySnapshotCaptureClaimAdoptedV1, RepositorySnapshotCleanupGrantedV1,
    RepositorySnapshotLeaseIssuedV1, RepositorySnapshotLeaseReleasedV1,
    RepositorySnapshotReleaseReconciledV1, RepositorySnapshotReleaseReconciledV2,
    RepositoryWriterLeaseRevokedV1, RootPlanningFailed, RootPlanningStageFailed, Run, RunClaimed,
    RunState, Session, WorkspaceRecoveryFinalizedV1,
};
use serde::{Deserialize, Serialize};

// Boxing an existing variant would change this protocol's externally visible
// Rust shape and require call-site migration despite leaving JSON unchanged.
// Keep the stable typed API and wire representation until a versioned protocol
// change can introduce indirection deliberately.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing PlannerInferencePrepared would be a versioned public protocol API change"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "data",
    rename_all = "snake_case"
)]
pub enum EventPayload {
    SessionCreated {
        session: Session,
    },
    UserInput {
        items: Vec<InputItem>,
    },
    RunCreated {
        run: Run,
    },
    RunStateChanged {
        from: RunState,
        to: RunState,
    },
    RunClaimed(RunClaimed),
    CancellationRequested(CancellationRequested),
    RootPlanningFailed(RootPlanningFailed),
    RootPlanningStageFailed(RootPlanningStageFailed),
    PlannerInferencePrepared(PlannerInferencePrepared),
    PlannerInferenceObserved(PlannerInferenceObserved),
    PlannerInferenceOutcomeUnknown(PlannerInferenceOutcomeUnknown),
    ReadOperationPrepared(ReadOperationPrepared),
    ReadOperationObserved(ReadOperationObserved),
    PlanProposalRejected(PlanProposalRejected),
    PlanProposalAccepted(PlanProposalAccepted),
    PlanSemanticReviewAccepted(PlanSemanticReviewAccepted),
    PlanSemanticReviewRejected(PlanSemanticReviewRejected),
    PlannerTurnPreparedV1(PlannerTurnPreparedV1),
    PlannerTurnObservedV1(PlannerTurnObservedV1),
    PlannerTurnUnknownV1(PlannerTurnUnknownV1),
    PlannerTurnAcceptedV1(PlannerTurnAcceptedV1),
    PlannerTurnRejectedV1(PlannerTurnRejectedV1),
    ReconCompletionGateAcceptedV1(ReconCompletionGateAcceptedV1),
    RepositoryWriterLeaseRevoked(RepositoryWriterLeaseRevokedV1),
    RepositorySnapshotCaptureClaimAdoptedV1(RepositorySnapshotCaptureClaimAdoptedV1),
    RepositorySnapshotCleanupGrantedV1(RepositorySnapshotCleanupGrantedV1),
    RepositorySnapshotCaptureAbandonedV1(RepositorySnapshotCaptureAbandonedV1),
    RepositorySnapshotCaptureAbandonedV2(RepositorySnapshotCaptureAbandonedV2),
    RepositorySnapshotLeaseIssued(RepositorySnapshotLeaseIssuedV1),
    RepositorySnapshotLeaseReleased(RepositorySnapshotLeaseReleasedV1),
    RepositorySnapshotReleaseReconciledV1(RepositorySnapshotReleaseReconciledV1),
    RepositorySnapshotReleaseReconciledV2(RepositorySnapshotReleaseReconciledV2),
    WorkspaceRecoveryFinalizedV1(WorkspaceRecoveryFinalizedV1),
    RepositoryBrokerEpochActivatedV1(RepositoryBrokerEpochActivatedV1),
    ChildDelegationAuthorized(ChildDelegationAuthorized),
    ChildDelegationAuthorizedV2(ChildDelegationAuthorizedV2),
    ChildWorkOrderIssued(ChildWorkOrderIssued),
    ChildExecutionClaimAdopted(ChildExecutionClaimAdoptedV1),
    ChildExecutionStarted(ChildExecutionStarted),
    ChildModelInferencePrepared(ChildModelInferencePrepared),
    ChildModelInferencePreparedV2(ChildModelInferencePreparedV2),
    ChildModelInferenceObserved(ChildModelInferenceObserved),
    ChildModelInferenceOutcomeUnknown(ChildModelInferenceOutcomeUnknown),
    ChildToolPrepared(ChildToolPrepared),
    ChildToolObserved(ChildToolObserved),
    ChildToolOutcomeUnknown(ChildToolOutcomeUnknown),
    ChildToolPreparedV2(ChildToolPreparedV2),
    ChildToolObservedV2(ChildToolObservedV2),
    ChildToolOutcomeUnknownV2(ChildToolOutcomeUnknownV2),
    ChildHandoffCommitted(ChildHandoffCommitted),
    ChildExecutionFinished(ChildExecutionFinished),
    /// Legacy extension envelope for non-core backend telemetry only.
    ///
    /// Durable root planning MUST NOT encode inference, reads, proposals,
    /// cancellation, claims, or lifecycle transitions through this variant.
    /// Those records use the typed variants above so storage can enforce their
    /// causal and budget invariants.
    BackendEvent {
        event_type: String,
        data: serde_json::Value,
    },
    ArtifactStored {
        artifact: ArtifactRef,
    },
}
