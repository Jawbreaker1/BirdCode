//! Exhaustive artifact-reference classification for durable event payloads.

use birdcode_protocol::{
    ArtifactRef, ChildModelContextInventoryV1, ChildPreviousToolContextV1, ChildToolObservation,
    EventEnvelope, EventPayload, InputItem, PlannerStageContext, RepositoryToolObservedTerminalV2,
};

fn input_items_reference_artifact(items: &[InputItem], artifact: &ArtifactRef) -> bool {
    items.iter().any(
        |item| matches!(item, InputItem::Artifact { artifact: retained } if retained == artifact),
    )
}

fn child_model_context_references_artifact(
    inventory: &ChildModelContextInventoryV1,
    artifact: &ArtifactRef,
) -> bool {
    &inventory.work_order_artifact == artifact
        || &inventory.context_manifest_artifact == artifact
        || inventory
            .prior_plan
            .as_ref()
            .is_some_and(|prior| &prior.source_model_evidence_artifact == artifact)
        || inventory.previous_tool.as_ref().is_some_and(|tool| {
            let retained = match tool {
                ChildPreviousToolContextV1::Observed {
                    terminal_receipt_artifact,
                    ..
                }
                | ChildPreviousToolContextV1::Unknown {
                    terminal_receipt_artifact,
                    ..
                } => terminal_receipt_artifact,
            };
            retained == artifact
        })
}

#[allow(
    clippy::too_many_lines,
    reason = "one exhaustive event match is the closed artifact-reference authority"
)]
pub(crate) fn child_event_references_artifact(
    event: &EventEnvelope,
    artifact: &ArtifactRef,
) -> bool {
    if event.provenance.raw_artifact.as_ref() == Some(artifact) {
        return true;
    }
    match &event.payload {
        EventPayload::UserInput { items } => input_items_reference_artifact(items, artifact),
        EventPayload::RunCreated { run } => {
            input_items_reference_artifact(&run.spec.input, artifact)
        }
        EventPayload::ArtifactStored { artifact: retained } => retained == artifact,
        EventPayload::RootPlanningFailed(failure) => &failure.evidence_artifact == artifact,
        EventPayload::RootPlanningStageFailed(failure) => {
            &failure.execution_policy_artifact == artifact || &failure.evidence_artifact == artifact
        }
        EventPayload::PlannerInferencePrepared(prepared) => {
            &prepared.prompt_artifact == artifact
                || &prepared.request_artifact == artifact
                || prepared
                    .stage_context
                    .as_ref()
                    .is_some_and(|stage| match stage {
                        PlannerStageContext::InitialPlan {
                            execution_policy_artifact,
                            ..
                        } => execution_policy_artifact == artifact,
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
                            execution_policy_artifact == artifact
                                || critic_policy_artifact == artifact
                                || &candidate.plan_artifact == artifact
                        }
                        PlannerStageContext::Repair {
                            execution_policy_artifact,
                            candidate,
                            ..
                        } => {
                            execution_policy_artifact == artifact
                                || &candidate.plan_artifact == artifact
                        }
                    })
        }
        EventPayload::PlannerInferenceObserved(observed) => {
            &observed.normalized_complete_evidence_artifact == artifact
        }
        EventPayload::PlannerInferenceOutcomeUnknown(_)
        | EventPayload::SessionCreated { .. }
        | EventPayload::RunStateChanged { .. }
        | EventPayload::RunClaimed(_)
        | EventPayload::CancellationRequested(_)
        | EventPayload::ChildExecutionClaimAdopted(_)
        | EventPayload::ChildExecutionStarted(_)
        | EventPayload::ChildExecutionFinished(_)
        | EventPayload::RepositoryBrokerEpochActivatedV1(_)
        | EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(_)
        | EventPayload::RepositorySnapshotCleanupGrantedV1(_)
        | EventPayload::RepositorySnapshotCaptureAbandonedV2(_)
        | EventPayload::RepositorySnapshotReleaseReconciledV2(_)
        | EventPayload::WorkspaceRecoveryFinalizedV1(_)
        | EventPayload::BackendEvent { .. } => false,
        EventPayload::ReadOperationPrepared(prepared) => &prepared.request_artifact == artifact,
        EventPayload::ReadOperationObserved(observed) => {
            &observed.normalized_complete_evidence_artifact == artifact
        }
        EventPayload::PlanProposalRejected(rejected) => {
            &rejected.proposal_artifact == artifact
                || &rejected.validation_evidence_artifact == artifact
        }
        EventPayload::PlanProposalAccepted(accepted) => {
            &accepted.proposal_artifact == artifact
                || &accepted.accepted_plan_artifact == artifact
                || &accepted.validation_evidence_artifact == artifact
        }
        EventPayload::PlanSemanticReviewAccepted(accepted) => {
            &accepted.candidate.plan_artifact == artifact
                || &accepted.critique_artifact == artifact
                || &accepted.validation_evidence_artifact == artifact
        }
        EventPayload::PlanSemanticReviewRejected(rejected) => {
            &rejected.candidate.plan_artifact == artifact
                || &rejected.critique_artifact == artifact
                || &rejected.validation_evidence_artifact == artifact
        }
        EventPayload::PlannerTurnPreparedV1(prepared) => {
            &prepared.base_plan.artifact == artifact
                || &prepared.durable_evidence_packet_artifact == artifact
                || &prepared.durable_evidence_delta_artifact == artifact
                || &prepared.prompt_evidence_packet_artifact == artifact
                || &prepared.prompt_evidence_delta_artifact == artifact
                || &prepared.prompt_manifest_artifact == artifact
                || &prepared.prompt_artifact == artifact
                || &prepared.request_artifact == artifact
        }
        EventPayload::PlannerTurnObservedV1(observed) => {
            &observed.normalized_complete_evidence_artifact == artifact
        }
        EventPayload::PlannerTurnUnknownV1(unknown) => {
            &unknown.boundary_evidence_artifact == artifact
        }
        EventPayload::PlannerTurnAcceptedV1(accepted) => {
            &accepted.base_plan.artifact == artifact
                || &accepted.resulting_plan.artifact == artifact
                || &accepted.accepted_prompt_output_artifact == artifact
                || &accepted.validation_evidence_artifact == artifact
        }
        EventPayload::PlannerTurnRejectedV1(rejected) => {
            &rejected.base_plan.artifact == artifact
                || &rejected.rejected_output_artifact == artifact
                || &rejected.validation_evidence_artifact == artifact
        }
        EventPayload::ReconCompletionGateAcceptedV1(accepted) => {
            &accepted.resulting_plan.artifact == artifact || &accepted.receipt_artifact == artifact
        }
        EventPayload::RepositorySnapshotLeaseIssued(issued) => {
            &issued.snapshot.immutability_lease.lease_artifact == artifact
        }
        EventPayload::RepositoryWriterLeaseRevoked(revoked) => {
            &revoked.evidence_artifact == artifact
        }
        EventPayload::RepositorySnapshotCaptureAbandonedV1(abandoned) => {
            &abandoned.recovery_artifact == artifact
        }
        EventPayload::RepositorySnapshotLeaseReleased(released) => {
            &released.release_artifact == artifact
        }
        EventPayload::RepositorySnapshotReleaseReconciledV1(reconciled) => {
            &reconciled.recovery_artifact == artifact
        }
        EventPayload::ChildDelegationAuthorized(authorized) => {
            &authorized.accepted_plan_artifact == artifact
                || &authorized.work_order_artifact == artifact
                || &authorized.context_manifest_artifact == artifact
                || &authorized.spec.repository_authority.policy_artifact == artifact
                || &authorized
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact
                    == artifact
        }
        EventPayload::ChildDelegationAuthorizedV2(authorized) => {
            &authorized.accepted_prompt_output_artifact == artifact
                || &authorized.planner_work_order.work_order_artifact == artifact
                || &authorized.work_order_artifact == artifact
                || &authorized.context_manifest_artifact == artifact
                || &authorized.spec.repository_authority.policy_artifact == artifact
                || &authorized
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact
                    == artifact
        }
        EventPayload::ChildWorkOrderIssued(issued) => {
            &issued.work_order_artifact == artifact
                || &issued.context_manifest_artifact == artifact
                || &issued.spec.repository_authority.policy_artifact == artifact
                || &issued
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact
                    == artifact
        }
        EventPayload::ChildModelInferencePrepared(prepared) => {
            &prepared.prompt_manifest_artifact == artifact
                || &prepared.prompt_artifact == artifact
                || &prepared.request_artifact == artifact
                || child_model_context_references_artifact(&prepared.context_inventory, artifact)
        }
        EventPayload::ChildModelInferencePreparedV2(prepared) => {
            &prepared.prepared.prompt_manifest_artifact == artifact
                || &prepared.prepared.prompt_artifact == artifact
                || &prepared.prepared.request_artifact == artifact
                || child_model_context_references_artifact(
                    &prepared.prepared.context_inventory,
                    artifact,
                )
                || prepared
                    .supplied_tool_results
                    .iter()
                    .any(|supplied| &supplied.result_artifact == artifact)
        }
        EventPayload::ChildModelInferenceObserved(observed) => {
            &observed.normalized_complete_evidence_artifact == artifact
        }
        EventPayload::ChildModelInferenceOutcomeUnknown(unknown) => {
            &unknown.boundary_artifact == artifact
        }
        EventPayload::ChildToolPrepared(prepared) => {
            &prepared.prepared_receipt_artifact == artifact
                || &prepared.action_binding.validated_action_artifact == artifact
        }
        EventPayload::ChildToolObserved(observed) => {
            &observed.terminal_receipt_artifact == artifact
                || &observed.action_binding.validated_action_artifact == artifact
                || matches!(
                    &observed.outcome,
                    ChildToolObservation::Succeeded { result }
                        if result.result_artifact() == artifact
                )
        }
        EventPayload::ChildToolOutcomeUnknown(unknown) => {
            &unknown.terminal_receipt_artifact == artifact
                || &unknown.action_binding.validated_action_artifact == artifact
        }
        EventPayload::ChildToolPreparedV2(prepared) => {
            &prepared.prepared_receipt_artifact == artifact
                || &prepared.action_binding.validated_action_artifact == artifact
        }
        EventPayload::ChildToolDispatchStartedV2(started) => {
            &started.action_binding.validated_action_artifact == artifact
        }
        EventPayload::ChildToolObservedV2(observed) => {
            &observed.terminal_receipt_artifact == artifact
                || &observed.action_binding.validated_action_artifact == artifact
                || match &observed.terminal {
                    RepositoryToolObservedTerminalV2::Succeeded { result_artifact } => {
                        result_artifact == artifact
                    }
                    RepositoryToolObservedTerminalV2::Failed {
                        evidence_artifact, ..
                    }
                    | RepositoryToolObservedTerminalV2::AuthorizationDenied {
                        evidence_artifact,
                        ..
                    } => evidence_artifact == artifact,
                }
        }
        EventPayload::ChildToolOutcomeUnknownV2(unknown) => {
            &unknown.terminal_receipt_artifact == artifact
                || &unknown.action_binding.validated_action_artifact == artifact
        }
        EventPayload::ChildHandoffCommitted(handoff) => {
            &handoff.handoff_artifact == artifact
                || &handoff.action_binding.validated_action_artifact == artifact
        }
    }
}
