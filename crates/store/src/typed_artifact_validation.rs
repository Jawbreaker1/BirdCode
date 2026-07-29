//! Exhaustive artifact-reference costing and on-disk verification.

use super::{
    ArtifactValidationCost, StoreError, add_stage_artifacts, verify_artifact_at_root,
    verify_input_artifacts, verify_stage_artifacts,
};
use birdcode_protocol::{
    ChildExecutionFailureCauseV1, ChildExecutionOutcome, ChildModelContextInventoryV1,
    ChildPreviousToolContextV1, ChildToolObservation, EventPayload, Provenance,
    RepositoryToolObservedTerminalV2,
};
use std::path::Path;

#[allow(
    clippy::too_many_lines,
    reason = "the closed event enum keeps all typed artifact-reference checks exhaustive"
)]
pub(crate) fn validate_typed_artifact_refs(
    artifact_root: &Path,
    provenance: &Provenance,
    payload: &EventPayload,
) -> Result<(), StoreError> {
    if matches!(payload, EventPayload::BackendEvent { .. }) && provenance.raw_artifact.is_none() {
        return Err(StoreError::InvalidStateEvent);
    }
    let mut cost = ArtifactValidationCost::default();
    if let Some(artifact) = &provenance.raw_artifact {
        cost.add(artifact)?;
    }
    match payload {
        EventPayload::UserInput { items } => cost.add_inputs(items)?,
        EventPayload::RunCreated { run } => cost.add_inputs(&run.spec.input)?,
        EventPayload::ArtifactStored { artifact } => cost.add(artifact)?,
        EventPayload::PlannerInferencePrepared(prepared) => {
            cost.add(&prepared.prompt_artifact)?;
            cost.add(&prepared.request_artifact)?;
            if let Some(stage) = &prepared.stage_context {
                add_stage_artifacts(&mut cost, stage)?;
            }
        }
        EventPayload::RootPlanningFailed(failure) => {
            cost.add(&failure.evidence_artifact)?;
        }
        EventPayload::RootPlanningStageFailed(failure) => {
            cost.add(&failure.execution_policy_artifact)?;
            cost.add(&failure.evidence_artifact)?;
        }
        EventPayload::PlannerInferenceObserved(observed) => {
            cost.add(&observed.normalized_complete_evidence_artifact)?;
        }
        EventPayload::ReadOperationPrepared(prepared) => {
            cost.add(&prepared.request_artifact)?;
        }
        EventPayload::ReadOperationObserved(observed) => {
            cost.add(&observed.normalized_complete_evidence_artifact)?;
        }
        EventPayload::PlanProposalRejected(rejected) => {
            cost.add(&rejected.proposal_artifact)?;
            cost.add(&rejected.validation_evidence_artifact)?;
        }
        EventPayload::PlanProposalAccepted(accepted) => {
            cost.add(&accepted.proposal_artifact)?;
            cost.add(&accepted.accepted_plan_artifact)?;
            cost.add(&accepted.validation_evidence_artifact)?;
        }
        EventPayload::PlanSemanticReviewAccepted(accepted) => {
            cost.add(&accepted.candidate.plan_artifact)?;
            cost.add(&accepted.critique_artifact)?;
            cost.add(&accepted.validation_evidence_artifact)?;
        }
        EventPayload::PlanSemanticReviewRejected(rejected) => {
            cost.add(&rejected.candidate.plan_artifact)?;
            cost.add(&rejected.critique_artifact)?;
            cost.add(&rejected.validation_evidence_artifact)?;
        }
        EventPayload::PlannerTurnPreparedV1(prepared) => {
            cost.add(&prepared.base_plan.artifact)?;
            cost.add(&prepared.durable_evidence_packet_artifact)?;
            cost.add(&prepared.durable_evidence_delta_artifact)?;
            cost.add(&prepared.prompt_evidence_packet_artifact)?;
            cost.add(&prepared.prompt_evidence_delta_artifact)?;
            cost.add(&prepared.prompt_manifest_artifact)?;
            cost.add(&prepared.prompt_artifact)?;
            cost.add(&prepared.request_artifact)?;
        }
        EventPayload::PlannerTurnObservedV1(observed) => {
            cost.add(&observed.normalized_complete_evidence_artifact)?;
        }
        EventPayload::PlannerTurnUnknownV1(unknown) => {
            cost.add(&unknown.boundary_evidence_artifact)?;
        }
        EventPayload::PlannerTurnAcceptedV1(accepted) => {
            cost.add(&accepted.base_plan.artifact)?;
            cost.add(&accepted.resulting_plan.artifact)?;
            cost.add(&accepted.accepted_prompt_output_artifact)?;
            cost.add(&accepted.validation_evidence_artifact)?;
        }
        EventPayload::PlannerTurnRejectedV1(rejected) => {
            cost.add(&rejected.base_plan.artifact)?;
            cost.add(&rejected.rejected_output_artifact)?;
            cost.add(&rejected.validation_evidence_artifact)?;
        }
        EventPayload::ReconCompletionGateAcceptedV1(accepted) => {
            cost.add(&accepted.resulting_plan.artifact)?;
            cost.add(&accepted.receipt_artifact)?;
        }
        EventPayload::RepositorySnapshotLeaseIssued(issued) => {
            cost.add(&issued.snapshot.immutability_lease.lease_artifact)?;
        }
        EventPayload::RepositoryWriterLeaseRevoked(revoked) => {
            cost.add(&revoked.evidence_artifact)?;
        }
        EventPayload::RepositorySnapshotCaptureAbandonedV1(abandoned) => {
            cost.add(&abandoned.recovery_artifact)?;
        }
        EventPayload::RepositorySnapshotCleanupGrantedV1(granted) => {
            cost.add(&granted.safety_evidence.evidence_artifact)?;
            let safety = &granted.safety_evidence.evidence;
            cost.add(&safety.process_quiescence.inspection_artifact)?;
            cost.add(&safety.initial_inspection.inspection_artifact)?;
            let topology = &safety.initial_inspection.inspection.topology_inspection;
            cost.add(&topology.inspection_artifact)?;
            cost.add(&topology.inspection.stdout_artifact)?;
            cost.add(&topology.inspection.stderr_artifact)?;
        }
        EventPayload::RepositorySnapshotCaptureAbandonedV2(abandoned) => {
            cost.add(&abandoned.recovery_artifact)?;
        }
        EventPayload::RepositorySnapshotLeaseReleased(released) => {
            cost.add(&released.release_artifact)?;
        }
        EventPayload::RepositorySnapshotReleaseReconciledV1(reconciled) => {
            cost.add(&reconciled.recovery_artifact)?;
        }
        EventPayload::RepositorySnapshotReleaseReconciledV2(reconciled) => {
            cost.add(&reconciled.recovery_artifact)?;
        }
        EventPayload::WorkspaceRecoveryFinalizedV1(finalized) => {
            cost.add(&finalized.recovery_artifact)?;
            cost.add(&finalized.finalization_artifact)?;
        }
        EventPayload::ChildDelegationAuthorized(authorized) => {
            cost.add(&authorized.accepted_plan_artifact)?;
            cost.add(&authorized.work_order_artifact)?;
            cost.add(&authorized.context_manifest_artifact)?;
            cost.add(&authorized.spec.repository_authority.policy_artifact)?;
            cost.add(
                &authorized
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact,
            )?;
        }
        EventPayload::ChildDelegationAuthorizedV2(authorized) => {
            cost.add(&authorized.accepted_prompt_output_artifact)?;
            cost.add(&authorized.planner_work_order.work_order_artifact)?;
            cost.add(&authorized.work_order_artifact)?;
            cost.add(&authorized.context_manifest_artifact)?;
            cost.add(&authorized.spec.repository_authority.policy_artifact)?;
            cost.add(
                &authorized
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact,
            )?;
        }
        EventPayload::ChildWorkOrderIssued(issued) => {
            cost.add(&issued.work_order_artifact)?;
            cost.add(&issued.context_manifest_artifact)?;
            cost.add(&issued.spec.repository_authority.policy_artifact)?;
            cost.add(
                &issued
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact,
            )?;
        }
        EventPayload::ChildModelInferencePrepared(prepared) => {
            cost.add(&prepared.prompt_manifest_artifact)?;
            cost.add(&prepared.prompt_artifact)?;
            cost.add(&prepared.request_artifact)?;
            add_child_model_context_artifacts(&mut cost, &prepared.context_inventory)?;
        }
        EventPayload::ChildModelInferencePreparedV2(prepared) => {
            cost.add(&prepared.prepared.prompt_manifest_artifact)?;
            cost.add(&prepared.prepared.prompt_artifact)?;
            cost.add(&prepared.prepared.request_artifact)?;
            add_child_model_context_artifacts(&mut cost, &prepared.prepared.context_inventory)?;
            for supplied in &prepared.supplied_tool_results {
                cost.add(&supplied.result_artifact)?;
            }
        }
        EventPayload::ChildModelInferenceObserved(observed) => {
            cost.add(&observed.normalized_complete_evidence_artifact)?;
        }
        EventPayload::ChildModelInferenceOutcomeUnknown(unknown) => {
            cost.add(&unknown.boundary_artifact)?;
        }
        EventPayload::ChildToolPrepared(prepared) => {
            cost.add(&prepared.prepared_receipt_artifact)?;
            cost.add(&prepared.action_binding.validated_action_artifact)?;
        }
        EventPayload::ChildToolObserved(observed) => {
            cost.add(&observed.terminal_receipt_artifact)?;
            cost.add(&observed.action_binding.validated_action_artifact)?;
            if let ChildToolObservation::Succeeded { result } = &observed.outcome {
                cost.add(result.result_artifact())?;
            }
        }
        EventPayload::ChildToolOutcomeUnknown(unknown) => {
            cost.add(&unknown.terminal_receipt_artifact)?;
            cost.add(&unknown.action_binding.validated_action_artifact)?;
        }
        EventPayload::ChildToolPreparedV2(prepared) => {
            cost.add(&prepared.prepared_receipt_artifact)?;
            cost.add(&prepared.action_binding.validated_action_artifact)?;
        }
        EventPayload::ChildToolDispatchStartedV2(started) => {
            cost.add(&started.action_binding.validated_action_artifact)?;
        }
        EventPayload::ChildToolObservedV2(observed) => {
            cost.add(&observed.terminal_receipt_artifact)?;
            cost.add(&observed.action_binding.validated_action_artifact)?;
            match &observed.terminal {
                RepositoryToolObservedTerminalV2::Succeeded { result_artifact } => {
                    cost.add(result_artifact)?;
                }
                RepositoryToolObservedTerminalV2::Failed {
                    evidence_artifact, ..
                }
                | RepositoryToolObservedTerminalV2::AuthorizationDenied {
                    evidence_artifact, ..
                } => cost.add(evidence_artifact)?,
            }
        }
        EventPayload::ChildToolOutcomeUnknownV2(unknown) => {
            cost.add(&unknown.terminal_receipt_artifact)?;
            cost.add(&unknown.action_binding.validated_action_artifact)?;
        }
        EventPayload::ChildHandoffCommitted(handoff) => {
            cost.add(&handoff.handoff_artifact)?;
            cost.add(&handoff.action_binding.validated_action_artifact)?;
        }
        EventPayload::ChildExecutionFinished(finished) => {
            if let ChildExecutionOutcome::Failed {
                cause:
                    ChildExecutionFailureCauseV1::RuntimeEvidence {
                        evidence_artifact, ..
                    },
                ..
            } = &finished.outcome
            {
                cost.add(evidence_artifact)?;
            }
        }
        EventPayload::SessionCreated { .. }
        | EventPayload::RunStateChanged { .. }
        | EventPayload::RunClaimed(_)
        | EventPayload::CancellationRequested(_)
        | EventPayload::PlannerInferenceOutcomeUnknown(_)
        | EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(_)
        | EventPayload::RepositoryBrokerEpochActivatedV1(_)
        | EventPayload::ChildExecutionClaimAdopted(_)
        | EventPayload::ChildExecutionStarted(_)
        | EventPayload::BackendEvent { .. } => {}
    }
    cost.enforce_event_limit()?;

    if let Some(artifact) = &provenance.raw_artifact {
        verify_artifact_at_root(artifact_root, artifact)?;
    }
    match payload {
        EventPayload::UserInput { items } => verify_input_artifacts(artifact_root, items),
        EventPayload::RunCreated { run } => verify_input_artifacts(artifact_root, &run.spec.input),
        EventPayload::ArtifactStored { artifact } => {
            verify_artifact_at_root(artifact_root, artifact)
        }
        EventPayload::PlannerInferencePrepared(prepared) => {
            verify_artifact_at_root(artifact_root, &prepared.prompt_artifact)?;
            verify_artifact_at_root(artifact_root, &prepared.request_artifact)?;
            if let Some(stage) = &prepared.stage_context {
                verify_stage_artifacts(artifact_root, stage)?;
            }
            Ok(())
        }
        EventPayload::RootPlanningFailed(failure) => {
            verify_artifact_at_root(artifact_root, &failure.evidence_artifact)
        }
        EventPayload::RootPlanningStageFailed(failure) => {
            verify_artifact_at_root(artifact_root, &failure.evidence_artifact)
        }
        EventPayload::PlannerInferenceObserved(observed) => verify_artifact_at_root(
            artifact_root,
            &observed.normalized_complete_evidence_artifact,
        ),
        EventPayload::ReadOperationPrepared(prepared) => {
            verify_artifact_at_root(artifact_root, &prepared.request_artifact)
        }
        EventPayload::ReadOperationObserved(observed) => verify_artifact_at_root(
            artifact_root,
            &observed.normalized_complete_evidence_artifact,
        ),
        EventPayload::PlanProposalRejected(rejected) => {
            verify_artifact_at_root(artifact_root, &rejected.proposal_artifact)?;
            verify_artifact_at_root(artifact_root, &rejected.validation_evidence_artifact)
        }
        EventPayload::PlanProposalAccepted(accepted) => {
            verify_artifact_at_root(artifact_root, &accepted.proposal_artifact)?;
            verify_artifact_at_root(artifact_root, &accepted.accepted_plan_artifact)?;
            verify_artifact_at_root(artifact_root, &accepted.validation_evidence_artifact)
        }
        EventPayload::PlanSemanticReviewAccepted(accepted) => {
            verify_artifact_at_root(artifact_root, &accepted.candidate.plan_artifact)?;
            verify_artifact_at_root(artifact_root, &accepted.critique_artifact)?;
            verify_artifact_at_root(artifact_root, &accepted.validation_evidence_artifact)
        }
        EventPayload::PlanSemanticReviewRejected(rejected) => {
            verify_artifact_at_root(artifact_root, &rejected.candidate.plan_artifact)?;
            verify_artifact_at_root(artifact_root, &rejected.critique_artifact)?;
            verify_artifact_at_root(artifact_root, &rejected.validation_evidence_artifact)
        }
        EventPayload::PlannerTurnPreparedV1(prepared) => {
            for artifact in [
                &prepared.base_plan.artifact,
                &prepared.durable_evidence_packet_artifact,
                &prepared.durable_evidence_delta_artifact,
                &prepared.prompt_evidence_packet_artifact,
                &prepared.prompt_evidence_delta_artifact,
                &prepared.prompt_manifest_artifact,
                &prepared.prompt_artifact,
                &prepared.request_artifact,
            ] {
                verify_artifact_at_root(artifact_root, artifact)?;
            }
            Ok(())
        }
        EventPayload::PlannerTurnObservedV1(observed) => verify_artifact_at_root(
            artifact_root,
            &observed.normalized_complete_evidence_artifact,
        ),
        EventPayload::PlannerTurnUnknownV1(unknown) => {
            verify_artifact_at_root(artifact_root, &unknown.boundary_evidence_artifact)
        }
        EventPayload::PlannerTurnAcceptedV1(accepted) => {
            for artifact in [
                &accepted.base_plan.artifact,
                &accepted.resulting_plan.artifact,
                &accepted.accepted_prompt_output_artifact,
                &accepted.validation_evidence_artifact,
            ] {
                verify_artifact_at_root(artifact_root, artifact)?;
            }
            Ok(())
        }
        EventPayload::PlannerTurnRejectedV1(rejected) => {
            for artifact in [
                &rejected.base_plan.artifact,
                &rejected.rejected_output_artifact,
                &rejected.validation_evidence_artifact,
            ] {
                verify_artifact_at_root(artifact_root, artifact)?;
            }
            Ok(())
        }
        EventPayload::ReconCompletionGateAcceptedV1(accepted) => {
            verify_artifact_at_root(artifact_root, &accepted.resulting_plan.artifact)?;
            verify_artifact_at_root(artifact_root, &accepted.receipt_artifact)
        }
        EventPayload::RepositorySnapshotLeaseIssued(issued) => verify_artifact_at_root(
            artifact_root,
            &issued.snapshot.immutability_lease.lease_artifact,
        ),
        EventPayload::RepositoryWriterLeaseRevoked(revoked) => {
            verify_artifact_at_root(artifact_root, &revoked.evidence_artifact)
        }
        EventPayload::RepositorySnapshotCaptureAbandonedV1(abandoned) => {
            verify_artifact_at_root(artifact_root, &abandoned.recovery_artifact)
        }
        EventPayload::RepositorySnapshotCleanupGrantedV1(granted) => {
            let safety = &granted.safety_evidence.evidence;
            let topology = &safety.initial_inspection.inspection.topology_inspection;
            for artifact in [
                &granted.safety_evidence.evidence_artifact,
                &safety.process_quiescence.inspection_artifact,
                &safety.initial_inspection.inspection_artifact,
                &topology.inspection_artifact,
                &topology.inspection.stdout_artifact,
                &topology.inspection.stderr_artifact,
            ] {
                verify_artifact_at_root(artifact_root, artifact)?;
            }
            Ok(())
        }
        EventPayload::RepositorySnapshotCaptureAbandonedV2(abandoned) => {
            verify_artifact_at_root(artifact_root, &abandoned.recovery_artifact)
        }
        EventPayload::RepositorySnapshotLeaseReleased(released) => {
            verify_artifact_at_root(artifact_root, &released.release_artifact)
        }
        EventPayload::RepositorySnapshotReleaseReconciledV1(reconciled) => {
            verify_artifact_at_root(artifact_root, &reconciled.recovery_artifact)
        }
        EventPayload::RepositorySnapshotReleaseReconciledV2(reconciled) => {
            verify_artifact_at_root(artifact_root, &reconciled.recovery_artifact)
        }
        EventPayload::WorkspaceRecoveryFinalizedV1(finalized) => {
            verify_artifact_at_root(artifact_root, &finalized.recovery_artifact)?;
            verify_artifact_at_root(artifact_root, &finalized.finalization_artifact)
        }
        EventPayload::ChildDelegationAuthorized(authorized) => {
            verify_artifact_at_root(artifact_root, &authorized.accepted_plan_artifact)?;
            verify_artifact_at_root(artifact_root, &authorized.work_order_artifact)?;
            verify_artifact_at_root(artifact_root, &authorized.context_manifest_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &authorized.spec.repository_authority.policy_artifact,
            )?;
            verify_artifact_at_root(
                artifact_root,
                &authorized
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact,
            )
        }
        EventPayload::ChildDelegationAuthorizedV2(authorized) => {
            for artifact in [
                &authorized.accepted_prompt_output_artifact,
                &authorized.planner_work_order.work_order_artifact,
                &authorized.work_order_artifact,
                &authorized.context_manifest_artifact,
                &authorized.spec.repository_authority.policy_artifact,
                &authorized
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact,
            ] {
                verify_artifact_at_root(artifact_root, artifact)?;
            }
            Ok(())
        }
        EventPayload::ChildWorkOrderIssued(issued) => {
            verify_artifact_at_root(artifact_root, &issued.work_order_artifact)?;
            verify_artifact_at_root(artifact_root, &issued.context_manifest_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &issued.spec.repository_authority.policy_artifact,
            )?;
            verify_artifact_at_root(
                artifact_root,
                &issued
                    .spec
                    .repository_authority
                    .snapshot
                    .immutability_lease
                    .lease_artifact,
            )
        }
        EventPayload::ChildModelInferencePrepared(prepared) => {
            verify_artifact_at_root(artifact_root, &prepared.prompt_manifest_artifact)?;
            verify_artifact_at_root(artifact_root, &prepared.prompt_artifact)?;
            verify_artifact_at_root(artifact_root, &prepared.request_artifact)?;
            verify_child_model_context_artifacts(artifact_root, &prepared.context_inventory)
        }
        EventPayload::ChildModelInferencePreparedV2(prepared) => {
            for artifact in [
                &prepared.prepared.prompt_manifest_artifact,
                &prepared.prepared.prompt_artifact,
                &prepared.prepared.request_artifact,
            ] {
                verify_artifact_at_root(artifact_root, artifact)?;
            }
            verify_child_model_context_artifacts(
                artifact_root,
                &prepared.prepared.context_inventory,
            )?;
            for supplied in &prepared.supplied_tool_results {
                verify_artifact_at_root(artifact_root, &supplied.result_artifact)?;
            }
            Ok(())
        }
        EventPayload::ChildModelInferenceObserved(observed) => verify_artifact_at_root(
            artifact_root,
            &observed.normalized_complete_evidence_artifact,
        ),
        EventPayload::ChildModelInferenceOutcomeUnknown(unknown) => {
            verify_artifact_at_root(artifact_root, &unknown.boundary_artifact)
        }
        EventPayload::ChildToolPrepared(prepared) => {
            verify_artifact_at_root(artifact_root, &prepared.prepared_receipt_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &prepared.action_binding.validated_action_artifact,
            )
        }
        EventPayload::ChildToolObserved(observed) => {
            verify_artifact_at_root(artifact_root, &observed.terminal_receipt_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &observed.action_binding.validated_action_artifact,
            )?;
            if let ChildToolObservation::Succeeded { result } = &observed.outcome {
                verify_artifact_at_root(artifact_root, result.result_artifact())?;
            }
            Ok(())
        }
        EventPayload::ChildToolOutcomeUnknown(unknown) => {
            verify_artifact_at_root(artifact_root, &unknown.terminal_receipt_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &unknown.action_binding.validated_action_artifact,
            )
        }
        EventPayload::ChildToolPreparedV2(prepared) => {
            verify_artifact_at_root(artifact_root, &prepared.prepared_receipt_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &prepared.action_binding.validated_action_artifact,
            )
        }
        EventPayload::ChildToolDispatchStartedV2(started) => verify_artifact_at_root(
            artifact_root,
            &started.action_binding.validated_action_artifact,
        ),
        EventPayload::ChildToolObservedV2(observed) => {
            verify_artifact_at_root(artifact_root, &observed.terminal_receipt_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &observed.action_binding.validated_action_artifact,
            )?;
            let artifact = match &observed.terminal {
                RepositoryToolObservedTerminalV2::Succeeded { result_artifact } => result_artifact,
                RepositoryToolObservedTerminalV2::Failed {
                    evidence_artifact, ..
                }
                | RepositoryToolObservedTerminalV2::AuthorizationDenied {
                    evidence_artifact, ..
                } => evidence_artifact,
            };
            verify_artifact_at_root(artifact_root, artifact)
        }
        EventPayload::ChildToolOutcomeUnknownV2(unknown) => {
            verify_artifact_at_root(artifact_root, &unknown.terminal_receipt_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &unknown.action_binding.validated_action_artifact,
            )
        }
        EventPayload::ChildHandoffCommitted(handoff) => {
            verify_artifact_at_root(artifact_root, &handoff.handoff_artifact)?;
            verify_artifact_at_root(
                artifact_root,
                &handoff.action_binding.validated_action_artifact,
            )
        }
        EventPayload::ChildExecutionFinished(finished) => {
            if let ChildExecutionOutcome::Failed {
                cause:
                    ChildExecutionFailureCauseV1::RuntimeEvidence {
                        evidence_artifact, ..
                    },
                ..
            } = &finished.outcome
            {
                verify_artifact_at_root(artifact_root, evidence_artifact)?;
            }
            Ok(())
        }
        EventPayload::SessionCreated { .. }
        | EventPayload::RunStateChanged { .. }
        | EventPayload::RunClaimed(_)
        | EventPayload::CancellationRequested(_)
        | EventPayload::PlannerInferenceOutcomeUnknown(_)
        | EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(_)
        | EventPayload::RepositoryBrokerEpochActivatedV1(_)
        | EventPayload::ChildExecutionClaimAdopted(_)
        | EventPayload::ChildExecutionStarted(_)
        | EventPayload::BackendEvent { .. } => Ok(()),
    }
}

fn add_child_model_context_artifacts(
    cost: &mut ArtifactValidationCost,
    inventory: &ChildModelContextInventoryV1,
) -> Result<(), StoreError> {
    cost.add(&inventory.work_order_artifact)?;
    cost.add(&inventory.context_manifest_artifact)?;
    if let Some(prior) = &inventory.prior_plan {
        cost.add(&prior.source_model_evidence_artifact)?;
    }
    if let Some(previous_tool) = &inventory.previous_tool {
        let artifact = match previous_tool {
            ChildPreviousToolContextV1::Observed {
                terminal_receipt_artifact,
                ..
            }
            | ChildPreviousToolContextV1::Unknown {
                terminal_receipt_artifact,
                ..
            } => terminal_receipt_artifact,
        };
        cost.add(artifact)?;
    }
    Ok(())
}

fn verify_child_model_context_artifacts(
    artifact_root: &Path,
    inventory: &ChildModelContextInventoryV1,
) -> Result<(), StoreError> {
    verify_artifact_at_root(artifact_root, &inventory.work_order_artifact)?;
    verify_artifact_at_root(artifact_root, &inventory.context_manifest_artifact)?;
    if let Some(prior) = &inventory.prior_plan {
        verify_artifact_at_root(artifact_root, &prior.source_model_evidence_artifact)?;
    }
    if let Some(previous_tool) = &inventory.previous_tool {
        let artifact = match previous_tool {
            ChildPreviousToolContextV1::Observed {
                terminal_receipt_artifact,
                ..
            }
            | ChildPreviousToolContextV1::Unknown {
                terminal_receipt_artifact,
                ..
            } => terminal_receipt_artifact,
        };
        verify_artifact_at_root(artifact_root, artifact)?;
    }
    Ok(())
}
