use super::PlanEventView;
use birdcode_protocol::{
    EventEnvelope, EventPayload, PlannerAcceptedDirectiveV1, PlannerInferenceObservation,
    PlannerTurnObservationV1, RepositoryToolAuthorizationDecisionV2,
    RepositoryToolObservedTerminalV2, RunState,
};

// Keeping this exhaustive match in one place makes every protocol event's UI
// projection auditable; splitting it would require catch-all branches that
// could silently hide a newly added typed event.
#[allow(clippy::too_many_lines)]
pub(super) fn project_event(event: &EventEnvelope) -> PlanEventView {
    let (kind, tone, title, detail) = match &event.payload {
        EventPayload::SessionCreated { .. } => (
            "session_created",
            "neutral",
            "Session created",
            "Durable planning session recorded".to_owned(),
        ),
        EventPayload::UserInput { items } => (
            "user_input",
            "neutral",
            "Goal recorded",
            format!("{} typed input item(s) persisted", items.len()),
        ),
        EventPayload::RunCreated { run } => (
            "run_created",
            "neutral",
            "Plan run queued",
            format!("Client run id {}", run.id),
        ),
        EventPayload::RunStateChanged { from, to } => (
            "run_state_changed",
            state_tone(*to),
            "Run state changed",
            format!("{} → {}", state_name(*from), state_name(*to)),
        ),
        EventPayload::RunClaimed(claim) => (
            "run_claimed",
            "active",
            "Planner claimed",
            format!(
                "Claim generation {} · cancellation generation {}",
                claim.claim_generation, claim.cancellation_generation
            ),
        ),
        EventPayload::CancellationRequested(cancellation) => (
            "cancellation_requested",
            "warning",
            "Cancellation recorded",
            format!(
                "Durable cancellation generation {}",
                cancellation.cancellation_generation
            ),
        ),
        EventPayload::RootPlanningFailed(failure) => (
            "root_planning_failed",
            "danger",
            "Planning failed before inference",
            format!(
                "Typed phase {:?} · reason {:?}",
                failure.phase, failure.reason
            ),
        ),
        EventPayload::RootPlanningStageFailed(failure) => (
            "root_planning_stage_failed",
            "danger",
            "Planning stage failed",
            format!(
                "Typed durable stage {:?} · reason {:?}",
                failure.failed_stage, failure.reason
            ),
        ),
        EventPayload::PlannerInferencePrepared(prepared) => (
            "planner_inference_prepared",
            "active",
            "Inference prepared",
            format!(
                "{} · revision {} · {} output tokens reserved",
                prepared.backend_model.model_id,
                prepared.plan_revision,
                prepared.token_reservation.max_output_tokens
            ),
        ),
        EventPayload::PlannerInferenceObserved(observed) => match &observed.outcome {
            PlannerInferenceObservation::Succeeded { token_usage, .. } => (
                "planner_inference_observed",
                "active",
                "Inference observed",
                format!(
                    "Complete response retained · {} total tokens",
                    token_usage.total_tokens
                ),
            ),
            PlannerInferenceObservation::Failed { error } => (
                "planner_inference_observed",
                "danger",
                "Inference failed",
                format!("Typed failure: {:?} · retry {:?}", error.kind, error.retry),
            ),
        },
        EventPayload::PlannerInferenceOutcomeUnknown(unknown) => (
            "planner_inference_outcome_unknown",
            "danger",
            "Inference outcome unknown",
            format!("Fail-closed reconciliation: {:?}", unknown.reason),
        ),
        EventPayload::ReadOperationPrepared(read) => (
            "read_operation_prepared",
            "active",
            "Read prepared",
            format!("Read-only operation {:?}", read.operation),
        ),
        EventPayload::ReadOperationObserved(read) => (
            "read_operation_observed",
            "active",
            "Read observed",
            format!("Typed read outcome {:?}", read.outcome),
        ),
        EventPayload::PlanProposalRejected(rejected) => (
            "plan_proposal_rejected",
            "danger",
            "Plan rejected",
            format!("Typed validation reason: {:?}", rejected.reason),
        ),
        EventPayload::PlanProposalAccepted(accepted) => (
            "plan_proposal_accepted",
            "success",
            "Plan candidate validated",
            format!(
                "Revision {} · {}",
                accepted.accepted_plan_revision,
                accepted.accepted_plan_digest.as_str()
            ),
        ),
        EventPayload::PlanSemanticReviewAccepted(review) => (
            "plan_semantic_review_accepted",
            "success",
            "Independent semantic review passed",
            format!(
                "Candidate revision {} · {}",
                review.candidate.plan_revision,
                review.candidate.plan_digest.as_str()
            ),
        ),
        EventPayload::PlanSemanticReviewRejected(review) => (
            "plan_semantic_review_rejected",
            "danger",
            "Semantic review did not pass",
            format!(
                "Disposition {:?} · {} required finding(s)",
                review.disposition,
                review.required_finding_ids.len()
            ),
        ),
        EventPayload::PlannerTurnPreparedV1(prepared) => (
            "planner_turn_prepared_v1",
            "active",
            "Semantic planner turn prepared",
            format!(
                "{:?} · plan revision {} · model {} · {} output tokens reserved",
                prepared.purpose,
                prepared.base_plan.revision,
                prepared.backend_model.model_id,
                prepared.token_reservation.max_output_tokens
            ),
        ),
        EventPayload::PlannerTurnObservedV1(observed) => match &observed.outcome {
            PlannerTurnObservationV1::Succeeded { token_usage, .. } => (
                "planner_turn_observed_v1",
                "active",
                "Semantic planner turn observed",
                format!(
                    "Turn {} · complete response · {} total tokens",
                    observed.turn_id, token_usage.total_tokens
                ),
            ),
            PlannerTurnObservationV1::Failed { error } => (
                "planner_turn_observed_v1",
                "danger",
                "Semantic planner turn failed",
                format!(
                    "Turn {} · typed failure {:?} · retry {:?}",
                    observed.turn_id, error.kind, error.retry
                ),
            ),
        },
        EventPayload::PlannerTurnUnknownV1(unknown) => (
            "planner_turn_unknown_v1",
            "danger",
            "Semantic planner outcome unknown",
            format!(
                "Turn {} · {:?} at {:?}",
                unknown.turn_id, unknown.reason, unknown.boundary
            ),
        ),
        EventPayload::PlannerTurnAcceptedV1(accepted) => match &accepted.resolved_directive {
            PlannerAcceptedDirectiveV1::Execute { work_order } => (
                "planner_turn_accepted_v1",
                "success",
                "Planner selected work",
                format!(
                    "{:?} · work order {} revision {} · resulting plan revision {}",
                    accepted.purpose,
                    work_order.work_order_id,
                    work_order.revision,
                    accepted.resulting_plan.revision
                ),
            ),
            PlannerAcceptedDirectiveV1::Delegate { delegations } => (
                "planner_turn_accepted_v1",
                "success",
                "Planner delegated work",
                format!(
                    "{:?} · {} delegation(s) covering {} work order(s) · resulting plan revision {}",
                    accepted.purpose,
                    delegations.len(),
                    delegations
                        .iter()
                        .map(|delegation| delegation.work_orders.len())
                        .sum::<usize>(),
                    accepted.resulting_plan.revision
                ),
            ),
            PlannerAcceptedDirectiveV1::Clarify { requests } => (
                "planner_turn_accepted_v1",
                "warning",
                "Planner requested clarification",
                format!(
                    "{:?} · {} clarification request(s) · resulting plan revision {}",
                    accepted.purpose,
                    requests.len(),
                    accepted.resulting_plan.revision
                ),
            ),
            PlannerAcceptedDirectiveV1::Escalate { requests } => (
                "planner_turn_accepted_v1",
                "warning",
                "Planner requested escalation",
                format!(
                    "{:?} · {} escalation request(s) · resulting plan revision {}",
                    accepted.purpose,
                    requests.len(),
                    accepted.resulting_plan.revision
                ),
            ),
            PlannerAcceptedDirectiveV1::FinishPendingGate { claims } => (
                "planner_turn_accepted_v1",
                "active",
                "Planner proposed completion",
                format!(
                    "{:?} · {} finish claim(s) await the completion gate · resulting plan revision {}",
                    accepted.purpose,
                    claims.len(),
                    accepted.resulting_plan.revision
                ),
            ),
        },
        EventPayload::PlannerTurnRejectedV1(rejected) => (
            "planner_turn_rejected_v1",
            "danger",
            "Semantic planner turn rejected",
            format!(
                "Turn {} · {:?} · typed validation reason {:?}",
                rejected.turn_id, rejected.purpose, rejected.reason
            ),
        ),
        EventPayload::ReconCompletionGateAcceptedV1(accepted) => (
            "recon_completion_gate_accepted_v1",
            "success",
            "Reconnaissance completion proven",
            format!(
                "Gate {} · plan revision {} · receipt {}",
                accepted.gate_id,
                accepted.resulting_plan.revision,
                accepted.receipt_digest.as_str()
            ),
        ),
        EventPayload::RepositoryWriterLeaseRevoked(revoked) => (
            "repository_writer_lease_revoked",
            "success",
            "Repository writers revoked",
            format!(
                "Claim generation {} · evidence {}",
                revoked.claim_generation,
                revoked.evidence_digest.as_str()
            ),
        ),
        EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(adopted) => (
            "repository_snapshot_capture_claim_adopted_v1",
            "active",
            "Snapshot capture claim renewed",
            format!(
                "Snapshot {} · claim generation {} → {}",
                adopted.snapshot_id, adopted.prior_claim_generation, adopted.new_claim_generation
            ),
        ),
        EventPayload::RepositorySnapshotCleanupGrantedV1(granted) => (
            "repository_snapshot_cleanup_granted_v1",
            "warning",
            "Snapshot cleanup authorized",
            format!(
                "{:?} · grant generation {} · snapshot {}",
                granted.kind, granted.cleanup_grant_generation, granted.snapshot_id
            ),
        ),
        EventPayload::RepositorySnapshotCaptureAbandonedV1(abandoned) => (
            "repository_snapshot_capture_abandoned_v1",
            "warning",
            "Snapshot capture abandoned",
            format!(
                "Lease {} · recovery {}",
                abandoned.lease_id, abandoned.recovery_id
            ),
        ),
        EventPayload::RepositorySnapshotCaptureAbandonedV2(abandoned) => (
            "repository_snapshot_capture_abandoned_v2",
            "warning",
            "Snapshot capture recovery closure committed",
            format!(
                "Lease {} · recovery {} · grant generation {}",
                abandoned.lease_id, abandoned.recovery_id, abandoned.cleanup_grant_generation
            ),
        ),
        EventPayload::RepositorySnapshotLeaseIssued(issued) => (
            "repository_snapshot_lease_issued",
            "success",
            "Read-only repository snapshot issued",
            format!(
                "Snapshot {} · lease {}",
                issued.snapshot.snapshot_id, issued.snapshot.immutability_lease.lease_id
            ),
        ),
        EventPayload::RepositorySnapshotLeaseReleased(released) => (
            "repository_snapshot_lease_released",
            "neutral",
            "Repository snapshot released",
            format!(
                "Lease {} · release {}",
                released.lease_event_id,
                released.release_digest.as_str()
            ),
        ),
        EventPayload::RepositorySnapshotReleaseReconciledV1(reconciled) => (
            "repository_snapshot_release_reconciled_v1",
            "success",
            "Snapshot release reconciled",
            format!(
                "Lease {} · recovery {}",
                reconciled.lease_id, reconciled.recovery_id
            ),
        ),
        EventPayload::RepositorySnapshotReleaseReconciledV2(reconciled) => (
            "repository_snapshot_release_reconciled_v2",
            "success",
            "Snapshot release recovery closure committed",
            format!(
                "Lease {} · recovery {} · grant generation {}",
                reconciled.lease_id, reconciled.recovery_id, reconciled.cleanup_grant_generation
            ),
        ),
        EventPayload::WorkspaceRecoveryFinalizedV1(finalized) => (
            "workspace_recovery_finalized_v1",
            "success",
            "Workspace recovery finalized",
            format!(
                "Recovery {} · finalization {}",
                finalized.recovery_id, finalized.finalization_id
            ),
        ),
        EventPayload::RepositoryBrokerEpochActivatedV1(activated) => (
            "repository_broker_epoch_activated_v1",
            "neutral",
            "Repository broker epoch activated",
            format!(
                "Broker {} active · {} prior broker epoch(s) closed",
                activated.state.active_broker_instance_id,
                activated.state.closed_broker_instance_ids.len()
            ),
        ),
        EventPayload::ChildDelegationAuthorized(authorized) => (
            "child_delegation_authorized",
            "neutral",
            "Explorer delegation authorized",
            format!(
                "Actor {} · work order {}",
                authorized.spec.child_actor_id, authorized.spec.work_order_id
            ),
        ),
        EventPayload::ChildDelegationAuthorizedV2(authorized) => (
            "child_delegation_authorized_v2",
            "neutral",
            "Planner-v2 explorer delegation authorized",
            format!(
                "Actor {} · work order {} · planner turn {}",
                authorized.spec.child_actor_id,
                authorized.planner_work_order.work_order_id,
                authorized.planner_turn_id
            ),
        ),
        EventPayload::ChildWorkOrderIssued(issued) => (
            "child_work_order_issued",
            "neutral",
            "Explorer work order issued",
            format!(
                "Actor {} · {:?} · {} read-only tool grant(s)",
                issued.spec.child_actor_id,
                issued.spec.role,
                issued.spec.repository_authority.tool_grants.len()
            ),
        ),
        EventPayload::ChildExecutionClaimAdopted(adopted) => (
            "child_execution_claim_adopted",
            "active",
            "Explorer claim adopted",
            format!(
                "{:?} · claim generation {}",
                adopted.kind, adopted.new_claim_generation
            ),
        ),
        EventPayload::ChildExecutionStarted(started) => (
            "child_execution_started",
            "active",
            "Explorer attempt started",
            format!(
                "Attempt {} · model {}",
                started.binding.attempt_id, started.backend_model.model_id
            ),
        ),
        EventPayload::ChildModelInferencePrepared(prepared) => (
            "child_model_inference_prepared",
            "active",
            "Explorer inference prepared",
            format!(
                "Model turn {} · {} output tokens reserved",
                prepared.model_call_ordinal, prepared.token_reservation.max_output_tokens
            ),
        ),
        EventPayload::ChildModelInferencePreparedV2(prepared) => (
            "child_model_inference_prepared_v2",
            "active",
            "Explorer inference prepared",
            format!(
                "Model turn {} · model {} · {} supplied tool result(s) · {} output tokens reserved",
                prepared.prepared.model_call_ordinal,
                prepared.prepared.backend_model.model_id,
                prepared.supplied_tool_results.len(),
                prepared.prepared.token_reservation.max_output_tokens
            ),
        ),
        EventPayload::ChildModelInferenceObserved(observed) => (
            "child_model_inference_observed",
            "active",
            "Explorer inference observed",
            format!(
                "Model turn {} · {:?}",
                observed.model_call_ordinal, observed.outcome
            ),
        ),
        EventPayload::ChildModelInferenceOutcomeUnknown(unknown) => (
            "child_model_inference_outcome_unknown",
            "danger",
            "Explorer inference outcome unknown",
            format!("{:?} at {:?}", unknown.reason, unknown.boundary),
        ),
        EventPayload::ChildToolPrepared(prepared) => (
            "child_tool_prepared",
            "active",
            "Explorer tool prepared",
            format!(
                "Tool turn {} · {:?}",
                prepared.tool_ordinal,
                prepared.operation.kind()
            ),
        ),
        EventPayload::ChildToolPreparedV2(prepared) => match &prepared.authorization {
            RepositoryToolAuthorizationDecisionV2::Authorized => (
                "child_tool_prepared_v2",
                "active",
                "Explorer repository tool prepared",
                format!(
                    "Tool turn {} · {:?} · broker call {}",
                    prepared.tool_ordinal,
                    prepared.operation.kind(),
                    prepared.broker_call_sequence
                ),
            ),
            RepositoryToolAuthorizationDecisionV2::Denied { denial } => (
                "child_tool_prepared_v2",
                "warning",
                "Explorer repository tool denied",
                format!(
                    "Tool turn {} · {:?} · typed denial {:?}",
                    prepared.tool_ordinal,
                    prepared.operation.kind(),
                    denial
                ),
            ),
        },
        EventPayload::ChildToolObserved(observed) => (
            "child_tool_observed",
            "active",
            "Explorer tool observed",
            format!("Call {} · {:?}", observed.tool_call_id, observed.outcome),
        ),
        EventPayload::ChildToolObservedV2(observed) => match &observed.terminal {
            RepositoryToolObservedTerminalV2::Succeeded { result_artifact } => (
                "child_tool_observed_v2",
                "success",
                "Explorer repository tool succeeded",
                format!(
                    "Call {} · result {}",
                    observed.tool_call_id,
                    result_artifact.sha256.as_str()
                ),
            ),
            RepositoryToolObservedTerminalV2::Failed { failure, .. } => (
                "child_tool_observed_v2",
                "danger",
                "Explorer repository tool failed",
                format!(
                    "Call {} · typed failure {:?}",
                    observed.tool_call_id, failure
                ),
            ),
            RepositoryToolObservedTerminalV2::AuthorizationDenied { denial, .. } => (
                "child_tool_observed_v2",
                "warning",
                "Explorer repository tool denied",
                format!("Call {} · typed denial {:?}", observed.tool_call_id, denial),
            ),
        },
        EventPayload::ChildToolOutcomeUnknown(unknown) => (
            "child_tool_outcome_unknown",
            "danger",
            "Explorer tool outcome unknown",
            format!("{:?} at {:?}", unknown.reason, unknown.boundary),
        ),
        EventPayload::ChildToolOutcomeUnknownV2(unknown) => (
            "child_tool_outcome_unknown_v2",
            "danger",
            "Explorer repository tool outcome unknown",
            format!(
                "Call {} · {:?} at {:?}",
                unknown.tool_call_id, unknown.reason, unknown.boundary
            ),
        ),
        EventPayload::ChildHandoffCommitted(handoff) => (
            "child_handoff_committed",
            "success",
            "Explorer handoff retained",
            format!("Handoff {} · evidence hash bound", handoff.handoff_id),
        ),
        EventPayload::ChildExecutionFinished(finished) => (
            "child_execution_finished",
            match finished.outcome {
                birdcode_protocol::ChildExecutionOutcome::Succeeded { .. } => "success",
                birdcode_protocol::ChildExecutionOutcome::Failed { .. } => "danger",
                birdcode_protocol::ChildExecutionOutcome::Cancelled { .. } => "warning",
            },
            "Explorer attempt finished",
            format!(
                "{:?} · {} model call(s) · {} tool call(s)",
                finished.outcome, finished.completed_model_calls, finished.completed_tool_calls
            ),
        ),
        EventPayload::BackendEvent { event_type, .. } => (
            "backend_event",
            "neutral",
            "Backend telemetry",
            event_type.clone(),
        ),
        EventPayload::ArtifactStored { artifact } => (
            "artifact_stored",
            "neutral",
            "Artifact stored",
            format!("{} · {} bytes", artifact.media_type, artifact.size_bytes),
        ),
    };
    PlanEventView {
        sequence: event.sequence,
        occurred_at: event.occurred_at.to_rfc3339(),
        kind,
        tone,
        title,
        detail,
    }
}

const fn state_name(state: RunState) -> &'static str {
    match state {
        RunState::Queued => "queued",
        RunState::Running => "running",
        RunState::Waiting => "waiting",
        RunState::Completed => "completed",
        RunState::Failed => "failed",
        RunState::Cancelled => "cancelled",
    }
}

const fn state_tone(state: RunState) -> &'static str {
    match state {
        RunState::Queued | RunState::Waiting => "neutral",
        RunState::Running => "active",
        RunState::Completed => "success",
        RunState::Failed => "danger",
        RunState::Cancelled => "warning",
    }
}
