use birdcode_orchestrator::{
    ActorGraph, ActorGraphExecutionError, ActorGraphExecutor, ActorGraphLimits, ActorGraphOutcome,
    ActorGraphPolicy, ActorGraphValidationError, ActorGraphViolation, AgentAssignment, AgentBudget,
    AgentCleanupFuture, AgentCompletion, AgentDispatch, AgentFailure, AgentFailureKind,
    AgentFailureViolation, AgentFuture, AgentWorker, CandidateGroupId, CapabilityId,
    CleanupReceipt, HandoffOutcome, InMemorySchedulerJournal, ModelLineage, ModelProfileId,
    PermissionGrant, RoleId, SchedulerEvent, SchedulerJournal, SchedulerJournalError,
    SchedulerRecord, TimedOutAttempt, Usage, ValidatedActorGraph, WorkOrder, WorkOrderFailure,
    WorkOrderId, WorkspaceAccess, WorkspaceGrant, WorkspaceLeaseId, WorkspaceLeasePolicy,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier as ThreadBarrier, Mutex};
use std::time::Duration;
use tokio::sync::Barrier;

const SNAPSHOT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn capability(value: &str) -> CapabilityId {
    CapabilityId::new(value).expect("valid capability")
}

fn permissions(values: &[&str]) -> PermissionGrant {
    PermissionGrant {
        capabilities: values.iter().map(|value| capability(value)).collect(),
    }
}

fn assignment(lineage: &str) -> AgentAssignment {
    AgentAssignment {
        role_id: RoleId::new(format!("role/{lineage}")).expect("valid role"),
        model_profile_id: ModelProfileId::new(format!("profile/{lineage}"))
            .expect("valid model profile"),
        lineage: ModelLineage {
            backend_id: "test-backend".to_owned(),
            model_id: format!("model/{lineage}"),
            deployment_id: format!("deployment/{lineage}"),
            independence_domain_id: format!("independence/{lineage}"),
        },
    }
}

fn order(id: WorkOrderId, lease: &str, lineage: &str) -> WorkOrder {
    WorkOrder {
        id,
        objective: format!("opaque objective {id}"),
        acceptance_criteria: vec!["return a typed handoff with evidence".to_owned()],
        dependencies: BTreeSet::new(),
        candidate_group: None,
        priority: 0,
        context_manifest_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_owned(),
        assignment: assignment(lineage),
        permissions: permissions(&["repo:read"]),
        workspace: WorkspaceGrant {
            lease_id: WorkspaceLeaseId::new(lease).expect("valid lease"),
            base_snapshot_sha256: SNAPSHOT.to_owned(),
            access: WorkspaceAccess::ReadOnly,
        },
        budget: AgentBudget {
            max_output_tokens: 1_000,
            max_tool_calls: 10,
            max_wall_time_ms: 2_000,
            max_cleanup_time_ms: 500,
            max_attempts: 2,
        },
        reviews: BTreeSet::new(),
    }
}

fn graph_and_policy(
    work_orders: Vec<WorkOrder>,
    max_parallel: u32,
) -> (ActorGraph, ActorGraphPolicy) {
    let workspace_leases = work_orders
        .iter()
        .map(|order| {
            (
                order.workspace.lease_id.clone(),
                WorkspaceLeasePolicy {
                    base_snapshot_sha256: order.workspace.base_snapshot_sha256.clone(),
                    access: order.workspace.access,
                },
            )
        })
        .collect();
    let model_profiles = work_orders
        .iter()
        .map(|order| {
            (
                order.assignment.model_profile_id.clone(),
                order.assignment.lineage.clone(),
            )
        })
        .collect();
    let graph = ActorGraph {
        schema_version: 1,
        root_snapshot_sha256: SNAPSHOT.to_owned(),
        work_orders,
    };
    let policy = ActorGraphPolicy {
        policy_version: "test-policy/1".to_owned(),
        root_snapshot_sha256: SNAPSHOT.to_owned(),
        root_permissions: permissions(&["repo:read", "repo:write"]),
        limits: ActorGraphLimits {
            max_work_orders: 32,
            max_parallel,
            max_total_attempts: 64,
            max_total_output_tokens: 64_000,
            max_total_tool_calls: 640,
            max_total_wall_time_ms: 128_000,
        },
        require_reported_token_usage: true,
        workspace_leases,
        model_profiles,
    };
    (graph, policy)
}

fn validate_graph(
    work_orders: Vec<WorkOrder>,
    max_parallel: u32,
) -> Result<ValidatedActorGraph, ActorGraphValidationError> {
    let (graph, policy) = graph_and_policy(work_orders, max_parallel);
    graph.validate_against(&policy)
}

fn completion(summary: impl Into<String>) -> AgentCompletion {
    AgentCompletion {
        outcome: HandoffOutcome::Completed,
        summary: summary.into(),
        execution_receipt_id: "execution-receipt/test".to_owned(),
        artifact_sha256: Vec::new(),
        evidence_ids: vec!["evidence/test".to_owned()],
        usage: Usage {
            output_tokens: Some(20),
            tool_calls: 1,
        },
    }
}

struct ParallelWorker {
    barrier: Arc<Barrier>,
    active: AtomicUsize,
    maximum: AtomicUsize,
    root_ids: BTreeSet<WorkOrderId>,
    dependency_counts: Mutex<BTreeMap<WorkOrderId, usize>>,
}

impl ParallelWorker {
    fn observe_start(&self) {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
    }
}

impl AgentWorker for ParallelWorker {
    fn execute(&self, dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async move {
            self.dependency_counts
                .lock()
                .expect("dependency lock")
                .insert(dispatch.work_order.id, dispatch.dependency_handoffs.len());
            if self.root_ids.contains(&dispatch.work_order.id) {
                self.observe_start();
                self.barrier.wait().await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
            }
            Ok(completion(dispatch.work_order.objective.clone()))
        })
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn independent_children_overlap_and_review_waits_for_both_handoffs() {
    let first = WorkOrderId::new();
    let second = WorkOrderId::new();
    let review = WorkOrderId::new();
    let mut first_order = order(first, "lease/first", "producer-a");
    first_order.candidate_group = Some(CandidateGroupId::new("candidate/pair").unwrap());
    first_order.priority = 10;
    let mut second_order = order(second, "lease/second", "producer-b");
    second_order.candidate_group = Some(CandidateGroupId::new("candidate/pair").unwrap());
    second_order.priority = 10;
    second_order.objective.clone_from(&first_order.objective);
    let mut review_order = order(review, "lease/review", "reviewer");
    review_order.dependencies = BTreeSet::from([first, second]);
    review_order.reviews = BTreeSet::from([first, second]);

    let worker = ParallelWorker {
        barrier: Arc::new(Barrier::new(2)),
        active: AtomicUsize::new(0),
        maximum: AtomicUsize::new(0),
        root_ids: BTreeSet::from([first, second]),
        dependency_counts: Mutex::new(BTreeMap::new()),
    };
    let journal = InMemorySchedulerJournal::default();
    let validated = validate_graph(vec![review_order, second_order, first_order], 2)
        .expect("graph should validate");

    let run = ActorGraphExecutor::new(&worker, &journal)
        .execute(&validated)
        .await
        .expect("scheduler should complete");

    assert_eq!(run.outcome, ActorGraphOutcome::Completed);
    assert_eq!(run.maximum_in_flight, 2);
    assert_eq!(worker.maximum.load(Ordering::SeqCst), 2);
    assert_eq!(run.handoffs.len(), 3);
    assert_eq!(run.terminal_event_ids.len(), 3);
    assert_eq!(
        worker
            .dependency_counts
            .lock()
            .expect("dependency lock")
            .get(&review),
        Some(&2)
    );

    let records = journal.snapshot().expect("journal snapshot");
    assert_eq!(run.accepted_event_id, records[0].id);
    let SchedulerEvent::GraphAccepted {
        graph_sha256,
        policy_version,
        root_snapshot_sha256,
    } = &records[0].event
    else {
        panic!("first event must accept the graph")
    };
    assert_eq!(graph_sha256, run.graph_sha256.as_str());
    assert_eq!(policy_version, "test-policy/1");
    assert_eq!(root_snapshot_sha256, SNAPSHOT);
    let review_dispatch = records
        .iter()
        .position(|record| {
            matches!(
                record.event,
                SchedulerEvent::AttemptDispatched { work_order_id, .. } if work_order_id == review
            )
        })
        .expect("review dispatch should be retained");
    let producer_event_ids = records
        .iter()
        .filter_map(|record| match &record.event {
            SchedulerEvent::HandoffRetained { handoff }
                if handoff.work_order_id == first || handoff.work_order_id == second =>
            {
                assert_eq!(handoff.retained_event_id, record.id);
                Some((handoff.work_order_id, record.id))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let SchedulerEvent::AttemptDispatched {
        attestation,
        dependency_handoff_event_ids,
        ..
    } = &records[review_dispatch].event
    else {
        unreachable!("position selected the review dispatch")
    };
    assert_eq!(dependency_handoff_event_ids, &producer_event_ids);
    assert_eq!(attestation.graph_sha256, run.graph_sha256);
    assert_eq!(attestation.context_manifest_sha256.len(), 64);
    assert_eq!(attestation.work_order_sha256.len(), 64);
    assert_eq!(attestation.permissions_sha256.len(), 64);
    let producer_handoffs = records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| {
            matches!(
                &record.event,
                SchedulerEvent::HandoffRetained { handoff }
                    if handoff.work_order_id == first || handoff.work_order_id == second
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(producer_handoffs.len(), 2);
    assert!(
        producer_handoffs
            .into_iter()
            .all(|index| index < review_dispatch)
    );
    let finished = records.last().expect("graph terminal event");
    let SchedulerEvent::GraphFinished {
        terminal_event_ids, ..
    } = &finished.event
    else {
        panic!("last event must finish the graph")
    };
    assert_eq!(terminal_event_ids.len(), 3);
    assert_eq!(terminal_event_ids, &run.terminal_event_ids);
    assert_eq!(finished.id, run.finished_event_id);
    assert!(finished.causal_parent.is_some_and(|parent| {
        terminal_event_ids
            .values()
            .any(|terminal| *terminal == parent)
    }));
}

#[test]
fn validation_collects_policy_budget_isolation_and_review_violations() {
    let first = WorkOrderId::new();
    let second = WorkOrderId::new();
    let missing = WorkOrderId::new();
    let mut first_order = order(first, "lease/shared", "same-lineage");
    first_order.workspace.access = WorkspaceAccess::Write;
    first_order.dependencies.insert(second);
    first_order.budget.max_attempts = 4;
    let mut second_order = order(second, "lease/shared", "same-lineage");
    second_order.workspace.access = WorkspaceAccess::Write;
    second_order.dependencies.insert(first);
    second_order.permissions = permissions(&["repo:read", "not-granted"]);
    second_order.reviews = BTreeSet::from([first, missing]);
    second_order.budget.max_attempts = 4;
    let (invalid, mut policy) = graph_and_policy(vec![first_order, second_order], 0);
    policy.limits.max_work_orders = 1;
    policy.limits.max_total_attempts = 1;
    policy.limits.max_total_output_tokens = 1;
    policy.limits.max_total_tool_calls = 1;
    policy.limits.max_total_wall_time_ms = 1;

    let ActorGraphValidationError::Violations { violations } = invalid
        .validate_against(&policy)
        .expect_err("invalid graph must fail")
    else {
        panic!("expected collected graph violations")
    };

    assert!(
        violations
            .iter()
            .any(|violation| matches!(violation, ActorGraphViolation::InvalidParallelLimit))
    );
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::WorkOrderLimitExceeded { .. }
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::AuthorityExpansion { work_order_id } if *work_order_id == second
    )));
    assert!(
        violations
            .iter()
            .any(|violation| matches!(violation, ActorGraphViolation::SharedWriterLease { .. }))
    );
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::ReviewerHasWriteWorkspace { reviewer_id } if *reviewer_id == second
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::ReviewerLineageConflict { reviewer_id, target_id }
            if *reviewer_id == second && *target_id == first
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::UnknownReviewTarget { reviewer_id, target_id }
            if *reviewer_id == second && *target_id == missing
    )));
    assert!(
        violations
            .iter()
            .any(|violation| matches!(violation, ActorGraphViolation::DependencyCycle { .. }))
    );
    assert!(
        violations.iter().any(|violation| matches!(
            violation,
            ActorGraphViolation::AttemptBudgetExceeded { .. }
        ))
    );
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::OutputTokenBudgetExceeded { .. }
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::ToolCallBudgetExceeded { .. }
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::WallTimeBudgetExceeded { .. }
    )));
}

#[test]
fn hostile_work_order_count_fails_before_sorting_or_deep_validation() {
    let repeated = order(WorkOrderId::new(), "lease/repeated", "repeated");
    let (graph, policy) = graph_and_policy(vec![repeated; 1_025], 1);

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("the hard structural cap must fail closed")
    else {
        panic!("expected a structural limit violation")
    };
    assert_eq!(
        violations,
        vec![ActorGraphViolation::HardWorkOrderLimitExceeded {
            maximum: 1_024,
            actual: 1_025,
        }]
    );
}

#[test]
fn aggregate_capability_references_are_bounded_before_subset_checks() {
    let mut orders = Vec::new();
    for order_index in 0..8 {
        let mut proposed = order(
            WorkOrderId::new(),
            &format!("lease/capabilities/{order_index}"),
            &format!("capabilities-{order_index}"),
        );
        proposed.permissions.capabilities = (0..4_096)
            .map(|capability_index| capability(&format!("opaque/{order_index}/{capability_index}")))
            .collect();
        orders.push(proposed);
    }
    let (graph, policy) = graph_and_policy(orders, 1);

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("aggregate capability references must have a hard ceiling")
    else {
        panic!("expected aggregate capability structural rejection")
    };
    assert_eq!(
        violations,
        vec![ActorGraphViolation::TotalCapabilityReferenceLimitExceeded {
            maximum: 32_768,
            actual: 32_770,
        }]
    );
}

#[test]
fn dependency_cycle_reports_only_actual_cycle_members() {
    let first_id = WorkOrderId::new();
    let second_id = WorkOrderId::new();
    let downstream_id = WorkOrderId::new();
    let mut first = order(first_id, "lease/cycle-first", "first");
    first.dependencies.insert(second_id);
    let mut second = order(second_id, "lease/cycle-second", "second");
    second.dependencies.insert(first_id);
    let mut downstream = order(downstream_id, "lease/cycle-downstream", "downstream");
    downstream.dependencies.insert(first_id);
    let (graph, policy) = graph_and_policy(vec![downstream, first, second], 1);

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("cycle must fail validation")
    else {
        panic!("expected dependency cycle")
    };
    let cycle = violations
        .iter()
        .find_map(|violation| match violation {
            ActorGraphViolation::DependencyCycle { work_order_ids } => Some(work_order_ids),
            _ => None,
        })
        .expect("actual cycle members should be retained");
    assert_eq!(
        cycle.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([first_id, second_id])
    );
    assert!(!cycle.contains(&downstream_id));
}

#[test]
fn trusted_policy_rejects_spoofed_lineage_and_unknown_workspace_lease() {
    let id = WorkOrderId::new();
    let proposed = order(id, "lease/spoofed", "producer");
    let profile_id = proposed.assignment.model_profile_id.clone();
    let (graph, mut policy) = graph_and_policy(vec![proposed], 1);
    policy.model_profiles.insert(
        profile_id.clone(),
        ModelLineage {
            backend_id: "attested-backend".to_owned(),
            model_id: "attested-model".to_owned(),
            deployment_id: "attested-deployment".to_owned(),
            independence_domain_id: "attested-independence".to_owned(),
        },
    );
    policy.workspace_leases.clear();

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("planner declarations cannot replace trusted receipts")
    else {
        panic!("expected collected graph violations")
    };

    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::ModelLineageMismatch {
            work_order_id,
            model_profile_id
        } if *work_order_id == id && model_profile_id == &profile_id
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::UnknownWorkspaceLease { work_order_id, .. }
            if *work_order_id == id
    )));
}

#[test]
fn reviewer_on_another_deployment_is_rejected_inside_the_same_independence_domain() {
    let producer_id = WorkOrderId::new();
    let reviewer_id = WorkOrderId::new();
    let producer = order(producer_id, "lease/domain-producer", "producer");
    let mut reviewer = order(reviewer_id, "lease/domain-reviewer", "reviewer");
    reviewer.assignment.lineage.backend_id = producer.assignment.lineage.backend_id.clone();
    reviewer.assignment.lineage.model_id = producer.assignment.lineage.model_id.clone();
    reviewer.assignment.lineage.independence_domain_id =
        producer.assignment.lineage.independence_domain_id.clone();
    assert_ne!(
        reviewer.assignment.lineage.deployment_id,
        producer.assignment.lineage.deployment_id
    );
    reviewer.dependencies.insert(producer_id);
    reviewer.reviews.insert(producer_id);
    let (graph, policy) = graph_and_policy(vec![producer, reviewer], 1);

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("deployment aliases cannot create review independence")
    else {
        panic!("expected an independence-domain violation")
    };
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::ReviewerLineageConflict {
            reviewer_id: actual_reviewer,
            target_id
        } if *actual_reviewer == reviewer_id && *target_id == producer_id
    )));
}

#[test]
fn reader_cannot_share_a_workspace_lease_with_a_writer() {
    let writer_id = WorkOrderId::new();
    let reader_id = WorkOrderId::new();
    let mut writer = order(writer_id, "lease/aliased", "writer");
    writer.workspace.access = WorkspaceAccess::Write;
    let reader = order(reader_id, "lease/aliased", "reader");
    let (graph, mut policy) = graph_and_policy(vec![reader, writer], 2);
    policy.workspace_leases.insert(
        WorkspaceLeaseId::new("lease/aliased").unwrap(),
        WorkspaceLeasePolicy {
            base_snapshot_sha256: SNAPSHOT.to_owned(),
            access: WorkspaceAccess::Write,
        },
    );

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("a writer lease must be exclusive")
    else {
        panic!("expected shared writer lease violation")
    };
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::SharedWriterLease { lease_id }
            if lease_id.as_str() == "lease/aliased"
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::WriteWorkspaceExecutionUnsupported { work_order_id }
            if *work_order_id == writer_id
    )));
}

#[test]
fn candidate_peers_cannot_depend_on_or_share_live_contexts() {
    let first_id = WorkOrderId::new();
    let second_id = WorkOrderId::new();
    let group = CandidateGroupId::new("candidate/independent").unwrap();
    let mut first = order(first_id, "lease/candidate", "first");
    first.candidate_group = Some(group.clone());
    let mut second = order(second_id, "lease/candidate", "second");
    second.candidate_group = Some(group.clone());
    second.dependencies.insert(first_id);
    let (graph, policy) = graph_and_policy(vec![first, second], 2);

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("candidate peers must remain independent")
    else {
        panic!("expected candidate isolation violations")
    };
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::CandidateDependency { candidate_group_id, .. }
            if candidate_group_id == &group
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::CandidateContractMismatch { candidate_group_id }
            if candidate_group_id == &group
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::CandidateSharedWorkspaceLease { candidate_group_id, .. }
            if candidate_group_id == &group
    )));
}

#[test]
fn candidate_group_requires_at_least_two_independent_members() {
    let group = CandidateGroupId::new("candidate/singleton").unwrap();
    let mut singleton = order(WorkOrderId::new(), "lease/singleton", "singleton");
    singleton.candidate_group = Some(group.clone());
    let (graph, policy) = graph_and_policy(vec![singleton], 1);

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("a one-member candidate group cannot be a comparison")
    else {
        panic!("expected singleton candidate rejection")
    };
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::CandidateGroupTooSmall {
            candidate_group_id,
            actual: 1
        } if candidate_group_id == &group
    )));
}

#[test]
fn candidate_peers_cannot_observe_each_other_through_a_mediator() {
    let first_id = WorkOrderId::new();
    let mediator_id = WorkOrderId::new();
    let second_id = WorkOrderId::new();
    let group = CandidateGroupId::new("candidate/transitive").unwrap();
    let mut first = order(first_id, "lease/transitive-first", "first");
    first.candidate_group = Some(group.clone());
    let mut mediator = order(mediator_id, "lease/transitive-mediator", "mediator");
    mediator.dependencies.insert(first_id);
    let mut second = order(second_id, "lease/transitive-second", "second");
    second.candidate_group = Some(group.clone());
    second.objective.clone_from(&first.objective);
    second.dependencies.insert(mediator_id);
    let (graph, policy) = graph_and_policy(vec![first, mediator, second], 2);

    let ActorGraphValidationError::Violations { violations } = graph
        .validate_against(&policy)
        .expect_err("candidate isolation must include transitive graph reachability")
    else {
        panic!("expected a transitive candidate dependency violation")
    };
    assert!(violations.iter().any(|violation| matches!(
        violation,
        ActorGraphViolation::CandidateDependency {
            candidate_group_id,
            work_order_id,
            dependency_id
        } if candidate_group_id == &group
            && *work_order_id == second_id
            && *dependency_id == first_id
    )));
}

#[test]
fn graph_digest_normalizes_order_and_binds_the_trusted_policy() {
    let first = order(WorkOrderId::new(), "lease/digest-first", "first");
    let second = order(WorkOrderId::new(), "lease/digest-second", "second");
    let (forward, policy) = graph_and_policy(vec![first.clone(), second.clone()], 2);
    let (reverse, reverse_policy) = graph_and_policy(vec![second, first], 2);
    let forward = forward
        .validate_against(&policy)
        .expect("forward graph should validate");
    let reverse = reverse
        .validate_against(&reverse_policy)
        .expect("reverse graph should validate");
    assert_eq!(forward.digest_sha256(), reverse.digest_sha256());

    let mut changed_policy = policy.clone();
    changed_policy.policy_version = "test-policy/2".to_owned();
    let rebound = forward
        .graph()
        .clone()
        .validate_against(&changed_policy)
        .expect("same proposal should fit the changed policy");
    assert_ne!(forward.digest_sha256(), rebound.digest_sha256());
}

#[tokio::test]
async fn repeated_graph_executions_have_distinct_durable_roots_and_terminals() {
    let id = WorkOrderId::new();
    let validated = validate_graph(vec![order(id, "lease/repeated-run", "producer")], 1)
        .expect("graph should validate");
    let worker = CountingWorker(AtomicUsize::new(0));
    let first_journal = InMemorySchedulerJournal::default();
    let second_journal = InMemorySchedulerJournal::default();

    let first = ActorGraphExecutor::new(&worker, &first_journal)
        .execute(&validated)
        .await
        .expect("first run should complete");
    let second = ActorGraphExecutor::new(&worker, &second_journal)
        .execute(&validated)
        .await
        .expect("second run should complete");

    assert_eq!(first.graph_sha256, second.graph_sha256);
    assert_ne!(first.accepted_event_id, second.accepted_event_id);
    assert_ne!(first.finished_event_id, second.finished_event_id);
    assert_ne!(first.terminal_event_ids, second.terminal_event_ids);
}

struct RetryWorker {
    calls: AtomicUsize,
}

impl AgentWorker for RetryWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Err(AgentFailure {
                    kind: AgentFailureKind::RetryableNoEffect,
                    message: "typed transient failure".to_owned(),
                    usage: Usage::default(),
                    execution_receipt_id: "execution-receipt/retry-1".to_owned(),
                    effect_receipt_id: Some("effect-receipt/no-effect/1".to_owned()),
                })
            } else {
                Ok(completion("recovered"))
            }
        })
    }
}

#[tokio::test]
async fn retry_is_bounded_and_causally_linked_without_message_parsing() {
    let id = WorkOrderId::new();
    let validated = validate_graph(vec![order(id, "lease/retry", "producer")], 1)
        .expect("graph should validate");
    let worker = RetryWorker {
        calls: AtomicUsize::new(0),
    };
    let journal = InMemorySchedulerJournal::default();

    let run = ActorGraphExecutor::new(&worker, &journal)
        .execute(&validated)
        .await
        .expect("scheduler should complete");

    assert_eq!(run.outcome, ActorGraphOutcome::Completed);
    assert_eq!(worker.calls.load(Ordering::SeqCst), 2);
    let records = journal.snapshot().expect("journal snapshot");
    let dispatches = records
        .iter()
        .filter_map(|record| match &record.event {
            SchedulerEvent::AttemptDispatched {
                attempt_id,
                parent_attempt_id,
                ..
            } => Some((record, *attempt_id, *parent_attempt_id)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(dispatches.len(), 2);
    assert_eq!(dispatches[0].2, None);
    assert_eq!(dispatches[1].2, Some(dispatches[0].1));
    let first_failure = records
        .iter()
        .find(|record| {
            matches!(
                record.event,
                SchedulerEvent::AttemptFailed {
                    will_retry: true,
                    ..
                }
            )
        })
        .expect("retryable failure should be retained");
    assert_eq!(dispatches[1].0.causal_parent, Some(first_failure.id));
}

struct UnreceiptedRetryWorker(AtomicUsize);

impl AgentWorker for UnreceiptedRetryWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(AgentFailure {
                kind: AgentFailureKind::RetryableNoEffect,
                message: "unattested effect disposition".to_owned(),
                usage: Usage::default(),
                execution_receipt_id: "execution-receipt/unattested".to_owned(),
                effect_receipt_id: None,
            })
        })
    }
}

#[tokio::test]
async fn retryable_label_without_no_effect_receipt_is_not_retried() {
    let id = WorkOrderId::new();
    let validated = validate_graph(vec![order(id, "lease/no-receipt", "producer")], 1)
        .expect("graph should validate");
    let worker = UnreceiptedRetryWorker(AtomicUsize::new(0));
    let journal = InMemorySchedulerJournal::default();

    let run = ActorGraphExecutor::new(&worker, &journal)
        .execute(&validated)
        .await
        .expect("worker failure should produce a terminal run");

    assert_eq!(run.outcome, ActorGraphOutcome::Failed);
    assert_eq!(worker.0.load(Ordering::SeqCst), 1);
    assert!(journal.snapshot().unwrap().iter().any(|record| matches!(
        record.event,
        SchedulerEvent::AttemptFailed {
            will_retry: false,
            ..
        }
    )));
}

struct InvalidFailureWorker;

impl AgentWorker for InvalidFailureWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async {
            Err(AgentFailure {
                kind: AgentFailureKind::PermanentBackend,
                message: String::new(),
                usage: Usage {
                    output_tokens: Some(9_999),
                    tool_calls: 999,
                },
                execution_receipt_id: "execution-receipt/invalid-failure".to_owned(),
                effect_receipt_id: Some("x".repeat(513)),
            })
        })
    }
}

#[tokio::test]
async fn malformed_failure_retains_bounded_receipts_usage_and_payload_hash() {
    let id = WorkOrderId::new();
    let validated = validate_graph(vec![order(id, "lease/invalid-failure", "producer")], 1)
        .expect("graph should validate");

    let run = ActorGraphExecutor::new(&InvalidFailureWorker, &InMemorySchedulerJournal::default())
        .execute(&validated)
        .await
        .expect("invalid worker failure should remain a terminal observation");

    let Some(WorkOrderFailure::InvalidWorkerFailure {
        violations,
        usage_violation,
        observation,
    }) = run.failures.get(&id)
    else {
        panic!("invalid failure must retain reconciliation material")
    };
    assert!(violations.contains(&AgentFailureViolation::EmptyMessage));
    assert!(violations.contains(&AgentFailureViolation::InvalidEffectReceipt));
    assert!(matches!(
        usage_violation,
        Some(ActorGraphViolation::OutputTokenBudgetExceeded { actual: 9_999, .. })
    ));
    assert_eq!(
        observation.execution_receipt_id.as_deref(),
        Some("execution-receipt/invalid-failure")
    );
    assert_eq!(observation.effect_receipt_id, None);
    assert_eq!(observation.usage.output_tokens, Some(9_999));
    assert_eq!(observation.payload_sha256.len(), 64);
}

struct InvalidCompletionWorker;

impl AgentWorker for InvalidCompletionWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async {
            Ok(AgentCompletion {
                outcome: HandoffOutcome::Completed,
                summary: String::new(),
                execution_receipt_id: "execution-receipt/malformed".to_owned(),
                artifact_sha256: vec!["not-a-digest".to_owned()],
                evidence_ids: Vec::new(),
                usage: Usage {
                    output_tokens: Some(9_999),
                    tool_calls: 999,
                },
            })
        })
    }
}

#[tokio::test]
async fn malformed_handoff_fails_before_unmetered_success_can_open_dependencies() {
    let id = WorkOrderId::new();
    let validated = validate_graph(vec![order(id, "lease/invalid-handoff", "producer")], 1)
        .expect("graph should validate");

    let run = ActorGraphExecutor::new(
        &InvalidCompletionWorker,
        &InMemorySchedulerJournal::default(),
    )
    .execute(&validated)
    .await
    .expect("invalid handoff should be retained as a terminal failure");

    assert_eq!(run.outcome, ActorGraphOutcome::Failed);
    let Some(WorkOrderFailure::InvalidHandoff {
        violations,
        usage_violation,
        observation,
    }) = run.failures.get(&id)
    else {
        panic!("malformed completion must retain its bounded observation")
    };
    assert!(violations.len() >= 3);
    assert!(matches!(
        usage_violation,
        Some(ActorGraphViolation::OutputTokenBudgetExceeded { actual: 9_999, .. })
    ));
    assert_eq!(
        observation.execution_receipt_id.as_deref(),
        Some("execution-receipt/malformed")
    );
    assert_eq!(observation.usage.output_tokens, Some(9_999));
    assert_eq!(observation.payload_sha256.len(), 64);
    assert!(!run.handoffs.contains_key(&id));
}

struct UnmeteredCompletionWorker;

impl AgentWorker for UnmeteredCompletionWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async {
            Ok(AgentCompletion {
                usage: Usage {
                    output_tokens: None,
                    tool_calls: 1,
                },
                ..completion("valid except missing provider usage")
            })
        })
    }
}

#[tokio::test]
async fn trusted_policy_can_fail_closed_on_missing_provider_token_usage() {
    let id = WorkOrderId::new();
    let validated = validate_graph(vec![order(id, "lease/unmetered", "producer")], 1)
        .expect("graph should validate");

    let run = ActorGraphExecutor::new(
        &UnmeteredCompletionWorker,
        &InMemorySchedulerJournal::default(),
    )
    .execute(&validated)
    .await
    .expect("usage violation should produce a terminal run");

    assert!(matches!(
        run.failures.get(&id),
        Some(WorkOrderFailure::UsageViolation {
            violation: ActorGraphViolation::MissingOutputTokenUsage
        })
    ));
}

enum ConfiguredBehavior {
    Complete,
    PermanentFailure,
    Partial,
}

struct ConfiguredWorker {
    behavior: BTreeMap<WorkOrderId, ConfiguredBehavior>,
    calls: Mutex<Vec<WorkOrderId>>,
}

impl AgentWorker for ConfiguredWorker {
    fn execute(&self, dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async move {
            self.calls
                .lock()
                .expect("calls lock")
                .push(dispatch.work_order.id);
            match self.behavior[&dispatch.work_order.id] {
                ConfiguredBehavior::Complete => Ok(completion("complete")),
                ConfiguredBehavior::PermanentFailure => Err(AgentFailure {
                    kind: AgentFailureKind::PermanentBackend,
                    message: "typed permanent failure".to_owned(),
                    usage: Usage::default(),
                    execution_receipt_id: "execution-receipt/permanent".to_owned(),
                    effect_receipt_id: None,
                }),
                ConfiguredBehavior::Partial => Ok(AgentCompletion {
                    outcome: HandoffOutcome::Partial,
                    ..completion("partial")
                }),
            }
        })
    }
}

#[tokio::test]
async fn failures_and_partial_handoffs_block_dependencies_but_not_independent_siblings() {
    let failed = WorkOrderId::new();
    let partial = WorkOrderId::new();
    let failed_dependent = WorkOrderId::new();
    let transitive_dependent = WorkOrderId::new();
    let partial_dependent = WorkOrderId::new();
    let sibling = WorkOrderId::new();
    let mut failed_dependent_order = order(failed_dependent, "lease/fd", "dependent");
    failed_dependent_order.dependencies.insert(failed);
    let mut partial_dependent_order = order(partial_dependent, "lease/pd", "dependent");
    partial_dependent_order.dependencies.insert(partial);
    let mut transitive_dependent_order = order(transitive_dependent, "lease/td", "dependent");
    transitive_dependent_order
        .dependencies
        .insert(failed_dependent);
    let validated = validate_graph(
        vec![
            order(failed, "lease/fail", "producer"),
            order(partial, "lease/partial", "producer"),
            failed_dependent_order,
            transitive_dependent_order,
            partial_dependent_order,
            order(sibling, "lease/sibling", "sibling"),
        ],
        3,
    )
    .expect("graph should validate");
    let worker = ConfiguredWorker {
        behavior: BTreeMap::from([
            (failed, ConfiguredBehavior::PermanentFailure),
            (partial, ConfiguredBehavior::Partial),
            (failed_dependent, ConfiguredBehavior::Complete),
            (transitive_dependent, ConfiguredBehavior::Complete),
            (partial_dependent, ConfiguredBehavior::Complete),
            (sibling, ConfiguredBehavior::Complete),
        ]),
        calls: Mutex::new(Vec::new()),
    };
    let journal = InMemorySchedulerJournal::default();

    let run = ActorGraphExecutor::new(&worker, &journal)
        .execute(&validated)
        .await
        .expect("scheduler should reach a terminal projection");

    assert_eq!(run.outcome, ActorGraphOutcome::Failed);
    assert!(run.handoffs.contains_key(&partial));
    assert!(run.handoffs.contains_key(&sibling));
    assert!(matches!(
        run.failures.get(&partial),
        Some(WorkOrderFailure::IncompleteHandoff {
            outcome: HandoffOutcome::Partial
        })
    ));
    assert!(matches!(
        run.failures.get(&failed_dependent),
        Some(WorkOrderFailure::DependencyFailed { .. })
    ));
    assert!(matches!(
        run.failures.get(&partial_dependent),
        Some(WorkOrderFailure::DependencyFailed { .. })
    ));
    assert!(matches!(
        run.failures.get(&transitive_dependent),
        Some(WorkOrderFailure::DependencyFailed { .. })
    ));
    let calls = worker.calls.lock().expect("calls lock");
    assert!(!calls.contains(&failed_dependent));
    assert!(!calls.contains(&partial_dependent));
    assert!(!calls.contains(&transitive_dependent));
    assert!(calls.contains(&sibling));
}

struct SlowWorker;

impl AgentWorker for SlowWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(completion("too late"))
        })
    }
}

struct CleanedSlowWorker;

impl AgentWorker for CleanedSlowWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(completion("too late"))
        })
    }

    fn cancel_and_cleanup(&self, _attempt: TimedOutAttempt) -> AgentCleanupFuture<'_> {
        Box::pin(async {
            Some(CleanupReceipt {
                cleanup_receipt_id: "cleanup-receipt/process-tree-stopped".to_owned(),
            })
        })
    }
}

#[tokio::test]
async fn attempt_deadline_is_enforced_by_the_scheduler() {
    let id = WorkOrderId::new();
    let mut slow = order(id, "lease/slow", "producer");
    slow.budget.max_wall_time_ms = 10;
    let validated = validate_graph(vec![slow], 1).expect("graph should validate");
    let journal = InMemorySchedulerJournal::default();

    let error = ActorGraphExecutor::new(&SlowWorker, &journal)
        .execute(&validated)
        .await
        .expect_err("unproven cleanup must suspend the graph");

    assert!(matches!(
        error,
        ActorGraphExecutionError::CleanupUnproven { ref work_order_ids, .. }
            if work_order_ids == &[id]
    ));
    let records = journal.snapshot().expect("suspended journal");
    assert!(records.iter().any(|record| matches!(
        &record.event,
        SchedulerEvent::AttemptFailed {
            failure: WorkOrderFailure::CleanupUnproven {
                maximum_ms: 10,
                cleanup_maximum_ms: 500
            },
            ..
        }
    )));
    assert!(matches!(
        records.last().map(|record| &record.event),
        Some(SchedulerEvent::GraphSuspended {
            cleanup_unproven_work_order_ids,
            pending_work_order_ids,
            ..
        }) if cleanup_unproven_work_order_ids == &[id] && pending_work_order_ids.is_empty()
    ));
    assert!(
        !records
            .iter()
            .any(|record| matches!(record.event, SchedulerEvent::GraphFinished { .. }))
    );
}

struct FailStopWorker {
    slow_id: WorkOrderId,
    calls: Mutex<Vec<WorkOrderId>>,
}

impl AgentWorker for FailStopWorker {
    fn execute(&self, dispatch: AgentDispatch) -> AgentFuture<'_> {
        let work_order_id = dispatch.work_order.id;
        self.calls
            .lock()
            .expect("fail-stop calls lock")
            .push(work_order_id);
        if work_order_id == self.slow_id {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(completion("too late"))
            })
        } else {
            Box::pin(async { Ok(completion("must remain pending")) })
        }
    }
}

#[tokio::test]
async fn cleanup_unproven_stops_new_dispatch_and_suspends_pending_work() {
    let slow_id = WorkOrderId::new();
    let pending_id = WorkOrderId::new();
    let mut slow = order(slow_id, "lease/fail-stop-slow", "slow");
    slow.priority = 10;
    slow.budget.max_wall_time_ms = 10;
    let pending = order(pending_id, "lease/fail-stop-pending", "pending");
    let validated = validate_graph(vec![pending, slow], 1).expect("graph should validate");
    let worker = FailStopWorker {
        slow_id,
        calls: Mutex::new(Vec::new()),
    };
    let journal = InMemorySchedulerJournal::default();

    let error = ActorGraphExecutor::new(&worker, &journal)
        .execute(&validated)
        .await
        .expect_err("unproven cleanup must suspend all new dispatch");

    assert!(matches!(
        error,
        ActorGraphExecutionError::CleanupUnproven { ref work_order_ids, .. }
            if work_order_ids == &[slow_id]
    ));
    assert_eq!(
        worker
            .calls
            .lock()
            .expect("fail-stop calls lock")
            .as_slice(),
        &[slow_id]
    );
    let records = journal.snapshot().expect("suspended journal");
    assert!(matches!(
        records.last().map(|record| &record.event),
        Some(SchedulerEvent::GraphSuspended {
            cleanup_unproven_work_order_ids,
            pending_work_order_ids,
            ..
        }) if cleanup_unproven_work_order_ids == &[slow_id]
            && pending_work_order_ids == &[pending_id]
    ));
}

#[tokio::test]
async fn deadline_is_only_confirmed_when_cleanup_returns_a_bounded_receipt() {
    let id = WorkOrderId::new();
    let mut slow = order(id, "lease/cleaned-timeout", "producer");
    slow.budget.max_wall_time_ms = 10;
    let validated = validate_graph(vec![slow], 1).expect("graph should validate");

    let run = ActorGraphExecutor::new(&CleanedSlowWorker, &InMemorySchedulerJournal::default())
        .execute(&validated)
        .await
        .expect("cleanup receipt should produce a bounded terminal failure");

    assert!(matches!(
        run.failures.get(&id),
        Some(WorkOrderFailure::DeadlineExceeded {
            maximum_ms: 10,
            cleanup_receipt_id
        }) if cleanup_receipt_id == "cleanup-receipt/process-tree-stopped"
    ));
}

struct CountingWorker(AtomicUsize);

impl AgentWorker for CountingWorker {
    fn execute(&self, _dispatch: AgentDispatch) -> AgentFuture<'_> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(completion("must not run")) })
    }
}

struct RejectDispatchJournal {
    root_seen: ThreadBarrier,
}

impl SchedulerJournal for RejectDispatchJournal {
    fn retain(&self, record: &SchedulerRecord) -> Result<(), SchedulerJournalError> {
        match record.event {
            SchedulerEvent::GraphAccepted { .. } => {
                self.root_seen.wait();
                Ok(())
            }
            SchedulerEvent::AttemptDispatched { .. } => Err(SchedulerJournalError::new(
                "injected durable dispatch failure",
            )),
            _ => Ok(()),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_must_acknowledge_dispatch_before_worker_is_called() {
    let id = WorkOrderId::new();
    let validated = validate_graph(vec![order(id, "lease/journal", "producer")], 1)
        .expect("graph should validate");
    let worker = CountingWorker(AtomicUsize::new(0));
    let journal = Arc::new(RejectDispatchJournal {
        root_seen: ThreadBarrier::new(2),
    });
    let journal_for_thread = Arc::clone(&journal);
    let waiter = std::thread::spawn(move || journal_for_thread.root_seen.wait());

    let error = ActorGraphExecutor::new(&worker, journal.as_ref())
        .execute(&validated)
        .await
        .expect_err("journal failure must stop the graph");

    waiter.join().expect("barrier thread should join");
    assert!(
        error
            .to_string()
            .contains("injected durable dispatch failure")
    );
    assert_eq!(worker.0.load(Ordering::SeqCst), 0);
}
