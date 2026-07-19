use birdcode_backends::{
    BackendFuture, BackendId, InferenceEvidence, Message, MessageRole, ModelBackend, ModelCatalog,
    ModelId, StructuredInferenceRequest, StructuredInferenceResponse, StructuredOutputSpec,
};
use birdcode_orchestrator::planner::*;
use serde_json::json;
use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Fixture {
    catalog: ProtectedObligationCatalog,
    obligation: ProtectedObligation,
    evidence: PlannerEvidenceId,
    context: PlannerContextCatalog,
    policy: PlannerPolicy,
    base: PlanSnapshot,
}

fn fixture() -> Fixture {
    let obligation = ProtectedObligation::new(
        ObligationId::new(),
        "Bevara svenska, 日本語, العربية och emoji 🐦 exakt.",
        true,
    );
    let catalog = ProtectedObligationCatalog::new(
        PlannerDigest::of_bytes(b"protected acceptance policy"),
        [obligation.clone()],
    )
    .expect("protected catalog");
    let evidence = PlannerEvidenceId::new("event:user-goal:1").expect("evidence ID");
    let context =
        PlannerContextCatalog::new([evidence.clone()]).expect("content-bound context catalog");
    let policy = PlannerPolicy::read_only(PlannerLimits::default()).expect("read-only policy");
    let base = PlanSnapshot::empty(PlanId::new(), &catalog);
    Fixture {
        catalog,
        obligation,
        evidence,
        context,
        policy,
        base,
    }
}

fn basis(fixture: &Fixture, rationale: &str) -> DecisionBasis {
    DecisionBasis {
        evidence_ids: BTreeSet::from([fixture.evidence.clone()]),
        rationale: rationale.to_owned(),
    }
}

fn obligation_ref(fixture: &Fixture) -> ProtectedObligationRef {
    ProtectedObligationRef::from(&fixture.obligation)
}

fn execute_new(local_id: u32) -> PlannerDirective {
    PlannerDirective {
        kind: PlannerDirectiveKind::Execute,
        execute: WorkSelection {
            existing: BTreeSet::new(),
            new: BTreeSet::from([LocalWorkOrderId(local_id)]),
        },
        delegations: Vec::new(),
        clarifications: Vec::new(),
        escalations: Vec::new(),
        finish_claims: Vec::new(),
    }
}

fn execute_existing(id: PlanWorkOrderId) -> PlannerDirective {
    PlannerDirective {
        kind: PlannerDirectiveKind::Execute,
        execute: WorkSelection {
            existing: BTreeSet::from([id]),
            new: BTreeSet::new(),
        },
        delegations: Vec::new(),
        clarifications: Vec::new(),
        escalations: Vec::new(),
        finish_claims: Vec::new(),
    }
}

fn initial_proposal(fixture: &Fixture) -> PlannerTurnProposal {
    let obligation = obligation_ref(fixture);
    PlannerTurnProposal {
        schema_version: 1,
        bindings: PlannerTurnBindings::new(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect("bindings"),
        patch: PlanPatch {
            strategy_summary: Some(
                "Kartlägg först koden; behåll 日本語 och العربية oförändrade 🐦.".to_owned(),
            ),
            add_verification_targets: vec![NewVerificationTarget {
                local_id: LocalVerificationTargetId(1),
                statement: "Rapporten visar de exakta multilingual-värdena 🐦.".to_owned(),
                obligations: BTreeSet::from([obligation.clone()]),
                basis: basis(fixture, "Användarmålet kräver explicit bevarande."),
            }],
            add_work_orders: vec![NewWorkOrder {
                local_id: LocalWorkOrderId(1),
                objective: "Inspektera 日本語-koden och rapportera العربية utan ändringar 🐦."
                    .to_owned(),
                obligations: BTreeSet::from([obligation]),
                existing_dependencies: BTreeSet::new(),
                new_dependencies: BTreeSet::new(),
                existing_verification_targets: BTreeSet::new(),
                new_verification_targets: BTreeSet::from([LocalVerificationTargetId(1)]),
                required_access: PlannerAccess::ReadOnly,
                basis: basis(
                    fixture,
                    "Repositoryinspektion behövs innan fortsatt planering.",
                ),
            }],
            replace_work_orders: Vec::new(),
            cancel_work_orders: Vec::new(),
        },
        directive: execute_new(1),
    }
}

fn proposal_with_directive(fixture: &Fixture, directive: PlannerDirective) -> PlannerTurnProposal {
    PlannerTurnProposal {
        schema_version: 1,
        bindings: PlannerTurnBindings::new(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect("bindings"),
        patch: PlanPatch::default(),
        directive,
    }
}

fn assert_violation(error: &PlannerValidationError, expected: impl Fn(&PlannerViolation) -> bool) {
    assert!(
        error.violations.iter().any(expected),
        "missing expected violation in {:?}",
        error.violations
    );
}

#[test]
fn multilingual_plan_is_preserved_without_language_specific_identifiers() {
    let fixture = fixture();
    let proposal = initial_proposal(&fixture);
    let result = proposal
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect("multilingual plan should validate");

    assert_eq!(result.plan.revision, 1);
    assert!(result.plan.strategy_summary.contains("日本語"));
    assert!(result.plan.strategy_summary.contains("العربية"));
    assert!(result.plan.strategy_summary.contains('🐦'));
    let work = result.plan.work_orders.values().next().expect("work order");
    assert!(work.objective.contains("日本語"));
    assert!(work.objective.contains("العربية"));
    assert_eq!(work.required_access, PlannerAccess::ReadOnly);
    assert!(matches!(
        result.directive,
        ResolvedPlannerDirective::Execute { work_order_id } if work_order_id == work.id
    ));

    let encoded = serde_json::to_vec(&result.plan).expect("plan serialization");
    let decoded: PlanSnapshot = serde_json::from_slice(&encoded).expect("plan deserialization");
    assert_eq!(decoded, result.plan);
    assert_eq!(decoded.sha256().unwrap(), result.plan_sha256);
}

#[test]
fn replaying_the_same_observed_proposal_materializes_the_identical_plan() {
    let fixture = fixture();
    let proposal = initial_proposal(&fixture);

    let first = proposal
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect("first materialization should validate");
    let replay = proposal
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect("replayed materialization should validate");

    assert_eq!(replay.plan, first.plan);
    assert_eq!(replay.plan_sha256, first.plan_sha256);
    assert_eq!(replay.directive, first.directive);
}

#[test]
fn stale_bindings_fail_before_any_plan_mutation() {
    let fixture = fixture();
    let mut proposal = initial_proposal(&fixture);
    proposal.bindings.base_plan_sha256 = PlannerDigest::of_bytes(b"stale plan");
    let before = fixture.base.clone();
    let before_hash = fixture.base.sha256().unwrap();

    let error = proposal
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("stale proposal must fail");

    assert_violation(&error, |violation| {
        matches!(violation, PlannerViolation::StalePlanBinding)
    });
    assert_eq!(fixture.base, before);
    assert_eq!(fixture.base.sha256().unwrap(), before_hash);
}

#[test]
fn required_obligation_coverage_is_mechanical_and_atomic() {
    let first = ProtectedObligation::new(ObligationId::new(), "Första kravet", true);
    let second = ProtectedObligation::new(ObligationId::new(), "第二の必須要件", true);
    let catalog = ProtectedObligationCatalog::new(
        PlannerDigest::of_bytes(b"acceptance"),
        [first.clone(), second.clone()],
    )
    .unwrap();
    let evidence = PlannerEvidenceId::new("event:goal").unwrap();
    let context = PlannerContextCatalog::new([evidence.clone()]).unwrap();
    let policy = PlannerPolicy::read_only(PlannerLimits::default()).unwrap();
    let base = PlanSnapshot::empty(PlanId::new(), &catalog);
    let mut fixture = fixture();
    fixture.catalog = catalog;
    fixture.obligation = first;
    fixture.evidence = evidence;
    fixture.context = context;
    fixture.policy = policy;
    fixture.base = base;
    let proposal = initial_proposal(&fixture);
    let before = fixture.base.clone();

    let error = proposal
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("one required obligation is uncovered");

    assert_violation(&error, |violation| {
        matches!(
            violation,
            PlannerViolation::RequiredObligationUncovered { obligation_id }
                if *obligation_id == second.id
        )
    });
    assert_eq!(fixture.base, before, "failed patch must be atomic");
}

#[test]
fn initial_clarification_and_escalation_can_pause_without_inventing_work() {
    let fixture = fixture();
    let clarification = proposal_with_directive(
        &fixture,
        PlannerDirective {
            kind: PlannerDirectiveKind::Clarify,
            execute: WorkSelection::default(),
            delegations: Vec::new(),
            clarifications: vec![ClarificationRequest {
                question: "Vilket observerbart resultat ska prioriteras? 日本語 🐦".to_owned(),
                blocked_obligations: BTreeSet::from([obligation_ref(&fixture)]),
                basis: basis(&fixture, "Målet lämnar ett auktoritativt val öppet."),
            }],
            escalations: Vec::new(),
            finish_claims: Vec::new(),
        },
    )
    .validate_and_apply(
        &fixture.base,
        &fixture.catalog,
        &fixture.context,
        &fixture.policy,
    )
    .expect("an initial clarification is a valid fail-closed pause");
    assert!(clarification.plan.work_orders.is_empty());
    assert_eq!(clarification.plan.revision, 0);
    assert!(matches!(
        clarification.directive,
        ResolvedPlannerDirective::Clarify { .. }
    ));

    let escalation = proposal_with_directive(
        &fixture,
        PlannerDirective {
            kind: PlannerDirectiveKind::Escalate,
            execute: WorkSelection::default(),
            delegations: Vec::new(),
            clarifications: Vec::new(),
            escalations: vec![EscalationRequest {
                kind: EscalationKind::Authority,
                request: "Ge read-only-åtkomst till den valda arbetsytan.".to_owned(),
                blocked_obligations: BTreeSet::from([obligation_ref(&fixture)]),
                basis: basis(
                    &fixture,
                    "Planering kräver en uttrycklig arbetsyteauktoritet.",
                ),
            }],
            finish_claims: Vec::new(),
        },
    )
    .validate_and_apply(
        &fixture.base,
        &fixture.catalog,
        &fixture.context,
        &fixture.policy,
    )
    .expect("an initial escalation is a valid fail-closed pause");
    assert!(escalation.plan.work_orders.is_empty());
    assert_eq!(escalation.plan.revision, 0);
    assert!(matches!(
        escalation.directive,
        ResolvedPlannerDirective::Escalate { .. }
    ));
}

#[test]
fn empty_initial_execute_delegate_and_finish_keep_obligation_coverage() {
    let fixture = fixture();
    let directives = [
        PlannerDirective {
            kind: PlannerDirectiveKind::Execute,
            execute: WorkSelection::default(),
            delegations: Vec::new(),
            clarifications: Vec::new(),
            escalations: Vec::new(),
            finish_claims: Vec::new(),
        },
        PlannerDirective {
            kind: PlannerDirectiveKind::Delegate,
            execute: WorkSelection::default(),
            delegations: vec![DelegationRequest {
                work_orders: WorkSelection::default(),
                basis: basis(&fixture, "Ingen fabricerad arbetsorder får väljas."),
            }],
            clarifications: Vec::new(),
            escalations: Vec::new(),
            finish_claims: Vec::new(),
        },
        PlannerDirective {
            kind: PlannerDirectiveKind::Finish,
            execute: WorkSelection::default(),
            delegations: Vec::new(),
            clarifications: Vec::new(),
            escalations: Vec::new(),
            finish_claims: vec![FinishClaim {
                obligation: obligation_ref(&fixture),
                evidence_ids: BTreeSet::from([fixture.evidence.clone()]),
            }],
        },
    ];

    for directive in directives {
        let error = proposal_with_directive(&fixture, directive)
            .validate_and_apply(
                &fixture.base,
                &fixture.catalog,
                &fixture.context,
                &fixture.policy,
            )
            .expect_err("active/completion directives require covered obligations");
        assert_violation(&error, |violation| {
            matches!(
                violation,
                PlannerViolation::RequiredObligationUncovered { .. }
            )
        });
    }
}

#[test]
fn read_only_policy_rejects_model_requested_workspace_write() {
    let fixture = fixture();
    let mut proposal = initial_proposal(&fixture);
    proposal.patch.add_work_orders[0].required_access = PlannerAccess::WorkspaceWrite;

    let error = proposal
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("write access must fail in first policy");

    assert_violation(&error, |violation| {
        matches!(
            violation,
            PlannerViolation::AccessExpansion {
                access: PlannerAccess::WorkspaceWrite
            }
        )
    });
}

#[test]
fn context_catalog_is_canonical_bounded_and_rejects_digest_substitution() {
    let first = PlannerEvidenceId::new("event:z").unwrap();
    let second = PlannerEvidenceId::new("event:a").unwrap();
    let left = PlannerContextCatalog::new([first.clone(), second.clone()]).unwrap();
    let right = PlannerContextCatalog::new([second.clone(), first.clone()]).unwrap();
    assert_eq!(
        left, right,
        "input ordering cannot change canonical evidence"
    );
    assert_eq!(left.evidence_ids().len(), 2);
    assert!(matches!(
        PlannerContextCatalog::new([first.clone(), first]),
        Err(PlannerContractError::DuplicateContextEvidenceId(_))
    ));

    let mut encoded = serde_json::to_value(&left).unwrap();
    encoded["manifest_sha256"] = serde_json::Value::String("0".repeat(64));
    assert!(serde_json::from_value::<PlannerContextCatalog>(encoded).is_err());

    let oversized = ProtectedObligation::new(ObligationId::new(), "x".repeat(70_000), true);
    assert!(matches!(
        ProtectedObligationCatalog::new(PlannerDigest::of_bytes(b"policy"), [oversized]),
        Err(PlannerContractError::InvalidObligationStatement)
    ));

    let too_many_obligations = ProtectedObligationCatalog::new(
        PlannerDigest::of_bytes(b"policy"),
        (0..4_100).map(|index| {
            ProtectedObligation::new(ObligationId::new(), format!("obligation-{index}"), true)
        }),
    );
    assert!(matches!(
        too_many_obligations,
        Err(PlannerContractError::TooManyObligations)
    ));

    let oversized_context =
        PlannerContextCatalog::new((0..4_096).map(|index| {
            PlannerEvidenceId::new(format!("{index:04}{}", "e".repeat(507))).unwrap()
        }));
    assert!(matches!(
        oversized_context,
        Err(PlannerContractError::ContextCatalogTooLarge)
    ));
}

#[test]
fn directive_hard_cardinality_and_encoded_byte_caps_fail_before_semantic_collection() {
    let fixture = fixture();
    let escalation = EscalationRequest {
        kind: EscalationKind::Budget,
        request: "Reservera verifierad budget.".to_owned(),
        blocked_obligations: BTreeSet::from([obligation_ref(&fixture)]),
        basis: basis(&fixture, "Budgettaket blockerar nästa säkra steg."),
    };
    let too_many_escalations = proposal_with_directive(
        &fixture,
        PlannerDirective {
            kind: PlannerDirectiveKind::Escalate,
            execute: WorkSelection::default(),
            delegations: Vec::new(),
            clarifications: Vec::new(),
            escalations: vec![escalation; 17],
            finish_claims: Vec::new(),
        },
    );
    let error = too_many_escalations
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("escalation hard cap");
    assert_violation(&error, |violation| {
        matches!(violation, PlannerViolation::EscalationLimitExceeded { .. })
    });

    {
        let claim = FinishClaim {
            obligation: obligation_ref(&fixture),
            evidence_ids: BTreeSet::from([fixture.evidence.clone()]),
        };
        let too_many_finish_claims = proposal_with_directive(
            &fixture,
            PlannerDirective {
                kind: PlannerDirectiveKind::Finish,
                execute: WorkSelection::default(),
                delegations: Vec::new(),
                clarifications: Vec::new(),
                escalations: Vec::new(),
                finish_claims: vec![claim; 4_097],
            },
        );
        let error = too_many_finish_claims
            .validate_and_apply(
                &fixture.base,
                &fixture.catalog,
                &fixture.context,
                &fixture.policy,
            )
            .expect_err("finish-claim hard cap");
        assert_violation(&error, |violation| {
            matches!(violation, PlannerViolation::FinishClaimLimitExceeded { .. })
        });
    }

    let evidence_a = PlannerEvidenceId::new(format!("a{}", "x".repeat(510))).unwrap();
    let evidence_b = PlannerEvidenceId::new(format!("b{}", "y".repeat(510))).unwrap();
    let large_claim = FinishClaim {
        obligation: obligation_ref(&fixture),
        evidence_ids: BTreeSet::from([evidence_a, evidence_b]),
    };
    let oversized_finish = proposal_with_directive(
        &fixture,
        PlannerDirective {
            kind: PlannerDirectiveKind::Finish,
            execute: WorkSelection::default(),
            delegations: Vec::new(),
            clarifications: Vec::new(),
            escalations: Vec::new(),
            finish_claims: vec![large_claim; 4_096],
        },
    );
    let error = oversized_finish
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("aggregate encoded directive cap");
    assert_violation(&error, |violation| {
        matches!(
            violation,
            PlannerViolation::DirectiveEncodedLimitExceeded { .. }
        )
    });
}

#[test]
fn new_work_order_cycle_is_rejected_after_local_id_resolution() {
    let fixture = fixture();
    let mut proposal = initial_proposal(&fixture);
    let obligation = obligation_ref(&fixture);
    proposal.patch.add_work_orders[0].new_dependencies = BTreeSet::from([LocalWorkOrderId(2)]);
    proposal.patch.add_work_orders.push(NewWorkOrder {
        local_id: LocalWorkOrderId(2),
        objective: "Oberoende specialist som råkar bero tillbaka på första.".to_owned(),
        obligations: BTreeSet::from([obligation]),
        existing_dependencies: BTreeSet::new(),
        new_dependencies: BTreeSet::from([LocalWorkOrderId(1)]),
        existing_verification_targets: BTreeSet::new(),
        new_verification_targets: BTreeSet::from([LocalVerificationTargetId(1)]),
        required_access: PlannerAccess::ReadOnly,
        basis: basis(&fixture, "Ett andra perspektiv föreslogs."),
    });

    let error = proposal
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("cycle must fail");

    assert_violation(&error, |violation| {
        matches!(violation, PlannerViolation::DependencyCycle)
    });
}

#[test]
fn evidence_driven_replace_works_but_cancelling_last_coverage_fails_atomically() {
    let fixture = fixture();
    let first = initial_proposal(&fixture)
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .unwrap();
    let work = first.plan.work_orders.values().next().unwrap().clone();
    let target = first.plan.verification_targets.values().next().unwrap().id;
    let replacement = PlannerTurnProposal {
        schema_version: 1,
        bindings: PlannerTurnBindings::new(
            &first.plan,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .unwrap(),
        patch: PlanPatch {
            strategy_summary: Some("Ny plan efter verifierad observation.".to_owned()),
            add_verification_targets: Vec::new(),
            add_work_orders: Vec::new(),
            replace_work_orders: vec![ReplaceWorkOrder {
                target: ProtectedWorkOrderRef {
                    id: work.id,
                    revision_sha256: work.revision_sha256().unwrap(),
                },
                objective: "Revidera inspektionen utifrån observerad evidens 日本語.".to_owned(),
                obligations: work.obligations.clone(),
                existing_dependencies: BTreeSet::new(),
                new_dependencies: BTreeSet::new(),
                existing_verification_targets: BTreeSet::from([target]),
                new_verification_targets: BTreeSet::new(),
                required_access: PlannerAccess::ReadOnly,
                basis: basis(&fixture, "En faktisk observation ändrade nästa steg."),
            }],
            cancel_work_orders: Vec::new(),
        },
        directive: execute_existing(work.id),
    }
    .validate_and_apply(
        &first.plan,
        &fixture.catalog,
        &fixture.context,
        &fixture.policy,
    )
    .expect("replacement should validate");
    assert_eq!(replacement.plan.work_orders[&work.id].revision, 2);
    assert!(
        replacement.plan.work_orders[&work.id]
            .objective
            .contains("日本語")
    );

    let current = replacement.plan.work_orders[&work.id].clone();
    let cancellation = PlannerTurnProposal {
        schema_version: 1,
        bindings: PlannerTurnBindings::new(
            &replacement.plan,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .unwrap(),
        patch: PlanPatch {
            cancel_work_orders: vec![CancelWorkOrder {
                target: ProtectedWorkOrderRef {
                    id: current.id,
                    revision_sha256: current.revision_sha256().unwrap(),
                },
                basis: basis(&fixture, "Observationen visar att arbetet bör avbrytas."),
            }],
            ..PlanPatch::default()
        },
        directive: execute_existing(current.id),
    };
    let before = replacement.plan.clone();
    let error = cancellation
        .validate_and_apply(
            &replacement.plan,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("last obligation coverage cannot disappear");
    assert_violation(&error, |violation| {
        matches!(
            violation,
            PlannerViolation::RequiredObligationUncovered { .. }
        )
    });
    assert_eq!(replacement.plan, before);
}

#[test]
fn work_order_revision_overflow_fails_atomically() {
    let fixture = fixture();
    let first = initial_proposal(&fixture)
        .validate_and_apply(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .unwrap();
    let mut overflow_base = first.plan;
    let id = *overflow_base.work_orders.keys().next().unwrap();
    overflow_base.work_orders.get_mut(&id).unwrap().revision = u32::MAX;
    let work = overflow_base.work_orders[&id].clone();
    let replacement = PlannerTurnProposal {
        schema_version: 1,
        bindings: PlannerTurnBindings::new(
            &overflow_base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .unwrap(),
        patch: PlanPatch {
            replace_work_orders: vec![ReplaceWorkOrder {
                target: ProtectedWorkOrderRef {
                    id,
                    revision_sha256: work.revision_sha256().unwrap(),
                },
                objective: work.objective.clone(),
                obligations: work.obligations.clone(),
                existing_dependencies: work.dependencies.clone(),
                new_dependencies: BTreeSet::new(),
                existing_verification_targets: work.verification_targets.clone(),
                new_verification_targets: BTreeSet::new(),
                required_access: work.required_access,
                basis: basis(&fixture, "Revisionen får aldrig slå runt."),
            }],
            ..PlanPatch::default()
        },
        directive: execute_existing(id),
    };
    let before = overflow_base.clone();
    let error = replacement
        .validate_and_apply(
            &overflow_base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
        )
        .expect_err("work-order revision overflow");
    assert_violation(&error, |violation| {
        matches!(
            violation,
            PlannerViolation::WorkOrderRevisionOverflow { work_order_id }
                if *work_order_id == id
        )
    });
    assert_eq!(overflow_base, before);
}

fn backend_id() -> BackendId {
    BackendId::new("planner-test").unwrap()
}

fn model_id() -> ModelId {
    ModelId::new("planner/test-model").unwrap()
}

fn inference_request() -> StructuredInferenceRequest {
    StructuredInferenceRequest::new(
        model_id(),
        vec![Message::new(MessageRole::User, "typed planner invocation")],
        StructuredOutputSpec::new("planner_turn", json!({"type": "object"})).unwrap(),
        4_096,
    )
    .unwrap()
}

fn response(proposal: &PlannerTurnProposal) -> StructuredInferenceResponse {
    let value = serde_json::to_value(proposal).unwrap();
    StructuredInferenceResponse {
        model_id: model_id(),
        raw_text: serde_json::to_string(&value).unwrap(),
        value,
        finish_reason: Some("stop".to_owned()),
        usage: None,
        evidence: InferenceEvidence {
            backend_id: backend_id(),
            endpoint: "fake://planner".to_owned(),
            status: 200,
            completion_id: Some("planner-completion-1".to_owned()),
            response_body_sha256: Some("0".repeat(64)),
            raw_response: json!({"retained": true}),
        },
    }
}

struct OrderingBackend {
    id: BackendId,
    prepared_seen: Arc<AtomicBool>,
    calls: AtomicUsize,
    replies: Mutex<VecDeque<StructuredInferenceResponse>>,
}

impl OrderingBackend {
    fn new(prepared_seen: Arc<AtomicBool>, response: StructuredInferenceResponse) -> Self {
        Self {
            id: backend_id(),
            prepared_seen,
            calls: AtomicUsize::new(0),
            replies: Mutex::new(VecDeque::from([response])),
        }
    }
}

impl ModelBackend for OrderingBackend {
    fn backend_id(&self) -> &BackendId {
        &self.id
    }

    fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
        Box::pin(async { panic!("planner executor must not discover models") })
    }

    fn infer_structured(
        &self,
        _request: StructuredInferenceRequest,
    ) -> BackendFuture<'_, StructuredInferenceResponse> {
        assert!(
            self.prepared_seen.load(Ordering::SeqCst),
            "backend method was called before Prepared acknowledgement"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("one configured response"))
        })
    }
}

struct OrderingJournal {
    inner: InMemoryPlannerJournal,
    prepared_seen: Arc<AtomicBool>,
}

impl PlannerJournal for OrderingJournal {
    fn retain(&self, record: &PlannerJournalRecord) -> Result<(), PlannerJournalError> {
        self.inner.retain(record)?;
        if matches!(record, PlannerJournalRecord::Prepared(_)) {
            self.prepared_seen.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[tokio::test]
async fn executor_acknowledges_prepared_before_calling_backend() {
    let fixture = fixture();
    let proposal = initial_proposal(&fixture);
    let prepared_seen = Arc::new(AtomicBool::new(false));
    let backend = OrderingBackend::new(Arc::clone(&prepared_seen), response(&proposal));
    let journal = OrderingJournal {
        inner: InMemoryPlannerJournal::default(),
        prepared_seen,
    };
    let execution = PlannerExecutor::new(&backend, &journal)
        .execute(PlannerExecutionRequest::new(
            inference_request(),
            fixture.base,
            fixture.catalog,
            fixture.context,
            fixture.policy,
        ))
        .await
        .expect("planner execution");

    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        execution.status,
        PlannerExecutionStatus::Accepted { .. }
    ));
    let records = journal.inner.snapshot().unwrap();
    assert!(matches!(records[0], PlannerJournalRecord::Prepared(_)));
    assert!(matches!(records[1], PlannerJournalRecord::Observed(_)));
    assert!(matches!(records[2], PlannerJournalRecord::Accepted(_)));
    let encoded = serde_json::to_vec(&records).expect("journal serialization");
    let decoded: Vec<PlannerJournalRecord> =
        serde_json::from_slice(&encoded).expect("durable journal deserialization");
    assert_eq!(decoded, records);
    PlannerJournalProjection::replay(&decoded).expect("round-tripped journal replay");
    assert!(matches!(
        journal
            .inner
            .projection()
            .unwrap()
            .attempts
            .get(&execution.prepared.attempt_id),
        Some(PlannerAttemptProjection::Accepted { .. })
    ));
}

#[tokio::test]
async fn replay_recomputes_acceptance_and_rejects_fabricated_result_or_authority() {
    let fixture = fixture();
    let proposal = initial_proposal(&fixture);
    let prepared_seen = Arc::new(AtomicBool::new(false));
    let backend = OrderingBackend::new(Arc::clone(&prepared_seen), response(&proposal));
    let journal = OrderingJournal {
        inner: InMemoryPlannerJournal::default(),
        prepared_seen,
    };
    PlannerExecutor::new(&backend, &journal)
        .execute(PlannerExecutionRequest::new(
            inference_request(),
            fixture.base,
            fixture.catalog,
            fixture.context,
            fixture.policy,
        ))
        .await
        .expect("accepted execution");
    let records = journal.inner.snapshot().unwrap();

    let mut fabricated_result = records.clone();
    let PlannerJournalRecord::Accepted(accepted) = fabricated_result.last_mut().unwrap() else {
        panic!("terminal acceptance");
    };
    accepted
        .result
        .plan
        .strategy_summary
        .push_str(" fabricated");
    let error = PlannerJournalProjection::replay(&fabricated_result)
        .expect_err("result must be recomputed from observed proposal and authority");
    assert!(error.message.contains("fabricated"));

    let mut fabricated_proposal_digest = records.clone();
    let PlannerJournalRecord::Accepted(accepted) = fabricated_proposal_digest.last_mut().unwrap()
    else {
        panic!("terminal acceptance");
    };
    accepted.proposal_sha256 = PlannerDigest::of_bytes(b"substituted proposal");
    let error = PlannerJournalProjection::replay(&fabricated_proposal_digest)
        .expect_err("proposal digest must bind the exact observed JSON");
    assert!(error.message.contains("fabricated"));

    let mut substituted_authority = records;
    let PlannerJournalRecord::Prepared(prepared) = &mut substituted_authority[0] else {
        panic!("preparation");
    };
    prepared.base_plan.strategy_summary = "substituted authority".to_owned();
    let error = PlannerJournalProjection::replay(&substituted_authority)
        .expect_err("prepared authority snapshot must bind its repeated digest");
    assert!(error.message.contains("authority snapshots"));
}

#[tokio::test]
async fn replay_rejects_second_root_after_prepared_observed_or_accepted() {
    let fixture = fixture();
    let proposal = initial_proposal(&fixture);
    let prepared_seen = Arc::new(AtomicBool::new(false));
    let backend = OrderingBackend::new(Arc::clone(&prepared_seen), response(&proposal));
    let journal = OrderingJournal {
        inner: InMemoryPlannerJournal::default(),
        prepared_seen,
    };
    PlannerExecutor::new(&backend, &journal)
        .execute(PlannerExecutionRequest::new(
            inference_request(),
            fixture.base,
            fixture.catalog,
            fixture.context,
            fixture.policy,
        ))
        .await
        .expect("accepted execution");
    let records = journal.inner.snapshot().unwrap();
    let PlannerJournalRecord::Prepared(first) = &records[0] else {
        panic!("preparation");
    };
    let mut second = first.clone();
    second.attempt_id = PlannerAttemptId::new();
    second.budget_reservation_id = BudgetReservationId::new();
    second.parent_attempt_id = None;

    for prefix_len in [1, 2, 3] {
        let mut candidate = records[..prefix_len].to_vec();
        candidate.push(PlannerJournalRecord::Prepared(second.clone()));
        let error = PlannerJournalProjection::replay(&candidate)
            .expect_err("one execution may never gain a second root attempt");
        assert!(error.message.contains("exactly one root"));
    }
}

struct RejectPreparationJournal;

impl PlannerJournal for RejectPreparationJournal {
    fn retain(&self, record: &PlannerJournalRecord) -> Result<(), PlannerJournalError> {
        if matches!(record, PlannerJournalRecord::Prepared(_)) {
            Err(PlannerJournalError::new("budget reservation failed"))
        } else {
            panic!("no later transition is legal")
        }
    }
}

#[tokio::test]
async fn rejected_preparation_prevents_backend_call() {
    let fixture = fixture();
    let proposal = initial_proposal(&fixture);
    let prepared_seen = Arc::new(AtomicBool::new(false));
    let backend = OrderingBackend::new(prepared_seen, response(&proposal));

    let error = PlannerExecutor::new(&backend, &RejectPreparationJournal)
        .execute(PlannerExecutionRequest::new(
            inference_request(),
            fixture.base,
            fixture.catalog,
            fixture.context,
            fixture.policy,
        ))
        .await
        .expect_err("preparation rejection must stop inference");

    assert!(matches!(
        error,
        PlannerExecutionError::PreparationUnacknowledged { .. }
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

struct DropObservationJournal {
    records: Mutex<Vec<PlannerJournalRecord>>,
    prepared_seen: Arc<AtomicBool>,
}

impl PlannerJournal for DropObservationJournal {
    fn retain(&self, record: &PlannerJournalRecord) -> Result<(), PlannerJournalError> {
        match record {
            PlannerJournalRecord::Prepared(_) => {
                self.records.lock().unwrap().push(record.clone());
                self.prepared_seen.store(true, Ordering::SeqCst);
                Ok(())
            }
            PlannerJournalRecord::Observed(_) => Err(PlannerJournalError::new(
                "simulated crash before observation commit",
            )),
            PlannerJournalRecord::Accepted(_) | PlannerJournalRecord::Rejected(_) => {
                panic!("decision cannot follow an unacknowledged observation")
            }
        }
    }
}

#[tokio::test]
async fn unobserved_preparation_replays_as_reconciliation_required() {
    let fixture = fixture();
    let proposal = initial_proposal(&fixture);
    let prepared_seen = Arc::new(AtomicBool::new(false));
    let backend = OrderingBackend::new(Arc::clone(&prepared_seen), response(&proposal));
    let journal = DropObservationJournal {
        records: Mutex::new(Vec::new()),
        prepared_seen,
    };

    let error = PlannerExecutor::new(&backend, &journal)
        .execute(PlannerExecutionRequest::new(
            inference_request(),
            fixture.base,
            fixture.catalog,
            fixture.context,
            fixture.policy,
        ))
        .await
        .expect_err("lost observation must require reconciliation");
    assert!(matches!(
        error,
        PlannerExecutionError::ObservationUnacknowledged { .. }
    ));
    let records = journal.records.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    let projection = PlannerJournalProjection::replay(&records).unwrap();
    assert!(matches!(
        projection.attempts.values().next(),
        Some(PlannerAttemptProjection::ReconciliationRequired { .. })
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn replay_rejects_reused_budget_reservation_and_unauthorized_retry_parent() {
    let fixture = fixture();
    let request = inference_request();
    let first = PlannerAttemptPrepared {
        execution_id: PlannerExecutionId::new(),
        attempt_id: PlannerAttemptId::new(),
        parent_attempt_id: None,
        budget_reservation_id: BudgetReservationId::new(),
        backend_id: backend_id(),
        model_id: model_id(),
        max_output_tokens: request.max_output_tokens(),
        base_plan_sha256: fixture.base.sha256().unwrap(),
        obligation_snapshot_sha256: fixture.catalog.snapshot_sha256().clone(),
        acceptance_policy_sha256: fixture.catalog.acceptance_policy_sha256().clone(),
        context_manifest_sha256: fixture.context.manifest_sha256().clone(),
        planner_policy_sha256: fixture.policy.policy_sha256().clone(),
        request_sha256: PlannerDigest::of_bytes(&serde_json::to_vec(&request).unwrap()),
        request: request.clone(),
        base_plan: Box::new(fixture.base.clone()),
        obligations: Box::new(fixture.catalog.clone()),
        context: Box::new(fixture.context.clone()),
        policy: Box::new(fixture.policy.clone()),
    };
    let mut reused = first.clone();
    reused.attempt_id = PlannerAttemptId::new();
    let error = PlannerJournalProjection::replay(&[
        PlannerJournalRecord::Prepared(first.clone()),
        PlannerJournalRecord::Prepared(reused),
    ])
    .expect_err("one reservation cannot fund two attempts");
    assert!(error.message.contains("reservation"));

    let mut wrong_parent = first.clone();
    wrong_parent.attempt_id = PlannerAttemptId::new();
    wrong_parent.parent_attempt_id = Some(first.attempt_id);
    wrong_parent.execution_id = PlannerExecutionId::new();
    wrong_parent.budget_reservation_id = BudgetReservationId::new();
    let error = PlannerJournalProjection::replay(&[
        PlannerJournalRecord::Prepared(first),
        PlannerJournalRecord::Prepared(wrong_parent),
    ])
    .expect_err("parent links are not retry authority");
    assert!(error.message.contains("retry authorization"));
}
