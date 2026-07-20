use birdcode_backends::{ModelId, ReasoningSetting};
use birdcode_prompting::{
    ObligationAssessment, ObligationAssessmentStatus, PlanCriticFinding, PlanCriticFindingCategory,
    PlanCriticFindingSeverity, PlanCriticOutput, PlanCriticVerdict, ProposedVerificationTarget,
    RootPlannerDecisionEvidence, RootPlannerDirective, RootPlannerOutput, RootPlannerWorkOrder,
    TrustLevel, VerificationKind, builtin_registry,
};
use birdcode_protocol::{
    BackendKind, BackendSelection, CreateSessionRequest, EventId, InputItem,
    PlanAcceptanceContract, Run, RunId, RunLimits, RunPurpose, RunSpec, Session, Sha256Digest,
    WorkspacePath,
};
use birdcode_runtime::{
    MAX_PLAN_REPAIR_OUTPUT_TOKENS, PlanRepairCompileError, compile_plan_critic_request,
    compile_plan_repair_request, compile_root_plan_request,
};
use sha2::{Digest, Sha256};

const PRODUCER_MODEL: &str = "publisher/producer-26b-q8";
const REVIEWER_MODEL: &str = "publisher/reviewer-32b-q6";

fn session(path: &[u8]) -> Session {
    Session::new(CreateSessionRequest {
        workspace_root: WorkspacePath::from_unix_bytes(path.to_vec()),
        title: Some("repair contract test".to_owned()),
    })
}

fn run(session: &Session, goal: &str) -> Run {
    Run::with_id(
        RunId::new(),
        RunSpec {
            session_id: session.id,
            purpose: RunPurpose::PlanOnly,
            plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
            backend: BackendSelection {
                backend_id: "lmstudio".to_owned(),
                kind: BackendKind::Model,
                model: Some(PRODUCER_MODEL.to_owned()),
                reasoning_effort: Some("high".to_owned()),
            },
            input: vec![InputItem::Text {
                text: goal.to_owned(),
            }],
            limits: RunLimits {
                max_output_tokens: Some(32_768),
                max_wall_time_seconds: Some(300),
                max_subagents: 0,
            },
        },
    )
}

fn root_request(session: &Session, run: &Run) -> birdcode_runtime::CompiledRootPlanRequest {
    compile_root_plan_request(
        session,
        run,
        ModelId::new(PRODUCER_MODEL).expect("producer model"),
        4_096,
        Some(ReasoningSetting::High),
    )
    .expect("root request compiles")
}

fn candidate(root: &birdcode_runtime::CompiledRootPlanRequest) -> RootPlannerOutput {
    let obligation = root.root_planner_policy.obligations[0].reference();
    RootPlannerOutput {
        schema_version: 1,
        root_snapshot_sha256: root.root_planner_policy.root_snapshot_sha256.clone(),
        planner_policy_sha256: root.root_planner_policy.planner_policy_sha256.clone(),
        context_manifest_sha256: root.root_planner_policy.context_manifest_sha256.clone(),
        directive: RootPlannerDirective::Plan,
        rationale: "Bevara uppgiften och gör en fullständig plan。".to_owned(),
        decision_evidence: vec![RootPlannerDecisionEvidence {
            section: "run_input".to_owned(),
            basis: "Den fullständiga användarbegäran styr planens mål。".to_owned(),
        }],
        work_orders: vec![RootPlannerWorkOrder {
            local_id: "node-original".to_owned(),
            objective: "Undersök hela uppgiften i en verifierbar följd。".to_owned(),
            obligation_refs: vec![obligation.clone()],
            depends_on: Vec::new(),
            proposed_verification_targets: vec![ProposedVerificationTarget {
                kind: VerificationKind::RepositoryTree,
                selector: ".".to_owned(),
                question: "Vilka delar av kodbasen berörs?".to_owned(),
                obligation_refs: vec![obligation],
            }],
        }],
        clarification_questions: Vec::new(),
        escalation_requests: Vec::new(),
    }
}

fn digest<T: serde::Serialize>(value: &T) -> Sha256Digest {
    let bytes = serde_json::to_vec(value).expect("fixture serializes");
    let hash = Sha256::digest(bytes);
    Sha256Digest::parse(format!("{hash:x}")).expect("SHA-256 is canonical")
}

fn critique(
    critic: &birdcode_runtime::CompiledPlanCriticRequest,
    candidate: &RootPlannerOutput,
) -> PlanCriticOutput {
    let obligation = critic.critic_policy.obligations[0].reference();
    PlanCriticOutput {
        schema_version: 1,
        bindings: critic.critic_policy.bindings(),
        verdict: PlanCriticVerdict::Revise,
        summary: "Planen behöver en explicit oberoende granskning och syntes。".to_owned(),
        obligation_assessments: vec![ObligationAssessment {
            obligation_ref: obligation,
            status: ObligationAssessmentStatus::Partial,
            basis: "Målet finns men uppdelning och slutlig syntes saknas。".to_owned(),
            affected_work_order_ids: vec![candidate.work_orders[0].local_id.clone()],
        }],
        findings: vec![PlanCriticFinding {
            finding_id: "finding-independent-synthesis".to_owned(),
            severity: PlanCriticFindingSeverity::Major,
            category: PlanCriticFindingCategory::IndependentReview,
            statement: "Kandidaten saknar oberoende granskning före syntes。".to_owned(),
            source_sections: vec!["run_input".to_owned(), "candidate_plan".to_owned()],
            affected_work_order_ids: vec![candidate.work_orders[0].local_id.clone()],
            required_change: "Skapa separata gransknings- och syntesnoder med korrekt beroende。"
                .to_owned(),
        }],
        clarification_questions: Vec::new(),
        escalation_requests: Vec::new(),
        decision_evidence: vec![RootPlannerDecisionEvidence {
            section: "run_input".to_owned(),
            basis: "Begäran kräver en robust, verifierbar slutplan。".to_owned(),
        }],
    }
}

fn repair_fixture(
    goal: &str,
) -> (
    Session,
    Run,
    birdcode_runtime::CompiledRootPlanRequest,
    RootPlannerOutput,
    Sha256Digest,
    birdcode_runtime::CompiledPlanCriticRequest,
    PlanCriticOutput,
    Sha256Digest,
) {
    let session = session(goal.as_bytes());
    let run = run(&session, goal);
    let root = root_request(&session, &run);
    let candidate = candidate(&root);
    let candidate_digest = digest(&candidate);
    let critic = compile_plan_critic_request(
        &session,
        &run,
        &root.root_planner_policy,
        &candidate,
        &candidate_digest,
        ModelId::new(REVIEWER_MODEL).expect("reviewer model"),
        2_048,
        None,
    )
    .expect("critic request compiles");
    let critique = critique(&critic, &candidate);
    let critique_digest = digest(&critique);
    (
        session,
        run,
        root,
        candidate,
        candidate_digest,
        critic,
        critique,
        critique_digest,
    )
}

#[test]
fn repair_compilation_is_deterministic_exactly_bound_and_non_authoritative() {
    let (session, run, root, candidate, candidate_digest, critic, critique, critique_digest) =
        repair_fixture("Gör två oberoende granskningar ثم syntetisera resultaten。");
    let review_event_id = EventId::new();
    let finding_ids = vec!["finding-independent-synthesis".to_owned()];
    let compile = || {
        compile_plan_repair_request(
            &session,
            &run,
            &root.root_planner_policy,
            &candidate,
            &candidate_digest,
            &critic.critic_policy,
            &critique,
            &critique_digest,
            review_event_id,
            &finding_ids,
            ModelId::new(PRODUCER_MODEL).expect("producer model"),
            MAX_PLAN_REPAIR_OUTPUT_TOKENS,
            Some(ReasoningSetting::High),
        )
        .expect("repair request compiles")
    };
    let first = compile();
    let second = compile();

    assert_eq!(first, second);
    assert_eq!(first.candidate_plan_sha256, candidate_digest);
    assert_eq!(first.critique_sha256, critique_digest);
    assert_eq!(first.triggering_review_event_id, review_event_id);
    assert_eq!(first.required_finding_ids, finding_ids);
    assert_eq!(first.prompt_invocation.sections.len(), 5);
    assert_eq!(first.inference_request.model_id().as_str(), PRODUCER_MODEL);
    assert!(first.prompt_invocation.sections.iter().any(|section| {
        section.name == "committed_critique"
            && section.trust == TrustLevel::Tool
            && section.provenance.artifact_sha256.as_deref() == Some(critique_digest.as_str())
            && section.provenance.event_id.as_deref() == Some(review_event_id.to_string().as_str())
    }));

    let registry = builtin_registry().expect("bundled registry");
    let replacement = serde_json::to_vec(&candidate).expect("replacement serializes");
    registry
        .decode_output::<RootPlannerOutput>(
            &first.compiled_prompt,
            &first.prompt_invocation,
            &replacement,
        )
        .expect("complete replacement remains a valid root plan");
}

#[test]
fn repair_rejects_stale_critique_non_revise_and_altered_finding_selection() {
    let (session, run, root, candidate, candidate_digest, critic, mut critique, stale_digest) =
        repair_fixture("Planera en säker fullständig förändring。");
    critique.summary.push_str(" ändrad efter commit");
    let error = compile_plan_repair_request(
        &session,
        &run,
        &root.root_planner_policy,
        &candidate,
        &candidate_digest,
        &critic.critic_policy,
        &critique,
        &stale_digest,
        EventId::new(),
        &["finding-independent-synthesis".to_owned()],
        ModelId::new(PRODUCER_MODEL).expect("producer model"),
        4_096,
        None,
    )
    .expect_err("stale critique bytes fail closed");
    assert!(matches!(
        error,
        PlanRepairCompileError::CritiqueDigestMismatch { .. }
    ));

    critique.summary = "Planen behöver en explicit oberoende granskning och syntes。".to_owned();
    let current_digest = digest(&critique);
    let error = compile_plan_repair_request(
        &session,
        &run,
        &root.root_planner_policy,
        &candidate,
        &candidate_digest,
        &critic.critic_policy,
        &critique,
        &current_digest,
        EventId::new(),
        &["annan-finding".to_owned()],
        ModelId::new(PRODUCER_MODEL).expect("producer model"),
        4_096,
        None,
    )
    .expect_err("runtime cannot select a different finding set");
    assert!(matches!(
        error,
        PlanRepairCompileError::RequiredFindingIdsMismatch { .. }
    ));

    critique.verdict = PlanCriticVerdict::Accept;
    critique.obligation_assessments[0].status = ObligationAssessmentStatus::Addressed;
    critique.findings.clear();
    let accept_digest = digest(&critique);
    let error = compile_plan_repair_request(
        &session,
        &run,
        &root.root_planner_policy,
        &candidate,
        &candidate_digest,
        &critic.critic_policy,
        &critique,
        &accept_digest,
        EventId::new(),
        &[],
        ModelId::new(PRODUCER_MODEL).expect("producer model"),
        4_096,
        None,
    )
    .expect_err("accept cannot be converted into repair authority");
    assert!(matches!(
        error,
        PlanRepairCompileError::CriticVerdictNotRevisable { .. }
    ));
}

#[test]
fn repair_output_cannot_promote_critique_or_candidate_into_plan_evidence() {
    let (session, run, root, mut candidate, candidate_digest, critic, critique, critique_digest) =
        repair_fixture("افحص المسارات المستقلة ثم أصلح الخطة دون توسيع السلطة。");
    let compiled = compile_plan_repair_request(
        &session,
        &run,
        &root.root_planner_policy,
        &candidate,
        &candidate_digest,
        &critic.critic_policy,
        &critique,
        &critique_digest,
        EventId::new(),
        &["finding-independent-synthesis".to_owned()],
        ModelId::new(PRODUCER_MODEL).expect("producer model"),
        4_096,
        None,
    )
    .expect("repair request compiles");
    candidate.decision_evidence[0].section = "committed_critique".to_owned();
    let bytes = serde_json::to_vec(&candidate).expect("invalid replacement serializes");
    let error = builtin_registry()
        .expect("registry")
        .decode_output::<RootPlannerOutput>(
            &compiled.compiled_prompt,
            &compiled.prompt_invocation,
            &bytes,
        )
        .expect_err("repair data cannot become replacement-plan authority");
    assert!(error.to_string().contains("root-planner invariants"));
}
