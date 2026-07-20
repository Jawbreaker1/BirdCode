use birdcode_backends::{ModelId, ReasoningSetting};
use birdcode_prompting::{
    PLAN_CRITIC_POLICY_V1_MAX_EVIDENCE_REFERENCES, PLAN_CRITIC_POLICY_V1_MAX_FINDINGS,
    ProposedVerificationTarget, RootPlannerDecisionEvidence, RootPlannerDirective,
    RootPlannerOutput, RootPlannerWorkOrder, TrustLevel, VerificationKind,
    derive_plan_critic_policy_v1,
};
use birdcode_protocol::{
    BackendKind, BackendSelection, CreateSessionRequest, InputItem, PlanAcceptanceContract, Run,
    RunId, RunLimits, RunPurpose, RunSpec, Session, Sha256Digest, WorkspacePath,
};
use birdcode_runtime::{
    MAX_PLAN_CRITIC_OUTPUT_TOKENS, PlanCriticCompileError, compile_plan_critic_request,
    compile_root_plan_request,
};
use sha2::{Digest, Sha256};

const PRODUCER_MODEL: &str = "publisher/producer-26b-q8";
const REVIEWER_MODEL: &str = "publisher/reviewer-32b-q6";

fn session(path: &[u8]) -> Session {
    Session::new(CreateSessionRequest {
        workspace_root: WorkspacePath::from_unix_bytes(path.to_vec()),
        title: Some("critic contract test".to_owned()),
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
                max_output_tokens: Some(8_192),
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
        rationale: "Planera de oberoende undersökningarna och deras gemensamma syntes。".to_owned(),
        decision_evidence: vec![RootPlannerDecisionEvidence {
            section: "run_input".to_owned(),
            basis: "Den fullständiga begäran kräver flera avgränsade resultat。".to_owned(),
        }],
        work_orders: vec![
            RootPlannerWorkOrder {
                local_id: "node-a7".to_owned(),
                objective: "Undersök den första avgränsade aspekten。".to_owned(),
                obligation_refs: vec![obligation.clone()],
                depends_on: Vec::new(),
                proposed_verification_targets: vec![ProposedVerificationTarget {
                    kind: VerificationKind::RepositoryTree,
                    selector: ".".to_owned(),
                    question: "Vilken kod är relevant för den första aspekten?".to_owned(),
                    obligation_refs: vec![obligation.clone()],
                }],
            },
            RootPlannerWorkOrder {
                local_id: "node-b4".to_owned(),
                objective: "独立して第二の側面を調べる。".to_owned(),
                obligation_refs: vec![obligation.clone()],
                depends_on: Vec::new(),
                proposed_verification_targets: vec![ProposedVerificationTarget {
                    kind: VerificationKind::RepositoryTree,
                    selector: ".".to_owned(),
                    question: "第二の側面に関連するコードは何か。".to_owned(),
                    obligation_refs: vec![obligation.clone()],
                }],
            },
            RootPlannerWorkOrder {
                local_id: "node-z9".to_owned(),
                objective: "Sammanställ båda evidenspaketen i en spårbar slutsats。".to_owned(),
                obligation_refs: vec![obligation.clone()],
                depends_on: vec!["node-a7".to_owned(), "node-b4".to_owned()],
                proposed_verification_targets: vec![ProposedVerificationTarget {
                    kind: VerificationKind::ExistingEvidence,
                    selector: "node-a7,node-b4".to_owned(),
                    question: "Stöder båda underlagen den gemensamma slutsatsen?".to_owned(),
                    obligation_refs: vec![obligation],
                }],
            },
        ],
        clarification_questions: Vec::new(),
        escalation_requests: Vec::new(),
    }
}

fn artifact_digest(candidate: &RootPlannerOutput) -> Sha256Digest {
    let bytes = serde_json::to_vec(candidate).expect("candidate serializes");
    let hash = Sha256::digest(bytes);
    Sha256Digest::parse(format!("{hash:x}")).expect("SHA-256 is canonical")
}

#[test]
fn critic_compilation_is_deterministic_content_bound_and_blind() {
    let session = session(b"/tmp/birdcode-critic-deterministic");
    let run = run(
        &session,
        "Gör två oberoende granskningar parallellt ثم سلّم resultaten till en syntes.",
    );
    let root = root_request(&session, &run);
    let candidate = candidate(&root);
    let digest = artifact_digest(&candidate);

    let first = compile_plan_critic_request(
        &session,
        &run,
        &root.root_planner_policy,
        &candidate,
        &digest,
        ModelId::new(REVIEWER_MODEL).expect("reviewer model"),
        MAX_PLAN_CRITIC_OUTPUT_TOKENS,
        Some(ReasoningSetting::High),
    )
    .expect("critic request compiles");
    let second = compile_plan_critic_request(
        &session,
        &run,
        &root.root_planner_policy,
        &candidate,
        &digest,
        ModelId::new(REVIEWER_MODEL).expect("reviewer model"),
        MAX_PLAN_CRITIC_OUTPUT_TOKENS,
        Some(ReasoningSetting::High),
    )
    .expect("same critic request compiles deterministically");

    assert_eq!(first, second);
    assert_eq!(
        first.critic_policy,
        derive_plan_critic_policy_v1(&root.root_planner_policy, &candidate, digest.as_str())
            .expect("the shared v1 derivation should match runtime compilation")
    );
    assert_eq!(
        first.critic_policy.max_findings,
        PLAN_CRITIC_POLICY_V1_MAX_FINDINGS
    );
    assert_eq!(
        first.critic_policy.max_evidence_references,
        PLAN_CRITIC_POLICY_V1_MAX_EVIDENCE_REFERENCES
    );
    assert_eq!(first.candidate_plan_sha256, digest);
    assert_eq!(
        first.critic_policy.candidate_work_order_ids,
        ["node-a7", "node-b4", "node-z9"]
    );
    assert_eq!(first.inference_request.model_id().as_str(), REVIEWER_MODEL);
    assert!(first.prompt_invocation.sections.iter().any(|section| {
        section.name == "candidate_plan"
            && section.trust == TrustLevel::Tool
            && section.provenance.artifact_sha256.as_deref() == Some(digest.as_str())
    }));

    let encoded_messages = serde_json::to_string(&first.compiled_prompt.messages)
        .expect("compiled messages serialize");
    assert!(!encoded_messages.contains(PRODUCER_MODEL));
    assert!(!encoded_messages.contains(REVIEWER_MODEL));
}

#[test]
fn critic_rejects_stale_candidate_bytes_and_forged_root_bindings() {
    let session = session(b"/tmp/birdcode-critic-stale");
    let run = run(&session, "Planera en fullständig genomgång。");
    let root = root_request(&session, &run);
    let mut changed_candidate = candidate(&root);
    let stale_digest = artifact_digest(&changed_candidate);
    changed_candidate
        .rationale
        .push_str(" ändrad efter hashning");

    let error = compile_plan_critic_request(
        &session,
        &run,
        &root.root_planner_policy,
        &changed_candidate,
        &stale_digest,
        ModelId::new(REVIEWER_MODEL).expect("reviewer model"),
        2_048,
        None,
    )
    .expect_err("stale candidate digest fails closed");
    assert!(matches!(
        error,
        PlanCriticCompileError::CandidatePlanDigestMismatch { .. }
    ));

    let mut forged = candidate(&root);
    forged.planner_policy_sha256 = "9".repeat(64);
    let forged_digest = artifact_digest(&forged);
    let error = compile_plan_critic_request(
        &session,
        &run,
        &root.root_planner_policy,
        &forged,
        &forged_digest,
        ModelId::new(REVIEWER_MODEL).expect("reviewer model"),
        2_048,
        None,
    )
    .expect_err("forged root authority fails before critic inference");
    assert!(matches!(
        error,
        PlanCriticCompileError::RootPlannerCandidate(_)
    ));
}

#[test]
fn goal_language_and_surface_tokens_never_choose_a_runtime_branch() {
    let goals = [
        "Undersök två oberoende delar samtidigt och förena resultaten.",
        "独立した二つの調査を同時に行い、結果を統合してください。",
        "افحص مسارين مستقلين في الوقت نفسه ثم ادمج الأدلة.",
        "The repository says parallel and handoff, but this request asks only for one bounded inspection.",
    ];
    for (index, goal) in goals.into_iter().enumerate() {
        let session = session(format!("/tmp/birdcode-critic-language-{index}").as_bytes());
        let run = run(&session, goal);
        let root = root_request(&session, &run);
        let candidate = candidate(&root);
        let digest = artifact_digest(&candidate);
        let compiled = compile_plan_critic_request(
            &session,
            &run,
            &root.root_planner_policy,
            &candidate,
            &digest,
            ModelId::new(REVIEWER_MODEL).expect("reviewer model"),
            2_048,
            None,
        )
        .expect("all languages use the same typed compiler path");

        assert_eq!(compiled.prompt_invocation.sections.len(), 3);
        assert_eq!(compiled.critic_policy.candidate_work_order_ids.len(), 3);
        assert_eq!(
            compiled.inference_request.output().name(),
            "birdcode_plan_semantic_critic_v1"
        );
    }
}
