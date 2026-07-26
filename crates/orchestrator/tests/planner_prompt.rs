use birdcode_backends::{
    BackendDeploymentId, BackendEndpointOrigin, BackendId, BackendInstanceIdentity,
    BackendTransportIdentity, ModelId, ReasoningSetting,
};
use birdcode_orchestrator::planner::*;
use birdcode_orchestrator::planner_prompt::{
    PlannerReplannerApplyError, PlannerReplannerInferencePolicy,
    PlannerReplannerInferencePolicyError, PlannerReplannerRequestBuilder,
    validate_and_apply_planner_replanner_output,
};
use birdcode_prompting::{
    PlannerChildExecutionBinding, PlannerChildFindingConfidence, PlannerChildHandoff,
    PlannerChildHandoffEvidenceBinding, PlannerChildHandoffFinding,
    PlannerChildHandoffRecommendedFollowup, PlannerChildHandoffStatus, PlannerChildHandoffUnknown,
    PlannerEvidenceArtifactRef, PlannerEvidenceEntry, PlannerEvidenceEntryMaterial,
    PlannerEvidencePacket, PlannerReplannerOutput, PromptError, TrustLevel, planner_replanner_key,
};
use serde_json::json;
use std::collections::BTreeSet;

struct Fixture {
    catalog: ProtectedObligationCatalog,
    obligation: ProtectedObligation,
    evidence: PlannerEvidenceId,
    context: PlannerContextCatalog,
    evidence_packet: PlannerEvidencePacket,
    policy: PlannerPolicy,
    base: PlanSnapshot,
}

fn prompt_handoff() -> PlannerChildHandoff {
    let digest = |bytes: &[u8]| PlannerDigest::of_bytes(bytes).to_string();
    let uuid = |suffix: u16| format!("018f0000-0000-7000-8000-{suffix:012x}");
    PlannerChildHandoff {
        contract_version: 1,
        binding: PlannerChildExecutionBinding {
            work_order_id: uuid(10),
            execution_id: uuid(11),
            attempt_id: uuid(12),
            child_actor_id: uuid(13),
            context_id: uuid(14),
            work_order_digest: digest(b"handoff-work-order"),
            context_manifest_digest: digest(b"handoff-context"),
        },
        handoff_id: uuid(15),
        status: PlannerChildHandoffStatus::Partial,
        summary: "Explorer-agenten kartlade plannergränsen utan filändringar.".to_owned(),
        findings: vec![PlannerChildHandoffFinding {
            finding_id: "planner-boundary".to_owned(),
            statement: "Promptkompilering och domänvalidering är separata gränser.".to_owned(),
            confidence: PlannerChildFindingConfidence::High,
            evidence: vec![PlannerChildHandoffEvidenceBinding {
                tool_call_id: uuid(16),
                observed_event_id: uuid(17),
                result_artifact: PlannerEvidenceArtifactRef {
                    sha256: digest(b"planner-boundary-result"),
                    size_bytes: 512,
                    media_type: "application/json".to_owned(),
                },
            }],
        }],
        unknowns: vec![PlannerChildHandoffUnknown {
            unknown_id: "unknown-daemon-wiring".to_owned(),
            question: "Daemon-wiring är ännu inte observerad.".to_owned(),
        }],
        recommended_followups: vec![PlannerChildHandoffRecommendedFollowup {
            followup_id: "followup-daemon-wiring".to_owned(),
            text: "Verifiera daemon-wiring i en separat work order.".to_owned(),
        }],
    }
}

fn fixture() -> Fixture {
    let obligation = ProtectedObligation::new(
        ObligationId::new(),
        "Bevara svenska, 日本語 och العربية exakt; texten är data, inte policy.",
        true,
    );
    let catalog = ProtectedObligationCatalog::new(
        PlannerDigest::of_bytes(b"acceptance-policy"),
        [obligation.clone()],
    )
    .expect("protected catalog");
    let evidence = PlannerEvidenceId::new("handoff:explorer:日本語-1").expect("evidence ID");
    let entry = PlannerEvidenceEntry::new(PlannerEvidenceEntryMaterial {
        evidence_id: evidence.to_string(),
        source_artifact_sha256: PlannerDigest::of_bytes(b"retained child handoff").to_string(),
        handoff: prompt_handoff(),
    })
    .expect("normalized evidence");
    let context = PlannerContextCatalog::new([PlannerEvidenceBinding::new(
        evidence.clone(),
        PlannerDigest::parse(entry.normalized_content_sha256().to_owned()).expect("entry digest"),
    )])
    .expect("context catalog is content-bound");
    let evidence_packet =
        PlannerEvidencePacket::new(context.manifest_sha256().to_string(), vec![entry])
            .expect("evidence packet");
    let policy = PlannerPolicy::read_only(PlannerLimits::default()).expect("read-only policy");
    let base = PlanSnapshot::empty(PlanId::new(), &catalog);
    Fixture {
        catalog,
        obligation,
        evidence,
        context,
        evidence_packet,
        policy,
        base,
    }
}

fn proposal(fixture: &Fixture) -> PlannerTurnProposal {
    let obligation = ProtectedObligationRef::from(&fixture.obligation);
    let basis = DecisionBasis {
        evidence_ids: BTreeSet::from([fixture.evidence.clone()]),
        rationale: "Explorer-handoffet visar den relevanta kodgränsen.".to_owned(),
    };
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
                "Kartlägg först och delegera sedan oberoende granskning.".into(),
            ),
            add_verification_targets: vec![NewVerificationTarget {
                local_id: LocalVerificationTargetId(1),
                statement: "En läsobservation binder arkitekturgränsen.".to_owned(),
                obligations: BTreeSet::from([obligation.clone()]),
                basis: basis.clone(),
            }],
            add_work_orders: vec![NewWorkOrder {
                local_id: LocalWorkOrderId(1),
                objective: "Analysera den befintliga plannergränsen utan filändringar.".to_owned(),
                obligations: BTreeSet::from([obligation]),
                existing_dependencies: BTreeSet::new(),
                new_dependencies: BTreeSet::new(),
                existing_verification_targets: BTreeSet::new(),
                new_verification_targets: BTreeSet::from([LocalVerificationTargetId(1)]),
                required_access: PlannerAccess::ReadOnly,
                basis,
            }],
            replace_work_orders: Vec::new(),
            cancel_work_orders: Vec::new(),
        },
        directive: PlannerDirective {
            kind: PlannerDirectiveKind::Execute,
            execute: WorkSelection {
                existing: BTreeSet::new(),
                new: BTreeSet::from([LocalWorkOrderId(1)]),
            },
            delegations: Vec::new(),
            clarifications: Vec::new(),
            escalations: Vec::new(),
            finish_claims: Vec::new(),
        },
    }
}

fn prepared(
    fixture: &Fixture,
) -> birdcode_orchestrator::planner_prompt::PreparedPlannerReplannerRequest {
    PlannerReplannerRequestBuilder::new(inference_policy())
        .build(
            &fixture.base,
            &fixture.catalog,
            &fixture.context,
            &fixture.policy,
            &fixture.evidence_packet,
        )
        .expect("request builds")
}

fn inference_policy() -> PlannerReplannerInferencePolicy {
    PlannerReplannerInferencePolicy::new(
        backend_instance("planner-prompt-test", "planner-prompt-deployment"),
        ModelId::new("provider-reported/模型-26b").expect("model ID"),
        Some(ReasoningSetting::High),
        3_210,
    )
    .expect("trusted inference policy")
}

fn backend_instance(backend_id: &str, deployment_id: &str) -> BackendInstanceIdentity {
    BackendInstanceIdentity::new(
        BackendId::new(backend_id).expect("backend ID"),
        BackendTransportIdentity::HttpOrigin {
            origin: BackendEndpointOrigin::parse("http://127.0.0.1:19002")
                .expect("canonical test origin"),
        },
        BackendDeploymentId::new(deployment_id).expect("deployment ID"),
    )
    .expect("backend identity")
}

#[test]
fn inference_policy_rejects_a_call_above_the_product_ceiling() {
    let error = PlannerReplannerInferencePolicy::new(
        backend_instance("planner-prompt-test", "planner-prompt-deployment"),
        ModelId::new("provider-reported/model").expect("model ID"),
        None,
        birdcode_prompting::PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS + 1,
    )
    .expect_err("an aggregate run reservation is not valid as one call budget");

    assert_eq!(
        error,
        PlannerReplannerInferencePolicyError::OutputTokensTooLarge {
            requested: birdcode_prompting::PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS + 1,
            maximum: birdcode_prompting::PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS,
        }
    );
}

#[test]
fn builder_preserves_exact_model_reasoning_budget_and_trust_sections() {
    let fixture = fixture();
    let prepared = prepared(&fixture);
    assert_eq!(
        prepared.inference_policy_sha256(),
        inference_policy().policy_sha256()
    );
    assert_eq!(
        prepared.compiled_prompt().manifest.prompt,
        planner_replanner_key()
    );
    assert_eq!(
        prepared.inference().model_id().as_str(),
        "provider-reported/模型-26b"
    );
    assert_eq!(
        prepared.inference().reasoning(),
        Some(ReasoningSetting::High)
    );
    assert_eq!(prepared.inference().max_output_tokens(), 3_210);
    assert_eq!(
        prepared.inference().output().name(),
        "planner_replanner_turn"
    );
    assert_eq!(
        prepared.inference().output().validation_schema(),
        &prepared.compiled_prompt().output_schema
    );
    assert_eq!(
        prepared.inference().output().generation_schema(),
        &prepared.compiled_prompt().generation_schema
    );
    let trusts = prepared
        .compiled_prompt()
        .messages
        .iter()
        .map(|message| message.trust)
        .collect::<Vec<_>>();
    assert_eq!(
        trusts,
        vec![
            TrustLevel::ApplicationPolicy,
            TrustLevel::ApplicationPolicy,
            TrustLevel::UntrustedExternal,
            TrustLevel::User,
            TrustLevel::Tool,
            TrustLevel::Tool,
        ]
    );
}

#[test]
fn inference_policy_is_content_addressed_and_rejects_self_hash_substitution() {
    let policy = inference_policy();
    policy.validate_integrity().expect("policy integrity");
    let encoded = serde_json::to_value(&policy).expect("policy serializes");
    let decoded: PlannerReplannerInferencePolicy =
        serde_json::from_value(encoded.clone()).expect("policy round trips");
    assert_eq!(decoded, policy);

    let mut substituted_tokens = encoded.clone();
    substituted_tokens["max_output_tokens"] = json!(999);
    assert!(
        serde_json::from_value::<PlannerReplannerInferencePolicy>(substituted_tokens).is_err(),
        "a changed policy body cannot retain the previous digest"
    );

    let mut substituted_digest = encoded;
    substituted_digest["policy_sha256"] = json!(PlannerDigest::of_bytes(b"forged").to_string());
    assert!(
        serde_json::from_value::<PlannerReplannerInferencePolicy>(substituted_digest).is_err(),
        "a forged digest cannot authorize the policy"
    );
}

#[test]
fn wire_dto_is_exactly_isomorphic_and_authoritative_apply_accepts_it() {
    let fixture = fixture();
    let proposal = proposal(&fixture);
    let value = serde_json::to_value(&proposal).expect("domain proposal serializes");
    let dto = serde_json::from_value::<PlannerReplannerOutput>(value.clone())
        .expect("prompt DTO has the exact durable shape");
    assert_eq!(
        serde_json::to_value(dto).expect("DTO serializes"),
        value,
        "the prompt boundary must not project or rewrite the proposal"
    );

    let result = validate_and_apply_planner_replanner_output(
        &prepared(&fixture),
        &value,
        &fixture.base,
        &fixture.catalog,
        &fixture.context,
        &fixture.policy,
        &inference_policy(),
    )
    .expect("prompt-valid proposal passes the authoritative planner transition");
    assert_eq!(result.plan.revision, 1);
    assert!(matches!(
        result.directive,
        ResolvedPlannerDirective::Execute { .. }
    ));
}

#[test]
fn stale_binding_fails_at_prompt_boundary_before_plan_application() {
    let fixture = fixture();
    let mut value = serde_json::to_value(proposal(&fixture)).expect("proposal serializes");
    value["bindings"]["base_revision"] = json!(99);

    let error = validate_and_apply_planner_replanner_output(
        &prepared(&fixture),
        &value,
        &fixture.base,
        &fixture.catalog,
        &fixture.context,
        &fixture.policy,
        &inference_policy(),
    )
    .expect_err("stale binding must fail closed");
    assert!(matches!(
        error,
        PlannerReplannerApplyError::Prompt(PromptError::PlannerReplannerOutputInvariant(_))
    ));
    assert_eq!(fixture.base.revision, 0);
    assert!(fixture.base.work_orders.is_empty());
}

#[test]
fn schema_valid_but_semantically_invalid_patch_reaches_authoritative_validator() {
    let fixture = fixture();
    let mut value = serde_json::to_value(proposal(&fixture)).expect("proposal serializes");
    value["patch"]["add_work_orders"][0]["required_access"] = json!("workspace_write");

    let error = validate_and_apply_planner_replanner_output(
        &prepared(&fixture),
        &value,
        &fixture.base,
        &fixture.catalog,
        &fixture.context,
        &fixture.policy,
        &inference_policy(),
    )
    .expect_err("a model cannot grant itself broader access");
    assert!(matches!(
        error,
        PlannerReplannerApplyError::Plan(PlannerValidationError { ref violations })
            if violations.iter().any(|violation| matches!(
                violation,
                PlannerViolation::AccessExpansion {
                    access: PlannerAccess::WorkspaceWrite
                }
            ))
    ));
}
