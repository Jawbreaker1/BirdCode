use birdcode_backends::{
    BackendDeploymentId, BackendEndpointOrigin, BackendId, BackendInstanceIdentity,
    BackendTransportIdentity, ModelId, ReasoningSetting,
};
use birdcode_orchestrator::planner::*;
use birdcode_orchestrator::planner_prompt::PlannerReplannerInferencePolicy;
use birdcode_orchestrator::planner_prompt_v2::{
    PlannerReplannerV2ApplyError, PlannerReplannerV2BuildInput, PlannerReplannerV2RequestBuilder,
    PlannerReplannerV2SetupError, PreparedPlannerReplannerV2Request,
    decode_and_apply_planner_replanner_v2_output,
};
use birdcode_prompting::{
    PlannerAcceptedRootPlanEvidenceV2, PlannerEvidenceArtifactRef,
    PlannerReplannerClarificationRequest, PlannerReplannerDecisionBasis,
    PlannerReplannerDirectiveKind, PlannerReplannerLocalWorkOrderId, PlannerReplannerOutput,
    PlannerReplannerPlanPatch, PlannerReplannerV2Bindings, PlannerReplannerV2ContextCatalog,
    PlannerReplannerV2EvidenceDelta, PlannerReplannerV2EvidenceEntry,
    PlannerReplannerV2EvidenceMaterial, PlannerReplannerV2EvidencePacket,
    PlannerReplannerV2InvocationMaterial, PlannerReplannerV2Output, PlannerReplannerV2PlanSnapshot,
    PlannerReplannerV2Policy, PlannerReplannerV2ProtectedObligationCatalog,
    PlannerReplannerV2Purpose, PlannerReplannerV2Reasoning, ProposedVerificationTarget,
    ProtectedObligationRef as RootProtectedObligationRef, RootPlannerDecisionEvidence,
    RootPlannerDirective, RootPlannerOutput, RootPlannerWorkOrder, VerificationKind,
    builtin_registry, planner_replanner_v2_key,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const ROOT_EVIDENCE_ID: &str = "accepted-root:semantisk-plan:1";
const ACCEPTED_PLAN_MEDIA_TYPE: &str = "application/vnd.birdcode.accepted-plan+json";
const PLAN_CRITIQUE_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-critique+json";
const PLAN_VALIDATION_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-validation+json";

struct Fixture {
    input: PlannerReplannerV2BuildInput,
    output: PlannerReplannerV2Output,
}

fn uuid(suffix: u32) -> String {
    format!("018f0000-0000-7000-8000-{suffix:012x}")
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn artifact_for(value: &impl Serialize, media_type: &str) -> PlannerEvidenceArtifactRef {
    let encoded = serde_json::to_vec(value).expect("fixture artifact serializes");
    PlannerEvidenceArtifactRef {
        sha256: digest(&encoded),
        size_bytes: u64::try_from(encoded.len()).expect("artifact size fits u64"),
        media_type: media_type.to_owned(),
    }
}

fn opaque_artifact(label: &[u8], media_type: &str) -> PlannerEvidenceArtifactRef {
    PlannerEvidenceArtifactRef {
        sha256: digest(label),
        size_bytes: u64::try_from(label.len()).expect("artifact size fits u64"),
        media_type: media_type.to_owned(),
    }
}

fn root_plan() -> RootPlannerOutput {
    let root_obligation = RootProtectedObligationRef {
        obligation_id: "complete-agentic-result".to_owned(),
        obligation_sha256: digest(b"complete-agentic-result"),
    };
    RootPlannerOutput {
        schema_version: 1,
        root_snapshot_sha256: digest(b"root-snapshot"),
        planner_policy_sha256: digest(b"root-policy"),
        context_manifest_sha256: digest(b"root-context"),
        directive: RootPlannerDirective::Plan,
        rationale: "Delegera den semantiska repository-analysen till en isolerad specialist."
            .to_owned(),
        decision_evidence: vec![RootPlannerDecisionEvidence {
            section: "user_request".to_owned(),
            basis: "Användaren kräver parallella LLM-styrda agenter utan textheuristik.".to_owned(),
        }],
        work_orders: vec![RootPlannerWorkOrder {
            local_id: "repository-explorer".to_owned(),
            objective: "Kartlägg den durable agentloopen och dess verifieringsbevis.".to_owned(),
            obligation_refs: vec![root_obligation.clone()],
            depends_on: Vec::new(),
            proposed_verification_targets: vec![ProposedVerificationTarget {
                kind: VerificationKind::RepositoryTree,
                selector: ".".to_owned(),
                question: "Vilka moduler äger plan, delegation och replay?".to_owned(),
                obligation_refs: vec![root_obligation],
            }],
        }],
        clarification_questions: Vec::new(),
        escalation_requests: Vec::new(),
    }
}

fn inference_policy() -> PlannerReplannerInferencePolicy {
    inference_policy_with_reasoning(Some(ReasoningSetting::High))
}

fn inference_policy_with_reasoning(
    reasoning: Option<ReasoningSetting>,
) -> PlannerReplannerInferencePolicy {
    PlannerReplannerInferencePolicy::new(
        backend_instance(),
        ModelId::new("google/gemma-4-26b-a4b").expect("model id"),
        reasoning,
        4_096,
    )
    .expect("inference policy")
}

fn backend_instance() -> BackendInstanceIdentity {
    BackendInstanceIdentity::new(
        BackendId::new("lmstudio-local").expect("backend id"),
        BackendTransportIdentity::HttpOrigin {
            origin: BackendEndpointOrigin::parse("http://127.0.0.1:1234")
                .expect("canonical test origin"),
        },
        BackendDeploymentId::new("lmstudio-local-deployment").expect("deployment id"),
    )
    .expect("backend instance identity")
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps one complete cross-crate v2 authority graph visible in one place"
)]
fn fixture() -> Fixture {
    let obligation = ProtectedObligation::new(
        ObligationId::from_uuid(uuid::Uuid::parse_str(&uuid(1)).expect("uuid")),
        "Resultatet ska vara evidensbundet och gå att återspela exakt.",
        true,
    );
    let obligations = ProtectedObligationCatalog::new(
        PlannerDigest::of_bytes(b"acceptance-policy"),
        [obligation.clone()],
    )
    .expect("obligation catalog");
    let base = PlanSnapshot::empty(
        PlanId::from_uuid(uuid::Uuid::parse_str(&uuid(2)).expect("uuid")),
        &obligations,
    );

    let plan = root_plan();
    let plan_artifact = artifact_for(&plan, ACCEPTED_PLAN_MEDIA_TYPE);
    let root_entry = PlannerReplannerV2EvidenceEntry::new(
        PlannerReplannerV2EvidenceMaterial::AcceptedRootPlan {
            evidence_id: ROOT_EVIDENCE_ID.to_owned(),
            accepted_root_plan: PlannerAcceptedRootPlanEvidenceV2 {
                contract_version: 1,
                review_event_id: uuid(10),
                review_id: uuid(11),
                proposal_event_id: uuid(12),
                plan_revision: 0,
                plan_digest: plan_artifact.sha256.clone(),
                plan_artifact,
                critique_artifact: opaque_artifact(b"critique", PLAN_CRITIQUE_MEDIA_TYPE),
                validation_evidence_artifact: opaque_artifact(
                    b"validation",
                    PLAN_VALIDATION_MEDIA_TYPE,
                ),
                plan,
            },
        },
    )
    .expect("accepted root evidence");
    let evidence_id = PlannerEvidenceId::new(ROOT_EVIDENCE_ID).expect("evidence id");
    let evidence_digest = PlannerDigest::parse(root_entry.normalized_content_sha256().to_owned())
        .expect("evidence digest");
    let context = PlannerContextCatalog::new([PlannerEvidenceBinding::new(
        evidence_id.clone(),
        evidence_digest,
    )])
    .expect("context catalog");
    let prompt_context: PlannerReplannerV2ContextCatalog = serde_json::from_value(
        serde_json::to_value(&context).expect("context projection serializes"),
    )
    .expect("context projection is isomorphic");
    let packet = PlannerReplannerV2EvidencePacket::new(
        PlannerReplannerV2Purpose::InitialDelegation,
        prompt_context.manifest_sha256.clone(),
        vec![root_entry],
    )
    .expect("initial packet");
    let delta = PlannerReplannerV2EvidenceDelta::new(
        PlannerReplannerV2Purpose::InitialDelegation,
        &packet,
        None,
    )
    .expect("initial delta");
    let policy = PlannerPolicy::read_only(PlannerLimits::default()).expect("planner policy");
    let prompt_base: PlannerReplannerV2PlanSnapshot =
        serde_json::from_value(serde_json::to_value(&base).expect("base serializes"))
            .expect("base projection is isomorphic");
    let prompt_obligations: PlannerReplannerV2ProtectedObligationCatalog =
        serde_json::from_value(serde_json::to_value(&obligations).expect("obligations serialize"))
            .expect("obligation projection is isomorphic");
    let prompt_policy: PlannerReplannerV2Policy =
        serde_json::from_value(serde_json::to_value(&policy).expect("policy serializes"))
            .expect("policy projection is isomorphic");
    let prompt_key = planner_replanner_v2_key();
    let registry = builtin_registry().expect("prompt registry");
    let prompt_manifest_sha256 = registry
        .get(&prompt_key)
        .expect("bundled v2 manifest")
        .content_sha256()
        .expect("manifest digest");
    let bindings = PlannerReplannerV2Bindings {
        purpose: PlannerReplannerV2Purpose::InitialDelegation,
        prompt_id: prompt_key.id.as_str().to_owned(),
        prompt_version: prompt_key.version.to_string(),
        prompt_manifest_sha256,
        plan_id: base.plan_id.to_string(),
        base_revision: base.revision,
        base_plan_sha256: base.sha256().expect("base digest").to_string(),
        obligation_snapshot_sha256: obligations.snapshot_sha256().to_string(),
        acceptance_policy_sha256: obligations.acceptance_policy_sha256().to_string(),
        context_manifest_sha256: context.manifest_sha256().to_string(),
        planner_policy_sha256: policy.policy_sha256().to_string(),
        evidence_packet_sha256: packet.packet_sha256.clone(),
        previous_evidence_packet_sha256: None,
        evidence_delta_sha256: delta.delta_sha256.clone(),
        backend_id: "lmstudio-local".to_owned(),
        backend_configured_deployment_id: "lmstudio-local-deployment".to_owned(),
        backend_endpoint_origin: "http://127.0.0.1:1234".to_owned(),
        backend_instance_sha256: backend_instance().identity_sha256().as_str().to_owned(),
        model_id: "google/gemma-4-26b-a4b".to_owned(),
        reasoning: Some(PlannerReplannerV2Reasoning::High),
        budget_reservation_id: uuid(20),
        max_output_tokens: 4_096,
    };
    let input = PlannerReplannerV2BuildInput::new(
        PlannerReplannerV2InvocationMaterial {
            base_plan: prompt_base,
            protected_obligation_catalog: prompt_obligations,
            planner_context_catalog: prompt_context,
            evidence_packet: packet,
            evidence_delta: delta,
            planner_policy: prompt_policy,
            bindings: bindings.clone(),
        },
        inference_policy(),
    );

    let obligation_ref = ProtectedObligationRef::from(&obligation);
    let basis = DecisionBasis {
        evidence_ids: BTreeSet::from([evidence_id]),
        rationale: "Den accepterade rotplanen kräver en isolerad repository-specialist.".to_owned(),
    };
    let proposal = PlannerTurnProposal {
        schema_version: 1,
        bindings: PlannerTurnBindings::new(&base, &obligations, &context, &policy)
            .expect("domain bindings"),
        patch: PlanPatch {
            strategy_summary: Some("Delegera en evidensbunden read-only analys.".to_owned()),
            add_verification_targets: vec![NewVerificationTarget {
                local_id: LocalVerificationTargetId(1),
                statement: "Arkitekturgränserna ska citeras från verkliga repository-bevis."
                    .to_owned(),
                obligations: BTreeSet::from([obligation_ref.clone()]),
                basis: basis.clone(),
            }],
            add_work_orders: vec![NewWorkOrder {
                local_id: LocalWorkOrderId(1),
                objective: "Kartlägg planner, subagenter, tooling och durable replay.".to_owned(),
                obligations: BTreeSet::from([obligation_ref]),
                existing_dependencies: BTreeSet::new(),
                new_dependencies: BTreeSet::new(),
                existing_verification_targets: BTreeSet::new(),
                new_verification_targets: BTreeSet::from([LocalVerificationTargetId(1)]),
                required_access: PlannerAccess::ReadOnly,
                basis: basis.clone(),
            }],
            replace_work_orders: Vec::new(),
            cancel_work_orders: Vec::new(),
        },
        directive: PlannerDirective {
            kind: PlannerDirectiveKind::Delegate,
            execute: WorkSelection::default(),
            delegations: vec![DelegationRequest {
                work_orders: WorkSelection {
                    existing: BTreeSet::new(),
                    new: BTreeSet::from([LocalWorkOrderId(1)]),
                },
                basis,
            }],
            clarifications: Vec::new(),
            escalations: Vec::new(),
            finish_claims: Vec::new(),
        },
    };
    let wire: PlannerReplannerOutput =
        serde_json::from_value(serde_json::to_value(proposal).expect("proposal serializes"))
            .expect("prompt proposal is isomorphic");
    let output = PlannerReplannerV2Output {
        schema_version: 2,
        bindings,
        turn_basis: PlannerReplannerDecisionBasis {
            evidence_ids: BTreeSet::from([ROOT_EVIDENCE_ID.to_owned()]),
            rationale: "Den accepterade rotplanen är den nya evidensen för denna övergång."
                .to_owned(),
        },
        patch: wire.patch,
        directive: wire.directive,
    };
    Fixture { input, output }
}

fn assert_attestation_mismatch(input: &PlannerReplannerV2BuildInput, encoded: Value) {
    let substituted: PreparedPlannerReplannerV2Request =
        serde_json::from_value(encoded).expect("substitution remains structurally decodable");
    assert!(matches!(
        substituted.validate_against(input),
        Err(PlannerReplannerV2SetupError::AttestationMismatch)
    ));
}

#[test]
fn one_builder_owns_the_exact_v2_request_and_replay_attestation() {
    let fixture = fixture();
    let prepared = PlannerReplannerV2RequestBuilder::build(&fixture.input).expect("v2 request");
    let repeated =
        PlannerReplannerV2RequestBuilder::build(&fixture.input).expect("repeated v2 request");
    assert_eq!(
        serde_json::to_vec(&prepared).expect("prepared request bytes"),
        serde_json::to_vec(&repeated).expect("repeated prepared request bytes")
    );
    assert_eq!(
        prepared.inference().output().name(),
        "birdcode_planner_replanner_v2_turn"
    );
    assert_eq!(
        prepared.inference().model_id().as_str(),
        "google/gemma-4-26b-a4b"
    );
    assert_eq!(
        prepared.inference().reasoning(),
        Some(ReasoningSetting::High)
    );
    assert_eq!(prepared.inference().max_output_tokens(), 4_096);
    assert_eq!(
        prepared.inference().output().validation_schema(),
        &prepared.compiled_prompt().output_schema
    );
    assert_eq!(
        prepared.inference().output().generation_schema(),
        &prepared.compiled_prompt().generation_schema
    );
    prepared
        .validate_against(&fixture.input)
        .expect("unmodified retained request replays exactly");

    let mut encoded = serde_json::to_value(&prepared).expect("prepared serializes");
    encoded["inference"]["max_output_tokens"] = json!(4_095);
    assert_attestation_mismatch(&fixture.input, encoded);
}

#[test]
fn each_output_contract_surface_is_byte_exactly_attested() {
    let fixture = fixture();
    let prepared = PlannerReplannerV2RequestBuilder::build(&fixture.input).expect("v2 request");

    let mut schema_name = serde_json::to_value(&prepared).expect("prepared serializes");
    schema_name["inference"]["output"]["name"] = json!("substituted_schema_name");
    assert_attestation_mismatch(&fixture.input, schema_name);

    let mut validation_schema = serde_json::to_value(&prepared).expect("prepared serializes");
    validation_schema["inference"]["output"]["validation_schema"]["title"] =
        json!("substituted validation schema");
    assert_attestation_mismatch(&fixture.input, validation_schema);

    let mut generation_schema = serde_json::to_value(&prepared).expect("prepared serializes");
    generation_schema["inference"]["output"]["generation_schema"]["title"] =
        json!("substituted generation schema");
    assert_attestation_mismatch(&fixture.input, generation_schema);
}

#[test]
fn absent_reasoning_and_explicit_off_never_collapse() {
    let fixture = fixture();
    let mut none_material = fixture.input.material().clone();
    none_material.bindings.reasoning = None;
    let none_input =
        PlannerReplannerV2BuildInput::new(none_material, inference_policy_with_reasoning(None));
    let none = PlannerReplannerV2RequestBuilder::build(&none_input).expect("reasoning omitted");

    let mut off_material = fixture.input.material().clone();
    off_material.bindings.reasoning = Some(PlannerReplannerV2Reasoning::Off);
    let off_input = PlannerReplannerV2BuildInput::new(
        off_material,
        inference_policy_with_reasoning(Some(ReasoningSetting::Off)),
    );
    let off = PlannerReplannerV2RequestBuilder::build(&off_input).expect("reasoning off");

    assert_eq!(none.inference().reasoning(), None);
    assert_eq!(off.inference().reasoning(), Some(ReasoningSetting::Off));
    assert_ne!(
        serde_json::to_vec(&none).expect("none bytes"),
        serde_json::to_vec(&off).expect("off bytes")
    );
    assert!(matches!(
        none.validate_against(&off_input),
        Err(PlannerReplannerV2SetupError::AttestationMismatch)
    ));
    assert!(matches!(
        off.validate_against(&none_input),
        Err(PlannerReplannerV2SetupError::AttestationMismatch)
    ));
}

#[test]
fn inference_echo_must_equal_independent_runtime_policy() {
    let fixture = fixture();
    for field in [
        "backend_configured_deployment_id",
        "backend_endpoint_origin",
        "backend_instance_sha256",
        "model_id",
    ] {
        let mut material = fixture.input.material().clone();
        match field {
            "backend_configured_deployment_id" => {
                material.bindings.backend_configured_deployment_id =
                    "another-deployment".to_owned();
            }
            "backend_endpoint_origin" => {
                material.bindings.backend_endpoint_origin = "http://127.0.0.1:1235".to_owned();
            }
            "backend_instance_sha256" => {
                material.bindings.backend_instance_sha256 = digest(b"another-instance");
            }
            "model_id" => material.bindings.model_id = "substituted-model".to_owned(),
            _ => unreachable!("closed fixture field set"),
        }
        let mismatched = PlannerReplannerV2BuildInput::new(material, inference_policy());
        assert!(matches!(
            PlannerReplannerV2RequestBuilder::build(&mismatched),
            Err(PlannerReplannerV2SetupError::InferenceBindingMismatch { field: actual })
                if actual == field
        ));
    }
}

#[test]
fn v2_output_applies_through_the_authoritative_domain_with_uuid_v8_children() {
    let fixture = fixture();
    let prepared = PlannerReplannerV2RequestBuilder::build(&fixture.input).expect("v2 request");
    let value = serde_json::to_value(&fixture.output).expect("output serializes");
    let accepted = decode_and_apply_planner_replanner_v2_output(&prepared, &value, &fixture.input)
        .expect("v2 output is prompt-valid and domain-valid");
    assert_eq!(accepted.source_schema_version, 2);
    assert_eq!(accepted.validated.plan.revision, 1);
    assert_eq!(accepted.validated.plan.work_orders.len(), 1);
    assert_eq!(
        accepted
            .local_work_order_ids()
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![LocalWorkOrderId(1)]
    );
    let allocated = accepted.local_work_order_ids()[&LocalWorkOrderId(1)];
    assert!(accepted.validated.plan.work_orders.contains_key(&allocated));
    assert!(
        accepted
            .validated
            .plan
            .work_orders
            .keys()
            .all(|id| id.as_uuid().get_version_num() == 8)
    );
    assert!(matches!(
        accepted.validated.directive,
        ResolvedPlannerDirective::Delegate { ref work_order_ids }
            if work_order_ids.len() == 1
                && work_order_ids[0] == allocated
                && work_order_ids[0].as_uuid().get_version_num() == 8
    ));
    assert!(
        serde_json::to_value(&accepted.validated)
            .expect("durable validated turn serializes")
            .get("local_work_order_ids")
            .is_none(),
        "the local allocation must not change ValidatedPlannerTurn's durable wire"
    );
}

#[test]
fn no_op_pause_has_no_local_allocations_or_plan_revision() {
    let fixture = fixture();
    let prepared = PlannerReplannerV2RequestBuilder::build(&fixture.input).expect("v2 request");
    let mut output = fixture.output;
    let blocked_obligations = output.patch.add_work_orders[0].obligations.clone();
    output.patch = PlannerReplannerPlanPatch::default();
    output.directive.kind = PlannerReplannerDirectiveKind::Clarify;
    output.directive.delegations.clear();
    output
        .directive
        .clarifications
        .push(PlannerReplannerClarificationRequest {
            question: "Vilken extern auktoritet får godkänna nästa steg?".to_owned(),
            blocked_obligations,
            basis: output.turn_basis.clone(),
        });

    let value = serde_json::to_value(output).expect("output serializes");
    let accepted = decode_and_apply_planner_replanner_v2_output(&prepared, &value, &fixture.input)
        .expect("initial clarification is a valid no-op pause");
    assert!(accepted.local_work_order_ids().is_empty());
    assert_eq!(accepted.validated.plan.revision, 0);
    assert!(accepted.validated.plan.work_orders.is_empty());
    assert!(matches!(
        accepted.validated.directive,
        ResolvedPlannerDirective::Clarify { ref requests } if requests.len() == 1
    ));
}

#[test]
fn invalid_or_duplicate_local_work_order_ids_never_return_an_allocation() {
    let fixture = fixture();
    let prepared = PlannerReplannerV2RequestBuilder::build(&fixture.input).expect("v2 request");

    let mut zero = fixture.output.clone();
    zero.patch.add_work_orders[0].local_id = PlannerReplannerLocalWorkOrderId(0);
    zero.directive.delegations[0].work_orders.new =
        BTreeSet::from([PlannerReplannerLocalWorkOrderId(0)]);
    let zero_value = serde_json::to_value(zero).expect("zero output serializes");
    assert!(matches!(
        decode_and_apply_planner_replanner_v2_output(&prepared, &zero_value, &fixture.input),
        Err(PlannerReplannerV2ApplyError::OutputInvariant { .. })
    ));

    let mut duplicate = fixture.output;
    duplicate
        .patch
        .add_work_orders
        .push(duplicate.patch.add_work_orders[0].clone());
    let duplicate_value = serde_json::to_value(duplicate).expect("duplicate output serializes");
    assert!(matches!(
        decode_and_apply_planner_replanner_v2_output(
            &prepared,
            &duplicate_value,
            &fixture.input
        ),
        Err(PlannerReplannerV2ApplyError::Plan(PlannerValidationError { violations }))
            if violations.iter().any(|violation| matches!(
                violation,
                PlannerViolation::DuplicateLocalWorkOrderId {
                    id: LocalWorkOrderId(1)
                }
            ))
    ));
}

#[test]
fn output_binding_substitution_fails_before_plan_application() {
    let fixture = fixture();
    let prepared = PlannerReplannerV2RequestBuilder::build(&fixture.input).expect("v2 request");
    let mut value = serde_json::to_value(&fixture.output).expect("output serializes");
    value["bindings"]["base_revision"] = json!(99);
    assert!(matches!(
        decode_and_apply_planner_replanner_v2_output(&prepared, &value, &fixture.input),
        Err(PlannerReplannerV2ApplyError::OutputInvariant { .. })
    ));
}
