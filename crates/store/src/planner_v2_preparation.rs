//! Planner-v2 durable request preparation and pre-effect event construction.
//!
//! Preparation and replay projection intentionally form a private dependency
//! component: preparation consults replay state, while replay revalidates the
//! retained request. Changing that ownership is a separate refactor; this split
//! preserves the existing behavior.

use super::{
    BTreeSet, BackendDeploymentId, BackendEndpointOrigin, BackendId, BackendInstanceIdentity,
    BackendTransportIdentity, CanonicalJson, ChildModelReasoningSettingV1, EventEnvelope,
    EventPayload, INFERENCE_REQUEST_MEDIA_TYPE, IdentifiedNewEvent, MAX_SQLITE_INTEGER_U64,
    ModelId, NewEvent, PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_OUTPUT_TOKENS_PER_CALL,
    PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_TURNS,
    PARALLEL_RECONNAISSANCE_V1_PLANNER_ATTEMPTS_PER_STAGE, PLANNER_PLAN_V2_MEDIA_TYPE,
    PLANNER_PROMPT_MANIFEST_V2_MEDIA_TYPE, Path, PlannerNextAction, PlannerV2PreparationAuthority,
    PromptInvocation, Provenance, RETAINED_PROMPT_MEDIA_TYPE, ReasoningSetting,
    RetainedInferenceRequest, RetainedPromptEvidence, RunId, RunPurpose, Sha256Digest, Store,
    StoreError, Transaction, all_model_reserved_output_tokens_for_run, build_planner_evidence,
    builtin_registry, canonical_digest, decode_stored_run, digest_matches_artifact,
    exact_request_fits_reservation, expected_backend_selection, latest_planner_prepared_before,
    model_token_reservation_identity_count, params, planner_evidence_bindings, planner_run_id,
    planner_v2_committed_material, planner_v2_prepared_turn_count,
    planner_v2_prepared_turn_count_for_purpose, planner_v2_retry_terminal_for_prepared,
    planner_v2_terminal_authorizes_retry, project_recon_run, prompting_planner_purpose,
    prompting_v2_purpose_matches, protocol_backend_instance_identity, put_json_artifact,
    read_canonical_json_artifact, read_planner_base_snapshot, require_current_claim_owner,
    require_exact_model_provenance, require_latest_run_parent, require_running_run,
    valid_child_token_reservation, valid_lineage, validate_planner_base_authority,
    validate_planner_durable_evidence_material,
};

#[allow(
    clippy::too_many_lines,
    reason = "one total preparation owns durable evidence, request construction, artifacts, and the pre-effect event"
)]
pub(super) fn build_planner_v2_prepared_event(
    store: &Store,
    run_id: RunId,
    authority: &PlannerV2PreparationAuthority,
) -> Result<IdentifiedNewEvent, StoreError> {
    let projection = project_recon_run(&store.connection, &store.artifact_root, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let (purpose, projected_base, retry_prepared_event_id) = match &projection.planner.next_action {
        PlannerNextAction::ReadyToPrepare { purpose, base_plan } => {
            (*purpose, base_plan.clone(), None)
        }
        PlannerNextAction::RetryPrepared {
            purpose,
            base_plan,
            prior_prepared_event_id,
            ..
        } => (
            *purpose,
            Some(base_plan.clone()),
            Some(*prior_prepared_event_id),
        ),
        _ => return Err(StoreError::InvalidStateEvent),
    };
    let claim = projection
        .guard
        .latest_claim
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    if !projection.guard.claim_matches_cancellation_generation
        || projection.guard.cancellation_generation != 0
        || projection.planner.prepared_turn_count >= PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_TURNS
        || !valid_child_token_reservation(&authority.token_reservation)
        || authority.token_reservation.max_output_tokens
            > PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_OUTPUT_TOKENS_PER_CALL
        || authority.output_budget.max_total_reserved_output_tokens == 0
        || authority.output_budget.max_output_tokens_per_call == 0
        || authority.output_budget.max_output_tokens_per_call
            > PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_OUTPUT_TOKENS_PER_CALL
        || authority.token_reservation.max_output_tokens
            > authority.output_budget.max_output_tokens_per_call
        || authority.prepared_at.runtime_instance_id != claim.claim.runtime_instance_id
        || authority.backend_model.kind != birdcode_protocol::BackendKind::Model
        || authority.backend_instance.validate_integrity().is_err()
        || authority.backend_instance.backend_id().as_str() != authority.backend_model.backend_id
        || authority
            .backend_instance
            .configured_deployment_id()
            .as_str()
            != authority.model_lineage.deployment_id
        || authority.model_lineage.backend_id != authority.backend_model.backend_id
        || authority.model_lineage.model_id != authority.backend_model.model_id
        || !valid_lineage(&authority.model_lineage)
        || authority
            .protected_obligation_catalog
            .derived_snapshot_sha256()
            .map_err(|_| StoreError::InvalidStateEvent)?
            != authority.protected_obligation_catalog.snapshot_sha256
        || authority
            .planner_policy
            .derived_policy_sha256()
            .map_err(|_| StoreError::InvalidStateEvent)?
            != authority.planner_policy.policy_sha256
    {
        return Err(StoreError::InvalidStateEvent);
    }

    let run = decode_stored_run(&store.connection.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), projection.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?)?;
    if run.spec.limits.max_output_tokens.is_some_and(|limit| {
        authority.output_budget.max_total_reserved_output_tokens > limit
            || authority.token_reservation.max_output_tokens > limit
    }) {
        return Err(StoreError::InvalidStateEvent);
    }

    let (base_plan, base_snapshot) = match (purpose, projected_base) {
        (birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation, None) => {
            let plan_id = authority
                .initial_plan_id
                .clone()
                .ok_or(StoreError::InvalidStateEvent)?;
            let snapshot = birdcode_prompting::PlannerReplannerV2PlanSnapshot::empty(
                plan_id,
                authority
                    .protected_obligation_catalog
                    .snapshot_sha256
                    .clone(),
                authority
                    .protected_obligation_catalog
                    .acceptance_policy_sha256
                    .clone(),
            );
            let artifact = put_json_artifact(store, &snapshot, PLANNER_PLAN_V2_MEDIA_TYPE)?;
            let root = projection
                .planner
                .accepted_root_plan
                .as_ref()
                .ok_or(StoreError::InvalidStateEvent)?;
            (
                birdcode_protocol::PlannerBasePlanBindingV1 {
                    accepted_event_id: root.accepted_plan_event_id,
                    revision: 0,
                    digest: Sha256Digest::parse(artifact.sha256.clone())
                        .map_err(|_| StoreError::InvalidStateEvent)?,
                    artifact,
                },
                snapshot,
            )
        }
        (_, Some(binding)) if retry_prepared_event_id.is_some() => {
            if authority.initial_plan_id.is_some() {
                return Err(StoreError::InvalidStateEvent);
            }
            let previous = latest_planner_prepared_before(
                &store.connection,
                projection.session_id,
                run_id,
                MAX_SQLITE_INTEGER_U64,
            )?
            .ok_or(StoreError::InvalidStateEvent)?;
            let EventPayload::PlannerTurnPreparedV1(previous_prepared) = &previous.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            let previous_material =
                planner_v2_committed_material(&store.artifact_root, previous.clone())?;
            if Some(previous.id) != retry_prepared_event_id
                || previous_prepared.base_plan != binding
                || previous_material
                    .build_input
                    .material()
                    .protected_obligation_catalog
                    != authority.protected_obligation_catalog
                || previous_material.build_input.material().planner_policy
                    != authority.planner_policy
            {
                return Err(StoreError::InvalidStateEvent);
            }
            let snapshot = read_planner_base_snapshot(&store.artifact_root, &binding)?;
            (binding, snapshot)
        }
        (birdcode_protocol::PlannerTurnPurposeV1::EvidenceReplan, Some(binding)) => {
            if authority.initial_plan_id.is_some() {
                return Err(StoreError::InvalidStateEvent);
            }
            let snapshot = read_planner_base_snapshot(&store.artifact_root, &binding)?;
            let previous = latest_planner_prepared_before(
                &store.connection,
                projection.session_id,
                run_id,
                MAX_SQLITE_INTEGER_U64,
            )?
            .ok_or(StoreError::InvalidStateEvent)?;
            let previous_material = planner_v2_committed_material(&store.artifact_root, previous)?;
            if previous_material
                .build_input
                .material()
                .protected_obligation_catalog
                != authority.protected_obligation_catalog
                || previous_material.build_input.material().planner_policy
                    != authority.planner_policy
            {
                return Err(StoreError::InvalidStateEvent);
            }
            (binding, snapshot)
        }
        _ => return Err(StoreError::InvalidStateEvent),
    };
    if base_snapshot.obligation_snapshot_sha256
        != authority.protected_obligation_catalog.snapshot_sha256
        || base_snapshot.acceptance_policy_sha256
            != authority
                .protected_obligation_catalog
                .acceptance_policy_sha256
    {
        return Err(StoreError::InvalidStateEvent);
    }

    let evidence = build_planner_evidence(
        store,
        projection.session_id,
        run_id,
        purpose,
        retry_prepared_event_id,
    )?;
    let prompt_key = birdcode_prompting::planner_replanner_v2_key();
    let registry = builtin_registry().map_err(|_| StoreError::InvalidStateEvent)?;
    let manifest = registry
        .get(&prompt_key)
        .ok_or(StoreError::InvalidStateEvent)?;
    let manifest_digest = manifest
        .content_sha256()
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let manifest_bytes = CanonicalJson::new(serde_json::to_value(manifest)?)
        .to_compact_string()
        .map_err(|_| StoreError::InvalidStateEvent)?
        .into_bytes();
    let prompt_manifest_artifact =
        store.put_artifact(&manifest_bytes, PLANNER_PROMPT_MANIFEST_V2_MEDIA_TYPE)?;
    if prompt_manifest_artifact.sha256 != manifest_digest {
        return Err(StoreError::InvalidStateEvent);
    }
    let max_output_tokens = u32::try_from(authority.token_reservation.max_output_tokens)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let bindings = birdcode_prompting::PlannerReplannerV2Bindings {
        purpose: prompting_planner_purpose(purpose),
        prompt_id: prompt_key.id.as_str().to_owned(),
        prompt_version: prompt_key.version.to_string(),
        prompt_manifest_sha256: manifest_digest.clone(),
        plan_id: base_snapshot.plan_id.clone(),
        base_revision: base_snapshot.revision,
        base_plan_sha256: base_plan.digest.as_str().to_owned(),
        obligation_snapshot_sha256: authority
            .protected_obligation_catalog
            .snapshot_sha256
            .clone(),
        acceptance_policy_sha256: authority
            .protected_obligation_catalog
            .acceptance_policy_sha256
            .clone(),
        context_manifest_sha256: evidence.context.manifest_sha256.clone(),
        planner_policy_sha256: authority.planner_policy.policy_sha256.clone(),
        evidence_packet_sha256: evidence.prompt_packet.packet_sha256.clone(),
        previous_evidence_packet_sha256: evidence.prompt_delta.previous_packet_sha256.clone(),
        evidence_delta_sha256: evidence.prompt_delta.delta_sha256.clone(),
        backend_id: authority.backend_model.backend_id.clone(),
        backend_configured_deployment_id: authority
            .backend_instance
            .configured_deployment_id()
            .as_str()
            .to_owned(),
        backend_endpoint_origin: authority
            .backend_instance
            .endpoint_origin()
            .as_str()
            .to_owned(),
        backend_instance_sha256: authority
            .backend_instance
            .identity_sha256()
            .as_str()
            .to_owned(),
        model_id: authority.backend_model.model_id.clone(),
        reasoning: authority.reasoning.map(planner_prompt_reasoning_setting),
        budget_reservation_id: authority.token_reservation.id.to_string(),
        max_output_tokens,
    };
    let invocation_material = birdcode_prompting::PlannerReplannerV2InvocationMaterial {
        base_plan: base_snapshot,
        protected_obligation_catalog: authority.protected_obligation_catalog.clone(),
        planner_context_catalog: evidence.context.clone(),
        evidence_packet: evidence.prompt_packet.clone(),
        evidence_delta: evidence.prompt_delta.clone(),
        planner_policy: authority.planner_policy.clone(),
        bindings,
    };
    let inference_policy =
        birdcode_orchestrator::planner_prompt::PlannerReplannerInferencePolicy::new(
            authority.backend_instance.clone(),
            ModelId::new(authority.backend_model.model_id.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?,
            authority.reasoning.map(planner_reasoning_setting),
            max_output_tokens,
        )
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let build_input = birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2BuildInput::new(
        invocation_material,
        inference_policy,
    );
    let request =
        birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2RequestBuilder::build(
            &build_input,
        )
        .map_err(|_| StoreError::InvalidStateEvent)?;
    if !exact_request_fits_reservation(request.inference(), &authority.token_reservation)? {
        return Err(StoreError::InvalidStateEvent);
    }
    let prompt_artifact = put_json_artifact(
        store,
        &RetainedPromptEvidence {
            prompt_invocation: request.invocation().clone(),
            compiled_prompt: request.compiled_prompt().clone(),
        },
        RETAINED_PROMPT_MEDIA_TYPE,
    )?;
    let request_artifact = put_json_artifact(
        store,
        &RetainedInferenceRequest {
            request: request.inference().clone(),
            request_sha256: canonical_digest(request.inference())?,
        },
        INFERENCE_REQUEST_MEDIA_TYPE,
    )?;
    let prepared = birdcode_protocol::PlannerTurnPreparedV1 {
        schema_version: birdcode_protocol::PLANNER_TURN_CONTRACT_VERSION,
        turn_id: authority.turn_id,
        purpose,
        claim_event_id: claim.event.id,
        claim_id: claim.claim.claim_id,
        claim_generation: claim.claim.claim_generation,
        claim_runtime_instance_id: claim.claim.runtime_instance_id,
        cancellation_generation: projection.guard.cancellation_generation,
        base_plan,
        obligation_snapshot_digest: Sha256Digest::parse(
            authority
                .protected_obligation_catalog
                .snapshot_sha256
                .clone(),
        )
        .map_err(|_| StoreError::InvalidStateEvent)?,
        acceptance_policy_digest: Sha256Digest::parse(
            authority
                .protected_obligation_catalog
                .acceptance_policy_sha256
                .clone(),
        )
        .map_err(|_| StoreError::InvalidStateEvent)?,
        context_manifest_digest: Sha256Digest::parse(evidence.context.manifest_sha256)
            .map_err(|_| StoreError::InvalidStateEvent)?,
        planner_policy_digest: Sha256Digest::parse(authority.planner_policy.policy_sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
        durable_evidence_packet: evidence.durable_packet,
        durable_evidence_packet_digest: Sha256Digest::parse(
            evidence.durable_packet_artifact.sha256.clone(),
        )
        .map_err(|_| StoreError::InvalidStateEvent)?,
        durable_evidence_packet_artifact: evidence.durable_packet_artifact,
        durable_evidence_delta: evidence.durable_delta,
        durable_evidence_delta_digest: Sha256Digest::parse(
            evidence.durable_delta_artifact.sha256.clone(),
        )
        .map_err(|_| StoreError::InvalidStateEvent)?,
        durable_evidence_delta_artifact: evidence.durable_delta_artifact,
        prompt_evidence_packet_digest: Sha256Digest::parse(
            evidence.prompt_packet_artifact.sha256.clone(),
        )
        .map_err(|_| StoreError::InvalidStateEvent)?,
        prompt_evidence_packet_artifact: evidence.prompt_packet_artifact,
        prompt_evidence_delta_digest: Sha256Digest::parse(
            evidence.prompt_delta_artifact.sha256.clone(),
        )
        .map_err(|_| StoreError::InvalidStateEvent)?,
        prompt_evidence_delta_artifact: evidence.prompt_delta_artifact,
        backend_model: authority.backend_model.clone(),
        backend_instance: protocol_backend_instance_identity(&authority.backend_instance)?,
        model_lineage: authority.model_lineage.clone(),
        reasoning: authority.reasoning,
        prompt_manifest_digest: Sha256Digest::parse(prompt_manifest_artifact.sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
        prompt_manifest_artifact,
        prompt_digest: Sha256Digest::parse(prompt_artifact.sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
        prompt_artifact,
        request_digest: Sha256Digest::parse(request_artifact.sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
        request_artifact: request_artifact.clone(),
        token_reservation: authority.token_reservation.clone(),
        output_budget: authority.output_budget,
        prepared_at: authority.prepared_at.clone(),
    };
    Ok(IdentifiedNewEvent {
        event_id: authority.event_id,
        event: NewEvent {
            session_id: projection.session_id,
            run_id: Some(run_id),
            actor_id: claim.event.actor_id,
            causal_parent: Some(projection.last_event.id),
            provenance: Provenance {
                producer: "birdcode-store-planner-v2".to_owned(),
                backend: Some(expected_backend_selection(&run, &authority.backend_model)),
                raw_artifact: Some(request_artifact),
            },
            payload: EventPayload::PlannerTurnPreparedV1(prepared),
        },
    })
}

pub(super) fn validate_planner_v2_retained_prompt(
    artifact_root: &Path,
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    base_snapshot: &birdcode_prompting::PlannerReplannerV2PlanSnapshot,
) -> Result<ValidatedPlannerV2DurableRequest, StoreError> {
    let retained = read_canonical_json_artifact::<RetainedPromptEvidence>(
        artifact_root,
        &prepared.prompt_artifact,
        RETAINED_PROMPT_MEDIA_TYPE,
    )?;
    let prompt_packet =
        read_canonical_json_artifact::<birdcode_prompting::PlannerReplannerV2EvidencePacket>(
            artifact_root,
            &prepared.prompt_evidence_packet_artifact,
            birdcode_protocol::PLANNER_PROMPT_EVIDENCE_PACKET_V2_MEDIA_TYPE,
        )?;
    let prompt_delta =
        read_canonical_json_artifact::<birdcode_prompting::PlannerReplannerV2EvidenceDelta>(
            artifact_root,
            &prepared.prompt_evidence_delta_artifact,
            birdcode_protocol::PLANNER_PROMPT_EVIDENCE_DELTA_V2_MEDIA_TYPE,
        )?;
    let material = birdcode_prompting::PlannerReplannerV2InvocationMaterial {
        base_plan: base_snapshot.clone(),
        protected_obligation_catalog: planner_invocation_section(
            &retained.prompt_invocation,
            "protected_obligation_catalog",
        )?,
        planner_context_catalog: planner_invocation_section(
            &retained.prompt_invocation,
            "planner_context_catalog",
        )?,
        evidence_packet: prompt_packet,
        evidence_delta: prompt_delta,
        planner_policy: planner_invocation_constraint(
            &retained.prompt_invocation,
            "planner_policy",
        )?,
        bindings: planner_invocation_constraint(
            &retained.prompt_invocation,
            "planner_turn_bindings",
        )?,
    };
    validate_planner_v2_prepared_bindings(
        prepared,
        base_snapshot,
        &material.evidence_packet,
        &material.evidence_delta,
        &material.bindings,
    )?;
    let backend_instance = backend_instance_from_planner_bindings(&material.bindings)?;
    let inference_policy =
        birdcode_orchestrator::planner_prompt::PlannerReplannerInferencePolicy::new(
            backend_instance,
            ModelId::new(prepared.backend_model.model_id.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?,
            prepared.reasoning.map(planner_reasoning_setting),
            u32::try_from(prepared.token_reservation.max_output_tokens)
                .map_err(|_| StoreError::InvalidStateEvent)?,
        )
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let input = birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2BuildInput::new(
        material,
        inference_policy,
    );
    let authoritative =
        birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2RequestBuilder::build(&input)
            .map_err(|_| StoreError::InvalidStateEvent)?;
    authoritative
        .validate_against(&input)
        .map_err(|_| StoreError::InvalidStateEvent)?;

    let retained_request = read_canonical_json_artifact::<RetainedInferenceRequest>(
        artifact_root,
        &prepared.request_artifact,
        INFERENCE_REQUEST_MEDIA_TYPE,
    )?;
    if canonical_digest(&retained_request.request)? != retained_request.request_sha256
        || retained.prompt_invocation != *authoritative.invocation()
        || retained.compiled_prompt != *authoritative.compiled_prompt()
        || retained_request.request != *authoritative.inference()
        || !exact_request_fits_reservation(&retained_request.request, &prepared.token_reservation)?
        || authoritative.compiled_prompt().manifest.content_sha256
            != prepared.prompt_manifest_digest.as_str()
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(ValidatedPlannerV2DurableRequest {
        input,
        authoritative,
    })
}

pub(super) struct ValidatedPlannerV2DurableRequest {
    pub(super) input: birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2BuildInput,
    pub(super) authoritative:
        birdcode_orchestrator::planner_prompt_v2::PreparedPlannerReplannerV2Request,
}

fn backend_instance_from_planner_bindings(
    bindings: &birdcode_prompting::PlannerReplannerV2Bindings,
) -> Result<BackendInstanceIdentity, StoreError> {
    let identity = BackendInstanceIdentity::new(
        BackendId::new(bindings.backend_id.clone()).map_err(|_| StoreError::InvalidStateEvent)?,
        BackendTransportIdentity::HttpOrigin {
            origin: BackendEndpointOrigin::parse(bindings.backend_endpoint_origin.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?,
        },
        BackendDeploymentId::new(bindings.backend_configured_deployment_id.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
    )
    .map_err(|_| StoreError::InvalidStateEvent)?;
    if identity.identity_sha256().as_str() != bindings.backend_instance_sha256 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(identity)
}

fn validate_planner_v2_prepared_bindings(
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    base_snapshot: &birdcode_prompting::PlannerReplannerV2PlanSnapshot,
    evidence_packet: &birdcode_prompting::PlannerReplannerV2EvidencePacket,
    evidence_delta: &birdcode_prompting::PlannerReplannerV2EvidenceDelta,
    bindings: &birdcode_prompting::PlannerReplannerV2Bindings,
) -> Result<(), StoreError> {
    let prompt_key = birdcode_prompting::planner_replanner_v2_key();
    let max_output_tokens = u32::try_from(prepared.token_reservation.max_output_tokens)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let backend_instance = backend_instance_from_planner_bindings(bindings)?;
    let protocol_backend_instance = protocol_backend_instance_identity(&backend_instance)?;
    if !prompting_v2_purpose_matches(bindings.purpose, prepared.purpose)
        || bindings.prompt_id != prompt_key.id.as_str()
        || bindings.prompt_version != prompt_key.version.to_string()
        || bindings.prompt_manifest_sha256 != prepared.prompt_manifest_digest.as_str()
        || bindings.plan_id != base_snapshot.plan_id
        || bindings.base_revision != prepared.base_plan.revision
        || bindings.base_plan_sha256 != prepared.base_plan.digest.as_str()
        || bindings.obligation_snapshot_sha256 != prepared.obligation_snapshot_digest.as_str()
        || bindings.acceptance_policy_sha256 != prepared.acceptance_policy_digest.as_str()
        || bindings.context_manifest_sha256 != prepared.context_manifest_digest.as_str()
        || bindings.planner_policy_sha256 != prepared.planner_policy_digest.as_str()
        || bindings.evidence_packet_sha256 != evidence_packet.packet_sha256
        || bindings.previous_evidence_packet_sha256 != evidence_delta.previous_packet_sha256
        || bindings.evidence_delta_sha256 != evidence_delta.delta_sha256
        || bindings.backend_id != prepared.backend_model.backend_id
        || protocol_backend_instance != prepared.backend_instance
        || backend_instance.backend_id().as_str() != prepared.backend_model.backend_id
        || backend_instance.configured_deployment_id().as_str()
            != prepared.model_lineage.deployment_id
        || bindings.model_id != prepared.backend_model.model_id
        || bindings.reasoning != prepared.reasoning.map(planner_prompt_reasoning_setting)
        || bindings.budget_reservation_id != prepared.token_reservation.id.to_string()
        || bindings.max_output_tokens != max_output_tokens
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

const fn planner_prompt_reasoning_setting(
    reasoning: ChildModelReasoningSettingV1,
) -> birdcode_prompting::PlannerReplannerV2Reasoning {
    match reasoning {
        ChildModelReasoningSettingV1::Off => birdcode_prompting::PlannerReplannerV2Reasoning::Off,
        ChildModelReasoningSettingV1::On => birdcode_prompting::PlannerReplannerV2Reasoning::On,
        ChildModelReasoningSettingV1::Low => birdcode_prompting::PlannerReplannerV2Reasoning::Low,
        ChildModelReasoningSettingV1::Medium => {
            birdcode_prompting::PlannerReplannerV2Reasoning::Medium
        }
        ChildModelReasoningSettingV1::High => birdcode_prompting::PlannerReplannerV2Reasoning::High,
    }
}

const fn planner_reasoning_setting(reasoning: ChildModelReasoningSettingV1) -> ReasoningSetting {
    match reasoning {
        ChildModelReasoningSettingV1::Off => ReasoningSetting::Off,
        ChildModelReasoningSettingV1::On => ReasoningSetting::On,
        ChildModelReasoningSettingV1::Low => ReasoningSetting::Low,
        ChildModelReasoningSettingV1::Medium => ReasoningSetting::Medium,
        ChildModelReasoningSettingV1::High => ReasoningSetting::High,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "planner Prepared binds claim, budgets, two evidence wires, artifacts, and history"
)]
pub(super) fn validate_planner_turn_prepared_v1(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    require_latest_run_parent(transaction, event, run_id)?;
    let run = decode_stored_run(&transaction.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?)?;
    let claim_event =
        require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let expected_backend = expected_backend_selection(&run, &prepared.backend_model);
    let prior_planner_turns =
        planner_v2_prepared_turn_count(transaction, event.session_id, run_id)?;
    let prior_stage_turns = planner_v2_prepared_turn_count_for_purpose(
        transaction,
        event.session_id,
        run_id,
        prepared.purpose,
    )?;
    if run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1
        || prior_planner_turns >= u64::from(PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_TURNS)
        || prior_stage_turns >= u64::from(PARALLEL_RECONNAISSANCE_V1_PLANNER_ATTEMPTS_PER_STAGE)
        || prepared.schema_version != birdcode_protocol::PLANNER_TURN_CONTRACT_VERSION
        || prepared.durable_evidence_packet.schema_version
            != birdcode_protocol::PLANNER_EVIDENCE_CONTRACT_VERSION
        || prepared.durable_evidence_delta.schema_version
            != birdcode_protocol::PLANNER_EVIDENCE_CONTRACT_VERSION
        || prepared.durable_evidence_packet.purpose != prepared.purpose
        || prepared.durable_evidence_delta.purpose != prepared.purpose
        || prepared.durable_evidence_packet.context_manifest_digest
            != prepared.context_manifest_digest
        || event.actor_id != claim_event.actor_id
        || claim_event.id != prepared.claim_event_id
        || claim.claim_id != prepared.claim_id
        || claim.claim_generation != prepared.claim_generation
        || claim.runtime_instance_id != prepared.claim_runtime_instance_id
        || claim.cancellation_generation != prepared.cancellation_generation
        || prepared.prepared_at.runtime_instance_id != prepared.claim_runtime_instance_id
        || prepared.backend_model.kind != birdcode_protocol::BackendKind::Model
        || prepared.backend_instance.validate_integrity().is_err()
        || prepared.backend_instance.backend_id != prepared.backend_model.backend_id
        || prepared.backend_instance.configured_deployment_id
            != prepared.model_lineage.deployment_id
        || prepared.model_lineage.backend_id != prepared.backend_model.backend_id
        || prepared.model_lineage.model_id != prepared.backend_model.model_id
        || !valid_lineage(&prepared.model_lineage)
        || !valid_child_token_reservation(&prepared.token_reservation)
        || prepared.token_reservation.max_output_tokens
            > PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_OUTPUT_TOKENS_PER_CALL
        || prepared.output_budget.max_total_reserved_output_tokens == 0
        || prepared.output_budget.max_output_tokens_per_call == 0
        || prepared.output_budget.max_output_tokens_per_call
            > PARALLEL_RECONNAISSANCE_V1_MAX_PLANNER_OUTPUT_TOKENS_PER_CALL
        || prepared.output_budget.max_output_tokens_per_call
            > prepared.output_budget.max_total_reserved_output_tokens
        || prepared.token_reservation.max_output_tokens
            > prepared.output_budget.max_output_tokens_per_call
        || model_token_reservation_identity_count(transaction, prepared.token_reservation.id)? != 0
        || !digest_matches_artifact(
            &prepared.durable_evidence_packet_digest,
            &prepared.durable_evidence_packet_artifact,
        )
        || !digest_matches_artifact(
            &prepared.durable_evidence_delta_digest,
            &prepared.durable_evidence_delta_artifact,
        )
        || !digest_matches_artifact(
            &prepared.prompt_evidence_packet_digest,
            &prepared.prompt_evidence_packet_artifact,
        )
        || !digest_matches_artifact(
            &prepared.prompt_evidence_delta_digest,
            &prepared.prompt_evidence_delta_artifact,
        )
        || !digest_matches_artifact(
            &prepared.prompt_manifest_digest,
            &prepared.prompt_manifest_artifact,
        )
        || !digest_matches_artifact(&prepared.prompt_digest, &prepared.prompt_artifact)
        || !digest_matches_artifact(&prepared.request_digest, &prepared.request_artifact)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_exact_model_provenance(event, &expected_backend, Some(&prepared.request_artifact))?;
    if run.spec.limits.max_output_tokens.is_some_and(|limit| {
        prepared.output_budget.max_total_reserved_output_tokens > limit
            || prepared.token_reservation.max_output_tokens > limit
    }) {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(limit) = run.spec.limits.max_output_tokens {
        let prior =
            all_model_reserved_output_tokens_for_run(transaction, event.session_id, run_id)?;
        if prior
            .checked_add(prepared.token_reservation.max_output_tokens)
            .is_none_or(|total| total > limit)
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }

    let base_snapshot = read_planner_base_snapshot(artifact_root, &prepared.base_plan)?;
    validate_planner_base_authority(transaction, event, prepared, &base_snapshot)?;
    let _ = validate_planner_v2_retained_prompt(artifact_root, prepared, &base_snapshot)?;

    let durable_packet = read_canonical_json_artifact::<birdcode_protocol::PlannerEvidencePacketV2>(
        artifact_root,
        &prepared.durable_evidence_packet_artifact,
        birdcode_protocol::PLANNER_DURABLE_EVIDENCE_PACKET_V2_MEDIA_TYPE,
    )?;
    let durable_delta = read_canonical_json_artifact::<birdcode_protocol::PlannerEvidenceDeltaV2>(
        artifact_root,
        &prepared.durable_evidence_delta_artifact,
        birdcode_protocol::PLANNER_DURABLE_EVIDENCE_DELTA_V2_MEDIA_TYPE,
    )?;
    if durable_packet != prepared.durable_evidence_packet
        || durable_delta != prepared.durable_evidence_delta
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let prompt_packet =
        read_canonical_json_artifact::<birdcode_prompting::PlannerReplannerV2EvidencePacket>(
            artifact_root,
            &prepared.prompt_evidence_packet_artifact,
            birdcode_protocol::PLANNER_PROMPT_EVIDENCE_PACKET_V2_MEDIA_TYPE,
        )?;
    let prompt_delta =
        read_canonical_json_artifact::<birdcode_prompting::PlannerReplannerV2EvidenceDelta>(
            artifact_root,
            &prepared.prompt_evidence_delta_artifact,
            birdcode_protocol::PLANNER_PROMPT_EVIDENCE_DELTA_V2_MEDIA_TYPE,
        )?;
    prompt_packet
        .validate_integrity()
        .map_err(|_| StoreError::InvalidStateEvent)?;
    prompt_delta
        .validate_against(&prompt_packet)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let durable_bindings = planner_evidence_bindings(&durable_packet);
    let prompt_bindings = prompt_packet
        .entries
        .iter()
        .map(|entry| (entry.evidence_id(), entry.normalized_content_sha256()))
        .collect::<Vec<_>>();
    if !prompting_v2_purpose_matches(prompt_packet.purpose, prepared.purpose)
        || !prompting_v2_purpose_matches(prompt_delta.purpose, prepared.purpose)
        || prompt_packet.context_manifest_sha256 != prepared.context_manifest_digest.as_str()
        || prompt_bindings.len() != durable_bindings.len()
        || prompt_bindings
            .iter()
            .zip(&durable_bindings)
            .any(|((id, digest), durable)| {
                *id != durable.evidence_id.to_string()
                    || *digest != durable.normalized_content_digest.as_str()
            })
    {
        return Err(StoreError::InvalidStateEvent);
    }
    for entry in &durable_packet.entries {
        validate_planner_durable_evidence_material(transaction, event, &entry.material)?;
    }

    let previous =
        latest_planner_prepared_before(transaction, event.session_id, run_id, event.sequence)?;
    let retry_terminal = previous
        .as_ref()
        .map(|previous| {
            planner_v2_retry_terminal_for_prepared(
                transaction,
                event.session_id,
                run_id,
                previous.id,
                event.sequence,
            )
        })
        .transpose()?
        .flatten()
        .filter(|terminal| {
            previous
                .as_ref()
                .is_some_and(|previous| planner_v2_terminal_authorizes_retry(terminal, previous.id))
        });
    match (prepared.purpose, previous, retry_terminal) {
        (birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation, None, None) => {
            if prepared
                .durable_evidence_delta
                .previous_packet_digest
                .is_some()
                || !prepared.durable_evidence_delta.previous_evidence.is_empty()
                || prompt_delta.previous_packet_sha256.is_some()
                || !prompt_delta.previous_evidence.is_empty()
                || durable_packet.entries.len() != 1
                || !matches!(
                    durable_packet.entries[0].material,
                    birdcode_protocol::PlannerEvidenceMaterialV2::AcceptedRootPlan(_)
                )
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        (purpose, Some(previous_event), Some(retry_terminal)) => {
            let EventPayload::PlannerTurnPreparedV1(previous_prepared) = &previous_event.payload
            else {
                return Err(StoreError::InvalidStateEvent);
            };
            let previous_prompt = read_canonical_json_artifact::<
                birdcode_prompting::PlannerReplannerV2EvidencePacket,
            >(
                artifact_root,
                &previous_prepared.prompt_evidence_packet_artifact,
                birdcode_protocol::PLANNER_PROMPT_EVIDENCE_PACKET_V2_MEDIA_TYPE,
            )?;
            let previous_delta = read_canonical_json_artifact::<
                birdcode_prompting::PlannerReplannerV2EvidenceDelta,
            >(
                artifact_root,
                &previous_prepared.prompt_evidence_delta_artifact,
                birdcode_protocol::PLANNER_PROMPT_EVIDENCE_DELTA_V2_MEDIA_TYPE,
            )?;
            if previous_prepared.purpose != purpose
                || previous_prepared.base_plan != prepared.base_plan
                || previous_prepared.durable_evidence_packet != prepared.durable_evidence_packet
                || previous_prepared.durable_evidence_delta != prepared.durable_evidence_delta
                || previous_prompt != prompt_packet
                || previous_delta != prompt_delta
                || retry_terminal.sequence <= previous_event.sequence
                || retry_terminal.sequence >= event.sequence
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        (birdcode_protocol::PlannerTurnPurposeV1::EvidenceReplan, Some(previous_event), None) => {
            let EventPayload::PlannerTurnPreparedV1(previous_prepared) = previous_event.payload
            else {
                return Err(StoreError::InvalidStateEvent);
            };
            let previous_prompt = read_canonical_json_artifact::<
                birdcode_prompting::PlannerReplannerV2EvidencePacket,
            >(
                artifact_root,
                &previous_prepared.prompt_evidence_packet_artifact,
                birdcode_protocol::PLANNER_PROMPT_EVIDENCE_PACKET_V2_MEDIA_TYPE,
            )?;
            if prepared.durable_evidence_delta.previous_packet_digest
                != Some(previous_prepared.durable_evidence_packet_digest)
                || prepared.durable_evidence_delta.previous_evidence
                    != planner_evidence_bindings(&previous_prepared.durable_evidence_packet)
                || prompt_delta.previous_packet_sha256
                    != Some(previous_prompt.packet_sha256.clone())
                || prompt_delta.previous_evidence
                    != previous_prompt
                        .entries
                        .iter()
                        .map(
                            |entry| birdcode_prompting::PlannerReplannerV2EvidenceBinding {
                                evidence_id: entry.evidence_id().to_owned(),
                                normalized_content_sha256: entry
                                    .normalized_content_sha256()
                                    .to_owned(),
                            },
                        )
                        .collect::<Vec<_>>()
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        _ => return Err(StoreError::InvalidStateEvent),
    }
    let previous_ids = prepared
        .durable_evidence_delta
        .previous_evidence
        .iter()
        .map(|binding| binding.evidence_id)
        .collect::<BTreeSet<_>>();
    let expected_new = durable_bindings
        .into_iter()
        .filter(|binding| !previous_ids.contains(&binding.evidence_id))
        .collect::<Vec<_>>();
    if prepared.durable_evidence_delta.newly_available != expected_new
        || prepared.durable_evidence_delta.newly_available.is_empty()
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn planner_invocation_section<T: serde::de::DeserializeOwned>(
    invocation: &PromptInvocation,
    name: &str,
) -> Result<T, StoreError> {
    let payload = invocation
        .sections
        .iter()
        .find(|section| section.name == name)
        .map(|section| section.payload.clone())
        .ok_or(StoreError::InvalidStateEvent)?;
    serde_json::from_value(payload).map_err(|_| StoreError::InvalidStateEvent)
}

fn planner_invocation_constraint<T: serde::de::DeserializeOwned>(
    invocation: &PromptInvocation,
    name: &str,
) -> Result<T, StoreError> {
    let payload = invocation
        .runtime_constraints
        .iter()
        .find(|constraint| constraint.name == name)
        .map(|constraint| constraint.payload.clone())
        .ok_or(StoreError::InvalidStateEvent)?;
    serde_json::from_value(payload).map_err(|_| StoreError::InvalidStateEvent)
}
