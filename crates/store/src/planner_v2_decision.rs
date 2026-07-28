//! Planner-v2 response classification, accepted directives, and durable decision validation.

use super::{
    ArtifactRef, BTreeMap, BTreeSet, Connection, EventEnvelope, EventPayload,
    INFERENCE_EVIDENCE_MEDIA_TYPE, IdempotentAppendOutcome, IdentifiedNewEvent, NewEvent,
    PLAN_VALIDATION_MEDIA_TYPE, PLANNER_PLAN_V2_MEDIA_TYPE,
    PLANNER_V2_FINALIZATION_EVIDENCE_MEDIA_TYPE, PLANNER_V2_FINALIZATION_PRODUCER,
    PLANNER_WORK_ORDER_V2_MEDIA_TYPE, Path, PlannerPromptV2AcceptedOutputV1,
    PlannerV2FinalizationAuthority, PlannerV2FinalizationDisposition, Provenance,
    ReconRunProjection, RetainedInferenceEvidence, RetainedPlanValidation,
    RetainedPlannerV2FinalizationEvidence, RetainedPlannerV2TerminalDisposition, RunState,
    Sha256Digest, Store, StoreError, StructuredInferenceResponse, Transaction, artifact_path_at,
    digest_matches_artifact, planner_run_id, planner_turn_decision_count,
    prompting_planner_v2_accepted_output, protocol_planner_v2_accepted_output, put_json_artifact,
    read_canonical_json_artifact, read_planner_base_snapshot, read_verified_artifact,
    require_running_run, same_runtime_not_before, sha256_hex, stored_event_for_run,
    validate_planner_v2_retained_prompt,
};

pub(super) fn validate_authoritative_planner_apply(
    artifact_root: &Path,
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    output: &birdcode_prompting::PlannerReplannerV2Output,
) -> Result<birdcode_orchestrator::planner_prompt_v2::ValidatedPlannerReplannerV2Turn, StoreError> {
    let base_snapshot = read_planner_base_snapshot(artifact_root, &prepared.base_plan)?;
    let retained = validate_planner_v2_retained_prompt(artifact_root, prepared, &base_snapshot)?;
    birdcode_orchestrator::planner_prompt_v2::decode_and_apply_planner_replanner_v2_output(
        &retained.authoritative,
        &serde_json::to_value(output)?,
        &retained.input,
    )
    .map_err(|_| StoreError::InvalidStateEvent)
}

struct PlannerV2AcceptedClassification {
    prompting: birdcode_prompting::PlannerReplannerV2Output,
    protocol: PlannerPromptV2AcceptedOutputV1,
    authoritative: birdcode_orchestrator::planner_prompt_v2::ValidatedPlannerReplannerV2Turn,
    resulting_plan: birdcode_prompting::PlannerReplannerV2PlanSnapshot,
}

#[allow(
    clippy::large_enum_variant,
    reason = "classification is short-lived and retains the validated orchestrator result intact"
)]
enum PlannerV2ResponseClassification {
    Accepted(PlannerV2AcceptedClassification),
    Rejected {
        reason: birdcode_protocol::PlannerTurnRejectionReasonV1,
        validation: RetainedPlanValidation,
    },
}

const fn planner_rejection_priority(reason: birdcode_protocol::PlannerTurnRejectionReasonV1) -> u8 {
    use birdcode_protocol::PlannerTurnRejectionReasonV1 as Reason;
    match reason {
        Reason::InvalidSchema => 0,
        Reason::WrongPurpose => 1,
        Reason::StaleBasePlan => 2,
        Reason::EvidenceOmitted => 3,
        Reason::EvidenceSubstituted => 4,
        Reason::EvidenceFabricated => 5,
        Reason::DirectiveInvalid => 6,
        Reason::PolicyLimitExceeded => 7,
        Reason::BindingMismatch => 8,
    }
}

fn strongest_planner_rejection(
    reasons: impl IntoIterator<Item = birdcode_protocol::PlannerTurnRejectionReasonV1>,
) -> birdcode_protocol::PlannerTurnRejectionReasonV1 {
    reasons
        .into_iter()
        .min_by_key(|reason| planner_rejection_priority(*reason))
        .unwrap_or(birdcode_protocol::PlannerTurnRejectionReasonV1::BindingMismatch)
}

fn prompting_invariant_rejection(
    violation: &birdcode_prompting::PlannerReplannerV2InvariantViolation,
) -> birdcode_protocol::PlannerTurnRejectionReasonV1 {
    use birdcode_prompting::PlannerReplannerV2InvariantViolation as Violation;
    use birdcode_protocol::PlannerTurnRejectionReasonV1 as Reason;
    match violation {
        Violation::TypedOutputDecode { .. }
        | Violation::ContractValidation { .. }
        | Violation::OutputSchemaVersion { .. }
        | Violation::RuntimeConstraintShape => Reason::InvalidSchema,
        Violation::PurposeMismatch => Reason::WrongPurpose,
        Violation::BasePlanEvidenceOmission { .. }
        | Violation::EvidencePacketOmission { .. }
        | Violation::TurnBasisMissesDelta
        | Violation::EmptyTurnBasis => Reason::EvidenceOmitted,
        Violation::EvidencePacketUnknownId { .. } | Violation::UnknownEvidenceId { .. } => {
            Reason::EvidenceFabricated
        }
        Violation::EvidencePacketIntegrity { .. }
        | Violation::EvidenceDeltaIntegrity { .. }
        | Violation::EvidencePacketDigestMismatch { .. }
        | Violation::AuthorityIntegrity { .. } => Reason::EvidenceSubstituted,
        Violation::InitialFinishForbidden => Reason::DirectiveInvalid,
        Violation::InvalidBindings { .. }
        | Violation::MissingContextCatalog
        | Violation::ContextCatalogDecode { .. }
        | Violation::MissingEvidencePacket
        | Violation::EvidencePacketDecode { .. }
        | Violation::EvidenceDeltaDecode { .. }
        | Violation::AcceptedRootPlanBindingMismatch { .. }
        | Violation::EvidencePacketContextMismatch
        | Violation::InvocationBindingMismatch { .. }
        | Violation::BindingMismatch { .. } => Reason::BindingMismatch,
    }
}

fn plan_violation_rejection(
    violation: &birdcode_orchestrator::planner::PlannerViolation,
) -> birdcode_protocol::PlannerTurnRejectionReasonV1 {
    use birdcode_orchestrator::planner::PlannerViolation as Violation;
    use birdcode_protocol::PlannerTurnRejectionReasonV1 as Reason;
    match violation {
        Violation::UnsupportedSchemaVersion { .. } => Reason::InvalidSchema,
        Violation::StalePlanBinding | Violation::StaleWorkOrder { .. } => Reason::StaleBasePlan,
        Violation::EmptyEvidence { .. }
        | Violation::RequiredObligationUncovered { .. }
        | Violation::FinishMissingRequiredObligation { .. } => Reason::EvidenceOmitted,
        Violation::UnknownEvidence { .. } => Reason::EvidenceFabricated,
        Violation::PatchOperationLimitExceeded { .. }
        | Violation::WorkOrderLimitExceeded { .. }
        | Violation::VerificationTargetLimitExceeded { .. }
        | Violation::TextLimitExceeded { .. }
        | Violation::DirectiveEncodedLimitExceeded { .. }
        | Violation::DirectiveCollectionLimitExceeded { .. }
        | Violation::FieldTooLarge { .. }
        | Violation::EvidenceLimitExceeded { .. }
        | Violation::DependencyLimitExceeded { .. }
        | Violation::DelegationLimitExceeded { .. }
        | Violation::ClarificationLimitExceeded { .. }
        | Violation::EscalationLimitExceeded { .. }
        | Violation::FinishClaimLimitExceeded { .. } => Reason::PolicyLimitExceeded,
        Violation::DirectiveShapeMismatch { .. }
        | Violation::DirectiveTargetNotPending { .. }
        | Violation::FinishRequiresEmptyPatch
        | Violation::DuplicateFinishClaim { .. } => Reason::DirectiveInvalid,
        Violation::PolicySnapshotInvalid
        | Violation::ObligationCatalogInvalid
        | Violation::ContextCatalogInvalid
        | Violation::BasePlanInvalid
        | Violation::ObligationSnapshotMismatch
        | Violation::AcceptancePolicyMismatch
        | Violation::ContextManifestMismatch
        | Violation::PlannerPolicyMismatch
        | Violation::EmptyText { .. }
        | Violation::InvalidLocalWorkOrderId { .. }
        | Violation::InvalidLocalVerificationTargetId { .. }
        | Violation::DuplicateLocalWorkOrderId { .. }
        | Violation::DuplicateLocalVerificationTargetId { .. }
        | Violation::UnknownObligation { .. }
        | Violation::ObligationDigestMismatch { .. }
        | Violation::EmptyObligationSet { .. }
        | Violation::UnknownWorkOrder { .. }
        | Violation::UnknownNewWorkOrder { .. }
        | Violation::WorkOrderOperationConflict { .. }
        | Violation::ImmutableWorkOrder { .. }
        | Violation::UnknownVerificationTarget { .. }
        | Violation::UnknownNewVerificationTarget { .. }
        | Violation::EmptyVerificationTargets { .. }
        | Violation::AccessExpansion { .. }
        | Violation::DependencyOnCancelled { .. }
        | Violation::DependencyCycle
        | Violation::PlanRevisionOverflow
        | Violation::WorkOrderRevisionOverflow { .. } => Reason::BindingMismatch,
    }
}

fn serialized_violation_entries<T: serde::Serialize>(
    violations: &[T],
    fallback: &str,
) -> Vec<String> {
    if violations.is_empty() {
        return vec![fallback.to_owned()];
    }
    violations
        .iter()
        .map(|violation| serde_json::to_string(violation).unwrap_or_else(|_| fallback.to_owned()))
        .collect()
}

fn planner_v2_classify_response(
    artifact_root: &Path,
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    response: &StructuredInferenceResponse,
) -> Result<PlannerV2ResponseClassification, StoreError> {
    let base_snapshot = read_planner_base_snapshot(artifact_root, &prepared.base_plan)?;
    let retained = validate_planner_v2_retained_prompt(artifact_root, prepared, &base_snapshot)?;
    let applied =
        birdcode_orchestrator::planner_prompt_v2::decode_and_apply_planner_replanner_v2_output(
            &retained.authoritative,
            &response.value,
            &retained.input,
        );
    match applied {
        Ok(authoritative) => {
            let prompting = serde_json::from_value::<birdcode_prompting::PlannerReplannerV2Output>(
                response.value.clone(),
            )
            .map_err(|_| StoreError::InvalidStateEvent)?;
            let protocol = protocol_planner_v2_accepted_output(
                &prompting,
                &prepared.token_reservation,
                prepared.output_budget,
            )?;
            let resulting_plan = serde_json::from_value::<
                birdcode_prompting::PlannerReplannerV2PlanSnapshot,
            >(serde_json::to_value(&authoritative.validated.plan)?)?;
            Ok(PlannerV2ResponseClassification::Accepted(
                PlannerV2AcceptedClassification {
                    prompting,
                    protocol,
                    authoritative,
                    resulting_plan,
                },
            ))
        }
        Err(birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2ApplyError::Setup(_)) => {
            Err(StoreError::InvalidStateEvent)
        }
        Err(
            birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2ApplyError::OutputDecode(_),
        ) => Ok(PlannerV2ResponseClassification::Rejected {
            reason: birdcode_protocol::PlannerTurnRejectionReasonV1::InvalidSchema,
            validation: RetainedPlanValidation {
                status: "rejected".to_owned(),
                violations: vec!["output_decode".to_owned()],
            },
        }),
        Err(
            birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2ApplyError::OutputInvariant {
                violations,
            },
        ) => Ok(PlannerV2ResponseClassification::Rejected {
            reason: strongest_planner_rejection(
                violations.iter().map(prompting_invariant_rejection),
            ),
            validation: RetainedPlanValidation {
                status: "rejected".to_owned(),
                violations: serialized_violation_entries(&violations, "output_invariant"),
            },
        }),
        Err(
            birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2ApplyError::DomainProjection {
                field,
                ..
            },
        ) => Ok(PlannerV2ResponseClassification::Rejected {
            reason: birdcode_protocol::PlannerTurnRejectionReasonV1::BindingMismatch,
            validation: RetainedPlanValidation {
                status: "rejected".to_owned(),
                violations: vec![format!("domain_projection:{field}")],
            },
        }),
        Err(birdcode_orchestrator::planner_prompt_v2::PlannerReplannerV2ApplyError::Plan(error)) => {
            Ok(PlannerV2ResponseClassification::Rejected {
                reason: strongest_planner_rejection(
                    error.violations.iter().map(plan_violation_rejection),
                ),
                validation: RetainedPlanValidation {
                    status: "rejected".to_owned(),
                    violations: serialized_violation_entries(&error.violations, "plan_validation"),
                },
            })
        }
    }
}

fn planner_work_order_binding(
    plan: &birdcode_prompting::PlannerReplannerV2PlanSnapshot,
    work_order_id: &str,
) -> Result<birdcode_protocol::PlannerDelegatedWorkOrderBindingV1, StoreError> {
    let work_order = plan
        .work_orders
        .get(work_order_id)
        .ok_or(StoreError::InvalidStateEvent)?;
    let bytes = serde_json::to_vec(work_order)?;
    let digest = Sha256Digest::of_bytes(&bytes);
    Ok(birdcode_protocol::PlannerDelegatedWorkOrderBindingV1 {
        work_order_id: work_order_id.to_owned(),
        revision: work_order.revision,
        work_order_artifact: ArtifactRef {
            sha256: digest.as_str().to_owned(),
            size_bytes: u64::try_from(bytes.len()).map_err(|_| StoreError::InvalidStateEvent)?,
            media_type: PLANNER_WORK_ORDER_V2_MEDIA_TYPE.to_owned(),
        },
        work_order_digest: digest,
    })
}

fn persist_planner_work_order_binding(
    store: &Store,
    plan: &birdcode_prompting::PlannerReplannerV2PlanSnapshot,
    work_order_id: &str,
) -> Result<birdcode_protocol::PlannerDelegatedWorkOrderBindingV1, StoreError> {
    let work_order = plan
        .work_orders
        .get(work_order_id)
        .ok_or(StoreError::InvalidStateEvent)?;
    let artifact = put_json_artifact(store, work_order, PLANNER_WORK_ORDER_V2_MEDIA_TYPE)?;
    let expected = planner_work_order_binding(plan, work_order_id)?;
    if artifact != expected.work_order_artifact {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(expected)
}

fn fresh_planner_delegate_directive_id(
    connection: &Connection,
    allocated: &BTreeSet<birdcode_protocol::PlannerDelegateDirectiveId>,
) -> Result<birdcode_protocol::PlannerDelegateDirectiveId, StoreError> {
    for _ in 0..16 {
        let candidate = birdcode_protocol::PlannerDelegateDirectiveId::new();
        if !allocated.contains(&candidate)
            && !planner_delegate_directive_id_seen(connection, candidate)?
        {
            return Ok(candidate);
        }
    }
    Err(StoreError::InvalidStateEvent)
}

fn build_planner_accepted_directive(
    store: &Store,
    accepted: &PlannerV2AcceptedClassification,
) -> Result<birdcode_protocol::PlannerAcceptedDirectiveV1, StoreError> {
    use birdcode_protocol::{PlannerAcceptedDirectiveV1 as Resolved, PlannerPromptDirectiveKindV1};
    let directive = &accepted.protocol.directive;
    let local_ids = accepted.authoritative.local_work_order_ids();
    Ok(match directive.kind {
        PlannerPromptDirectiveKindV1::Execute => {
            let selected = resolve_planner_work_selection(
                &directive.execute,
                local_ids,
                &accepted.resulting_plan,
            )?;
            let [work_order_id] = selected.as_slice() else {
                return Err(StoreError::InvalidStateEvent);
            };
            Resolved::Execute {
                work_order: persist_planner_work_order_binding(
                    store,
                    &accepted.resulting_plan,
                    work_order_id,
                )?,
            }
        }
        PlannerPromptDirectiveKindV1::Delegate => {
            let mut allocated = BTreeSet::new();
            let mut delegations = Vec::with_capacity(directive.delegations.len());
            for (index, delegation) in directive.delegations.iter().enumerate() {
                let selected = resolve_planner_work_selection(
                    &delegation.work_orders,
                    local_ids,
                    &accepted.resulting_plan,
                )?;
                if selected.is_empty() {
                    return Err(StoreError::InvalidStateEvent);
                }
                let work_orders = selected
                    .iter()
                    .map(|id| {
                        persist_planner_work_order_binding(store, &accepted.resulting_plan, id)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let directive_id =
                    fresh_planner_delegate_directive_id(&store.connection, &allocated)?;
                allocated.insert(directive_id);
                delegations.push(birdcode_protocol::PlannerAcceptedDelegationV1 {
                    directive_id,
                    source_delegation_index: u32::try_from(index)
                        .map_err(|_| StoreError::InvalidStateEvent)?,
                    work_orders,
                });
            }
            Resolved::Delegate { delegations }
        }
        PlannerPromptDirectiveKindV1::Clarify => Resolved::Clarify {
            requests: directive.clarifications.clone(),
        },
        PlannerPromptDirectiveKindV1::Escalate => Resolved::Escalate {
            requests: directive.escalations.clone(),
        },
        PlannerPromptDirectiveKindV1::Finish => Resolved::FinishPendingGate {
            claims: directive.finish_claims.clone(),
        },
    })
}

fn planner_v2_observed_response(
    artifact_root: &Path,
    observed_event: &EventEnvelope,
) -> Result<StructuredInferenceResponse, StoreError> {
    let EventPayload::PlannerTurnObservedV1(observed) = &observed_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if !matches!(
        observed.outcome,
        birdcode_protocol::PlannerTurnObservationV1::Succeeded { .. }
    ) {
        return Err(StoreError::InvalidStateEvent);
    }
    let retained = read_canonical_json_artifact::<RetainedInferenceEvidence>(
        artifact_root,
        &observed.normalized_complete_evidence_artifact,
        INFERENCE_EVIDENCE_MEDIA_TYPE,
    )?;
    let RetainedInferenceEvidence::Response { response } = retained else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(response)
}

#[allow(
    clippy::too_many_lines,
    reason = "one finalizer owns accepted, rejected, and terminal artifact derivation"
)]
pub(super) fn build_planner_v2_decision_event(
    store: &mut Store,
    projection: &ReconRunProjection,
    prepared_event: &EventEnvelope,
    observed_event: &EventEnvelope,
    authority: &PlannerV2FinalizationAuthority,
) -> Result<(IdempotentAppendOutcome, PlannerV2FinalizationDisposition), StoreError> {
    let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let EventPayload::PlannerTurnObservedV1(observed) = &observed_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if observed.prepared_event_id != prepared_event.id
        || observed.turn_id != prepared.turn_id
        || !same_runtime_not_before(&observed.observed_at, &authority.finalized_at)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let actor_id = projection
        .guard
        .latest_claim
        .as_ref()
        .map(|claim| claim.event.actor_id)
        .ok_or(StoreError::InvalidStateEvent)?;
    let response = planner_v2_observed_response(&store.artifact_root, observed_event)?;
    match planner_v2_classify_response(&store.artifact_root, prepared, &response)? {
        PlannerV2ResponseClassification::Accepted(accepted) => {
            let output_artifact = put_json_artifact(
                store,
                &accepted.protocol,
                birdcode_protocol::PLANNER_PROMPT_OUTPUT_V2_MEDIA_TYPE,
            )?;
            let validation = RetainedPlanValidation {
                status: "accepted".to_owned(),
                violations: Vec::new(),
            };
            let validation_artifact =
                put_json_artifact(store, &validation, PLAN_VALIDATION_MEDIA_TYPE)?;
            let resulting_plan = if accepted.prompting.patch
                == birdcode_prompting::PlannerReplannerPlanPatch::default()
            {
                prepared.base_plan.clone()
            } else {
                let plan_artifact =
                    put_json_artifact(store, &accepted.resulting_plan, PLANNER_PLAN_V2_MEDIA_TYPE)?;
                birdcode_protocol::PlannerBasePlanBindingV1 {
                    accepted_event_id: authority.event_id,
                    revision: accepted.resulting_plan.revision,
                    digest: Sha256Digest::parse(plan_artifact.sha256.clone())
                        .map_err(|_| StoreError::InvalidStateEvent)?,
                    artifact: plan_artifact,
                }
            };
            let resolved_directive = build_planner_accepted_directive(store, &accepted)?;
            let output_digest = Sha256Digest::parse(output_artifact.sha256.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?;
            let validation_digest = Sha256Digest::parse(validation_artifact.sha256.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?;
            let append = store.append_identified_event(IdentifiedNewEvent {
                event_id: authority.event_id,
                event: NewEvent {
                    session_id: projection.session_id,
                    run_id: Some(projection.run_id),
                    actor_id,
                    causal_parent: Some(observed_event.id),
                    provenance: Provenance {
                        producer: PLANNER_V2_FINALIZATION_PRODUCER.to_owned(),
                        backend: None,
                        raw_artifact: Some(validation_artifact.clone()),
                    },
                    payload: EventPayload::PlannerTurnAcceptedV1(
                        birdcode_protocol::PlannerTurnAcceptedV1 {
                            turn_id: prepared.turn_id,
                            purpose: prepared.purpose,
                            prepared_event_id: prepared_event.id,
                            observed_event_id: observed_event.id,
                            base_plan: prepared.base_plan.clone(),
                            resulting_plan,
                            accepted_prompt_output_artifact: output_artifact,
                            accepted_prompt_output_digest: output_digest,
                            accepted_prompt_output: accepted.protocol,
                            resolved_directive,
                            validation_evidence_artifact: validation_artifact,
                            validation_evidence_digest: validation_digest,
                            accepted_at: authority.finalized_at.clone(),
                        },
                    ),
                },
            })?;
            Ok((append, PlannerV2FinalizationDisposition::Accepted))
        }
        PlannerV2ResponseClassification::Rejected { reason, validation } => {
            let output_artifact = store.put_artifact(
                response.raw_text.as_bytes(),
                birdcode_protocol::PLANNER_PROMPT_OUTPUT_V2_MEDIA_TYPE,
            )?;
            let validation_artifact =
                put_json_artifact(store, &validation, PLAN_VALIDATION_MEDIA_TYPE)?;
            let output_digest = Sha256Digest::parse(output_artifact.sha256.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?;
            let validation_digest = Sha256Digest::parse(validation_artifact.sha256.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?;
            let append = store.append_identified_event(IdentifiedNewEvent {
                event_id: authority.event_id,
                event: NewEvent {
                    session_id: projection.session_id,
                    run_id: Some(projection.run_id),
                    actor_id,
                    causal_parent: Some(observed_event.id),
                    provenance: Provenance {
                        producer: PLANNER_V2_FINALIZATION_PRODUCER.to_owned(),
                        backend: None,
                        raw_artifact: Some(validation_artifact.clone()),
                    },
                    payload: EventPayload::PlannerTurnRejectedV1(
                        birdcode_protocol::PlannerTurnRejectedV1 {
                            turn_id: prepared.turn_id,
                            purpose: prepared.purpose,
                            prepared_event_id: prepared_event.id,
                            observed_event_id: observed_event.id,
                            base_plan: prepared.base_plan.clone(),
                            rejected_output_artifact: output_artifact,
                            rejected_output_digest: output_digest,
                            reason,
                            validation_evidence_artifact: validation_artifact,
                            validation_evidence_digest: validation_digest,
                            rejected_at: authority.finalized_at.clone(),
                        },
                    ),
                },
            })?;
            Ok((append, PlannerV2FinalizationDisposition::Rejected(reason)))
        }
    }
}

pub(super) fn build_planner_v2_run_terminal_event(
    store: &mut Store,
    projection: &ReconRunProjection,
    prepared_event: &EventEnvelope,
    terminal_event: &EventEnvelope,
    authority: &PlannerV2FinalizationAuthority,
    cancelled: bool,
) -> Result<(IdempotentAppendOutcome, PlannerV2FinalizationDisposition), StoreError> {
    let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let terminal_at = match &terminal_event.payload {
        EventPayload::PlannerTurnObservedV1(observed)
            if observed.prepared_event_id == prepared_event.id
                && observed.turn_id == prepared.turn_id
                && matches!(
                    observed.outcome,
                    birdcode_protocol::PlannerTurnObservationV1::Failed { .. }
                ) =>
        {
            &observed.observed_at
        }
        EventPayload::PlannerTurnUnknownV1(unknown)
            if unknown.prepared_event_id == prepared_event.id
                && unknown.turn_id == prepared.turn_id =>
        {
            &unknown.boundary_at
        }
        _ => return Err(StoreError::InvalidStateEvent),
    };
    let claim = projection
        .guard
        .latest_claim
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    if authority.finalized_at.runtime_instance_id != claim.claim.runtime_instance_id
        || terminal_at.runtime_instance_id == authority.finalized_at.runtime_instance_id
            && !same_runtime_not_before(terminal_at, &authority.finalized_at)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let disposition = if cancelled {
        RetainedPlannerV2TerminalDisposition::Cancelled
    } else {
        RetainedPlannerV2TerminalDisposition::Failed
    };
    let retained = RetainedPlannerV2FinalizationEvidence {
        prepared_event_id: prepared_event.id,
        terminal_event_id: terminal_event.id,
        finalized_at: authority.finalized_at.clone(),
        disposition,
    };
    let artifact = put_json_artifact(
        store,
        &retained,
        PLANNER_V2_FINALIZATION_EVIDENCE_MEDIA_TYPE,
    )?;
    let to = if cancelled {
        RunState::Cancelled
    } else {
        RunState::Failed
    };
    let append = store.append_identified_event(IdentifiedNewEvent {
        event_id: authority.event_id,
        event: NewEvent {
            session_id: projection.session_id,
            run_id: Some(projection.run_id),
            actor_id: claim.event.actor_id,
            causal_parent: Some(projection.last_event.id),
            provenance: Provenance {
                producer: PLANNER_V2_FINALIZATION_PRODUCER.to_owned(),
                backend: None,
                raw_artifact: Some(artifact),
            },
            payload: EventPayload::RunStateChanged {
                from: RunState::Running,
                to,
            },
        },
    })?;
    Ok((
        append,
        if cancelled {
            PlannerV2FinalizationDisposition::RunCancelled
        } else {
            PlannerV2FinalizationDisposition::RunFailed
        },
    ))
}

fn resolve_planner_work_selection(
    selection: &birdcode_protocol::PlannerPromptWorkSelectionV1,
    local_ids: &BTreeMap<
        birdcode_orchestrator::planner::LocalWorkOrderId,
        birdcode_orchestrator::planner::PlanWorkOrderId,
    >,
    plan: &birdcode_prompting::PlannerReplannerV2PlanSnapshot,
) -> Result<Vec<String>, StoreError> {
    let mut resolved = selection.existing.iter().cloned().collect::<BTreeSet<_>>();
    for local_id in &selection.new {
        resolved.insert(
            local_ids
                .get(&birdcode_orchestrator::planner::LocalWorkOrderId(
                    local_id.0,
                ))
                .map(ToString::to_string)
                .ok_or(StoreError::InvalidStateEvent)?,
        );
    }
    if resolved
        .iter()
        .any(|work_order_id| !plan.work_orders.contains_key(work_order_id))
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(resolved.into_iter().collect())
}

fn planner_delegate_directive_id_seen(
    connection: &Connection,
    directive_id: birdcode_protocol::PlannerDelegateDirectiveId,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM events AS event,
                      json_each(
                          event.value_json,
                          '$.payload.data.resolved_directive.delegations'
                      ) AS delegation
                 WHERE json_extract(event.value_json, '$.payload.type')
                           = 'planner_turn_accepted_v1'
                   AND json_extract(
                           event.value_json,
                           '$.payload.data.resolved_directive.directive'
                       ) = 'delegate'
                   AND json_extract(delegation.value, '$.directive_id') = ?1
             )",
            [directive_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

pub(super) fn validate_planner_prompt_directive_shape(
    connection: &Connection,
    output: &PlannerPromptV2AcceptedOutputV1,
    resulting_plan: &birdcode_prompting::PlannerReplannerV2PlanSnapshot,
    authoritative: &birdcode_orchestrator::planner_prompt_v2::ValidatedPlannerReplannerV2Turn,
    resolved: &birdcode_protocol::PlannerAcceptedDirectiveV1,
) -> Result<(), StoreError> {
    use birdcode_protocol::{PlannerAcceptedDirectiveV1 as Accepted, PlannerPromptDirectiveKindV1};
    let directive = &output.directive;
    let local_ids = authoritative.local_work_order_ids();
    let authoritative_directive = &authoritative.validated.directive;
    let branch_valid = match (directive.kind, resolved) {
        (PlannerPromptDirectiveKindV1::Execute, Accepted::Execute { work_order }) => {
            let selected =
                resolve_planner_work_selection(&directive.execute, local_ids, resulting_plan)?;
            let expected = selected
                .first()
                .filter(|_| selected.len() == 1)
                .map(|id| planner_work_order_binding(resulting_plan, id))
                .transpose()?;
            matches!(
                authoritative_directive,
                birdcode_orchestrator::planner::ResolvedPlannerDirective::Execute {
                    work_order_id,
                } if selected.first().is_some_and(|id| id == &work_order_id.to_string())
            ) && expected.as_ref() == Some(work_order)
        }
        (PlannerPromptDirectiveKindV1::Delegate, Accepted::Delegate { delegations }) => {
            if delegations.len() == directive.delegations.len() {
                let mut directive_ids = BTreeSet::new();
                let mut all_work_order_ids = BTreeSet::new();
                let mut exact = true;
                for (index, accepted) in delegations.iter().enumerate() {
                    let selected = resolve_planner_work_selection(
                        &directive.delegations[index].work_orders,
                        local_ids,
                        resulting_plan,
                    )?;
                    let expected = selected
                        .iter()
                        .map(|id| planner_work_order_binding(resulting_plan, id))
                        .collect::<Result<Vec<_>, _>>()?;
                    exact &= accepted.source_delegation_index
                        == u32::try_from(index).map_err(|_| StoreError::InvalidStateEvent)?
                        && !expected.is_empty()
                        && accepted.work_orders == expected
                        && directive_ids.insert(accepted.directive_id)
                        && !planner_delegate_directive_id_seen(connection, accepted.directive_id)?;
                    for id in selected {
                        exact &= all_work_order_ids.insert(id);
                    }
                }
                let authoritative_ids = match authoritative_directive {
                    birdcode_orchestrator::planner::ResolvedPlannerDirective::Delegate {
                        work_order_ids,
                    } => work_order_ids
                        .iter()
                        .map(ToString::to_string)
                        .collect::<BTreeSet<_>>(),
                    _ => BTreeSet::new(),
                };
                exact && all_work_order_ids == authoritative_ids
            } else {
                false
            }
        }
        (PlannerPromptDirectiveKindV1::Clarify, Accepted::Clarify { requests }) => {
            matches!(
                authoritative_directive,
                birdcode_orchestrator::planner::ResolvedPlannerDirective::Clarify { .. }
            ) && requests == &directive.clarifications
        }
        (PlannerPromptDirectiveKindV1::Escalate, Accepted::Escalate { requests }) => {
            matches!(
                authoritative_directive,
                birdcode_orchestrator::planner::ResolvedPlannerDirective::Escalate { .. }
            ) && requests == &directive.escalations
        }
        (PlannerPromptDirectiveKindV1::Finish, Accepted::FinishPendingGate { claims }) => {
            matches!(
                authoritative_directive,
                birdcode_orchestrator::planner::ResolvedPlannerDirective::FinishPendingGate { .. }
            ) && claims == &directive.finish_claims
        }
        _ => false,
    };
    if branch_valid {
        Ok(())
    } else {
        Err(StoreError::InvalidStateEvent)
    }
}

pub(super) fn validate_planner_accepted_bindings(
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    output: &PlannerPromptV2AcceptedOutputV1,
    artifact_root: &Path,
) -> Result<(), StoreError> {
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
    let max_output = u32::try_from(prepared.token_reservation.max_output_tokens)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let bindings = &output.bindings;
    let prompt_key = birdcode_prompting::planner_replanner_v2_key();
    let base_snapshot = read_planner_base_snapshot(artifact_root, &prepared.base_plan)?;
    if output.schema_version != birdcode_protocol::PLANNER_EVIDENCE_CONTRACT_VERSION
        || bindings.purpose != prepared.purpose
        || bindings.prompt_id != prompt_key.id.as_str()
        || bindings.prompt_version != prompt_key.version.to_string()
        || bindings.prompt_manifest_sha256 != prepared.prompt_manifest_digest
        || bindings.plan_id != base_snapshot.plan_id
        || bindings.base_revision != prepared.base_plan.revision
        || bindings.base_plan_sha256 != prepared.base_plan.digest
        || bindings.obligation_snapshot_sha256 != prepared.obligation_snapshot_digest
        || bindings.acceptance_policy_sha256 != prepared.acceptance_policy_digest
        || bindings.context_manifest_sha256 != prepared.context_manifest_digest
        || bindings.planner_policy_sha256 != prepared.planner_policy_digest
        || bindings.evidence_packet_sha256.as_str() != prompt_packet.packet_sha256
        || bindings
            .previous_evidence_packet_sha256
            .as_ref()
            .map(Sha256Digest::as_str)
            != prompt_delta.previous_packet_sha256.as_deref()
        || bindings.evidence_delta_sha256.as_str() != prompt_delta.delta_sha256
        || bindings.backend_id != prepared.backend_model.backend_id
        || bindings.model_id != prepared.backend_model.model_id
        || bindings.reasoning != prepared.reasoning
        || bindings.budget_reservation_id != prepared.token_reservation.id
        || bindings.max_output_tokens != max_output
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "planner acceptance is one atomic replay boundary over request, output, plan, and directive"
)]
pub(super) fn validate_planner_turn_accepted_v1(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    accepted: &birdcode_protocol::PlannerTurnAcceptedV1,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let observed_event = stored_event_for_run(
        transaction,
        event.session_id,
        run_id,
        accepted.observed_event_id,
    )?;
    let EventPayload::PlannerTurnObservedV1(observed) = &observed_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let prepared_event = stored_event_for_run(
        transaction,
        event.session_id,
        run_id,
        accepted.prepared_event_id,
    )?;
    let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if event.causal_parent != Some(observed_event.id)
        || prepared_event.sequence >= observed_event.sequence
        || observed_event.sequence >= event.sequence
        || observed.turn_id != accepted.turn_id
        || observed.prepared_event_id != prepared_event.id
        || !matches!(
            observed.outcome,
            birdcode_protocol::PlannerTurnObservationV1::Succeeded { .. }
        )
        || prepared.turn_id != accepted.turn_id
        || planner_turn_decision_count(transaction, accepted.turn_id)? != 0
        || accepted.purpose != prepared.purpose
        || accepted.base_plan != prepared.base_plan
        || !digest_matches_artifact(
            &accepted.accepted_prompt_output_digest,
            &accepted.accepted_prompt_output_artifact,
        )
        || !digest_matches_artifact(
            &accepted.validation_evidence_digest,
            &accepted.validation_evidence_artifact,
        )
        || event.provenance.backend.is_some()
        || event.provenance.producer != PLANNER_V2_FINALIZATION_PRODUCER
        || event.provenance.raw_artifact.as_ref() != Some(&accepted.validation_evidence_artifact)
        || !same_runtime_not_before(&observed.observed_at, &accepted.accepted_at)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let retained = read_canonical_json_artifact::<PlannerPromptV2AcceptedOutputV1>(
        artifact_root,
        &accepted.accepted_prompt_output_artifact,
        birdcode_protocol::PLANNER_PROMPT_OUTPUT_V2_MEDIA_TYPE,
    )?;
    let observed_evidence = read_canonical_json_artifact::<RetainedInferenceEvidence>(
        artifact_root,
        &observed.normalized_complete_evidence_artifact,
        INFERENCE_EVIDENCE_MEDIA_TYPE,
    )?;
    let RetainedInferenceEvidence::Response { response } = observed_evidence else {
        return Err(StoreError::InvalidStateEvent);
    };
    let validation = read_canonical_json_artifact::<RetainedPlanValidation>(
        artifact_root,
        &accepted.validation_evidence_artifact,
        PLAN_VALIDATION_MEDIA_TYPE,
    )?;
    if retained != accepted.accepted_prompt_output
        || response.value != serde_json::to_value(&retained)?
        || validation
            != (RetainedPlanValidation {
                status: "accepted".to_owned(),
                violations: Vec::new(),
            })
    {
        return Err(StoreError::InvalidStateEvent);
    }
    validate_planner_accepted_bindings(prepared, &retained, artifact_root)?;
    let prompting = prompting_planner_v2_accepted_output(
        &retained,
        &prepared.token_reservation,
        prepared.output_budget,
    )?;
    if serde_json::to_value(&prompting)? != serde_json::to_value(&retained)? {
        return Err(StoreError::InvalidStateEvent);
    }
    let authoritative = validate_authoritative_planner_apply(artifact_root, prepared, &prompting)?;
    let expected_plan = serde_json::from_value::<birdcode_prompting::PlannerReplannerV2PlanSnapshot>(
        serde_json::to_value(&authoritative.validated.plan)?,
    )?;
    let base_snapshot = read_planner_base_snapshot(artifact_root, &prepared.base_plan)?;
    let patch_is_empty =
        prompting.patch == birdcode_prompting::PlannerReplannerPlanPatch::default();
    if patch_is_empty {
        if expected_plan != base_snapshot || accepted.resulting_plan != accepted.base_plan {
            return Err(StoreError::InvalidStateEvent);
        }
    } else {
        let plan_bytes = serde_json::to_vec(&expected_plan)?;
        let plan_digest = Sha256Digest::of_bytes(&plan_bytes);
        let expected_binding = birdcode_protocol::PlannerBasePlanBindingV1 {
            accepted_event_id: event.id,
            revision: expected_plan.revision,
            digest: plan_digest,
            artifact: ArtifactRef {
                sha256: sha256_hex(&plan_bytes),
                size_bytes: u64::try_from(plan_bytes.len())
                    .map_err(|_| StoreError::InvalidStateEvent)?,
                media_type: PLANNER_PLAN_V2_MEDIA_TYPE.to_owned(),
            },
        };
        if accepted.resulting_plan != expected_binding
            || read_planner_base_snapshot(artifact_root, &accepted.resulting_plan)? != expected_plan
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    validate_planner_prompt_directive_shape(
        transaction,
        &retained,
        &expected_plan,
        &authoritative,
        &accepted.resolved_directive,
    )
}

pub(super) fn validate_planner_turn_rejected_v1(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    rejected: &birdcode_protocol::PlannerTurnRejectedV1,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let observed_event = stored_event_for_run(
        transaction,
        event.session_id,
        run_id,
        rejected.observed_event_id,
    )?;
    let EventPayload::PlannerTurnObservedV1(observed) = &observed_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let prepared_event = stored_event_for_run(
        transaction,
        event.session_id,
        run_id,
        rejected.prepared_event_id,
    )?;
    let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if event.causal_parent != Some(observed_event.id)
        || prepared_event.sequence >= observed_event.sequence
        || observed_event.sequence >= event.sequence
        || observed.turn_id != rejected.turn_id
        || observed.prepared_event_id != prepared_event.id
        || !matches!(
            observed.outcome,
            birdcode_protocol::PlannerTurnObservationV1::Succeeded { .. }
        )
        || prepared.turn_id != rejected.turn_id
        || planner_turn_decision_count(transaction, rejected.turn_id)? != 0
        || rejected.purpose != prepared.purpose
        || rejected.base_plan != prepared.base_plan
        || !digest_matches_artifact(
            &rejected.rejected_output_digest,
            &rejected.rejected_output_artifact,
        )
        || !digest_matches_artifact(
            &rejected.validation_evidence_digest,
            &rejected.validation_evidence_artifact,
        )
        || rejected.rejected_output_artifact.media_type
            != birdcode_protocol::PLANNER_PROMPT_OUTPUT_V2_MEDIA_TYPE
        || event.provenance.backend.is_some()
        || event.provenance.producer != PLANNER_V2_FINALIZATION_PRODUCER
        || event.provenance.raw_artifact.as_ref() != Some(&rejected.validation_evidence_artifact)
        || !same_runtime_not_before(&observed.observed_at, &rejected.rejected_at)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let rejected_bytes = read_verified_artifact(
        &artifact_path_at(artifact_root, &rejected.rejected_output_artifact.sha256)?,
        &rejected.rejected_output_artifact,
    )?;
    let evidence = read_canonical_json_artifact::<RetainedInferenceEvidence>(
        artifact_root,
        &observed.normalized_complete_evidence_artifact,
        INFERENCE_EVIDENCE_MEDIA_TYPE,
    )?;
    let RetainedInferenceEvidence::Response { response } = evidence else {
        return Err(StoreError::InvalidStateEvent);
    };
    let validation = read_canonical_json_artifact::<RetainedPlanValidation>(
        artifact_root,
        &rejected.validation_evidence_artifact,
        PLAN_VALIDATION_MEDIA_TYPE,
    )?;
    if rejected_bytes != response.raw_text.as_bytes() {
        return Err(StoreError::InvalidStateEvent);
    }
    let PlannerV2ResponseClassification::Rejected {
        reason,
        validation: expected_validation,
    } = planner_v2_classify_response(artifact_root, prepared, &response)?
    else {
        return Err(StoreError::InvalidStateEvent);
    };
    if rejected.reason != reason || validation != expected_validation {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}
