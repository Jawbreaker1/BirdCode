//! Planner-v2 durable evidence construction, projection, and authority validation.

use super::{
    ACCEPTED_PLAN_MEDIA_TYPE, ArtifactRef, BTreeMap, BTreeSet, CHILD_EXECUTION_FAILURE_MEDIA_TYPE,
    CHILD_HANDOFF_MEDIA_TYPE, CHILD_RECONNAISSANCE_CONTRACT_VERSION, ChildCancellationCauseV1,
    ChildExecutionBinding, ChildExecutionFailureCauseV1, ChildExecutionFailureEvidenceV1,
    ChildExecutionFailureKind, ChildExecutionOutcome, ChildHandoffDocument, Connection,
    EventEnvelope, EventId, EventPayload, MAX_PLANNER_V2_EVIDENCE_ENTRIES, MAX_SQLITE_INTEGER_U64,
    OptionalExtension, PLANNER_PLAN_V2_MEDIA_TYPE, Path, PlannerV2ObservedEvidence,
    RetainedInferenceEvidence, RetryDisposition, RootPlannerOutput, RunId, SessionId, Sha256Digest,
    Store, StoreError, UnknownInferenceBoundary, decode_canonical_event, digest_matches_artifact,
    latest_cancellation_for_run_before, latest_planner_prepared_before, params, planner_run_id,
    project_child_work_order, prompt_evidence_artifact_ref, put_json_artifact,
    read_canonical_json_artifact, stored_event_for_run,
};

pub(super) fn retained_planner_v2_evidence(
    evidence: &PlannerV2ObservedEvidence,
) -> RetainedInferenceEvidence {
    match evidence {
        PlannerV2ObservedEvidence::Response(response) => RetainedInferenceEvidence::Response {
            response: response.clone(),
        },
        PlannerV2ObservedEvidence::Error(error) => RetainedInferenceEvidence::Error {
            error: error.clone(),
        },
        PlannerV2ObservedEvidence::NotDispatched { reason } => {
            RetainedInferenceEvidence::NotDispatched { reason: *reason }
        }
        PlannerV2ObservedEvidence::CancelledBeforeCall => {
            RetainedInferenceEvidence::CancelledBeforeCall
        }
    }
}

pub(super) const fn planner_v2_unknown_reason(
    boundary: UnknownInferenceBoundary,
) -> birdcode_protocol::UnknownInferenceOutcomeReason {
    match boundary {
        UnknownInferenceBoundary::Restart | UnknownInferenceBoundary::Shutdown => {
            birdcode_protocol::UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation
        }
        UnknownInferenceBoundary::ClaimRenewalFailed => {
            birdcode_protocol::UnknownInferenceOutcomeReason::ClaimExpiredBeforeObservation
        }
        UnknownInferenceBoundary::Deadline | UnknownInferenceBoundary::Cancelled => {
            birdcode_protocol::UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate
        }
    }
}

pub(super) fn planner_v2_cancellation_cause_before(
    connection: &Connection,
    session_id: SessionId,
    run_id: RunId,
    boundary: UnknownInferenceBoundary,
    upper_sequence_exclusive: u64,
) -> Result<Option<ChildCancellationCauseV1>, StoreError> {
    if boundary != UnknownInferenceBoundary::Cancelled {
        return Ok(None);
    }
    let event = latest_cancellation_for_run_before(
        connection,
        session_id,
        run_id,
        upper_sequence_exclusive,
    )?
    .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::CancellationRequested(request) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(Some(ChildCancellationCauseV1 {
        request_event_id: event.id,
        request_id: request.cancellation_request_id,
        cancellation_generation: request.cancellation_generation,
    }))
}

pub(super) fn planner_v2_cancellation_cause(
    connection: &Connection,
    session_id: SessionId,
    run_id: RunId,
    boundary: UnknownInferenceBoundary,
) -> Result<Option<ChildCancellationCauseV1>, StoreError> {
    planner_v2_cancellation_cause_before(
        connection,
        session_id,
        run_id,
        boundary,
        MAX_SQLITE_INTEGER_U64,
    )
}

type PromptPlannerEvidenceEntry = birdcode_prompting::PlannerReplannerV2EvidenceEntry;
type DurablePlannerEvidenceMaterial = birdcode_protocol::PlannerEvidenceMaterialV2;

struct PlannerEvidencePair {
    prompt: PromptPlannerEvidenceEntry,
    durable_id: birdcode_protocol::PlannerEvidenceEntryId,
    durable: DurablePlannerEvidenceMaterial,
}

fn root_planner_evidence_pair(
    connection: &Connection,
    artifact_root: &Path,
    session_id: SessionId,
    run_id: RunId,
) -> Result<PlannerEvidencePair, StoreError> {
    let root = accepted_root_plan_projection(connection, session_id, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let review_event =
        stored_event_for_run(connection, session_id, run_id, root.accepted_plan_event_id)?;
    let EventPayload::PlanSemanticReviewAccepted(review) = &review_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let plan = read_canonical_json_artifact::<RootPlannerOutput>(
        artifact_root,
        &review.candidate.plan_artifact,
        ACCEPTED_PLAN_MEDIA_TYPE,
    )?;
    let prompt = PromptPlannerEvidenceEntry::new(
        birdcode_prompting::PlannerReplannerV2EvidenceMaterial::AcceptedRootPlan {
            evidence_id: review_event.id.to_string(),
            accepted_root_plan: birdcode_prompting::PlannerAcceptedRootPlanEvidenceV2 {
                contract_version: birdcode_protocol::PLANNER_EVIDENCE_CONTRACT_VERSION,
                review_event_id: review_event.id.to_string(),
                review_id: review.review_id.to_string(),
                proposal_event_id: review.candidate.proposal_event_id.to_string(),
                plan_revision: review.candidate.plan_revision,
                plan_digest: review.candidate.plan_digest.as_str().to_owned(),
                plan_artifact: prompt_evidence_artifact_ref(&review.candidate.plan_artifact),
                critique_artifact: prompt_evidence_artifact_ref(&review.critique_artifact),
                validation_evidence_artifact: prompt_evidence_artifact_ref(
                    &review.validation_evidence_artifact,
                ),
                plan,
            },
        },
    )
    .map_err(|_| StoreError::InvalidStateEvent)?;
    Ok(PlannerEvidencePair {
        prompt,
        durable_id: birdcode_protocol::PlannerEvidenceEntryId::from_uuid(review_event.id.as_uuid()),
        durable: DurablePlannerEvidenceMaterial::AcceptedRootPlan(root),
    })
}

fn prompting_child_binding(
    binding: &ChildExecutionBinding,
) -> Result<birdcode_prompting::PlannerChildExecutionBinding, StoreError> {
    serde_json::from_value(serde_json::to_value(binding)?)
        .map_err(|_| StoreError::InvalidStateEvent)
}

fn prompting_child_handoff(
    document: &ChildHandoffDocument,
) -> Result<birdcode_prompting::PlannerChildHandoff, StoreError> {
    serde_json::from_value(serde_json::json!({
        "contract_version": document.contract_version,
        "binding": document.binding,
        "handoff_id": document.handoff_id,
        "status": document.content.status,
        "summary": document.content.summary,
        "findings": document.content.findings,
        "unknowns": document.content.unknowns,
        "recommended_followups": document.content.recommended_followups,
    }))
    .map_err(|_| StoreError::InvalidStateEvent)
}

fn child_failure_evidence_for_planner(
    store: &Store,
    event: &EventEnvelope,
    finished: &birdcode_protocol::ChildExecutionFinished,
    kind: ChildExecutionFailureKind,
    retry: RetryDisposition,
    cause: &ChildExecutionFailureCauseV1,
) -> Result<(ArtifactRef, ChildExecutionFailureEvidenceV1), StoreError> {
    if let ChildExecutionFailureCauseV1::RuntimeEvidence {
        evidence_artifact,
        evidence_digest,
    } = cause
    {
        if !digest_matches_artifact(evidence_digest, evidence_artifact) {
            return Err(StoreError::InvalidStateEvent);
        }
        let evidence = read_canonical_json_artifact::<ChildExecutionFailureEvidenceV1>(
            &store.artifact_root,
            evidence_artifact,
            CHILD_EXECUTION_FAILURE_MEDIA_TYPE,
        )?;
        if evidence.binding != finished.binding || evidence.kind != kind || evidence.retry != retry
        {
            return Err(StoreError::InvalidStateEvent);
        }
        return Ok((evidence_artifact.clone(), evidence));
    }
    let source_event_id = match cause {
        ChildExecutionFailureCauseV1::ModelTerminal {
            terminal_event_id, ..
        }
        | ChildExecutionFailureCauseV1::ToolTerminal {
            terminal_event_id, ..
        } => *terminal_event_id,
        ChildExecutionFailureCauseV1::RuntimeEvidence { .. } => unreachable!(),
    };
    let source = stored_event_for_run(
        &store.connection,
        event.session_id,
        event.run_id.ok_or(StoreError::InvalidStateEvent)?,
        source_event_id,
    )?;
    if source.sequence >= event.sequence {
        return Err(StoreError::InvalidStateEvent);
    }
    let evidence = ChildExecutionFailureEvidenceV1 {
        contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        binding: finished.binding.clone(),
        kind,
        retry,
        diagnostic: serde_json::to_value(source)?,
    };
    let artifact = put_json_artifact(store, &evidence, CHILD_EXECUTION_FAILURE_MEDIA_TYPE)?;
    Ok((artifact, evidence))
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed outcome match preserves exact child evidence provenance"
)]
fn child_planner_evidence_pair(
    store: &Store,
    event: &EventEnvelope,
    finished: &birdcode_protocol::ChildExecutionFinished,
) -> Result<PlannerEvidencePair, StoreError> {
    let run_id = event.run_id.ok_or(StoreError::InvalidStateEvent)?;
    let projection = project_child_work_order(
        &store.connection,
        &store.artifact_root,
        run_id,
        finished.binding.work_order_id,
    )?
    .ok_or(StoreError::InvalidStateEvent)?;
    if !projection.attempts.iter().any(|attempt| {
        attempt.attempt_id == finished.binding.attempt_id
            && attempt.terminal_event_id == Some(event.id)
            && attempt.outcome.as_ref() == Some(&finished.outcome)
    }) {
        return Err(StoreError::InvalidStateEvent);
    }
    let evidence_id = event.id.to_string();
    let durable_id = birdcode_protocol::PlannerEvidenceEntryId::from_uuid(event.id.as_uuid());
    let (prompt_material, durable) = match &finished.outcome {
        ChildExecutionOutcome::Succeeded { .. } => {
            let handoff_event_id = finished
                .handoff_event_id
                .ok_or(StoreError::InvalidStateEvent)?;
            let handoff_event = stored_event_for_run(
                &store.connection,
                event.session_id,
                run_id,
                handoff_event_id,
            )?;
            let EventPayload::ChildHandoffCommitted(committed) = &handoff_event.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            let document = read_canonical_json_artifact::<ChildHandoffDocument>(
                &store.artifact_root,
                &committed.handoff_artifact,
                CHILD_HANDOFF_MEDIA_TYPE,
            )?;
            let prompt_handoff = prompting_child_handoff(&document)?;
            (
                birdcode_prompting::PlannerReplannerV2EvidenceMaterial::ChildHandoff {
                    evidence_id,
                    child_handoff: birdcode_prompting::PlannerVerifiedChildHandoffV2 {
                        contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                        committed_event_id: handoff_event.id.to_string(),
                        handoff_artifact: prompt_evidence_artifact_ref(&committed.handoff_artifact),
                        handoff: prompt_handoff,
                    },
                },
                DurablePlannerEvidenceMaterial::ChildHandoff(
                    birdcode_protocol::PlannerChildHandoffEvidenceV2 {
                        binding: finished.binding.clone(),
                        handoff_event_id,
                        handoff_id: committed.handoff_id,
                        handoff_artifact: committed.handoff_artifact.clone(),
                        handoff_digest: committed.handoff_digest.clone(),
                        finished_event_id: event.id,
                    },
                ),
            )
        }
        ChildExecutionOutcome::Failed { kind, retry, cause } => {
            let (evidence_artifact, evidence) =
                child_failure_evidence_for_planner(store, event, finished, *kind, *retry, cause)?;
            let prompt_kind = serde_json::from_value(serde_json::to_value(kind)?)
                .map_err(|_| StoreError::InvalidStateEvent)?;
            let prompt_retry = serde_json::from_value(serde_json::to_value(retry)?)
                .map_err(|_| StoreError::InvalidStateEvent)?;
            let prompt_cause = serde_json::from_value(serde_json::to_value(cause)?)
                .map_err(|_| StoreError::InvalidStateEvent)?;
            let evidence_digest = Sha256Digest::parse(evidence_artifact.sha256.clone())
                .map_err(|_| StoreError::InvalidStateEvent)?;
            (
                birdcode_prompting::PlannerReplannerV2EvidenceMaterial::ChildFailed {
                    evidence_id,
                    child_failed: birdcode_prompting::PlannerChildFailedV2 {
                        contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                        binding: prompting_child_binding(&finished.binding)?,
                        finished_event_id: event.id.to_string(),
                        completed_model_calls: finished.completed_model_calls,
                        completed_tool_calls: finished.completed_tool_calls,
                        kind: prompt_kind,
                        retry: prompt_retry,
                        cause: prompt_cause,
                        evidence_artifact: prompt_evidence_artifact_ref(&evidence_artifact),
                        evidence_digest: evidence_digest.as_str().to_owned(),
                        diagnostic: evidence.diagnostic,
                    },
                },
                DurablePlannerEvidenceMaterial::ChildFailed(
                    birdcode_protocol::PlannerChildFailedEvidenceV2 {
                        binding: finished.binding.clone(),
                        finished_event_id: event.id,
                        kind: *kind,
                        retry: *retry,
                        cause: cause.clone(),
                        evidence_artifact,
                        evidence_digest,
                    },
                ),
            )
        }
        ChildExecutionOutcome::Cancelled { cause } => {
            let prompt_cause = serde_json::from_value(serde_json::to_value(cause)?)
                .map_err(|_| StoreError::InvalidStateEvent)?;
            (
                birdcode_prompting::PlannerReplannerV2EvidenceMaterial::ChildCancelled {
                    evidence_id,
                    child_cancelled: birdcode_prompting::PlannerChildCancelledV2 {
                        contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                        binding: prompting_child_binding(&finished.binding)?,
                        finished_event_id: event.id.to_string(),
                        completed_model_calls: finished.completed_model_calls,
                        completed_tool_calls: finished.completed_tool_calls,
                        cause: prompt_cause,
                    },
                },
                DurablePlannerEvidenceMaterial::ChildCancelled(
                    birdcode_protocol::PlannerChildCancelledEvidenceV2 {
                        binding: finished.binding.clone(),
                        finished_event_id: event.id,
                        cause: *cause,
                    },
                ),
            )
        }
    };
    let prompt = PromptPlannerEvidenceEntry::new(prompt_material)
        .map_err(|_| StoreError::InvalidStateEvent)?;
    Ok(PlannerEvidencePair {
        prompt,
        durable_id,
        durable,
    })
}

fn planner_evidence_pairs(
    store: &Store,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Vec<PlannerEvidencePair>, StoreError> {
    let mut pairs = vec![root_planner_evidence_pair(
        &store.connection,
        &store.artifact_root,
        session_id,
        run_id,
    )?];
    let mut statement = store.connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'child_execution_finished'
         ORDER BY sequence ASC LIMIT ?3",
    )?;
    let rows = statement
        .query_map(
            params![
                run_id.to_string(),
                session_id.to_string(),
                u64::try_from(MAX_PLANNER_V2_EVIDENCE_ENTRIES)
                    .map_err(|_| StoreError::InvalidStateEvent)?,
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() >= MAX_PLANNER_V2_EVIDENCE_ENTRIES {
        let total = store.connection.query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'child_execution_finished'",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, u64>(0),
        )?;
        if total >= MAX_PLANNER_V2_EVIDENCE_ENTRIES as u64 {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    for json in rows {
        let event = decode_canonical_event(&json)?;
        let EventPayload::ChildExecutionFinished(finished) = &event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        pairs.push(child_planner_evidence_pair(store, &event, finished)?);
    }
    Ok(pairs)
}

fn planner_context_catalog(
    entries: &[PromptPlannerEvidenceEntry],
) -> Result<birdcode_prompting::PlannerReplannerV2ContextCatalog, StoreError> {
    let mut evidence_bindings = entries
        .iter()
        .map(
            |entry| birdcode_prompting::PlannerReplannerV2ContextEvidenceBinding {
                id: entry.evidence_id().to_owned(),
                content_sha256: entry.normalized_content_sha256().to_owned(),
            },
        )
        .collect::<Vec<_>>();
    evidence_bindings.sort();
    let mut context = birdcode_prompting::PlannerReplannerV2ContextCatalog {
        manifest_sha256: String::new(),
        evidence_bindings,
    };
    context.manifest_sha256 = context
        .derived_manifest_sha256()
        .map_err(|_| StoreError::InvalidStateEvent)?;
    Ok(context)
}

pub(super) const fn prompting_planner_purpose(
    purpose: birdcode_protocol::PlannerTurnPurposeV1,
) -> birdcode_prompting::PlannerReplannerV2Purpose {
    match purpose {
        birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation => {
            birdcode_prompting::PlannerReplannerV2Purpose::InitialDelegation
        }
        birdcode_protocol::PlannerTurnPurposeV1::EvidenceReplan => {
            birdcode_prompting::PlannerReplannerV2Purpose::EvidenceReplan
        }
    }
}

pub(super) struct BuiltPlannerEvidence {
    pub(super) context: birdcode_prompting::PlannerReplannerV2ContextCatalog,
    pub(super) prompt_packet: birdcode_prompting::PlannerReplannerV2EvidencePacket,
    pub(super) prompt_delta: birdcode_prompting::PlannerReplannerV2EvidenceDelta,
    pub(super) durable_packet: birdcode_protocol::PlannerEvidencePacketV2,
    pub(super) durable_delta: birdcode_protocol::PlannerEvidenceDeltaV2,
    pub(super) prompt_packet_artifact: ArtifactRef,
    pub(super) prompt_delta_artifact: ArtifactRef,
    pub(super) durable_packet_artifact: ArtifactRef,
    pub(super) durable_delta_artifact: ArtifactRef,
}

#[allow(
    clippy::too_many_lines,
    reason = "one builder owns the exact prompt and durable evidence packet pair"
)]
pub(super) fn build_planner_evidence(
    store: &Store,
    session_id: SessionId,
    run_id: RunId,
    purpose: birdcode_protocol::PlannerTurnPurposeV1,
    retry_prepared_event_id: Option<EventId>,
) -> Result<BuiltPlannerEvidence, StoreError> {
    if let Some(prepared_event_id) = retry_prepared_event_id {
        let event = stored_event_for_run(&store.connection, session_id, run_id, prepared_event_id)?;
        let EventPayload::PlannerTurnPreparedV1(prepared) = event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        if prepared.purpose != purpose {
            return Err(StoreError::InvalidStateEvent);
        }
        let prompt_packet =
            read_canonical_json_artifact::<birdcode_prompting::PlannerReplannerV2EvidencePacket>(
                &store.artifact_root,
                &prepared.prompt_evidence_packet_artifact,
                birdcode_protocol::PLANNER_PROMPT_EVIDENCE_PACKET_V2_MEDIA_TYPE,
            )?;
        let prompt_delta =
            read_canonical_json_artifact::<birdcode_prompting::PlannerReplannerV2EvidenceDelta>(
                &store.artifact_root,
                &prepared.prompt_evidence_delta_artifact,
                birdcode_protocol::PLANNER_PROMPT_EVIDENCE_DELTA_V2_MEDIA_TYPE,
            )?;
        let durable_packet =
            read_canonical_json_artifact::<birdcode_protocol::PlannerEvidencePacketV2>(
                &store.artifact_root,
                &prepared.durable_evidence_packet_artifact,
                birdcode_protocol::PLANNER_DURABLE_EVIDENCE_PACKET_V2_MEDIA_TYPE,
            )?;
        let durable_delta =
            read_canonical_json_artifact::<birdcode_protocol::PlannerEvidenceDeltaV2>(
                &store.artifact_root,
                &prepared.durable_evidence_delta_artifact,
                birdcode_protocol::PLANNER_DURABLE_EVIDENCE_DELTA_V2_MEDIA_TYPE,
            )?;
        let context = planner_context_catalog(&prompt_packet.entries)?;
        if context.manifest_sha256 != prepared.context_manifest_digest.as_str()
            || durable_packet != prepared.durable_evidence_packet
            || durable_delta != prepared.durable_evidence_delta
        {
            return Err(StoreError::InvalidStateEvent);
        }
        return Ok(BuiltPlannerEvidence {
            context,
            prompt_packet,
            prompt_delta,
            durable_packet,
            durable_delta,
            prompt_packet_artifact: prepared.prompt_evidence_packet_artifact,
            prompt_delta_artifact: prepared.prompt_evidence_delta_artifact,
            durable_packet_artifact: prepared.durable_evidence_packet_artifact,
            durable_delta_artifact: prepared.durable_evidence_delta_artifact,
        });
    }
    let pairs = planner_evidence_pairs(store, session_id, run_id)?;
    let pair_by_id = pairs
        .iter()
        .map(|pair| (pair.prompt.evidence_id().to_owned(), pair))
        .collect::<BTreeMap<_, _>>();
    if pair_by_id.len() != pairs.len() {
        return Err(StoreError::InvalidStateEvent);
    }
    let prompt_entries = pairs
        .iter()
        .map(|pair| pair.prompt.clone())
        .collect::<Vec<_>>();
    let context = planner_context_catalog(&prompt_entries)?;
    let prompt_purpose = prompting_planner_purpose(purpose);
    let previous_event = latest_planner_prepared_before(
        &store.connection,
        session_id,
        run_id,
        MAX_SQLITE_INTEGER_U64,
    )?;
    let previous = previous_event
        .as_ref()
        .map(|event| match &event.payload {
            EventPayload::PlannerTurnPreparedV1(prepared) => Ok(prepared),
            _ => Err(StoreError::InvalidStateEvent),
        })
        .transpose()?;
    if matches!(
        purpose,
        birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation
    ) != previous.is_none()
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let previous_prompt_packet = previous
        .map(|prepared| {
            read_canonical_json_artifact::<birdcode_prompting::PlannerReplannerV2EvidencePacket>(
                &store.artifact_root,
                &prepared.prompt_evidence_packet_artifact,
                birdcode_protocol::PLANNER_PROMPT_EVIDENCE_PACKET_V2_MEDIA_TYPE,
            )
        })
        .transpose()?;
    let prompt_packet = birdcode_prompting::PlannerReplannerV2EvidencePacket::new(
        prompt_purpose,
        context.manifest_sha256.clone(),
        prompt_entries,
    )
    .map_err(|_| StoreError::InvalidStateEvent)?;
    let prompt_delta = birdcode_prompting::PlannerReplannerV2EvidenceDelta::new(
        prompt_purpose,
        &prompt_packet,
        previous_prompt_packet.as_ref(),
    )
    .map_err(|_| StoreError::InvalidStateEvent)?;

    let durable_entries = prompt_packet
        .entries
        .iter()
        .map(|entry| {
            let pair = pair_by_id
                .get(entry.evidence_id())
                .ok_or(StoreError::InvalidStateEvent)?;
            Ok(birdcode_protocol::PlannerEvidenceEntryV2 {
                evidence_id: pair.durable_id,
                normalized_content_digest: Sha256Digest::parse(
                    entry.normalized_content_sha256().to_owned(),
                )
                .map_err(|_| StoreError::InvalidStateEvent)?,
                material: pair.durable.clone(),
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let durable_packet = birdcode_protocol::PlannerEvidencePacketV2 {
        schema_version: birdcode_protocol::PLANNER_EVIDENCE_CONTRACT_VERSION,
        purpose,
        context_manifest_digest: Sha256Digest::parse(context.manifest_sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
        entries: durable_entries,
    };
    let current_bindings = planner_evidence_bindings(&durable_packet);
    let previous_bindings = previous
        .map(|prepared| planner_evidence_bindings(&prepared.durable_evidence_packet))
        .unwrap_or_default();
    let previous_ids = previous_bindings
        .iter()
        .map(|binding| binding.evidence_id)
        .collect::<BTreeSet<_>>();
    let newly_available = current_bindings
        .iter()
        .filter(|binding| !previous_ids.contains(&binding.evidence_id))
        .cloned()
        .collect::<Vec<_>>();
    if newly_available.is_empty() {
        return Err(StoreError::InvalidStateEvent);
    }
    let durable_delta = birdcode_protocol::PlannerEvidenceDeltaV2 {
        schema_version: birdcode_protocol::PLANNER_EVIDENCE_CONTRACT_VERSION,
        purpose,
        previous_packet_digest: previous
            .map(|prepared| prepared.durable_evidence_packet_digest.clone()),
        previous_evidence: previous_bindings,
        newly_available,
        delta_digest: Sha256Digest::parse(prompt_delta.delta_sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
    };
    let prompt_packet_artifact = put_json_artifact(
        store,
        &prompt_packet,
        birdcode_protocol::PLANNER_PROMPT_EVIDENCE_PACKET_V2_MEDIA_TYPE,
    )?;
    let prompt_delta_artifact = put_json_artifact(
        store,
        &prompt_delta,
        birdcode_protocol::PLANNER_PROMPT_EVIDENCE_DELTA_V2_MEDIA_TYPE,
    )?;
    let durable_packet_artifact = put_json_artifact(
        store,
        &durable_packet,
        birdcode_protocol::PLANNER_DURABLE_EVIDENCE_PACKET_V2_MEDIA_TYPE,
    )?;
    let durable_delta_artifact = put_json_artifact(
        store,
        &durable_delta,
        birdcode_protocol::PLANNER_DURABLE_EVIDENCE_DELTA_V2_MEDIA_TYPE,
    )?;
    Ok(BuiltPlannerEvidence {
        context,
        prompt_packet,
        prompt_delta,
        durable_packet,
        durable_delta,
        prompt_packet_artifact,
        prompt_delta_artifact,
        durable_packet_artifact,
        durable_delta_artifact,
    })
}

pub(super) fn accepted_root_plan_projection(
    connection: &Connection,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<birdcode_protocol::PlannerAcceptedRootPlanEvidenceV2>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'plan_semantic_review_accepted'
         ORDER BY sequence ASC LIMIT 2",
    )?;
    let rows = statement
        .query_map(params![run_id.to_string(), session_id.to_string()], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let ([] | [_]) = rows.as_slice() else {
        return Err(StoreError::InvalidStateEvent);
    };
    let Some(json) = rows.first() else {
        return Ok(None);
    };
    let event = decode_canonical_event(json)?;
    let EventPayload::PlanSemanticReviewAccepted(accepted) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(Some(birdcode_protocol::PlannerAcceptedRootPlanEvidenceV2 {
        accepted_plan_event_id: event.id,
        accepted_plan_revision: accepted.candidate.plan_revision,
        accepted_plan_artifact: accepted.candidate.plan_artifact,
        accepted_plan_digest: accepted.candidate.plan_digest,
    }))
}

pub(super) fn prompting_v2_purpose_matches(
    prompt: birdcode_prompting::PlannerReplannerV2Purpose,
    durable: birdcode_protocol::PlannerTurnPurposeV1,
) -> bool {
    matches!(
        (prompt, durable),
        (
            birdcode_prompting::PlannerReplannerV2Purpose::InitialDelegation,
            birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation
        ) | (
            birdcode_prompting::PlannerReplannerV2Purpose::EvidenceReplan,
            birdcode_protocol::PlannerTurnPurposeV1::EvidenceReplan
        )
    )
}

pub(super) fn planner_evidence_bindings(
    packet: &birdcode_protocol::PlannerEvidencePacketV2,
) -> Vec<birdcode_protocol::PlannerEvidenceBindingV2> {
    packet
        .entries
        .iter()
        .map(|entry| birdcode_protocol::PlannerEvidenceBindingV2 {
            evidence_id: entry.evidence_id,
            normalized_content_digest: entry.normalized_content_digest.clone(),
        })
        .collect()
}

pub(super) fn validate_planner_durable_evidence_material(
    connection: &Connection,
    event: &EventEnvelope,
    material: &birdcode_protocol::PlannerEvidenceMaterialV2,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    match material {
        birdcode_protocol::PlannerEvidenceMaterialV2::AcceptedRootPlan(evidence) => {
            let source = stored_event_for_run(
                connection,
                event.session_id,
                run_id,
                evidence.accepted_plan_event_id,
            )?;
            let EventPayload::PlanSemanticReviewAccepted(accepted) = &source.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            if source.sequence >= event.sequence
                || accepted.candidate.plan_artifact != evidence.accepted_plan_artifact
                || accepted.candidate.plan_digest != evidence.accepted_plan_digest
                || accepted.candidate.plan_revision != evidence.accepted_plan_revision
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        birdcode_protocol::PlannerEvidenceMaterialV2::ChildHandoff(evidence) => {
            let handoff = stored_event_for_run(
                connection,
                event.session_id,
                run_id,
                evidence.handoff_event_id,
            )?;
            let finished = stored_event_for_run(
                connection,
                event.session_id,
                run_id,
                evidence.finished_event_id,
            )?;
            let EventPayload::ChildHandoffCommitted(committed) = &handoff.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            let EventPayload::ChildExecutionFinished(terminal) = &finished.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            if handoff.sequence >= finished.sequence
                || finished.sequence >= event.sequence
                || committed.binding != evidence.binding
                || committed.handoff_id != evidence.handoff_id
                || committed.handoff_artifact != evidence.handoff_artifact
                || committed.handoff_digest != evidence.handoff_digest
                || terminal.binding != evidence.binding
                || terminal.handoff_event_id != Some(evidence.handoff_event_id)
                || !matches!(terminal.outcome, ChildExecutionOutcome::Succeeded { .. })
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        birdcode_protocol::PlannerEvidenceMaterialV2::ChildFailed(evidence) => {
            let finished = stored_event_for_run(
                connection,
                event.session_id,
                run_id,
                evidence.finished_event_id,
            )?;
            let EventPayload::ChildExecutionFinished(terminal) = &finished.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            if finished.sequence >= event.sequence
                || terminal.binding != evidence.binding
                || !matches!(
                    &terminal.outcome,
                    ChildExecutionOutcome::Failed { kind, retry, cause }
                        if kind == &evidence.kind
                            && retry == &evidence.retry
                            && cause == &evidence.cause
                )
                || !digest_matches_artifact(&evidence.evidence_digest, &evidence.evidence_artifact)
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        birdcode_protocol::PlannerEvidenceMaterialV2::ChildCancelled(evidence) => {
            let finished = stored_event_for_run(
                connection,
                event.session_id,
                run_id,
                evidence.finished_event_id,
            )?;
            let EventPayload::ChildExecutionFinished(terminal) = &finished.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            if finished.sequence >= event.sequence
                || terminal.binding != evidence.binding
                || !matches!(
                    &terminal.outcome,
                    ChildExecutionOutcome::Cancelled { cause } if cause == &evidence.cause
                )
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
    }
    Ok(())
}

pub(super) fn read_planner_base_snapshot(
    artifact_root: &Path,
    binding: &birdcode_protocol::PlannerBasePlanBindingV1,
) -> Result<birdcode_prompting::PlannerReplannerV2PlanSnapshot, StoreError> {
    let snapshot = read_canonical_json_artifact::<
        birdcode_prompting::PlannerReplannerV2PlanSnapshot,
    >(artifact_root, &binding.artifact, PLANNER_PLAN_V2_MEDIA_TYPE)?;
    if snapshot.revision != binding.revision
        || snapshot
            .sha256()
            .map_err(|_| StoreError::InvalidStateEvent)?
            != binding.digest.as_str()
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(snapshot)
}

fn latest_planner_accepted_before(
    connection: &Connection,
    session_id: SessionId,
    run_id: RunId,
    upper_sequence_exclusive: u64,
) -> Result<Option<EventEnvelope>, StoreError> {
    let json = connection
        .query_row(
            "SELECT value_json FROM events
             WHERE session_id = ?1 AND run_id = ?2 AND sequence < ?3
               AND json_extract(value_json, '$.payload.type') = 'planner_turn_accepted_v1'
             ORDER BY sequence DESC LIMIT 1",
            params![
                session_id.to_string(),
                run_id.to_string(),
                upper_sequence_exclusive,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    json.as_deref().map(decode_canonical_event).transpose()
}

pub(super) fn validate_planner_base_authority(
    connection: &Connection,
    event: &EventEnvelope,
    prepared: &birdcode_protocol::PlannerTurnPreparedV1,
    snapshot: &birdcode_prompting::PlannerReplannerV2PlanSnapshot,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    if snapshot.obligation_snapshot_sha256 != prepared.obligation_snapshot_digest.as_str()
        || snapshot.acceptance_policy_sha256 != prepared.acceptance_policy_digest.as_str()
    {
        return Err(StoreError::InvalidStateEvent);
    }
    match prepared.purpose {
        birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation => {
            let root = prepared
                .durable_evidence_packet
                .entries
                .first()
                .and_then(|entry| match &entry.material {
                    birdcode_protocol::PlannerEvidenceMaterialV2::AcceptedRootPlan(root) => {
                        Some(root)
                    }
                    _ => None,
                })
                .ok_or(StoreError::InvalidStateEvent)?;
            let anchor = stored_event_for_run(
                connection,
                event.session_id,
                run_id,
                prepared.base_plan.accepted_event_id,
            )?;
            if anchor.sequence >= event.sequence
                || !matches!(anchor.payload, EventPayload::PlanSemanticReviewAccepted(_))
                || root.accepted_plan_event_id != anchor.id
                || prepared.base_plan.revision != 0
                || snapshot.schema_version != 1
                || snapshot.revision != 0
                || snapshot.parent_plan_sha256.is_some()
                || !snapshot.strategy_summary.is_empty()
                || !snapshot.verification_targets.is_empty()
                || !snapshot.work_orders.is_empty()
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
        birdcode_protocol::PlannerTurnPurposeV1::EvidenceReplan => {
            let previous = latest_planner_accepted_before(
                connection,
                event.session_id,
                run_id,
                event.sequence,
            )?
            .ok_or(StoreError::InvalidStateEvent)?;
            let EventPayload::PlannerTurnAcceptedV1(previous_accepted) = previous.payload else {
                return Err(StoreError::InvalidStateEvent);
            };
            if previous.id != prepared.base_plan.accepted_event_id
                || previous_accepted.resulting_plan != prepared.base_plan
            {
                return Err(StoreError::InvalidStateEvent);
            }
        }
    }
    Ok(())
}
