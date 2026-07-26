//! Typed, journal-derived repository-review results.
//!
//! Scheduler `Completed` means that the reviewer finished its work. It never
//! means that the candidate passed. This module independently re-reads the
//! review journal, reconstructs the authoritative prompt contract, and exposes
//! a closed route derived from the validated verdict enum. It does not grant
//! merge, apply, promotion, or run-completion authority.

use crate::repository_reviewer_prompt::REPOSITORY_REVIEW_OUTPUT_SCHEMA_NAME_V1;
use crate::repository_reviewer_repair_prompt::{
    REPOSITORY_REVIEW_MISSING_EVIDENCE_REPAIR_SCHEMA_NAME_V1,
    RepositoryReviewMissingEvidenceRepairInputV1, RepositoryReviewMissingEvidenceRepairOutputV1,
    RepositoryReviewMissingEvidenceRepairPolicyV1,
    apply_repository_review_missing_evidence_repair_v1,
    prepare_repository_review_missing_evidence_repair_v1, repair_registry,
};
use crate::repository_reviewer_worker::{
    InMemoryRepositoryReviewJournalV1, REPOSITORY_REVIEW_RECEIPT_V1_MEDIA_TYPE,
    REPOSITORY_REVIEW_VERDICT_V1_MEDIA_TYPE, REVIEW_COMPILED_PROMPT_MEDIA_TYPE,
    REVIEW_DISCLOSURE_MEDIA_TYPE, REVIEW_INPUT_MEDIA_TYPE,
    REVIEW_REPAIR_COMPILED_PROMPT_MEDIA_TYPE, REVIEW_REPAIR_INPUT_MEDIA_TYPE,
    REVIEW_REPAIR_PATCH_MEDIA_TYPE, REVIEW_REPAIR_POLICY_MEDIA_TYPE,
    REVIEW_REPAIR_REQUEST_MEDIA_TYPE, REVIEW_REPAIR_RESPONSE_MEDIA_TYPE, REVIEW_REQUEST_MEDIA_TYPE,
    REVIEW_RESPONSE_MEDIA_TYPE, RepositoryReviewDisclosureV1, RepositoryReviewExecutionClaimV1,
    RepositoryReviewJournalEntryV1, RepositoryReviewJournalErrorV1,
    RepositoryReviewJournalRecordV1, RepositoryReviewReceiptV1,
    RepositoryReviewVerdictAcceptanceSourceV1, RepositoryReviewerArtifactV1,
    RepositoryReviewerConfigErrorV1, RepositoryReviewerDispatchAuthorityV1,
    RepositoryReviewerWorkerPolicyV1, compiled_backend_messages,
};
use birdcode_backends::{
    ModelId, StructuredInferenceRequest, StructuredInferenceResponse, StructuredOutputSpec,
};
use birdcode_orchestrator::{
    AgentAttemptId, AgentDispatch, ExecutionId, GraphActorId, HandoffOutcome,
    InMemorySchedulerJournal, SchedulerDispatchVerificationError, SchedulerDispatchVerifier,
    SchedulerEvent, SchedulerEventId, SchedulerJournalError, SchedulerRecord, ValidatedActorGraph,
    WorkOrderId,
};
use birdcode_prompting::{
    CompiledPrompt, PromptInvocation, RepositoryReviewInputV1, RepositoryReviewOutputV1,
    RepositoryReviewVerdictV1, builtin_registry, derive_repository_review_policy_v1,
    repository_review_invocation_v1, repository_reviewer_key,
};
use birdcode_protocol::{ArtifactRef, EventId, Sha256Digest};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;

/// Exact runtime subject selected by the controller from a scheduler run.
///
/// The query contains no verdict, artifact, summary, or receipt string. Those
/// are derived from the configured journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryReviewResultQueryV1 {
    pub graph_accepted_event_id: SchedulerEventId,
    pub reviewer_handoff_event_id: SchedulerEventId,
    pub reviewer_work_order_id: WorkOrderId,
    pub reviewer_actor_id: GraphActorId,
    pub reviewer_execution_id: ExecutionId,
    pub reviewer_attempt_id: AgentAttemptId,
}

/// Graph-bound authority for resolving one exact repository reviewer.
#[derive(Clone, Debug)]
pub struct RepositoryReviewResultAuthorityV1 {
    reviewer: RepositoryReviewerDispatchAuthorityV1,
    target_work_order_id: WorkOrderId,
    worker_policy: RepositoryReviewerWorkerPolicyV1,
}

impl RepositoryReviewResultAuthorityV1 {
    /// Binds the result reader to the exact authority accepted by the reviewer
    /// worker.
    ///
    /// # Errors
    ///
    /// Rejects any graph/work-order combination that could not configure the
    /// no-tool, one-target reviewer.
    pub fn bind(
        graph: &ValidatedActorGraph,
        reviewer_work_order_id: WorkOrderId,
    ) -> Result<Self, RepositoryReviewResultErrorV1> {
        Self::bind_with_policy(
            graph,
            reviewer_work_order_id,
            RepositoryReviewerWorkerPolicyV1::default(),
        )
    }

    /// Binds the result reader to the exact reviewer and worker policy that
    /// constructed both structured inference requests.
    ///
    /// # Errors
    ///
    /// Rejects invalid reviewer authority or worker-policy bounds.
    pub fn bind_with_policy(
        graph: &ValidatedActorGraph,
        reviewer_work_order_id: WorkOrderId,
        worker_policy: RepositoryReviewerWorkerPolicyV1,
    ) -> Result<Self, RepositoryReviewResultErrorV1> {
        let worker_policy = worker_policy
            .validate()
            .map_err(RepositoryReviewResultErrorV1::Authority)?;
        let reviewer = RepositoryReviewerDispatchAuthorityV1::bind(graph, reviewer_work_order_id)
            .map_err(RepositoryReviewResultErrorV1::Authority)?;
        let target_work_order_id = reviewer
            .resolver_authority()
            .reviewer_work_order()
            .reviews
            .iter()
            .next()
            .copied()
            .ok_or(RepositoryReviewResultErrorV1::AuthoritySubjectMismatch)?;
        Ok(Self {
            reviewer,
            target_work_order_id,
            worker_policy,
        })
    }

    #[must_use]
    pub const fn reviewer_work_order_id(&self) -> WorkOrderId {
        self.reviewer.reviewer_work_order_id()
    }

    #[must_use]
    pub const fn target_work_order_id(&self) -> WorkOrderId {
        self.target_work_order_id
    }
}

/// Deliberately non-authorizing route derived from an already validated
/// semantic verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryReviewRouteV1 {
    /// The artifact-only semantic gate passed. Mechanical build/test/runtime
    /// gates and an explicit promotion capability are still required.
    SemanticGateSatisfied,
    RevisionRequired {
        finding_ids: Vec<String>,
    },
    EvidenceRequired {
        missing_evidence_ids: Vec<String>,
    },
}

/// Private-construction proof that one exact journal result was independently
/// revalidated.
#[derive(Clone, Debug)]
pub struct VerifiedRepositoryReviewResultV1 {
    query: RepositoryReviewResultQueryV1,
    claim: RepositoryReviewExecutionClaimV1,
    verdict_accepted_event_id: EventId,
    verdict_artifact: ArtifactRef,
    receipt_artifact: ArtifactRef,
    output: RepositoryReviewOutputV1,
    route: RepositoryReviewRouteV1,
}

impl VerifiedRepositoryReviewResultV1 {
    #[must_use]
    pub const fn query(&self) -> RepositoryReviewResultQueryV1 {
        self.query
    }

    #[must_use]
    pub const fn claim(&self) -> &RepositoryReviewExecutionClaimV1 {
        &self.claim
    }

    #[must_use]
    pub const fn verdict_accepted_event_id(&self) -> EventId {
        self.verdict_accepted_event_id
    }

    #[must_use]
    pub const fn verdict_artifact(&self) -> &ArtifactRef {
        &self.verdict_artifact
    }

    #[must_use]
    pub const fn receipt_artifact(&self) -> &ArtifactRef {
        &self.receipt_artifact
    }

    #[must_use]
    pub const fn output(&self) -> &RepositoryReviewOutputV1 {
        &self.output
    }

    #[must_use]
    pub const fn route(&self) -> &RepositoryReviewRouteV1 {
        &self.route
    }
}

/// Narrow read boundary for an append-only review journal.
pub trait RepositoryReviewResultJournalV1: Send + Sync {
    /// Returns a stable snapshot whose event IDs and artifact bytes can be
    /// checked without interpreting prose.
    ///
    /// # Errors
    ///
    /// Returns an error unless the snapshot reflects one consistent read.
    fn review_result_snapshot(
        &self,
    ) -> Result<Vec<RepositoryReviewJournalEntryV1>, RepositoryReviewJournalErrorV1>;
}

impl RepositoryReviewResultJournalV1 for InMemoryRepositoryReviewJournalV1 {
    fn review_result_snapshot(
        &self,
    ) -> Result<Vec<RepositoryReviewJournalEntryV1>, RepositoryReviewJournalErrorV1> {
        self.snapshot()
    }
}

/// Narrow read boundary for the scheduler's retained reviewer handoff.
pub trait RepositoryReviewSchedulerResultJournalV1:
    SchedulerDispatchVerifier + Send + Sync
{
    /// Returns one stable scheduler-journal snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error unless the snapshot reflects one consistent read.
    fn scheduler_result_snapshot(&self) -> Result<Vec<SchedulerRecord>, SchedulerJournalError>;
}

impl RepositoryReviewSchedulerResultJournalV1 for InMemorySchedulerJournal {
    fn scheduler_result_snapshot(&self) -> Result<Vec<SchedulerRecord>, SchedulerJournalError> {
        self.snapshot()
    }
}

#[derive(Debug, Error)]
pub enum RepositoryReviewResultErrorV1 {
    #[error("repository review result authority is invalid: {0}")]
    Authority(RepositoryReviewerConfigErrorV1),
    #[error("repository review result authority has no exact subject")]
    AuthoritySubjectMismatch,
    #[error("repository review result journal read failed: {0}")]
    Journal(RepositoryReviewJournalErrorV1),
    #[error("repository review scheduler journal read failed: {0}")]
    SchedulerJournal(SchedulerJournalError),
    #[error("repository review scheduler dispatch verification failed: {0}")]
    SchedulerDispatch(#[from] SchedulerDispatchVerificationError),
    #[error("repository review result query differs from configured authority")]
    QueryAuthorityMismatch,
    #[error("repository review journal contains duplicate event identities")]
    DuplicateEventIdentity,
    #[error("repository review execution claim is missing, ambiguous, or conflicting")]
    ExecutionClaimMismatch,
    #[error("repository review execution-start boundary is missing or ambiguous")]
    ExecutionStartMismatch,
    #[error("repository review accepted-verdict boundary is missing or ambiguous")]
    VerdictAcceptanceMismatch,
    #[error("repository review scheduler handoff is missing, ambiguous, or cross-wired")]
    SchedulerHandoffMismatch,
    #[error("repository review event chain is incomplete or cross-wired")]
    EventChainMismatch,
    #[error(
        "repository review artifact is missing, ambiguous, inexact, or has the wrong media type"
    )]
    ArtifactMismatch,
    #[error("repository review retained document is noncanonical or invalid")]
    DocumentInvalid,
    #[error("repository review disclosure differs from its execution authority")]
    DisclosureMismatch,
    #[error("repository review prompt could not be reconstructed exactly")]
    PromptMismatch,
    #[error("repository review verdict no longer satisfies its authoritative contract")]
    VerdictContractMismatch,
    #[error("repository review has a conflicting failed or rejected terminal")]
    ConflictingTerminal,
}

/// Resolves and independently validates one exact reviewer result.
///
/// This function never inspects summaries, receipt prefixes, or free-form
/// evidence strings. A successful return is still not promotion authority.
///
/// # Errors
///
/// Fails closed on stale/foreign identity, ambiguity, artifact substitution,
/// event-chain mismatch, prompt drift, or verdict-contract failure.
#[allow(clippy::too_many_lines)]
pub fn resolve_repository_review_result_v1(
    authority: &RepositoryReviewResultAuthorityV1,
    query: RepositoryReviewResultQueryV1,
    journal: &dyn RepositoryReviewResultJournalV1,
    scheduler_journal: &dyn RepositoryReviewSchedulerResultJournalV1,
) -> Result<VerifiedRepositoryReviewResultV1, RepositoryReviewResultErrorV1> {
    let reviewer_authority = authority.reviewer.resolver_authority();
    if query.reviewer_work_order_id != authority.reviewer_work_order_id() {
        return Err(RepositoryReviewResultErrorV1::QueryAuthorityMismatch);
    }
    let entries = journal
        .review_result_snapshot()
        .map_err(RepositoryReviewResultErrorV1::Journal)?;
    require_unique_event_ids(&entries)?;
    let scheduler_records = scheduler_journal
        .scheduler_result_snapshot()
        .map_err(RepositoryReviewResultErrorV1::SchedulerJournal)?;
    require_unique_scheduler_event_ids(&scheduler_records)?;

    let slot_claims = entries
        .iter()
        .filter_map(|entry| match &entry.record {
            RepositoryReviewJournalRecordV1::ExecutionClaimed { claim }
                if claim.graph_accepted_event_id == query.graph_accepted_event_id
                    && claim.reviewer_work_order_id == query.reviewer_work_order_id
                    && claim.reviewer_actor_id == query.reviewer_actor_id
                    && claim.reviewer_execution_id == query.reviewer_execution_id
                    && claim.reviewer_attempt_id == query.reviewer_attempt_id =>
            {
                Some((entry, claim))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(claim_entry, claim)] = slot_claims.as_slice() else {
        return Err(RepositoryReviewResultErrorV1::ExecutionClaimMismatch);
    };
    if claim.contract_version != 1
        || claim.graph_sha256 != *reviewer_authority.graph_sha256()
        || claim.target_work_order_id != authority.target_work_order_id
    {
        return Err(RepositoryReviewResultErrorV1::ExecutionClaimMismatch);
    }

    let starts = entries
        .iter()
        .filter(|entry| {
            matches!(
                &entry.record,
                RepositoryReviewJournalRecordV1::ExecutionStarted {
                    execution_claimed_event_id,
                    reviewer_work_order_id,
                    reviewer_actor_id,
                    reviewer_execution_id,
                    reviewer_attempt_id,
                    reviewer_lineage,
                } if *execution_claimed_event_id == claim_entry.event_id
                    && *reviewer_work_order_id == query.reviewer_work_order_id
                    && *reviewer_actor_id == query.reviewer_actor_id
                    && *reviewer_execution_id == query.reviewer_execution_id
                    && *reviewer_attempt_id == query.reviewer_attempt_id
                    && reviewer_lineage
                        == &reviewer_authority.reviewer_work_order().assignment.lineage
            )
        })
        .count();
    if starts != 1 {
        return Err(RepositoryReviewResultErrorV1::ExecutionStartMismatch);
    }

    let mut accepted = Vec::new();
    for entry in &entries {
        let RepositoryReviewJournalRecordV1::VerdictAccepted {
            source,
            verdict_artifact,
            receipt_artifact,
        } = &entry.record
        else {
            continue;
        };
        let receipt_bytes = exact_artifact(
            entry,
            receipt_artifact,
            REPOSITORY_REVIEW_RECEIPT_V1_MEDIA_TYPE,
        )?;
        let receipt = decode_canonical::<RepositoryReviewReceiptV1>(receipt_bytes)?;
        if receipt.execution_claimed_event_id == claim_entry.event_id {
            accepted.push((entry, source, verdict_artifact, receipt_artifact, receipt));
        }
    }
    let [(accepted_entry, accepted_source, verdict_ref, receipt_ref, receipt)] =
        accepted.as_slice()
    else {
        return Err(RepositoryReviewResultErrorV1::VerdictAcceptanceMismatch);
    };
    if receipt.verdict_artifact != **verdict_ref
        || receipt.acceptance_source != **accepted_source
        || receipt.contract_version != 1
        || receipt.prompt_contract != repository_reviewer_key().to_string()
        || receipt.configured_reviewer_lineage
            != reviewer_authority.reviewer_work_order().assignment.lineage
        || receipt.blind_subject_id.is_empty()
        || receipt
            .configured_backend_instance
            .validate_integrity()
            .is_err()
        || receipt.configured_backend_instance.backend_id().as_str()
            != receipt.configured_reviewer_lineage.backend_id
        || receipt
            .configured_backend_instance
            .configured_deployment_id()
            .as_str()
            != receipt.configured_reviewer_lineage.deployment_id
        || receipt.reported_model_id.as_str() != receipt.configured_reviewer_lineage.model_id
        || !receipt
            .configured_backend_instance
            .matches_response_evidence(&receipt.response_evidence)
    {
        return Err(RepositoryReviewResultErrorV1::VerdictAcceptanceMismatch);
    }
    let verdict_bytes = exact_artifact(
        accepted_entry,
        verdict_ref,
        REPOSITORY_REVIEW_VERDICT_V1_MEDIA_TYPE,
    )?;

    let subject_entry = exact_entry(&entries, receipt.subject_prepared_event_id)?;
    let RepositoryReviewJournalRecordV1::SubjectPrepared {
        blind_subject_id,
        target_work_order_id,
        model_input_artifact,
        disclosure_artifact,
        compiled_prompt_artifact,
    } = &subject_entry.record
    else {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    };
    if blind_subject_id != &receipt.blind_subject_id
        || *target_work_order_id != claim.target_work_order_id
        || model_input_artifact != &receipt.model_input_artifact
        || disclosure_artifact != &receipt.disclosure_artifact
        || compiled_prompt_artifact != &receipt.compiled_prompt_artifact
    {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    }
    let input = decode_canonical::<RepositoryReviewInputV1>(exact_artifact(
        subject_entry,
        model_input_artifact,
        REVIEW_INPUT_MEDIA_TYPE,
    )?)?;
    let disclosure = decode_canonical::<RepositoryReviewDisclosureV1>(exact_artifact(
        subject_entry,
        disclosure_artifact,
        REVIEW_DISCLOSURE_MEDIA_TYPE,
    )?)?;
    let retained_compiled = decode_canonical::<CompiledPrompt>(exact_artifact(
        subject_entry,
        compiled_prompt_artifact,
        REVIEW_COMPILED_PROMPT_MEDIA_TYPE,
    )?)?;

    if disclosure.contract_version != 1
        || disclosure.blind_subject_id != receipt.blind_subject_id
        || disclosure.graph_accepted_event_id != claim.graph_accepted_event_id
        || disclosure.reviewer_work_order_id != claim.reviewer_work_order_id
        || disclosure.reviewer_actor_id != claim.reviewer_actor_id
        || disclosure.reviewer_execution_id != claim.reviewer_execution_id
        || disclosure.reviewer_attempt_id != claim.reviewer_attempt_id
        || disclosure.producer_locator.graph_sha256 != claim.graph_sha256
        || disclosure.producer_locator.work_order_id != claim.target_work_order_id
        || disclosure.producer_locator.actor_id != claim.producer_actor_id
        || disclosure.producer_locator.execution_id != claim.producer_execution_id
        || disclosure.producer_locator.attempt_id != claim.producer_attempt_id
        || disclosure.candidate_sha256 != claim.candidate_sha256
        || disclosure.reviewer_lineage != receipt.configured_reviewer_lineage
    {
        return Err(RepositoryReviewResultErrorV1::DisclosureMismatch);
    }

    let policy = derive_repository_review_policy_v1(&input)
        .map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
    if policy.blind_subject_id != receipt.blind_subject_id
        || policy.visible_payload_sha256 != receipt.visible_payload_sha256
        || policy.review_policy_sha256 != receipt.review_policy_sha256
    {
        return Err(RepositoryReviewResultErrorV1::PromptMismatch);
    }
    let invocation = repository_review_invocation_v1(&input, &policy)
        .map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
    let registry = builtin_registry().map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
    let rebuilt = registry
        .compile(&repository_reviewer_key(), &invocation)
        .map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
    if rebuilt != retained_compiled
        || retained_compiled.manifest.content_sha256 != receipt.prompt_manifest_sha256
        || retained_compiled.manifest.prompt != repository_reviewer_key()
    {
        return Err(RepositoryReviewResultErrorV1::PromptMismatch);
    }
    let output = registry
        .decode_output::<RepositoryReviewOutputV1>(
            &retained_compiled,
            &invocation,
            &verdict_bytes.bytes,
        )
        .map_err(|_| RepositoryReviewResultErrorV1::VerdictContractMismatch)?;
    if serde_json::to_vec(&output).ok().as_deref() != Some(verdict_bytes.bytes.as_slice())
        || output.bindings.blind_subject_id != receipt.blind_subject_id
        || output.bindings.visible_payload_sha256 != receipt.visible_payload_sha256
        || output.bindings.review_policy_sha256 != receipt.review_policy_sha256
    {
        return Err(RepositoryReviewResultErrorV1::VerdictContractMismatch);
    }

    verify_model_chain(
        &entries,
        accepted_entry,
        receipt,
        accepted_source,
        authority.worker_policy,
        &input,
        &invocation,
        &retained_compiled,
        &output,
    )?;
    if has_conflicting_terminal(&entries, receipt) {
        return Err(RepositoryReviewResultErrorV1::ConflictingTerminal);
    }
    verify_scheduler_handoff(
        scheduler_journal,
        &scheduler_records,
        authority,
        query,
        claim_entry.event_id,
        accepted_entry.event_id,
        receipt_ref,
        receipt,
        &disclosure,
        &output,
    )?;

    Ok(VerifiedRepositoryReviewResultV1 {
        query,
        claim: (*claim).clone(),
        verdict_accepted_event_id: accepted_entry.event_id,
        verdict_artifact: (*verdict_ref).clone(),
        receipt_artifact: (*receipt_ref).clone(),
        route: route_for(&output),
        output,
    })
}

fn route_for(output: &RepositoryReviewOutputV1) -> RepositoryReviewRouteV1 {
    match output.verdict {
        RepositoryReviewVerdictV1::Pass => RepositoryReviewRouteV1::SemanticGateSatisfied,
        RepositoryReviewVerdictV1::Revise => RepositoryReviewRouteV1::RevisionRequired {
            finding_ids: output
                .findings
                .iter()
                .map(|finding| finding.finding_id.clone())
                .collect(),
        },
        RepositoryReviewVerdictV1::Inconclusive => RepositoryReviewRouteV1::EvidenceRequired {
            missing_evidence_ids: output
                .missing_evidence
                .iter()
                .map(|missing| missing.missing_evidence_id.clone())
                .collect(),
        },
    }
}

fn require_unique_event_ids(
    entries: &[RepositoryReviewJournalEntryV1],
) -> Result<(), RepositoryReviewResultErrorV1> {
    let mut ids = BTreeSet::new();
    if entries.iter().all(|entry| ids.insert(entry.event_id)) {
        Ok(())
    } else {
        Err(RepositoryReviewResultErrorV1::DuplicateEventIdentity)
    }
}

fn require_unique_scheduler_event_ids(
    records: &[SchedulerRecord],
) -> Result<(), RepositoryReviewResultErrorV1> {
    let mut ids = BTreeSet::new();
    if records.iter().all(|record| ids.insert(record.id)) {
        Ok(())
    } else {
        Err(RepositoryReviewResultErrorV1::DuplicateEventIdentity)
    }
}

fn exact_entry(
    entries: &[RepositoryReviewJournalEntryV1],
    event_id: EventId,
) -> Result<&RepositoryReviewJournalEntryV1, RepositoryReviewResultErrorV1> {
    let mut matches = entries.iter().filter(|entry| entry.event_id == event_id);
    let Some(entry) = matches.next() else {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    };
    if matches.next().is_some() {
        return Err(RepositoryReviewResultErrorV1::DuplicateEventIdentity);
    }
    Ok(entry)
}

fn exact_artifact<'a>(
    entry: &'a RepositoryReviewJournalEntryV1,
    reference: &ArtifactRef,
    media_type: &str,
) -> Result<&'a RepositoryReviewerArtifactV1, RepositoryReviewResultErrorV1> {
    if reference.media_type != media_type {
        return Err(RepositoryReviewResultErrorV1::ArtifactMismatch);
    }
    let mut matches = entry
        .artifacts
        .iter()
        .filter(|artifact| artifact.artifact == *reference);
    let Some(artifact) = matches.next() else {
        return Err(RepositoryReviewResultErrorV1::ArtifactMismatch);
    };
    if matches.next().is_some() || !artifact.is_exact() {
        return Err(RepositoryReviewResultErrorV1::ArtifactMismatch);
    }
    Ok(artifact)
}

fn decode_canonical<T>(
    artifact: &RepositoryReviewerArtifactV1,
) -> Result<T, RepositoryReviewResultErrorV1>
where
    T: DeserializeOwned + Serialize,
{
    let decoded = serde_json::from_slice::<T>(&artifact.bytes)
        .map_err(|_| RepositoryReviewResultErrorV1::DocumentInvalid)?;
    if serde_json::to_vec(&decoded).ok().as_deref() != Some(artifact.bytes.as_slice())
        || artifact.artifact.sha256 != Sha256Digest::of_bytes(&artifact.bytes).as_str()
    {
        return Err(RepositoryReviewResultErrorV1::DocumentInvalid);
    }
    Ok(decoded)
}

fn verify_model_chain(
    entries: &[RepositoryReviewJournalEntryV1],
    accepted_entry: &RepositoryReviewJournalEntryV1,
    receipt: &RepositoryReviewReceiptV1,
    source: &RepositoryReviewVerdictAcceptanceSourceV1,
    worker_policy: RepositoryReviewerWorkerPolicyV1,
    input: &RepositoryReviewInputV1,
    invocation: &PromptInvocation,
    compiled: &CompiledPrompt,
    final_output: &RepositoryReviewOutputV1,
) -> Result<(), RepositoryReviewResultErrorV1> {
    let prepared_count = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.record,
                RepositoryReviewJournalRecordV1::ModelPrepared {
                    subject_prepared_event_id,
                    ..
                } if subject_prepared_event_id == receipt.subject_prepared_event_id
            )
        })
        .count();
    let input_rejection_count = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.record,
                RepositoryReviewJournalRecordV1::InputRejected {
                    subject_prepared_event_id,
                    ..
                } if subject_prepared_event_id == receipt.subject_prepared_event_id
            )
        })
        .count();
    if prepared_count != 1 || input_rejection_count != 0 {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    }
    let prepared = exact_entry(entries, receipt.model_prepared_event_id)?;
    let RepositoryReviewJournalRecordV1::ModelPrepared {
        subject_prepared_event_id,
        request_artifact,
    } = &prepared.record
    else {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    };
    if *subject_prepared_event_id != receipt.subject_prepared_event_id
        || request_artifact != &receipt.request_artifact
    {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    }
    let retained_primary_request = decode_canonical::<StructuredInferenceRequest>(exact_artifact(
        prepared,
        request_artifact,
        REVIEW_REQUEST_MEDIA_TYPE,
    )?)?;
    let expected_primary_request = reconstruct_request(
        compiled,
        receipt.reported_model_id.clone(),
        REPOSITORY_REVIEW_OUTPUT_SCHEMA_NAME_V1,
        worker_policy.max_output_tokens,
        worker_policy,
    )?;
    if retained_primary_request != expected_primary_request
        || request_artifact.size_bytes > worker_policy.max_request_bytes
    {
        return Err(RepositoryReviewResultErrorV1::PromptMismatch);
    }

    let observed_count = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.record,
                RepositoryReviewJournalRecordV1::ModelObserved {
                    model_prepared_event_id,
                    ..
                } if model_prepared_event_id == receipt.model_prepared_event_id
            )
        })
        .count();
    let model_failure_count = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.record,
                RepositoryReviewJournalRecordV1::ModelFailed {
                    model_prepared_event_id,
                    ..
                } if model_prepared_event_id == receipt.model_prepared_event_id
            )
        })
        .count();
    if observed_count != 1 || model_failure_count != 0 {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    }
    let observed = exact_entry(entries, receipt.model_observed_event_id)?;
    let RepositoryReviewJournalRecordV1::ModelObserved {
        model_prepared_event_id,
        response_artifact,
        output_tokens,
    } = &observed.record
    else {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    };
    if *model_prepared_event_id != receipt.model_prepared_event_id
        || response_artifact != &receipt.response_artifact
    {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    }
    let primary_response_artifact =
        exact_artifact(observed, response_artifact, REVIEW_RESPONSE_MEDIA_TYPE)?;
    let primary_response =
        decode_canonical::<StructuredInferenceResponse>(primary_response_artifact)?;
    if primary_response.model_id != receipt.reported_model_id
        || primary_response.evidence != receipt.response_evidence
        || primary_response.finish_reason != receipt.finish_reason
        || primary_response.usage != receipt.usage
        || *output_tokens
            != primary_response
                .usage
                .as_ref()
                .and_then(|usage| usage.output_tokens)
        || output_tokens.is_some_and(|tokens| tokens > u64::from(worker_policy.max_output_tokens))
        || !serde_json::from_str::<serde_json::Value>(&primary_response.raw_text)
            .is_ok_and(|value| value == primary_response.value)
    {
        return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
    }

    match (source, &receipt.repair) {
        (
            RepositoryReviewVerdictAcceptanceSourceV1::FirstPass {
                model_observed_event_id,
            },
            None,
        ) if *model_observed_event_id == receipt.model_observed_event_id => {
            if repair_branch_count(entries, receipt.model_observed_event_id) != 0
                || receipt.aggregate_output_tokens != *output_tokens
            {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            let registry =
                builtin_registry().map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
            let observed_output = registry
                .decode_output::<RepositoryReviewOutputV1>(
                    compiled,
                    invocation,
                    primary_response.raw_text.as_bytes(),
                )
                .map_err(|_| RepositoryReviewResultErrorV1::VerdictContractMismatch)?;
            if &observed_output != final_output {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            Ok(())
        }
        (
            RepositoryReviewVerdictAcceptanceSourceV1::AfterMissingEvidenceRepair {
                parent_model_observed_event_id,
                repair_observed_event_id,
                repair_patch_artifact,
            },
            Some(repair),
        ) if *parent_model_observed_event_id == receipt.model_observed_event_id
            && *repair_observed_event_id == repair.repair_observed_event_id
            && repair_patch_artifact == &repair.repair_patch_artifact =>
        {
            if repair_branch_count(entries, receipt.model_observed_event_id) != 1 {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            let repair_prepared = exact_entry(entries, repair.repair_prepared_event_id)?;
            let RepositoryReviewJournalRecordV1::MissingEvidenceRepairPrepared {
                model_observed_event_id,
                parent_raw_text_sha256,
                repair_input_artifact,
                repair_policy_artifact,
                repair_compiled_prompt_artifact,
                repair_request_artifact,
            } = &repair_prepared.record
            else {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            };
            if *model_observed_event_id != receipt.model_observed_event_id
                || repair_input_artifact != &repair.repair_input_artifact
                || repair_policy_artifact != &repair.repair_policy_artifact
                || repair_compiled_prompt_artifact != &repair.repair_compiled_prompt_artifact
                || repair_request_artifact != &repair.repair_request_artifact
            {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            let retained_repair_input =
                decode_canonical::<RepositoryReviewMissingEvidenceRepairInputV1>(exact_artifact(
                    repair_prepared,
                    repair_input_artifact,
                    REVIEW_REPAIR_INPUT_MEDIA_TYPE,
                )?)?;
            let retained_repair_policy =
                decode_canonical::<RepositoryReviewMissingEvidenceRepairPolicyV1>(exact_artifact(
                    repair_prepared,
                    repair_policy_artifact,
                    REVIEW_REPAIR_POLICY_MEDIA_TYPE,
                )?)?;
            let retained_repair_compiled = decode_canonical::<CompiledPrompt>(exact_artifact(
                repair_prepared,
                repair_compiled_prompt_artifact,
                REVIEW_REPAIR_COMPILED_PROMPT_MEDIA_TYPE,
            )?)?;
            let retained_repair_request =
                decode_canonical::<StructuredInferenceRequest>(exact_artifact(
                    repair_prepared,
                    repair_request_artifact,
                    REVIEW_REPAIR_REQUEST_MEDIA_TYPE,
                )?)?;
            if repair_request_artifact.size_bytes > worker_policy.max_request_bytes {
                return Err(RepositoryReviewResultErrorV1::PromptMismatch);
            }
            let repair_observed_count = entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.record,
                        RepositoryReviewJournalRecordV1::MissingEvidenceRepairObserved {
                            repair_prepared_event_id,
                            ..
                        } if repair_prepared_event_id == repair.repair_prepared_event_id
                    )
                })
                .count();
            let repair_failure_count = entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.record,
                        RepositoryReviewJournalRecordV1::MissingEvidenceRepairFailed {
                            repair_prepared_event_id,
                            ..
                        } if repair_prepared_event_id == repair.repair_prepared_event_id
                    )
                })
                .count();
            if repair_observed_count != 1 || repair_failure_count != 0 {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            let repair_observed = exact_entry(entries, repair.repair_observed_event_id)?;
            let RepositoryReviewJournalRecordV1::MissingEvidenceRepairObserved {
                repair_prepared_event_id,
                repair_response_artifact,
                output_tokens: repair_output_tokens,
            } = &repair_observed.record
            else {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            };
            if *repair_prepared_event_id != repair.repair_prepared_event_id
                || repair_response_artifact != &repair.repair_response_artifact
            {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            let repair_response_artifact = exact_artifact(
                repair_observed,
                repair_response_artifact,
                REVIEW_REPAIR_RESPONSE_MEDIA_TYPE,
            )?;
            let repair_response =
                decode_canonical::<StructuredInferenceResponse>(repair_response_artifact)?;
            let retained_patch =
                decode_canonical::<RepositoryReviewMissingEvidenceRepairOutputV1>(exact_artifact(
                    accepted_entry,
                    repair_patch_artifact,
                    REVIEW_REPAIR_PATCH_MEDIA_TYPE,
                )?)?;

            let candidate =
                serde_json::from_value::<RepositoryReviewOutputV1>(primary_response.value.clone())
                    .map_err(|_| RepositoryReviewResultErrorV1::EventChainMismatch)?;
            let reconstructed = prepare_repository_review_missing_evidence_repair_v1(
                input,
                invocation,
                compiled,
                &candidate,
                Sha256Digest::of_bytes(primary_response.raw_text.as_bytes())
                    .as_str()
                    .to_owned(),
                primary_response_artifact.artifact.sha256.clone(),
            )
            .map_err(|_| RepositoryReviewResultErrorV1::EventChainMismatch)?;
            let (repair_output_registry, repair_key) =
                repair_registry().map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
            if retained_repair_input != reconstructed.input
                || retained_repair_policy != reconstructed.policy
                || retained_repair_compiled != reconstructed.compiled
                || repair.prompt_contract != repair_key.to_string()
                || repair.prompt_manifest_sha256 != reconstructed.compiled.manifest.content_sha256
                || repair.repair_policy_sha256 != reconstructed.policy.repair_policy_sha256
                || repair.parent_raw_text_sha256 != reconstructed.policy.parent_raw_text_sha256
                || parent_raw_text_sha256 != &reconstructed.policy.parent_raw_text_sha256
                || repair_response.model_id != receipt.reported_model_id
                || repair_response.evidence != repair.response_evidence
                || repair_response.finish_reason != repair.finish_reason
                || repair_response.usage != repair.usage
                || *repair_output_tokens
                    != repair_response
                        .usage
                        .as_ref()
                        .and_then(|usage| usage.output_tokens)
                || repair_output_tokens.is_some_and(|tokens| {
                    tokens > u64::from(worker_policy.repair_max_output_tokens)
                })
                || !receipt
                    .configured_backend_instance
                    .matches_response_evidence(&repair_response.evidence)
                || !serde_json::from_str::<serde_json::Value>(&repair_response.raw_text)
                    .is_ok_and(|value| value == repair_response.value)
            {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            let expected_repair_request = reconstruct_request(
                &reconstructed.compiled,
                receipt.reported_model_id.clone(),
                REPOSITORY_REVIEW_MISSING_EVIDENCE_REPAIR_SCHEMA_NAME_V1,
                worker_policy.repair_max_output_tokens,
                worker_policy,
            )?;
            if retained_repair_request != expected_repair_request
                || receipt.aggregate_output_tokens
                    != combined_output_tokens(*output_tokens, *repair_output_tokens)
            {
                return Err(RepositoryReviewResultErrorV1::PromptMismatch);
            }
            let decoded_patch = repair_output_registry
                .decode_output::<RepositoryReviewMissingEvidenceRepairOutputV1>(
                    &reconstructed.compiled,
                    &reconstructed.invocation,
                    repair_response.raw_text.as_bytes(),
                )
                .map_err(|_| RepositoryReviewResultErrorV1::VerdictContractMismatch)?;
            if decoded_patch != retained_patch {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            let reapplied = apply_repository_review_missing_evidence_repair_v1(
                candidate,
                invocation,
                compiled,
                &reconstructed,
                retained_patch,
            )
            .map_err(|_| RepositoryReviewResultErrorV1::VerdictContractMismatch)?;
            if &reapplied != final_output {
                return Err(RepositoryReviewResultErrorV1::EventChainMismatch);
            }
            Ok(())
        }
        _ => Err(RepositoryReviewResultErrorV1::EventChainMismatch),
    }
}

fn reconstruct_request(
    compiled: &CompiledPrompt,
    model_id: ModelId,
    schema_name: &'static str,
    max_output_tokens: u32,
    worker_policy: RepositoryReviewerWorkerPolicyV1,
) -> Result<StructuredInferenceRequest, RepositoryReviewResultErrorV1> {
    let messages = compiled_backend_messages(compiled)
        .map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
    let output = StructuredOutputSpec::new(schema_name, compiled.generation_schema.clone())
        .map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
    let mut request =
        StructuredInferenceRequest::new(model_id, messages, output, max_output_tokens)
            .map_err(|_| RepositoryReviewResultErrorV1::PromptMismatch)?;
    if let Some(reasoning) = worker_policy.reasoning {
        request = request.with_reasoning(reasoning);
    }
    Ok(request)
}

fn repair_branch_count(entries: &[RepositoryReviewJournalEntryV1], parent: EventId) -> usize {
    entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.record,
                RepositoryReviewJournalRecordV1::MissingEvidenceRepairPrepared {
                    model_observed_event_id,
                    ..
                } | RepositoryReviewJournalRecordV1::MissingEvidenceRepairInputRejected {
                    model_observed_event_id,
                    ..
                } if model_observed_event_id == parent
            )
        })
        .count()
}

fn combined_output_tokens(primary: Option<u64>, repair: Option<u64>) -> Option<u64> {
    primary
        .zip(repair)
        .and_then(|(primary, repair)| primary.checked_add(repair))
}

fn has_conflicting_terminal(
    entries: &[RepositoryReviewJournalEntryV1],
    receipt: &RepositoryReviewReceiptV1,
) -> bool {
    entries.iter().any(|entry| match &entry.record {
        RepositoryReviewJournalRecordV1::ModelFailed {
            model_prepared_event_id,
            ..
        } => *model_prepared_event_id == receipt.model_prepared_event_id,
        RepositoryReviewJournalRecordV1::ModelContractRejected {
            model_observed_event_id,
            ..
        } => *model_observed_event_id == receipt.model_observed_event_id,
        RepositoryReviewJournalRecordV1::MissingEvidenceRepairFailed {
            repair_prepared_event_id,
            ..
        } => receipt
            .repair
            .as_ref()
            .is_some_and(|repair| *repair_prepared_event_id == repair.repair_prepared_event_id),
        RepositoryReviewJournalRecordV1::MissingEvidenceRepairRejected {
            repair_observed_event_id,
            ..
        } => receipt
            .repair
            .as_ref()
            .is_some_and(|repair| *repair_observed_event_id == repair.repair_observed_event_id),
        _ => false,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_scheduler_handoff(
    scheduler_journal: &dyn RepositoryReviewSchedulerResultJournalV1,
    records: &[SchedulerRecord],
    authority: &RepositoryReviewResultAuthorityV1,
    query: RepositoryReviewResultQueryV1,
    execution_claimed_event_id: EventId,
    verdict_accepted_event_id: EventId,
    receipt_artifact: &ArtifactRef,
    receipt: &RepositoryReviewReceiptV1,
    disclosure: &RepositoryReviewDisclosureV1,
    output: &RepositoryReviewOutputV1,
) -> Result<(), RepositoryReviewResultErrorV1> {
    let reviewer_authority = authority.reviewer.resolver_authority();
    let mut dispatch_matches = records
        .iter()
        .filter(|record| record.id == disclosure.reviewer_dispatch_event_id);
    let Some(dispatch_record) = dispatch_matches.next() else {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    };
    if dispatch_matches.next().is_some() {
        return Err(RepositoryReviewResultErrorV1::DuplicateEventIdentity);
    }
    let SchedulerEvent::AttemptDispatched {
        work_order_id,
        actor_id,
        execution_id,
        attempt_id,
        parent_attempt_id,
        graph_accepted_event_id,
        dependency_handoff_event_ids,
        ..
    } = &dispatch_record.event
    else {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    };
    let dispatch_position = records
        .iter()
        .position(|candidate| candidate.id == dispatch_record.id)
        .ok_or(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch)?;
    if *work_order_id != query.reviewer_work_order_id
        || *actor_id != query.reviewer_actor_id
        || *execution_id != query.reviewer_execution_id
        || *attempt_id != query.reviewer_attempt_id
        || *graph_accepted_event_id != query.graph_accepted_event_id
    {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    }

    let mut dependency_handoffs = BTreeMap::new();
    for (dependency_id, event_id) in dependency_handoff_event_ids {
        let mut dependency_matches = records.iter().filter(|record| record.id == *event_id);
        let Some(dependency_record) = dependency_matches.next() else {
            return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
        };
        if dependency_matches.next().is_some() {
            return Err(RepositoryReviewResultErrorV1::DuplicateEventIdentity);
        }
        let SchedulerEvent::HandoffRetained { handoff } = &dependency_record.event else {
            return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
        };
        dependency_handoffs.insert(*dependency_id, Arc::new(handoff.clone()));
    }
    let dispatch = AgentDispatch {
        actor_id: query.reviewer_actor_id,
        execution_id: query.reviewer_execution_id,
        attempt_id: query.reviewer_attempt_id,
        parent_attempt_id: *parent_attempt_id,
        graph_accepted_event_id: query.graph_accepted_event_id,
        graph_sha256: reviewer_authority.graph_sha256().as_str().to_owned(),
        attestation: reviewer_authority.reviewer_attestation().clone(),
        work_order: Arc::new(reviewer_authority.reviewer_work_order().clone()),
        dependency_handoffs,
        dependency_handoff_event_ids: dependency_handoff_event_ids.clone(),
    };
    let verified_dispatch = scheduler_journal.verify_dispatch(&dispatch)?;
    let Some(verified_target) = verified_dispatch
        .dependencies
        .get(&authority.target_work_order_id)
    else {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    };
    let Some(target_attestation) =
        reviewer_authority.target_attestation(authority.target_work_order_id)
    else {
        return Err(RepositoryReviewResultErrorV1::AuthoritySubjectMismatch);
    };
    if verified_dispatch.dispatch_event_id != disclosure.reviewer_dispatch_event_id
        || verified_dispatch.graph_accepted_event_id != query.graph_accepted_event_id
        || verified_dispatch.dependencies.len() != 1
        || verified_target.handoff_event_id != disclosure.dependency_handoff_event_id
        || verified_target.producer_dispatch_event_id != disclosure.producer_dispatch_event_id
        || verified_target.actor_id != disclosure.producer_locator.actor_id
        || verified_target.execution_id != disclosure.producer_locator.execution_id
        || verified_target.attempt_id != disclosure.producer_locator.attempt_id
        || &verified_target.dispatch_attestation != target_attestation
    {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    }

    let mut matches = records
        .iter()
        .filter(|record| record.id == query.reviewer_handoff_event_id);
    let Some(record) = matches.next() else {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    };
    if matches.next().is_some() {
        return Err(RepositoryReviewResultErrorV1::DuplicateEventIdentity);
    }
    let SchedulerEvent::HandoffRetained { handoff } = &record.event else {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    };
    let handoff_position = records
        .iter()
        .position(|candidate| candidate.id == record.id)
        .ok_or(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch)?;
    let reviewer_terminal_count = records
        .iter()
        .filter(|candidate| match &candidate.event {
            SchedulerEvent::HandoffRetained {
                handoff: candidate_handoff,
            } => {
                candidate_handoff.work_order_id == query.reviewer_work_order_id
                    && candidate_handoff.actor_id == query.reviewer_actor_id
                    && candidate_handoff.execution_id == query.reviewer_execution_id
                    && candidate_handoff.attempt_id == query.reviewer_attempt_id
            }
            SchedulerEvent::AttemptFailed {
                work_order_id,
                execution_id,
                attempt_id,
                ..
            } => {
                *work_order_id == query.reviewer_work_order_id
                    && *execution_id == query.reviewer_execution_id
                    && *attempt_id == query.reviewer_attempt_id
            }
            _ => false,
        })
        .count();
    if dispatch_position >= handoff_position
        || reviewer_terminal_count != 1
        || record.causal_parent != Some(verified_dispatch.dispatch_event_id)
        || handoff.retained_event_id != query.reviewer_handoff_event_id
        || handoff.work_order_id != query.reviewer_work_order_id
        || handoff.actor_id != query.reviewer_actor_id
        || handoff.execution_id != query.reviewer_execution_id
        || handoff.attempt_id != query.reviewer_attempt_id
        || handoff.outcome != HandoffOutcome::Completed
        || handoff.summary != output.summary
        || handoff.usage.tool_calls != 0
        || handoff.usage.output_tokens != receipt.aggregate_output_tokens
    {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    }

    let mut expected_artifacts = [
        &receipt.model_input_artifact,
        &receipt.disclosure_artifact,
        &receipt.compiled_prompt_artifact,
        &receipt.request_artifact,
        &receipt.response_artifact,
        &receipt.verdict_artifact,
        receipt_artifact,
    ]
    .into_iter()
    .map(|artifact| artifact.sha256.clone())
    .collect::<BTreeSet<_>>();
    if let Some(repair) = &receipt.repair {
        expected_artifacts.extend(
            [
                &repair.repair_input_artifact,
                &repair.repair_policy_artifact,
                &repair.repair_compiled_prompt_artifact,
                &repair.repair_request_artifact,
                &repair.repair_response_artifact,
                &repair.repair_patch_artifact,
            ]
            .into_iter()
            .map(|artifact| artifact.sha256.clone()),
        );
    }
    let actual_artifacts = handoff
        .artifact_sha256
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_artifacts.len() != handoff.artifact_sha256.len()
        || actual_artifacts != expected_artifacts
    {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    }

    let mut expected_evidence = [
        disclosure.graph_accepted_event_id.to_string(),
        disclosure.reviewer_dispatch_event_id.to_string(),
        disclosure.dependency_handoff_event_id.to_string(),
        disclosure.producer_dispatch_event_id.to_string(),
        disclosure.publication_event_id.to_string(),
        disclosure.cleanup_observed_event_id.to_string(),
        disclosure.ready_event_id.to_string(),
        execution_claimed_event_id.to_string(),
        receipt.subject_prepared_event_id.to_string(),
        receipt.model_prepared_event_id.to_string(),
        receipt.model_observed_event_id.to_string(),
        verdict_accepted_event_id.to_string(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if let Some(repair) = &receipt.repair {
        expected_evidence.insert(repair.repair_prepared_event_id.to_string());
        expected_evidence.insert(repair.repair_observed_event_id.to_string());
    }
    let actual_evidence = handoff
        .evidence_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_evidence.len() != handoff.evidence_ids.len() || actual_evidence != expected_evidence {
        return Err(RepositoryReviewResultErrorV1::SchedulerHandoffMismatch);
    }
    Ok(())
}
