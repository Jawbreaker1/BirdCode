//! Provider-neutral model -> repository tool -> observation -> finish worker.
//!
//! The semantic model owns the local plan and selects typed actions. This
//! adapter validates mechanical lifecycle bindings, retains every boundary and
//! executes only through the descriptor-confined repository broker.

use crate::repository_agent_prompt;
use birdcode_backends::{
    BackendError, ModelBackend, ModelId, ReasoningSetting, StructuredInferenceRequest,
    StructuredInferenceResponse,
};
use birdcode_orchestrator::{
    AgentCompletion, AgentDispatch, AgentFailure, AgentFailureKind, AgentFuture, AgentWorker,
    DispatchAttestation, HandoffOutcome, Usage, WorkOrder, WorkOrderId, WorkspaceAccess,
    WorkspaceSourceBinding,
};
use birdcode_protocol::{
    ArtifactRef, CHILD_HANDOFF_MEDIA_TYPE, CHILD_RECONNAISSANCE_CONTRACT_VERSION,
    CHILD_RECONNAISSANCE_MAX_EVIDENCE_BINDINGS, CHILD_RECONNAISSANCE_MAX_FINDINGS,
    CHILD_RECONNAISSANCE_MAX_IDENTIFIER_BYTES, CHILD_RECONNAISSANCE_MAX_IDENTIFIER_UNICODE_SCALARS,
    CHILD_RECONNAISSANCE_MAX_MODEL_ARTIFACT_BYTES,
    CHILD_RECONNAISSANCE_MAX_MODEL_CALLS_PER_ATTEMPT,
    CHILD_RECONNAISSANCE_MAX_OUTPUT_TOKENS_PER_MODEL_CALL,
    CHILD_RECONNAISSANCE_MAX_PLAN_ASSUMPTIONS, CHILD_RECONNAISSANCE_MAX_PLAN_STEPS,
    CHILD_RECONNAISSANCE_MAX_PLAN_UNKNOWNS, CHILD_RECONNAISSANCE_MAX_RECOMMENDED_FOLLOWUPS,
    CHILD_RECONNAISSANCE_MAX_TEXT_BYTES, CHILD_RECONNAISSANCE_MAX_TEXT_UNICODE_SCALARS,
    CHILD_RECONNAISSANCE_MAX_UNRESOLVED_QUESTIONS,
    CHILD_REPOSITORY_EXPLORER_V1_MAX_RAW_INPUT_BYTES, CHILD_VALIDATED_ACTION_MEDIA_TYPE,
    ChildActionV1, ChildActorId, ChildAttemptId, ChildExecutionBinding, ChildExecutionId,
    ChildHandoffContentV1, ChildHandoffDocument, ChildHandoffId, ChildHandoffStatus,
    ChildLocalPlanBindingV1, ChildLocalPlanId, ChildLocalPlanSnapshotV1,
    ChildLocalPlanStepStatusV1, ChildModelCallId, ChildModelStructuredResponseV1, ChildToolCallId,
    ChildToolObservedV2, ChildValidatedActionBindingV1, ChildValidatedActionDocumentV1,
    ChildValidatedActionId, ChildWorkOrderId, EventId, ModelLineage,
    REPOSITORY_BROKER_CONTRACT_VERSION, RepositoryLiteralSearchResultV1,
    RepositoryReadFileResultV2, RepositoryToolCanonicalParametersV1, RepositoryToolGrantId,
    RepositoryToolGrantV1, RepositoryToolObservedTerminalV2, RepositoryToolResultV2,
    RepositoryTreeResultV1, RuntimeClockReading, RuntimeInstanceId, Sha256Digest,
};
use birdcode_tooling::{
    RepositoryToolBroker, RepositoryToolExecuteInputV2, RepositoryToolPrepareInputV2,
    RepositoryToolTerminalV2, RetainedArtifactV2, project_observed_event_v2,
    project_prepared_event_v2, verify_terminal_output_v2,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const HARD_MAX_ACTION_REJECTIONS: u32 = 16;
const MODEL_REQUEST_MEDIA_TYPE: &str = "application/vnd.birdcode.repository-agent-request.v1+json";
const MODEL_RESPONSE_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-agent-response.v1+json";
const MODEL_ERROR_MEDIA_TYPE: &str = "application/vnd.birdcode.repository-agent-error.v1+json";
const MODEL_CONTRACT_ERROR_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-agent-contract-error.v1+json";
/// Aggregate raw file bytes that may be projected into one attempt's model
/// context. Canonical base64 is at most 4/3 this size, leaving deliberate room
/// below the 2 MiB raw-turn ceiling for plans, receipts and other evidence.
const REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES: u64 = 256 * 1024;

/// Trusted mechanical limits for one worker attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryAgentPolicy {
    pub max_model_calls: u32,
    pub max_action_rejections: u32,
    pub max_output_tokens_per_call: u32,
    pub min_plan_revisions_before_finish: u32,
    pub reasoning: Option<ReasoningSetting>,
}

impl RepositoryAgentPolicy {
    /// Validates hard resource ceilings without interpreting user or model text.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error when a limit is zero, exceeds its
    /// hard ceiling or cannot leave room for a non-repair model turn.
    pub fn validate(self) -> Result<Self, RepositoryAgentConfigError> {
        if self.max_model_calls == 0
            || self.max_model_calls > CHILD_RECONNAISSANCE_MAX_MODEL_CALLS_PER_ATTEMPT
        {
            return Err(RepositoryAgentConfigError::InvalidModelCallLimit);
        }
        if self.max_action_rejections > HARD_MAX_ACTION_REJECTIONS
            || self.max_action_rejections >= self.max_model_calls
        {
            return Err(RepositoryAgentConfigError::InvalidRejectionLimit);
        }
        if self.max_output_tokens_per_call == 0
            || u64::from(self.max_output_tokens_per_call)
                > CHILD_RECONNAISSANCE_MAX_OUTPUT_TOKENS_PER_MODEL_CALL
            || self.min_plan_revisions_before_finish == 0
            || self.min_plan_revisions_before_finish > self.max_model_calls
        {
            return Err(RepositoryAgentConfigError::InvalidPositiveLimit);
        }
        Ok(self)
    }
}

impl Default for RepositoryAgentPolicy {
    fn default() -> Self {
        Self {
            max_model_calls: 16,
            max_action_rejections: 2,
            max_output_tokens_per_call: 4_096,
            min_plan_revisions_before_finish: 2,
            reasoning: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryAgentConfigError {
    InvalidModelCallLimit,
    InvalidRejectionLimit,
    InvalidPositiveLimit,
    InvalidBackendIdentity,
    EmptyAuthority,
    DuplicateWorkOrderAuthority,
    EmptyPermissionAuthority,
    UnknownToolGrant,
    InvalidAuthorityGraphDigest,
    InvalidAuthorityEncoding,
    InvalidWorkspaceAuthority,
    ModelVisibleReadGrantTooLarge,
}

impl fmt::Display for RepositoryAgentConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModelCallLimit => formatter.write_str("invalid model-call limit"),
            Self::InvalidRejectionLimit => formatter.write_str("invalid action-rejection limit"),
            Self::InvalidPositiveLimit => formatter.write_str("worker limits must be positive"),
            Self::InvalidBackendIdentity => {
                formatter.write_str("backend instance identity failed integrity validation")
            }
            Self::EmptyAuthority => formatter.write_str("worker requires dispatch authority"),
            Self::DuplicateWorkOrderAuthority => {
                formatter.write_str("worker authority repeats a work-order identity")
            }
            Self::EmptyPermissionAuthority => {
                formatter.write_str("worker authority requires an opaque permission grant")
            }
            Self::UnknownToolGrant => {
                formatter.write_str("worker authority names a tool grant outside its broker")
            }
            Self::InvalidAuthorityGraphDigest => {
                formatter.write_str("worker authority has an invalid graph digest")
            }
            Self::InvalidAuthorityEncoding => {
                formatter.write_str("worker authority could not bind its exact work order")
            }
            Self::InvalidWorkspaceAuthority => formatter.write_str(
                "worker authority requires the broker's exact read-only workspace snapshot",
            ),
            Self::ModelVisibleReadGrantTooLarge => formatter
                .write_str("worker read grant exceeds the model-visible aggregate read budget"),
        }
    }
}

impl std::error::Error for RepositoryAgentConfigError {}

/// Exact bytes acknowledged with one worker-journal boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryAgentArtifact {
    pub artifact: ArtifactRef,
    pub bytes: Vec<u8>,
}

impl RepositoryAgentArtifact {
    fn from_bytes(media_type: &str, bytes: Vec<u8>) -> Self {
        let digest = Sha256Digest::of_bytes(&bytes);
        Self {
            artifact: ArtifactRef {
                sha256: digest.as_str().to_owned(),
                size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                media_type: media_type.to_owned(),
            },
            bytes,
        }
    }

    fn from_tooling(artifact: &RetainedArtifactV2) -> Self {
        Self {
            artifact: artifact.artifact.clone(),
            bytes: artifact.bytes.clone(),
        }
    }

    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.artifact.size_bytes == u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
            && self.artifact.sha256 == Sha256Digest::of_bytes(&self.bytes).as_str()
    }
}

/// Typed reason returned to the model when a schema-valid candidate violates
/// the trusted local-plan, budget or evidence contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryAgentRejectionV1 {
    ContractMismatch,
    ExecutionBindingMismatch,
    PlanIdentityMismatch,
    ObjectiveMismatch,
    PlanRevisionMismatch,
    PlanStructureInvalid,
    PlanTransitionInvalid,
    ActionPlanStateInvalid,
    FinishBeforeMinimumRevision,
    FinishEvidenceInvalid,
    ToolBudgetExhausted,
    ModelVisibleReadBudgetExceeded,
    ToolGrantOutsideDispatchAuthority,
}

/// Mechanical rejection of a completed model call. This is distinct from an
/// LLM-repairable semantic action rejection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryAgentModelContractViolationV1 {
    OutputTokenCeilingExceeded,
    ResponseBindingMismatch,
    StructuredResponseInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryAgentJournalRecord {
    ExecutionStarted {
        binding: ChildExecutionBinding,
        local_plan_id: ChildLocalPlanId,
        model_lineage: ModelLineage,
    },
    ModelPrepared {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        model_call_ordinal: u32,
        request_artifact: ArtifactRef,
    },
    ModelObserved {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        model_call_ordinal: u32,
        prepared_event_id: EventId,
        evidence_artifact: ArtifactRef,
        output_tokens: Option<u64>,
    },
    ModelFailed {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        model_call_ordinal: u32,
        prepared_event_id: EventId,
        error_artifact: ArtifactRef,
    },
    ModelContractRejected {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        model_observed_event_id: EventId,
        violation: RepositoryAgentModelContractViolationV1,
    },
    ActionRejected {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        model_observed_event_id: EventId,
        rejection: RepositoryAgentRejectionV1,
    },
    ActionValidated {
        binding: ChildExecutionBinding,
        action_binding: ChildValidatedActionBindingV1,
    },
    ToolPrepared {
        projection: birdcode_protocol::ChildToolPreparedV2,
    },
    ToolObserved {
        projection: ChildToolObservedV2,
    },
    ToolOutcomeUnknown {
        binding: ChildExecutionBinding,
        tool_call_id: ChildToolCallId,
        prepared_event_id: EventId,
        terminal_receipt_artifact: ArtifactRef,
    },
    FinishAccepted {
        binding: ChildExecutionBinding,
        handoff_id: ChildHandoffId,
        action_binding: ChildValidatedActionBindingV1,
        handoff_artifact: ArtifactRef,
    },
}

/// One append-only journal unit. Every artifact must be acknowledged together
/// with the record before the worker crosses the associated effect boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryAgentJournalEntry {
    pub record: RepositoryAgentJournalRecord,
    pub artifacts: Vec<RepositoryAgentArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryAgentJournalError {
    message: String,
}

impl RepositoryAgentJournalError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RepositoryAgentJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RepositoryAgentJournalError {}

/// Durable acknowledgement boundary owned by the daemon integration layer.
pub trait RepositoryAgentJournal: Send + Sync {
    /// Retains one record and all exact artifacts before acknowledging it.
    ///
    /// # Errors
    ///
    /// Returns an error unless the complete entry satisfies the journal's
    /// configured durability contract.
    fn retain(
        &self,
        entry: RepositoryAgentJournalEntry,
    ) -> Result<EventId, RepositoryAgentJournalError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRepositoryAgentJournalEntry {
    pub event_id: EventId,
    pub entry: RepositoryAgentJournalEntry,
}

/// Deterministic in-process journal for tests and non-durable local harnesses.
#[derive(Debug, Default)]
pub struct InMemoryRepositoryAgentJournal {
    entries: Mutex<Vec<RetainedRepositoryAgentJournalEntry>>,
}

impl InMemoryRepositoryAgentJournal {
    /// Returns the retained entries in acknowledgement order.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory journal lock is poisoned.
    pub fn snapshot(
        &self,
    ) -> Result<Vec<RetainedRepositoryAgentJournalEntry>, RepositoryAgentJournalError> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .map_err(|_| RepositoryAgentJournalError::new("agent journal lock was poisoned"))
    }
}

impl RepositoryAgentJournal for InMemoryRepositoryAgentJournal {
    fn retain(
        &self,
        entry: RepositoryAgentJournalEntry,
    ) -> Result<EventId, RepositoryAgentJournalError> {
        if entry.artifacts.iter().any(|artifact| !artifact.is_exact()) {
            return Err(RepositoryAgentJournalError::new(
                "agent journal rejected an inexact artifact",
            ));
        }
        let event_id = EventId::new();
        self.entries
            .lock()
            .map_err(|_| RepositoryAgentJournalError::new("agent journal lock was poisoned"))?
            .push(RetainedRepositoryAgentJournalEntry { event_id, entry });
        Ok(event_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryAgentDependencyHandoffV1 {
    work_order_id: WorkOrderId,
    outcome: HandoffOutcome,
    summary: String,
    artifact_sha256: Vec<String>,
    evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryAgentToolObservationV1 {
    observed_event_id: EventId,
    observed: ChildToolObservedV2,
    result: Option<RepositoryAgentModelToolResultV1>,
}

/// Lossless model-facing projection of a verified repository result.
///
/// The broker artifact remains the canonical provenance. This projection only
/// changes how those exact bytes are presented to the next model turn: valid
/// UTF-8 is exposed directly as text, while arbitrary bytes retain the
/// broker's canonical base64 wire. UTF-8 decoding is a mechanical encoding
/// decision, never semantic content classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "tool",
    content = "result",
    rename_all = "snake_case"
)]
enum RepositoryAgentModelToolResultV1 {
    RepositoryTree(RepositoryTreeResultV1),
    RepositoryFileReadUtf8(RepositoryAgentUtf8FileReadResultV1),
    RepositoryFileReadBase64(RepositoryReadFileResultV2),
    LiteralSearch(RepositoryLiteralSearchResultV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryAgentUtf8FileReadResultV1 {
    path: birdcode_protocol::RepositoryRelativePathV1,
    offset_bytes: u64,
    content_offset_bytes: u64,
    leading_boundary_bytes: Vec<u8>,
    content_utf8: String,
    content_sha256: Sha256Digest,
    trailing_boundary_bytes: Vec<u8>,
    file_byte_len: u64,
    truncated: bool,
}

/// Runtime-owned identity that the model must copy into its next plan.
///
/// The model decides the semantic plan transition, but it must never be asked
/// to derive a cryptographic digest from JSON bytes. Supplying the exact next
/// revision and predecessor digest keeps that mechanical binding explicit and
/// independently validated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryAgentRequiredPlanIdentityV1 {
    plan_id: ChildLocalPlanId,
    revision: u64,
    previous_plan_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryAgentTurnInputV1 {
    contract_version: u32,
    binding: ChildExecutionBinding,
    local_plan_id: ChildLocalPlanId,
    model_call_ordinal: u32,
    objective: String,
    acceptance_criteria: Vec<String>,
    dependency_handoffs: Vec<RepositoryAgentDependencyHandoffV1>,
    available_tool_grants: Vec<RepositoryToolGrantV1>,
    remaining_tool_calls: u64,
    remaining_output_tokens: u64,
    minimum_plan_revisions_before_finish: u32,
    required_plan_identity: RepositoryAgentRequiredPlanIdentityV1,
    prior_plan: Option<ChildLocalPlanSnapshotV1>,
    tool_observations: Vec<RepositoryAgentToolObservationV1>,
    previous_rejection: Option<RepositoryAgentRejectionV1>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryAgentModelEvidenceV1<'a> {
    contract_version: u32,
    binding: &'a ChildExecutionBinding,
    model_call_id: ChildModelCallId,
    model_call_ordinal: u32,
    prepared_event_id: EventId,
    response: &'a StructuredInferenceResponse,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryAgentModelErrorEvidenceV1<'a> {
    contract_version: u32,
    binding: &'a ChildExecutionBinding,
    model_call_id: ChildModelCallId,
    model_call_ordinal: u32,
    prepared_event_id: EventId,
    error: &'a BackendError,
}

#[derive(Clone, Debug)]
struct SuccessfulObservation {
    observed_event_id: EventId,
    result_artifact: ArtifactRef,
}

struct AttemptState {
    binding: ChildExecutionBinding,
    local_plan_id: ChildLocalPlanId,
    prior_plan: Option<ChildLocalPlanSnapshotV1>,
    observations: Vec<RepositoryAgentToolObservationV1>,
    successful_observations: BTreeMap<ChildToolCallId, SuccessfulObservation>,
    previous_rejection: Option<RepositoryAgentRejectionV1>,
    model_calls: u32,
    action_rejections: u32,
    tool_calls: u64,
    model_visible_read_bytes: u64,
    remaining_output_tokens: u64,
    reported_output_tokens: Option<u64>,
}

#[derive(Debug)]
struct RepositoryAgentBrokerLaneState {
    healthy: bool,
}

/// Broker-epoch-scoped preparation lane shared by every worker authority that
/// can reach the same broker instance.
pub struct RepositoryAgentBrokerLane {
    broker: RepositoryToolBroker,
    state: Mutex<RepositoryAgentBrokerLaneState>,
}

impl RepositoryAgentBrokerLane {
    #[must_use]
    pub fn new(broker: RepositoryToolBroker) -> Self {
        Self {
            broker,
            state: Mutex::new(RepositoryAgentBrokerLaneState { healthy: true }),
        }
    }

    #[must_use]
    pub const fn broker(&self) -> &RepositoryToolBroker {
        &self.broker
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.healthy)
    }

    fn mark_reconciliation_required(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.healthy = false;
        }
    }

    fn mark_ready(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.healthy = true;
        }
    }
}

/// Exact trusted mapping from one validated work order to one broker lane and
/// a mechanically selected subset of its opaque tool grants.
#[derive(Clone)]
pub struct RepositoryAgentDispatchAuthority {
    work_order: WorkOrder,
    attestation: DispatchAttestation,
    allowed_tool_grant_ids: BTreeSet<RepositoryToolGrantId>,
    broker_lane: Arc<RepositoryAgentBrokerLane>,
}

impl RepositoryAgentDispatchAuthority {
    /// Binds one exact validated work order and graph digest to a broker lane.
    /// The allow-list is trusted adapter configuration and is never inferred
    /// from capability text.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the graph digest, permission/workspace
    /// authority, serialization or broker grant subset is invalid.
    pub fn bind(
        graph_sha256: impl Into<String>,
        work_order: WorkOrder,
        allowed_tool_grant_ids: BTreeSet<RepositoryToolGrantId>,
        broker_lane: Arc<RepositoryAgentBrokerLane>,
    ) -> Result<Self, RepositoryAgentConfigError> {
        let graph_sha256 = Sha256Digest::parse(graph_sha256.into())
            .map_err(|_| RepositoryAgentConfigError::InvalidAuthorityGraphDigest)?
            .as_str()
            .to_owned();
        if work_order.permissions.capabilities.is_empty() {
            return Err(RepositoryAgentConfigError::EmptyPermissionAuthority);
        }
        if work_order.workspace.access != WorkspaceAccess::ReadOnly
            || !matches!(
                &work_order.workspace.source,
                WorkspaceSourceBinding::BrokeredRepositorySnapshotV1 { snapshot_sha256 }
                    if snapshot_sha256
                        == broker_lane
                            .broker()
                            .authority()
                            .snapshot
                            .declared_snapshot_digest
                            .as_str()
            )
        {
            return Err(RepositoryAgentConfigError::InvalidWorkspaceAuthority);
        }
        let broker_grants = broker_lane
            .broker()
            .authority()
            .tool_grants
            .iter()
            .map(RepositoryToolGrantV1::tool_grant_id)
            .collect::<BTreeSet<_>>();
        if !allowed_tool_grant_ids.is_subset(&broker_grants) {
            return Err(RepositoryAgentConfigError::UnknownToolGrant);
        }
        if broker_lane
            .broker()
            .authority()
            .tool_grants
            .iter()
            .filter(|grant| allowed_tool_grant_ids.contains(&grant.tool_grant_id()))
            .any(|grant| {
                matches!(
                    grant,
                    RepositoryToolGrantV1::RepositoryFileRead { max_bytes, .. }
                        if *max_bytes > REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES
                )
            })
        {
            return Err(RepositoryAgentConfigError::ModelVisibleReadGrantTooLarge);
        }
        let work_order_bytes = serde_json::to_vec(&work_order)
            .map_err(|_| RepositoryAgentConfigError::InvalidAuthorityEncoding)?;
        let permission_bytes = serde_json::to_vec(&work_order.permissions)
            .map_err(|_| RepositoryAgentConfigError::InvalidAuthorityEncoding)?;
        let attestation = DispatchAttestation {
            graph_sha256,
            work_order_sha256: Sha256Digest::of_bytes(&work_order_bytes)
                .as_str()
                .to_owned(),
            permissions_sha256: Sha256Digest::of_bytes(&permission_bytes)
                .as_str()
                .to_owned(),
            assignment: work_order.assignment.clone(),
            context_manifest_sha256: work_order.context_manifest_sha256.clone(),
            workspace: work_order.workspace.clone(),
            budget: work_order.budget,
        };
        Ok(Self {
            work_order,
            attestation,
            allowed_tool_grant_ids,
            broker_lane,
        })
    }
}

/// The first real `BirdCode` worker implementation accepted by `ActorGraphExecutor`.
pub struct RepositoryAgentWorker<J: RepositoryAgentJournal + ?Sized> {
    backend: Arc<dyn ModelBackend>,
    authorities: BTreeMap<WorkOrderId, RepositoryAgentDispatchAuthority>,
    journal: Arc<J>,
    policy: RepositoryAgentPolicy,
    runtime_instance_id: RuntimeInstanceId,
    started_at: Instant,
}

impl<J: RepositoryAgentJournal + ?Sized> RepositoryAgentWorker<J> {
    /// Constructs a worker around one backend, repository broker and journal.
    ///
    /// # Errors
    ///
    /// Returns a typed error when policy limits or backend identity integrity
    /// are invalid.
    pub fn new(
        backend: Arc<dyn ModelBackend>,
        authorities: Vec<RepositoryAgentDispatchAuthority>,
        journal: Arc<J>,
        policy: RepositoryAgentPolicy,
    ) -> Result<Self, RepositoryAgentConfigError> {
        let policy = policy.validate()?;
        let instance = backend.instance_identity();
        instance
            .validate_integrity()
            .map_err(|_| RepositoryAgentConfigError::InvalidBackendIdentity)?;
        if instance.backend_id() != backend.backend_id() {
            return Err(RepositoryAgentConfigError::InvalidBackendIdentity);
        }
        if authorities.is_empty() {
            return Err(RepositoryAgentConfigError::EmptyAuthority);
        }
        let mut authority_map = BTreeMap::new();
        for authority in authorities {
            if authority_map
                .insert(authority.work_order.id, authority)
                .is_some()
            {
                return Err(RepositoryAgentConfigError::DuplicateWorkOrderAuthority);
            }
        }
        Ok(Self {
            backend,
            authorities: authority_map,
            journal,
            policy,
            runtime_instance_id: RuntimeInstanceId::new(),
            started_at: Instant::now(),
        })
    }

    fn clock(&self) -> RuntimeClockReading {
        RuntimeClockReading {
            runtime_instance_id: self.runtime_instance_id,
            monotonic_nanos: u64::try_from(self.started_at.elapsed().as_nanos())
                .unwrap_or(u64::MAX),
            observed_at: Utc::now(),
        }
    }

    fn retain(
        &self,
        record: RepositoryAgentJournalRecord,
        artifacts: Vec<RepositoryAgentArtifact>,
    ) -> Result<EventId, AgentFailure> {
        if artifacts.iter().any(|artifact| !artifact.is_exact()) {
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "worker attempted to retain an inexact artifact",
                Usage::default(),
            ));
        }
        self.journal
            .retain(RepositoryAgentJournalEntry { record, artifacts })
            .map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("repository-agent journal rejected a boundary: {error}"),
                    Usage::default(),
                )
            })
    }

    fn failure(
        &self,
        kind: AgentFailureKind,
        message: impl Into<String>,
        usage: Usage,
    ) -> AgentFailure {
        AgentFailure {
            kind,
            message: message.into(),
            usage,
            execution_receipt_id: format!("repository-agent-runtime:{}", self.runtime_instance_id),
            effect_receipt_id: None,
        }
    }

    fn usage(state: &AttemptState) -> Usage {
        Usage {
            output_tokens: state.reported_output_tokens,
            tool_calls: state.tool_calls,
        }
    }

    fn reject(
        &self,
        state: &mut AttemptState,
        model_call_id: ChildModelCallId,
        observed_event_id: EventId,
        rejection: RepositoryAgentRejectionV1,
    ) -> Result<(), AgentFailure> {
        self.retain(
            RepositoryAgentJournalRecord::ActionRejected {
                binding: state.binding.clone(),
                model_call_id,
                model_observed_event_id: observed_event_id,
                rejection,
            },
            Vec::new(),
        )?;
        state.action_rejections = state.action_rejections.saturating_add(1);
        state.previous_rejection = Some(rejection);
        if state.action_rejections > self.policy.max_action_rejections {
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "model exhausted the typed action-repair budget",
                Self::usage(state),
            ));
        }
        Ok(())
    }

    fn reject_model_contract(
        &self,
        state: &AttemptState,
        model_call_id: ChildModelCallId,
        model_observed_event_id: EventId,
        violation: RepositoryAgentModelContractViolationV1,
    ) -> Result<(), AgentFailure> {
        self.retain(
            RepositoryAgentJournalRecord::ModelContractRejected {
                binding: state.binding.clone(),
                model_call_id,
                model_observed_event_id,
                violation,
            },
            Vec::new(),
        )?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the first vertical worker keeps its causally ordered model/tool boundaries together; later slices will extract durable phase objects"
    )]
    async fn run_attempt(&self, dispatch: AgentDispatch) -> Result<AgentCompletion, AgentFailure> {
        let Some(authority) = self.authorities.get(&dispatch.work_order.id).cloned() else {
            return Err(self.failure(
                AgentFailureKind::PermissionDenied,
                "dispatch has no exact repository-agent authority",
                Usage::default(),
            ));
        };
        let broker = authority.broker_lane.broker();
        let lineage = &dispatch.work_order.assignment.lineage;
        let instance = self.backend.instance_identity();
        if dispatch.graph_sha256 != authority.attestation.graph_sha256
            || dispatch.attestation != authority.attestation
            || dispatch.work_order.as_ref() != &authority.work_order
            || lineage.backend_id != self.backend.backend_id().as_str()
            || lineage.model_id.is_empty()
            || lineage.deployment_id != instance.configured_deployment_id().as_str()
            || dispatch.work_order.workspace.access != WorkspaceAccess::ReadOnly
            || !matches!(
                &dispatch.work_order.workspace.source,
                WorkspaceSourceBinding::BrokeredRepositorySnapshotV1 { snapshot_sha256 }
                    if snapshot_sha256
                        == broker
                            .authority()
                            .snapshot
                            .declared_snapshot_digest
                            .as_str()
            )
        {
            return Err(self.failure(
                AgentFailureKind::PermissionDenied,
                "dispatch model lineage or workspace does not match the configured worker authority",
                Usage::default(),
            ));
        }
        let model_id = ModelId::new(lineage.model_id.clone()).map_err(|error| {
            self.failure(
                AgentFailureKind::PermissionDenied,
                format!("dispatch model identity is invalid: {error}"),
                Usage::default(),
            )
        })?;
        let work_order_digest = Sha256Digest::parse(dispatch.attestation.work_order_sha256.clone())
            .map_err(|error| {
                self.failure(
                    AgentFailureKind::PermissionDenied,
                    format!("dispatch work-order digest is invalid: {error}"),
                    Usage::default(),
                )
            })?;
        let context_manifest_digest = Sha256Digest::parse(
            dispatch.attestation.context_manifest_sha256.clone(),
        )
        .map_err(|error| {
            self.failure(
                AgentFailureKind::PermissionDenied,
                format!("dispatch context digest is invalid: {error}"),
                Usage::default(),
            )
        })?;
        let binding = ChildExecutionBinding {
            work_order_id: ChildWorkOrderId::from_uuid(dispatch.work_order.id.as_uuid()),
            execution_id: ChildExecutionId::from_uuid(dispatch.execution_id.as_uuid()),
            attempt_id: ChildAttemptId::from_uuid(dispatch.attempt_id.as_uuid()),
            child_actor_id: ChildActorId::from_uuid(dispatch.actor_id.as_uuid()),
            context_id: birdcode_protocol::ChildContextId::new(),
            work_order_digest,
            context_manifest_digest,
        };
        let local_plan_id = ChildLocalPlanId::new();
        self.retain(
            RepositoryAgentJournalRecord::ExecutionStarted {
                binding: binding.clone(),
                local_plan_id,
                model_lineage: lineage.clone(),
            },
            Vec::new(),
        )?;
        let mut state = AttemptState {
            binding,
            local_plan_id,
            prior_plan: None,
            observations: Vec::new(),
            successful_observations: BTreeMap::new(),
            previous_rejection: None,
            model_calls: 0,
            action_rejections: 0,
            tool_calls: 0,
            model_visible_read_bytes: 0,
            remaining_output_tokens: dispatch.work_order.budget.max_output_tokens,
            reported_output_tokens: Some(0),
        };

        loop {
            if state.model_calls >= self.policy.max_model_calls
                || state.remaining_output_tokens == 0
            {
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "agent exhausted its model-call or output-token budget",
                    Self::usage(&state),
                ));
            }
            state.model_calls = state.model_calls.saturating_add(1);
            let call_ordinal = state.model_calls;
            let model_call_id = ChildModelCallId::new();
            let max_output_tokens = u64::from(self.policy.max_output_tokens_per_call)
                .min(state.remaining_output_tokens);
            let max_output_tokens = u32::try_from(max_output_tokens).map_err(|_| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    "model-call token ceiling does not fit the backend contract",
                    Self::usage(&state),
                )
            })?;
            let remaining_tool_calls = dispatch
                .work_order
                .budget
                .max_tool_calls
                .saturating_sub(state.tool_calls);
            let dependency_handoffs = dispatch
                .dependency_handoffs
                .iter()
                .map(
                    |(work_order_id, handoff)| RepositoryAgentDependencyHandoffV1 {
                        work_order_id: *work_order_id,
                        outcome: handoff.outcome,
                        summary: handoff.summary.clone(),
                        artifact_sha256: handoff.artifact_sha256.clone(),
                        evidence_ids: handoff.evidence_ids.clone(),
                    },
                )
                .collect();
            let required_previous_plan_digest = state
                .prior_plan
                .as_ref()
                .map(|plan| {
                    serde_json::to_vec(plan)
                        .map(|bytes| Sha256Digest::of_bytes(&bytes))
                        .map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!(
                                    "prior plan could not be bound into the next turn: {error}"
                                ),
                                Self::usage(&state),
                            )
                        })
                })
                .transpose()?;
            let required_plan_identity = RepositoryAgentRequiredPlanIdentityV1 {
                plan_id: state.local_plan_id,
                revision: state
                    .prior_plan
                    .as_ref()
                    .map_or(1, |plan| plan.revision.saturating_add(1)),
                previous_plan_digest: required_previous_plan_digest,
            };
            let turn = RepositoryAgentTurnInputV1 {
                contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                binding: state.binding.clone(),
                local_plan_id: state.local_plan_id,
                model_call_ordinal: call_ordinal,
                objective: dispatch.work_order.objective.clone(),
                acceptance_criteria: dispatch.work_order.acceptance_criteria.clone(),
                dependency_handoffs,
                available_tool_grants: broker
                    .authority()
                    .tool_grants
                    .iter()
                    .filter(|grant| {
                        authority
                            .allowed_tool_grant_ids
                            .contains(&grant.tool_grant_id())
                    })
                    .cloned()
                    .collect(),
                remaining_tool_calls,
                remaining_output_tokens: state.remaining_output_tokens,
                minimum_plan_revisions_before_finish: self.policy.min_plan_revisions_before_finish,
                required_plan_identity,
                prior_plan: state.prior_plan.clone(),
                tool_observations: state.observations.clone(),
                previous_rejection: state.previous_rejection,
            };
            let turn_json = serde_json::to_string(&turn).map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("agent turn could not be encoded: {error}"),
                    Self::usage(&state),
                )
            })?;
            if turn_json.len() > CHILD_REPOSITORY_EXPLORER_V1_MAX_RAW_INPUT_BYTES {
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "agent turn exceeded the repository-explorer raw-input ceiling",
                    Self::usage(&state),
                ));
            }
            let output = repository_agent_prompt::output_spec().map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("agent output contract is invalid: {error}"),
                    Self::usage(&state),
                )
            })?;
            let mut request = StructuredInferenceRequest::new(
                model_id.clone(),
                repository_agent_prompt::messages(turn_json),
                output,
                max_output_tokens,
            )
            .map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("agent model request is invalid: {error}"),
                    Self::usage(&state),
                )
            })?;
            if let Some(reasoning) = self.policy.reasoning {
                request = request.with_reasoning(reasoning);
            }
            let request_artifact = RepositoryAgentArtifact::from_bytes(
                MODEL_REQUEST_MEDIA_TYPE,
                serde_json::to_vec(&request).map_err(|error| {
                    self.failure(
                        AgentFailureKind::PermanentBackend,
                        format!("agent request evidence could not be encoded: {error}"),
                        Self::usage(&state),
                    )
                })?,
            );
            if request_artifact.artifact.size_bytes > CHILD_RECONNAISSANCE_MAX_MODEL_ARTIFACT_BYTES
            {
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "agent model request exceeded the evidence-artifact ceiling",
                    Self::usage(&state),
                ));
            }
            let prepared_event_id = self.retain(
                RepositoryAgentJournalRecord::ModelPrepared {
                    binding: state.binding.clone(),
                    model_call_id,
                    model_call_ordinal: call_ordinal,
                    request_artifact: request_artifact.artifact.clone(),
                },
                vec![request_artifact],
            )?;
            let response = match self.backend.infer_structured(request).await {
                Ok(response) => response,
                Err(error) => {
                    let full_error_bytes =
                        serde_json::to_vec(&RepositoryAgentModelErrorEvidenceV1 {
                            contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                            binding: &state.binding,
                            model_call_id,
                            model_call_ordinal: call_ordinal,
                            prepared_event_id,
                            error: &error,
                        })
                        .map_err(|encode_error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!(
                                    "backend error evidence could not be encoded: {encode_error}"
                                ),
                                Self::usage(&state),
                            )
                        })?;
                    let error_artifact = if u64::try_from(full_error_bytes.len())
                        .unwrap_or(u64::MAX)
                        <= CHILD_RECONNAISSANCE_MAX_MODEL_ARTIFACT_BYTES
                    {
                        RepositoryAgentArtifact::from_bytes(
                            MODEL_ERROR_MEDIA_TYPE,
                            full_error_bytes,
                        )
                    } else {
                        RepositoryAgentArtifact::from_bytes(
                            MODEL_CONTRACT_ERROR_MEDIA_TYPE,
                            serde_json::to_vec(&serde_json::json!({
                                "contract_version": CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                                "binding": &state.binding,
                                "model_call_id": model_call_id,
                                "model_call_ordinal": call_ordinal,
                                "prepared_event_id": prepared_event_id,
                                "violation": "backend_error_evidence_too_large",
                                "full_error_sha256": Sha256Digest::of_bytes(&full_error_bytes),
                                "full_error_size_bytes": full_error_bytes.len(),
                            }))
                            .map_err(|encode_error| {
                                self.failure(
                                    AgentFailureKind::PermanentBackend,
                                    format!(
                                        "backend error summary could not be encoded: {encode_error}"
                                    ),
                                    Self::usage(&state),
                                )
                            })?,
                        )
                    };
                    self.retain(
                        RepositoryAgentJournalRecord::ModelFailed {
                            binding: state.binding.clone(),
                            model_call_id,
                            model_call_ordinal: call_ordinal,
                            prepared_event_id,
                            error_artifact: error_artifact.artifact.clone(),
                        },
                        vec![error_artifact],
                    )?;
                    return Err(self.failure(
                        AgentFailureKind::PermanentBackend,
                        format!("model backend failed: {error}"),
                        Self::usage(&state),
                    ));
                }
            };
            let response_output_tokens = response
                .usage
                .as_ref()
                .and_then(|usage| usage.output_tokens);
            let charged_output_tokens =
                response_output_tokens.unwrap_or(u64::from(max_output_tokens));
            state.remaining_output_tokens = state
                .remaining_output_tokens
                .saturating_sub(charged_output_tokens);
            state.reported_output_tokens =
                match (state.reported_output_tokens, response_output_tokens) {
                    (Some(total), Some(current)) => total.checked_add(current),
                    _ => None,
                };
            let evidence_artifact = RepositoryAgentArtifact::from_bytes(
                MODEL_RESPONSE_MEDIA_TYPE,
                serde_json::to_vec(&RepositoryAgentModelEvidenceV1 {
                    contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                    binding: &state.binding,
                    model_call_id,
                    model_call_ordinal: call_ordinal,
                    prepared_event_id,
                    response: &response,
                })
                .map_err(|error| {
                    self.failure(
                        AgentFailureKind::PermanentBackend,
                        format!("model response evidence could not be encoded: {error}"),
                        Self::usage(&state),
                    )
                })?,
            );
            if evidence_artifact.artifact.size_bytes > CHILD_RECONNAISSANCE_MAX_MODEL_ARTIFACT_BYTES
            {
                let oversized_artifact = evidence_artifact.artifact.clone();
                let error_artifact = RepositoryAgentArtifact::from_bytes(
                    MODEL_CONTRACT_ERROR_MEDIA_TYPE,
                    serde_json::to_vec(&serde_json::json!({
                        "contract_version": CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                        "binding": &state.binding,
                        "model_call_id": model_call_id,
                        "model_call_ordinal": call_ordinal,
                        "prepared_event_id": prepared_event_id,
                        "violation": "model_response_evidence_too_large",
                        "response_artifact": oversized_artifact,
                    }))
                    .map_err(|error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("model contract-error evidence could not be encoded: {error}"),
                            Self::usage(&state),
                        )
                    })?,
                );
                self.retain(
                    RepositoryAgentJournalRecord::ModelFailed {
                        binding: state.binding.clone(),
                        model_call_id,
                        model_call_ordinal: call_ordinal,
                        prepared_event_id,
                        error_artifact: error_artifact.artifact.clone(),
                    },
                    vec![error_artifact],
                )?;
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "backend response exceeded the evidence-artifact ceiling",
                    Self::usage(&state),
                ));
            }
            let model_observed_event_id = self.retain(
                RepositoryAgentJournalRecord::ModelObserved {
                    binding: state.binding.clone(),
                    model_call_id,
                    model_call_ordinal: call_ordinal,
                    prepared_event_id,
                    evidence_artifact: evidence_artifact.artifact.clone(),
                    output_tokens: response_output_tokens,
                },
                vec![evidence_artifact.clone()],
            )?;
            if response_output_tokens.is_some_and(|tokens| tokens > u64::from(max_output_tokens)) {
                self.reject_model_contract(
                    &state,
                    model_call_id,
                    model_observed_event_id,
                    RepositoryAgentModelContractViolationV1::OutputTokenCeilingExceeded,
                )?;
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "backend reported output usage above the prepared request ceiling",
                    Self::usage(&state),
                ));
            }
            if response.model_id != model_id
                || !instance.matches_response_evidence(&response.evidence)
                || !serde_json::from_str::<serde_json::Value>(&response.raw_text)
                    .is_ok_and(|value| value == response.value)
            {
                self.reject_model_contract(
                    &state,
                    model_call_id,
                    model_observed_event_id,
                    RepositoryAgentModelContractViolationV1::ResponseBindingMismatch,
                )?;
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "backend response failed exact model, endpoint or raw JSON binding",
                    Self::usage(&state),
                ));
            }
            let normalized = match serde_json::from_value::<ChildModelStructuredResponseV1>(
                response.value.clone(),
            ) {
                Ok(normalized) => normalized,
                Err(error) => {
                    self.reject_model_contract(
                        &state,
                        model_call_id,
                        model_observed_event_id,
                        RepositoryAgentModelContractViolationV1::StructuredResponseInvalid,
                    )?;
                    return Err(self.failure(
                        AgentFailureKind::PermanentBackend,
                        format!("backend returned a nonconforming structured response: {error}"),
                        Self::usage(&state),
                    ));
                }
            };
            let plan_binding = match validate_plan(
                &dispatch.work_order.objective,
                &state.binding,
                state.local_plan_id,
                state.prior_plan.as_ref(),
                &normalized,
            ) {
                Ok(binding) => binding,
                Err(rejection) => {
                    self.reject(
                        &mut state,
                        model_call_id,
                        model_observed_event_id,
                        rejection,
                    )?;
                    continue;
                }
            };
            state.prior_plan = Some(normalized.plan.clone());

            if let ChildActionV1::Finish { handoff } = &normalized.action {
                if normalized.plan.revision
                    < u64::from(self.policy.min_plan_revisions_before_finish)
                {
                    self.reject(
                        &mut state,
                        model_call_id,
                        model_observed_event_id,
                        RepositoryAgentRejectionV1::FinishBeforeMinimumRevision,
                    )?;
                    continue;
                }
                let finish_evidence =
                    match validate_finish_evidence(handoff, &state.successful_observations) {
                        Ok(evidence) => evidence,
                        Err(rejection) => {
                            self.reject(
                                &mut state,
                                model_call_id,
                                model_observed_event_id,
                                rejection,
                            )?;
                            continue;
                        }
                    };
                let handoff_id = ChildHandoffId::new();
                let (action_binding, action_artifact) = make_action_binding(
                    &state.binding,
                    &normalized,
                    &plan_binding,
                    model_call_id,
                    call_ordinal,
                    model_observed_event_id,
                    &evidence_artifact,
                    Some(handoff_id),
                )
                .map_err(|message| {
                    self.failure(
                        AgentFailureKind::PermanentBackend,
                        message,
                        Self::usage(&state),
                    )
                })?;
                self.retain(
                    RepositoryAgentJournalRecord::ActionValidated {
                        binding: state.binding.clone(),
                        action_binding: action_binding.clone(),
                    },
                    vec![action_artifact],
                )?;
                let handoff_document = ChildHandoffDocument {
                    contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                    binding: state.binding.clone(),
                    handoff_id,
                    content: handoff.clone(),
                };
                let handoff_artifact = RepositoryAgentArtifact::from_bytes(
                    CHILD_HANDOFF_MEDIA_TYPE,
                    serde_json::to_vec(&handoff_document).map_err(|error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("finish handoff could not be encoded: {error}"),
                            Self::usage(&state),
                        )
                    })?,
                );
                let finish_event_id = self.retain(
                    RepositoryAgentJournalRecord::FinishAccepted {
                        binding: state.binding.clone(),
                        handoff_id,
                        action_binding,
                        handoff_artifact: handoff_artifact.artifact.clone(),
                    },
                    vec![handoff_artifact.clone()],
                )?;
                let mut artifact_sha256 = finish_evidence.artifact_sha256;
                artifact_sha256.insert(handoff_artifact.artifact.sha256);
                return Ok(AgentCompletion {
                    outcome: match handoff.status {
                        ChildHandoffStatus::Complete => HandoffOutcome::Completed,
                        ChildHandoffStatus::Partial => HandoffOutcome::Partial,
                        ChildHandoffStatus::Blocked => HandoffOutcome::Blocked,
                    },
                    summary: handoff.summary.clone(),
                    execution_receipt_id: format!("repository-agent-event:{finish_event_id}"),
                    artifact_sha256: artifact_sha256.into_iter().collect(),
                    evidence_ids: finish_evidence
                        .observed_event_ids
                        .into_iter()
                        .map(|event_id| event_id.to_string())
                        .collect(),
                    usage: Self::usage(&state),
                });
            }

            if state.tool_calls >= dispatch.work_order.budget.max_tool_calls {
                self.reject(
                    &mut state,
                    model_call_id,
                    model_observed_event_id,
                    RepositoryAgentRejectionV1::ToolBudgetExhausted,
                )?;
                continue;
            }
            let Some(tool_grant_id) = normalized.action.tool_grant_id() else {
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "validated non-finish action did not contain a tool grant",
                    Self::usage(&state),
                ));
            };
            if !authority.allowed_tool_grant_ids.contains(&tool_grant_id) {
                self.reject(
                    &mut state,
                    model_call_id,
                    model_observed_event_id,
                    RepositoryAgentRejectionV1::ToolGrantOutsideDispatchAuthority,
                )?;
                continue;
            }
            let Some(operation) = normalized.action.tool_operation() else {
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "validated non-finish action did not contain a tool operation",
                    Self::usage(&state),
                ));
            };
            if model_visible_read_reservation(state.model_visible_read_bytes, &operation).is_none()
            {
                self.reject(
                    &mut state,
                    model_call_id,
                    model_observed_event_id,
                    RepositoryAgentRejectionV1::ModelVisibleReadBudgetExceeded,
                )?;
                continue;
            }
            let (action_binding, action_artifact) = make_action_binding(
                &state.binding,
                &normalized,
                &plan_binding,
                model_call_id,
                call_ordinal,
                model_observed_event_id,
                &evidence_artifact,
                None,
            )
            .map_err(|message| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    message,
                    Self::usage(&state),
                )
            })?;
            self.retain(
                RepositoryAgentJournalRecord::ActionValidated {
                    binding: state.binding.clone(),
                    action_binding: action_binding.clone(),
                },
                vec![action_artifact],
            )?;
            let tool_call_id = ChildToolCallId::new();
            let tool_ordinal = u32::try_from(state.tool_calls.saturating_add(1)).map_err(|_| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    "tool-call ordinal exceeded the protocol representation",
                    Self::usage(&state),
                )
            })?;
            let (prepared, prepared_event_id) = {
                let mut coordinator = authority.broker_lane.state.lock().map_err(|_| {
                    self.failure(
                        AgentFailureKind::PermanentBackend,
                        "repository preparation coordinator was poisoned",
                        Self::usage(&state),
                    )
                })?;
                if !coordinator.healthy {
                    return Err(self.failure(
                        AgentFailureKind::PermanentBackend,
                        "repository broker epoch requires reconciliation before another prepare",
                        Self::usage(&state),
                    ));
                }
                let prepared = broker
                    .prepare(RepositoryToolPrepareInputV2 {
                        parameters: RepositoryToolCanonicalParametersV1 {
                            schema_version: REPOSITORY_BROKER_CONTRACT_VERSION,
                            binding: state.binding.clone(),
                            tool_call_id,
                            tool_ordinal,
                            action_binding,
                            tool_grant_id,
                            operation: operation.clone(),
                        },
                        runtime_prepared_at: self.clock(),
                    })
                    .map_err(|error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("repository broker could not prepare the tool call: {error}"),
                            Self::usage(&state),
                        )
                    })?;
                coordinator.healthy = false;
                state.tool_calls = state.tool_calls.saturating_add(1);
                let projection = project_prepared_event_v2(&prepared).map_err(|error| {
                    self.failure(
                        AgentFailureKind::PermanentBackend,
                        format!("repository Prepared projection failed: {error}"),
                        Self::usage(&state),
                    )
                })?;
                let event_id = match self.retain(
                    RepositoryAgentJournalRecord::ToolPrepared { projection },
                    vec![
                        RepositoryAgentArtifact::from_tooling(&prepared.canonical_parameters),
                        RepositoryAgentArtifact::from_tooling(&prepared.prepared_receipt),
                    ],
                ) {
                    Ok(event_id) => event_id,
                    Err(error) => {
                        coordinator.healthy = false;
                        return Err(error);
                    }
                };
                (prepared, event_id)
            };
            let execution_lane = Arc::clone(&authority.broker_lane);
            let execution_prepared = prepared.clone();
            let runtime_instance_id = self.runtime_instance_id;
            let runtime_started_at = self.started_at;
            let terminal = tokio::task::spawn_blocking(move || {
                execution_lane.broker().execute(
                    RepositoryToolExecuteInputV2 {
                        prepared: execution_prepared,
                        prepared_event_id,
                    },
                    move || RuntimeClockReading {
                        runtime_instance_id,
                        monotonic_nanos: u64::try_from(runtime_started_at.elapsed().as_nanos())
                            .unwrap_or(u64::MAX),
                        observed_at: Utc::now(),
                    },
                )
            })
            .await
            .map_err(|error| {
                authority.broker_lane.mark_reconciliation_required();
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("repository broker task did not join: {error}"),
                    Self::usage(&state),
                )
            })?
            .map_err(|error| {
                authority.broker_lane.mark_reconciliation_required();
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("repository broker execution failed: {error}"),
                    Self::usage(&state),
                )
            })?;
            if !verify_terminal_output_v2(&prepared, &terminal) {
                authority.broker_lane.mark_reconciliation_required();
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "repository broker terminal failed exact verification; reconciliation required",
                    Self::usage(&state),
                ));
            }
            let RepositoryToolTerminalV2::Observed(observed) = terminal else {
                let RepositoryToolTerminalV2::Unknown(unknown) = terminal else {
                    unreachable!("repository terminal has a closed two-variant contract")
                };
                let mut artifacts = unknown
                    .supporting_artifacts
                    .iter()
                    .map(RepositoryAgentArtifact::from_tooling)
                    .collect::<Vec<_>>();
                artifacts.push(RepositoryAgentArtifact::from_tooling(
                    &unknown.terminal_receipt,
                ));
                let retain_result = self.retain(
                    RepositoryAgentJournalRecord::ToolOutcomeUnknown {
                        binding: state.binding.clone(),
                        tool_call_id,
                        prepared_event_id,
                        terminal_receipt_artifact: unknown.terminal_receipt.artifact,
                    },
                    artifacts,
                );
                authority.broker_lane.mark_reconciliation_required();
                retain_result?;
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "repository tool outcome is unknown and its broker epoch requires reconciliation",
                    Self::usage(&state),
                ));
            };
            let projection = match project_observed_event_v2(&prepared, &observed) {
                Ok(projection) => projection,
                Err(error) => {
                    authority.broker_lane.mark_reconciliation_required();
                    return Err(self.failure(
                        AgentFailureKind::PermanentBackend,
                        format!("repository Observed projection failed: {error}"),
                        Self::usage(&state),
                    ));
                }
            };
            let mut terminal_artifacts = observed
                .supporting_artifacts
                .iter()
                .map(RepositoryAgentArtifact::from_tooling)
                .collect::<Vec<_>>();
            terminal_artifacts.push(RepositoryAgentArtifact::from_tooling(
                &observed.terminal_receipt,
            ));
            let observed_event_id = match self.retain(
                RepositoryAgentJournalRecord::ToolObserved {
                    projection: projection.clone(),
                },
                terminal_artifacts,
            ) {
                Ok(event_id) => event_id,
                Err(error) => {
                    authority.broker_lane.mark_reconciliation_required();
                    return Err(error);
                }
            };
            authority.broker_lane.mark_ready();
            let result = successful_result(&observed)?;
            if let Some((result, result_artifact)) = result {
                if let RepositoryToolResultV2::RepositoryFileRead(read) = &result {
                    let observed_bytes = u64::try_from(read.bytes.len()).unwrap_or(u64::MAX);
                    let observed_total = state
                        .model_visible_read_bytes
                        .saturating_add(observed_bytes);
                    if observed_bytes > REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES
                        || observed_total > REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES
                    {
                        return Err(self.failure(
                            AgentFailureKind::PermanentBackend,
                            "verified repository read exceeded the model-visible aggregate read budget",
                            Self::usage(&state),
                        ));
                    }
                    state.model_visible_read_bytes = observed_total;
                }
                state.successful_observations.insert(
                    tool_call_id,
                    SuccessfulObservation {
                        observed_event_id,
                        result_artifact,
                    },
                );
                state.observations.push(RepositoryAgentToolObservationV1 {
                    observed_event_id,
                    observed: projection,
                    result: Some(model_visible_result(result)),
                });
            } else {
                state.observations.push(RepositoryAgentToolObservationV1 {
                    observed_event_id,
                    observed: projection,
                    result: None,
                });
            }
            state.previous_rejection = None;
        }
    }
}

impl<J: RepositoryAgentJournal + ?Sized> AgentWorker for RepositoryAgentWorker<J> {
    fn execute(&self, dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(self.run_attempt(dispatch))
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "every argument is an exact lifecycle binding retained in the canonical action document"
)]
fn make_action_binding(
    binding: &ChildExecutionBinding,
    normalized: &ChildModelStructuredResponseV1,
    plan_binding: &ChildLocalPlanBindingV1,
    model_call_id: ChildModelCallId,
    model_call_ordinal: u32,
    model_observed_event_id: EventId,
    model_evidence: &RepositoryAgentArtifact,
    completion_handoff_id: Option<ChildHandoffId>,
) -> Result<(ChildValidatedActionBindingV1, RepositoryAgentArtifact), String> {
    let document = ChildValidatedActionDocumentV1 {
        contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        binding: binding.clone(),
        action_id: ChildValidatedActionId::new(),
        source_model_call_id: model_call_id,
        source_model_call_ordinal: model_call_ordinal,
        source_model_observed_event_id: model_observed_event_id,
        source_model_evidence_digest: Sha256Digest::of_bytes(&model_evidence.bytes),
        source_plan: plan_binding.clone(),
        active_plan_step_id: normalized.plan.active_step_id.clone(),
        completion_handoff_id,
        action: normalized.action.clone(),
    };
    let action_artifact = RepositoryAgentArtifact::from_bytes(
        CHILD_VALIDATED_ACTION_MEDIA_TYPE,
        serde_json::to_vec(&document)
            .map_err(|error| format!("validated action could not be encoded: {error}"))?,
    );
    let action_binding = ChildValidatedActionBindingV1 {
        action_id: document.action_id,
        source_model_call_id: model_call_id,
        source_model_call_ordinal: model_call_ordinal,
        source_model_observed_event_id: model_observed_event_id,
        source_model_evidence_digest: document.source_model_evidence_digest,
        source_plan: plan_binding.clone(),
        active_plan_step_id: document.active_plan_step_id,
        completion_handoff_id,
        validated_action_artifact: action_artifact.artifact.clone(),
        validated_action_digest: Sha256Digest::of_bytes(&action_artifact.bytes),
    };
    Ok((action_binding, action_artifact))
}

fn successful_result(
    observed: &birdcode_tooling::ObservedRepositoryToolCallV2,
) -> Result<Option<(RepositoryToolResultV2, ArtifactRef)>, AgentFailure> {
    let RepositoryToolObservedTerminalV2::Succeeded { result_artifact } =
        &observed.receipt.terminal
    else {
        return Ok(None);
    };
    let retained = observed
        .supporting_artifacts
        .iter()
        .find(|candidate| candidate.artifact == *result_artifact)
        .ok_or_else(|| AgentFailure {
            kind: AgentFailureKind::PermanentBackend,
            message: "repository success omitted its bound result artifact".to_owned(),
            usage: Usage::default(),
            execution_receipt_id: "repository-agent-result-validation".to_owned(),
            effect_receipt_id: None,
        })?;
    let result =
        birdcode_protocol::decode_repository_tool_result_v2(&retained.bytes).map_err(|_| {
            AgentFailure {
                kind: AgentFailureKind::PermanentBackend,
                message: "repository result artifact failed canonical decoding".to_owned(),
                usage: Usage::default(),
                execution_receipt_id: "repository-agent-result-validation".to_owned(),
                effect_receipt_id: None,
            }
        })?;
    Ok(Some((result, result_artifact.clone())))
}

fn model_visible_result(result: RepositoryToolResultV2) -> RepositoryAgentModelToolResultV1 {
    match result {
        RepositoryToolResultV2::RepositoryTree(result) => {
            RepositoryAgentModelToolResultV1::RepositoryTree(result)
        }
        RepositoryToolResultV2::RepositoryFileRead(result) => {
            let Some((content_start, content_end)) = model_visible_utf8_range(&result.bytes) else {
                return RepositoryAgentModelToolResultV1::RepositoryFileReadBase64(result);
            };
            let content_utf8 = std::str::from_utf8(&result.bytes[content_start..content_end])
                .expect("validated UTF-8 projection range");
            let escaped_length = json_escaped_utf8_payload_len(content_utf8);
            let base64_length = canonical_base64_payload_len(result.bytes.len());
            if escaped_length > base64_length.saturating_add(512) {
                return RepositoryAgentModelToolResultV1::RepositoryFileReadBase64(result);
            }
            RepositoryAgentModelToolResultV1::RepositoryFileReadUtf8(
                RepositoryAgentUtf8FileReadResultV1 {
                    path: result.path,
                    offset_bytes: result.offset_bytes,
                    content_offset_bytes: result
                        .offset_bytes
                        .saturating_add(u64::try_from(content_start).unwrap_or(u64::MAX)),
                    leading_boundary_bytes: result.bytes[..content_start].to_vec(),
                    content_utf8: content_utf8.to_owned(),
                    content_sha256: Sha256Digest::of_bytes(&result.bytes),
                    trailing_boundary_bytes: result.bytes[content_end..].to_vec(),
                    file_byte_len: result.file_byte_len,
                    truncated: result.truncated,
                },
            )
        }
        RepositoryToolResultV2::LiteralSearch(result) => {
            RepositoryAgentModelToolResultV1::LiteralSearch(result)
        }
    }
}

fn model_visible_utf8_range(bytes: &[u8]) -> Option<(usize, usize)> {
    let maximum_leading_boundary = bytes.len().min(3);
    for content_start in 0..=maximum_leading_boundary {
        if content_start > 0
            && !bytes[..content_start]
                .iter()
                .all(|byte| byte & 0b1100_0000 == 0b1000_0000)
        {
            continue;
        }
        match std::str::from_utf8(&bytes[content_start..]) {
            Ok(_) => return Some((content_start, bytes.len())),
            Err(error) if error.error_len().is_none() => {
                let content_end = content_start.saturating_add(error.valid_up_to());
                if bytes.len().saturating_sub(content_end) <= 3 {
                    return Some((content_start, content_end));
                }
            }
            Err(_) => {}
        }
    }
    None
}

fn json_escaped_utf8_payload_len(value: &str) -> u64 {
    value.bytes().fold(0_u64, |length, byte| {
        let encoded = match byte {
            b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        };
        length.saturating_add(encoded)
    })
}

fn canonical_base64_payload_len(byte_len: usize) -> u64 {
    u64::try_from(byte_len)
        .unwrap_or(u64::MAX)
        .saturating_add(2)
        .checked_div(3)
        .unwrap_or(u64::MAX)
        .saturating_mul(4)
}

fn model_visible_read_reservation(
    observed_read_bytes: u64,
    operation: &birdcode_protocol::ChildToolOperation,
) -> Option<u64> {
    let birdcode_protocol::ChildToolOperation::RepositoryFileRead { max_bytes, .. } = operation
    else {
        return Some(observed_read_bytes);
    };
    observed_read_bytes
        .checked_add(*max_bytes)
        .filter(|total| *total <= REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES)
}

fn bounded_nonempty(value: &str, maximum_scalars: usize, maximum_bytes: usize) -> bool {
    let count = value.chars().count();
    count > 0 && count <= maximum_scalars && value.len() <= maximum_bytes
}

fn bounded_identifier(value: &str) -> bool {
    bounded_nonempty(
        value,
        CHILD_RECONNAISSANCE_MAX_IDENTIFIER_UNICODE_SCALARS,
        CHILD_RECONNAISSANCE_MAX_IDENTIFIER_BYTES,
    )
}

fn bounded_text(value: &str) -> bool {
    bounded_nonempty(
        value,
        CHILD_RECONNAISSANCE_MAX_TEXT_UNICODE_SCALARS,
        CHILD_RECONNAISSANCE_MAX_TEXT_BYTES,
    )
}

const fn valid_step_transition(
    previous: ChildLocalPlanStepStatusV1,
    next: ChildLocalPlanStepStatusV1,
) -> bool {
    matches!(
        (previous, next),
        (
            ChildLocalPlanStepStatusV1::Pending,
            ChildLocalPlanStepStatusV1::Pending
                | ChildLocalPlanStepStatusV1::InProgress
                | ChildLocalPlanStepStatusV1::Blocked
                | ChildLocalPlanStepStatusV1::Cancelled
        ) | (
            ChildLocalPlanStepStatusV1::InProgress,
            ChildLocalPlanStepStatusV1::InProgress
                | ChildLocalPlanStepStatusV1::Completed
                | ChildLocalPlanStepStatusV1::Blocked
                | ChildLocalPlanStepStatusV1::Cancelled
        ) | (
            ChildLocalPlanStepStatusV1::Blocked,
            ChildLocalPlanStepStatusV1::Blocked
                | ChildLocalPlanStepStatusV1::InProgress
                | ChildLocalPlanStepStatusV1::Cancelled
        ) | (
            ChildLocalPlanStepStatusV1::Completed,
            ChildLocalPlanStepStatusV1::Completed
        ) | (
            ChildLocalPlanStepStatusV1::Cancelled,
            ChildLocalPlanStepStatusV1::Cancelled
        )
    )
}

fn valid_finish_plan_state(
    plan: &ChildLocalPlanSnapshotV1,
    status: ChildHandoffStatus,
    handoff_unknowns_empty: bool,
) -> bool {
    if plan.steps.iter().any(|step| {
        matches!(
            step.status,
            ChildLocalPlanStepStatusV1::Pending | ChildLocalPlanStepStatusV1::InProgress
        )
    }) {
        return false;
    }
    match status {
        ChildHandoffStatus::Complete => {
            handoff_unknowns_empty
                && plan
                    .steps
                    .iter()
                    .all(|step| step.status == ChildLocalPlanStepStatusV1::Completed)
        }
        ChildHandoffStatus::Partial => {
            plan.steps
                .iter()
                .any(|step| step.status == ChildLocalPlanStepStatusV1::Cancelled)
                || !handoff_unknowns_empty
        }
        ChildHandoffStatus::Blocked => plan
            .steps
            .iter()
            .any(|step| step.status == ChildLocalPlanStepStatusV1::Blocked),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the validator checks the closed local-plan transition contract in one auditable path"
)]
fn validate_plan(
    objective: &str,
    binding: &ChildExecutionBinding,
    local_plan_id: ChildLocalPlanId,
    prior: Option<&ChildLocalPlanSnapshotV1>,
    response: &ChildModelStructuredResponseV1,
) -> Result<ChildLocalPlanBindingV1, RepositoryAgentRejectionV1> {
    let plan = &response.plan;
    if response.contract_version != CHILD_RECONNAISSANCE_CONTRACT_VERSION
        || plan.contract_version != CHILD_RECONNAISSANCE_CONTRACT_VERSION
    {
        return Err(RepositoryAgentRejectionV1::ContractMismatch);
    }
    if plan.binding != *binding {
        return Err(RepositoryAgentRejectionV1::ExecutionBindingMismatch);
    }
    if plan.plan_id != local_plan_id {
        return Err(RepositoryAgentRejectionV1::PlanIdentityMismatch);
    }
    if plan.objective != objective {
        return Err(RepositoryAgentRejectionV1::ObjectiveMismatch);
    }
    let prior_digest = prior.and_then(|prior| {
        serde_json::to_vec(prior)
            .ok()
            .map(|bytes| Sha256Digest::of_bytes(&bytes))
    });
    let valid_revision = match prior {
        None => plan.revision == 1 && plan.previous_plan_digest.is_none(),
        Some(previous) => {
            plan.revision == previous.revision.saturating_add(1)
                && plan.previous_plan_digest == prior_digest
        }
    };
    if !valid_revision {
        return Err(RepositoryAgentRejectionV1::PlanRevisionMismatch);
    }
    if plan.steps.is_empty()
        || plan.steps.len() > CHILD_RECONNAISSANCE_MAX_PLAN_STEPS
        || plan.assumptions.len() > CHILD_RECONNAISSANCE_MAX_PLAN_ASSUMPTIONS
        || plan.unknowns.len() > CHILD_RECONNAISSANCE_MAX_PLAN_UNKNOWNS
    {
        return Err(RepositoryAgentRejectionV1::PlanStructureInvalid);
    }
    let mut steps = BTreeMap::new();
    let mut in_progress = Vec::new();
    for step in &plan.steps {
        if !bounded_identifier(step.step_id.as_str())
            || !bounded_text(&step.objective)
            || steps.insert(step.step_id.clone(), step).is_some()
        {
            return Err(RepositoryAgentRejectionV1::PlanStructureInvalid);
        }
        if step.status == ChildLocalPlanStepStatusV1::InProgress {
            in_progress.push(step.step_id.clone());
        }
    }
    if let Some(previous) = prior {
        for previous_step in &previous.steps {
            let Some(current) = steps.get(&previous_step.step_id) else {
                return Err(RepositoryAgentRejectionV1::PlanTransitionInvalid);
            };
            if current.objective != previous_step.objective
                || !valid_step_transition(previous_step.status, current.status)
            {
                return Err(RepositoryAgentRejectionV1::PlanTransitionInvalid);
            }
        }
    }
    let active_is_exact = match plan.active_step_id.as_ref() {
        Some(active) => in_progress.as_slice() == [active.clone()],
        None => in_progress.is_empty(),
    };
    if !active_is_exact {
        return Err(RepositoryAgentRejectionV1::PlanStructureInvalid);
    }
    let mut assumption_ids = BTreeSet::new();
    if plan.assumptions.iter().any(|assumption| {
        !bounded_identifier(&assumption.assumption_id)
            || !bounded_text(&assumption.statement)
            || !assumption_ids.insert(assumption.assumption_id.as_str())
    }) {
        return Err(RepositoryAgentRejectionV1::PlanStructureInvalid);
    }
    let mut unknown_ids = BTreeSet::new();
    if plan.unknowns.iter().any(|unknown| {
        !bounded_identifier(&unknown.unknown_id)
            || !bounded_text(&unknown.question)
            || !unknown_ids.insert(unknown.unknown_id.as_str())
    }) {
        return Err(RepositoryAgentRejectionV1::PlanStructureInvalid);
    }
    match &response.action {
        ChildActionV1::RepositoryTree { .. }
        | ChildActionV1::RepositoryFileRead { .. }
        | ChildActionV1::LiteralSearch { .. }
            if plan.active_step_id.is_some() => {}
        ChildActionV1::Finish { handoff }
            if plan.active_step_id.is_none()
                && valid_finish_plan_state(plan, handoff.status, handoff.unknowns.is_empty()) => {}
        _ => return Err(RepositoryAgentRejectionV1::ActionPlanStateInvalid),
    }
    let bytes =
        serde_json::to_vec(plan).map_err(|_| RepositoryAgentRejectionV1::PlanStructureInvalid)?;
    Ok(ChildLocalPlanBindingV1 {
        plan_id: plan.plan_id,
        revision: plan.revision,
        plan_digest: Sha256Digest::of_bytes(&bytes),
    })
}

struct FinishEvidence {
    observed_event_ids: BTreeSet<EventId>,
    artifact_sha256: BTreeSet<String>,
}

fn validate_finish_evidence(
    handoff: &ChildHandoffContentV1,
    observed: &BTreeMap<ChildToolCallId, SuccessfulObservation>,
) -> Result<FinishEvidence, RepositoryAgentRejectionV1> {
    if !bounded_text(&handoff.summary)
        || handoff.findings.len() > CHILD_RECONNAISSANCE_MAX_FINDINGS
        || handoff.unknowns.len() > CHILD_RECONNAISSANCE_MAX_UNRESOLVED_QUESTIONS
        || handoff.recommended_followups.len() > CHILD_RECONNAISSANCE_MAX_RECOMMENDED_FOLLOWUPS
        || (handoff.status == ChildHandoffStatus::Complete
            && (handoff.findings.is_empty() || observed.is_empty()))
    {
        return Err(RepositoryAgentRejectionV1::FinishEvidenceInvalid);
    }
    let mut finding_ids = BTreeSet::new();
    let mut evidence_count = 0_usize;
    let mut observed_event_ids = BTreeSet::new();
    let mut artifact_sha256 = BTreeSet::new();
    for finding in &handoff.findings {
        if !bounded_identifier(&finding.finding_id)
            || !bounded_text(&finding.statement)
            || finding.evidence.is_empty()
            || !finding_ids.insert(finding.finding_id.as_str())
        {
            return Err(RepositoryAgentRejectionV1::FinishEvidenceInvalid);
        }
        evidence_count = evidence_count.saturating_add(finding.evidence.len());
        if evidence_count > CHILD_RECONNAISSANCE_MAX_EVIDENCE_BINDINGS {
            return Err(RepositoryAgentRejectionV1::FinishEvidenceInvalid);
        }
        let mut identities = BTreeSet::new();
        for evidence in &finding.evidence {
            let Some(expected) = observed.get(&evidence.tool_call_id) else {
                return Err(RepositoryAgentRejectionV1::FinishEvidenceInvalid);
            };
            if expected.observed_event_id != evidence.observed_event_id
                || expected.result_artifact != evidence.result_artifact
                || !identities.insert((
                    evidence.tool_call_id,
                    evidence.observed_event_id,
                    evidence.result_artifact.sha256.clone(),
                ))
            {
                return Err(RepositoryAgentRejectionV1::FinishEvidenceInvalid);
            }
            observed_event_ids.insert(evidence.observed_event_id);
            artifact_sha256.insert(evidence.result_artifact.sha256.clone());
        }
    }
    let mut unknown_ids = BTreeSet::new();
    if handoff.unknowns.iter().any(|unknown| {
        !bounded_identifier(&unknown.unknown_id)
            || !bounded_text(&unknown.question)
            || !unknown_ids.insert(unknown.unknown_id.as_str())
    }) {
        return Err(RepositoryAgentRejectionV1::FinishEvidenceInvalid);
    }
    let mut followup_ids = BTreeSet::new();
    if handoff.recommended_followups.iter().any(|followup| {
        !bounded_identifier(&followup.followup_id)
            || !bounded_text(&followup.text)
            || !followup_ids.insert(followup.followup_id.as_str())
    }) {
        return Err(RepositoryAgentRejectionV1::FinishEvidenceInvalid);
    }
    Ok(FinishEvidence {
        observed_event_ids,
        artifact_sha256,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use birdcode_backends::{
        BackendDeploymentId, BackendEndpointOrigin, BackendFuture, BackendId,
        BackendInstanceIdentity, BackendTransportIdentity, InferenceEvidence, LmStudioBackend,
        LmStudioConfig, ModelCatalog, TokenUsage,
    };
    use birdcode_orchestrator::{
        ActorGraph, ActorGraphExecutor, ActorGraphLimits, ActorGraphOutcome, ActorGraphPolicy,
        AgentAssignment, AgentBudget, CapabilityId, InMemorySchedulerJournal, ModelProfileId,
        PermissionGrant, RoleId, WorkspaceGrant, WorkspaceLeaseId, WorkspaceLeasePolicy,
    };
    use birdcode_protocol::{
        ChildFindingConfidence, ChildHandoffEvidenceBinding, ChildHandoffFinding,
        ChildLocalPlanStepIdV1, ChildLocalPlanStepV1, ModelRepositoryPathComponentV1,
        ModelRepositoryPathV1, READ_ONLY_REPOSITORY_AGENT_V1_MAX_ATTEMPTS,
        READ_ONLY_REPOSITORY_AGENT_V1_MAX_MODEL_CALLS,
        READ_ONLY_REPOSITORY_AGENT_V1_MAX_TOOL_CALLS,
        READ_ONLY_REPOSITORY_AGENT_V1_MAX_WALL_TIME_SECONDS,
        READ_ONLY_REPOSITORY_AGENT_V1_OUTPUT_TOKENS_PER_CALL,
        READ_ONLY_REPOSITORY_AGENT_V1_TOTAL_RESERVED_OUTPUT_TOKENS,
        REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE, REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
        REPOSITORY_TOOL_POLICY_MEDIA_TYPE, REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE,
        RepositoryBrokerEpochStateV1, RepositoryBrokerInstanceId, RepositoryFileIdentityV1,
        RepositoryRootBindingV1, RepositorySnapshotBindingV1, RepositorySnapshotLeaseBindingV1,
        RepositorySnapshotLeaseId, RepositorySnapshotLeaseModeV1, RepositoryToolBoundsV1,
        RepositoryToolGrantId, RepositoryToolReceiptAuthorityV2, RepositoryUnixFileIdentityV1,
    };
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    const FILE_BYTES: &[u8] = b"BirdCode makes code fly.\n";
    const MODEL_NAME: &str = "scripted/repository-agent";
    const DEPLOYMENT: &str = "repository-agent-test-deployment";
    const ENDPOINT: &str = "http://127.0.0.1:19111";

    #[test]
    fn model_visible_file_projection_is_utf8_when_exact_and_base64_when_not() {
        let path = birdcode_protocol::RepositoryRelativePathV1::Unix {
            components: vec![b"facts.txt".to_vec()],
        };
        let utf8 = model_visible_result(RepositoryToolResultV2::RepositoryFileRead(
            RepositoryReadFileResultV2 {
                path: path.clone(),
                offset_bytes: 0,
                bytes: FILE_BYTES.to_vec(),
                file_byte_len: u64::try_from(FILE_BYTES.len()).expect("fixture length"),
                truncated: false,
            },
        ));
        let RepositoryAgentModelToolResultV1::RepositoryFileReadUtf8(utf8) = utf8 else {
            panic!("valid UTF-8 must use the direct text projection")
        };
        assert_eq!(utf8.content_utf8.as_bytes(), FILE_BYTES);
        assert_eq!(utf8.content_sha256, Sha256Digest::of_bytes(FILE_BYTES));
        assert_eq!(utf8.content_offset_bytes, 0);
        assert!(utf8.leading_boundary_bytes.is_empty());
        assert!(utf8.trailing_boundary_bytes.is_empty());
        let encoded = serde_json::to_string(&utf8).expect("UTF-8 projection encodes");
        assert!(encoded.contains("content_utf8"));
        assert!(!encoded.contains("bytes_base64"));

        let binary_bytes = vec![0xff, 0x00, 0xfe];
        let binary = model_visible_result(RepositoryToolResultV2::RepositoryFileRead(
            RepositoryReadFileResultV2 {
                path,
                offset_bytes: 0,
                bytes: binary_bytes.clone(),
                file_byte_len: u64::try_from(binary_bytes.len()).expect("fixture length"),
                truncated: false,
            },
        ));
        let RepositoryAgentModelToolResultV1::RepositoryFileReadBase64(binary) = binary else {
            panic!("arbitrary bytes must retain the canonical base64 result")
        };
        assert_eq!(binary.bytes, binary_bytes);
        assert!(
            serde_json::to_string(&binary)
                .expect("binary projection encodes")
                .contains("bytes_base64")
        );

        let split_scalar = b"let bird = \"f\xC3".to_vec();
        let split = model_visible_result(RepositoryToolResultV2::RepositoryFileRead(
            RepositoryReadFileResultV2 {
                path: birdcode_protocol::RepositoryRelativePathV1::Unix {
                    components: vec![b"unicode.rs".to_vec()],
                },
                offset_bytes: 0,
                bytes: split_scalar.clone(),
                file_byte_len: 32,
                truncated: true,
            },
        ));
        let RepositoryAgentModelToolResultV1::RepositoryFileReadUtf8(split) = split else {
            panic!("a split trailing scalar must not downgrade the complete code chunk")
        };
        assert_eq!(split.content_utf8, "let bird = \"f");
        assert_eq!(split.trailing_boundary_bytes, vec![0xc3]);
        assert_eq!(split.content_sha256, Sha256Digest::of_bytes(&split_scalar));

        let leading_continuation = vec![0xa5, b';', b'\n'];
        let continued = model_visible_result(RepositoryToolResultV2::RepositoryFileRead(
            RepositoryReadFileResultV2 {
                path: birdcode_protocol::RepositoryRelativePathV1::Unix {
                    components: vec![b"unicode.rs".to_vec()],
                },
                offset_bytes: 31,
                bytes: leading_continuation,
                file_byte_len: 34,
                truncated: false,
            },
        ));
        let RepositoryAgentModelToolResultV1::RepositoryFileReadUtf8(continued) = continued else {
            panic!("a leading continuation byte must preserve the readable code suffix")
        };
        assert_eq!(continued.leading_boundary_bytes, vec![0xa5]);
        assert_eq!(continued.content_utf8, ";\n");
        assert_eq!(continued.content_offset_bytes, 32);

        let escaped_controls = vec![0_u8; 4_096];
        let escaped = model_visible_result(RepositoryToolResultV2::RepositoryFileRead(
            RepositoryReadFileResultV2 {
                path: birdcode_protocol::RepositoryRelativePathV1::Unix {
                    components: vec![b"controls.bin".to_vec()],
                },
                offset_bytes: 0,
                bytes: escaped_controls,
                file_byte_len: 4_096,
                truncated: false,
            },
        ));
        assert!(matches!(
            escaped,
            RepositoryAgentModelToolResultV1::RepositoryFileReadBase64(_)
        ));

        let reservation = birdcode_protocol::ChildToolOperation::RepositoryFileRead {
            path: birdcode_protocol::RepositoryRelativePathV1::Unix {
                components: vec![b"facts.txt".to_vec()],
            },
            offset_bytes: 0,
            max_bytes: REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES,
        };
        assert_eq!(
            model_visible_read_reservation(0, &reservation),
            Some(REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES)
        );
        assert_eq!(model_visible_read_reservation(1, &reservation), None);
    }

    fn backend_id() -> BackendId {
        BackendId::new("scripted").expect("valid backend ID")
    }

    fn model_id() -> ModelId {
        ModelId::new(MODEL_NAME).expect("valid model ID")
    }

    fn backend_instance() -> BackendInstanceIdentity {
        BackendInstanceIdentity::new(
            backend_id(),
            BackendTransportIdentity::HttpOrigin {
                origin: BackendEndpointOrigin::parse(ENDPOINT).expect("canonical endpoint"),
            },
            BackendDeploymentId::new(DEPLOYMENT).expect("valid deployment ID"),
        )
        .expect("valid backend instance")
    }

    struct ScriptedRepositoryBackend {
        id: BackendId,
        instance: BackendInstanceIdentity,
        calls: AtomicUsize,
        requests: Mutex<Vec<StructuredInferenceRequest>>,
    }

    impl ScriptedRepositoryBackend {
        fn new() -> Self {
            Self {
                id: backend_id(),
                instance: backend_instance(),
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn requests(&self) -> Vec<StructuredInferenceRequest> {
            self.requests.lock().expect("request lock").clone()
        }
    }

    impl ModelBackend for ScriptedRepositoryBackend {
        fn backend_id(&self) -> &BackendId {
            &self.id
        }

        fn instance_identity(&self) -> &BackendInstanceIdentity {
            &self.instance
        }

        fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
            Box::pin(async { panic!("repository worker must not discover models") })
        }

        fn infer_structured(
            &self,
            request: StructuredInferenceRequest,
        ) -> BackendFuture<'_, StructuredInferenceResponse> {
            let ordinal = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let turn = serde_json::from_str::<RepositoryAgentTurnInputV1>(
                &request.messages().last().expect("user turn exists").content,
            )
            .expect("typed user turn decodes");
            let value = serde_json::to_value(scripted_response(ordinal, &turn))
                .expect("scripted response encodes");
            self.requests.lock().expect("request lock").push(request);
            let response = StructuredInferenceResponse {
                model_id: model_id(),
                raw_text: serde_json::to_string(&value).expect("raw response encodes"),
                value,
                finish_reason: Some("stop".to_owned()),
                usage: Some(TokenUsage {
                    input_tokens: Some(50),
                    output_tokens: Some(10),
                    total_tokens: Some(60),
                }),
                evidence: InferenceEvidence {
                    backend_id: backend_id(),
                    backend_instance: Some(backend_instance()),
                    endpoint: format!("{ENDPOINT}/v1/chat/completions"),
                    status: 200,
                    completion_id: Some(format!("scripted-completion-{ordinal}")),
                    response_body_sha256: Some(format!("{ordinal:064x}")),
                    raw_response: json!({"scripted_call": ordinal}),
                },
            };
            Box::pin(async move { Ok(response) })
        }
    }

    fn plan_for(
        turn: &RepositoryAgentTurnInputV1,
        status: ChildLocalPlanStepStatusV1,
    ) -> ChildLocalPlanSnapshotV1 {
        let step_id = ChildLocalPlanStepIdV1("inspect-facts".to_owned());
        ChildLocalPlanSnapshotV1 {
            contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            binding: turn.binding.clone(),
            plan_id: turn.required_plan_identity.plan_id,
            revision: turn.required_plan_identity.revision,
            previous_plan_digest: turn.required_plan_identity.previous_plan_digest.clone(),
            objective: turn.objective.clone(),
            steps: vec![ChildLocalPlanStepV1 {
                step_id: step_id.clone(),
                objective: "Read the repository fact file".to_owned(),
                status,
            }],
            active_step_id: (status == ChildLocalPlanStepStatusV1::InProgress).then_some(step_id),
            assumptions: Vec::new(),
            unknowns: Vec::new(),
        }
    }

    fn finish_response(
        turn: &RepositoryAgentTurnInputV1,
        evidence: ChildHandoffEvidenceBinding,
    ) -> ChildModelStructuredResponseV1 {
        ChildModelStructuredResponseV1 {
            contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            plan: plan_for(turn, ChildLocalPlanStepStatusV1::Completed),
            action: ChildActionV1::Finish {
                handoff: ChildHandoffContentV1 {
                    status: ChildHandoffStatus::Complete,
                    summary: "facts.txt was read through the real repository broker".to_owned(),
                    findings: vec![ChildHandoffFinding {
                        finding_id: "fact-file".to_owned(),
                        statement: "The repository fact file contains the expected bytes"
                            .to_owned(),
                        confidence: ChildFindingConfidence::High,
                        evidence: vec![evidence],
                    }],
                    unknowns: Vec::new(),
                    recommended_followups: Vec::new(),
                },
            },
        }
    }

    fn scripted_response(
        ordinal: usize,
        turn: &RepositoryAgentTurnInputV1,
    ) -> ChildModelStructuredResponseV1 {
        match ordinal {
            1 => {
                assert!(turn.prior_plan.is_none());
                assert!(turn.tool_observations.is_empty());
                let read_grant = turn
                    .available_tool_grants
                    .iter()
                    .find(|grant| matches!(grant, RepositoryToolGrantV1::RepositoryFileRead { .. }))
                    .expect("read grant supplied")
                    .tool_grant_id();
                ChildModelStructuredResponseV1 {
                    contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
                    plan: plan_for(turn, ChildLocalPlanStepStatusV1::InProgress),
                    action: ChildActionV1::RepositoryFileRead {
                        tool_grant_id: read_grant,
                        path: ModelRepositoryPathV1 {
                            components: vec![ModelRepositoryPathComponentV1::Utf8 {
                                value: "facts.txt".to_owned(),
                            }],
                        },
                        offset_bytes: 0,
                        max_bytes: 4_096,
                    },
                }
            }
            2 => {
                assert_eq!(turn.tool_observations.len(), 1);
                let RepositoryAgentModelToolResultV1::RepositoryFileReadUtf8(read) = turn
                    .tool_observations[0]
                    .result
                    .as_ref()
                    .expect("read result supplied")
                else {
                    panic!("expected a UTF-8 file-read observation")
                };
                assert_eq!(read.content_utf8.as_bytes(), FILE_BYTES);
                assert_eq!(read.content_sha256, Sha256Digest::of_bytes(FILE_BYTES));
                finish_response(
                    turn,
                    ChildHandoffEvidenceBinding {
                        tool_call_id: ChildToolCallId::new(),
                        observed_event_id: EventId::new(),
                        result_artifact: ArtifactRef {
                            sha256: "f".repeat(64),
                            size_bytes: 1,
                            media_type: REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE.to_owned(),
                        },
                    },
                )
            }
            3 => {
                assert_eq!(
                    turn.previous_rejection,
                    Some(RepositoryAgentRejectionV1::FinishEvidenceInvalid)
                );
                let observation = turn
                    .tool_observations
                    .last()
                    .expect("tool observation supplied");
                let RepositoryToolObservedTerminalV2::Succeeded { result_artifact } =
                    &observation.observed.terminal
                else {
                    panic!("expected successful repository observation")
                };
                finish_response(
                    turn,
                    ChildHandoffEvidenceBinding {
                        tool_call_id: observation.observed.tool_call_id,
                        observed_event_id: observation.observed_event_id,
                        result_artifact: result_artifact.clone(),
                    },
                )
            }
            _ => panic!("worker made an unexpected fourth model call"),
        }
    }

    fn artifact(bytes: &[u8], media_type: &str) -> ArtifactRef {
        ArtifactRef {
            sha256: Sha256Digest::of_bytes(bytes).as_str().to_owned(),
            size_bytes: u64::try_from(bytes.len()).expect("fixture length fits u64"),
            media_type: media_type.to_owned(),
        }
    }

    fn root_identity(root: &Path) -> RepositoryFileIdentityV1 {
        let metadata = fs::symlink_metadata(root).expect("root metadata");
        RepositoryFileIdentityV1::Unix(RepositoryUnixFileIdentityV1 {
            device: metadata.dev(),
            inode: metadata.ino(),
            byte_len: i64::try_from(metadata.size()).expect("root size fits i64"),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn broker_bounds() -> RepositoryToolBoundsV1 {
        RepositoryToolBoundsV1 {
            max_calls_per_broker: 32,
            max_request_bytes: 1024 * 1024,
            max_path_components: 32,
            max_path_bytes: 64 * 1024,
            max_component_bytes: 4 * 1024,
            max_read_bytes: 1024 * 1024,
            max_tree_depth: 8,
            max_tree_entries: 1_024,
            max_directory_entries_scanned: 4_096,
            max_directory_name_bytes_scanned: 4 * 1024 * 1024,
            max_search_pattern_bytes: 16 * 1024,
            max_search_depth: 8,
            max_search_files: 1_024,
            max_search_matches: 4_096,
            max_search_bytes_per_file: 1024 * 1024,
            max_search_total_bytes: 8 * 1024 * 1024,
            max_artifact_bytes: REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
        }
    }

    fn broker_authority(
        root: &Path,
        snapshot_digest: Sha256Digest,
        read_grant_id: RepositoryToolGrantId,
    ) -> RepositoryToolReceiptAuthorityV2 {
        let policy_bytes = b"repository-agent-test-policy";
        let lease_bytes = b"repository-agent-test-lease";
        RepositoryToolReceiptAuthorityV2 {
            policy_id: "repository-agent-test-policy".to_owned(),
            policy_artifact: artifact(policy_bytes, REPOSITORY_TOOL_POLICY_MEDIA_TYPE),
            policy_digest: Sha256Digest::of_bytes(policy_bytes),
            snapshot: RepositorySnapshotBindingV1 {
                snapshot_id: "repository-agent-test-snapshot".to_owned(),
                declared_snapshot_digest: snapshot_digest,
                immutability_lease: RepositorySnapshotLeaseBindingV1 {
                    lease_id: RepositorySnapshotLeaseId::new(),
                    mode: RepositorySnapshotLeaseModeV1::MacOsCooperativeQuiescedReadOnlyDiskImage,
                    lease_artifact: artifact(lease_bytes, REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE),
                    lease_digest: Sha256Digest::of_bytes(lease_bytes),
                },
            },
            root: RepositoryRootBindingV1 {
                repository_root_id: "repository-agent-test-root".to_owned(),
                descriptor_identity: root_identity(root),
            },
            broker_bounds: broker_bounds(),
            tool_grants: vec![RepositoryToolGrantV1::RepositoryFileRead {
                tool_grant_id: read_grant_id,
                max_path_components: 32,
                max_path_bytes: 64 * 1024,
                max_component_bytes: 4 * 1024,
                max_offset_bytes: 1024 * 1024,
                max_bytes: REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES,
            }],
        }
    }

    fn permission(value: &str) -> PermissionGrant {
        PermissionGrant {
            capabilities: BTreeSet::from([CapabilityId::new(value).expect("valid capability ID")]),
        }
    }

    fn validated_graph(snapshot_sha256: &str) -> birdcode_orchestrator::ValidatedActorGraph {
        validated_graph_for(
            snapshot_sha256,
            "Read facts.txt and return an evidence-bound finding",
            ModelLineage {
                backend_id: backend_id().as_str().to_owned(),
                model_id: MODEL_NAME.to_owned(),
                deployment_id: DEPLOYMENT.to_owned(),
                independence_domain_id: "repository-agent-test-domain".to_owned(),
            },
            AgentBudget {
                max_output_tokens: 200,
                max_tool_calls: 2,
                max_wall_time_ms: 5_000,
                max_cleanup_time_ms: 100,
                max_attempts: 1,
            },
        )
    }

    fn validated_graph_for(
        snapshot_sha256: &str,
        objective: &str,
        lineage: ModelLineage,
        budget: AgentBudget,
    ) -> birdcode_orchestrator::ValidatedActorGraph {
        let work_order_id = birdcode_orchestrator::WorkOrderId::new();
        let lease_id =
            WorkspaceLeaseId::new("repository-agent/test-lease").expect("valid workspace lease ID");
        let profile_id =
            ModelProfileId::new("repository-agent/test-model").expect("valid model profile ID");
        let work_order = birdcode_orchestrator::WorkOrder {
            id: work_order_id,
            objective: objective.to_owned(),
            acceptance_criteria: vec![
                "The handoff cites the exact successful repository observation".to_owned(),
            ],
            dependencies: BTreeSet::new(),
            candidate_group: None,
            priority: 0,
            context_manifest_sha256: "c".repeat(64),
            assignment: AgentAssignment {
                role_id: RoleId::new("repository_explorer").expect("valid role ID"),
                model_profile_id: profile_id.clone(),
                lineage: lineage.clone(),
            },
            permissions: permission("repository/read"),
            workspace: WorkspaceGrant {
                lease_id: lease_id.clone(),
                source: WorkspaceSourceBinding::BrokeredRepositorySnapshotV1 {
                    snapshot_sha256: snapshot_sha256.to_owned(),
                },
                access: WorkspaceAccess::ReadOnly,
            },
            budget,
            reviews: BTreeSet::new(),
        };
        let graph = ActorGraph {
            schema_version: 2,
            plan_input_snapshot_sha256: snapshot_sha256.to_owned(),
            work_orders: vec![work_order],
        };
        let policy = ActorGraphPolicy {
            policy_version: "repository-agent-test/1".to_owned(),
            plan_input_snapshot_sha256: snapshot_sha256.to_owned(),
            root_permissions: permission("repository/read"),
            limits: ActorGraphLimits {
                max_work_orders: 1,
                max_parallel: 1,
                max_total_attempts: u64::from(budget.max_attempts),
                max_total_output_tokens: budget.max_output_tokens,
                max_total_tool_calls: budget.max_tool_calls,
                max_total_wall_time_ms: budget
                    .max_wall_time_ms
                    .saturating_add(budget.max_cleanup_time_ms),
            },
            require_reported_token_usage: true,
            workspace_leases: BTreeMap::from([(
                lease_id,
                WorkspaceLeasePolicy {
                    source: WorkspaceSourceBinding::BrokeredRepositorySnapshotV1 {
                        snapshot_sha256: snapshot_sha256.to_owned(),
                    },
                    access: WorkspaceAccess::ReadOnly,
                },
            )]),
            model_profiles: BTreeMap::from([(profile_id, lineage)]),
        };
        graph.validate_against(&policy).expect("graph validates")
    }

    fn journal_record_name(record: &RepositoryAgentJournalRecord) -> &'static str {
        match record {
            RepositoryAgentJournalRecord::ExecutionStarted { .. } => "execution_started",
            RepositoryAgentJournalRecord::ModelPrepared { .. } => "model_prepared",
            RepositoryAgentJournalRecord::ModelObserved { .. } => "model_observed",
            RepositoryAgentJournalRecord::ModelFailed { .. } => "model_failed",
            RepositoryAgentJournalRecord::ModelContractRejected { .. } => "model_contract_rejected",
            RepositoryAgentJournalRecord::ActionRejected { .. } => "action_rejected",
            RepositoryAgentJournalRecord::ActionValidated { .. } => "action_validated",
            RepositoryAgentJournalRecord::ToolPrepared { .. } => "tool_prepared",
            RepositoryAgentJournalRecord::ToolObserved { .. } => "tool_observed",
            RepositoryAgentJournalRecord::ToolOutcomeUnknown { .. } => "tool_outcome_unknown",
            RepositoryAgentJournalRecord::FinishAccepted { .. } => "finish_accepted",
        }
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the acceptance test asserts the complete causal path and exact retained ordering"
    )]
    async fn repository_worker_repairs_finish_after_real_tool_observation() {
        let repository = TempDir::new().expect("temporary repository");
        fs::write(repository.path().join("facts.txt"), FILE_BYTES).expect("fixture file writes");
        let snapshot_digest = Sha256Digest::of_bytes(b"repository-agent-test-snapshot");
        let read_grant_id = RepositoryToolGrantId::new();
        let broker = RepositoryToolBroker::open(
            repository.path(),
            broker_authority(repository.path(), snapshot_digest.clone(), read_grant_id),
            RepositoryBrokerEpochStateV1 {
                active_broker_instance_id: RepositoryBrokerInstanceId::new(),
                closed_broker_instance_ids: Vec::new(),
            },
        )
        .expect("real repository broker opens");
        let backend = Arc::new(ScriptedRepositoryBackend::new());
        let model_backend: Arc<dyn ModelBackend> = backend.clone();
        let agent_journal = Arc::new(InMemoryRepositoryAgentJournal::default());
        let scheduler_journal = InMemorySchedulerJournal::default();
        let graph = validated_graph(snapshot_digest.as_str());
        let work_order = &graph.graph().work_orders[0];
        let broker_lane = Arc::new(RepositoryAgentBrokerLane::new(broker));
        let authority = RepositoryAgentDispatchAuthority::bind(
            graph.digest_sha256(),
            work_order.clone(),
            BTreeSet::from([read_grant_id]),
            broker_lane,
        )
        .expect("exact dispatch authority binds");
        let worker = RepositoryAgentWorker::new(
            model_backend,
            vec![authority],
            agent_journal.clone(),
            RepositoryAgentPolicy {
                max_model_calls: 4,
                max_action_rejections: 1,
                max_output_tokens_per_call: 64,
                min_plan_revisions_before_finish: 2,
                reasoning: None,
            },
        )
        .expect("worker constructs");

        let run = ActorGraphExecutor::new(&worker, &scheduler_journal)
            .execute(&graph)
            .await
            .expect("real worker completes through ActorGraphExecutor");

        assert_eq!(run.outcome, ActorGraphOutcome::Completed);
        assert_eq!(run.maximum_in_flight, 1);
        assert!(run.failures.is_empty());
        let handoff = run.handoffs.values().next().expect("one handoff retained");
        assert_eq!(handoff.outcome, HandoffOutcome::Completed);
        assert_eq!(
            handoff.summary,
            "facts.txt was read through the real repository broker"
        );
        assert_eq!(
            handoff.usage,
            Usage {
                output_tokens: Some(30),
                tool_calls: 1,
            }
        );
        assert_eq!(handoff.evidence_ids.len(), 1);
        assert_eq!(handoff.artifact_sha256.len(), 2);
        assert_eq!(backend.call_count(), 3);

        let requests = backend.requests();
        assert_eq!(requests.len(), 3);
        for request in &requests {
            assert_eq!(request.model_id().as_str(), MODEL_NAME);
            assert_eq!(request.messages().len(), 2);
            assert_eq!(
                request.messages()[0].content,
                repository_agent_prompt::REPOSITORY_AGENT_V1_SYSTEM_PROMPT
            );
            assert_eq!(request.output().name(), "repository_agent_v1");
        }
        let second_turn =
            serde_json::from_str::<RepositoryAgentTurnInputV1>(&requests[1].messages()[1].content)
                .expect("second turn decodes");
        assert!(
            requests[1].messages()[1]
                .content
                .contains("\"content_utf8\"")
        );
        assert!(
            !requests[1].messages()[1]
                .content
                .contains("\"bytes_base64\"")
        );
        let RepositoryAgentModelToolResultV1::RepositoryFileReadUtf8(read) = second_turn
            .tool_observations[0]
            .result
            .as_ref()
            .expect("real result supplied to next model turn")
        else {
            panic!("second model turn must receive a UTF-8 file result")
        };
        assert_eq!(read.content_utf8.as_bytes(), FILE_BYTES);
        assert_eq!(read.content_sha256, Sha256Digest::of_bytes(FILE_BYTES));
        let first_plan = second_turn
            .prior_plan
            .as_ref()
            .expect("first plan retained");
        assert_eq!(
            second_turn.required_plan_identity.plan_id,
            first_plan.plan_id
        );
        assert_eq!(
            second_turn.required_plan_identity.revision,
            first_plan.revision + 1
        );
        assert_eq!(
            second_turn.required_plan_identity.previous_plan_digest,
            Some(Sha256Digest::of_bytes(
                &serde_json::to_vec(first_plan).expect("first plan encodes")
            ))
        );
        let third_turn =
            serde_json::from_str::<RepositoryAgentTurnInputV1>(&requests[2].messages()[1].content)
                .expect("third turn decodes");
        assert_eq!(
            third_turn.previous_rejection,
            Some(RepositoryAgentRejectionV1::FinishEvidenceInvalid)
        );

        let retained = agent_journal.snapshot().expect("journal snapshot");
        let names = retained
            .iter()
            .map(|entry| journal_record_name(&entry.entry.record))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "execution_started",
                "model_prepared",
                "model_observed",
                "action_validated",
                "tool_prepared",
                "tool_observed",
                "model_prepared",
                "model_observed",
                "action_rejected",
                "model_prepared",
                "model_observed",
                "action_validated",
                "finish_accepted",
            ]
        );
        let prepared = retained
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    RepositoryAgentJournalRecord::ToolPrepared { .. }
                )
            })
            .expect("tool Prepared retained");
        assert_eq!(prepared.entry.artifacts.len(), 2);
        assert!(
            prepared
                .entry
                .artifacts
                .iter()
                .all(RepositoryAgentArtifact::is_exact)
        );
        let observed_index = names
            .iter()
            .position(|name| *name == "tool_observed")
            .expect("tool Observed retained");
        let prepared_index = names
            .iter()
            .position(|name| *name == "tool_prepared")
            .expect("tool Prepared retained");
        assert!(prepared_index < observed_index);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an explicitly running local LM Studio model"]
    async fn repository_worker_completes_with_live_lmstudio() {
        let endpoint = std::env::var("BIRDCODE_LMSTUDIO_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:1234/".to_owned());
        let model_name = std::env::var("BIRDCODE_LMSTUDIO_INFER_MODEL")
            .unwrap_or_else(|_| "google/gemma-4-26b-a4b".to_owned());
        let mut backend_config =
            LmStudioConfig::new(url::Url::parse(&endpoint).expect("live endpoint is a URL"));
        backend_config.limits.request_timeout = Duration::from_secs(120);
        let backend = Arc::new(
            LmStudioBackend::new(backend_config).expect("live LM Studio backend constructs"),
        );
        let backend_instance = backend.instance_identity();
        let lineage = ModelLineage {
            backend_id: backend.backend_id().as_str().to_owned(),
            model_id: model_name,
            deployment_id: backend_instance
                .configured_deployment_id()
                .as_str()
                .to_owned(),
            independence_domain_id: "live-lmstudio-repository-agent".to_owned(),
        };

        let repository = TempDir::new().expect("temporary repository");
        fs::write(
            repository.path().join("facts.txt"),
            b"BirdCode live verification code: SKY-2741.\n",
        )
        .expect("live fixture file writes");
        let snapshot_digest = Sha256Digest::of_bytes(b"live-lmstudio-repository-agent-snapshot");
        let read_grant_id = RepositoryToolGrantId::new();
        let broker = RepositoryToolBroker::open(
            repository.path(),
            broker_authority(repository.path(), snapshot_digest.clone(), read_grant_id),
            RepositoryBrokerEpochStateV1 {
                active_broker_instance_id: RepositoryBrokerInstanceId::new(),
                closed_broker_instance_ids: Vec::new(),
            },
        )
        .expect("live-smoke repository broker opens");
        let graph = validated_graph_for(
            snapshot_digest.as_str(),
            "Read facts.txt and report its exact verification code in an evidence-bound finding",
            lineage,
            AgentBudget {
                max_output_tokens: READ_ONLY_REPOSITORY_AGENT_V1_TOTAL_RESERVED_OUTPUT_TOKENS,
                max_tool_calls: u64::from(READ_ONLY_REPOSITORY_AGENT_V1_MAX_TOOL_CALLS),
                max_wall_time_ms: READ_ONLY_REPOSITORY_AGENT_V1_MAX_WALL_TIME_SECONDS * 1_000,
                max_cleanup_time_ms: 1_000,
                max_attempts: READ_ONLY_REPOSITORY_AGENT_V1_MAX_ATTEMPTS,
            },
        );
        let work_order = &graph.graph().work_orders[0];
        let broker_lane = Arc::new(RepositoryAgentBrokerLane::new(broker));
        let authority = RepositoryAgentDispatchAuthority::bind(
            graph.digest_sha256(),
            work_order.clone(),
            BTreeSet::from([read_grant_id]),
            broker_lane,
        )
        .expect("live exact dispatch authority binds");
        let model_backend: Arc<dyn ModelBackend> = backend;
        let agent_journal = Arc::new(InMemoryRepositoryAgentJournal::default());
        let worker = RepositoryAgentWorker::new(
            model_backend,
            vec![authority],
            agent_journal.clone(),
            RepositoryAgentPolicy {
                max_model_calls: READ_ONLY_REPOSITORY_AGENT_V1_MAX_MODEL_CALLS,
                max_action_rejections: 6,
                max_output_tokens_per_call: READ_ONLY_REPOSITORY_AGENT_V1_OUTPUT_TOKENS_PER_CALL,
                min_plan_revisions_before_finish: 2,
                reasoning: Some(ReasoningSetting::Off),
            },
        )
        .expect("live worker constructs");
        let scheduler_journal = InMemorySchedulerJournal::default();

        let run = ActorGraphExecutor::new(&worker, &scheduler_journal)
            .execute(&graph)
            .await
            .expect("live worker remains scheduler-total");

        let retained = agent_journal.snapshot().expect("live journal snapshot");
        if run.outcome != ActorGraphOutcome::Completed {
            for entry in &retained {
                if let RepositoryAgentJournalRecord::ModelObserved {
                    model_call_ordinal, ..
                } = entry.entry.record
                {
                    for artifact in &entry.entry.artifacts {
                        if let Ok(evidence) =
                            serde_json::from_slice::<serde_json::Value>(&artifact.bytes)
                        {
                            let value = evidence.pointer("/response/value");
                            eprintln!(
                                "live model response summary: {}",
                                serde_json::json!({
                                    "model_call_ordinal": model_call_ordinal,
                                    "revision": value.and_then(|value| value.pointer("/plan/revision")),
                                    "previous_plan_digest": value.and_then(|value| value.pointer("/plan/previous_plan_digest")),
                                    "steps": value.and_then(|value| value.pointer("/plan/steps")),
                                    "active_step_id": value.and_then(|value| value.pointer("/plan/active_step_id")),
                                    "action": value.and_then(|value| value.pointer("/action/action")),
                                })
                            );
                        }
                    }
                }
                if matches!(
                    entry.entry.record,
                    RepositoryAgentJournalRecord::ModelFailed { .. }
                        | RepositoryAgentJournalRecord::ModelContractRejected { .. }
                        | RepositoryAgentJournalRecord::ActionRejected { .. }
                ) {
                    eprintln!("live journal record: {:#?}", entry.entry.record);
                    for artifact in &entry.entry.artifacts {
                        eprintln!(
                            "live journal artifact {}: {}",
                            artifact.artifact.media_type,
                            String::from_utf8_lossy(&artifact.bytes)
                        );
                    }
                }
            }
        }
        assert_eq!(run.outcome, ActorGraphOutcome::Completed, "{run:#?}");
        let handoff = run.handoffs.values().next().expect("live handoff exists");
        assert_eq!(handoff.outcome, HandoffOutcome::Completed);
        let names = retained
            .iter()
            .map(|entry| journal_record_name(&entry.entry.record))
            .collect::<Vec<_>>();
        assert!(names.contains(&"tool_observed"));
        assert_eq!(names.last(), Some(&"finish_accepted"));
        let handoff_document = retained
            .iter()
            .flat_map(|entry| &entry.entry.artifacts)
            .find(|artifact| artifact.artifact.media_type == CHILD_HANDOFF_MEDIA_TYPE)
            .and_then(|artifact| {
                serde_json::from_slice::<ChildHandoffDocument>(&artifact.bytes).ok()
            })
            .expect("live finish retains its typed handoff document");
        assert!(
            handoff_document.content.summary.contains("SKY-2741")
                || handoff_document
                    .content
                    .findings
                    .iter()
                    .any(|finding| finding.statement.contains("SKY-2741")),
            "live model must report the exact nonce that existed only in the read fixture"
        );
        eprintln!("live LM Studio handoff: {}", handoff.summary);
    }

    #[test]
    fn dispatch_authority_rejects_read_grant_above_model_visible_budget() {
        let repository = TempDir::new().expect("temporary repository");
        fs::write(repository.path().join("facts.txt"), FILE_BYTES).expect("fixture file writes");
        let snapshot_digest = Sha256Digest::of_bytes(b"oversized-model-visible-read-snapshot");
        let read_grant_id = RepositoryToolGrantId::new();
        let mut authority =
            broker_authority(repository.path(), snapshot_digest.clone(), read_grant_id);
        let RepositoryToolGrantV1::RepositoryFileRead { max_bytes, .. } =
            &mut authority.tool_grants[0]
        else {
            panic!("fixture grant kind")
        };
        *max_bytes = REPOSITORY_AGENT_V1_MAX_MODEL_VISIBLE_READ_BYTES + 1;
        let broker = RepositoryToolBroker::open(
            repository.path(),
            authority,
            RepositoryBrokerEpochStateV1 {
                active_broker_instance_id: RepositoryBrokerInstanceId::new(),
                closed_broker_instance_ids: Vec::new(),
            },
        )
        .expect("broker accepts its wider mechanical read authority");
        let graph = validated_graph(snapshot_digest.as_str());
        let work_order = graph.graph().work_orders[0].clone();
        let error = match RepositoryAgentDispatchAuthority::bind(
            graph.digest_sha256(),
            work_order,
            BTreeSet::from([read_grant_id]),
            Arc::new(RepositoryAgentBrokerLane::new(broker)),
        ) {
            Ok(_) => panic!("model-visible profile must reject the wider read grant"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            RepositoryAgentConfigError::ModelVisibleReadGrantTooLarge
        );
    }

    #[test]
    fn dispatch_authority_rejects_git_baseline_workspace_source() {
        let repository = TempDir::new().expect("temporary repository");
        fs::write(repository.path().join("facts.txt"), FILE_BYTES).expect("fixture file writes");
        let snapshot_digest = Sha256Digest::of_bytes(b"repository-agent-typed-source-test");
        let read_grant_id = RepositoryToolGrantId::new();
        let broker = RepositoryToolBroker::open(
            repository.path(),
            broker_authority(repository.path(), snapshot_digest.clone(), read_grant_id),
            RepositoryBrokerEpochStateV1 {
                active_broker_instance_id: RepositoryBrokerInstanceId::new(),
                closed_broker_instance_ids: Vec::new(),
            },
        )
        .expect("real repository broker opens");
        let graph = validated_graph(snapshot_digest.as_str());
        let mut work_order = graph.graph().work_orders[0].clone();
        work_order.workspace.source = WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
            git_baseline_sha256: snapshot_digest.as_str().to_owned(),
        };

        let error = match RepositoryAgentDispatchAuthority::bind(
            graph.digest_sha256(),
            work_order,
            BTreeSet::from([read_grant_id]),
            Arc::new(RepositoryAgentBrokerLane::new(broker)),
        ) {
            Ok(_) => panic!("read-only repository agent must reject a Git baseline source"),
            Err(error) => error,
        };

        assert_eq!(error, RepositoryAgentConfigError::InvalidWorkspaceAuthority);
    }

    #[tokio::test]
    async fn repository_worker_denies_dispatch_outside_exact_permission_authority() {
        let repository = TempDir::new().expect("temporary repository");
        fs::write(repository.path().join("facts.txt"), FILE_BYTES).expect("fixture file writes");
        let snapshot_digest = Sha256Digest::of_bytes(b"repository-agent-authority-test-snapshot");
        let read_grant_id = RepositoryToolGrantId::new();
        let broker = RepositoryToolBroker::open(
            repository.path(),
            broker_authority(repository.path(), snapshot_digest.clone(), read_grant_id),
            RepositoryBrokerEpochStateV1 {
                active_broker_instance_id: RepositoryBrokerInstanceId::new(),
                closed_broker_instance_ids: Vec::new(),
            },
        )
        .expect("real repository broker opens");
        let backend = Arc::new(ScriptedRepositoryBackend::new());
        let model_backend: Arc<dyn ModelBackend> = backend.clone();
        let agent_journal = Arc::new(InMemoryRepositoryAgentJournal::default());
        let scheduler_journal = InMemorySchedulerJournal::default();
        let graph = validated_graph(snapshot_digest.as_str());
        let mut unauthorized_order = graph.graph().work_orders[0].clone();
        unauthorized_order.permissions = permission("repository/different-authority");
        let broker_lane = Arc::new(RepositoryAgentBrokerLane::new(broker));
        let authority = RepositoryAgentDispatchAuthority::bind(
            graph.digest_sha256(),
            unauthorized_order,
            BTreeSet::from([read_grant_id]),
            broker_lane.clone(),
        )
        .expect("distinct exact authority binds");
        let worker = RepositoryAgentWorker::new(
            model_backend,
            vec![authority],
            agent_journal.clone(),
            RepositoryAgentPolicy::default(),
        )
        .expect("worker constructs");

        let run = ActorGraphExecutor::new(&worker, &scheduler_journal)
            .execute(&graph)
            .await
            .expect("scheduler retains the denied worker result");

        assert_eq!(run.outcome, ActorGraphOutcome::Failed);
        assert!(run.handoffs.is_empty());
        assert_eq!(backend.call_count(), 0);
        assert!(
            agent_journal
                .snapshot()
                .expect("journal snapshot")
                .is_empty()
        );
        assert!(broker_lane.is_healthy());
        let failure = run.failures.values().next().expect("one denied work order");
        let birdcode_orchestrator::WorkOrderFailure::Worker { failure } = failure else {
            panic!("exact authority mismatch must remain a typed worker failure")
        };
        assert_eq!(failure.kind, AgentFailureKind::PermissionDenied);
        assert_eq!(failure.usage, Usage::default());
    }
}
