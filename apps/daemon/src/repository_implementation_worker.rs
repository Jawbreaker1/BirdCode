//! First executable repository implementation loop.
//!
//! This profile is deliberately narrow: an exact clean committed-HEAD
//! worktree, one descriptor-confined full UTF-8 read of one granted file, one
//! exact replacement, one retained Git diff, and a final model-authored
//! handoff.  Semantic planning and action selection belong to the model;
//! authority, budgets, phase transitions, effects, and evidence are mechanical.

use crate::repository_candidate::{
    ExactUtf8ReplaceCandidateV1, REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
    RepositoryCandidateBaselineV1, RepositoryCandidateBodyV1, RepositoryCandidateBundleV1,
    RepositoryCandidateProducerLocatorV1, RepositoryCandidateProducerV1, RepositoryCandidateStore,
    dispatch_attestation_digest,
};
use crate::repository_implementation_prompt::{
    self, REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION, RepositoryImplementationActionV1,
    RepositoryImplementationModelResponseV1,
};
use crate::worktree_write_lane::{
    ExactReplaceUtf8FileGrantV1, ExactReplaceUtf8FileRequestV1, GitBaselineMaterializationV1,
    ObservedSingleWriteV1, WorktreeWriteLane, WorktreeWriteLaneJournal, WorktreeWriteOriginV1,
};
use birdcode_backends::{
    BackendError, ModelBackend, ModelId, ReasoningSetting, StructuredInferenceRequest,
    StructuredInferenceResponse,
};
use birdcode_orchestrator::{
    AgentCompletion, AgentDispatch, AgentFailure, AgentFailureKind, AgentFuture, AgentWorker,
    CapabilityId, DispatchAttestation, HandoffOutcome, Usage, ValidatedActorGraph, WorkOrder,
    WorkOrderId, WorkspaceAccess, WorkspaceSourceBinding,
};
use birdcode_protocol::{
    ArtifactRef, CHILD_HANDOFF_MEDIA_TYPE, CHILD_RECONNAISSANCE_MAX_EVIDENCE_BINDINGS,
    CHILD_RECONNAISSANCE_MAX_FINDINGS, CHILD_RECONNAISSANCE_MAX_IDENTIFIER_BYTES,
    CHILD_RECONNAISSANCE_MAX_IDENTIFIER_UNICODE_SCALARS,
    CHILD_RECONNAISSANCE_MAX_MODEL_ARTIFACT_BYTES,
    CHILD_RECONNAISSANCE_MAX_OUTPUT_TOKENS_PER_MODEL_CALL,
    CHILD_RECONNAISSANCE_MAX_PLAN_ASSUMPTIONS, CHILD_RECONNAISSANCE_MAX_PLAN_STEPS,
    CHILD_RECONNAISSANCE_MAX_PLAN_UNKNOWNS, CHILD_RECONNAISSANCE_MAX_RECOMMENDED_FOLLOWUPS,
    CHILD_RECONNAISSANCE_MAX_TEXT_BYTES, CHILD_RECONNAISSANCE_MAX_TEXT_UNICODE_SCALARS,
    CHILD_RECONNAISSANCE_MAX_UNRESOLVED_QUESTIONS, ChildActorId, ChildAttemptId,
    ChildExecutionBinding, ChildExecutionId, ChildHandoffContentV1, ChildHandoffDocument,
    ChildHandoffEvidenceBinding, ChildHandoffId, ChildHandoffStatus, ChildLocalPlanBindingV1,
    ChildLocalPlanId, ChildLocalPlanSnapshotV1, ChildLocalPlanStepIdV1, ChildLocalPlanStepStatusV1,
    ChildModelCallId, ChildToolCallId, ChildValidatedActionBindingV1, ChildValidatedActionId,
    ChildWorkOrderId, EventId, ModelLineage, ModelRepositoryPathComponentV1, ModelRepositoryPathV1,
    REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES, REPOSITORY_TOOL_HARD_MAX_PATH_BYTES,
    REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS, RepositoryFileIdentityV1, RepositoryRelativePathV1,
    RepositoryToolGrantId, RepositoryToolGrantV1, RuntimeInstanceId, Sha256Digest, WorkspacePath,
};
use birdcode_workspace::{
    ArtifactBoundary, CanonicalArtifactBoundary, GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES,
    GitWorktreeUtf8FileReadV1, TemporaryGitWorktree,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const PROFILE_ID: &str = "git_clean_committed_head_v1";
const IMPLEMENTATION_CAPABILITY_ID: &str = "repository-implementation-v1";
const MAX_MODEL_VISIBLE_FILE_BYTES: u64 = 256 * 1024;
const HARD_MAX_MODEL_CALLS: u32 = 16;
const HARD_MAX_REJECTIONS: u32 = 8;
const MODEL_REQUEST_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-implementation-request.v1+json";
const MODEL_RESPONSE_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-implementation-response.v1+json";
const MODEL_ERROR_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-implementation-error.v1+json";
const ACTION_MEDIA_TYPE: &str = "application/vnd.birdcode.repository-implementation-action.v1+json";
const READ_RESULT_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-implementation-read-result.v1+json";
const MATERIALIZATION_MEDIA_TYPE: &str =
    "application/vnd.birdcode.git-clean-head-materialization.v1+json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryImplementationPolicy {
    pub max_model_calls: u32,
    pub max_action_rejections: u32,
    pub max_output_tokens_per_call: u32,
    pub minimum_plan_revisions_before_finish: u32,
    /// Includes the successful Finish call and leaves repair room when > 1.
    pub finish_call_reserve: u32,
    pub reasoning: Option<ReasoningSetting>,
}

impl Default for RepositoryImplementationPolicy {
    fn default() -> Self {
        Self {
            max_model_calls: 6,
            max_action_rejections: 2,
            max_output_tokens_per_call: 4_096,
            minimum_plan_revisions_before_finish: 3,
            finish_call_reserve: 2,
            reasoning: None,
        }
    }
}

impl RepositoryImplementationPolicy {
    fn validate(self) -> Result<Self, RepositoryImplementationConfigError> {
        if self.max_model_calls < 3 || self.max_model_calls > HARD_MAX_MODEL_CALLS {
            return Err(RepositoryImplementationConfigError::InvalidModelCallLimit);
        }
        if self.max_action_rejections > HARD_MAX_REJECTIONS
            || self.max_action_rejections >= self.max_model_calls
        {
            return Err(RepositoryImplementationConfigError::InvalidRejectionLimit);
        }
        if self.max_output_tokens_per_call == 0
            || u64::from(self.max_output_tokens_per_call)
                > CHILD_RECONNAISSANCE_MAX_OUTPUT_TOKENS_PER_MODEL_CALL
            || self.minimum_plan_revisions_before_finish != 3
            || self.finish_call_reserve == 0
            || self.finish_call_reserve > self.max_model_calls.saturating_sub(2)
        {
            return Err(RepositoryImplementationConfigError::InvalidPositiveLimit);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryImplementationConfigError {
    InvalidModelCallLimit,
    InvalidRejectionLimit,
    InvalidPositiveLimit,
    InvalidBackendIdentity,
    EmptyAuthority,
    DuplicateWorkOrderAuthority,
    InvalidWorkspaceAuthority,
    EmptyPermissionAuthority,
    InvalidReadGrant,
    InvalidWriteGrant,
    InvalidAuthorityEncoding,
    InvalidGraphDigest,
    UnsupportedRetryProfile,
    UnknownWorkOrderAuthority,
}

impl fmt::Display for RepositoryImplementationConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidModelCallLimit => "invalid implementation model-call limit",
            Self::InvalidRejectionLimit => "invalid implementation rejection limit",
            Self::InvalidPositiveLimit => "invalid positive implementation limit",
            Self::InvalidBackendIdentity => "backend identity failed exact validation",
            Self::EmptyAuthority => "implementation worker requires authority",
            Self::DuplicateWorkOrderAuthority => "implementation authority repeats a work order",
            Self::InvalidWorkspaceAuthority => "implementation authority requires write workspace",
            Self::EmptyPermissionAuthority => "implementation authority requires permission",
            Self::InvalidReadGrant => "implementation read grant is outside the narrow profile",
            Self::InvalidWriteGrant => "implementation write grant is outside the narrow profile",
            Self::InvalidAuthorityEncoding => "implementation authority could not be encoded",
            Self::InvalidGraphDigest => "implementation graph digest is invalid",
            Self::UnsupportedRetryProfile => "implementation v1 permits exactly one attempt",
            Self::UnknownWorkOrderAuthority => {
                "validated graph does not contain the requested implementation work order"
            }
        })
    }
}

impl std::error::Error for RepositoryImplementationConfigError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedExactReplaceUtf8FileGrantV1 {
    pub grant_id: RepositoryToolGrantId,
    pub path: RepositoryRelativePathV1,
    pub expected_preimage_sha256: Sha256Digest,
    pub max_content_bytes: u64,
}

#[derive(Clone)]
pub struct RepositoryImplementationDispatchAuthority {
    work_order: WorkOrder,
    attestation: DispatchAttestation,
    source_repository: PathBuf,
    scratch_root: PathBuf,
    read_grant: RepositoryToolGrantV1,
    write_grant: StagedExactReplaceUtf8FileGrantV1,
}

impl RepositoryImplementationDispatchAuthority {
    /// Binds one exact validated work order to the clean-HEAD implementation profile.
    ///
    /// # Errors
    ///
    /// Returns an error unless the work order exists in the validated graph and
    /// every model, permission, workspace, retry, read, and write bound fits the
    /// closed implementation profile.
    pub fn bind(
        graph: &ValidatedActorGraph,
        work_order_id: WorkOrderId,
        source_repository: PathBuf,
        scratch_root: PathBuf,
        read_grant: RepositoryToolGrantV1,
        write_grant: StagedExactReplaceUtf8FileGrantV1,
    ) -> Result<Self, RepositoryImplementationConfigError> {
        let work_order = graph
            .graph()
            .work_orders
            .iter()
            .find(|order| order.id == work_order_id)
            .cloned()
            .ok_or(RepositoryImplementationConfigError::UnknownWorkOrderAuthority)?;
        Self::bind_parts(
            graph.digest_sha256(),
            work_order,
            source_repository,
            scratch_root,
            read_grant,
            write_grant,
        )
    }

    fn bind_parts(
        graph_sha256: impl Into<String>,
        work_order: WorkOrder,
        source_repository: PathBuf,
        scratch_root: PathBuf,
        read_grant: RepositoryToolGrantV1,
        write_grant: StagedExactReplaceUtf8FileGrantV1,
    ) -> Result<Self, RepositoryImplementationConfigError> {
        let graph_sha256 = Sha256Digest::parse(graph_sha256.into())
            .map_err(|_| RepositoryImplementationConfigError::InvalidGraphDigest)?
            .as_str()
            .to_owned();
        let WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
            git_baseline_sha256,
        } = &work_order.workspace.source
        else {
            return Err(RepositoryImplementationConfigError::InvalidWorkspaceAuthority);
        };
        if work_order.workspace.access != WorkspaceAccess::Write
            || Sha256Digest::parse(git_baseline_sha256.clone()).is_err()
        {
            return Err(RepositoryImplementationConfigError::InvalidWorkspaceAuthority);
        }
        let implementation_capability = CapabilityId::new(IMPLEMENTATION_CAPABILITY_ID)
            .map_err(|_| RepositoryImplementationConfigError::EmptyPermissionAuthority)?;
        if !work_order
            .permissions
            .capabilities
            .contains(&implementation_capability)
        {
            return Err(RepositoryImplementationConfigError::EmptyPermissionAuthority);
        }
        if work_order.budget.max_attempts != 1 {
            return Err(RepositoryImplementationConfigError::UnsupportedRetryProfile);
        }
        let RepositoryToolGrantV1::RepositoryFileRead {
            max_path_components,
            max_path_bytes,
            max_component_bytes,
            max_offset_bytes,
            max_bytes,
            ..
        } = &read_grant
        else {
            return Err(RepositoryImplementationConfigError::InvalidReadGrant);
        };
        if *max_offset_bytes != 0
            || *max_bytes == 0
            || *max_bytes > MAX_MODEL_VISIBLE_FILE_BYTES
            || *max_path_components == 0
            || *max_path_components > REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS
            || *max_path_bytes == 0
            || *max_path_bytes > REPOSITORY_TOOL_HARD_MAX_PATH_BYTES
            || *max_component_bytes == 0
            || *max_component_bytes > REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES
            || !path_fits_read_grant(
                &write_grant.path,
                *max_path_components,
                *max_path_bytes,
                *max_component_bytes,
            )
        {
            return Err(RepositoryImplementationConfigError::InvalidReadGrant);
        }
        if write_grant.max_content_bytes == 0
            || write_grant.max_content_bytes > GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES
        {
            return Err(RepositoryImplementationConfigError::InvalidWriteGrant);
        }
        let work_order_bytes = serde_json::to_vec(&work_order)
            .map_err(|_| RepositoryImplementationConfigError::InvalidAuthorityEncoding)?;
        let permission_bytes = serde_json::to_vec(&work_order.permissions)
            .map_err(|_| RepositoryImplementationConfigError::InvalidAuthorityEncoding)?;
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
            source_repository,
            scratch_root,
            read_grant,
            write_grant,
        })
    }

    #[must_use]
    pub fn attestation(&self) -> &DispatchAttestation {
        &self.attestation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryImplementationArtifact {
    pub artifact: ArtifactRef,
    pub bytes: Vec<u8>,
}

impl RepositoryImplementationArtifact {
    fn from_bytes(media_type: &str, bytes: Vec<u8>) -> Self {
        Self {
            artifact: ArtifactRef {
                sha256: Sha256Digest::of_bytes(&bytes).as_str().to_owned(),
                size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                media_type: media_type.to_owned(),
            },
            bytes,
        }
    }

    fn is_exact(&self) -> bool {
        self.artifact.size_bytes == u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
            && self.artifact.sha256 == Sha256Digest::of_bytes(&self.bytes).as_str()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryImplementationRejectionV1 {
    ContractMismatch,
    ExecutionBindingMismatch,
    PlanIdentityMismatch,
    ObjectiveMismatch,
    PlanRevisionMismatch,
    PlanStructureInvalid,
    PlanTransitionInvalid,
    ActionPlanStateInvalid,
    ReadGrantMismatch,
    ReadAlreadyObserved,
    ReadRequiredBeforeWrite,
    WriteGrantMismatch,
    WriteWouldBeNoOp,
    PostWriteActionMustFinish,
    ToolBudgetExhausted,
    FinishBudgetNotReserved,
    FinishBeforeMinimumRevision,
    FinishEvidenceInvalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryImplementationModelViolationV1 {
    OutputTokenCeilingExceeded,
    ResponseBindingMismatch,
    StructuredResponseInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryImplementationJournalRecordV1 {
    ExecutionStarted {
        binding: ChildExecutionBinding,
        local_plan_id: ChildLocalPlanId,
        model_lineage: ModelLineage,
    },
    GitBaselineMaterialized {
        binding: ChildExecutionBinding,
        worktree_id: uuid::Uuid,
        base_commit: String,
        receipt_artifact: ArtifactRef,
    },
    ModelPrepared {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        ordinal: u32,
        request_artifact: ArtifactRef,
    },
    ModelObserved {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        ordinal: u32,
        prepared_event_id: EventId,
        response_artifact: ArtifactRef,
        output_tokens: Option<u64>,
    },
    ModelFailed {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        ordinal: u32,
        prepared_event_id: EventId,
        error_artifact: ArtifactRef,
    },
    ModelContractRejected {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        observed_event_id: EventId,
        violation: RepositoryImplementationModelViolationV1,
    },
    ActionRejected {
        binding: ChildExecutionBinding,
        model_call_id: ChildModelCallId,
        observed_event_id: EventId,
        rejection: RepositoryImplementationRejectionV1,
    },
    ActionValidated {
        binding: ChildExecutionBinding,
        action_binding: ChildValidatedActionBindingV1,
    },
    ReadPrepared {
        binding: ChildExecutionBinding,
        tool_call_id: ChildToolCallId,
        action_binding: ChildValidatedActionBindingV1,
    },
    ReadObserved {
        binding: ChildExecutionBinding,
        tool_call_id: ChildToolCallId,
        prepared_event_id: EventId,
        result_artifact: ArtifactRef,
    },
    FinishAccepted {
        binding: ChildExecutionBinding,
        handoff_id: ChildHandoffId,
        action_binding: ChildValidatedActionBindingV1,
        handoff_artifact: ArtifactRef,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryImplementationJournalEntryV1 {
    pub record: RepositoryImplementationJournalRecordV1,
    pub artifacts: Vec<RepositoryImplementationArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryImplementationJournalError(String);

impl fmt::Display for RepositoryImplementationJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RepositoryImplementationJournalError {}

pub trait RepositoryImplementationJournal: Send + Sync {
    /// Retains one exact causal boundary and all referenced artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error unless the journal durably accepts the complete entry.
    fn retain(
        &self,
        entry: RepositoryImplementationJournalEntryV1,
    ) -> Result<EventId, RepositoryImplementationJournalError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRepositoryImplementationJournalEntryV1 {
    pub event_id: EventId,
    pub entry: RepositoryImplementationJournalEntryV1,
}

#[derive(Debug, Default)]
pub struct InMemoryRepositoryImplementationJournal {
    entries: Mutex<Vec<RetainedRepositoryImplementationJournalEntryV1>>,
}

impl InMemoryRepositoryImplementationJournal {
    /// Returns a stable snapshot in retention order.
    ///
    /// # Errors
    ///
    /// Returns an error if the journal lock is poisoned.
    pub fn snapshot(
        &self,
    ) -> Result<
        Vec<RetainedRepositoryImplementationJournalEntryV1>,
        RepositoryImplementationJournalError,
    > {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .map_err(|_| RepositoryImplementationJournalError("journal lock poisoned".to_owned()))
    }
}

impl RepositoryImplementationJournal for InMemoryRepositoryImplementationJournal {
    fn retain(
        &self,
        entry: RepositoryImplementationJournalEntryV1,
    ) -> Result<EventId, RepositoryImplementationJournalError> {
        if entry.artifacts.iter().any(|artifact| !artifact.is_exact()) {
            return Err(RepositoryImplementationJournalError(
                "journal rejected inexact artifact".to_owned(),
            ));
        }
        let event_id = EventId::new();
        self.entries
            .lock()
            .map_err(|_| RepositoryImplementationJournalError("journal lock poisoned".to_owned()))?
            .push(RetainedRepositoryImplementationJournalEntryV1 { event_id, entry });
        Ok(event_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelWriteGrantV1 {
    grant_id: RepositoryToolGrantId,
    path: ModelRepositoryPathV1,
    expected_preimage_sha256: Sha256Digest,
    max_content_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryImplementationDependencyHandoffV1 {
    work_order_id: WorkOrderId,
    outcome: HandoffOutcome,
    summary: String,
    artifact_sha256: Vec<String>,
    evidence_ids: Vec<String>,
    scheduler_event_id: birdcode_orchestrator::SchedulerEventId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RequiredPlanIdentityV1 {
    plan_id: ChildLocalPlanId,
    revision: u64,
    previous_plan_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelReadObservationV1 {
    tool_call_id: ChildToolCallId,
    observed_event_id: EventId,
    path: RepositoryRelativePathV1,
    content_utf8: String,
    byte_len: u64,
    content_sha256: Sha256Digest,
    result_artifact: ArtifactRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelWriteObservationV1 {
    tool_call_id: ChildToolCallId,
    replace_event_id: EventId,
    diff_event_id: EventId,
    path: RepositoryRelativePathV1,
    preimage_sha256: Sha256Digest,
    postimage_sha256: Sha256Digest,
    diff_artifact: ArtifactRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryImplementationTurnInputV1 {
    contract_version: u32,
    profile_id: String,
    binding: ChildExecutionBinding,
    model_call_ordinal: u32,
    objective: String,
    acceptance_criteria: Vec<String>,
    dependency_handoffs: Vec<RepositoryImplementationDependencyHandoffV1>,
    required_read_target: Option<ModelRepositoryPathV1>,
    available_tool_grants: Vec<RepositoryToolGrantV1>,
    available_write_grants: Vec<ModelWriteGrantV1>,
    remaining_model_calls: u32,
    remaining_tool_calls: u64,
    remaining_output_tokens: u64,
    minimum_plan_revisions_before_finish: u32,
    required_plan_identity: RequiredPlanIdentityV1,
    prior_plan: Option<ChildLocalPlanSnapshotV1>,
    read_observation: Option<ModelReadObservationV1>,
    write_observation: Option<ModelWriteObservationV1>,
    required_finish_evidence: Option<ChildHandoffEvidenceBinding>,
    previous_rejection: Option<RepositoryImplementationRejectionV1>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ModelEvidenceV1<'a> {
    contract_version: u32,
    binding: &'a ChildExecutionBinding,
    model_call_id: ChildModelCallId,
    model_call_ordinal: u32,
    prepared_event_id: EventId,
    response: &'a StructuredInferenceResponse,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ModelErrorEvidenceV1<'a> {
    contract_version: u32,
    binding: &'a ChildExecutionBinding,
    model_call_id: ChildModelCallId,
    model_call_ordinal: u32,
    prepared_event_id: EventId,
    error: &'a BackendError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GitCleanHeadMaterializationReceiptV1 {
    contract_version: u32,
    profile_id: String,
    binding: ChildExecutionBinding,
    workspace_lease_id: birdcode_orchestrator::WorkspaceLeaseId,
    source_repository: WorkspacePath,
    worktree_path: WorkspacePath,
    worktree_root_identity: RepositoryFileIdentityV1,
    worktree_id: uuid::Uuid,
    base_commit: String,
    git_baseline_sha256: Sha256Digest,
    target_path: RepositoryRelativePathV1,
    target_preimage_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryImplementationValidatedActionDocumentV1 {
    contract_version: u32,
    binding: ChildExecutionBinding,
    action_id: ChildValidatedActionId,
    source_model_call_id: ChildModelCallId,
    source_model_call_ordinal: u32,
    source_model_observed_event_id: EventId,
    source_model_evidence_digest: Sha256Digest,
    source_plan: ChildLocalPlanBindingV1,
    active_plan_step_id: Option<ChildLocalPlanStepIdV1>,
    completion_handoff_id: Option<ChildHandoffId>,
    action: RepositoryImplementationActionV1,
}

struct AttemptState<W: WorktreeWriteLaneJournal + ?Sized> {
    binding: ChildExecutionBinding,
    local_plan_id: ChildLocalPlanId,
    prior_plan: Option<ChildLocalPlanSnapshotV1>,
    previous_rejection: Option<RepositoryImplementationRejectionV1>,
    model_calls: u32,
    action_rejections: u32,
    tool_calls: u64,
    remaining_output_tokens: u64,
    reported_output_tokens: Option<u64>,
    worktree: Option<TemporaryGitWorktree>,
    materialization: GitBaselineMaterializationV1,
    exact_write_grant: ExactReplaceUtf8FileGrantV1,
    read_observation: Option<ModelReadObservationV1>,
    write_observation: Option<ModelWriteObservationV1>,
    observed_write: Option<ObservedSingleWriteV1>,
    write_lane: Option<WorktreeWriteLane<W>>,
}

/// Executable implementation worker for one exact file in a clean Git HEAD.
pub struct RepositoryImplementationAgentWorker<
    J: RepositoryImplementationJournal + ?Sized,
    W: WorktreeWriteLaneJournal + ?Sized,
> {
    backend: Arc<dyn ModelBackend>,
    authorities: BTreeMap<WorkOrderId, RepositoryImplementationDispatchAuthority>,
    journal: Arc<J>,
    write_journal: Arc<W>,
    candidate_store: Arc<dyn RepositoryCandidateStore>,
    policy: RepositoryImplementationPolicy,
    runtime_instance_id: RuntimeInstanceId,
}

impl<J, W> RepositoryImplementationAgentWorker<J, W>
where
    J: RepositoryImplementationJournal + ?Sized,
    W: WorktreeWriteLaneJournal + ?Sized,
{
    /// Constructs a worker from exact validated dispatch authorities.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend identity, worker policy, authority set,
    /// or reserved work-order budgets violate the closed profile.
    pub fn new(
        backend: Arc<dyn ModelBackend>,
        authorities: Vec<RepositoryImplementationDispatchAuthority>,
        journal: Arc<J>,
        write_journal: Arc<W>,
        candidate_store: Arc<dyn RepositoryCandidateStore>,
        policy: RepositoryImplementationPolicy,
    ) -> Result<Self, RepositoryImplementationConfigError> {
        let policy = policy.validate()?;
        let instance = backend.instance_identity();
        instance
            .validate_integrity()
            .map_err(|_| RepositoryImplementationConfigError::InvalidBackendIdentity)?;
        if instance.backend_id() != backend.backend_id() {
            return Err(RepositoryImplementationConfigError::InvalidBackendIdentity);
        }
        if authorities.is_empty() {
            return Err(RepositoryImplementationConfigError::EmptyAuthority);
        }
        let mut authority_map = BTreeMap::new();
        for authority in authorities {
            let required_tokens = u64::from(policy.max_model_calls)
                .checked_mul(u64::from(policy.max_output_tokens_per_call))
                .ok_or(RepositoryImplementationConfigError::InvalidPositiveLimit)?;
            if authority.work_order.budget.max_tool_calls < 2
                || authority.work_order.budget.max_output_tokens < required_tokens
            {
                return Err(RepositoryImplementationConfigError::InvalidPositiveLimit);
            }
            if authority_map
                .insert(authority.work_order.id, authority)
                .is_some()
            {
                return Err(RepositoryImplementationConfigError::DuplicateWorkOrderAuthority);
            }
        }
        Ok(Self {
            backend,
            authorities: authority_map,
            journal,
            write_journal,
            candidate_store,
            policy,
            runtime_instance_id: RuntimeInstanceId::new(),
        })
    }

    fn retain(
        &self,
        record: RepositoryImplementationJournalRecordV1,
        artifacts: Vec<RepositoryImplementationArtifact>,
    ) -> Result<EventId, AgentFailure> {
        if artifacts.iter().any(|artifact| !artifact.is_exact()) {
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "implementation worker attempted to retain an inexact artifact",
                Usage::default(),
                None,
            ));
        }
        self.journal
            .retain(RepositoryImplementationJournalEntryV1 { record, artifacts })
            .map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("implementation journal rejected a boundary: {error}"),
                    Usage::default(),
                    None,
                )
            })
    }

    fn failure(
        &self,
        kind: AgentFailureKind,
        message: impl Into<String>,
        usage: Usage,
        effect_receipt_id: Option<String>,
    ) -> AgentFailure {
        AgentFailure {
            kind,
            message: message.into(),
            usage,
            execution_receipt_id: format!(
                "repository-implementation-runtime:{}",
                self.runtime_instance_id
            ),
            effect_receipt_id,
        }
    }

    fn usage(state: &AttemptState<W>) -> Usage {
        Usage {
            output_tokens: state.reported_output_tokens,
            tool_calls: state.tool_calls,
        }
    }

    fn effect_receipt(state: &AttemptState<W>) -> Option<String> {
        state
            .observed_write
            .as_ref()
            .map(|write| format!("repository-write-diff:{}", write.diff_event_id))
    }

    fn bind_failure_to_state(
        &self,
        state: &AttemptState<W>,
        mut failure: AgentFailure,
    ) -> AgentFailure {
        failure.usage = Self::usage(state);
        failure.execution_receipt_id = format!(
            "repository-implementation-runtime:{}",
            self.runtime_instance_id
        );
        failure.effect_receipt_id = Self::effect_receipt(state);
        failure
    }

    fn retain_for_state(
        &self,
        state: &AttemptState<W>,
        record: RepositoryImplementationJournalRecordV1,
        artifacts: Vec<RepositoryImplementationArtifact>,
    ) -> Result<EventId, AgentFailure> {
        self.retain(record, artifacts)
            .map_err(|failure| self.bind_failure_to_state(state, failure))
    }

    fn reject(
        &self,
        state: &mut AttemptState<W>,
        model_call_id: ChildModelCallId,
        observed_event_id: EventId,
        rejection: RepositoryImplementationRejectionV1,
    ) -> Result<(), AgentFailure> {
        self.retain_for_state(
            state,
            RepositoryImplementationJournalRecordV1::ActionRejected {
                binding: state.binding.clone(),
                model_call_id,
                observed_event_id,
                rejection,
            },
            Vec::new(),
        )?;
        state.action_rejections = state.action_rejections.saturating_add(1);
        state.previous_rejection = Some(rejection);
        if state.action_rejections > self.policy.max_action_rejections {
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "implementation model exhausted its typed action-repair budget",
                Self::usage(state),
                Self::effect_receipt(state),
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the first bounded implementation vertical keeps its causal model/read/write/finish order auditable in one function"
    )]
    async fn run_attempt(&self, dispatch: AgentDispatch) -> Result<AgentCompletion, AgentFailure> {
        let Some(authority) = self.authorities.get(&dispatch.work_order.id).cloned() else {
            return Err(self.failure(
                AgentFailureKind::PermissionDenied,
                "dispatch has no exact implementation authority",
                Usage::default(),
                None,
            ));
        };
        let lineage = &dispatch.work_order.assignment.lineage;
        let instance = self.backend.instance_identity();
        if dispatch.graph_sha256 != authority.attestation.graph_sha256
            || dispatch.attestation != authority.attestation
            || dispatch.work_order.as_ref() != &authority.work_order
            || lineage.backend_id != self.backend.backend_id().as_str()
            || lineage.model_id.is_empty()
            || lineage.deployment_id != instance.configured_deployment_id().as_str()
            || dispatch.work_order.workspace.access != WorkspaceAccess::Write
            || dispatch.work_order.budget.max_attempts != 1
            || !dependency_maps_match(&dispatch)
        {
            return Err(self.failure(
                AgentFailureKind::PermissionDenied,
                "dispatch identity, model, workspace, or retry authority differs",
                Usage::default(),
                None,
            ));
        }
        let model_id = ModelId::new(lineage.model_id.clone()).map_err(|error| {
            self.failure(
                AgentFailureKind::PermissionDenied,
                format!("dispatch model identity is invalid: {error}"),
                Usage::default(),
                None,
            )
        })?;
        let work_order_digest = Sha256Digest::parse(dispatch.attestation.work_order_sha256.clone())
            .map_err(|error| {
                self.failure(
                    AgentFailureKind::PermissionDenied,
                    format!("work-order digest is invalid: {error}"),
                    Usage::default(),
                    None,
                )
            })?;
        let context_manifest_digest = Sha256Digest::parse(
            dispatch.attestation.context_manifest_sha256.clone(),
        )
        .map_err(|error| {
            self.failure(
                AgentFailureKind::PermissionDenied,
                format!("context digest is invalid: {error}"),
                Usage::default(),
                None,
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
        let dependency_handoffs = dispatch
            .work_order
            .dependencies
            .iter()
            .map(|work_order_id| {
                let handoff = dispatch
                    .dependency_handoffs
                    .get(work_order_id)
                    .ok_or_else(|| {
                        self.failure(
                            AgentFailureKind::PermissionDenied,
                            "dependency handoff disappeared after exact dispatch validation",
                            Usage::default(),
                            None,
                        )
                    })?;
                let scheduler_event_id = dispatch
                    .dependency_handoff_event_ids
                    .get(work_order_id)
                    .copied()
                    .ok_or_else(|| {
                        self.failure(
                            AgentFailureKind::PermissionDenied,
                            "dependency event disappeared after exact dispatch validation",
                            Usage::default(),
                            None,
                        )
                    })?;
                Ok(RepositoryImplementationDependencyHandoffV1 {
                    work_order_id: *work_order_id,
                    outcome: handoff.outcome,
                    summary: handoff.summary.clone(),
                    artifact_sha256: handoff.artifact_sha256.clone(),
                    evidence_ids: handoff.evidence_ids.clone(),
                    scheduler_event_id,
                })
            })
            .collect::<Result<Vec<_>, AgentFailure>>()?;
        let local_plan_id = ChildLocalPlanId::new();
        self.retain(
            RepositoryImplementationJournalRecordV1::ExecutionStarted {
                binding: binding.clone(),
                local_plan_id,
                model_lineage: lineage.clone(),
            },
            Vec::new(),
        )?;

        let source_repository = authority.source_repository.clone();
        let scratch_root = authority.scratch_root.clone();
        let worktree = tokio::task::spawn_blocking(move || {
            TemporaryGitWorktree::create_clean_committed_head(source_repository, scratch_root)
        })
        .await
        .map_err(|error| {
            self.failure(
                AgentFailureKind::PermanentBackend,
                format!("clean-HEAD materializer task did not join: {error}"),
                Usage::default(),
                None,
            )
        })?
        .map_err(|error| {
            self.failure(
                AgentFailureKind::PermissionDenied,
                format!("clean-HEAD materialization failed closed: {error}"),
                Usage::default(),
                None,
            )
        })?;
        let WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
            git_baseline_sha256,
        } = &dispatch.work_order.workspace.source
        else {
            return Err(self.failure(
                AgentFailureKind::PermissionDenied,
                "implementation dispatch is not bound to a clean Git HEAD",
                Usage::default(),
                None,
            ));
        };
        let workspace_snapshot =
            Sha256Digest::parse(git_baseline_sha256.clone()).map_err(|error| {
                self.failure(
                    AgentFailureKind::PermissionDenied,
                    format!("workspace baseline digest is invalid: {error}"),
                    Usage::default(),
                    None,
                )
            })?;
        if worktree.git_baseline_sha256() != &workspace_snapshot {
            return Err(self.failure(
                AgentFailureKind::PermissionDenied,
                "materialized Git HEAD differs from the exact workspace baseline",
                Usage::default(),
                None,
            ));
        }
        let target_read = worktree
            .read_utf8_file(&authority.write_grant.path)
            .map_err(|error| {
                self.failure(
                    AgentFailureKind::PermissionDenied,
                    format!("write target preimage could not be observed: {error}"),
                    Usage::default(),
                    None,
                )
            })?;
        if target_read.observation.sha256 != authority.write_grant.expected_preimage_sha256
            || target_read.observation.byte_len > MAX_MODEL_VISIBLE_FILE_BYTES
            || target_read.observation.byte_len > read_grant_max_bytes(&authority.read_grant)
        {
            return Err(self.failure(
                AgentFailureKind::PermissionDenied,
                "write target differs from its staged preimage or exceeds the read profile",
                Usage::default(),
                None,
            ));
        }
        let receipt = GitCleanHeadMaterializationReceiptV1 {
            contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
            profile_id: PROFILE_ID.to_owned(),
            binding: binding.clone(),
            workspace_lease_id: dispatch.work_order.workspace.lease_id.clone(),
            source_repository: native_path(worktree.source_repository()).map_err(|message| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    message,
                    Usage::default(),
                    None,
                )
            })?,
            worktree_path: native_path(worktree.path()).map_err(|message| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    message,
                    Usage::default(),
                    None,
                )
            })?,
            worktree_root_identity: worktree.root_identity().map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("materialized worktree identity failed: {error}"),
                    Usage::default(),
                    None,
                )
            })?,
            worktree_id: worktree.worktree_id(),
            base_commit: worktree.base_commit().to_owned(),
            git_baseline_sha256: worktree.git_baseline_sha256().clone(),
            target_path: authority.write_grant.path.clone(),
            target_preimage_sha256: target_read.observation.sha256,
        };
        let receipt_artifact = RepositoryImplementationArtifact::from_bytes(
            MATERIALIZATION_MEDIA_TYPE,
            serde_json::to_vec(&receipt).map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("materialization receipt could not be encoded: {error}"),
                    Usage::default(),
                    None,
                )
            })?,
        );
        let materialization_event_id = self.retain(
            RepositoryImplementationJournalRecordV1::GitBaselineMaterialized {
                binding: binding.clone(),
                worktree_id: worktree.worktree_id(),
                base_commit: worktree.base_commit().to_owned(),
                receipt_artifact: receipt_artifact.artifact.clone(),
            },
            vec![receipt_artifact.clone()],
        )?;
        let materialization = GitBaselineMaterializationV1 {
            workspace_lease_id: dispatch.work_order.workspace.lease_id.clone(),
            source_snapshot_sha256: workspace_snapshot.clone(),
            git_baseline_sha256: worktree.git_baseline_sha256().clone(),
            base_commit: worktree.base_commit().to_owned(),
            worktree_id: worktree.worktree_id(),
            materialization_event_id,
            receipt_artifact: receipt_artifact.artifact,
        };
        let exact_write_grant = ExactReplaceUtf8FileGrantV1 {
            grant_id: authority.write_grant.grant_id,
            binding: binding.clone(),
            workspace_lease_id: dispatch.work_order.workspace.lease_id.clone(),
            workspace_access: WorkspaceAccess::Write,
            base_snapshot_sha256: workspace_snapshot,
            git_baseline_sha256: worktree.git_baseline_sha256().clone(),
            worktree_id: worktree.worktree_id(),
            base_commit: worktree.base_commit().to_owned(),
            path: authority.write_grant.path.clone(),
            expected_preimage_sha256: authority.write_grant.expected_preimage_sha256.clone(),
            max_content_bytes: authority.write_grant.max_content_bytes,
        };
        let mut state = AttemptState {
            binding,
            local_plan_id,
            prior_plan: None,
            previous_rejection: None,
            model_calls: 0,
            action_rejections: 0,
            tool_calls: 0,
            remaining_output_tokens: dispatch.work_order.budget.max_output_tokens,
            reported_output_tokens: Some(0),
            worktree: Some(worktree),
            materialization,
            exact_write_grant,
            read_observation: None,
            write_observation: None,
            observed_write: None,
            write_lane: None,
        };

        loop {
            if state.model_calls >= self.policy.max_model_calls
                || state.remaining_output_tokens < u64::from(self.policy.max_output_tokens_per_call)
            {
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    "implementation agent exhausted a complete model-call slot",
                    Self::usage(&state),
                    Self::effect_receipt(&state),
                ));
            }
            state.model_calls = state.model_calls.saturating_add(1);
            let model_call_ordinal = state.model_calls;
            let model_call_id = ChildModelCallId::new();
            let required_previous_plan_digest = state
                .prior_plan
                .as_ref()
                .map(|plan| {
                    serde_json::to_vec(plan)
                        .map(|bytes| Sha256Digest::of_bytes(&bytes))
                        .map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!("prior plan could not be bound: {error}"),
                                Self::usage(&state),
                                Self::effect_receipt(&state),
                            )
                        })
                })
                .transpose()?;
            let turn = RepositoryImplementationTurnInputV1 {
                contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
                profile_id: PROFILE_ID.to_owned(),
                binding: state.binding.clone(),
                model_call_ordinal,
                objective: dispatch.work_order.objective.clone(),
                acceptance_criteria: dispatch.work_order.acceptance_criteria.clone(),
                dependency_handoffs: dependency_handoffs.clone(),
                required_read_target: (state.read_observation.is_none()
                    && state.write_observation.is_none())
                .then(|| model_path_from_repository_path(&authority.write_grant.path)),
                available_tool_grants: (state.read_observation.is_none()
                    && state.write_observation.is_none())
                .then(|| authority.read_grant.clone())
                .into_iter()
                .collect(),
                available_write_grants: (state.read_observation.is_some()
                    && state.write_observation.is_none())
                .then(|| ModelWriteGrantV1 {
                    grant_id: authority.write_grant.grant_id,
                    path: model_path_from_repository_path(&authority.write_grant.path),
                    expected_preimage_sha256: authority
                        .write_grant
                        .expected_preimage_sha256
                        .clone(),
                    max_content_bytes: authority.write_grant.max_content_bytes,
                })
                .into_iter()
                .collect(),
                remaining_model_calls: self.policy.max_model_calls - state.model_calls,
                remaining_tool_calls: dispatch
                    .work_order
                    .budget
                    .max_tool_calls
                    .saturating_sub(state.tool_calls),
                remaining_output_tokens: state.remaining_output_tokens,
                minimum_plan_revisions_before_finish: self
                    .policy
                    .minimum_plan_revisions_before_finish,
                required_plan_identity: RequiredPlanIdentityV1 {
                    plan_id: state.local_plan_id,
                    revision: state
                        .prior_plan
                        .as_ref()
                        .map_or(1, |plan| plan.revision.saturating_add(1)),
                    previous_plan_digest: required_previous_plan_digest,
                },
                prior_plan: state.prior_plan.clone(),
                read_observation: state.read_observation.clone(),
                write_observation: state.write_observation.clone(),
                required_finish_evidence: state.write_observation.as_ref().map(|write| {
                    ChildHandoffEvidenceBinding {
                        tool_call_id: write.tool_call_id,
                        observed_event_id: write.diff_event_id,
                        result_artifact: write.diff_artifact.clone(),
                    }
                }),
                previous_rejection: state.previous_rejection,
            };
            let response = self
                .call_model(&model_id, instance, &mut state, model_call_id, &turn)
                .await?;
            let model_observed_event_id = response.observed_event_id;
            let evidence_artifact = response.evidence_artifact;
            let normalized = response.normalized;
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

            if state.observed_write.is_some()
                && !matches!(
                    normalized.action,
                    RepositoryImplementationActionV1::Finish { .. }
                )
            {
                self.reject(
                    &mut state,
                    model_call_id,
                    model_observed_event_id,
                    RepositoryImplementationRejectionV1::PostWriteActionMustFinish,
                )?;
                continue;
            }

            match normalized.action.clone() {
                RepositoryImplementationActionV1::RepositoryFileRead {
                    tool_grant_id,
                    path,
                    offset_bytes,
                    max_bytes,
                } => {
                    if state.read_observation.is_some() || state.write_observation.is_some() {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::ReadAlreadyObserved,
                        )?;
                        continue;
                    }
                    if !read_action_matches(
                        &authority,
                        tool_grant_id,
                        &path,
                        offset_bytes,
                        max_bytes,
                    ) {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::ReadGrantMismatch,
                        )?;
                        continue;
                    }
                    if state.tool_calls >= dispatch.work_order.budget.max_tool_calls {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::ToolBudgetExhausted,
                        )?;
                        continue;
                    }
                    let (action_binding, action_artifact) = make_action_binding(
                        &state.binding,
                        &normalized,
                        &plan_binding,
                        model_call_id,
                        model_call_ordinal,
                        model_observed_event_id,
                        &evidence_artifact,
                        None,
                    )
                    .map_err(|failure| self.bind_failure_to_state(&state, failure))?;
                    self.retain_for_state(
                        &state,
                        RepositoryImplementationJournalRecordV1::ActionValidated {
                            binding: state.binding.clone(),
                            action_binding: action_binding.clone(),
                        },
                        vec![action_artifact],
                    )?;
                    let tool_call_id = ChildToolCallId::new();
                    let prepared_event_id = self.retain(
                        RepositoryImplementationJournalRecordV1::ReadPrepared {
                            binding: state.binding.clone(),
                            tool_call_id,
                            action_binding,
                        },
                        Vec::new(),
                    )?;
                    state.tool_calls = state.tool_calls.saturating_add(1);
                    let read = state
                        .worktree
                        .as_ref()
                        .ok_or_else(|| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                "read phase lost its worktree",
                                Self::usage(&state),
                                Self::effect_receipt(&state),
                            )
                        })?
                        .read_utf8_file(&authority.write_grant.path)
                        .map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!("descriptor-confined read failed: {error}"),
                                Self::usage(&state),
                                Self::effect_receipt(&state),
                            )
                        })?;
                    if read.observation.sha256 != authority.write_grant.expected_preimage_sha256
                        || read.observation.byte_len > read_grant_max_bytes(&authority.read_grant)
                    {
                        return Err(self.failure(
                            AgentFailureKind::PermissionDenied,
                            "read target changed after clean-HEAD materialization",
                            Self::usage(&state),
                            Self::effect_receipt(&state),
                        ));
                    }
                    let read_artifact = RepositoryImplementationArtifact::from_bytes(
                        READ_RESULT_MEDIA_TYPE,
                        serde_json::to_vec(&read).map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!("read result could not be encoded: {error}"),
                                Self::usage(&state),
                                Self::effect_receipt(&state),
                            )
                        })?,
                    );
                    let observed_event_id = self.retain(
                        RepositoryImplementationJournalRecordV1::ReadObserved {
                            binding: state.binding.clone(),
                            tool_call_id,
                            prepared_event_id,
                            result_artifact: read_artifact.artifact.clone(),
                        },
                        vec![read_artifact.clone()],
                    )?;
                    state.read_observation = Some(model_read_observation(
                        tool_call_id,
                        observed_event_id,
                        read,
                        read_artifact.artifact,
                    ));
                    state.previous_rejection = None;
                }
                RepositoryImplementationActionV1::ReplaceUtf8File {
                    grant_id,
                    path,
                    expected_preimage_sha256,
                    content_utf8,
                } => {
                    if state.read_observation.as_ref().is_none_or(|read| {
                        read.path != authority.write_grant.path
                            || read.byte_len
                                != u64::try_from(read.content_utf8.len()).unwrap_or(u64::MAX)
                            || read.content_sha256 != authority.write_grant.expected_preimage_sha256
                    }) {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::ReadRequiredBeforeWrite,
                        )?;
                        continue;
                    }
                    if !write_action_matches(
                        &authority,
                        grant_id,
                        &path,
                        &expected_preimage_sha256,
                        &content_utf8,
                    ) {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::WriteGrantMismatch,
                        )?;
                        continue;
                    }
                    if state
                        .read_observation
                        .as_ref()
                        .is_some_and(|read| read.content_utf8 == content_utf8)
                    {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::WriteWouldBeNoOp,
                        )?;
                        continue;
                    }
                    if state.tool_calls >= dispatch.work_order.budget.max_tool_calls {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::ToolBudgetExhausted,
                        )?;
                        continue;
                    }
                    if self
                        .policy
                        .max_model_calls
                        .saturating_sub(state.model_calls)
                        < self.policy.finish_call_reserve
                    {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::FinishBudgetNotReserved,
                        )?;
                        continue;
                    }
                    let (action_binding, action_artifact) = make_action_binding(
                        &state.binding,
                        &normalized,
                        &plan_binding,
                        model_call_id,
                        model_call_ordinal,
                        model_observed_event_id,
                        &evidence_artifact,
                        None,
                    )?;
                    let validated_action_event_id = self.retain(
                        RepositoryImplementationJournalRecordV1::ActionValidated {
                            binding: state.binding.clone(),
                            action_binding: action_binding.clone(),
                        },
                        vec![action_artifact.clone()],
                    )?;
                    let tool_call_id = ChildToolCallId::new();
                    let tool_ordinal =
                        u32::try_from(state.tool_calls.saturating_add(1)).map_err(|_| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                "write tool ordinal overflowed",
                                Self::usage(&state),
                                None,
                            )
                        })?;
                    let origin = WorktreeWriteOriginV1 {
                        binding: state.binding.clone(),
                        source_model_call_id: model_call_id,
                        source_model_call_ordinal: model_call_ordinal,
                        source_model_observed_event_id: model_observed_event_id,
                        source_plan: plan_binding,
                        active_plan_step_id: normalized.plan.active_step_id.clone().ok_or_else(
                            || {
                                self.failure(
                                    AgentFailureKind::PermanentBackend,
                                    "validated write plan has no active step",
                                    Self::usage(&state),
                                    None,
                                )
                            },
                        )?,
                        validated_action_event_id,
                        action_artifact: action_artifact.artifact,
                        tool_call_id,
                        tool_ordinal,
                    };
                    let request = ExactReplaceUtf8FileRequestV1 {
                        grant_id,
                        binding: state.binding.clone(),
                        worktree_id: state.exact_write_grant.worktree_id,
                        base_commit: state.exact_write_grant.base_commit.clone(),
                        path: path.to_repository_path(),
                        expected_preimage_sha256,
                        content_utf8,
                    };
                    let worktree = state.worktree.take().ok_or_else(|| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            "write phase lost its materialized worktree",
                            Self::usage(&state),
                            Self::effect_receipt(&state),
                        )
                    })?;
                    let lane = WorktreeWriteLane::new(
                        worktree,
                        state.exact_write_grant.clone(),
                        &dispatch.work_order.workspace,
                        state.materialization.clone(),
                        Arc::clone(&self.write_journal),
                    )
                    .map_err(|error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("write lane rejected materialization: {error}"),
                            Self::usage(&state),
                            None,
                        )
                    })?;
                    state.tool_calls = state.tool_calls.saturating_add(1);
                    let observed = lane.execute_once(origin, request).map_err(|error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("exact write failed: {error}"),
                            Self::usage(&state),
                            Some(format!(
                                "repository-write-worktree:{}",
                                state.exact_write_grant.worktree_id
                            )),
                        )
                    })?;
                    state.write_observation = Some(model_write_observation(&observed));
                    state.observed_write = Some(observed);
                    state.write_lane = Some(lane);
                    state.previous_rejection = None;
                }
                RepositoryImplementationActionV1::Finish { handoff } => {
                    if normalized.plan.revision
                        < u64::from(self.policy.minimum_plan_revisions_before_finish)
                    {
                        self.reject(
                            &mut state,
                            model_call_id,
                            model_observed_event_id,
                            RepositoryImplementationRejectionV1::FinishBeforeMinimumRevision,
                        )?;
                        continue;
                    }
                    let finish_evidence = match validate_finish_evidence(
                        &handoff,
                        state.read_observation.as_ref(),
                        state.write_observation.as_ref(),
                    ) {
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
                        model_call_ordinal,
                        model_observed_event_id,
                        &evidence_artifact,
                        Some(handoff_id),
                    )
                    .map_err(|failure| self.bind_failure_to_state(&state, failure))?;
                    self.retain_for_state(
                        &state,
                        RepositoryImplementationJournalRecordV1::ActionValidated {
                            binding: state.binding.clone(),
                            action_binding: action_binding.clone(),
                        },
                        vec![action_artifact],
                    )?;
                    let handoff_document = ChildHandoffDocument {
                        contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
                        binding: state.binding.clone(),
                        handoff_id,
                        content: handoff.clone(),
                    };
                    let handoff_artifact = RepositoryImplementationArtifact::from_bytes(
                        CHILD_HANDOFF_MEDIA_TYPE,
                        serde_json::to_vec(&handoff_document).map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!("finish handoff could not be encoded: {error}"),
                                Self::usage(&state),
                                Self::effect_receipt(&state),
                            )
                        })?,
                    );
                    let finish_event_id = self.retain_for_state(
                        &state,
                        RepositoryImplementationJournalRecordV1::FinishAccepted {
                            binding: state.binding.clone(),
                            handoff_id,
                            action_binding,
                            handoff_artifact: handoff_artifact.artifact.clone(),
                        },
                        vec![handoff_artifact.clone()],
                    )?;
                    let observed_write = state.observed_write.as_ref().ok_or_else(|| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            "Finish was accepted without an exact observed write",
                            Self::usage(&state),
                            Self::effect_receipt(&state),
                        )
                    })?;
                    let read_observation = state.read_observation.as_ref().ok_or_else(|| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            "Finish was accepted without an exact preimage read",
                            Self::usage(&state),
                            Self::effect_receipt(&state),
                        )
                    })?;
                    let retained_handoff = CanonicalArtifactBoundary
                        .retain(CHILD_HANDOFF_MEDIA_TYPE, handoff_artifact.bytes.clone())
                        .map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!("candidate handoff retention failed: {error}"),
                                Self::usage(&state),
                                Self::effect_receipt(&state),
                            )
                        })?;
                    let candidate_body = RepositoryCandidateBodyV1 {
                        contract_version: REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
                        producer_work_order_id: dispatch.work_order.id,
                        producer: RepositoryCandidateProducerV1 {
                            locator: RepositoryCandidateProducerLocatorV1 {
                                graph_sha256: Sha256Digest::parse(dispatch.graph_sha256.clone())
                                    .map_err(|error| {
                                        self.failure(
                                            AgentFailureKind::PermanentBackend,
                                            format!(
                                                "candidate graph binding is invalid: {error}"
                                            ),
                                            Self::usage(&state),
                                            Self::effect_receipt(&state),
                                        )
                                    })?,
                                work_order_id: dispatch.work_order.id,
                                actor_id: dispatch.actor_id,
                                execution_id: dispatch.execution_id,
                                attempt_id: dispatch.attempt_id,
                            },
                            binding: state.binding.clone(),
                            lineage: dispatch.work_order.assignment.lineage.clone(),
                            dispatch_attestation: dispatch.attestation.clone(),
                            dispatch_attestation_sha256: dispatch_attestation_digest(
                                &dispatch.attestation,
                            )
                            .map_err(|error| {
                                self.failure(
                                    AgentFailureKind::PermanentBackend,
                                    format!("candidate dispatch binding failed: {error}"),
                                    Self::usage(&state),
                                    Self::effect_receipt(&state),
                                )
                            })?,
                        },
                        baseline: RepositoryCandidateBaselineV1 {
                            workspace_lease_id: state.exact_write_grant.workspace_lease_id.clone(),
                            git_baseline_sha256: state.materialization.git_baseline_sha256.clone(),
                            base_commit: state.materialization.base_commit.clone(),
                        },
                        change: ExactUtf8ReplaceCandidateV1 {
                            path: observed_write.mutation.path.clone(),
                            preimage: observed_write.mutation.preimage.clone(),
                            postimage: observed_write.mutation.postimage.clone(),
                            preimage_artifact: ArtifactRef {
                                sha256: observed_write.mutation.preimage.sha256.as_str().to_owned(),
                                size_bytes: observed_write.mutation.preimage.byte_len,
                                media_type: crate::repository_candidate::REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE
                                    .to_owned(),
                            },
                            postimage_artifact: observed_write
                                .postimage_artifact
                                .artifact
                                .clone(),
                            diff_artifact: observed_write.diff_artifact.artifact.clone(),
                            replace_event_id: observed_write.replace_event_id,
                            diff_event_id: observed_write.diff_event_id,
                        },
                        finish_event_id,
                        producer_handoff_artifact: retained_handoff.artifact.clone(),
                    };
                    let candidate = RepositoryCandidateBundleV1::seal(
                        candidate_body,
                        read_observation.content_utf8.as_bytes().to_vec(),
                        observed_write.postimage_artifact.clone(),
                        observed_write.diff_artifact.clone(),
                        retained_handoff,
                    )
                    .map_err(|error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("repository candidate sealing failed: {error}"),
                            Self::usage(&state),
                            Self::effect_receipt(&state),
                        )
                    })?;
                    let candidate_artifact_sha256 =
                        candidate.manifest_artifact.artifact.sha256.clone();
                    let candidate_preimage_sha256 =
                        candidate.preimage_artifact.artifact.sha256.clone();
                    let candidate_postimage_sha256 =
                        candidate.postimage_artifact.artifact.sha256.clone();
                    let publication = self.candidate_store.publish(candidate).map_err(|error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("repository candidate publication failed: {error}"),
                            Self::usage(&state),
                            Self::effect_receipt(&state),
                        )
                    })?;
                    let candidate_published_event_id = publication.published_event_id();
                    let publication_artifact_sha256 =
                        publication.receipt_artifact().artifact.sha256.clone();
                    let lane = state.write_lane.as_ref().ok_or_else(|| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            "candidate publication has no owned write lane",
                            Self::usage(&state),
                            Self::effect_receipt(&state),
                        )
                    })?;
                    let release = lane
                        .release_after_candidate_published(&state.binding, &publication)
                        .map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!("published candidate could not release worktree: {error}"),
                                Self::usage(&state),
                                Some(format!(
                                    "repository-candidate-published:{candidate_published_event_id}"
                                )),
                            )
                        })?;
                    let cleanup_event_id = release.cleanup_observed_event_id();
                    let cleanup_artifact_sha256 =
                        release.receipt_artifact().artifact.sha256.clone();
                    let ready = self
                        .candidate_store
                        .mark_cleanup_observed(&publication, &release)
                        .map_err(|error| {
                            self.failure(
                                AgentFailureKind::PermanentBackend,
                                format!("candidate cleanup acknowledgement failed: {error}"),
                                Self::usage(&state),
                                Some(format!("repository-candidate-cleanup:{cleanup_event_id}")),
                            )
                        })?;
                    let ready_event_id = ready.ready_event_id();
                    let ready_artifact_sha256 = ready.receipt_artifact().artifact.sha256.clone();
                    let mut artifact_sha256 = finish_evidence.artifact_sha256;
                    artifact_sha256.insert(handoff_artifact.artifact.sha256);
                    artifact_sha256.insert(candidate_artifact_sha256);
                    artifact_sha256.insert(candidate_preimage_sha256);
                    artifact_sha256.insert(candidate_postimage_sha256);
                    artifact_sha256.insert(publication_artifact_sha256);
                    artifact_sha256.insert(cleanup_artifact_sha256);
                    artifact_sha256.insert(ready_artifact_sha256);
                    let mut evidence_ids = finish_evidence.observed_event_ids;
                    evidence_ids.insert(finish_event_id);
                    evidence_ids.insert(candidate_published_event_id);
                    evidence_ids.insert(cleanup_event_id);
                    evidence_ids.insert(ready_event_id);
                    return Ok(AgentCompletion {
                        outcome: match handoff.status {
                            ChildHandoffStatus::Complete => HandoffOutcome::Completed,
                            ChildHandoffStatus::Partial => HandoffOutcome::Partial,
                            ChildHandoffStatus::Blocked => HandoffOutcome::Blocked,
                        },
                        summary: handoff.summary,
                        execution_receipt_id: format!(
                            "repository-candidate-ready:{ready_event_id}"
                        ),
                        artifact_sha256: artifact_sha256.into_iter().collect(),
                        evidence_ids: evidence_ids
                            .into_iter()
                            .map(|event_id| event_id.to_string())
                            .collect(),
                        usage: Self::usage(&state),
                    });
                }
                RepositoryImplementationActionV1::RepositoryTree { .. }
                | RepositoryImplementationActionV1::LiteralSearch { .. } => {
                    self.reject(
                        &mut state,
                        model_call_id,
                        model_observed_event_id,
                        RepositoryImplementationRejectionV1::ReadGrantMismatch,
                    )?;
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the model boundary keeps request, provider evidence, validation, and journal causality visibly contiguous"
    )]
    async fn call_model(
        &self,
        model_id: &ModelId,
        instance: &birdcode_backends::BackendInstanceIdentity,
        state: &mut AttemptState<W>,
        model_call_id: ChildModelCallId,
        turn: &RepositoryImplementationTurnInputV1,
    ) -> Result<ObservedModelResponse, AgentFailure> {
        let model_call_ordinal = turn.model_call_ordinal;
        let turn_json = serde_json::to_string(turn).map_err(|error| {
            self.failure(
                AgentFailureKind::PermanentBackend,
                format!("implementation turn could not be encoded: {error}"),
                Self::usage(state),
                Self::effect_receipt(state),
            )
        })?;
        let generation_phase = if turn.write_observation.is_some() {
            repository_implementation_prompt::RepositoryImplementationGenerationPhaseV1::Finish
        } else if turn.read_observation.is_some() {
            repository_implementation_prompt::RepositoryImplementationGenerationPhaseV1::Replace
        } else {
            repository_implementation_prompt::RepositoryImplementationGenerationPhaseV1::Read
        };
        let output = repository_implementation_prompt::output_spec(
            generation_phase,
            turn.required_finish_evidence.as_ref(),
        )
        .map_err(|error| {
            self.failure(
                AgentFailureKind::PermanentBackend,
                format!("implementation output contract is invalid: {error}"),
                Self::usage(state),
                Self::effect_receipt(state),
            )
        })?;
        let mut request = StructuredInferenceRequest::new(
            model_id.clone(),
            repository_implementation_prompt::messages(turn_json),
            output,
            self.policy.max_output_tokens_per_call,
        )
        .map_err(|error| {
            self.failure(
                AgentFailureKind::PermanentBackend,
                format!("implementation model request is invalid: {error}"),
                Self::usage(state),
                Self::effect_receipt(state),
            )
        })?;
        if let Some(reasoning) = self.policy.reasoning {
            request = request.with_reasoning(reasoning);
        }
        let request_artifact = RepositoryImplementationArtifact::from_bytes(
            MODEL_REQUEST_MEDIA_TYPE,
            serde_json::to_vec(&request).map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("implementation request evidence could not be encoded: {error}"),
                    Self::usage(state),
                    Self::effect_receipt(state),
                )
            })?,
        );
        if request_artifact.artifact.size_bytes > CHILD_RECONNAISSANCE_MAX_MODEL_ARTIFACT_BYTES {
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "implementation request exceeded the evidence ceiling",
                Self::usage(state),
                Self::effect_receipt(state),
            ));
        }
        let prepared_event_id = self.retain_for_state(
            state,
            RepositoryImplementationJournalRecordV1::ModelPrepared {
                binding: state.binding.clone(),
                model_call_id,
                ordinal: model_call_ordinal,
                request_artifact: request_artifact.artifact.clone(),
            },
            vec![request_artifact],
        )?;
        let response = match self.backend.infer_structured(request).await {
            Ok(response) => response,
            Err(error) => {
                let error_artifact = RepositoryImplementationArtifact::from_bytes(
                    MODEL_ERROR_MEDIA_TYPE,
                    serde_json::to_vec(&ModelErrorEvidenceV1 {
                        contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
                        binding: &state.binding,
                        model_call_id,
                        model_call_ordinal,
                        prepared_event_id,
                        error: &error,
                    })
                    .map_err(|encode_error| {
                        self.failure(
                            AgentFailureKind::PermanentBackend,
                            format!("backend error evidence failed: {encode_error}"),
                            Self::usage(state),
                            Self::effect_receipt(state),
                        )
                    })?,
                );
                self.retain_for_state(
                    state,
                    RepositoryImplementationJournalRecordV1::ModelFailed {
                        binding: state.binding.clone(),
                        model_call_id,
                        ordinal: model_call_ordinal,
                        prepared_event_id,
                        error_artifact: error_artifact.artifact.clone(),
                    },
                    vec![error_artifact],
                )?;
                return Err(self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("implementation backend failed: {error}"),
                    Self::usage(state),
                    Self::effect_receipt(state),
                ));
            }
        };
        let output_tokens = response
            .usage
            .as_ref()
            .and_then(|usage| usage.output_tokens);
        let charged = output_tokens.unwrap_or(u64::from(self.policy.max_output_tokens_per_call));
        state.remaining_output_tokens = state.remaining_output_tokens.saturating_sub(charged);
        state.reported_output_tokens = match (state.reported_output_tokens, output_tokens) {
            (Some(total), Some(current)) => total.checked_add(current),
            _ => None,
        };
        let evidence_artifact = RepositoryImplementationArtifact::from_bytes(
            MODEL_RESPONSE_MEDIA_TYPE,
            serde_json::to_vec(&ModelEvidenceV1 {
                contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
                binding: &state.binding,
                model_call_id,
                model_call_ordinal,
                prepared_event_id,
                response: &response,
            })
            .map_err(|error| {
                self.failure(
                    AgentFailureKind::PermanentBackend,
                    format!("model response evidence could not be encoded: {error}"),
                    Self::usage(state),
                    Self::effect_receipt(state),
                )
            })?,
        );
        if evidence_artifact.artifact.size_bytes > CHILD_RECONNAISSANCE_MAX_MODEL_ARTIFACT_BYTES {
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "implementation response exceeded the evidence ceiling",
                Self::usage(state),
                Self::effect_receipt(state),
            ));
        }
        let observed_event_id = self.retain_for_state(
            state,
            RepositoryImplementationJournalRecordV1::ModelObserved {
                binding: state.binding.clone(),
                model_call_id,
                ordinal: model_call_ordinal,
                prepared_event_id,
                response_artifact: evidence_artifact.artifact.clone(),
                output_tokens,
            },
            vec![evidence_artifact.clone()],
        )?;
        if output_tokens
            .is_some_and(|tokens| tokens > u64::from(self.policy.max_output_tokens_per_call))
        {
            self.retain_for_state(
                state,
                RepositoryImplementationJournalRecordV1::ModelContractRejected {
                    binding: state.binding.clone(),
                    model_call_id,
                    observed_event_id,
                    violation: RepositoryImplementationModelViolationV1::OutputTokenCeilingExceeded,
                },
                Vec::new(),
            )?;
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "backend reported output usage above the prepared ceiling",
                Self::usage(state),
                Self::effect_receipt(state),
            ));
        }
        if response.model_id != *model_id
            || !instance.matches_response_evidence(&response.evidence)
            || !serde_json::from_str::<serde_json::Value>(&response.raw_text)
                .is_ok_and(|value| value == response.value)
        {
            self.retain_for_state(
                state,
                RepositoryImplementationJournalRecordV1::ModelContractRejected {
                    binding: state.binding.clone(),
                    model_call_id,
                    observed_event_id,
                    violation: RepositoryImplementationModelViolationV1::ResponseBindingMismatch,
                },
                Vec::new(),
            )?;
            return Err(self.failure(
                AgentFailureKind::PermanentBackend,
                "backend response failed exact identity or raw JSON binding",
                Self::usage(state),
                Self::effect_receipt(state),
            ));
        }
        let normalized =
            match serde_json::from_value::<RepositoryImplementationModelResponseV1>(response.value)
            {
                Ok(normalized) => normalized,
                Err(error) => {
                    self.retain_for_state(
                        state,
                        RepositoryImplementationJournalRecordV1::ModelContractRejected {
                            binding: state.binding.clone(),
                            model_call_id,
                            observed_event_id,
                            violation:
                                RepositoryImplementationModelViolationV1::StructuredResponseInvalid,
                        },
                        Vec::new(),
                    )?;
                    return Err(self.failure(
                        AgentFailureKind::PermanentBackend,
                        format!(
                            "backend returned a nonconforming implementation response: {error}"
                        ),
                        Self::usage(state),
                        Self::effect_receipt(state),
                    ));
                }
            };
        Ok(ObservedModelResponse {
            normalized,
            observed_event_id,
            evidence_artifact,
        })
    }
}

impl<J, W> AgentWorker for RepositoryImplementationAgentWorker<J, W>
where
    J: RepositoryImplementationJournal + ?Sized,
    W: WorktreeWriteLaneJournal + ?Sized,
{
    fn execute(&self, dispatch: AgentDispatch) -> AgentFuture<'_> {
        Box::pin(self.run_attempt(dispatch))
    }
}

struct ObservedModelResponse {
    normalized: RepositoryImplementationModelResponseV1,
    observed_event_id: EventId,
    evidence_artifact: RepositoryImplementationArtifact,
}

fn model_path_from_repository_path(path: &RepositoryRelativePathV1) -> ModelRepositoryPathV1 {
    ModelRepositoryPathV1 {
        components: path
            .unix_components()
            .iter()
            .cloned()
            .map(|value| ModelRepositoryPathComponentV1::UnixBytes { value })
            .collect(),
    }
}

fn dependency_maps_match(dispatch: &AgentDispatch) -> bool {
    let dependencies = &dispatch.work_order.dependencies;
    dispatch.dependency_handoffs.len() == dependencies.len()
        && dispatch.dependency_handoff_event_ids.len() == dependencies.len()
        && dependencies.iter().all(|work_order_id| {
            dispatch.dependency_handoffs.contains_key(work_order_id)
                && dispatch
                    .dependency_handoff_event_ids
                    .contains_key(work_order_id)
        })
}

fn read_grant_max_bytes(grant: &RepositoryToolGrantV1) -> u64 {
    match grant {
        RepositoryToolGrantV1::RepositoryFileRead { max_bytes, .. } => *max_bytes,
        RepositoryToolGrantV1::RepositoryTree { .. }
        | RepositoryToolGrantV1::LiteralSearch { .. } => 0,
    }
}

fn path_fits_read_grant(
    path: &RepositoryRelativePathV1,
    max_path_components: u32,
    max_path_bytes: u64,
    max_component_bytes: u64,
) -> bool {
    let components = path.unix_components();
    if components.is_empty()
        || u64::try_from(components.len()).unwrap_or(u64::MAX) > u64::from(max_path_components)
    {
        return false;
    }
    let mut path_bytes = 0_u64;
    for component in components {
        if component.is_empty()
            || component.as_slice() == b"."
            || component.as_slice() == b".."
            || component.contains(&b'/')
            || component.contains(&0)
            || u64::try_from(component.len()).unwrap_or(u64::MAX) > max_component_bytes
        {
            return false;
        }
        let Some(next) = path_bytes
            .checked_add(u64::try_from(component.len()).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(1))
        else {
            return false;
        };
        path_bytes = next;
    }
    path_bytes <= max_path_bytes
}

fn read_action_matches(
    authority: &RepositoryImplementationDispatchAuthority,
    grant_id: RepositoryToolGrantId,
    path: &ModelRepositoryPathV1,
    offset_bytes: u64,
    max_bytes: u64,
) -> bool {
    let RepositoryToolGrantV1::RepositoryFileRead {
        tool_grant_id,
        max_offset_bytes,
        max_bytes: granted_max_bytes,
        ..
    } = &authority.read_grant
    else {
        return false;
    };
    grant_id == *tool_grant_id
        && path.to_repository_path() == authority.write_grant.path
        && offset_bytes == 0
        && offset_bytes <= *max_offset_bytes
        && max_bytes == *granted_max_bytes
}

fn write_action_matches(
    authority: &RepositoryImplementationDispatchAuthority,
    grant_id: RepositoryToolGrantId,
    path: &ModelRepositoryPathV1,
    expected_preimage_sha256: &Sha256Digest,
    content_utf8: &str,
) -> bool {
    grant_id == authority.write_grant.grant_id
        && path.to_repository_path() == authority.write_grant.path
        && expected_preimage_sha256 == &authority.write_grant.expected_preimage_sha256
        && u64::try_from(content_utf8.len())
            .is_ok_and(|size| size <= authority.write_grant.max_content_bytes)
}

fn model_read_observation(
    tool_call_id: ChildToolCallId,
    observed_event_id: EventId,
    read: GitWorktreeUtf8FileReadV1,
    result_artifact: ArtifactRef,
) -> ModelReadObservationV1 {
    ModelReadObservationV1 {
        tool_call_id,
        observed_event_id,
        path: read.path,
        content_utf8: read.content_utf8,
        byte_len: read.observation.byte_len,
        content_sha256: read.observation.sha256,
        result_artifact,
    }
}

fn model_write_observation(observed: &ObservedSingleWriteV1) -> ModelWriteObservationV1 {
    ModelWriteObservationV1 {
        tool_call_id: observed.origin.tool_call_id,
        replace_event_id: observed.replace_event_id,
        diff_event_id: observed.diff_event_id,
        path: observed.mutation.path.clone(),
        preimage_sha256: observed.mutation.preimage.sha256.clone(),
        postimage_sha256: observed.mutation.postimage.sha256.clone(),
        diff_artifact: observed.diff_artifact.artifact.clone(),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "every argument is an exact causal binding retained in the app-local action document"
)]
fn make_action_binding(
    binding: &ChildExecutionBinding,
    normalized: &RepositoryImplementationModelResponseV1,
    plan_binding: &ChildLocalPlanBindingV1,
    model_call_id: ChildModelCallId,
    model_call_ordinal: u32,
    model_observed_event_id: EventId,
    model_evidence: &RepositoryImplementationArtifact,
    completion_handoff_id: Option<ChildHandoffId>,
) -> Result<
    (
        ChildValidatedActionBindingV1,
        RepositoryImplementationArtifact,
    ),
    AgentFailure,
> {
    let document = RepositoryImplementationValidatedActionDocumentV1 {
        contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
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
    let bytes = serde_json::to_vec(&document).map_err(|error| AgentFailure {
        kind: AgentFailureKind::PermanentBackend,
        message: format!("validated implementation action could not be encoded: {error}"),
        usage: Usage::default(),
        execution_receipt_id: "repository-implementation-action-validation".to_owned(),
        effect_receipt_id: None,
    })?;
    let action_artifact = RepositoryImplementationArtifact::from_bytes(ACTION_MEDIA_TYPE, bytes);
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
    reason = "the closed plan transition is kept in one auditable mechanical validator"
)]
fn validate_plan(
    objective: &str,
    binding: &ChildExecutionBinding,
    local_plan_id: ChildLocalPlanId,
    prior: Option<&ChildLocalPlanSnapshotV1>,
    response: &RepositoryImplementationModelResponseV1,
) -> Result<ChildLocalPlanBindingV1, RepositoryImplementationRejectionV1> {
    let plan = &response.plan;
    if response.contract_version != REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION
        || plan.contract_version != REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION
    {
        return Err(RepositoryImplementationRejectionV1::ContractMismatch);
    }
    if plan.binding != *binding {
        return Err(RepositoryImplementationRejectionV1::ExecutionBindingMismatch);
    }
    if plan.plan_id != local_plan_id {
        return Err(RepositoryImplementationRejectionV1::PlanIdentityMismatch);
    }
    if plan.objective != objective {
        return Err(RepositoryImplementationRejectionV1::ObjectiveMismatch);
    }
    let prior_digest = prior.and_then(|previous| {
        serde_json::to_vec(previous)
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
        return Err(RepositoryImplementationRejectionV1::PlanRevisionMismatch);
    }
    if plan.steps.is_empty()
        || plan.steps.len() > CHILD_RECONNAISSANCE_MAX_PLAN_STEPS
        || plan.assumptions.len() > CHILD_RECONNAISSANCE_MAX_PLAN_ASSUMPTIONS
        || plan.unknowns.len() > CHILD_RECONNAISSANCE_MAX_PLAN_UNKNOWNS
    {
        return Err(RepositoryImplementationRejectionV1::PlanStructureInvalid);
    }
    let mut steps = BTreeMap::new();
    let mut in_progress = Vec::new();
    for step in &plan.steps {
        if !bounded_identifier(step.step_id.as_str())
            || !bounded_text(&step.objective)
            || steps.insert(step.step_id.clone(), step).is_some()
        {
            return Err(RepositoryImplementationRejectionV1::PlanStructureInvalid);
        }
        if step.status == ChildLocalPlanStepStatusV1::InProgress {
            in_progress.push(step.step_id.clone());
        }
    }
    if let Some(previous) = prior {
        let previous_step_ids = previous
            .steps
            .iter()
            .map(|step| &step.step_id)
            .collect::<BTreeSet<_>>();
        if plan.steps.iter().any(|step| {
            !previous_step_ids.contains(&step.step_id)
                && !matches!(
                    step.status,
                    ChildLocalPlanStepStatusV1::Pending | ChildLocalPlanStepStatusV1::InProgress
                )
        }) {
            return Err(RepositoryImplementationRejectionV1::PlanTransitionInvalid);
        }
        for previous_step in &previous.steps {
            let Some(current) = steps.get(&previous_step.step_id) else {
                return Err(RepositoryImplementationRejectionV1::PlanTransitionInvalid);
            };
            if current.objective != previous_step.objective
                || !valid_step_transition(previous_step.status, current.status)
            {
                return Err(RepositoryImplementationRejectionV1::PlanTransitionInvalid);
            }
        }
    } else if plan.steps.iter().any(|step| {
        !matches!(
            step.status,
            ChildLocalPlanStepStatusV1::Pending | ChildLocalPlanStepStatusV1::InProgress
        )
    }) {
        return Err(RepositoryImplementationRejectionV1::PlanTransitionInvalid);
    }
    let active_is_exact = match plan.active_step_id.as_ref() {
        Some(active) => in_progress.as_slice() == [active.clone()],
        None => in_progress.is_empty(),
    };
    if !active_is_exact {
        return Err(RepositoryImplementationRejectionV1::PlanStructureInvalid);
    }
    let mut assumption_ids = BTreeSet::new();
    if plan.assumptions.iter().any(|assumption| {
        !bounded_identifier(&assumption.assumption_id)
            || !bounded_text(&assumption.statement)
            || !assumption_ids.insert(assumption.assumption_id.as_str())
    }) {
        return Err(RepositoryImplementationRejectionV1::PlanStructureInvalid);
    }
    let mut unknown_ids = BTreeSet::new();
    if plan.unknowns.iter().any(|unknown| {
        !bounded_identifier(&unknown.unknown_id)
            || !bounded_text(&unknown.question)
            || !unknown_ids.insert(unknown.unknown_id.as_str())
    }) {
        return Err(RepositoryImplementationRejectionV1::PlanStructureInvalid);
    }
    match &response.action {
        RepositoryImplementationActionV1::RepositoryTree { .. }
        | RepositoryImplementationActionV1::RepositoryFileRead { .. }
        | RepositoryImplementationActionV1::LiteralSearch { .. }
        | RepositoryImplementationActionV1::ReplaceUtf8File { .. }
            if plan.active_step_id.is_some() => {}
        RepositoryImplementationActionV1::Finish { handoff }
            if plan.active_step_id.is_none()
                && valid_finish_plan_state(plan, handoff.status, handoff.unknowns.is_empty()) => {}
        _ => return Err(RepositoryImplementationRejectionV1::ActionPlanStateInvalid),
    }
    let bytes = serde_json::to_vec(plan)
        .map_err(|_| RepositoryImplementationRejectionV1::PlanStructureInvalid)?;
    Ok(ChildLocalPlanBindingV1 {
        plan_id: plan.plan_id,
        revision: plan.revision,
        plan_digest: Sha256Digest::of_bytes(&bytes),
    })
}

#[derive(Debug)]
struct FinishEvidence {
    observed_event_ids: BTreeSet<EventId>,
    artifact_sha256: BTreeSet<String>,
}

fn validate_finish_evidence(
    handoff: &ChildHandoffContentV1,
    read: Option<&ModelReadObservationV1>,
    write: Option<&ModelWriteObservationV1>,
) -> Result<FinishEvidence, RepositoryImplementationRejectionV1> {
    if !bounded_text(&handoff.summary)
        || handoff.findings.len() > CHILD_RECONNAISSANCE_MAX_FINDINGS
        || handoff.unknowns.len() > CHILD_RECONNAISSANCE_MAX_UNRESOLVED_QUESTIONS
        || handoff.recommended_followups.len() > CHILD_RECONNAISSANCE_MAX_RECOMMENDED_FOLLOWUPS
        || (handoff.status == ChildHandoffStatus::Complete
            && (handoff.findings.is_empty() || write.is_none()))
    {
        return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
    }
    let mut known = BTreeMap::new();
    if let Some(read) = read {
        known.insert(
            (read.tool_call_id, read.observed_event_id),
            read.result_artifact.clone(),
        );
    }
    if let Some(write) = write {
        known.insert(
            (write.tool_call_id, write.diff_event_id),
            write.diff_artifact.clone(),
        );
    }
    let required_write = write.map(|write| {
        (
            write.tool_call_id,
            write.diff_event_id,
            write.diff_artifact.clone(),
        )
    });
    let mut cited_write = false;
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
            return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
        }
        evidence_count = evidence_count.saturating_add(finding.evidence.len());
        if evidence_count > CHILD_RECONNAISSANCE_MAX_EVIDENCE_BINDINGS {
            return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
        }
        let mut identities = BTreeSet::new();
        for evidence in &finding.evidence {
            let Some(expected) = known.get(&(evidence.tool_call_id, evidence.observed_event_id))
            else {
                return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
            };
            if expected != &evidence.result_artifact
                || !identities.insert((
                    evidence.tool_call_id,
                    evidence.observed_event_id,
                    evidence.result_artifact.sha256.clone(),
                ))
            {
                return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
            }
            if required_write.as_ref().is_some_and(|required| {
                required.0 == evidence.tool_call_id
                    && required.1 == evidence.observed_event_id
                    && required.2 == evidence.result_artifact
            }) {
                cited_write = true;
            }
            observed_event_ids.insert(evidence.observed_event_id);
            artifact_sha256.insert(evidence.result_artifact.sha256.clone());
        }
    }
    if required_write.is_some() && !cited_write {
        return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
    }
    let mut unknown_ids = BTreeSet::new();
    if handoff.unknowns.iter().any(|unknown| {
        !bounded_identifier(&unknown.unknown_id)
            || !bounded_text(&unknown.question)
            || !unknown_ids.insert(unknown.unknown_id.as_str())
    }) {
        return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
    }
    let mut followup_ids = BTreeSet::new();
    if handoff.recommended_followups.iter().any(|followup| {
        !bounded_identifier(&followup.followup_id)
            || !bounded_text(&followup.text)
            || !followup_ids.insert(followup.followup_id.as_str())
    }) {
        return Err(RepositoryImplementationRejectionV1::FinishEvidenceInvalid);
    }
    Ok(FinishEvidence {
        observed_event_ids,
        artifact_sha256,
    })
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the Unix and non-Unix implementations intentionally share one fail-closed signature"
)]
fn native_path(path: &std::path::Path) -> Result<WorkspacePath, &'static str> {
    use std::os::unix::ffi::OsStrExt as _;
    Ok(WorkspacePath::from_unix_bytes(
        path.as_os_str().as_bytes().to_vec(),
    ))
}

#[cfg(not(unix))]
fn native_path(_path: &std::path::Path) -> Result<WorkspacePath, &'static str> {
    Err("git_clean_committed_head_v1 is currently available only on Unix")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::repository_candidate::{
        InMemoryRepositoryCandidateStore, RepositoryCandidateReader,
    };
    use crate::worktree_write_lane::{
        InMemoryWorktreeWriteLaneJournal, WorktreeReleaseObservationV1,
        WorktreeWriteLaneJournalRecordV1,
    };
    use birdcode_backends::{
        BackendDeploymentId, BackendEndpointOrigin, BackendFuture, BackendId,
        BackendInstanceIdentity, BackendTransportIdentity, InferenceEvidence, LmStudioBackend,
        LmStudioConfig, MessageRole, ModelCatalog, TokenUsage,
    };
    use birdcode_orchestrator::{
        ActorGraph, ActorGraphExecutor, ActorGraphLimits, ActorGraphOutcome, ActorGraphPolicy,
        AgentAssignment, AgentAttemptId, AgentBudget, CapabilityId, ExecutionId, GraphActorId,
        InMemorySchedulerJournal, ModelProfileId, PermissionGrant, RoleId, SchedulerEvent,
        WorkspaceGrant, WorkspaceLeaseId, WorkspaceLeasePolicy,
    };
    use birdcode_protocol::{
        ChildFindingConfidence, ChildHandoffEvidenceBinding, ChildHandoffFinding,
        ChildLocalPlanStepV1,
    };
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    const PREIMAGE: &str = "product=BirdCode\nnonce=SKY-8427\nstate=grounded\n";
    const POSTIMAGE: &str = "product=BirdCode\nnonce=SKY-8427\nstate=flying\n";
    const MODEL_NAME: &str = "scripted/repository-implementation";
    const DEPLOYMENT: &str = "repository-implementation-test";
    const ENDPOINT: &str = "http://127.0.0.1:19121";

    fn backend_id() -> BackendId {
        BackendId::new("scripted-implementation").expect("backend id")
    }

    fn model_id() -> ModelId {
        ModelId::new(MODEL_NAME).expect("model id")
    }

    fn backend_instance() -> BackendInstanceIdentity {
        BackendInstanceIdentity::new(
            backend_id(),
            BackendTransportIdentity::HttpOrigin {
                origin: BackendEndpointOrigin::parse(ENDPOINT).expect("endpoint"),
            },
            BackendDeploymentId::new(DEPLOYMENT).expect("deployment"),
        )
        .expect("backend instance")
    }

    #[derive(Clone, Copy)]
    enum ScriptedScenario {
        HappyPath,
        NoOpThenRepair,
    }

    struct ScriptedImplementationBackend {
        id: BackendId,
        instance: BackendInstanceIdentity,
        calls: AtomicUsize,
        scenario: ScriptedScenario,
    }

    impl ScriptedImplementationBackend {
        fn new() -> Self {
            Self {
                id: backend_id(),
                instance: backend_instance(),
                calls: AtomicUsize::new(0),
                scenario: ScriptedScenario::HappyPath,
            }
        }

        fn no_op_then_repair() -> Self {
            Self {
                id: backend_id(),
                instance: backend_instance(),
                calls: AtomicUsize::new(0),
                scenario: ScriptedScenario::NoOpThenRepair,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ModelBackend for ScriptedImplementationBackend {
        fn backend_id(&self) -> &BackendId {
            &self.id
        }

        fn instance_identity(&self) -> &BackendInstanceIdentity {
            &self.instance
        }

        fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
            Box::pin(async { panic!("implementation worker must not discover models") })
        }

        fn infer_structured(
            &self,
            request: StructuredInferenceRequest,
        ) -> BackendFuture<'_, StructuredInferenceResponse> {
            let ordinal = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            assert_eq!(request.messages().len(), 2);
            assert_eq!(request.messages()[0].role, MessageRole::System);
            assert_eq!(
                request.messages()[0].content,
                repository_implementation_prompt::REPOSITORY_IMPLEMENTATION_AGENT_V1_SYSTEM_PROMPT
            );
            assert_eq!(request.messages()[1].role, MessageRole::User);
            assert_eq!(
                request.output().name(),
                "repository_implementation_agent_v1"
            );
            assert_eq!(
                request.output().validation_schema(),
                &repository_implementation_prompt::validation_schema()
            );
            let turn = serde_json::from_str::<RepositoryImplementationTurnInputV1>(
                &request.messages()[1].content,
            )
            .expect("typed turn");
            let generation_phase = if turn.write_observation.is_some() {
                repository_implementation_prompt::RepositoryImplementationGenerationPhaseV1::Finish
            } else if turn.read_observation.is_some() {
                repository_implementation_prompt::RepositoryImplementationGenerationPhaseV1::Replace
            } else {
                repository_implementation_prompt::RepositoryImplementationGenerationPhaseV1::Read
            };
            assert_eq!(
                request.output().generation_schema(),
                &repository_implementation_prompt::generation_schema_for_phase(
                    generation_phase,
                    turn.required_finish_evidence.as_ref(),
                )
            );
            assert!(turn.dependency_handoffs.is_empty());
            match (&turn.read_observation, &turn.write_observation) {
                (None, None) => {
                    assert_eq!(turn.available_tool_grants.len(), 1);
                    assert!(turn.available_write_grants.is_empty());
                    assert!(turn.required_finish_evidence.is_none());
                }
                (Some(_), None) => {
                    assert!(turn.available_tool_grants.is_empty());
                    assert_eq!(turn.available_write_grants.len(), 1);
                    assert!(turn.required_finish_evidence.is_none());
                }
                (_, Some(write)) => {
                    assert!(turn.available_tool_grants.is_empty());
                    assert!(turn.available_write_grants.is_empty());
                    assert_eq!(
                        turn.required_finish_evidence,
                        Some(ChildHandoffEvidenceBinding {
                            tool_call_id: write.tool_call_id,
                            observed_event_id: write.diff_event_id,
                            result_artifact: write.diff_artifact.clone(),
                        })
                    );
                }
            }
            let final_ordinal = match self.scenario {
                ScriptedScenario::HappyPath => 3,
                ScriptedScenario::NoOpThenRepair => 4,
            };
            if ordinal == final_ordinal {
                let write = turn.write_observation.as_ref().expect("write observation");
                assert_eq!(
                    write.postimage_sha256,
                    Sha256Digest::of_bytes(POSTIMAGE.as_bytes())
                );
            }
            let modeled = match self.scenario {
                ScriptedScenario::HappyPath => scripted_response(ordinal, &turn),
                ScriptedScenario::NoOpThenRepair => no_op_repair_response(ordinal, &turn),
            };
            let value = serde_json::to_value(modeled).expect("response encodes");
            let validator = jsonschema::draft202012::options()
                .build(request.output().validation_schema())
                .expect("implementation validation schema compiles");
            assert!(validator.is_valid(&value), "scripted response: {value}");
            let generation_validator = jsonschema::draft202012::options()
                .build(request.output().generation_schema())
                .expect("implementation generation schema compiles");
            assert!(
                generation_validator.is_valid(&value),
                "scripted response violates its phase schema: {value}"
            );
            let response = StructuredInferenceResponse {
                model_id: model_id(),
                raw_text: serde_json::to_string(&value).expect("raw response"),
                value,
                finish_reason: Some("stop".to_owned()),
                usage: Some(TokenUsage {
                    input_tokens: Some(100),
                    output_tokens: Some(64),
                    total_tokens: Some(164),
                }),
                evidence: InferenceEvidence {
                    backend_id: backend_id(),
                    backend_instance: Some(backend_instance()),
                    endpoint: format!("{ENDPOINT}/v1/chat/completions"),
                    status: 200,
                    completion_id: Some(format!("implementation-{ordinal}")),
                    response_body_sha256: Some(format!("{ordinal:064x}")),
                    raw_response: json!({"ordinal": ordinal}),
                },
            };
            Box::pin(async move { Ok(response) })
        }
    }

    fn plan_for(
        turn: &RepositoryImplementationTurnInputV1,
        status: ChildLocalPlanStepStatusV1,
    ) -> ChildLocalPlanSnapshotV1 {
        let step_id = ChildLocalPlanStepIdV1("implement-flight-state".to_owned());
        ChildLocalPlanSnapshotV1 {
            contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
            binding: turn.binding.clone(),
            plan_id: turn.required_plan_identity.plan_id,
            revision: turn.required_plan_identity.revision,
            previous_plan_digest: turn.required_plan_identity.previous_plan_digest.clone(),
            objective: turn.objective.clone(),
            steps: vec![ChildLocalPlanStepV1 {
                step_id: step_id.clone(),
                objective: "Read and update the exact flight-state file".to_owned(),
                status,
            }],
            active_step_id: (status == ChildLocalPlanStepStatusV1::InProgress).then_some(step_id),
            assumptions: Vec::new(),
            unknowns: Vec::new(),
        }
    }

    fn scripted_response(
        ordinal: usize,
        turn: &RepositoryImplementationTurnInputV1,
    ) -> RepositoryImplementationModelResponseV1 {
        match ordinal {
            1 => {
                assert!(turn.prior_plan.is_none());
                assert!(turn.read_observation.is_none());
                let RepositoryToolGrantV1::RepositoryFileRead {
                    tool_grant_id,
                    max_bytes,
                    ..
                } = &turn.available_tool_grants[0]
                else {
                    panic!("read grant")
                };
                RepositoryImplementationModelResponseV1 {
                    contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
                    plan: plan_for(turn, ChildLocalPlanStepStatusV1::InProgress),
                    action: RepositoryImplementationActionV1::RepositoryFileRead {
                        tool_grant_id: *tool_grant_id,
                        path: turn
                            .required_read_target
                            .clone()
                            .expect("runtime-supplied exact read target"),
                        offset_bytes: 0,
                        max_bytes: *max_bytes,
                    },
                }
            }
            2 => {
                let read = turn.read_observation.as_ref().expect("read observation");
                assert_eq!(read.content_utf8, PREIMAGE);
                assert_eq!(
                    read.content_sha256,
                    Sha256Digest::of_bytes(PREIMAGE.as_bytes())
                );
                replacement_response(turn, POSTIMAGE)
            }
            3 => finish_response(turn),
            _ => panic!("unexpected model call"),
        }
    }

    fn replacement_response(
        turn: &RepositoryImplementationTurnInputV1,
        content_utf8: &str,
    ) -> RepositoryImplementationModelResponseV1 {
        let grant = &turn.available_write_grants[0];
        RepositoryImplementationModelResponseV1 {
            contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
            plan: plan_for(turn, ChildLocalPlanStepStatusV1::InProgress),
            action: RepositoryImplementationActionV1::ReplaceUtf8File {
                grant_id: grant.grant_id,
                path: grant.path.clone(),
                expected_preimage_sha256: grant.expected_preimage_sha256.clone(),
                content_utf8: content_utf8.to_owned(),
            },
        }
    }

    fn finish_response(
        turn: &RepositoryImplementationTurnInputV1,
    ) -> RepositoryImplementationModelResponseV1 {
        let required_finish_evidence = turn
            .required_finish_evidence
            .clone()
            .expect("required finish evidence");
        RepositoryImplementationModelResponseV1 {
            contract_version: REPOSITORY_IMPLEMENTATION_AGENT_V1_CONTRACT_VERSION,
            plan: plan_for(turn, ChildLocalPlanStepStatusV1::Completed),
            action: RepositoryImplementationActionV1::Finish {
                handoff: ChildHandoffContentV1 {
                    status: ChildHandoffStatus::Complete,
                    summary: "The exact flight state was updated and diff-observed".to_owned(),
                    findings: vec![ChildHandoffFinding {
                        finding_id: "flight-state-updated".to_owned(),
                        statement: "The retained diff changes grounded to flying".to_owned(),
                        confidence: ChildFindingConfidence::High,
                        evidence: vec![required_finish_evidence],
                    }],
                    unknowns: Vec::new(),
                    recommended_followups: Vec::new(),
                },
            },
        }
    }

    fn no_op_repair_response(
        ordinal: usize,
        turn: &RepositoryImplementationTurnInputV1,
    ) -> RepositoryImplementationModelResponseV1 {
        match ordinal {
            1 => scripted_response(1, turn),
            2 => replacement_response(turn, PREIMAGE),
            3 => {
                assert_eq!(
                    turn.previous_rejection,
                    Some(RepositoryImplementationRejectionV1::WriteWouldBeNoOp)
                );
                replacement_response(turn, POSTIMAGE)
            }
            4 => finish_response(turn),
            _ => panic!("unexpected repair model call"),
        }
    }

    fn run_git(repository: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(repository)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git utf8")
            .trim()
            .to_owned()
    }

    fn baseline_digest(repository: &Path) -> Sha256Digest {
        let commit = run_git(repository, &["rev-parse", "HEAD"]);
        let mut bytes = b"birdcode.git-baseline.v1\0".to_vec();
        bytes.extend_from_slice(commit.as_bytes());
        Sha256Digest::of_bytes(&bytes)
    }

    fn fixture() -> (TempDir, TempDir) {
        let repository = tempfile::tempdir().expect("repository");
        let scratch = tempfile::tempdir().expect("scratch");
        run_git(repository.path(), &["init", "-q"]);
        run_git(
            repository.path(),
            &["config", "user.email", "birdcode@example.invalid"],
        );
        run_git(
            repository.path(),
            &["config", "user.name", "BirdCode Tests"],
        );
        fs::write(repository.path().join("flight.txt"), PREIMAGE).expect("fixture file");
        run_git(repository.path(), &["add", "flight.txt"]);
        run_git(repository.path(), &["commit", "-qm", "fixture"]);
        (repository, scratch)
    }

    fn permission() -> PermissionGrant {
        PermissionGrant {
            capabilities: [CapabilityId::new("repository-implementation-v1").expect("capability")]
                .into_iter()
                .collect(),
        }
    }

    fn work_order(baseline: &Sha256Digest) -> WorkOrder {
        WorkOrder {
            id: WorkOrderId::new(),
            objective: "Ändra den tilldelade resursens state från grounded till flying och bevara nonce SKY-8427".to_owned(),
            acceptance_criteria: vec![
                "Den tilldelade resursen innehåller state=flying".to_owned(),
                "nonce SKY-8427 is unchanged".to_owned(),
            ],
            dependencies: BTreeSet::new(),
            candidate_group: None,
            priority: 0,
            context_manifest_sha256: Sha256Digest::of_bytes(b"context").as_str().to_owned(),
            assignment: AgentAssignment {
                role_id: RoleId::new("implementation-agent").expect("role"),
                model_profile_id: ModelProfileId::new("scripted-model").expect("profile"),
                lineage: ModelLineage {
                    backend_id: backend_id().as_str().to_owned(),
                    model_id: MODEL_NAME.to_owned(),
                    deployment_id: DEPLOYMENT.to_owned(),
                    independence_domain_id: "test-producer".to_owned(),
                },
            },
            permissions: permission(),
            workspace: WorkspaceGrant {
                lease_id: WorkspaceLeaseId::new("git-clean-head-test").expect("lease"),
                source: WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
                    git_baseline_sha256: baseline.as_str().to_owned(),
                },
                access: WorkspaceAccess::Write,
            },
            budget: AgentBudget {
                max_output_tokens: 6 * 4_096,
                max_tool_calls: 2,
                max_wall_time_ms: 60_000,
                max_cleanup_time_ms: 10_000,
                max_attempts: 1,
            },
            reviews: BTreeSet::new(),
        }
    }

    fn validated_graph(order: WorkOrder) -> ValidatedActorGraph {
        let plan_input_snapshot_sha256 = Sha256Digest::of_bytes(b"implementation-plan-input")
            .as_str()
            .to_owned();
        assert_ne!(
            order.workspace.source.digest_sha256(),
            plan_input_snapshot_sha256
        );
        let graph = ActorGraph {
            schema_version: 2,
            plan_input_snapshot_sha256: plan_input_snapshot_sha256.clone(),
            work_orders: vec![order.clone()],
        };
        let policy = ActorGraphPolicy {
            policy_version: "repository-implementation-test/2".to_owned(),
            plan_input_snapshot_sha256,
            root_permissions: permission(),
            limits: ActorGraphLimits {
                max_work_orders: 1,
                max_parallel: 1,
                max_total_attempts: 1,
                max_total_output_tokens: order.budget.max_output_tokens,
                max_total_tool_calls: order.budget.max_tool_calls,
                max_total_wall_time_ms: order
                    .budget
                    .max_wall_time_ms
                    .checked_add(order.budget.max_cleanup_time_ms)
                    .expect("test wall-time budget"),
            },
            require_reported_token_usage: true,
            workspace_leases: [(
                order.workspace.lease_id.clone(),
                WorkspaceLeasePolicy {
                    source: order.workspace.source.clone(),
                    access: order.workspace.access,
                },
            )]
            .into_iter()
            .collect(),
            model_profiles: [(
                order.assignment.model_profile_id.clone(),
                order.assignment.lineage.clone(),
            )]
            .into_iter()
            .collect(),
        };
        graph.validate_against(&policy).expect("validated graph")
    }

    fn authority_and_dispatch(
        repository: &Path,
        scratch: &Path,
    ) -> (RepositoryImplementationDispatchAuthority, AgentDispatch) {
        authority_and_dispatch_with_read_max(repository, scratch, 4_096)
    }

    fn authority_and_dispatch_with_read_max(
        repository: &Path,
        scratch: &Path,
        read_max_bytes: u64,
    ) -> (RepositoryImplementationDispatchAuthority, AgentDispatch) {
        let (graph, authority) =
            graph_and_authority_with_read_max(repository, scratch, read_max_bytes);
        let order = graph.graph().work_orders[0].clone();
        let dispatch = AgentDispatch {
            actor_id: GraphActorId::new(),
            execution_id: ExecutionId::new(),
            attempt_id: AgentAttemptId::new(),
            parent_attempt_id: None,
            graph_accepted_event_id: birdcode_orchestrator::SchedulerEventId::new(),
            graph_sha256: graph.digest_sha256().to_owned(),
            attestation: authority.attestation().clone(),
            work_order: Arc::new(order),
            dependency_handoffs: BTreeMap::new(),
            dependency_handoff_event_ids: BTreeMap::new(),
        };
        (authority, dispatch)
    }

    fn graph_and_authority_with_read_max(
        repository: &Path,
        scratch: &Path,
        read_max_bytes: u64,
    ) -> (
        ValidatedActorGraph,
        RepositoryImplementationDispatchAuthority,
    ) {
        let graph = validated_graph(work_order(&baseline_digest(repository)));
        let order = graph.graph().work_orders[0].clone();
        let authority = RepositoryImplementationDispatchAuthority::bind(
            &graph,
            order.id,
            repository.to_path_buf(),
            scratch.to_path_buf(),
            RepositoryToolGrantV1::RepositoryFileRead {
                tool_grant_id: RepositoryToolGrantId::new(),
                max_path_components: 8,
                max_path_bytes: 1_024,
                max_component_bytes: 255,
                max_offset_bytes: 0,
                max_bytes: read_max_bytes,
            },
            StagedExactReplaceUtf8FileGrantV1 {
                grant_id: RepositoryToolGrantId::new(),
                path: RepositoryRelativePathV1::Unix {
                    components: vec![b"flight.txt".to_vec()],
                },
                expected_preimage_sha256: Sha256Digest::of_bytes(PREIMAGE.as_bytes()),
                max_content_bytes: 4_096,
            },
        )
        .expect("authority");
        (graph, authority)
    }

    #[derive(Debug, Default)]
    struct FailOnFinishJournal {
        retained: InMemoryRepositoryImplementationJournal,
    }

    impl RepositoryImplementationJournal for FailOnFinishJournal {
        fn retain(
            &self,
            entry: RepositoryImplementationJournalEntryV1,
        ) -> Result<EventId, RepositoryImplementationJournalError> {
            if matches!(
                &entry.record,
                RepositoryImplementationJournalRecordV1::FinishAccepted { .. }
            ) {
                return Err(RepositoryImplementationJournalError(
                    "injected Finish retention failure".to_owned(),
                ));
            }
            self.retained.retain(entry)
        }
    }

    #[derive(Debug, Default)]
    struct RejectingCandidateStore;

    impl RepositoryCandidateStore for RejectingCandidateStore {
        fn publish(
            &self,
            _bundle: RepositoryCandidateBundleV1,
        ) -> Result<
            crate::repository_candidate::RepositoryCandidatePublicationV1,
            crate::repository_candidate::RepositoryCandidateStoreError,
        > {
            Err(crate::repository_candidate::RepositoryCandidateStoreError::Unavailable)
        }

        fn mark_cleanup_observed(
            &self,
            _publication: &crate::repository_candidate::RepositoryCandidatePublicationV1,
            _release: &WorktreeReleaseObservationV1,
        ) -> Result<
            crate::repository_candidate::RepositoryCandidateReadyV1,
            crate::repository_candidate::RepositoryCandidateStoreError,
        > {
            Err(crate::repository_candidate::RepositoryCandidateStoreError::Unavailable)
        }
    }

    impl RepositoryCandidateReader for RejectingCandidateStore {
        fn resolve_ready(
            &self,
            _producer: &RepositoryCandidateProducerLocatorV1,
        ) -> Result<
            Option<crate::repository_candidate::RetainedRepositoryCandidateV1>,
            crate::repository_candidate::RepositoryCandidateStoreError,
        > {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn implementation_worker_reads_replaces_finishes_and_releases() {
        let (repository, scratch) = fixture();
        let source_head = run_git(repository.path(), &["rev-parse", "HEAD"]);
        let source_index = run_git(repository.path(), &["write-tree"]);
        let source_status = run_git(
            repository.path(),
            &[
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignored=matching",
            ],
        );
        let source_worktrees = run_git(
            repository.path(),
            &["worktree", "list", "--porcelain", "-z"],
        );
        let (graph, authority) =
            graph_and_authority_with_read_max(repository.path(), scratch.path(), 4_096);
        let work_order_id = graph.graph().work_orders[0].id;
        let backend = Arc::new(ScriptedImplementationBackend::new());
        let journal = Arc::new(InMemoryRepositoryImplementationJournal::default());
        let write_journal = Arc::new(InMemoryWorktreeWriteLaneJournal::default());
        let candidate_store = Arc::new(InMemoryRepositoryCandidateStore::default());
        let scheduler_journal = Arc::new(InMemorySchedulerJournal::default());
        let worker = RepositoryImplementationAgentWorker::new(
            backend.clone(),
            vec![authority],
            journal.clone(),
            write_journal.clone(),
            candidate_store.clone(),
            RepositoryImplementationPolicy::default(),
        )
        .expect("worker");

        let run = ActorGraphExecutor::new(&worker, scheduler_journal.as_ref())
            .execute(&graph)
            .await
            .expect("scheduler completion");
        assert_eq!(run.outcome, ActorGraphOutcome::Completed);
        assert!(run.failures.is_empty());
        assert_eq!(run.maximum_in_flight, 1);
        let completion = run
            .handoffs
            .get(&work_order_id)
            .expect("implementation handoff");

        assert_eq!(completion.outcome, HandoffOutcome::Completed);
        assert_eq!(backend.call_count(), 3);
        assert!(
            completion
                .execution_receipt_id
                .starts_with("repository-candidate-ready:")
        );
        assert_eq!(
            fs::read_to_string(repository.path().join("flight.txt")).unwrap(),
            PREIMAGE
        );
        assert_eq!(
            run_git(repository.path(), &["rev-parse", "HEAD"]),
            source_head
        );
        assert_eq!(run_git(repository.path(), &["write-tree"]), source_index);
        assert_eq!(
            run_git(
                repository.path(),
                &[
                    "status",
                    "--porcelain=v2",
                    "-z",
                    "--untracked-files=all",
                    "--ignored=matching",
                ],
            ),
            source_status
        );
        assert_eq!(
            run_git(
                repository.path(),
                &["worktree", "list", "--porcelain", "-z"],
            ),
            source_worktrees
        );
        let scheduler_entries = scheduler_journal.snapshot().expect("scheduler journal");
        assert_eq!(scheduler_entries.len(), 4);
        assert!(matches!(
            scheduler_entries[0].event,
            SchedulerEvent::GraphAccepted { .. }
        ));
        let SchedulerEvent::AttemptDispatched { attestation, .. } = &scheduler_entries[1].event
        else {
            panic!("second scheduler event must dispatch the implementation worker")
        };
        assert_eq!(attestation.graph_sha256, graph.digest_sha256());
        assert_eq!(
            attestation.workspace,
            graph.graph().work_orders[0].workspace
        );
        assert!(matches!(
            attestation.workspace.source,
            WorkspaceSourceBinding::GitCleanCommittedHeadV1 { .. }
        ));
        assert!(matches!(
            scheduler_entries[2].event,
            SchedulerEvent::HandoffRetained { .. }
        ));
        assert!(matches!(
            scheduler_entries[3].event,
            SchedulerEvent::GraphFinished {
                outcome: ActorGraphOutcome::Completed,
                ..
            }
        ));
        for index in 1..scheduler_entries.len() {
            assert_eq!(
                scheduler_entries[index].causal_parent,
                Some(scheduler_entries[index - 1].id)
            );
        }
        let entries = journal.snapshot().expect("journal");
        assert_eq!(
            entries
                .iter()
                .filter(|entry| matches!(
                    entry.entry.record,
                    RepositoryImplementationJournalRecordV1::ReadObserved { .. }
                ))
                .count(),
            1
        );
        let finish_entry = entries
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    RepositoryImplementationJournalRecordV1::FinishAccepted { .. }
                )
            })
            .expect("FinishAccepted");
        let write_model_event_id = entries
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    RepositoryImplementationJournalRecordV1::ModelObserved { ordinal: 2, .. }
                )
            })
            .expect("write model observation")
            .event_id;
        let write_entries = write_journal.snapshot().expect("write journal");
        let prepared = write_entries
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    WorktreeWriteLaneJournalRecordV1::FileReplacePrepared { .. }
                )
            })
            .expect("replace prepared");
        let WorktreeWriteLaneJournalRecordV1::FileReplacePrepared { origin, .. } =
            &prepared.entry.record
        else {
            unreachable!()
        };
        assert_eq!(origin.source_model_observed_event_id, write_model_event_id);
        let validated_write = entries
            .iter()
            .find(|entry| entry.event_id == origin.validated_action_event_id)
            .expect("write ActionValidated");
        let RepositoryImplementationJournalRecordV1::ActionValidated { action_binding, .. } =
            &validated_write.entry.record
        else {
            panic!("write origin must bind ActionValidated")
        };
        assert_eq!(
            action_binding.validated_action_artifact,
            origin.action_artifact
        );
        let diff_entry = write_entries
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    WorktreeWriteLaneJournalRecordV1::GitDiffObserved { .. }
                )
            })
            .expect("GitDiffObserved");
        let WorktreeWriteLaneJournalRecordV1::GitDiffObserved {
            changed_paths,
            diff_artifact,
            ..
        } = &diff_entry.entry.record
        else {
            unreachable!()
        };
        assert_eq!(
            changed_paths,
            &[RepositoryRelativePathV1::Unix {
                components: vec![b"flight.txt".to_vec()]
            }]
        );
        assert_eq!(diff_entry.entry.artifacts.len(), 1);
        assert_eq!(diff_entry.entry.artifacts[0].artifact, *diff_artifact);
        let diff_text = String::from_utf8(diff_entry.entry.artifacts[0].bytes.clone())
            .expect("Git diff is UTF-8 for this fixture");
        assert!(diff_text.contains("-state=grounded"));
        assert!(diff_text.contains("+state=flying"));
        let producer_locator = RepositoryCandidateProducerLocatorV1 {
            graph_sha256: Sha256Digest::parse(graph.digest_sha256().to_owned()).expect("graph"),
            work_order_id,
            actor_id: completion.actor_id,
            execution_id: completion.execution_id,
            attempt_id: completion.attempt_id,
        };
        let retained_candidate = candidate_store
            .resolve_ready(&producer_locator)
            .expect("candidate store")
            .expect("cleanup-complete candidate");
        retained_candidate
            .bundle
            .validate()
            .expect("candidate remains exact");
        assert_eq!(
            retained_candidate
                .bundle
                .manifest
                .body
                .producer_work_order_id,
            work_order_id
        );
        assert_eq!(
            retained_candidate.bundle.manifest.body.finish_event_id,
            finish_entry.event_id
        );
        assert_eq!(
            retained_candidate.bundle.manifest.body.change.diff_event_id,
            diff_entry.event_id
        );
        assert_eq!(
            retained_candidate.bundle.preimage_artifact.bytes,
            PREIMAGE.as_bytes()
        );
        assert_eq!(
            retained_candidate.bundle.postimage_artifact.bytes,
            POSTIMAGE.as_bytes()
        );
        assert_eq!(
            retained_candidate.bundle.diff_artifact.bytes,
            diff_entry.entry.artifacts[0].bytes
        );
        assert!(
            completion
                .artifact_sha256
                .contains(&retained_candidate.bundle.manifest_artifact.artifact.sha256)
        );
        assert!(
            completion.artifact_sha256.contains(
                &retained_candidate
                    .publication
                    .receipt_artifact()
                    .artifact
                    .sha256
            )
        );
        assert!(
            completion.artifact_sha256.contains(
                &retained_candidate
                    .cleanup
                    .receipt_artifact()
                    .artifact
                    .sha256
            )
        );
        assert!(
            completion
                .artifact_sha256
                .contains(&retained_candidate.ready.receipt_artifact().artifact.sha256)
        );
        assert!(
            completion.evidence_ids.contains(
                &retained_candidate
                    .publication
                    .published_event_id()
                    .to_string()
            )
        );
        let mut substituted = retained_candidate.bundle.clone();
        substituted.postimage_artifact.bytes.push(b'!');
        let substitution_store = InMemoryRepositoryCandidateStore::default();
        assert!(matches!(
            substitution_store.publish(substituted),
            Err(crate::repository_candidate::RepositoryCandidateStoreError::InvalidCandidate(_))
        ));
        assert_eq!(
            candidate_store
                .publish(retained_candidate.bundle.clone())
                .expect("exact publication replay"),
            retained_candidate.publication
        );
        let cleanup_prepared = write_entries
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared { .. }
                )
            })
            .expect("cleanup prepared");
        let WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared {
            publication,
            publication_receipt_artifact,
            diff_event_id,
            ..
        } = &cleanup_prepared.entry.record
        else {
            unreachable!()
        };
        assert_eq!(
            publication.published_event_id,
            retained_candidate.publication.published_event_id()
        );
        assert_eq!(
            publication_receipt_artifact,
            &retained_candidate.publication.receipt_artifact().artifact
        );
        assert_eq!(*diff_event_id, diff_entry.event_id);
        let cleanup_observed = write_entries
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved { .. }
                )
            })
            .expect("cleanup observed");
        assert_eq!(
            completion.execution_receipt_id,
            format!(
                "repository-candidate-ready:{}",
                retained_candidate.ready.ready_event_id()
            )
        );
        assert_eq!(
            retained_candidate.ready.cleanup_observed_event_id(),
            cleanup_observed.event_id
        );
        assert!(
            completion
                .evidence_ids
                .contains(&finish_entry.event_id.to_string())
        );
        assert!(
            completion
                .evidence_ids
                .contains(&diff_entry.event_id.to_string())
        );
        assert!(
            completion
                .evidence_ids
                .contains(&cleanup_observed.event_id.to_string())
        );
        assert!(
            fs::read_dir(scratch.path())
                .expect("scratch entries")
                .all(|entry| !entry
                    .expect("scratch entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("birdcode-worktree-"))
        );
    }

    #[tokio::test]
    async fn candidate_publication_failure_preserves_worktree_and_never_starts_cleanup() {
        let (repository, scratch) = fixture();
        let (authority, dispatch) = authority_and_dispatch(repository.path(), scratch.path());
        let backend = Arc::new(ScriptedImplementationBackend::new());
        let journal = Arc::new(InMemoryRepositoryImplementationJournal::default());
        let write_journal = Arc::new(InMemoryWorktreeWriteLaneJournal::default());
        let worker = RepositoryImplementationAgentWorker::new(
            backend,
            vec![authority],
            journal,
            write_journal.clone(),
            Arc::new(RejectingCandidateStore),
            RepositoryImplementationPolicy::default(),
        )
        .expect("worker");

        let failure = worker
            .run_attempt(dispatch)
            .await
            .expect_err("publication must fail closed");

        assert_eq!(failure.kind, AgentFailureKind::PermanentBackend);
        assert!(
            failure
                .message
                .contains("repository candidate publication failed")
        );
        assert!(failure.effect_receipt_id.is_some());
        assert_eq!(
            fs::read_to_string(repository.path().join("flight.txt")).expect("source preimage"),
            PREIMAGE
        );
        let write_entries = write_journal.snapshot().expect("write journal");
        assert!(write_entries.iter().any(|entry| matches!(
            entry.entry.record,
            WorktreeWriteLaneJournalRecordV1::GitDiffObserved { .. }
        )));
        assert!(!write_entries.iter().any(|entry| matches!(
            entry.entry.record,
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared { .. }
                | WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved { .. }
        )));
        assert!(
            fs::read_dir(scratch.path())
                .expect("scratch entries")
                .any(|entry| entry
                    .expect("scratch entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("birdcode-worktree-"))
        );
    }

    #[tokio::test]
    async fn no_op_write_is_rejected_before_effect_and_model_repairs() {
        let (repository, scratch) = fixture();
        let (authority, dispatch) = authority_and_dispatch(repository.path(), scratch.path());
        let backend = Arc::new(ScriptedImplementationBackend::no_op_then_repair());
        let journal = Arc::new(InMemoryRepositoryImplementationJournal::default());
        let write_journal = Arc::new(InMemoryWorktreeWriteLaneJournal::default());
        let worker = RepositoryImplementationAgentWorker::new(
            backend.clone(),
            vec![authority],
            journal.clone(),
            write_journal.clone(),
            Arc::new(InMemoryRepositoryCandidateStore::default()),
            RepositoryImplementationPolicy::default(),
        )
        .expect("worker");

        let completion = worker
            .run_attempt(dispatch)
            .await
            .expect("repaired completion");

        assert_eq!(completion.outcome, HandoffOutcome::Completed);
        assert_eq!(backend.call_count(), 4);
        let entries = journal.snapshot().expect("journal");
        assert_eq!(
            entries
                .iter()
                .filter(|entry| matches!(
                    entry.entry.record,
                    RepositoryImplementationJournalRecordV1::ActionRejected {
                        rejection: RepositoryImplementationRejectionV1::WriteWouldBeNoOp,
                        ..
                    }
                ))
                .count(),
            1
        );
        let write_entries = write_journal.snapshot().expect("write journal");
        let prepared_origins = write_entries
            .iter()
            .filter_map(|entry| match &entry.entry.record {
                WorktreeWriteLaneJournalRecordV1::FileReplacePrepared { origin, .. } => {
                    Some(origin)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(prepared_origins.len(), 1);
        assert_eq!(prepared_origins[0].source_model_call_ordinal, 3);
        assert_eq!(
            write_entries
                .iter()
                .filter(|entry| matches!(
                    entry.entry.record,
                    WorktreeWriteLaneJournalRecordV1::GitDiffObserved { .. }
                ))
                .count(),
            1
        );
        assert!(write_entries.iter().any(|entry| matches!(
            entry.entry.record,
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved { .. }
        )));
        assert_eq!(
            fs::read_to_string(repository.path().join("flight.txt")).unwrap(),
            PREIMAGE
        );
    }

    #[tokio::test]
    async fn file_larger_than_read_grant_never_reaches_model() {
        let (repository, scratch) = fixture();
        let (authority, dispatch) =
            authority_and_dispatch_with_read_max(repository.path(), scratch.path(), 1);
        let backend = Arc::new(ScriptedImplementationBackend::new());
        let journal = Arc::new(InMemoryRepositoryImplementationJournal::default());
        let worker = RepositoryImplementationAgentWorker::new(
            backend.clone(),
            vec![authority],
            journal.clone(),
            Arc::new(InMemoryWorktreeWriteLaneJournal::default()),
            Arc::new(InMemoryRepositoryCandidateStore::default()),
            RepositoryImplementationPolicy::default(),
        )
        .expect("worker");

        let failure = worker
            .run_attempt(dispatch)
            .await
            .expect_err("oversized read must fail closed");

        assert_eq!(failure.kind, AgentFailureKind::PermissionDenied);
        assert_eq!(backend.call_count(), 0);
        assert!(!journal.snapshot().expect("journal").iter().any(|entry| {
            matches!(
                entry.entry.record,
                RepositoryImplementationJournalRecordV1::ReadObserved { .. }
            )
        }));
        assert!(
            fs::read_dir(scratch.path())
                .expect("scratch entries")
                .all(|entry| !entry
                    .expect("scratch entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("birdcode-worktree-"))
        );
    }

    #[test]
    fn staged_target_must_fit_every_read_path_bound() {
        let (repository, scratch) = fixture();
        let bind = |max_path_components, max_path_bytes, max_component_bytes| {
            RepositoryImplementationDispatchAuthority::bind_parts(
                Sha256Digest::of_bytes(b"bounded-graph").as_str(),
                work_order(&baseline_digest(repository.path())),
                repository.path().to_path_buf(),
                scratch.path().to_path_buf(),
                RepositoryToolGrantV1::RepositoryFileRead {
                    tool_grant_id: RepositoryToolGrantId::new(),
                    max_path_components,
                    max_path_bytes,
                    max_component_bytes,
                    max_offset_bytes: 0,
                    max_bytes: 4_096,
                },
                StagedExactReplaceUtf8FileGrantV1 {
                    grant_id: RepositoryToolGrantId::new(),
                    path: RepositoryRelativePathV1::Unix {
                        components: vec![b"flight.txt".to_vec()],
                    },
                    expected_preimage_sha256: Sha256Digest::of_bytes(PREIMAGE.as_bytes()),
                    max_content_bytes: 4_096,
                },
            )
        };

        assert_eq!(
            bind(0, 1_024, 255).err(),
            Some(RepositoryImplementationConfigError::InvalidReadGrant)
        );
        assert_eq!(
            bind(8, 10, 255).err(),
            Some(RepositoryImplementationConfigError::InvalidReadGrant)
        );
        assert_eq!(
            bind(8, 1_024, 9).err(),
            Some(RepositoryImplementationConfigError::InvalidReadGrant)
        );
    }

    #[tokio::test]
    async fn postwrite_finish_journal_failure_preserves_effect_for_reconciliation() {
        let (repository, scratch) = fixture();
        let (authority, dispatch) = authority_and_dispatch(repository.path(), scratch.path());
        let backend = Arc::new(ScriptedImplementationBackend::new());
        let journal = Arc::new(FailOnFinishJournal::default());
        let write_journal = Arc::new(InMemoryWorktreeWriteLaneJournal::default());
        let worker = RepositoryImplementationAgentWorker::new(
            backend,
            vec![authority],
            journal,
            write_journal.clone(),
            Arc::new(InMemoryRepositoryCandidateStore::default()),
            RepositoryImplementationPolicy::default(),
        )
        .expect("worker");

        let failure = worker
            .run_attempt(dispatch)
            .await
            .expect_err("injected Finish journal failure");

        assert_eq!(failure.kind, AgentFailureKind::PermanentBackend);
        assert!(
            failure
                .effect_receipt_id
                .as_deref()
                .is_some_and(|receipt| receipt.starts_with("repository-write-diff:"))
        );
        assert_eq!(
            fs::read_to_string(repository.path().join("flight.txt")).unwrap(),
            PREIMAGE
        );
        let write_entries = write_journal.snapshot().expect("write journal");
        assert!(write_entries.iter().any(|entry| matches!(
            entry.entry.record,
            WorktreeWriteLaneJournalRecordV1::GitDiffObserved { .. }
        )));
        assert!(!write_entries.iter().any(|entry| matches!(
            entry.entry.record,
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared { .. }
                | WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved { .. }
        )));
        assert!(
            fs::read_dir(scratch.path())
                .expect("scratch entries")
                .any(|entry| entry
                    .expect("scratch entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("birdcode-worktree-"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an explicitly running local LM Studio model"]
    async fn implementation_worker_completes_with_live_lmstudio() {
        let endpoint = std::env::var("BIRDCODE_LMSTUDIO_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:1234/".to_owned());
        let model_name = std::env::var("BIRDCODE_LMSTUDIO_INFER_MODEL")
            .unwrap_or_else(|_| "google/gemma-4-26b-a4b".to_owned());
        let mut backend_config = LmStudioConfig::new(
            url::Url::parse(&endpoint).expect("live LM Studio endpoint is a URL"),
        );
        let per_call_timeout = Duration::from_secs(180);
        backend_config.limits.request_timeout = per_call_timeout;
        let backend = Arc::new(
            LmStudioBackend::new(backend_config).expect("live LM Studio backend constructs"),
        );
        let backend_instance = backend.instance_identity();
        let (repository, scratch) = fixture();
        let baseline = baseline_digest(repository.path());
        let mut order = work_order(&baseline);
        order.assignment.model_profile_id =
            ModelProfileId::new("live-gemma-implementation").expect("model profile");
        order.assignment.lineage = ModelLineage {
            backend_id: backend.backend_id().as_str().to_owned(),
            model_id: model_name,
            deployment_id: backend_instance
                .configured_deployment_id()
                .as_str()
                .to_owned(),
            independence_domain_id: "live-lmstudio-implementation".to_owned(),
        };
        let max_model_calls = 8_u32;
        order.budget.max_output_tokens = u64::from(max_model_calls) * 4_096;
        order.budget.max_wall_time_ms = u64::from(max_model_calls)
            .checked_mul(
                u64::try_from(per_call_timeout.as_millis()).expect("timeout fits scheduler budget"),
            )
            .and_then(|budget| budget.checked_add(30_000))
            .expect("bounded live scheduler budget");
        let graph = validated_graph(order);
        let order = graph.graph().work_orders[0].clone();
        let work_order_id = order.id;
        let authority = RepositoryImplementationDispatchAuthority::bind(
            &graph,
            order.id,
            repository.path().to_path_buf(),
            scratch.path().to_path_buf(),
            RepositoryToolGrantV1::RepositoryFileRead {
                tool_grant_id: RepositoryToolGrantId::new(),
                max_path_components: 8,
                max_path_bytes: 1_024,
                max_component_bytes: 255,
                max_offset_bytes: 0,
                max_bytes: 4_096,
            },
            StagedExactReplaceUtf8FileGrantV1 {
                grant_id: RepositoryToolGrantId::new(),
                path: RepositoryRelativePathV1::Unix {
                    components: vec![b"flight.txt".to_vec()],
                },
                expected_preimage_sha256: Sha256Digest::of_bytes(PREIMAGE.as_bytes()),
                max_content_bytes: 4_096,
            },
        )
        .expect("live authority");
        let journal = Arc::new(InMemoryRepositoryImplementationJournal::default());
        let write_journal = Arc::new(InMemoryWorktreeWriteLaneJournal::default());
        let scheduler_journal = Arc::new(InMemorySchedulerJournal::default());
        let model_backend: Arc<dyn ModelBackend> = backend;
        let worker = RepositoryImplementationAgentWorker::new(
            model_backend,
            vec![authority],
            journal.clone(),
            write_journal.clone(),
            Arc::new(InMemoryRepositoryCandidateStore::default()),
            RepositoryImplementationPolicy {
                max_model_calls,
                max_action_rejections: 4,
                max_output_tokens_per_call: 4_096,
                minimum_plan_revisions_before_finish: 3,
                finish_call_reserve: 2,
                reasoning: None,
            },
        )
        .expect("live worker");

        let result = ActorGraphExecutor::new(&worker, scheduler_journal.as_ref())
            .execute(&graph)
            .await;
        let should_dump = match &result {
            Ok(run) => {
                if !run.failures.is_empty() {
                    eprintln!("live scheduler failures: {:#?}", run.failures);
                }
                run.outcome != ActorGraphOutcome::Completed
            }
            Err(error) => {
                eprintln!("live scheduler failure: {error:#?}");
                true
            }
        };
        if should_dump {
            for entry in journal.snapshot().expect("live journal") {
                if matches!(
                    entry.entry.record,
                    RepositoryImplementationJournalRecordV1::ModelObserved { .. }
                        | RepositoryImplementationJournalRecordV1::ModelFailed { .. }
                        | RepositoryImplementationJournalRecordV1::ModelContractRejected { .. }
                        | RepositoryImplementationJournalRecordV1::ActionRejected { .. }
                ) {
                    eprintln!("live implementation record: {:?}", entry.entry.record);
                    for artifact in entry.entry.artifacts {
                        eprintln!(
                            "live implementation artifact media_type={} size_bytes={} sha256={}",
                            artifact.artifact.media_type,
                            artifact.artifact.size_bytes,
                            artifact.artifact.sha256
                        );
                        if artifact.artifact.media_type == MODEL_ERROR_MEDIA_TYPE {
                            eprintln!(
                                "live implementation model error evidence: {}",
                                String::from_utf8_lossy(&artifact.bytes)
                            );
                        }
                    }
                }
            }
        }
        let run = result.expect("live Gemma scheduler completion");
        assert_eq!(
            run.outcome,
            ActorGraphOutcome::Completed,
            "live Gemma worker failures: {:?}",
            run.failures
        );
        let completion = run
            .handoffs
            .get(&work_order_id)
            .expect("live Gemma implementation handoff");

        assert_eq!(completion.outcome, HandoffOutcome::Completed);
        assert!(
            completion
                .execution_receipt_id
                .starts_with("repository-candidate-ready:")
        );
        assert_eq!(
            fs::read_to_string(repository.path().join("flight.txt")).unwrap(),
            PREIMAGE
        );
        let write_entries = write_journal.snapshot().expect("live write journal");
        let replace_result = write_entries
            .iter()
            .find_map(|entry| match &entry.entry.record {
                WorktreeWriteLaneJournalRecordV1::FileReplaceObserved { result, .. } => {
                    Some(result)
                }
                _ => None,
            })
            .expect("live replace observation");
        assert_eq!(
            replace_result.postimage.sha256,
            Sha256Digest::of_bytes(POSTIMAGE.as_bytes())
        );
        let diff_entry = write_entries
            .iter()
            .find(|entry| {
                matches!(
                    entry.entry.record,
                    WorktreeWriteLaneJournalRecordV1::GitDiffObserved { .. }
                )
            })
            .expect("live diff observation");
        let WorktreeWriteLaneJournalRecordV1::GitDiffObserved { changed_paths, .. } =
            &diff_entry.entry.record
        else {
            unreachable!()
        };
        assert_eq!(
            changed_paths,
            &[RepositoryRelativePathV1::Unix {
                components: vec![b"flight.txt".to_vec()],
            }]
        );
        let diff_text = String::from_utf8(diff_entry.entry.artifacts[0].bytes.clone())
            .expect("live diff is UTF-8");
        assert!(diff_text.contains("-state=grounded"));
        assert!(diff_text.contains("+state=flying"));
        assert!(!diff_text.contains("-nonce=SKY-8427"));
        assert!(!diff_text.contains("+nonce=SKY-8427"));
        assert!(write_entries.iter().any(|entry| matches!(
            entry.entry.record,
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved { .. }
        )));
    }

    #[test]
    fn finish_must_cite_the_exact_observed_write_diff() {
        let path = RepositoryRelativePathV1::Unix {
            components: vec![b"flight.txt".to_vec()],
        };
        let read_artifact = ArtifactRef {
            sha256: Sha256Digest::of_bytes(PREIMAGE.as_bytes())
                .as_str()
                .to_owned(),
            size_bytes: u64::try_from(PREIMAGE.len()).unwrap(),
            media_type: "text/plain".to_owned(),
        };
        let diff_bytes = b"diff --git a/flight.txt b/flight.txt";
        let diff_artifact = ArtifactRef {
            sha256: Sha256Digest::of_bytes(diff_bytes).as_str().to_owned(),
            size_bytes: u64::try_from(diff_bytes.len()).unwrap(),
            media_type: "application/vnd.git.diff".to_owned(),
        };
        let read = ModelReadObservationV1 {
            tool_call_id: ChildToolCallId::new(),
            observed_event_id: EventId::new(),
            path: path.clone(),
            content_utf8: PREIMAGE.to_owned(),
            byte_len: u64::try_from(PREIMAGE.len()).unwrap(),
            content_sha256: Sha256Digest::of_bytes(PREIMAGE.as_bytes()),
            result_artifact: read_artifact.clone(),
        };
        let write = ModelWriteObservationV1 {
            tool_call_id: ChildToolCallId::new(),
            replace_event_id: EventId::new(),
            diff_event_id: EventId::new(),
            path,
            preimage_sha256: Sha256Digest::of_bytes(PREIMAGE.as_bytes()),
            postimage_sha256: Sha256Digest::of_bytes(POSTIMAGE.as_bytes()),
            diff_artifact: diff_artifact.clone(),
        };
        let evidence_for =
            |tool_call_id, observed_event_id, result_artifact| ChildHandoffEvidenceBinding {
                tool_call_id,
                observed_event_id,
                result_artifact,
            };
        let handoff_for = |evidence| ChildHandoffContentV1 {
            status: ChildHandoffStatus::Complete,
            summary: "The requested state transition is evidenced".to_owned(),
            findings: vec![ChildHandoffFinding {
                finding_id: "state-transition".to_owned(),
                statement: "The exact target has an observed result".to_owned(),
                confidence: ChildFindingConfidence::High,
                evidence: vec![evidence],
            }],
            unknowns: Vec::new(),
            recommended_followups: Vec::new(),
        };

        let read_only_handoff = handoff_for(evidence_for(
            read.tool_call_id,
            read.observed_event_id,
            read_artifact,
        ));
        assert_eq!(
            validate_finish_evidence(&read_only_handoff, Some(&read), Some(&write)).unwrap_err(),
            RepositoryImplementationRejectionV1::FinishEvidenceInvalid
        );

        let write_handoff = handoff_for(evidence_for(
            write.tool_call_id,
            write.diff_event_id,
            diff_artifact,
        ));
        let accepted = validate_finish_evidence(&write_handoff, Some(&read), Some(&write))
            .expect("exact write diff evidence");
        assert_eq!(
            accepted.observed_event_ids,
            BTreeSet::from([write.diff_event_id])
        );
    }
}
