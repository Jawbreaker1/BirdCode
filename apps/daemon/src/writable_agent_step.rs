//! One deliberately narrow model-to-mutation vertical slice.
//!
//! The model may select only one exact, pre-granted replacement of an existing
//! UTF-8 file. This module is not advertised as a runtime capability; it proves
//! the causal model -> validated action -> prepared effect -> observed effect
//! -> retained diff -> cleanup ordering before the general write loop exists.

use crate::writable_agent_prompt;
use birdcode_backends::{
    BackendError, BackendInstanceDigest, BackendInstanceIdentity, ModelBackend, ModelId,
    ReasoningSetting, StructuredInferenceRequest, StructuredInferenceResponse,
    StructuredOutputSpec,
};
use birdcode_protocol::{
    ArtifactRef, ChildExecutionId, EventId, RepositoryRelativePathV1, RepositoryToolGrantId,
    Sha256Digest,
};
use birdcode_workspace::{
    ArtifactBoundary, CanonicalArtifactBoundary, GIT_WORKTREE_DIFF_MEDIA_TYPE,
    GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES, GitWorktreeFileReplaceError,
    GitWorktreeUtf8FileReplacePreparedV1, GitWorktreeUtf8FileReplaceRequestV1,
    GitWorktreeUtf8FileReplaceResultV1, RetainedArtifact, TemporaryGitWorktree,
    TemporaryGitWorktreeError,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const WRITABLE_AGENT_STEP_V1_CONTRACT_VERSION: u32 = 1;
pub const WRITABLE_AGENT_STEP_V1_MAX_OUTPUT_TOKENS: u32 = 2048;

const WRITABLE_AGENT_STEP_V1_MAX_OBJECTIVE_BYTES: usize = 32 * 1024;
const WRITABLE_AGENT_STEP_V1_MAX_SUMMARY_BYTES: usize = 32 * 1024;
const WRITABLE_AGENT_STEP_V1_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const WRITABLE_AGENT_STEP_V1_MAX_PATH_COMPONENTS: usize = 64;
const WRITABLE_AGENT_STEP_V1_MAX_PATH_BYTES: usize = 4096;
const WRITABLE_AGENT_STEP_V1_MAX_PATH_COMPONENT_BYTES: usize = 255;

const MODEL_REQUEST_MEDIA_TYPE: &str =
    "application/vnd.birdcode.writable-agent-step-request.v1+json";
const MODEL_RESPONSE_MEDIA_TYPE: &str =
    "application/vnd.birdcode.writable-agent-step-response.v1+json";
const MODEL_ERROR_MEDIA_TYPE: &str =
    "application/vnd.birdcode.writable-agent-step-backend-error.v1+json";
const VALIDATED_ACTION_MEDIA_TYPE: &str =
    "application/vnd.birdcode.writable-agent-step-action.v1+json";
const FILE_CONTENT_MEDIA_TYPE: &str = "text/plain;charset=utf-8";
const FILE_REPLACE_PREPARED_MEDIA_TYPE: &str =
    "application/vnd.birdcode.worktree-file-replace-prepared.v1+json";
const FILE_REPLACE_RESULT_MEDIA_TYPE: &str =
    "application/vnd.birdcode.worktree-file-replace-result.v1+json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Utf8RepositoryPathV1 {
    pub components: Vec<String>,
}

impl Utf8RepositoryPathV1 {
    fn to_repository_path(&self) -> RepositoryRelativePathV1 {
        RepositoryRelativePathV1::Unix {
            components: self
                .components
                .iter()
                .map(|component| component.as_bytes().to_vec())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceUtf8FileGrantV1 {
    pub grant_id: RepositoryToolGrantId,
    pub execution_id: ChildExecutionId,
    pub worktree_id: Uuid,
    pub base_commit: String,
    pub backend_instance_sha256: BackendInstanceDigest,
    pub model_id: ModelId,
    pub path: Utf8RepositoryPathV1,
    pub expected_preimage_sha256: Sha256Digest,
    pub max_content_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WritableAgentStepInputV1 {
    contract_version: u32,
    execution_id: ChildExecutionId,
    objective: String,
    base_commit: String,
    grant: ReplaceUtf8FileGrantV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WritableAgentStepOutputV1 {
    pub contract_version: u32,
    pub execution_id: ChildExecutionId,
    pub base_commit: String,
    pub summary: String,
    pub action: WritableAgentActionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub enum WritableAgentActionV1 {
    ReplaceUtf8File {
        grant_id: RepositoryToolGrantId,
        path: Utf8RepositoryPathV1,
        expected_preimage_sha256: Sha256Digest,
        content_utf8: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritableAgentStepBoundaryV1 {
    ModelPrepared,
    ModelObserved,
    ModelFailed,
    ModelRejected,
    WritableActionRejected,
    WritableActionValidated,
    FileReplacePrepared,
    FileReplaceObserved,
    GitDiffObserved,
    WorktreeCleanupPrepared,
    WorktreeCleanupObserved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WritableAgentModelContractViolationV1 {
    ResponseBindingMismatch,
    IncompleteEvidence,
    ResponseByteCeilingExceeded,
    OutputTokenCeilingExceeded,
    RawResponseInvalid,
    RawAndDecodedResponseDiffer,
    TypedOutputInvalid,
    RuntimeBindingMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WritableAgentActionContractViolationV1 {
    SummaryByteCeilingExceeded,
    ExactGrantMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WritableAgentStepJournalRecordV1 {
    ModelPrepared {
        execution_id: ChildExecutionId,
        request_artifact: ArtifactRef,
    },
    ModelObserved {
        execution_id: ChildExecutionId,
        prepared_event_id: EventId,
        response_artifact: ArtifactRef,
    },
    ModelFailed {
        execution_id: ChildExecutionId,
        prepared_event_id: EventId,
        error_artifact: ArtifactRef,
    },
    ModelRejected {
        execution_id: ChildExecutionId,
        observed_event_id: EventId,
        violation: WritableAgentModelContractViolationV1,
    },
    WritableActionRejected {
        execution_id: ChildExecutionId,
        model_observed_event_id: EventId,
        violation: WritableAgentActionContractViolationV1,
    },
    WritableActionValidated {
        execution_id: ChildExecutionId,
        model_observed_event_id: EventId,
        action_artifact: ArtifactRef,
    },
    FileReplacePrepared {
        execution_id: ChildExecutionId,
        action_event_id: EventId,
        prepared: GitWorktreeUtf8FileReplacePreparedV1,
        content_artifact: ArtifactRef,
    },
    FileReplaceObserved {
        execution_id: ChildExecutionId,
        prepared_event_id: EventId,
        result: GitWorktreeUtf8FileReplaceResultV1,
    },
    GitDiffObserved {
        execution_id: ChildExecutionId,
        replace_event_id: EventId,
        base_commit: String,
        changed_paths: Vec<RepositoryRelativePathV1>,
        diff_artifact: ArtifactRef,
    },
    WorktreeCleanupPrepared {
        execution_id: ChildExecutionId,
        diff_event_id: EventId,
        worktree_id: String,
    },
    WorktreeCleanupObserved {
        execution_id: ChildExecutionId,
        prepared_event_id: EventId,
        worktree_id: String,
    },
}

impl WritableAgentStepJournalRecordV1 {
    #[must_use]
    pub const fn boundary(&self) -> WritableAgentStepBoundaryV1 {
        match self {
            Self::ModelPrepared { .. } => WritableAgentStepBoundaryV1::ModelPrepared,
            Self::ModelObserved { .. } => WritableAgentStepBoundaryV1::ModelObserved,
            Self::ModelFailed { .. } => WritableAgentStepBoundaryV1::ModelFailed,
            Self::ModelRejected { .. } => WritableAgentStepBoundaryV1::ModelRejected,
            Self::WritableActionRejected { .. } => {
                WritableAgentStepBoundaryV1::WritableActionRejected
            }
            Self::WritableActionValidated { .. } => {
                WritableAgentStepBoundaryV1::WritableActionValidated
            }
            Self::FileReplacePrepared { .. } => WritableAgentStepBoundaryV1::FileReplacePrepared,
            Self::FileReplaceObserved { .. } => WritableAgentStepBoundaryV1::FileReplaceObserved,
            Self::GitDiffObserved { .. } => WritableAgentStepBoundaryV1::GitDiffObserved,
            Self::WorktreeCleanupPrepared { .. } => {
                WritableAgentStepBoundaryV1::WorktreeCleanupPrepared
            }
            Self::WorktreeCleanupObserved { .. } => {
                WritableAgentStepBoundaryV1::WorktreeCleanupObserved
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WritableAgentStepJournalEntryV1 {
    pub record: WritableAgentStepJournalRecordV1,
    pub artifacts: Vec<RetainedArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WritableAgentStepJournalError {
    message: String,
}

impl WritableAgentStepJournalError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for WritableAgentStepJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WritableAgentStepJournalError {}

pub trait WritableAgentStepJournal: Send + Sync {
    /// Retains a complete boundary before the caller crosses the next effect.
    ///
    /// # Errors
    ///
    /// Returns an error unless every record and artifact is acknowledged.
    fn retain(
        &self,
        entry: WritableAgentStepJournalEntryV1,
    ) -> Result<EventId, WritableAgentStepJournalError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedWritableAgentStepJournalEntryV1 {
    pub event_id: EventId,
    pub entry: WritableAgentStepJournalEntryV1,
}

#[derive(Debug, Default)]
pub struct InMemoryWritableAgentStepJournal {
    entries: Mutex<Vec<RetainedWritableAgentStepJournalEntryV1>>,
}

impl InMemoryWritableAgentStepJournal {
    /// Returns retained entries in acknowledgement order.
    ///
    /// # Errors
    ///
    /// Returns an error if the journal lock is poisoned.
    pub fn snapshot(
        &self,
    ) -> Result<Vec<RetainedWritableAgentStepJournalEntryV1>, WritableAgentStepJournalError> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .map_err(|_| WritableAgentStepJournalError::new("writable journal lock poisoned"))
    }
}

impl WritableAgentStepJournal for InMemoryWritableAgentStepJournal {
    fn retain(
        &self,
        entry: WritableAgentStepJournalEntryV1,
    ) -> Result<EventId, WritableAgentStepJournalError> {
        if entry
            .artifacts
            .iter()
            .any(|artifact| !artifact_is_exact(artifact))
        {
            return Err(WritableAgentStepJournalError::new(
                "writable journal rejected an inexact artifact",
            ));
        }
        let event_id = EventId::new();
        self.entries
            .lock()
            .map_err(|_| WritableAgentStepJournalError::new("writable journal lock poisoned"))?
            .push(RetainedWritableAgentStepJournalEntryV1 { event_id, entry });
        Ok(event_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WritableAgentStepError {
    #[error("writable step configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("writable step authority is invalid: {0}")]
    InvalidAuthority(&'static str),
    #[error("writable model response violated the typed contract: {0:?}")]
    ResponseContract(WritableAgentModelContractViolationV1),
    #[error("writable model action exceeded its exact authority: {0:?}")]
    ActionAuthority(WritableAgentActionContractViolationV1),
    #[error("writable step artifact encoding failed")]
    Encoding,
    #[error("writable model request failed: {0}")]
    Backend(#[from] BackendError),
    #[error("writable step journal failed: {0}")]
    Journal(#[from] WritableAgentStepJournalError),
    #[error("worktree mutation failed: {0}")]
    Mutation(#[from] GitWorktreeFileReplaceError),
    #[error("worktree lifecycle failed: {0}")]
    Worktree(#[from] TemporaryGitWorktreeError),
    #[error("writable step requires a pristine tracked worktree")]
    DirtyWorktree,
    #[error("writable step grant target is not a regular file tracked by the exact base commit")]
    GrantTargetNotTracked,
    #[error("writable step produced an empty tracked diff")]
    EmptyDiff,
    #[error("writable step diff contains paths outside the exact write grant")]
    UnexpectedChangedPaths,
}

#[derive(Clone, Debug)]
pub struct WritableAgentStepResultV1 {
    pub execution_id: ChildExecutionId,
    pub summary: String,
    pub mutation: GitWorktreeUtf8FileReplaceResultV1,
    pub diff_artifact: RetainedArtifact,
    pub cleanup_observed_event_id: EventId,
}

pub struct WritableAgentStep {
    backend: Arc<dyn ModelBackend>,
    backend_instance: BackendInstanceIdentity,
    model_id: ModelId,
    output_spec: StructuredOutputSpec,
    journal: Arc<dyn WritableAgentStepJournal>,
    reasoning: Option<ReasoningSetting>,
}

struct ObservedWritableModelStep {
    output: WritableAgentStepOutputV1,
    event_id: EventId,
}

struct ValidatedReplaceUtf8File {
    path: RepositoryRelativePathV1,
    expected_preimage_sha256: Sha256Digest,
    content_utf8: String,
    max_content_bytes: u64,
}

struct ObservedFileReplace {
    result: GitWorktreeUtf8FileReplaceResultV1,
    event_id: EventId,
}

struct ObservedGitDiff {
    artifact: RetainedArtifact,
    event_id: EventId,
}

impl WritableAgentStep {
    /// Constructs the one-turn writable worker against an exact backend.
    ///
    /// # Errors
    ///
    /// Rejects an inconsistent backend identity or invalid output contract.
    pub fn new(
        backend: Arc<dyn ModelBackend>,
        model_id: ModelId,
        journal: Arc<dyn WritableAgentStepJournal>,
        reasoning: Option<ReasoningSetting>,
    ) -> Result<Self, WritableAgentStepError> {
        let backend_instance = backend.instance_identity().clone();
        backend_instance
            .validate_integrity()
            .map_err(|error| WritableAgentStepError::InvalidConfiguration(error.to_string()))?;
        if backend_instance.backend_id() != backend.backend_id() {
            return Err(WritableAgentStepError::InvalidConfiguration(
                "backend instance does not bind the selected backend".to_owned(),
            ));
        }
        let output_spec = writable_agent_prompt::output_spec()
            .map_err(|error| WritableAgentStepError::InvalidConfiguration(error.to_string()))?;
        Ok(Self {
            backend,
            backend_instance,
            model_id,
            output_spec,
            journal,
            reasoning,
        })
    }

    /// Runs one model-selected, exact existing-file replacement through diff
    /// retention and explicit worktree cleanup.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid authority, model/evidence substitution,
    /// journaling failure, mutation failure, empty diff or cleanup failure.
    /// On error, the caller retains ownership of `worktree` and must explicitly
    /// release or reconcile it; best-effort `Drop` is not provenance.
    pub async fn run(
        &self,
        worktree: &mut TemporaryGitWorktree,
        objective: impl Into<String>,
        grant: ReplaceUtf8FileGrantV1,
    ) -> Result<WritableAgentStepResultV1, WritableAgentStepError> {
        let objective = objective.into();
        validate_authority(
            &objective,
            &grant,
            worktree,
            &self.backend_instance,
            &self.model_id,
        )?;
        let granted_path = grant.path.to_repository_path();
        if !worktree.is_pristine()? {
            return Err(WritableAgentStepError::DirtyWorktree);
        }
        if !worktree.base_commit_tracks_regular_file(&granted_path)? {
            return Err(WritableAgentStepError::GrantTargetNotTracked);
        }
        let execution_id = grant.execution_id;
        let turn = WritableAgentStepInputV1 {
            contract_version: WRITABLE_AGENT_STEP_V1_CONTRACT_VERSION,
            execution_id,
            objective,
            base_commit: worktree.base_commit().to_owned(),
            grant: grant.clone(),
        };
        let model = self.observe_model_step(&turn).await?;
        let (action, action_event_id) =
            self.validate_and_retain_action(&turn, &model.output, model.event_id)?;
        let replacement =
            self.replace_and_retain(worktree, execution_id, action_event_id, action)?;
        let diff = self.diff_and_retain(worktree, execution_id, &replacement)?;
        let cleanup_observed_event_id =
            self.cleanup_and_retain(worktree, execution_id, diff.event_id)?;
        Ok(WritableAgentStepResultV1 {
            execution_id,
            summary: model.output.summary,
            mutation: replacement.result,
            diff_artifact: diff.artifact,
            cleanup_observed_event_id,
        })
    }

    async fn observe_model_step(
        &self,
        turn: &WritableAgentStepInputV1,
    ) -> Result<ObservedWritableModelStep, WritableAgentStepError> {
        let request = self.request(turn)?;
        let request_artifact = retain_json(MODEL_REQUEST_MEDIA_TYPE, &request)?;
        let prepared_event_id = self.retain(
            WritableAgentStepJournalRecordV1::ModelPrepared {
                execution_id: turn.execution_id,
                request_artifact: request_artifact.artifact.clone(),
            },
            vec![request_artifact],
        )?;
        let response = match self.backend.infer_structured(request).await {
            Ok(response) => response,
            Err(error) => {
                let error_artifact = retain_json(MODEL_ERROR_MEDIA_TYPE, &error)?;
                self.retain(
                    WritableAgentStepJournalRecordV1::ModelFailed {
                        execution_id: turn.execution_id,
                        prepared_event_id,
                        error_artifact: error_artifact.artifact.clone(),
                    },
                    vec![error_artifact],
                )?;
                return Err(error.into());
            }
        };
        let response_artifact = retain_json(MODEL_RESPONSE_MEDIA_TYPE, &response)?;
        let event_id = self.retain(
            WritableAgentStepJournalRecordV1::ModelObserved {
                execution_id: turn.execution_id,
                prepared_event_id,
                response_artifact: response_artifact.artifact.clone(),
            },
            vec![response_artifact],
        )?;
        let output = match self.validate_response(turn, &response) {
            Ok(output) => output,
            Err(violation) => {
                self.retain(
                    WritableAgentStepJournalRecordV1::ModelRejected {
                        execution_id: turn.execution_id,
                        observed_event_id: event_id,
                        violation,
                    },
                    Vec::new(),
                )?;
                return Err(WritableAgentStepError::ResponseContract(violation));
            }
        };
        Ok(ObservedWritableModelStep { output, event_id })
    }

    fn validate_and_retain_action(
        &self,
        turn: &WritableAgentStepInputV1,
        output: &WritableAgentStepOutputV1,
        model_observed_event_id: EventId,
    ) -> Result<(ValidatedReplaceUtf8File, EventId), WritableAgentStepError> {
        let action = match validate_action(turn, output) {
            Ok(action) => action,
            Err(violation) => {
                self.retain(
                    WritableAgentStepJournalRecordV1::WritableActionRejected {
                        execution_id: turn.execution_id,
                        model_observed_event_id,
                        violation,
                    },
                    Vec::new(),
                )?;
                return Err(WritableAgentStepError::ActionAuthority(violation));
            }
        };
        let action_artifact = retain_json(VALIDATED_ACTION_MEDIA_TYPE, &output.action)?;
        let event_id = self.retain(
            WritableAgentStepJournalRecordV1::WritableActionValidated {
                execution_id: turn.execution_id,
                model_observed_event_id,
                action_artifact: action_artifact.artifact.clone(),
            },
            vec![action_artifact],
        )?;
        Ok((action, event_id))
    }

    fn replace_and_retain(
        &self,
        worktree: &mut TemporaryGitWorktree,
        execution_id: ChildExecutionId,
        action_event_id: EventId,
        action: ValidatedReplaceUtf8File,
    ) -> Result<ObservedFileReplace, WritableAgentStepError> {
        if !worktree.is_pristine()? {
            return Err(WritableAgentStepError::DirtyWorktree);
        }
        if !worktree.base_commit_tracks_regular_file(&action.path)? {
            return Err(WritableAgentStepError::GrantTargetNotTracked);
        }
        let prepared = worktree.prepare_utf8_file_replace(GitWorktreeUtf8FileReplaceRequestV1 {
            path: action.path,
            expected_preimage_sha256: action.expected_preimage_sha256,
            replacement_utf8: action.content_utf8.clone(),
            max_replacement_bytes: action.max_content_bytes,
        })?;
        let content_artifact =
            retain_bytes(FILE_CONTENT_MEDIA_TYPE, action.content_utf8.into_bytes())?;
        let prepared_artifact = retain_json(FILE_REPLACE_PREPARED_MEDIA_TYPE, prepared.receipt())?;
        let prepared_event_id = match self.retain(
            WritableAgentStepJournalRecordV1::FileReplacePrepared {
                execution_id,
                action_event_id,
                prepared: prepared.receipt().clone(),
                content_artifact: content_artifact.artifact.clone(),
            },
            vec![content_artifact, prepared_artifact],
        ) {
            Ok(event_id) => event_id,
            Err(error) => {
                let _ = worktree.cancel_prepared_utf8_file_replace(&prepared);
                return Err(error);
            }
        };
        let result = worktree.execute_prepared_utf8_file_replace(&prepared)?;
        let result_artifact = retain_json(FILE_REPLACE_RESULT_MEDIA_TYPE, &result)?;
        let event_id = self.retain(
            WritableAgentStepJournalRecordV1::FileReplaceObserved {
                execution_id,
                prepared_event_id,
                result: result.clone(),
            },
            vec![result_artifact],
        )?;
        Ok(ObservedFileReplace { result, event_id })
    }

    fn diff_and_retain(
        &self,
        worktree: &TemporaryGitWorktree,
        execution_id: ChildExecutionId,
        replacement: &ObservedFileReplace,
    ) -> Result<ObservedGitDiff, WritableAgentStepError> {
        let diff = worktree.tracked_diff()?;
        if diff.changed_paths.len() != 1
            || diff.changed_paths.first() != Some(&replacement.result.path)
        {
            return Err(WritableAgentStepError::UnexpectedChangedPaths);
        }
        if diff.bytes.is_empty() {
            return Err(WritableAgentStepError::EmptyDiff);
        }
        let artifact = retain_bytes(GIT_WORKTREE_DIFF_MEDIA_TYPE, diff.bytes)?;
        let event_id = self.retain(
            WritableAgentStepJournalRecordV1::GitDiffObserved {
                execution_id,
                replace_event_id: replacement.event_id,
                base_commit: diff.base_commit,
                changed_paths: diff.changed_paths,
                diff_artifact: artifact.artifact.clone(),
            },
            vec![artifact.clone()],
        )?;
        Ok(ObservedGitDiff { artifact, event_id })
    }

    fn cleanup_and_retain(
        &self,
        worktree: &mut TemporaryGitWorktree,
        execution_id: ChildExecutionId,
        diff_event_id: EventId,
    ) -> Result<EventId, WritableAgentStepError> {
        let worktree_id = worktree.worktree_id().to_string();
        let prepared_event_id = self.retain(
            WritableAgentStepJournalRecordV1::WorktreeCleanupPrepared {
                execution_id,
                diff_event_id,
                worktree_id: worktree_id.clone(),
            },
            Vec::new(),
        )?;
        worktree.release()?;
        self.retain(
            WritableAgentStepJournalRecordV1::WorktreeCleanupObserved {
                execution_id,
                prepared_event_id,
                worktree_id,
            },
            Vec::new(),
        )
    }

    fn request(
        &self,
        turn: &WritableAgentStepInputV1,
    ) -> Result<StructuredInferenceRequest, WritableAgentStepError> {
        let turn_json =
            serde_json::to_string(turn).map_err(|_| WritableAgentStepError::Encoding)?;
        let request = StructuredInferenceRequest::new(
            self.model_id.clone(),
            writable_agent_prompt::messages(turn_json),
            self.output_spec.clone(),
            WRITABLE_AGENT_STEP_V1_MAX_OUTPUT_TOKENS,
        )
        .map_err(|error| WritableAgentStepError::InvalidConfiguration(error.to_string()))?;
        Ok(match self.reasoning {
            Some(reasoning) => request.with_reasoning(reasoning),
            None => request,
        })
    }

    fn validate_response(
        &self,
        turn: &WritableAgentStepInputV1,
        response: &StructuredInferenceResponse,
    ) -> Result<WritableAgentStepOutputV1, WritableAgentModelContractViolationV1> {
        if response.model_id != self.model_id
            || !self
                .backend_instance
                .matches_response_evidence(&response.evidence)
        {
            return Err(WritableAgentModelContractViolationV1::ResponseBindingMismatch);
        }
        if !(200..300).contains(&response.evidence.status)
            || response.finish_reason.as_deref() != Some("stop")
            || response
                .evidence
                .response_body_sha256
                .as_ref()
                .is_none_or(|digest| Sha256Digest::parse(digest.clone()).is_err())
        {
            return Err(WritableAgentModelContractViolationV1::IncompleteEvidence);
        }
        if response.raw_text.len() > WRITABLE_AGENT_STEP_V1_MAX_RESPONSE_BYTES {
            return Err(WritableAgentModelContractViolationV1::ResponseByteCeilingExceeded);
        }
        if response
            .usage
            .as_ref()
            .and_then(|usage| usage.output_tokens)
            .is_some_and(|tokens| tokens > u64::from(WRITABLE_AGENT_STEP_V1_MAX_OUTPUT_TOKENS))
        {
            return Err(WritableAgentModelContractViolationV1::OutputTokenCeilingExceeded);
        }
        let raw_value = serde_json::from_str::<serde_json::Value>(&response.raw_text)
            .map_err(|_| WritableAgentModelContractViolationV1::RawResponseInvalid)?;
        if raw_value != response.value {
            return Err(WritableAgentModelContractViolationV1::RawAndDecodedResponseDiffer);
        }
        let output = serde_json::from_value::<WritableAgentStepOutputV1>(response.value.clone())
            .map_err(|_| WritableAgentModelContractViolationV1::TypedOutputInvalid)?;
        if output.contract_version != turn.contract_version
            || output.execution_id != turn.execution_id
            || output.base_commit != turn.base_commit
        {
            return Err(WritableAgentModelContractViolationV1::RuntimeBindingMismatch);
        }
        Ok(output)
    }

    fn retain(
        &self,
        record: WritableAgentStepJournalRecordV1,
        artifacts: Vec<RetainedArtifact>,
    ) -> Result<EventId, WritableAgentStepError> {
        Ok(self
            .journal
            .retain(WritableAgentStepJournalEntryV1 { record, artifacts })?)
    }
}

fn validate_authority(
    objective: &str,
    grant: &ReplaceUtf8FileGrantV1,
    worktree: &TemporaryGitWorktree,
    backend_instance: &BackendInstanceIdentity,
    model_id: &ModelId,
) -> Result<(), WritableAgentStepError> {
    if objective.trim().is_empty() || objective.len() > WRITABLE_AGENT_STEP_V1_MAX_OBJECTIVE_BYTES {
        return Err(WritableAgentStepError::InvalidAuthority(
            "objective must be nonblank and bounded",
        ));
    }
    if grant.max_content_bytes == 0
        || grant.max_content_bytes > GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES
    {
        return Err(WritableAgentStepError::InvalidAuthority(
            "content ceiling is outside the frozen profile",
        ));
    }
    if grant.worktree_id != worktree.worktree_id() || grant.base_commit != worktree.base_commit() {
        return Err(WritableAgentStepError::InvalidAuthority(
            "grant is not bound to the selected worktree and base commit",
        ));
    }
    if grant.backend_instance_sha256 != *backend_instance.identity_sha256()
        || grant.model_id != *model_id
    {
        return Err(WritableAgentStepError::InvalidAuthority(
            "grant is not bound to the selected model actor",
        ));
    }
    validate_path(&grant.path)
}

fn validate_path(path: &Utf8RepositoryPathV1) -> Result<(), WritableAgentStepError> {
    if path.components.is_empty()
        || path.components.len() > WRITABLE_AGENT_STEP_V1_MAX_PATH_COMPONENTS
    {
        return Err(WritableAgentStepError::InvalidAuthority(
            "path component count is invalid",
        ));
    }
    let mut total = 0_usize;
    for (index, component) in path.components.iter().enumerate() {
        if component.is_empty()
            || matches!(component.as_str(), "." | "..")
            || component.as_bytes().contains(&b'/')
            || component.as_bytes().contains(&0)
            || component.len() > WRITABLE_AGENT_STEP_V1_MAX_PATH_COMPONENT_BYTES
            || component.eq_ignore_ascii_case(".git")
        {
            return Err(WritableAgentStepError::InvalidAuthority(
                "path contains a forbidden component",
            ));
        }
        total = total
            .saturating_add(component.len())
            .saturating_add(usize::from(index > 0));
    }
    if total > WRITABLE_AGENT_STEP_V1_MAX_PATH_BYTES {
        return Err(WritableAgentStepError::InvalidAuthority(
            "path exceeds the byte ceiling",
        ));
    }
    Ok(())
}

fn validate_action(
    turn: &WritableAgentStepInputV1,
    output: &WritableAgentStepOutputV1,
) -> Result<ValidatedReplaceUtf8File, WritableAgentActionContractViolationV1> {
    if output.summary.len() > WRITABLE_AGENT_STEP_V1_MAX_SUMMARY_BYTES {
        return Err(WritableAgentActionContractViolationV1::SummaryByteCeilingExceeded);
    }
    match &output.action {
        WritableAgentActionV1::ReplaceUtf8File {
            grant_id,
            path,
            expected_preimage_sha256,
            content_utf8,
        } if *grant_id == turn.grant.grant_id
            && *path == turn.grant.path
            && *expected_preimage_sha256 == turn.grant.expected_preimage_sha256
            && u64::try_from(content_utf8.len())
                .is_ok_and(|size| size <= turn.grant.max_content_bytes) =>
        {
            Ok(ValidatedReplaceUtf8File {
                path: path.to_repository_path(),
                expected_preimage_sha256: expected_preimage_sha256.clone(),
                content_utf8: content_utf8.clone(),
                max_content_bytes: turn.grant.max_content_bytes,
            })
        }
        WritableAgentActionV1::ReplaceUtf8File { .. } => {
            Err(WritableAgentActionContractViolationV1::ExactGrantMismatch)
        }
    }
}

fn retain_json(
    media_type: &'static str,
    value: &impl Serialize,
) -> Result<RetainedArtifact, WritableAgentStepError> {
    let bytes = serde_json::to_vec(value).map_err(|_| WritableAgentStepError::Encoding)?;
    retain_bytes(media_type, bytes)
}

fn retain_bytes(
    media_type: &'static str,
    bytes: Vec<u8>,
) -> Result<RetainedArtifact, WritableAgentStepError> {
    CanonicalArtifactBoundary
        .retain(media_type, bytes)
        .map_err(|_| WritableAgentStepError::Encoding)
}

fn artifact_is_exact(artifact: &RetainedArtifact) -> bool {
    artifact.artifact.sha256 == artifact.digest.as_str()
        && artifact.artifact.sha256 == Sha256Digest::of_bytes(&artifact.bytes).as_str()
        && artifact.artifact.size_bytes == u64::try_from(artifact.bytes.len()).unwrap_or(u64::MAX)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use birdcode_backends::{
        BackendDeploymentId, BackendEndpointOrigin, BackendErrorKind, BackendFuture, BackendId,
        BackendOperation, BackendTransportIdentity, InferenceEvidence, ModelCatalog, TokenUsage,
    };
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ENDPOINT: &str = "http://127.0.0.1:19112";
    const MODEL: &str = "scripted/writable-agent-step";
    const PREIMAGE: &[u8] = b"BirdCode is grounded.\n";
    const POSTIMAGE: &str = "BirdCode makes code fly.\n";

    fn backend_id() -> BackendId {
        BackendId::new("scripted-writable").expect("backend id")
    }

    fn model_id() -> ModelId {
        ModelId::new(MODEL).expect("model id")
    }

    fn backend_instance() -> BackendInstanceIdentity {
        BackendInstanceIdentity::new(
            backend_id(),
            BackendTransportIdentity::HttpOrigin {
                origin: BackendEndpointOrigin::parse(ENDPOINT).expect("endpoint"),
            },
            BackendDeploymentId::new("writable-step-test").expect("deployment"),
        )
        .expect("instance")
    }

    fn substituted_backend_instance() -> BackendInstanceIdentity {
        BackendInstanceIdentity::new(
            backend_id(),
            BackendTransportIdentity::HttpOrigin {
                origin: BackendEndpointOrigin::parse(ENDPOINT).expect("endpoint"),
            },
            BackendDeploymentId::new("substituted-writable-step-test").expect("deployment"),
        )
        .expect("substituted instance")
    }

    #[derive(Clone, Copy)]
    enum ScriptedBackendMode {
        Exact,
        TamperedPath,
        TamperedEvidence,
        BackendFailure,
    }

    struct ScriptedWritableBackend {
        id: BackendId,
        instance: BackendInstanceIdentity,
        calls: AtomicUsize,
        requests: Mutex<Vec<StructuredInferenceRequest>>,
        mode: ScriptedBackendMode,
    }

    impl ScriptedWritableBackend {
        fn new(mode: ScriptedBackendMode) -> Self {
            Self {
                id: backend_id(),
                instance: backend_instance(),
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
                mode,
            }
        }
    }

    impl ModelBackend for ScriptedWritableBackend {
        fn backend_id(&self) -> &BackendId {
            &self.id
        }

        fn instance_identity(&self) -> &BackendInstanceIdentity {
            &self.instance
        }

        fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
            Box::pin(async { panic!("writable step must not discover models") })
        }

        fn infer_structured(
            &self,
            request: StructuredInferenceRequest,
        ) -> BackendFuture<'_, StructuredInferenceResponse> {
            let ordinal = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            assert_eq!(ordinal, 1, "one-turn step called backend more than once");
            if matches!(self.mode, ScriptedBackendMode::BackendFailure) {
                let error = BackendError {
                    backend_id: backend_id(),
                    backend_instance: Some(Box::new(backend_instance())),
                    operation: BackendOperation::StructuredInference,
                    kind: BackendErrorKind::Transport,
                    message: "scripted transport failure".to_owned(),
                    evidence: None,
                };
                return Box::pin(async move { Err(error) });
            }
            let turn = serde_json::from_str::<WritableAgentStepInputV1>(
                &request.messages().last().expect("user message").content,
            )
            .expect("typed turn");
            let path = if matches!(self.mode, ScriptedBackendMode::TamperedPath) {
                Utf8RepositoryPathV1 {
                    components: vec!["src".to_owned(), "other.txt".to_owned()],
                }
            } else {
                turn.grant.path.clone()
            };
            let output = WritableAgentStepOutputV1 {
                contract_version: turn.contract_version,
                execution_id: turn.execution_id,
                base_commit: turn.base_commit,
                summary: "Updated the granted message file.".to_owned(),
                action: WritableAgentActionV1::ReplaceUtf8File {
                    grant_id: turn.grant.grant_id,
                    path,
                    expected_preimage_sha256: turn.grant.expected_preimage_sha256,
                    content_utf8: POSTIMAGE.to_owned(),
                },
            };
            let value = serde_json::to_value(output).expect("output value");
            self.requests.lock().expect("requests").push(request);
            let response = StructuredInferenceResponse {
                model_id: model_id(),
                raw_text: serde_json::to_string(&value).expect("raw output"),
                value,
                finish_reason: Some("stop".to_owned()),
                usage: Some(TokenUsage {
                    input_tokens: Some(100),
                    output_tokens: Some(80),
                    total_tokens: Some(180),
                }),
                evidence: InferenceEvidence {
                    backend_id: backend_id(),
                    backend_instance: Some(
                        if matches!(self.mode, ScriptedBackendMode::TamperedEvidence) {
                            substituted_backend_instance()
                        } else {
                            backend_instance()
                        },
                    ),
                    endpoint: format!("{ENDPOINT}/v1/chat/completions"),
                    status: 200,
                    completion_id: Some("scripted-write-1".to_owned()),
                    response_body_sha256: Some("1".repeat(64)),
                    raw_response: json!({"scripted": true}),
                },
            };
            Box::pin(async move { Ok(response) })
        }
    }

    struct InspectingJournal {
        entries: Mutex<Vec<RetainedWritableAgentStepJournalEntryV1>>,
        worktree_path: PathBuf,
        inject_unattributed_change: bool,
    }

    impl WritableAgentStepJournal for InspectingJournal {
        fn retain(
            &self,
            entry: WritableAgentStepJournalEntryV1,
        ) -> Result<EventId, WritableAgentStepJournalError> {
            let target = self.worktree_path.join("src/message.txt");
            match entry.record.boundary() {
                WritableAgentStepBoundaryV1::FileReplacePrepared => {
                    assert_eq!(fs::read(&target).expect("prepared preimage"), PREIMAGE);
                }
                WritableAgentStepBoundaryV1::FileReplaceObserved => {
                    assert_eq!(
                        fs::read(&target).expect("observed postimage"),
                        POSTIMAGE.as_bytes()
                    );
                    assert!(
                        fs::read_dir(target.parent().expect("parent"))
                            .expect("parent entries")
                            .all(|entry| !entry
                                .expect("entry")
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".birdcode-edit-"))
                    );
                    if self.inject_unattributed_change {
                        fs::write(
                            self.worktree_path.join("src/unrelated.txt"),
                            b"unattributed post-effect change\n",
                        )
                        .expect("inject unattributed change");
                    }
                }
                WritableAgentStepBoundaryV1::GitDiffObserved
                | WritableAgentStepBoundaryV1::WorktreeCleanupPrepared => {
                    assert!(self.worktree_path.exists());
                }
                WritableAgentStepBoundaryV1::WorktreeCleanupObserved => {
                    assert!(!self.worktree_path.exists());
                }
                _ => {}
            }
            assert!(entry.artifacts.iter().all(artifact_is_exact));
            let event_id = EventId::new();
            self.entries
                .lock()
                .expect("journal entries")
                .push(RetainedWritableAgentStepJournalEntryV1 { event_id, entry });
            Ok(event_id)
        }
    }

    struct RejectingJournal {
        reject_at: WritableAgentStepBoundaryV1,
        retained: Mutex<Vec<WritableAgentStepBoundaryV1>>,
    }

    impl WritableAgentStepJournal for RejectingJournal {
        fn retain(
            &self,
            entry: WritableAgentStepJournalEntryV1,
        ) -> Result<EventId, WritableAgentStepJournalError> {
            let boundary = entry.record.boundary();
            if boundary == self.reject_at {
                return Err(WritableAgentStepJournalError::new(
                    "scripted journal rejection",
                ));
            }
            assert!(entry.artifacts.iter().all(artifact_is_exact));
            self.retained
                .lock()
                .expect("retained boundaries")
                .push(boundary);
            Ok(EventId::new())
        }
    }

    fn git(repository: &Path, args: &[&str]) -> Output {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git starts");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn repository_fixture() -> tempfile::TempDir {
        let repository = tempfile::tempdir().expect("repository");
        git(repository.path(), &["init", "--quiet"]);
        git(repository.path(), &["config", "user.name", "BirdCode Test"]);
        git(
            repository.path(),
            &["config", "user.email", "birdcode@example.invalid"],
        );
        fs::create_dir(repository.path().join("src")).expect("src");
        fs::write(repository.path().join("src/message.txt"), PREIMAGE).expect("message");
        fs::write(
            repository.path().join("src/unrelated.txt"),
            b"unrelated original\n",
        )
        .expect("unrelated");
        git(
            repository.path(),
            &["add", "src/message.txt", "src/unrelated.txt"],
        );
        git(repository.path(), &["commit", "--quiet", "-m", "fixture"]);
        repository
    }

    fn grant(worktree: &TemporaryGitWorktree) -> ReplaceUtf8FileGrantV1 {
        ReplaceUtf8FileGrantV1 {
            grant_id: RepositoryToolGrantId::new(),
            execution_id: ChildExecutionId::new(),
            worktree_id: worktree.worktree_id(),
            base_commit: worktree.base_commit().to_owned(),
            backend_instance_sha256: backend_instance().identity_sha256().clone(),
            model_id: model_id(),
            path: Utf8RepositoryPathV1 {
                components: vec!["src".to_owned(), "message.txt".to_owned()],
            },
            expected_preimage_sha256: Sha256Digest::of_bytes(PREIMAGE),
            max_content_bytes: 4096,
        }
    }

    #[tokio::test]
    async fn scripted_model_mutates_retains_diff_then_cleans_worktree() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let worktree_path = worktree.path().to_path_buf();
        let journal = Arc::new(InspectingJournal {
            entries: Mutex::new(Vec::new()),
            worktree_path: worktree_path.clone(),
            inject_unattributed_change: false,
        });
        let backend = Arc::new(ScriptedWritableBackend::new(ScriptedBackendMode::Exact));
        let step = WritableAgentStep::new(backend.clone(), model_id(), journal.clone(), None)
            .expect("step");

        let write_grant = grant(&worktree);
        let result = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect("writable step");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        let requests = backend.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].messages().len(), 2);
        assert_eq!(requests[0].output().name(), "writable_agent_step_v1");
        assert!(!worktree_path.exists());
        assert_eq!(
            fs::read(repository.path().join("src/message.txt")).expect("source message"),
            PREIMAGE
        );
        assert!(
            git(repository.path(), &["status", "--porcelain"])
                .stdout
                .is_empty()
        );
        assert!(artifact_is_exact(&result.diff_artifact));
        assert!(
            result
                .diff_artifact
                .bytes
                .windows(b"-BirdCode is grounded.\n+BirdCode makes code fly.\n".len())
                .any(|window| window == b"-BirdCode is grounded.\n+BirdCode makes code fly.\n")
        );

        let entries = journal.entries.lock().expect("journal entries");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.entry.record.boundary())
                .collect::<Vec<_>>(),
            vec![
                WritableAgentStepBoundaryV1::ModelPrepared,
                WritableAgentStepBoundaryV1::ModelObserved,
                WritableAgentStepBoundaryV1::WritableActionValidated,
                WritableAgentStepBoundaryV1::FileReplacePrepared,
                WritableAgentStepBoundaryV1::FileReplaceObserved,
                WritableAgentStepBoundaryV1::GitDiffObserved,
                WritableAgentStepBoundaryV1::WorktreeCleanupPrepared,
                WritableAgentStepBoundaryV1::WorktreeCleanupObserved,
            ]
        );
        assert!(entries.iter().any(|entry| {
            entry.entry.record.boundary() == WritableAgentStepBoundaryV1::GitDiffObserved
                && entry.entry.artifacts == vec![result.diff_artifact.clone()]
        }));
    }

    #[tokio::test]
    async fn unattributed_changed_path_is_rejected_before_diff_retention() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let worktree_path = worktree.path().to_path_buf();
        let journal = Arc::new(InspectingJournal {
            entries: Mutex::new(Vec::new()),
            worktree_path,
            inject_unattributed_change: true,
        });
        let backend = Arc::new(ScriptedWritableBackend::new(ScriptedBackendMode::Exact));
        let step =
            WritableAgentStep::new(backend, model_id(), journal.clone(), None).expect("step");
        let write_grant = grant(&worktree);

        let error = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("extra changed path must fail");
        assert!(matches!(
            error,
            WritableAgentStepError::UnexpectedChangedPaths
        ));
        assert!(worktree.is_active(), "failed diff must remain recoverable");
        assert_eq!(
            journal
                .entries
                .lock()
                .expect("journal")
                .iter()
                .map(|entry| entry.entry.record.boundary())
                .collect::<Vec<_>>(),
            vec![
                WritableAgentStepBoundaryV1::ModelPrepared,
                WritableAgentStepBoundaryV1::ModelObserved,
                WritableAgentStepBoundaryV1::WritableActionValidated,
                WritableAgentStepBoundaryV1::FileReplacePrepared,
                WritableAgentStepBoundaryV1::FileReplaceObserved,
            ]
        );
        assert_eq!(
            fs::read(repository.path().join("src/unrelated.txt")).expect("source unrelated"),
            b"unrelated original\n"
        );
        worktree.release().expect("cleanup");
    }

    #[tokio::test]
    async fn rejected_prepared_boundary_has_no_write_and_releases_writer_lane() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let write_grant = grant(&worktree);
        let retry_grant = write_grant.clone();
        let journal = Arc::new(RejectingJournal {
            reject_at: WritableAgentStepBoundaryV1::FileReplacePrepared,
            retained: Mutex::new(Vec::new()),
        });
        let backend = Arc::new(ScriptedWritableBackend::new(ScriptedBackendMode::Exact));
        let step =
            WritableAgentStep::new(backend, model_id(), journal.clone(), None).expect("step");

        let error = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("prepared journal rejection must fail");
        assert!(matches!(error, WritableAgentStepError::Journal(_)));
        assert_eq!(
            fs::read(worktree.path().join("src/message.txt")).expect("unchanged message"),
            PREIMAGE
        );
        assert_eq!(
            *journal.retained.lock().expect("retained boundaries"),
            vec![
                WritableAgentStepBoundaryV1::ModelPrepared,
                WritableAgentStepBoundaryV1::ModelObserved,
                WritableAgentStepBoundaryV1::WritableActionValidated,
            ]
        );
        let prepared = worktree
            .prepare_utf8_file_replace(GitWorktreeUtf8FileReplaceRequestV1 {
                path: retry_grant.path.to_repository_path(),
                expected_preimage_sha256: retry_grant.expected_preimage_sha256,
                replacement_utf8: "writer lane was released\n".to_owned(),
                max_replacement_bytes: retry_grant.max_content_bytes,
            })
            .expect("writer lane is reusable");
        worktree
            .cancel_prepared_utf8_file_replace(&prepared)
            .expect("cancel retry preparation");
        worktree.release().expect("cleanup");
    }

    #[tokio::test]
    async fn authority_mismatch_stops_before_validation_or_mutation() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let journal = Arc::new(InMemoryWritableAgentStepJournal::default());
        let backend = Arc::new(ScriptedWritableBackend::new(
            ScriptedBackendMode::TamperedPath,
        ));
        let step =
            WritableAgentStep::new(backend, model_id(), journal.clone(), None).expect("step");

        let write_grant = grant(&worktree);
        let error = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("tampered path must fail");
        assert!(matches!(error, WritableAgentStepError::ActionAuthority(_)));
        assert_eq!(
            fs::read(worktree.path().join("src/message.txt")).expect("worktree message"),
            PREIMAGE
        );
        assert_eq!(
            journal
                .snapshot()
                .expect("journal")
                .iter()
                .map(|entry| entry.entry.record.boundary())
                .collect::<Vec<_>>(),
            vec![
                WritableAgentStepBoundaryV1::ModelPrepared,
                WritableAgentStepBoundaryV1::ModelObserved,
                WritableAgentStepBoundaryV1::WritableActionRejected,
            ]
        );
        worktree.release().expect("cleanup");
    }

    #[tokio::test]
    async fn substituted_backend_evidence_is_retained_then_rejected() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let journal = Arc::new(InMemoryWritableAgentStepJournal::default());
        let backend = Arc::new(ScriptedWritableBackend::new(
            ScriptedBackendMode::TamperedEvidence,
        ));
        let step =
            WritableAgentStep::new(backend, model_id(), journal.clone(), None).expect("step");
        let write_grant = grant(&worktree);

        let error = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("substituted evidence must fail");
        assert!(matches!(
            error,
            WritableAgentStepError::ResponseContract(
                WritableAgentModelContractViolationV1::ResponseBindingMismatch
            )
        ));
        assert_eq!(
            fs::read(worktree.path().join("src/message.txt")).expect("worktree message"),
            PREIMAGE
        );
        assert_eq!(
            journal
                .snapshot()
                .expect("journal")
                .iter()
                .map(|entry| entry.entry.record.boundary())
                .collect::<Vec<_>>(),
            vec![
                WritableAgentStepBoundaryV1::ModelPrepared,
                WritableAgentStepBoundaryV1::ModelObserved,
                WritableAgentStepBoundaryV1::ModelRejected,
            ]
        );
        worktree.release().expect("cleanup");
    }

    #[tokio::test]
    async fn backend_failure_is_retained_before_returning() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let journal = Arc::new(InMemoryWritableAgentStepJournal::default());
        let backend = Arc::new(ScriptedWritableBackend::new(
            ScriptedBackendMode::BackendFailure,
        ));
        let step =
            WritableAgentStep::new(backend, model_id(), journal.clone(), None).expect("step");
        let write_grant = grant(&worktree);

        let error = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("backend failure must propagate");
        assert!(matches!(error, WritableAgentStepError::Backend(_)));
        assert_eq!(
            journal
                .snapshot()
                .expect("journal")
                .iter()
                .map(|entry| entry.entry.record.boundary())
                .collect::<Vec<_>>(),
            vec![
                WritableAgentStepBoundaryV1::ModelPrepared,
                WritableAgentStepBoundaryV1::ModelFailed,
            ]
        );
        worktree.release().expect("cleanup");
    }

    #[tokio::test]
    async fn grant_cannot_be_replayed_against_another_worktree() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut granted_worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("first");
        let mut substituted_worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("second");
        let write_grant = grant(&granted_worktree);
        let journal = Arc::new(InMemoryWritableAgentStepJournal::default());
        let backend = Arc::new(ScriptedWritableBackend::new(ScriptedBackendMode::Exact));
        let step = WritableAgentStep::new(backend.clone(), model_id(), journal.clone(), None)
            .expect("step");

        let error = step
            .run(
                &mut substituted_worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("cross-worktree replay must fail");
        assert!(matches!(error, WritableAgentStepError::InvalidAuthority(_)));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert!(journal.snapshot().expect("journal").is_empty());
        granted_worktree.release().expect("first cleanup");
        substituted_worktree.release().expect("second cleanup");
    }

    #[tokio::test]
    async fn dirty_worktree_is_rejected_before_model_dispatch() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let write_grant = grant(&worktree);
        fs::write(
            worktree.path().join("src/message.txt"),
            b"unattributed change\n",
        )
        .expect("dirty worktree");
        let journal = Arc::new(InMemoryWritableAgentStepJournal::default());
        let backend = Arc::new(ScriptedWritableBackend::new(ScriptedBackendMode::Exact));
        let step = WritableAgentStep::new(backend.clone(), model_id(), journal.clone(), None)
            .expect("step");

        let error = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("dirty worktree must fail");
        assert!(matches!(error, WritableAgentStepError::DirtyWorktree));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert!(journal.snapshot().expect("journal").is_empty());
        worktree.release().expect("cleanup");
    }

    #[tokio::test]
    async fn untracked_grant_target_is_rejected_before_model_dispatch() {
        let repository = repository_fixture();
        let scratch = tempfile::tempdir().expect("scratch");
        let mut worktree =
            TemporaryGitWorktree::create(repository.path(), scratch.path()).expect("worktree");
        let mut write_grant = grant(&worktree);
        write_grant.path = Utf8RepositoryPathV1 {
            components: vec!["src".to_owned(), "missing.txt".to_owned()],
        };
        write_grant.expected_preimage_sha256 = Sha256Digest::of_bytes(b"missing\n");
        let journal = Arc::new(InMemoryWritableAgentStepJournal::default());
        let backend = Arc::new(ScriptedWritableBackend::new(ScriptedBackendMode::Exact));
        let step = WritableAgentStep::new(backend.clone(), model_id(), journal.clone(), None)
            .expect("step");

        let error = step
            .run(
                &mut worktree,
                "Replace the application message.",
                write_grant,
            )
            .await
            .expect_err("untracked grant target must fail");
        assert!(matches!(
            error,
            WritableAgentStepError::GrantTargetNotTracked
        ));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert!(journal.snapshot().expect("journal").is_empty());
        worktree.release().expect("cleanup");
    }
}
