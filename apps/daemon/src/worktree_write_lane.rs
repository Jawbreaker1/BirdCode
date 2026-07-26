//! Model-free, single-effect worktree write lane.
//!
//! The semantic agent chooses a typed action elsewhere. This module owns only
//! mechanical authority checks, the prepared filesystem boundary, exact
//! artifact retention, a terminal one-write state machine, and delayed
//! cleanup. A successful mutation remains available for the next model turn;
//! cleanup is permitted only after the caller has validated a Finish action.

use birdcode_orchestrator::{
    WorkspaceAccess, WorkspaceGrant, WorkspaceLeaseId, WorkspaceSourceBinding,
};
use birdcode_protocol::{
    ArtifactRef, ChildExecutionBinding, ChildLocalPlanBindingV1, ChildLocalPlanStepIdV1,
    ChildModelCallId, ChildToolCallId, EventId, RepositoryRelativePathV1, RepositoryToolGrantId,
    Sha256Digest,
};
use birdcode_workspace::{
    ArtifactBoundary, CanonicalArtifactBoundary, GIT_WORKTREE_DIFF_MEDIA_TYPE,
    GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES, GitWorktreeFileReplaceError,
    GitWorktreeMutationIoOperation, GitWorktreeUtf8FileReplacePreparedV1,
    GitWorktreeUtf8FileReplaceRequestV1, GitWorktreeUtf8FileReplaceResultV1, RetainedArtifact,
    TemporaryGitWorktree, TemporaryGitWorktreeError,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const WORKTREE_WRITE_LANE_V1_CONTRACT_VERSION: u32 = 1;

use crate::repository_candidate::{
    REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE, RepositoryCandidatePublicationDocumentV1,
    RepositoryCandidatePublicationV1,
};
const FILE_REPLACE_PREPARED_MEDIA_TYPE: &str =
    "application/vnd.birdcode.worktree-file-replace-prepared.v1+json";
const FILE_REPLACE_RESULT_MEDIA_TYPE: &str =
    "application/vnd.birdcode.worktree-file-replace-result.v1+json";
const FILE_REPLACE_UNKNOWN_MEDIA_TYPE: &str =
    "application/vnd.birdcode.worktree-file-replace-unknown.v1+json";
pub const WORKTREE_RELEASE_OBSERVATION_V1_MEDIA_TYPE: &str =
    "application/vnd.birdcode.worktree-release-observation.v1+json";

/// Runtime-authored provenance for the already validated implementation
/// action. The action bytes remain authoritative through `action_artifact`;
/// this lane never reparses natural language or chooses a tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorktreeWriteOriginV1 {
    pub binding: ChildExecutionBinding,
    pub source_model_call_id: ChildModelCallId,
    pub source_model_call_ordinal: u32,
    pub source_model_observed_event_id: EventId,
    pub source_plan: ChildLocalPlanBindingV1,
    pub active_plan_step_id: ChildLocalPlanStepIdV1,
    pub validated_action_event_id: EventId,
    pub action_artifact: ArtifactRef,
    pub tool_call_id: ChildToolCallId,
    pub tool_ordinal: u32,
}

/// Exact daemon-minted authority for one replacement in one isolated
/// worktree. It is deliberately distinct from read-only repository grants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactReplaceUtf8FileGrantV1 {
    pub grant_id: RepositoryToolGrantId,
    pub binding: ChildExecutionBinding,
    pub workspace_lease_id: WorkspaceLeaseId,
    pub workspace_access: WorkspaceAccess,
    pub base_snapshot_sha256: Sha256Digest,
    pub git_baseline_sha256: Sha256Digest,
    pub worktree_id: Uuid,
    pub base_commit: String,
    pub path: RepositoryRelativePathV1,
    pub expected_preimage_sha256: Sha256Digest,
    pub max_content_bytes: u64,
}

/// Trusted receipt linking the immutable workspace snapshot used for reads to
/// the daemon-owned Git baseline used for edits. Producing this receipt is a
/// workspace-materialization responsibility; the write lane only verifies and
/// repeats the exact binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitBaselineMaterializationV1 {
    pub workspace_lease_id: WorkspaceLeaseId,
    pub source_snapshot_sha256: Sha256Digest,
    pub git_baseline_sha256: Sha256Digest,
    pub base_commit: String,
    pub worktree_id: Uuid,
    pub materialization_event_id: EventId,
    pub receipt_artifact: ArtifactRef,
}

/// Runtime-normalized request derived losslessly from one model action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactReplaceUtf8FileRequestV1 {
    pub grant_id: RepositoryToolGrantId,
    pub binding: ChildExecutionBinding,
    pub worktree_id: Uuid,
    pub base_commit: String,
    pub path: RepositoryRelativePathV1,
    pub expected_preimage_sha256: Sha256Digest,
    pub content_utf8: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorktreeWriteLanePhaseV1 {
    Ready,
    EffectInFlight,
    Written,
    ReconciliationRequired,
    CleanupInFlight,
    Released,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorktreeWriteLaneJournalRecordV1 {
    FileReplacePrepared {
        origin: WorktreeWriteOriginV1,
        grant: ExactReplaceUtf8FileGrantV1,
        materialization: GitBaselineMaterializationV1,
        source_repository: PathBuf,
        worktree_path: PathBuf,
        prepared: GitWorktreeUtf8FileReplacePreparedV1,
        content_artifact: ArtifactRef,
    },
    FileReplaceObserved {
        binding: ChildExecutionBinding,
        tool_call_id: ChildToolCallId,
        prepared_event_id: EventId,
        result: GitWorktreeUtf8FileReplaceResultV1,
    },
    FileReplaceOutcomeUnknown {
        binding: ChildExecutionBinding,
        tool_call_id: ChildToolCallId,
        prepared_event_id: EventId,
        operation: Option<GitWorktreeMutationIoOperation>,
        raw_os_error: Option<i32>,
        evidence_artifact: ArtifactRef,
    },
    GitDiffObserved {
        binding: ChildExecutionBinding,
        tool_call_id: ChildToolCallId,
        replace_event_id: EventId,
        base_commit: String,
        changed_paths: Vec<RepositoryRelativePathV1>,
        diff_artifact: ArtifactRef,
    },
    WorktreeCleanupPrepared {
        binding: ChildExecutionBinding,
        publication: RepositoryCandidatePublicationDocumentV1,
        publication_receipt_artifact: ArtifactRef,
        diff_event_id: EventId,
        worktree_id: Uuid,
    },
    WorktreeCleanupObserved {
        binding: ChildExecutionBinding,
        prepared_event_id: EventId,
        worktree_id: Uuid,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeWriteLaneJournalEntryV1 {
    pub record: WorktreeWriteLaneJournalRecordV1,
    pub artifacts: Vec<RetainedArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeWriteLaneJournalError {
    message: String,
}

impl WorktreeWriteLaneJournalError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for WorktreeWriteLaneJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WorktreeWriteLaneJournalError {}

pub trait WorktreeWriteLaneJournal: Send + Sync {
    /// Durably retains an exact boundary before the lane crosses the next
    /// effect.
    ///
    /// # Errors
    ///
    /// Returns an error unless the complete entry has been acknowledged.
    fn retain(
        &self,
        entry: WorktreeWriteLaneJournalEntryV1,
    ) -> Result<EventId, WorktreeWriteLaneJournalError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedWorktreeWriteLaneJournalEntryV1 {
    pub event_id: EventId,
    pub entry: WorktreeWriteLaneJournalEntryV1,
}

#[derive(Debug, Default)]
pub struct InMemoryWorktreeWriteLaneJournal {
    entries: Mutex<Vec<RetainedWorktreeWriteLaneJournalEntryV1>>,
}

impl InMemoryWorktreeWriteLaneJournal {
    /// Returns retained entries in acknowledgement order.
    ///
    /// # Errors
    ///
    /// Returns an error if the journal lock is poisoned.
    pub fn snapshot(
        &self,
    ) -> Result<Vec<RetainedWorktreeWriteLaneJournalEntryV1>, WorktreeWriteLaneJournalError> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .map_err(|_| WorktreeWriteLaneJournalError::new("write-lane journal lock poisoned"))
    }
}

impl WorktreeWriteLaneJournal for InMemoryWorktreeWriteLaneJournal {
    fn retain(
        &self,
        entry: WorktreeWriteLaneJournalEntryV1,
    ) -> Result<EventId, WorktreeWriteLaneJournalError> {
        if entry
            .artifacts
            .iter()
            .any(|artifact| !artifact_is_exact(artifact))
        {
            return Err(WorktreeWriteLaneJournalError::new(
                "write-lane journal rejected an inexact artifact",
            ));
        }
        let event_id = EventId::new();
        self.entries
            .lock()
            .map_err(|_| WorktreeWriteLaneJournalError::new("write-lane journal lock poisoned"))?
            .push(RetainedWorktreeWriteLaneJournalEntryV1 { event_id, entry });
        Ok(event_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedSingleWriteV1 {
    pub origin: WorktreeWriteOriginV1,
    pub mutation: GitWorktreeUtf8FileReplaceResultV1,
    pub replace_event_id: EventId,
    pub diff_event_id: EventId,
    pub postimage_artifact: RetainedArtifact,
    pub diff_artifact: RetainedArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorktreeReleaseObservationDocumentV1 {
    contract_version: u32,
    binding: ChildExecutionBinding,
    worktree_id: Uuid,
    cleanup_prepared_event_id: EventId,
    cleanup_observed_event_id: EventId,
    publication_event_id: EventId,
    publication_receipt_artifact: ArtifactRef,
    candidate_sha256: Sha256Digest,
    diff_event_id: EventId,
}

/// Lane-issued proof that cleanup was durably observed for the exact
/// publication that authorized release. Private fields prevent callers from
/// substituting a naked event ID for the complete causal receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeReleaseObservationV1 {
    document: WorktreeReleaseObservationDocumentV1,
    receipt_artifact: RetainedArtifact,
}

impl WorktreeReleaseObservationV1 {
    #[must_use]
    pub const fn binding(&self) -> &ChildExecutionBinding {
        &self.document.binding
    }

    #[must_use]
    pub const fn worktree_id(&self) -> Uuid {
        self.document.worktree_id
    }

    #[must_use]
    pub const fn cleanup_prepared_event_id(&self) -> EventId {
        self.document.cleanup_prepared_event_id
    }

    #[must_use]
    pub const fn cleanup_observed_event_id(&self) -> EventId {
        self.document.cleanup_observed_event_id
    }

    #[must_use]
    pub const fn publication_event_id(&self) -> EventId {
        self.document.publication_event_id
    }

    #[must_use]
    pub const fn publication_receipt_artifact(&self) -> &ArtifactRef {
        &self.document.publication_receipt_artifact
    }

    #[must_use]
    pub const fn candidate_sha256(&self) -> &Sha256Digest {
        &self.document.candidate_sha256
    }

    #[must_use]
    pub const fn diff_event_id(&self) -> EventId {
        self.document.diff_event_id
    }

    #[must_use]
    pub const fn receipt_artifact(&self) -> &RetainedArtifact {
        &self.receipt_artifact
    }

    /// Verifies the complete retained receipt against the sealed publication
    /// that authorized cleanup.
    ///
    /// # Errors
    ///
    /// Rejects an inexact receipt artifact, invalid publication, or any
    /// substituted execution, candidate, publication, diff, or event binding.
    pub fn validate(
        &self,
        publication: &RepositoryCandidatePublicationV1,
    ) -> Result<(), WorktreeWriteLaneError> {
        publication.validate().map_err(|_| {
            WorktreeWriteLaneError::InvalidReleaseReceipt(
                "candidate publication failed exact validation",
            )
        })?;
        let publication_document = publication.document();
        let encoded =
            serde_json::to_vec(&self.document).map_err(|_| WorktreeWriteLaneError::Encoding)?;
        if self.document.contract_version != WORKTREE_WRITE_LANE_V1_CONTRACT_VERSION
            || self.document.worktree_id.is_nil()
            || self.document.cleanup_prepared_event_id == self.document.cleanup_observed_event_id
            || !artifact_is_exact(&self.receipt_artifact)
            || self.receipt_artifact.artifact.media_type
                != WORKTREE_RELEASE_OBSERVATION_V1_MEDIA_TYPE
            || self.receipt_artifact.bytes != encoded
            || self.document.binding != publication_document.producer_binding
            || self.document.publication_event_id != publication.published_event_id()
            || self.document.publication_receipt_artifact != publication.receipt_artifact().artifact
            || &self.document.candidate_sha256 != publication.candidate_sha256()
            || self.document.diff_event_id != publication_document.change.diff_event_id
        {
            return Err(WorktreeWriteLaneError::InvalidReleaseReceipt(
                "receipt does not bind the exact cleanup-authorizing publication",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorktreeWriteLaneError {
    #[error("write-lane authority is invalid: {0}")]
    InvalidAuthority(&'static str),
    #[error("write lane is in phase {0:?} and cannot perform the requested transition")]
    InvalidPhase(WorktreeWriteLanePhaseV1),
    #[error("write-lane state lock is poisoned")]
    LockPoisoned,
    #[error("write-lane artifact encoding failed")]
    Encoding,
    #[error("worktree release receipt is invalid: {0}")]
    InvalidReleaseReceipt(&'static str),
    #[error("write-lane journal failed: {0}")]
    Journal(#[from] WorktreeWriteLaneJournalError),
    #[error("worktree mutation failed: {0}")]
    Mutation(#[from] GitWorktreeFileReplaceError),
    #[error("worktree lifecycle failed: {0}")]
    Worktree(#[from] TemporaryGitWorktreeError),
    #[error("write lane requires a pristine worktree before its sole effect")]
    DirtyWorktree,
    #[error("write grant target is not a regular file tracked by the exact base commit")]
    GrantTargetNotTracked,
    #[error("write lane produced an empty tracked diff")]
    EmptyDiff,
    #[error("write lane observed tracked paths outside its exact grant")]
    UnexpectedChangedPaths,
    #[error("write lane observed an additional untracked or ignored file")]
    UnexpectedAdditionalFiles,
    #[error("worktree changed after its retained diff and before cleanup")]
    WorktreeChangedBeforeCleanup,
    #[error("prepared-boundary failure could not release the reserved writer lane: {0}")]
    PreparationCancellation(String),
    #[error("the effect boundary is terminal and requires reconciliation: {0}")]
    ReconciliationRequired(String),
}

#[derive(Clone, Debug)]
struct WrittenState {
    observed: ObservedSingleWriteV1,
}

#[derive(Debug)]
enum WorktreeWriteLaneState {
    Ready,
    EffectInFlight,
    Written(WrittenState),
    ReconciliationRequired,
    CleanupInFlight,
    Released,
}

impl WorktreeWriteLaneState {
    const fn phase(&self) -> WorktreeWriteLanePhaseV1 {
        match self {
            Self::Ready => WorktreeWriteLanePhaseV1::Ready,
            Self::EffectInFlight => WorktreeWriteLanePhaseV1::EffectInFlight,
            Self::Written(_) => WorktreeWriteLanePhaseV1::Written,
            Self::ReconciliationRequired => WorktreeWriteLanePhaseV1::ReconciliationRequired,
            Self::CleanupInFlight => WorktreeWriteLanePhaseV1::CleanupInFlight,
            Self::Released => WorktreeWriteLanePhaseV1::Released,
        }
    }
}

#[derive(Debug)]
struct WorktreeWriteLaneInner {
    worktree: TemporaryGitWorktree,
    state: WorktreeWriteLaneState,
}

/// Exclusive, model-free lane for exactly one existing-file replacement.
pub struct WorktreeWriteLane<J: WorktreeWriteLaneJournal + ?Sized> {
    grant: ExactReplaceUtf8FileGrantV1,
    materialization: GitBaselineMaterializationV1,
    journal: Arc<J>,
    inner: Mutex<WorktreeWriteLaneInner>,
}

impl<J: WorktreeWriteLaneJournal + ?Sized> WorktreeWriteLane<J> {
    /// Seals one exact daemon-minted grant into the lane before it can accept
    /// a model-derived request.
    ///
    /// # Errors
    ///
    /// Rejects a non-write grant, invalid limit, or substituted worktree.
    pub fn new(
        worktree: TemporaryGitWorktree,
        grant: ExactReplaceUtf8FileGrantV1,
        workspace_authority: &WorkspaceGrant,
        materialization: GitBaselineMaterializationV1,
        journal: Arc<J>,
    ) -> Result<Self, WorktreeWriteLaneError> {
        validate_sealed_grant(&grant, workspace_authority, &materialization, &worktree)?;
        Ok(Self {
            grant,
            materialization,
            journal,
            inner: Mutex::new(WorktreeWriteLaneInner {
                worktree,
                state: WorktreeWriteLaneState::Ready,
            }),
        })
    }

    #[must_use]
    pub const fn grant(&self) -> &ExactReplaceUtf8FileGrantV1 {
        &self.grant
    }

    /// Returns the current closed lifecycle phase.
    ///
    /// # Errors
    ///
    /// Returns an error if the state lock is poisoned.
    pub fn phase(&self) -> Result<WorktreeWriteLanePhaseV1, WorktreeWriteLaneError> {
        self.inner
            .lock()
            .map(|inner| inner.state.phase())
            .map_err(|_| WorktreeWriteLaneError::LockPoisoned)
    }

    /// Returns the exact owned worktree path for lifecycle observation.
    ///
    /// # Errors
    ///
    /// Returns an error if the state lock is poisoned.
    pub fn worktree_path(&self) -> Result<PathBuf, WorktreeWriteLaneError> {
        self.inner
            .lock()
            .map(|inner| inner.worktree.path().to_path_buf())
            .map_err(|_| WorktreeWriteLaneError::LockPoisoned)
    }

    /// Executes the lane's sole authorized replacement and retains its exact
    /// diff without releasing the worktree.
    ///
    /// # Errors
    ///
    /// Fails closed on authority mismatch, prior lane use, any preparation or
    /// mutation error, anomalous worktree state, or journal failure. Every
    /// failure after execution begins makes the lane terminal and non-retryable.
    pub fn execute_once(
        &self,
        origin: WorktreeWriteOriginV1,
        request: ExactReplaceUtf8FileRequestV1,
    ) -> Result<ObservedSingleWriteV1, WorktreeWriteLaneError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WorktreeWriteLaneError::LockPoisoned)?;
        if !matches!(inner.state, WorktreeWriteLaneState::Ready) {
            return Err(WorktreeWriteLaneError::InvalidPhase(inner.state.phase()));
        }
        validate_authority(&origin, &self.grant, &request, &inner.worktree)?;
        if !inner.worktree.is_pristine()? {
            return Err(WorktreeWriteLaneError::DirtyWorktree);
        }
        if !inner
            .worktree
            .base_commit_tracks_regular_file(&self.grant.path)?
        {
            return Err(WorktreeWriteLaneError::GrantTargetNotTracked);
        }
        let prepared =
            inner
                .worktree
                .prepare_utf8_file_replace(GitWorktreeUtf8FileReplaceRequestV1 {
                    path: request.path,
                    expected_preimage_sha256: request.expected_preimage_sha256,
                    replacement_utf8: request.content_utf8.clone(),
                    max_replacement_bytes: self.grant.max_content_bytes,
                })?;
        let content_artifact = retain_bytes(
            REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE,
            request.content_utf8.into_bytes(),
        )?;
        let prepared_artifact = retain_json(FILE_REPLACE_PREPARED_MEDIA_TYPE, prepared.receipt())?;
        let prepared_event_id = match self.retain(
            WorktreeWriteLaneJournalRecordV1::FileReplacePrepared {
                origin: origin.clone(),
                grant: self.grant.clone(),
                materialization: self.materialization.clone(),
                source_repository: inner.worktree.source_repository().to_path_buf(),
                worktree_path: inner.worktree.path().to_path_buf(),
                prepared: prepared.receipt().clone(),
                content_artifact: content_artifact.artifact.clone(),
            },
            vec![content_artifact.clone(), prepared_artifact],
        ) {
            Ok(event_id) => event_id,
            Err(error) => {
                if let Err(cancel_error) =
                    inner.worktree.cancel_prepared_utf8_file_replace(&prepared)
                {
                    inner.state = WorktreeWriteLaneState::ReconciliationRequired;
                    return Err(WorktreeWriteLaneError::PreparationCancellation(
                        cancel_error.to_string(),
                    ));
                }
                return Err(error);
            }
        };

        inner.worktree.preserve_on_drop_for_reconciliation();
        inner.state = WorktreeWriteLaneState::EffectInFlight;
        let mutation = match inner.worktree.execute_prepared_utf8_file_replace(&prepared) {
            Ok(result) => result,
            Err(error) => {
                inner.state = WorktreeWriteLaneState::ReconciliationRequired;
                if error.may_have_mutated() {
                    let (operation, raw_os_error) = unknown_boundary(&error);
                    let evidence = retain_json(
                        FILE_REPLACE_UNKNOWN_MEDIA_TYPE,
                        &FileReplaceUnknownEvidenceV1 {
                            contract_version: WORKTREE_WRITE_LANE_V1_CONTRACT_VERSION,
                            binding: origin.binding.clone(),
                            tool_call_id: origin.tool_call_id,
                            prepared_event_id,
                            operation,
                            raw_os_error,
                            message: error.to_string(),
                        },
                    );
                    if let Ok(evidence) = evidence {
                        let _ = self.retain(
                            WorktreeWriteLaneJournalRecordV1::FileReplaceOutcomeUnknown {
                                binding: origin.binding.clone(),
                                tool_call_id: origin.tool_call_id,
                                prepared_event_id,
                                operation,
                                raw_os_error,
                                evidence_artifact: evidence.artifact.clone(),
                            },
                            vec![evidence],
                        );
                    }
                }
                return Err(WorktreeWriteLaneError::ReconciliationRequired(
                    error.to_string(),
                ));
            }
        };
        let result_artifact = retain_json(FILE_REPLACE_RESULT_MEDIA_TYPE, &mutation)
            .map_err(|error| reconcile(&mut inner.state, error))?;
        let replace_event_id = self
            .retain(
                WorktreeWriteLaneJournalRecordV1::FileReplaceObserved {
                    binding: origin.binding.clone(),
                    tool_call_id: origin.tool_call_id,
                    prepared_event_id,
                    result: mutation.clone(),
                },
                vec![result_artifact],
            )
            .map_err(|error| reconcile(&mut inner.state, error))?;
        let diff = inner
            .worktree
            .tracked_diff()
            .map_err(|error| reconcile(&mut inner.state, error))?;
        if diff.bytes.is_empty() {
            inner.state = WorktreeWriteLaneState::ReconciliationRequired;
            return Err(WorktreeWriteLaneError::ReconciliationRequired(
                WorktreeWriteLaneError::EmptyDiff.to_string(),
            ));
        }
        if diff.changed_paths.len() != 1 || diff.changed_paths.first() != Some(&mutation.path) {
            inner.state = WorktreeWriteLaneState::ReconciliationRequired;
            return Err(WorktreeWriteLaneError::ReconciliationRequired(
                WorktreeWriteLaneError::UnexpectedChangedPaths.to_string(),
            ));
        }
        if inner
            .worktree
            .has_untracked_or_ignored_files()
            .map_err(|error| reconcile(&mut inner.state, error))?
        {
            inner.state = WorktreeWriteLaneState::ReconciliationRequired;
            return Err(WorktreeWriteLaneError::ReconciliationRequired(
                WorktreeWriteLaneError::UnexpectedAdditionalFiles.to_string(),
            ));
        }
        let diff_artifact = retain_bytes(GIT_WORKTREE_DIFF_MEDIA_TYPE, diff.bytes)
            .map_err(|error| reconcile(&mut inner.state, error))?;
        let diff_event_id = self
            .retain(
                WorktreeWriteLaneJournalRecordV1::GitDiffObserved {
                    binding: origin.binding.clone(),
                    tool_call_id: origin.tool_call_id,
                    replace_event_id,
                    base_commit: diff.base_commit,
                    changed_paths: diff.changed_paths,
                    diff_artifact: diff_artifact.artifact.clone(),
                },
                vec![diff_artifact.clone()],
            )
            .map_err(|error| reconcile(&mut inner.state, error))?;
        let observed = ObservedSingleWriteV1 {
            origin,
            mutation,
            replace_event_id,
            diff_event_id,
            postimage_artifact: content_artifact,
            diff_artifact,
        };
        validate_retained_worktree_state(&inner.worktree, &observed)
            .map_err(|error| reconcile(&mut inner.state, error))?;
        inner.state = WorktreeWriteLaneState::Written(WrittenState {
            observed: observed.clone(),
        });
        Ok(observed)
    }

    /// Releases the retained worktree only after its immutable candidate has
    /// been durably published from an independently validated Finish action.
    ///
    /// # Errors
    ///
    /// Rejects a substituted execution or every phase other than `Written`.
    /// Cleanup failures make the lane terminal and require reconciliation.
    pub fn release_after_candidate_published(
        &self,
        binding: &ChildExecutionBinding,
        publication: &RepositoryCandidatePublicationV1,
    ) -> Result<WorktreeReleaseObservationV1, WorktreeWriteLaneError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WorktreeWriteLaneError::LockPoisoned)?;
        let WorktreeWriteLaneState::Written(written) = &inner.state else {
            return Err(WorktreeWriteLaneError::InvalidPhase(inner.state.phase()));
        };
        if &written.observed.origin.binding != binding {
            return Err(WorktreeWriteLaneError::InvalidAuthority(
                "finish binding does not own the written worktree",
            ));
        }
        let expected = written.observed.clone();
        validate_candidate_publication(
            publication,
            binding,
            &self.grant,
            &self.materialization,
            &expected,
        )?;
        validate_retained_worktree_state(&inner.worktree, &expected)
            .map_err(|error| reconcile(&mut inner.state, error))?;
        let diff_event_id = expected.diff_event_id;
        let worktree_id = inner.worktree.worktree_id();
        let prepared_event_id = self.retain(
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared {
                binding: binding.clone(),
                publication: publication.document().clone(),
                publication_receipt_artifact: publication.receipt_artifact().artifact.clone(),
                diff_event_id,
                worktree_id,
            },
            vec![publication.receipt_artifact().clone()],
        )?;
        validate_retained_worktree_state(&inner.worktree, &expected)
            .map_err(|error| reconcile(&mut inner.state, error))?;
        inner.state = WorktreeWriteLaneState::CleanupInFlight;
        if let Err(error) = inner.worktree.release() {
            inner.state = WorktreeWriteLaneState::ReconciliationRequired;
            return Err(WorktreeWriteLaneError::ReconciliationRequired(
                error.to_string(),
            ));
        }
        let cleanup_observed_event_id = match self.retain(
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved {
                binding: binding.clone(),
                prepared_event_id,
                worktree_id,
            },
            Vec::new(),
        ) {
            Ok(event_id) => event_id,
            Err(error) => {
                inner.state = WorktreeWriteLaneState::ReconciliationRequired;
                return Err(WorktreeWriteLaneError::ReconciliationRequired(
                    error.to_string(),
                ));
            }
        };
        let release = seal_release_observation(
            publication,
            worktree_id,
            prepared_event_id,
            cleanup_observed_event_id,
        )
        .map_err(|error| reconcile(&mut inner.state, error))?;
        inner.state = WorktreeWriteLaneState::Released;
        Ok(release)
    }

    fn retain(
        &self,
        record: WorktreeWriteLaneJournalRecordV1,
        artifacts: Vec<RetainedArtifact>,
    ) -> Result<EventId, WorktreeWriteLaneError> {
        if artifacts
            .iter()
            .any(|artifact| !artifact_is_exact(artifact))
        {
            return Err(WorktreeWriteLaneError::Encoding);
        }
        self.journal
            .retain(WorktreeWriteLaneJournalEntryV1 { record, artifacts })
            .map_err(WorktreeWriteLaneError::Journal)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FileReplaceUnknownEvidenceV1 {
    contract_version: u32,
    binding: ChildExecutionBinding,
    tool_call_id: ChildToolCallId,
    prepared_event_id: EventId,
    operation: Option<GitWorktreeMutationIoOperation>,
    raw_os_error: Option<i32>,
    message: String,
}

fn validate_sealed_grant(
    grant: &ExactReplaceUtf8FileGrantV1,
    workspace_authority: &WorkspaceGrant,
    materialization: &GitBaselineMaterializationV1,
    worktree: &TemporaryGitWorktree,
) -> Result<(), WorktreeWriteLaneError> {
    let WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
        git_baseline_sha256,
    } = &workspace_authority.source
    else {
        return Err(WorktreeWriteLaneError::InvalidAuthority(
            "write workspace authority requires a clean committed-HEAD Git baseline",
        ));
    };
    let authority_baseline = Sha256Digest::parse(git_baseline_sha256.clone()).map_err(|_| {
        WorktreeWriteLaneError::InvalidAuthority(
            "workspace authority has an invalid Git baseline digest",
        )
    })?;
    if workspace_authority.access != WorkspaceAccess::Write
        || grant.workspace_access != workspace_authority.access
        || grant.workspace_lease_id != workspace_authority.lease_id
        || materialization.workspace_lease_id != workspace_authority.lease_id
        || grant.base_snapshot_sha256 != materialization.source_snapshot_sha256
        || grant.git_baseline_sha256 != authority_baseline
        || grant.git_baseline_sha256 != materialization.git_baseline_sha256
        || worktree.git_baseline_sha256() != &materialization.git_baseline_sha256
        || materialization.base_commit != worktree.base_commit()
        || materialization.worktree_id != worktree.worktree_id()
        || grant.worktree_id != worktree.worktree_id()
        || grant.base_commit != worktree.base_commit()
        || Sha256Digest::parse(materialization.receipt_artifact.sha256.clone()).is_err()
        || materialization.receipt_artifact.size_bytes == 0
    {
        return Err(WorktreeWriteLaneError::InvalidAuthority(
            "sealed grant does not match the trusted workspace lease or worktree",
        ));
    }
    if grant.max_content_bytes == 0
        || grant.max_content_bytes > GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES
    {
        return Err(WorktreeWriteLaneError::InvalidAuthority(
            "content ceiling is outside the hard write profile",
        ));
    }
    Ok(())
}

fn validate_authority(
    origin: &WorktreeWriteOriginV1,
    grant: &ExactReplaceUtf8FileGrantV1,
    request: &ExactReplaceUtf8FileRequestV1,
    worktree: &TemporaryGitWorktree,
) -> Result<(), WorktreeWriteLaneError> {
    if origin.binding != grant.binding
        || request.binding != grant.binding
        || request.grant_id != grant.grant_id
        || request.worktree_id != grant.worktree_id
        || request.base_commit != grant.base_commit
        || request.path != grant.path
        || request.expected_preimage_sha256 != grant.expected_preimage_sha256
        || grant.worktree_id != worktree.worktree_id()
        || grant.base_commit != worktree.base_commit()
    {
        return Err(WorktreeWriteLaneError::InvalidAuthority(
            "request, grant, execution and worktree bindings differ",
        ));
    }
    if origin.tool_ordinal == 0
        || origin.source_model_call_ordinal == 0
        || Sha256Digest::parse(origin.action_artifact.sha256.clone()).is_err()
        || origin.action_artifact.size_bytes == 0
        || !u64::try_from(request.content_utf8.len())
            .is_ok_and(|size| size <= grant.max_content_bytes)
    {
        return Err(WorktreeWriteLaneError::InvalidAuthority(
            "action provenance or replacement size is invalid",
        ));
    }
    Ok(())
}

fn validate_candidate_publication(
    publication: &RepositoryCandidatePublicationV1,
    binding: &ChildExecutionBinding,
    grant: &ExactReplaceUtf8FileGrantV1,
    materialization: &GitBaselineMaterializationV1,
    observed: &ObservedSingleWriteV1,
) -> Result<(), WorktreeWriteLaneError> {
    publication.validate().map_err(|_| {
        WorktreeWriteLaneError::InvalidAuthority(
            "candidate publication receipt failed exact validation",
        )
    })?;
    let document = publication.document();
    if &document.producer_binding != binding
        || document.baseline.workspace_lease_id != grant.workspace_lease_id
        || document.baseline.git_baseline_sha256 != grant.git_baseline_sha256
        || document.baseline.git_baseline_sha256 != materialization.git_baseline_sha256
        || document.baseline.base_commit != grant.base_commit
        || document.baseline.base_commit != materialization.base_commit
        || document.change.path != grant.path
        || document.change.path != observed.mutation.path
        || document.change.preimage != observed.mutation.preimage
        || document.change.postimage != observed.mutation.postimage
        || document.change.postimage_artifact != observed.postimage_artifact.artifact
        || document.change.diff_artifact != observed.diff_artifact.artifact
        || document.change.replace_event_id != observed.replace_event_id
        || document.change.diff_event_id != observed.diff_event_id
    {
        return Err(WorktreeWriteLaneError::InvalidAuthority(
            "candidate publication does not bind this exact write",
        ));
    }
    Ok(())
}

fn validate_retained_worktree_state(
    worktree: &TemporaryGitWorktree,
    expected: &ObservedSingleWriteV1,
) -> Result<(), WorktreeWriteLaneError> {
    let current_postimage = worktree.observe_utf8_file(&expected.mutation.path)?;
    let current_diff = worktree.tracked_diff()?;
    if current_postimage != expected.mutation.postimage
        || current_diff.base_commit != worktree.base_commit()
        || current_diff.sha256.as_str() != expected.diff_artifact.artifact.sha256
        || current_diff.bytes != expected.diff_artifact.bytes
        || current_diff.changed_paths.as_slice() != [expected.mutation.path.clone()]
        || worktree.has_untracked_or_ignored_files()?
    {
        return Err(WorktreeWriteLaneError::WorktreeChangedBeforeCleanup);
    }
    Ok(())
}

fn reconcile(
    state: &mut WorktreeWriteLaneState,
    error: impl fmt::Display,
) -> WorktreeWriteLaneError {
    *state = WorktreeWriteLaneState::ReconciliationRequired;
    WorktreeWriteLaneError::ReconciliationRequired(error.to_string())
}

fn unknown_boundary(
    error: &GitWorktreeFileReplaceError,
) -> (Option<GitWorktreeMutationIoOperation>, Option<i32>) {
    match error {
        GitWorktreeFileReplaceError::OutcomeUnknown {
            operation,
            raw_os_error,
        } => (Some(*operation), *raw_os_error),
        _ => (None, None),
    }
}

fn retain_json(
    media_type: &'static str,
    value: &impl Serialize,
) -> Result<RetainedArtifact, WorktreeWriteLaneError> {
    let bytes = serde_json::to_vec(value).map_err(|_| WorktreeWriteLaneError::Encoding)?;
    retain_bytes(media_type, bytes)
}

fn retain_bytes(
    media_type: &'static str,
    bytes: Vec<u8>,
) -> Result<RetainedArtifact, WorktreeWriteLaneError> {
    CanonicalArtifactBoundary
        .retain(media_type, bytes)
        .map_err(|_| WorktreeWriteLaneError::Encoding)
}

fn seal_release_observation(
    publication: &RepositoryCandidatePublicationV1,
    worktree_id: Uuid,
    cleanup_prepared_event_id: EventId,
    cleanup_observed_event_id: EventId,
) -> Result<WorktreeReleaseObservationV1, WorktreeWriteLaneError> {
    publication.validate().map_err(|_| {
        WorktreeWriteLaneError::InvalidReleaseReceipt(
            "candidate publication failed exact validation",
        )
    })?;
    let publication_document = publication.document();
    let document = WorktreeReleaseObservationDocumentV1 {
        contract_version: WORKTREE_WRITE_LANE_V1_CONTRACT_VERSION,
        binding: publication_document.producer_binding.clone(),
        worktree_id,
        cleanup_prepared_event_id,
        cleanup_observed_event_id,
        publication_event_id: publication.published_event_id(),
        publication_receipt_artifact: publication.receipt_artifact().artifact.clone(),
        candidate_sha256: publication.candidate_sha256().clone(),
        diff_event_id: publication_document.change.diff_event_id,
    };
    let receipt_artifact = retain_json(WORKTREE_RELEASE_OBSERVATION_V1_MEDIA_TYPE, &document)?;
    let release = WorktreeReleaseObservationV1 {
        document,
        receipt_artifact,
    };
    release.validate(publication)?;
    Ok(release)
}

/// Test-only minting boundary for repository-candidate unit tests. Production
/// callers can only obtain a release receipt from an owned write lane after
/// `WorktreeCleanupObserved` was durably acknowledged.
#[cfg(test)]
pub(crate) fn seal_test_release_observation(
    publication: &RepositoryCandidatePublicationV1,
    worktree_id: Uuid,
    cleanup_prepared_event_id: EventId,
    cleanup_observed_event_id: EventId,
) -> WorktreeReleaseObservationV1 {
    seal_release_observation(
        publication,
        worktree_id,
        cleanup_prepared_event_id,
        cleanup_observed_event_id,
    )
    .expect("test release observation must be exactly sealed")
}

fn artifact_is_exact(artifact: &RetainedArtifact) -> bool {
    artifact.artifact.sha256 == artifact.digest.as_str()
        && artifact.artifact.sha256 == Sha256Digest::of_bytes(&artifact.bytes).as_str()
        && artifact.artifact.size_bytes == u64::try_from(artifact.bytes.len()).unwrap_or(u64::MAX)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::repository_candidate::{
        REPOSITORY_CANDIDATE_V1_MEDIA_TYPE, RepositoryCandidateBaselineV1,
        RepositoryCandidateProducerLocatorV1, RepositoryCandidatePublicationDocumentV1,
        seal_test_publication,
    };
    use birdcode_orchestrator::{AgentAttemptId, ExecutionId, GraphActorId, WorkOrderId};
    use birdcode_protocol::{
        ChildActorId, ChildAttemptId, ChildContextId, ChildExecutionId, ChildLocalPlanId,
        ChildWorkOrderId,
    };
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    const PREIMAGE: &[u8] = b"product=BirdCode\nnonce=WING-7319\nstate=grounded\n";
    const POSTIMAGE: &str = "product=BirdCode\nnonce=WING-7319\nstate=flying\n";

    struct Fixture {
        repository: TempDir,
        scratch: TempDir,
        path: RepositoryRelativePathV1,
    }

    impl Fixture {
        fn new() -> Self {
            let repository = tempfile::tempdir().expect("repository tempdir");
            let scratch = tempfile::tempdir().expect("scratch tempdir");
            run_git(repository.path(), &["init", "-q"]);
            run_git(
                repository.path(),
                &["config", "user.email", "birdcode@example.invalid"],
            );
            run_git(
                repository.path(),
                &["config", "user.name", "BirdCode Tests"],
            );
            fs::create_dir_all(repository.path().join("src")).expect("create src");
            fs::write(repository.path().join("src/flight.txt"), PREIMAGE).expect("write target");
            fs::write(
                repository.path().join("src/unrelated.txt"),
                b"must remain unchanged\n",
            )
            .expect("write unrelated");
            fs::write(repository.path().join(".gitignore"), b".cache/\n").expect("write ignore");
            run_git(repository.path(), &["add", "."]);
            run_git(repository.path(), &["commit", "-qm", "fixture"]);
            Self {
                repository,
                scratch,
                path: RepositoryRelativePathV1::Unix {
                    components: vec![b"src".to_vec(), b"flight.txt".to_vec()],
                },
            }
        }

        fn worktree(&self) -> TemporaryGitWorktree {
            TemporaryGitWorktree::create(self.repository.path(), self.scratch.path())
                .expect("create worktree")
        }
    }

    fn run_git(repository: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .current_dir(repository)
            .args(arguments)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn binding() -> ChildExecutionBinding {
        ChildExecutionBinding {
            work_order_id: ChildWorkOrderId::new(),
            execution_id: ChildExecutionId::new(),
            attempt_id: ChildAttemptId::new(),
            child_actor_id: ChildActorId::new(),
            context_id: ChildContextId::new(),
            work_order_digest: Sha256Digest::of_bytes(b"work-order"),
            context_manifest_digest: Sha256Digest::of_bytes(b"context"),
        }
    }

    fn action_artifact() -> ArtifactRef {
        let bytes = b"canonical validated implementation action";
        ArtifactRef {
            sha256: Sha256Digest::of_bytes(bytes).as_str().to_owned(),
            size_bytes: u64::try_from(bytes.len()).expect("artifact size"),
            media_type: "application/vnd.birdcode.implementation-action.v1+json".to_owned(),
        }
    }

    fn origin(binding: &ChildExecutionBinding) -> WorktreeWriteOriginV1 {
        WorktreeWriteOriginV1 {
            binding: binding.clone(),
            source_model_call_id: ChildModelCallId::new(),
            source_model_call_ordinal: 2,
            source_model_observed_event_id: EventId::new(),
            source_plan: ChildLocalPlanBindingV1 {
                plan_id: ChildLocalPlanId::new(),
                revision: 2,
                plan_digest: Sha256Digest::of_bytes(b"plan-two"),
            },
            active_plan_step_id: ChildLocalPlanStepIdV1("implement".to_owned()),
            validated_action_event_id: EventId::new(),
            action_artifact: action_artifact(),
            tool_call_id: ChildToolCallId::new(),
            tool_ordinal: 2,
        }
    }

    fn grant(
        worktree: &TemporaryGitWorktree,
        binding: &ChildExecutionBinding,
        path: &RepositoryRelativePathV1,
    ) -> ExactReplaceUtf8FileGrantV1 {
        ExactReplaceUtf8FileGrantV1 {
            grant_id: RepositoryToolGrantId::new(),
            binding: binding.clone(),
            workspace_lease_id: WorkspaceLeaseId::new("implementation/test-lease")
                .expect("workspace lease"),
            workspace_access: WorkspaceAccess::Write,
            base_snapshot_sha256: Sha256Digest::of_bytes(b"source-snapshot"),
            git_baseline_sha256: worktree.git_baseline_sha256().clone(),
            worktree_id: worktree.worktree_id(),
            base_commit: worktree.base_commit().to_owned(),
            path: path.clone(),
            expected_preimage_sha256: Sha256Digest::of_bytes(PREIMAGE),
            max_content_bytes: 4_096,
        }
    }

    fn request(
        grant: &ExactReplaceUtf8FileGrantV1,
        content_utf8: &str,
    ) -> ExactReplaceUtf8FileRequestV1 {
        ExactReplaceUtf8FileRequestV1 {
            grant_id: grant.grant_id,
            binding: grant.binding.clone(),
            worktree_id: grant.worktree_id,
            base_commit: grant.base_commit.clone(),
            path: grant.path.clone(),
            expected_preimage_sha256: grant.expected_preimage_sha256.clone(),
            content_utf8: content_utf8.to_owned(),
        }
    }

    fn workspace_authority(grant: &ExactReplaceUtf8FileGrantV1) -> WorkspaceGrant {
        WorkspaceGrant {
            lease_id: grant.workspace_lease_id.clone(),
            source: WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
                git_baseline_sha256: grant.git_baseline_sha256.as_str().to_owned(),
            },
            access: WorkspaceAccess::Write,
        }
    }

    fn materialization(grant: &ExactReplaceUtf8FileGrantV1) -> GitBaselineMaterializationV1 {
        let receipt_bytes = b"accepted Git baseline materialization receipt";
        GitBaselineMaterializationV1 {
            workspace_lease_id: grant.workspace_lease_id.clone(),
            source_snapshot_sha256: grant.base_snapshot_sha256.clone(),
            git_baseline_sha256: grant.git_baseline_sha256.clone(),
            base_commit: grant.base_commit.clone(),
            worktree_id: grant.worktree_id,
            materialization_event_id: EventId::new(),
            receipt_artifact: ArtifactRef {
                sha256: Sha256Digest::of_bytes(receipt_bytes).as_str().to_owned(),
                size_bytes: u64::try_from(receipt_bytes.len()).expect("receipt size"),
                media_type: "application/vnd.birdcode.git-baseline-materialization.v1+json"
                    .to_owned(),
            },
        }
    }

    fn publication(
        grant: &ExactReplaceUtf8FileGrantV1,
        observed: &ObservedSingleWriteV1,
    ) -> RepositoryCandidatePublicationV1 {
        let manifest_bytes = b"test candidate manifest";
        seal_test_publication(RepositoryCandidatePublicationDocumentV1 {
            contract_version: crate::repository_candidate::REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
            published_event_id: EventId::new(),
            candidate_sha256: Sha256Digest::of_bytes(b"test candidate body"),
            candidate_manifest_artifact: ArtifactRef {
                sha256: Sha256Digest::of_bytes(manifest_bytes).as_str().to_owned(),
                size_bytes: u64::try_from(manifest_bytes.len()).expect("manifest size"),
                media_type: REPOSITORY_CANDIDATE_V1_MEDIA_TYPE.to_owned(),
            },
            producer: RepositoryCandidateProducerLocatorV1 {
                graph_sha256: Sha256Digest::of_bytes(b"test graph"),
                work_order_id: WorkOrderId::from_uuid(grant.binding.work_order_id.as_uuid()),
                actor_id: GraphActorId::from_uuid(grant.binding.child_actor_id.as_uuid()),
                execution_id: ExecutionId::from_uuid(grant.binding.execution_id.as_uuid()),
                attempt_id: AgentAttemptId::from_uuid(grant.binding.attempt_id.as_uuid()),
            },
            producer_binding: grant.binding.clone(),
            baseline: RepositoryCandidateBaselineV1 {
                workspace_lease_id: grant.workspace_lease_id.clone(),
                git_baseline_sha256: grant.git_baseline_sha256.clone(),
                base_commit: grant.base_commit.clone(),
            },
            change: crate::repository_candidate::ExactUtf8ReplaceCandidateV1 {
                path: observed.mutation.path.clone(),
                preimage: observed.mutation.preimage.clone(),
                postimage: observed.mutation.postimage.clone(),
                preimage_artifact: ArtifactRef {
                    sha256: observed.mutation.preimage.sha256.as_str().to_owned(),
                    size_bytes: observed.mutation.preimage.byte_len,
                    media_type: REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE.to_owned(),
                },
                postimage_artifact: observed.postimage_artifact.artifact.clone(),
                diff_artifact: observed.diff_artifact.artifact.clone(),
                replace_event_id: observed.replace_event_id,
                diff_event_id: observed.diff_event_id,
            },
        })
    }

    fn record_name(record: &WorktreeWriteLaneJournalRecordV1) -> &'static str {
        match record {
            WorktreeWriteLaneJournalRecordV1::FileReplacePrepared { .. } => "file_replace_prepared",
            WorktreeWriteLaneJournalRecordV1::FileReplaceObserved { .. } => "file_replace_observed",
            WorktreeWriteLaneJournalRecordV1::FileReplaceOutcomeUnknown { .. } => {
                "file_replace_outcome_unknown"
            }
            WorktreeWriteLaneJournalRecordV1::GitDiffObserved { .. } => "git_diff_observed",
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared { .. } => {
                "worktree_cleanup_prepared"
            }
            WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved { .. } => {
                "worktree_cleanup_observed"
            }
        }
    }

    #[test]
    fn exact_write_retains_worktree_until_finish_then_releases_it() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let worktree_path = worktree.path().to_path_buf();
        let binding = binding();
        let grant = grant(&worktree, &binding, &fixture.path);
        let journal = Arc::new(InMemoryWorktreeWriteLaneJournal::default());
        let authority = workspace_authority(&grant);
        let lane = WorktreeWriteLane::new(
            worktree,
            grant.clone(),
            &authority,
            materialization(&grant),
            Arc::clone(&journal),
        )
        .expect("seal write lane");

        let observed = lane
            .execute_once(origin(&binding), request(&grant, POSTIMAGE))
            .expect("execute exact write");

        assert_eq!(
            lane.phase().expect("phase"),
            WorktreeWriteLanePhaseV1::Written
        );
        assert!(worktree_path.exists(), "worktree must survive for Finish");
        assert_eq!(
            fs::read(worktree_path.join("src/flight.txt")).expect("read postimage"),
            POSTIMAGE.as_bytes()
        );
        assert_eq!(
            fs::read(fixture.repository.path().join("src/flight.txt")).expect("read source"),
            PREIMAGE
        );
        assert_eq!(observed.mutation.path, fixture.path);
        assert_eq!(
            observed.mutation.postimage.sha256,
            Sha256Digest::of_bytes(POSTIMAGE.as_bytes())
        );
        assert!(!observed.diff_artifact.bytes.is_empty());

        let before_release = journal.snapshot().expect("journal snapshot");
        assert_eq!(
            before_release
                .iter()
                .map(|entry| record_name(&entry.entry.record))
                .collect::<Vec<_>>(),
            vec![
                "file_replace_prepared",
                "file_replace_observed",
                "git_diff_observed"
            ]
        );

        let publication = publication(&grant, &observed);
        let release = lane
            .release_after_candidate_published(&binding, &publication)
            .expect("release after validated Finish");
        assert_eq!(
            lane.phase().expect("phase"),
            WorktreeWriteLanePhaseV1::Released
        );
        assert!(!worktree_path.exists());
        let after_release = journal.snapshot().expect("journal snapshot");
        assert_eq!(
            after_release
                .iter()
                .map(|entry| record_name(&entry.entry.record))
                .collect::<Vec<_>>(),
            vec![
                "file_replace_prepared",
                "file_replace_observed",
                "git_diff_observed",
                "worktree_cleanup_prepared",
                "worktree_cleanup_observed"
            ]
        );
        let cleanup_prepared = &after_release[3];
        let cleanup_observed = &after_release[4];
        let WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved {
            prepared_event_id, ..
        } = &cleanup_observed.entry.record
        else {
            panic!("final event must observe cleanup")
        };
        assert_eq!(*prepared_event_id, cleanup_prepared.event_id);
        assert_eq!(release.binding(), &binding);
        assert_eq!(release.worktree_id(), grant.worktree_id);
        assert_eq!(
            release.cleanup_prepared_event_id(),
            cleanup_prepared.event_id
        );
        assert_eq!(
            release.cleanup_observed_event_id(),
            cleanup_observed.event_id
        );
        assert_eq!(
            release.publication_event_id(),
            publication.published_event_id()
        );
        assert_eq!(
            release.publication_receipt_artifact(),
            &publication.receipt_artifact().artifact
        );
        assert_eq!(release.candidate_sha256(), publication.candidate_sha256());
        assert_eq!(release.diff_event_id(), observed.diff_event_id);
        assert_eq!(
            release.receipt_artifact().artifact.media_type,
            WORKTREE_RELEASE_OBSERVATION_V1_MEDIA_TYPE
        );
        assert!(artifact_is_exact(release.receipt_artifact()));
        assert_eq!(
            serde_json::from_slice::<WorktreeReleaseObservationDocumentV1>(
                &release.receipt_artifact().bytes
            )
            .expect("release document decodes"),
            release.document
        );
        release
            .validate(&publication)
            .expect("release receipt validates exact publication");
    }

    #[test]
    fn publications_for_another_binding_or_diff_cannot_authorize_cleanup() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let worktree_path = worktree.path().to_path_buf();
        let owner_binding = binding();
        let grant = grant(&worktree, &owner_binding, &fixture.path);
        let journal = Arc::new(InMemoryWorktreeWriteLaneJournal::default());
        let authority = workspace_authority(&grant);
        let lane = WorktreeWriteLane::new(
            worktree,
            grant.clone(),
            &authority,
            materialization(&grant),
            Arc::clone(&journal),
        )
        .expect("seal write lane");
        let observed = lane
            .execute_once(origin(&owner_binding), request(&grant, POSTIMAGE))
            .expect("execute exact write");

        let other_binding = binding();
        let mut other_grant = grant.clone();
        other_grant.binding = other_binding;
        let foreign_binding_publication = publication(&other_grant, &observed);
        foreign_binding_publication
            .validate()
            .expect("foreign-binding publication remains exactly sealed");

        let mut other_diff = observed.clone();
        other_diff.diff_event_id = EventId::new();
        let foreign_diff_publication = publication(&grant, &other_diff);
        foreign_diff_publication
            .validate()
            .expect("foreign-diff publication remains exactly sealed");

        for foreign_publication in [&foreign_binding_publication, &foreign_diff_publication] {
            assert!(matches!(
                lane.release_after_candidate_published(&owner_binding, foreign_publication),
                Err(WorktreeWriteLaneError::InvalidAuthority(
                    "candidate publication does not bind this exact write"
                ))
            ));
        }
        assert_eq!(
            lane.phase().expect("phase"),
            WorktreeWriteLanePhaseV1::Written
        );
        assert!(
            worktree_path.exists(),
            "rejected cleanup must preserve worktree"
        );
        assert_eq!(
            fs::read(worktree_path.join("src/flight.txt")).expect("read retained postimage"),
            POSTIMAGE.as_bytes()
        );
        assert!(
            !journal
                .snapshot()
                .expect("journal snapshot")
                .iter()
                .any(|entry| matches!(
                    entry.entry.record,
                    WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared { .. }
                        | WorktreeWriteLaneJournalRecordV1::WorktreeCleanupObserved { .. }
                ))
        );
    }

    #[test]
    fn successful_lane_rejects_every_second_write() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let binding = binding();
        let grant = grant(&worktree, &binding, &fixture.path);
        let authority = workspace_authority(&grant);
        let lane = WorktreeWriteLane::new(
            worktree,
            grant.clone(),
            &authority,
            materialization(&grant),
            Arc::new(InMemoryWorktreeWriteLaneJournal::default()),
        )
        .expect("seal write lane");
        lane.execute_once(origin(&binding), request(&grant, POSTIMAGE))
            .expect("first write");

        let error = lane
            .execute_once(origin(&binding), request(&grant, POSTIMAGE))
            .expect_err("second write must fail");
        assert!(matches!(
            error,
            WorktreeWriteLaneError::InvalidPhase(WorktreeWriteLanePhaseV1::Written)
        ));
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RejectedBoundary {
        Prepared,
        Observed,
    }

    #[derive(Debug)]
    struct RejectOnceJournal {
        reject: Mutex<Option<RejectedBoundary>>,
        entries: Mutex<Vec<RetainedWorktreeWriteLaneJournalEntryV1>>,
    }

    impl RejectOnceJournal {
        fn new(boundary: RejectedBoundary) -> Self {
            Self {
                reject: Mutex::new(Some(boundary)),
                entries: Mutex::new(Vec::new()),
            }
        }
    }

    impl WorktreeWriteLaneJournal for RejectOnceJournal {
        fn retain(
            &self,
            entry: WorktreeWriteLaneJournalEntryV1,
        ) -> Result<EventId, WorktreeWriteLaneJournalError> {
            let boundary = match &entry.record {
                WorktreeWriteLaneJournalRecordV1::FileReplacePrepared { .. } => {
                    Some(RejectedBoundary::Prepared)
                }
                WorktreeWriteLaneJournalRecordV1::FileReplaceObserved { .. } => {
                    Some(RejectedBoundary::Observed)
                }
                _ => None,
            };
            let mut reject = self
                .reject
                .lock()
                .map_err(|_| WorktreeWriteLaneJournalError::new("reject lock poisoned"))?;
            if boundary.is_some() && *reject == boundary {
                *reject = None;
                return Err(WorktreeWriteLaneJournalError::new("injected rejection"));
            }
            drop(reject);
            let event_id = EventId::new();
            self.entries
                .lock()
                .map_err(|_| WorktreeWriteLaneJournalError::new("entries lock poisoned"))?
                .push(RetainedWorktreeWriteLaneJournalEntryV1 { event_id, entry });
            Ok(event_id)
        }
    }

    #[test]
    fn prepared_journal_failure_has_no_effect_and_releases_reservation() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let worktree_path = worktree.path().to_path_buf();
        let first_binding = binding();
        let first_grant = grant(&worktree, &first_binding, &fixture.path);
        let authority = workspace_authority(&first_grant);
        let lane = WorktreeWriteLane::new(
            worktree,
            first_grant.clone(),
            &authority,
            materialization(&first_grant),
            Arc::new(RejectOnceJournal::new(RejectedBoundary::Prepared)),
        )
        .expect("seal write lane");

        let error = lane
            .execute_once(origin(&first_binding), request(&first_grant, POSTIMAGE))
            .expect_err("prepared journal rejects");
        assert!(matches!(error, WorktreeWriteLaneError::Journal(_)));
        assert_eq!(
            lane.phase().expect("phase"),
            WorktreeWriteLanePhaseV1::Ready
        );
        assert_eq!(
            fs::read(worktree_path.join("src/flight.txt")).expect("read preimage"),
            PREIMAGE
        );

        lane.execute_once(origin(&first_binding), request(&first_grant, POSTIMAGE))
            .expect("reservation was cancelled and may be prepared once more");
    }

    #[test]
    fn post_effect_journal_failure_is_terminal_and_non_retryable() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let worktree_path = worktree.path().to_path_buf();
        let first_binding = binding();
        let first_grant = grant(&worktree, &first_binding, &fixture.path);
        let authority = workspace_authority(&first_grant);
        let lane = WorktreeWriteLane::new(
            worktree,
            first_grant.clone(),
            &authority,
            materialization(&first_grant),
            Arc::new(RejectOnceJournal::new(RejectedBoundary::Observed)),
        )
        .expect("seal write lane");

        let first = lane
            .execute_once(origin(&first_binding), request(&first_grant, POSTIMAGE))
            .expect_err("observed journal rejects after effect");
        assert!(matches!(
            first,
            WorktreeWriteLaneError::ReconciliationRequired(_)
        ));
        assert_eq!(
            lane.phase().expect("phase"),
            WorktreeWriteLanePhaseV1::ReconciliationRequired
        );
        assert_eq!(
            fs::read(worktree_path.join("src/flight.txt")).expect("read postimage"),
            POSTIMAGE.as_bytes()
        );
        assert!(matches!(
            lane.execute_once(origin(&first_binding), request(&first_grant, POSTIMAGE)),
            Err(WorktreeWriteLaneError::InvalidPhase(
                WorktreeWriteLanePhaseV1::ReconciliationRequired
            ))
        ));
    }

    #[derive(Debug)]
    struct AdditionalFileJournal {
        worktree_path: PathBuf,
        inner: InMemoryWorktreeWriteLaneJournal,
        ignored: bool,
    }

    impl WorktreeWriteLaneJournal for AdditionalFileJournal {
        fn retain(
            &self,
            entry: WorktreeWriteLaneJournalEntryV1,
        ) -> Result<EventId, WorktreeWriteLaneJournalError> {
            if matches!(
                entry.record,
                WorktreeWriteLaneJournalRecordV1::FileReplaceObserved { .. }
            ) {
                let target = if self.ignored {
                    self.worktree_path.join(".cache/unexpected.bin")
                } else {
                    self.worktree_path.join("src/unexpected.bin")
                };
                fs::create_dir_all(target.parent().expect("additional-file parent"))
                    .map_err(|error| WorktreeWriteLaneJournalError::new(error.to_string()))?;
                fs::write(target, b"unexpected")
                    .map_err(|error| WorktreeWriteLaneJournalError::new(error.to_string()))?;
            }
            self.inner.retain(entry)
        }
    }

    #[test]
    fn untracked_and_ignored_additions_quarantine_the_lane() {
        for ignored in [false, true] {
            let fixture = Fixture::new();
            let worktree = fixture.worktree();
            let worktree_path = worktree.path().to_path_buf();
            let binding = binding();
            let grant = grant(&worktree, &binding, &fixture.path);
            let authority = workspace_authority(&grant);
            let lane = WorktreeWriteLane::new(
                worktree,
                grant.clone(),
                &authority,
                materialization(&grant),
                Arc::new(AdditionalFileJournal {
                    worktree_path,
                    inner: InMemoryWorktreeWriteLaneJournal::default(),
                    ignored,
                }),
            )
            .expect("seal write lane");

            let error = lane
                .execute_once(origin(&binding), request(&grant, POSTIMAGE))
                .expect_err("additional file must quarantine lane");
            assert!(matches!(
                error,
                WorktreeWriteLaneError::ReconciliationRequired(_)
            ));
            assert_eq!(
                lane.phase().expect("phase"),
                WorktreeWriteLanePhaseV1::ReconciliationRequired
            );
        }
    }

    #[test]
    fn cleanup_revalidates_retained_diff_and_refuses_late_changes() {
        for additional_path in [
            "src/unrelated.txt",
            "src/late-untracked.txt",
            ".cache/late.bin",
        ] {
            let fixture = Fixture::new();
            let worktree = fixture.worktree();
            let worktree_path = worktree.path().to_path_buf();
            let binding = binding();
            let grant = grant(&worktree, &binding, &fixture.path);
            let authority = workspace_authority(&grant);
            let lane = WorktreeWriteLane::new(
                worktree,
                grant.clone(),
                &authority,
                materialization(&grant),
                Arc::new(InMemoryWorktreeWriteLaneJournal::default()),
            )
            .expect("seal write lane");
            let observed = lane
                .execute_once(origin(&binding), request(&grant, POSTIMAGE))
                .expect("write before late change");
            let publication = publication(&grant, &observed);

            let additional = worktree_path.join(additional_path);
            fs::create_dir_all(additional.parent().expect("late-change parent"))
                .expect("create late-change parent");
            fs::write(&additional, b"late external change\n").expect("write late change");

            let error = lane
                .release_after_candidate_published(&binding, &publication)
                .expect_err("cleanup must preserve anomalous worktree");
            assert!(matches!(
                error,
                WorktreeWriteLaneError::ReconciliationRequired(_)
            ));
            assert_eq!(
                lane.phase().expect("phase"),
                WorktreeWriteLanePhaseV1::ReconciliationRequired
            );
            assert!(worktree_path.exists(), "anomalous worktree must survive");
        }
    }

    #[test]
    fn written_and_reconciliation_worktrees_survive_lane_drop() {
        let written_fixture = Fixture::new();
        let written_worktree = written_fixture.worktree();
        let written_path = written_worktree.path().to_path_buf();
        let written_binding = binding();
        let written_grant = grant(&written_worktree, &written_binding, &written_fixture.path);
        let written_authority = workspace_authority(&written_grant);
        let written_lane = WorktreeWriteLane::new(
            written_worktree,
            written_grant.clone(),
            &written_authority,
            materialization(&written_grant),
            Arc::new(InMemoryWorktreeWriteLaneJournal::default()),
        )
        .expect("seal written lane");
        written_lane
            .execute_once(origin(&written_binding), request(&written_grant, POSTIMAGE))
            .expect("write before drop");
        drop(written_lane);
        assert!(
            written_path.exists(),
            "Written worktree must survive lane Drop for recovery"
        );

        let failed_fixture = Fixture::new();
        let failed_worktree = failed_fixture.worktree();
        let failed_path = failed_worktree.path().to_path_buf();
        let failed_binding = binding();
        let failed_grant = grant(&failed_worktree, &failed_binding, &failed_fixture.path);
        let failed_authority = workspace_authority(&failed_grant);
        let failed_lane = WorktreeWriteLane::new(
            failed_worktree,
            failed_grant.clone(),
            &failed_authority,
            materialization(&failed_grant),
            Arc::new(RejectOnceJournal::new(RejectedBoundary::Observed)),
        )
        .expect("seal failed lane");
        assert!(matches!(
            failed_lane.execute_once(origin(&failed_binding), request(&failed_grant, POSTIMAGE)),
            Err(WorktreeWriteLaneError::ReconciliationRequired(_))
        ));
        drop(failed_lane);
        assert!(
            failed_path.exists(),
            "ReconciliationRequired worktree must survive lane Drop"
        );
    }

    #[test]
    fn lane_seals_trusted_workspace_snapshot_and_rejects_request_substitution() {
        {
            let fixture = Fixture::new();
            let worktree = fixture.worktree();
            let execution_binding = binding();
            let exact_grant = grant(&worktree, &execution_binding, &fixture.path);
            let mut substituted_authority = workspace_authority(&exact_grant);
            substituted_authority.source = WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
                git_baseline_sha256: Sha256Digest::of_bytes(b"substituted-baseline")
                    .as_str()
                    .to_owned(),
            };
            assert!(matches!(
                WorktreeWriteLane::new(
                    worktree,
                    exact_grant.clone(),
                    &substituted_authority,
                    materialization(&exact_grant),
                    Arc::new(InMemoryWorktreeWriteLaneJournal::default())
                ),
                Err(WorktreeWriteLaneError::InvalidAuthority(_))
            ));
        }

        {
            let fixture = Fixture::new();
            let worktree = fixture.worktree();
            let execution_binding = binding();
            let exact_grant = grant(&worktree, &execution_binding, &fixture.path);
            let mut substituted_authority = workspace_authority(&exact_grant);
            substituted_authority.lease_id =
                WorkspaceLeaseId::new("implementation/substituted-lease").expect("lease");
            assert!(matches!(
                WorktreeWriteLane::new(
                    worktree,
                    exact_grant.clone(),
                    &substituted_authority,
                    materialization(&exact_grant),
                    Arc::new(InMemoryWorktreeWriteLaneJournal::default())
                ),
                Err(WorktreeWriteLaneError::InvalidAuthority(_))
            ));
        }

        {
            let fixture = Fixture::new();
            let worktree = fixture.worktree();
            let execution_binding = binding();
            let exact_grant = grant(&worktree, &execution_binding, &fixture.path);
            let authority = workspace_authority(&exact_grant);
            let lane = WorktreeWriteLane::new(
                worktree,
                exact_grant.clone(),
                &authority,
                materialization(&exact_grant),
                Arc::new(InMemoryWorktreeWriteLaneJournal::default()),
            )
            .expect("seal exact authority");
            let mut substituted_request = request(&exact_grant, POSTIMAGE);
            substituted_request.grant_id = RepositoryToolGrantId::new();
            assert!(matches!(
                lane.execute_once(origin(&execution_binding), substituted_request),
                Err(WorktreeWriteLaneError::InvalidAuthority(_))
            ));
            assert_eq!(
                lane.phase().expect("phase"),
                WorktreeWriteLanePhaseV1::Ready
            );
        }
    }

    #[test]
    fn lane_rejects_brokered_repository_snapshot_workspace_source() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let execution_binding = binding();
        let exact_grant = grant(&worktree, &execution_binding, &fixture.path);
        let mut wrong_variant = workspace_authority(&exact_grant);
        wrong_variant.source = WorkspaceSourceBinding::BrokeredRepositorySnapshotV1 {
            snapshot_sha256: exact_grant.git_baseline_sha256.as_str().to_owned(),
        };

        assert!(matches!(
            WorktreeWriteLane::new(
                worktree,
                exact_grant.clone(),
                &wrong_variant,
                materialization(&exact_grant),
                Arc::new(InMemoryWorktreeWriteLaneJournal::default())
            ),
            Err(WorktreeWriteLaneError::InvalidAuthority(_))
        ));
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TargetMutationTrigger {
        DiffObserved,
        CleanupPrepared,
    }

    #[derive(Debug)]
    struct TargetMutationJournal {
        target: PathBuf,
        trigger: TargetMutationTrigger,
        inner: InMemoryWorktreeWriteLaneJournal,
    }

    impl WorktreeWriteLaneJournal for TargetMutationJournal {
        fn retain(
            &self,
            entry: WorktreeWriteLaneJournalEntryV1,
        ) -> Result<EventId, WorktreeWriteLaneJournalError> {
            let should_mutate = matches!(
                (&entry.record, self.trigger),
                (
                    WorktreeWriteLaneJournalRecordV1::GitDiffObserved { .. },
                    TargetMutationTrigger::DiffObserved
                ) | (
                    WorktreeWriteLaneJournalRecordV1::WorktreeCleanupPrepared { .. },
                    TargetMutationTrigger::CleanupPrepared
                )
            );
            let event_id = self.inner.retain(entry)?;
            if should_mutate {
                fs::write(&self.target, b"externally substituted postimage\n")
                    .map_err(|error| WorktreeWriteLaneJournalError::new(error.to_string()))?;
            }
            Ok(event_id)
        }
    }

    #[test]
    fn target_is_reobserved_after_diff_and_cleanup_journal_callbacks() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let worktree_path = worktree.path().to_path_buf();
        let first_binding = binding();
        let first_grant = grant(&worktree, &first_binding, &fixture.path);
        let authority = workspace_authority(&first_grant);
        let lane = WorktreeWriteLane::new(
            worktree,
            first_grant.clone(),
            &authority,
            materialization(&first_grant),
            Arc::new(TargetMutationJournal {
                target: worktree_path.join("src/flight.txt"),
                trigger: TargetMutationTrigger::DiffObserved,
                inner: InMemoryWorktreeWriteLaneJournal::default(),
            }),
        )
        .expect("seal diff-callback lane");
        assert!(matches!(
            lane.execute_once(origin(&first_binding), request(&first_grant, POSTIMAGE)),
            Err(WorktreeWriteLaneError::ReconciliationRequired(_))
        ));

        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        let worktree_path = worktree.path().to_path_buf();
        let second_binding = binding();
        let second_grant = grant(&worktree, &second_binding, &fixture.path);
        let authority = workspace_authority(&second_grant);
        let lane = WorktreeWriteLane::new(
            worktree,
            second_grant.clone(),
            &authority,
            materialization(&second_grant),
            Arc::new(TargetMutationJournal {
                target: worktree_path.join("src/flight.txt"),
                trigger: TargetMutationTrigger::CleanupPrepared,
                inner: InMemoryWorktreeWriteLaneJournal::default(),
            }),
        )
        .expect("seal cleanup-callback lane");
        let observed = lane
            .execute_once(origin(&second_binding), request(&second_grant, POSTIMAGE))
            .expect("write before cleanup callback");
        let publication = publication(&second_grant, &observed);
        assert!(matches!(
            lane.release_after_candidate_published(&second_binding, &publication),
            Err(WorktreeWriteLaneError::ReconciliationRequired(_))
        ));
        assert!(worktree_path.exists());
    }
}
