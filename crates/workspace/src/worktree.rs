use birdcode_protocol::{RepositoryFileIdentityV1, RepositoryRelativePathV1, Sha256Digest};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use thiserror::Error;
use uuid::Uuid;

use crate::worktree_edit::{
    GitWorktreeFileObservationV1, GitWorktreeFileReplaceError, GitWorktreeUtf8FileReadV1,
    GitWorktreeUtf8FileReplaceRequestV1, GitWorktreeUtf8FileReplaceResultV1,
    PreparedGitWorktreeUtf8FileReplace, WorktreeMutationRoot, execute_utf8_file_replace,
    observe_utf8_file, open_worktree_root, prepare_utf8_file_replace, read_utf8_file,
};

pub const GIT_WORKTREE_DIFF_MEDIA_TYPE: &str =
    "application/vnd.birdcode.git-worktree-diff.v1+octet-stream";
pub const GIT_WORKTREE_DIFF_MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES: u64 = 1024 * 1024;
pub const GIT_WORKTREE_CHANGED_PATHS_MAX_ENTRIES: usize = 4_096;
const GIT_BASELINE_DIGEST_DOMAIN: &[u8] = b"birdcode.git-baseline.v1\0";

const GIT_STDERR_MAX_BYTES: usize = 4 * 1024;
const GIT_STATUS_RETAINED_STDOUT_BYTES: u64 = 1;
const GIT_IDENTITY_MAX_BYTES: u64 = 65;
const GIT_CONFIG_VALUE_MAX_BYTES: u64 = 4 * 1024;
const GIT_CONFIG_KEYS_MAX_BYTES: u64 = 1024 * 1024;
const GIT_TREE_MODES_MAX_BYTES: u64 = 16 * 1024 * 1024;
const GIT_INDEX_FLAGS_MAX_BYTES: u64 = 16 * 1024 * 1024;
const GIT_LS_TREE_MAX_BYTES: u64 = 16 * 1024;
const GIT_PATH_IDENTITY_MAX_BYTES: u64 = 4 * 1024;
const GIT_WORKTREE_REGISTRATIONS_MAX_BYTES: u64 = 1024 * 1024;
const GIT_WORKTREE_CHANGED_PATH_MAX_BYTES: usize = 4_096;
const GIT_WORKTREE_CHANGED_PATH_MAX_COMPONENTS: usize = 64;
const GIT_WORKTREE_CHANGED_PATH_MAX_COMPONENT_BYTES: usize = 255;
const INHERITED_GIT_ENVIRONMENT: [&str; 16] = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ATTR_NOSYSTEM",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_EXTERNAL_DIFF",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_REPLACE_REF_BASE",
    "GIT_WORK_TREE",
    "GIT_DIFF_OPTS",
];

/// Exact tracked-file patch produced by Git relative to the immutable base
/// commit used to create a temporary worktree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWorktreeDiff {
    pub base_commit: String,
    pub media_type: &'static str,
    pub sha256: Sha256Digest,
    pub bytes: Vec<u8>,
    pub changed_paths: Vec<RepositoryRelativePathV1>,
}

impl GitWorktreeDiff {
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.media_type == GIT_WORKTREE_DIFF_MEDIA_TYPE
            && self.sha256 == Sha256Digest::of_bytes(&self.bytes)
            && u64::try_from(self.bytes.len()).is_ok_and(|size| size <= GIT_WORKTREE_DIFF_MAX_BYTES)
            && changed_paths_are_canonical(&self.changed_paths)
    }
}

#[derive(Debug, Error)]
pub enum TemporaryGitWorktreeError {
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("git {operation} failed with exit code {exit_code:?}: {stderr}")]
    Git {
        operation: &'static str,
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error("git {operation} returned non-UTF-8 identity output")]
    NonUtf8Identity { operation: &'static str },
    #[error("git returned an invalid commit object identity")]
    InvalidCommitIdentity,
    #[error("git {operation} returned an invalid boolean observation")]
    InvalidGitBoolean { operation: &'static str },
    #[error("git returned an invalid NUL-separated tree-mode observation")]
    InvalidGitTreeModeObservation,
    #[error("git returned an invalid NUL-separated config-key observation")]
    InvalidGitConfigKeyObservation,
    #[error("git returned an invalid NUL-separated index-flag observation")]
    InvalidGitIndexFlagObservation,
    #[error("temporary worktree scratch root overlaps the source repository")]
    OverlappingRoots,
    #[error("Git created the worktree outside its exact owned scratch root")]
    WorktreeEscapedScratchRoot,
    #[error("temporary worktree diff has {actual} bytes; maximum is {maximum}")]
    DiffTooLarge { actual: u64, maximum: u64 },
    #[error("temporary worktree changed-path observation has {actual} bytes; maximum is {maximum}")]
    ChangedPathsTooLarge { actual: u64, maximum: u64 },
    #[error(
        "temporary worktree changed-path observation has {actual} entries; maximum is {maximum}"
    )]
    ChangedPathCountTooLarge { actual: usize, maximum: usize },
    #[error("git returned an invalid NUL-separated numstat observation")]
    InvalidNumstatObservation,
    #[error("git returned an invalid NUL-separated ls-tree observation")]
    InvalidLsTreeObservation,
    #[error("repository path is invalid for an exact Git tree lookup")]
    InvalidRepositoryPath,
    #[error("raw repository path lookup is available only on Unix")]
    UnsupportedRepositoryPathPlatform,
    #[error("git {operation} produced {actual} stdout bytes; maximum is {maximum}")]
    GitStdoutTooLarge {
        operation: &'static str,
        actual: u64,
        maximum: u64,
    },
    #[error("temporary worktree cleanup completed but its path remains registered or present")]
    CleanupIncomplete,
    #[error("temporary worktree mutation root could not be retained: {message}")]
    MutationRootUnavailable { message: String },
    #[error("repository-local filter configuration is unsupported for worktree checkout")]
    RepositoryFilterConfigurationUnsupported,
    #[error("source repository was not pristine during {phase:?}")]
    SourceRepositoryNotPristine {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("source HEAD changed during clean committed-HEAD acquisition")]
    SourceHeadChanged { before: String, after: String },
    #[error("source repository has replace refs during {phase:?}")]
    ReplaceRefsUnsupported {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("source index has assume-unchanged or skip-worktree flags during {phase:?}")]
    IndexEntryFlagsUnsupported {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("source repository uses sparse checkout during {phase:?}")]
    SparseCheckoutUnsupported {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("source commit contains a gitlink/submodule during {phase:?}")]
    GitlinkUnsupported {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("source repository is shallow during {phase:?}")]
    ShallowRepositoryUnsupported {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("source repository is a partial clone during {phase:?}")]
    PartialCloneUnsupported {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("source repository uses an alternate object store during {phase:?}")]
    AlternateObjectStoreUnsupported {
        phase: GitCleanCommittedHeadObservationPhaseV1,
    },
    #[error("newly acquired worktree was not pristine")]
    AcquiredWorktreeNotPristine,
    #[error("acquisition validation failed and cleanup also failed")]
    AcquisitionCleanupFailed {
        validation: Box<TemporaryGitWorktreeError>,
        cleanup: Box<TemporaryGitWorktreeError>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitCleanCommittedHeadObservationPhaseV1 {
    BeforeAcquisition,
    AfterAcquisition,
}

struct WorktreeAcquisitionContext {
    git_executable: PathBuf,
    source_repository: PathBuf,
    scratch_root: PathBuf,
    empty_git_config: PathBuf,
    empty_hooks_directory: PathBuf,
}

/// One daemon-owned, detached Git worktree rooted at an exact commit.
///
/// This is an edit-isolation primitive, not a security boundary. Explicit
/// [`Self::release`] is the authoritative cleanup path; `Drop` only makes a
/// best-effort attempt so callers can still surface cleanup failures.
#[derive(Debug)]
pub struct TemporaryGitWorktree {
    git_executable: PathBuf,
    source_repository: PathBuf,
    scratch_root: PathBuf,
    empty_git_config: PathBuf,
    empty_hooks_directory: PathBuf,
    path: PathBuf,
    base_commit: String,
    git_baseline_sha256: Sha256Digest,
    worktree_id: Uuid,
    mutation_root: WorktreeMutationRoot,
    prepared_mutation_id: Option<Uuid>,
    mutation_lane_poisoned: bool,
    cleanup_state: WorktreeCleanupState,
    cleanup_on_drop: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorktreeCleanupState {
    Active,
    GitRemoved,
    Released,
}

impl TemporaryGitWorktree {
    /// Creates a detached worktree at the source repository's exact `HEAD`.
    /// Uncommitted source-checkout changes are deliberately outside this v1
    /// boundary and are never copied implicitly.
    ///
    /// # Errors
    ///
    /// Returns an error when paths cannot be resolved, roots overlap, Git
    /// cannot resolve `HEAD`, or the detached worktree cannot be created.
    pub fn create(
        source_repository: impl AsRef<Path>,
        scratch_root: impl AsRef<Path>,
    ) -> Result<Self, TemporaryGitWorktreeError> {
        Self::create_with_git(source_repository, scratch_root, Path::new("git"))
    }

    /// Same lifecycle as [`Self::create`] with an explicit Git executable.
    /// This is useful for packaged runtimes and deterministic test fixtures.
    ///
    /// # Errors
    ///
    /// Returns an error for the same path, identity, Git execution and cleanup
    /// failures as [`Self::create`].
    pub fn create_with_git(
        source_repository: impl AsRef<Path>,
        scratch_root: impl AsRef<Path>,
        git_executable: impl AsRef<Path>,
    ) -> Result<Self, TemporaryGitWorktreeError> {
        let context = prepare_worktree_acquisition(
            source_repository.as_ref(),
            scratch_root.as_ref(),
            git_executable.as_ref(),
        )?;
        reject_repository_filter_configuration(&context)?;
        let base_commit = resolve_base_commit(
            &context.git_executable,
            &context.source_repository,
            &context.empty_git_config,
            &context.empty_hooks_directory,
        )?;
        Self::create_worktree_at_commit(context, base_commit)
    }

    /// Acquires a detached worktree only from a clean, complete committed
    /// source `HEAD`. This profile deliberately excludes dirty state, sparse
    /// checkout, gitlinks, shallow/partial repositories and alternate object
    /// stores. It is edit isolation, not a security or snapshot boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the source is unsupported or changes across
    /// acquisition, or when worktree creation/validation/cleanup fails.
    pub fn create_clean_committed_head(
        source_repository: impl AsRef<Path>,
        scratch_root: impl AsRef<Path>,
    ) -> Result<Self, TemporaryGitWorktreeError> {
        Self::create_clean_committed_head_with_git(
            source_repository,
            scratch_root,
            Path::new("git"),
        )
    }

    /// [`Self::create_clean_committed_head`] with an explicit Git executable.
    ///
    /// # Errors
    ///
    /// Returns the same typed acquisition errors as the default executable
    /// constructor.
    pub fn create_clean_committed_head_with_git(
        source_repository: impl AsRef<Path>,
        scratch_root: impl AsRef<Path>,
        git_executable: impl AsRef<Path>,
    ) -> Result<Self, TemporaryGitWorktreeError> {
        let context = prepare_worktree_acquisition(
            source_repository.as_ref(),
            scratch_root.as_ref(),
            git_executable.as_ref(),
        )?;
        let before = observe_clean_committed_head(
            &context,
            GitCleanCommittedHeadObservationPhaseV1::BeforeAcquisition,
        )?;
        let mut worktree = Self::create_worktree_at_commit(context, before.clone())?;
        let validation = (|| {
            let after = observe_clean_committed_head(
                &WorktreeAcquisitionContext {
                    git_executable: worktree.git_executable.clone(),
                    source_repository: worktree.source_repository.clone(),
                    scratch_root: worktree.scratch_root.clone(),
                    empty_git_config: worktree.empty_git_config.clone(),
                    empty_hooks_directory: worktree.empty_hooks_directory.clone(),
                },
                GitCleanCommittedHeadObservationPhaseV1::AfterAcquisition,
            )?;
            if before != after {
                return Err(TemporaryGitWorktreeError::SourceHeadChanged { before, after });
            }
            if !worktree.is_pristine()? {
                return Err(TemporaryGitWorktreeError::AcquiredWorktreeNotPristine);
            }
            Ok(())
        })();
        if let Err(validation) = validation {
            return match worktree.release() {
                Ok(()) => Err(validation),
                Err(cleanup) => Err(TemporaryGitWorktreeError::AcquisitionCleanupFailed {
                    validation: Box::new(validation),
                    cleanup: Box::new(cleanup),
                }),
            };
        }
        Ok(worktree)
    }

    /// Returns the exact identity observed from the already-held worktree root
    /// descriptor. The path is not reopened or trusted for this observation.
    ///
    /// # Errors
    ///
    /// Rejects inactive worktrees and descriptor identity changes.
    pub fn root_identity(&self) -> Result<RepositoryFileIdentityV1, GitWorktreeFileReplaceError> {
        if self.cleanup_state != WorktreeCleanupState::Active {
            return Err(GitWorktreeFileReplaceError::WorktreeNotActive);
        }
        self.mutation_root.descriptor_identity()
    }

    fn create_worktree_at_commit(
        context: WorktreeAcquisitionContext,
        base_commit: String,
    ) -> Result<Self, TemporaryGitWorktreeError> {
        let WorktreeAcquisitionContext {
            git_executable,
            source_repository,
            scratch_root,
            empty_git_config,
            empty_hooks_directory,
        } = context;
        let git_baseline_sha256 = git_baseline_sha256(&base_commit);

        let worktree_id = Uuid::now_v7();
        let path = scratch_root.join(format!("birdcode-worktree-{worktree_id}"));
        add_detached_worktree(
            &git_executable,
            &source_repository,
            &empty_git_config,
            &empty_hooks_directory,
            &path,
            &base_commit,
        )?;
        let canonical_path = canonicalize_created_worktree(
            &git_executable,
            &source_repository,
            &scratch_root,
            &empty_git_config,
            &empty_hooks_directory,
            &path,
        )?;
        let mutation_root = match open_worktree_root(&canonical_path) {
            Ok(root) => root,
            Err(error) => {
                rollback_created_worktree(
                    &git_executable,
                    &source_repository,
                    &empty_git_config,
                    &empty_hooks_directory,
                    &canonical_path,
                );
                return Err(TemporaryGitWorktreeError::MutationRootUnavailable {
                    message: error.to_string(),
                });
            }
        };

        Ok(Self {
            git_executable,
            source_repository,
            scratch_root,
            empty_git_config,
            empty_hooks_directory,
            path: canonical_path,
            base_commit,
            git_baseline_sha256,
            worktree_id,
            mutation_root,
            prepared_mutation_id: None,
            mutation_lane_poisoned: false,
            cleanup_state: WorktreeCleanupState::Active,
            cleanup_on_drop: true,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn source_repository(&self) -> &Path {
        &self.source_repository
    }

    #[must_use]
    pub fn base_commit(&self) -> &str {
        &self.base_commit
    }

    #[must_use]
    pub const fn git_baseline_sha256(&self) -> &Sha256Digest {
        &self.git_baseline_sha256
    }

    #[must_use]
    pub const fn worktree_id(&self) -> Uuid {
        self.worktree_id
    }

    /// Returns whether tracked, untracked and ignored worktree state is empty.
    ///
    /// Git's porcelain-v2 NUL wire is used only as a mechanical presence
    /// observation: any stdout byte means the worktree is not pristine.
    ///
    /// # Errors
    ///
    /// Returns an error when Git cannot produce the bounded observation.
    pub fn is_pristine(&self) -> Result<bool, TemporaryGitWorktreeError> {
        let output = run_git_bounded(
            &self.git_executable,
            &self.path,
            &self.empty_git_config,
            &self.empty_hooks_directory,
            "observe pristine worktree state",
            [
                OsStr::new("status"),
                OsStr::new("--porcelain=v2"),
                OsStr::new("-z"),
                OsStr::new("--untracked-files=all"),
                OsStr::new("--ignored=matching"),
            ],
            None,
            GIT_STATUS_RETAINED_STDOUT_BYTES,
        )?;
        Ok(output.total_stdout_bytes == 0)
    }

    /// Returns whether the worktree contains any untracked or ignored file.
    ///
    /// This complements [`Self::tracked_diff`] after an authorized mutation:
    /// the retained patch proves the tracked changes while these two bounded
    /// Git plumbing observations ensure cleanup would not silently discard an
    /// additional untracked or ignored artifact. No pathname is decoded or
    /// semantically interpreted; any returned byte is sufficient evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when either bounded Git observation fails.
    pub fn has_untracked_or_ignored_files(&self) -> Result<bool, TemporaryGitWorktreeError> {
        let untracked = run_git_bounded(
            &self.git_executable,
            &self.path,
            &self.empty_git_config,
            &self.empty_hooks_directory,
            "observe untracked worktree files",
            [
                OsStr::new("ls-files"),
                OsStr::new("--others"),
                OsStr::new("--exclude-standard"),
                OsStr::new("-z"),
            ],
            None,
            GIT_STATUS_RETAINED_STDOUT_BYTES,
        )?;
        if untracked.total_stdout_bytes != 0 {
            return Ok(true);
        }
        let ignored = run_git_bounded(
            &self.git_executable,
            &self.path,
            &self.empty_git_config,
            &self.empty_hooks_directory,
            "observe ignored worktree files",
            [
                OsStr::new("ls-files"),
                OsStr::new("--others"),
                OsStr::new("--ignored"),
                OsStr::new("--exclude-standard"),
                OsStr::new("-z"),
            ],
            None,
            GIT_STATUS_RETAINED_STDOUT_BYTES,
        )?;
        Ok(ignored.total_stdout_bytes != 0)
    }

    /// Prevents best-effort `Drop` cleanup so a terminal or indeterminate
    /// mutation remains available to durable recovery. Explicit
    /// [`Self::release`] continues to work and is the only normal completion
    /// path after this flag is set.
    ///
    /// Callers must durably retain the worktree identity and path before using
    /// this method. This flag is intentionally one-way: once an effect can
    /// begin, object destruction must never silently become a cleanup retry.
    pub fn preserve_on_drop_for_reconciliation(&mut self) {
        self.cleanup_on_drop = false;
    }

    /// Observes one exact UTF-8 file through the descriptor-confined worktree
    /// root without reserving or performing a mutation.
    ///
    /// # Errors
    ///
    /// Rejects invalid paths, non-regular or non-UTF-8 files, traversal races,
    /// oversized observations and filesystem failures.
    pub fn observe_utf8_file(
        &self,
        path: &RepositoryRelativePathV1,
    ) -> Result<GitWorktreeFileObservationV1, GitWorktreeFileReplaceError> {
        observe_utf8_file(&self.mutation_root, path)
    }

    /// Reads one exact UTF-8 file through the held descriptor-confined root.
    /// The returned content and SHA-256 observation describe the same bounded
    /// read; no pathname is reopened after observation.
    ///
    /// # Errors
    ///
    /// Rejects inactive worktrees, invalid paths, non-regular or non-UTF-8
    /// files, traversal races, files over the 4 MiB hard bound and I/O errors.
    pub fn read_utf8_file(
        &self,
        path: &RepositoryRelativePathV1,
    ) -> Result<GitWorktreeUtf8FileReadV1, GitWorktreeFileReplaceError> {
        if self.cleanup_state != WorktreeCleanupState::Active {
            return Err(GitWorktreeFileReplaceError::WorktreeNotActive);
        }
        read_utf8_file(&self.mutation_root, path)
    }

    /// Returns whether the immutable base commit tracks the exact raw path as
    /// a regular non-symlink file.
    ///
    /// # Errors
    ///
    /// Rejects invalid paths, malformed Git output and execution failures.
    pub fn base_commit_tracks_regular_file(
        &self,
        path: &RepositoryRelativePathV1,
    ) -> Result<bool, TemporaryGitWorktreeError> {
        let raw_path = encode_repository_path(path)?;
        let literal_pathspec = literal_pathspec(&raw_path)?;
        let args = [
            OsString::from("ls-tree"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            OsString::from(&self.base_commit),
            OsString::from("--"),
            literal_pathspec,
        ];
        let output = run_git_bounded(
            &self.git_executable,
            &self.source_repository,
            &self.empty_git_config,
            &self.empty_hooks_directory,
            "inspect base commit path",
            args.iter().map(OsString::as_os_str),
            None,
            GIT_LS_TREE_MAX_BYTES,
        )?;
        if output.total_stdout_bytes > GIT_LS_TREE_MAX_BYTES {
            return Err(TemporaryGitWorktreeError::GitStdoutTooLarge {
                operation: "inspect base commit path",
                actual: output.total_stdout_bytes,
                maximum: GIT_LS_TREE_MAX_BYTES,
            });
        }
        parse_ls_tree_regular_file(&output.bytes, &raw_path)
    }

    /// Validates one exact existing UTF-8 file replacement without mutating
    /// the worktree and reserves its single in-process writer lane.
    ///
    /// # Errors
    ///
    /// Returns a typed path, authority, preimage, limit or filesystem error.
    pub fn prepare_utf8_file_replace(
        &mut self,
        request: GitWorktreeUtf8FileReplaceRequestV1,
    ) -> Result<PreparedGitWorktreeUtf8FileReplace, GitWorktreeFileReplaceError> {
        if self.cleanup_state != WorktreeCleanupState::Active {
            return Err(GitWorktreeFileReplaceError::WorktreeNotActive);
        }
        if self.mutation_lane_poisoned {
            return Err(GitWorktreeFileReplaceError::MutationLanePoisoned);
        }
        if self.prepared_mutation_id.is_some() {
            return Err(GitWorktreeFileReplaceError::MutationAlreadyPrepared);
        }
        let prepared = prepare_utf8_file_replace(&self.mutation_root, self.worktree_id, request)?;
        self.prepared_mutation_id = Some(prepared.operation_id());
        Ok(prepared)
    }

    /// Executes the exact prepared replacement and verifies its durable
    /// postimage before releasing the writer lane.
    ///
    /// # Errors
    ///
    /// Rejects substituted preparations. An indeterminate post-rename failure
    /// permanently poisons this worktree's mutation lane.
    pub fn execute_prepared_utf8_file_replace(
        &mut self,
        prepared: &PreparedGitWorktreeUtf8FileReplace,
    ) -> Result<GitWorktreeUtf8FileReplaceResultV1, GitWorktreeFileReplaceError> {
        if self.cleanup_state != WorktreeCleanupState::Active {
            return Err(GitWorktreeFileReplaceError::WorktreeNotActive);
        }
        if self.mutation_lane_poisoned {
            return Err(GitWorktreeFileReplaceError::MutationLanePoisoned);
        }
        if self.prepared_mutation_id != Some(prepared.operation_id()) {
            return Err(GitWorktreeFileReplaceError::PreparedMutationMismatch);
        }
        let result = execute_utf8_file_replace(&self.mutation_root, self.worktree_id, prepared);
        if result
            .as_ref()
            .is_err_and(GitWorktreeFileReplaceError::may_have_mutated)
        {
            self.mutation_lane_poisoned = true;
        } else {
            self.prepared_mutation_id = None;
        }
        result
    }

    /// Cancels a prepared replacement before its filesystem effect boundary.
    ///
    /// # Errors
    ///
    /// Rejects an object that does not own the current writer reservation.
    pub fn cancel_prepared_utf8_file_replace(
        &mut self,
        prepared: &PreparedGitWorktreeUtf8FileReplace,
    ) -> Result<(), GitWorktreeFileReplaceError> {
        if self.prepared_mutation_id != Some(prepared.operation_id()) {
            return Err(GitWorktreeFileReplaceError::PreparedMutationMismatch);
        }
        self.prepared_mutation_id = None;
        Ok(())
    }

    /// Captures Git's canonical binary patch for tracked files only.
    ///
    /// # Errors
    ///
    /// Returns an error when Git cannot produce the diff or its exact bytes
    /// exceed [`GIT_WORKTREE_DIFF_MAX_BYTES`].
    pub fn tracked_diff(&self) -> Result<GitWorktreeDiff, TemporaryGitWorktreeError> {
        let args = [
            OsString::from("diff"),
            OsString::from("--no-color"),
            OsString::from("--no-ext-diff"),
            OsString::from("--no-textconv"),
            OsString::from("--binary"),
            OsString::from("--full-index"),
            OsString::from("--no-renames"),
            OsString::from(&self.base_commit),
            OsString::from("--"),
            OsString::from("."),
        ];
        let output = run_git_bounded(
            &self.git_executable,
            &self.path,
            &self.empty_git_config,
            &self.empty_hooks_directory,
            "capture tracked diff",
            args.iter().map(OsString::as_os_str),
            None,
            GIT_WORKTREE_DIFF_MAX_BYTES,
        )?;
        let actual = output.total_stdout_bytes;
        if actual > GIT_WORKTREE_DIFF_MAX_BYTES {
            return Err(TemporaryGitWorktreeError::DiffTooLarge {
                actual,
                maximum: GIT_WORKTREE_DIFF_MAX_BYTES,
            });
        }
        let changed_paths = self.changed_paths_from_patch(&output.bytes)?;
        Ok(GitWorktreeDiff {
            base_commit: self.base_commit.clone(),
            media_type: GIT_WORKTREE_DIFF_MEDIA_TYPE,
            sha256: Sha256Digest::of_bytes(&output.bytes),
            bytes: output.bytes,
            changed_paths,
        })
    }

    fn changed_paths_from_patch(
        &self,
        patch: &[u8],
    ) -> Result<Vec<RepositoryRelativePathV1>, TemporaryGitWorktreeError> {
        if patch.is_empty() {
            return Ok(Vec::new());
        }
        let args = [
            OsString::from("apply"),
            OsString::from("--numstat"),
            OsString::from("-z"),
        ];
        let output = run_git_bounded(
            &self.git_executable,
            &self.path,
            &self.empty_git_config,
            &self.empty_hooks_directory,
            "derive changed paths from retained patch",
            args.iter().map(OsString::as_os_str),
            Some(patch),
            GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES,
        )?;
        if output.total_stdout_bytes > GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES {
            return Err(TemporaryGitWorktreeError::ChangedPathsTooLarge {
                actual: output.total_stdout_bytes,
                maximum: GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES,
            });
        }
        parse_numstat_changed_paths(&output.bytes)
    }

    /// Removes the exact owned worktree and verifies that neither its path nor
    /// its machine-readable Git registration remains.
    ///
    /// # Errors
    ///
    /// Returns an error when Git refuses removal or the exact owned path is
    /// still present or registered after Git reports success.
    pub fn release(&mut self) -> Result<(), TemporaryGitWorktreeError> {
        if self.cleanup_state == WorktreeCleanupState::Released {
            return Ok(());
        }
        if self.cleanup_state == WorktreeCleanupState::Active {
            let args = [
                OsString::from("worktree"),
                OsString::from("remove"),
                OsString::from("--force"),
                self.path.as_os_str().to_owned(),
            ];
            run_git_bounded_exact(
                &self.git_executable,
                &self.source_repository,
                &self.empty_git_config,
                &self.empty_hooks_directory,
                "remove temporary worktree",
                args.iter().map(OsString::as_os_str),
                None,
                0,
            )?;
            self.cleanup_state = WorktreeCleanupState::GitRemoved;
        }
        if path_exists_including_symlink(&self.path)? || self.registration_is_present()? {
            return Err(TemporaryGitWorktreeError::CleanupIncomplete);
        }
        self.cleanup_state = WorktreeCleanupState::Released;
        Ok(())
    }

    fn registration_is_present(&self) -> Result<bool, TemporaryGitWorktreeError> {
        let output = run_git_bounded_exact(
            &self.git_executable,
            &self.source_repository,
            &self.empty_git_config,
            &self.empty_hooks_directory,
            "list registered worktrees",
            [
                OsStr::new("worktree"),
                OsStr::new("list"),
                OsStr::new("--porcelain"),
                OsStr::new("-z"),
            ],
            None,
            GIT_WORKTREE_REGISTRATIONS_MAX_BYTES,
        )?;
        Ok(machine_worktree_paths(&output.bytes).any(|path| path == self.path))
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.cleanup_state, WorktreeCleanupState::Active)
    }

    #[must_use]
    pub fn scratch_root(&self) -> &Path {
        &self.scratch_root
    }
}

impl Drop for TemporaryGitWorktree {
    fn drop(&mut self) {
        if self.cleanup_on_drop && self.cleanup_state != WorktreeCleanupState::Released {
            let _ = self.release();
        }
    }
}

fn prepare_worktree_acquisition(
    source_repository: &Path,
    scratch_root: &Path,
    git_executable: &Path,
) -> Result<WorktreeAcquisitionContext, TemporaryGitWorktreeError> {
    fs::create_dir_all(scratch_root).map_err(|source| TemporaryGitWorktreeError::Io {
        operation: "create scratch root",
        source,
    })?;
    let scratch_root = canonicalize(scratch_root, "canonicalize scratch root")?;
    let source_input = canonicalize(source_repository, "canonicalize source repository")?;
    let git_executable = git_executable.to_path_buf();
    let control_root = scratch_root.join(format!("birdcode-git-control-{}", Uuid::now_v7()));
    ensure_path_absent(&control_root)?;
    let empty_git_config = control_root.join("global-config");
    let empty_hooks_directory = control_root.join("hooks");
    let source_repository = discover_repository_root(
        &git_executable,
        &source_input,
        &empty_git_config,
        &empty_hooks_directory,
    )?;
    if scratch_root.starts_with(&source_repository) || source_repository.starts_with(&scratch_root)
    {
        return Err(TemporaryGitWorktreeError::OverlappingRoots);
    }
    Ok(WorktreeAcquisitionContext {
        git_executable,
        source_repository,
        scratch_root,
        empty_git_config,
        empty_hooks_directory,
    })
}

fn observe_clean_committed_head(
    context: &WorktreeAcquisitionContext,
    phase: GitCleanCommittedHeadObservationPhaseV1,
) -> Result<String, TemporaryGitWorktreeError> {
    reject_repository_filter_configuration(context)?;
    if repository_has_replace_refs(context)? {
        return Err(TemporaryGitWorktreeError::ReplaceRefsUnsupported { phase });
    }
    if index_has_hidden_entry_flags(context)? {
        return Err(TemporaryGitWorktreeError::IndexEntryFlagsUnsupported { phase });
    }
    let head = resolve_base_commit_bounded(context)?;
    if !repository_is_pristine(context)? {
        return Err(TemporaryGitWorktreeError::SourceRepositoryNotPristine { phase });
    }
    if git_boolean_observation(
        context,
        "observe sparse checkout configuration",
        [
            OsStr::new("config"),
            OsStr::new("--type=bool"),
            OsStr::new("--get"),
            OsStr::new("--default=false"),
            OsStr::new("core.sparseCheckout"),
        ],
    )? {
        return Err(TemporaryGitWorktreeError::SparseCheckoutUnsupported { phase });
    }
    if git_boolean_observation(
        context,
        "observe shallow repository state",
        [
            OsStr::new("rev-parse"),
            OsStr::new("--is-shallow-repository"),
        ],
    )? {
        return Err(TemporaryGitWorktreeError::ShallowRepositoryUnsupported { phase });
    }
    if git_config_key_is_present(context, "extensions.partialClone")? {
        return Err(TemporaryGitWorktreeError::PartialCloneUnsupported { phase });
    }
    if repository_uses_alternate_object_store(context)? {
        return Err(TemporaryGitWorktreeError::AlternateObjectStoreUnsupported { phase });
    }
    if commit_contains_gitlink(context, &head)? {
        return Err(TemporaryGitWorktreeError::GitlinkUnsupported { phase });
    }
    Ok(head)
}

fn reject_repository_filter_configuration(
    context: &WorktreeAcquisitionContext,
) -> Result<(), TemporaryGitWorktreeError> {
    let operation = "observe effective repository config keys";
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        operation,
        [
            OsStr::new("config"),
            OsStr::new("--includes"),
            OsStr::new("--name-only"),
            OsStr::new("--list"),
            OsStr::new("-z"),
        ],
        None,
        GIT_CONFIG_KEYS_MAX_BYTES,
    )?;
    if output.total_stdout_bytes > GIT_CONFIG_KEYS_MAX_BYTES {
        return Err(TemporaryGitWorktreeError::GitStdoutTooLarge {
            operation,
            actual: output.total_stdout_bytes,
            maximum: GIT_CONFIG_KEYS_MAX_BYTES,
        });
    }
    if output.bytes.is_empty() {
        return Ok(());
    }
    let Some(records) = output.bytes.strip_suffix(&[0]) else {
        return Err(TemporaryGitWorktreeError::InvalidGitConfigKeyObservation);
    };
    for key in records.split(|byte| *byte == 0) {
        if key.is_empty() {
            return Err(TemporaryGitWorktreeError::InvalidGitConfigKeyObservation);
        }
        if key
            .get(..b"filter.".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"filter."))
        {
            return Err(TemporaryGitWorktreeError::RepositoryFilterConfigurationUnsupported);
        }
    }
    Ok(())
}

fn repository_has_replace_refs(
    context: &WorktreeAcquisitionContext,
) -> Result<bool, TemporaryGitWorktreeError> {
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        "observe replace refs",
        [
            OsStr::new("for-each-ref"),
            OsStr::new("--format=%(refname)"),
            OsStr::new("refs/replace/"),
        ],
        None,
        1,
    )?;
    Ok(output.total_stdout_bytes != 0)
}

fn index_has_hidden_entry_flags(
    context: &WorktreeAcquisitionContext,
) -> Result<bool, TemporaryGitWorktreeError> {
    let operation = "observe source index entry flags";
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        operation,
        [OsStr::new("ls-files"), OsStr::new("-v"), OsStr::new("-z")],
        None,
        GIT_INDEX_FLAGS_MAX_BYTES,
    )?;
    if output.total_stdout_bytes > GIT_INDEX_FLAGS_MAX_BYTES {
        return Err(TemporaryGitWorktreeError::GitStdoutTooLarge {
            operation,
            actual: output.total_stdout_bytes,
            maximum: GIT_INDEX_FLAGS_MAX_BYTES,
        });
    }
    if output.bytes.is_empty() {
        return Ok(false);
    }
    let Some(records) = output.bytes.strip_suffix(&[0]) else {
        return Err(TemporaryGitWorktreeError::InvalidGitIndexFlagObservation);
    };
    let mut hidden = false;
    for record in records.split(|byte| *byte == 0) {
        if record.len() < 3 || record[1] != b' ' {
            return Err(TemporaryGitWorktreeError::InvalidGitIndexFlagObservation);
        }
        hidden |= record[0] == b'S' || record[0].is_ascii_lowercase();
    }
    Ok(hidden)
}

fn resolve_base_commit_bounded(
    context: &WorktreeAcquisitionContext,
) -> Result<String, TemporaryGitWorktreeError> {
    let operation = "observe exact source HEAD";
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        operation,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--end-of-options"),
            OsStr::new("HEAD^{commit}"),
        ],
        None,
        GIT_IDENTITY_MAX_BYTES,
    )?;
    let value = bounded_identity_output(&output, operation, GIT_IDENTITY_MAX_BYTES)?;
    if !valid_git_object_identity(&value) {
        return Err(TemporaryGitWorktreeError::InvalidCommitIdentity);
    }
    Ok(value)
}

fn repository_is_pristine(
    context: &WorktreeAcquisitionContext,
) -> Result<bool, TemporaryGitWorktreeError> {
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        "observe source repository state",
        [
            OsStr::new("status"),
            OsStr::new("--porcelain=v2"),
            OsStr::new("-z"),
            OsStr::new("--untracked-files=all"),
            OsStr::new("--ignored=matching"),
        ],
        None,
        GIT_STATUS_RETAINED_STDOUT_BYTES,
    )?;
    Ok(output.total_stdout_bytes == 0)
}

fn git_boolean_observation<'a>(
    context: &WorktreeAcquisitionContext,
    operation: &'static str,
    arguments: impl IntoIterator<Item = &'a OsStr>,
) -> Result<bool, TemporaryGitWorktreeError> {
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        operation,
        arguments,
        None,
        6,
    )?;
    match bounded_identity_output(&output, operation, 6)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(TemporaryGitWorktreeError::InvalidGitBoolean { operation }),
    }
}

fn git_config_key_is_present(
    context: &WorktreeAcquisitionContext,
    key: &str,
) -> Result<bool, TemporaryGitWorktreeError> {
    let first = git_config_value_with_default(context, key, "birdcode-absent-a")?;
    let second = git_config_value_with_default(context, key, "birdcode-absent-b")?;
    Ok(first == second)
}

fn git_config_value_with_default(
    context: &WorktreeAcquisitionContext,
    key: &str,
    default: &str,
) -> Result<Vec<u8>, TemporaryGitWorktreeError> {
    let default = format!("--default={default}");
    let arguments = [
        OsString::from("config"),
        OsString::from("--local"),
        OsString::from("--get"),
        OsString::from(default),
        OsString::from(key),
    ];
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        "observe partial clone configuration",
        arguments.iter().map(OsString::as_os_str),
        None,
        GIT_CONFIG_VALUE_MAX_BYTES,
    )?;
    if output.total_stdout_bytes > GIT_CONFIG_VALUE_MAX_BYTES {
        return Err(TemporaryGitWorktreeError::GitStdoutTooLarge {
            operation: "observe partial clone configuration",
            actual: output.total_stdout_bytes,
            maximum: GIT_CONFIG_VALUE_MAX_BYTES,
        });
    }
    Ok(output.bytes)
}

fn repository_uses_alternate_object_store(
    context: &WorktreeAcquisitionContext,
) -> Result<bool, TemporaryGitWorktreeError> {
    let operation = "observe common Git directory";
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        operation,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--path-format=absolute"),
            OsStr::new("--git-common-dir"),
        ],
        None,
        GIT_CONFIG_VALUE_MAX_BYTES,
    )?;
    let common = bounded_identity_output(&output, operation, GIT_CONFIG_VALUE_MAX_BYTES)?;
    let common = PathBuf::from(common);
    let objects = common.join("objects");
    if fs::symlink_metadata(&objects)
        .map(|metadata| metadata.file_type().is_symlink())
        .or_else(|error| {
            if error.kind() == ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error)
            }
        })
        .map_err(|source| TemporaryGitWorktreeError::Io {
            operation: "inspect Git object directory",
            source,
        })?
    {
        return Ok(true);
    }
    for name in ["alternates", "http-alternates"] {
        match fs::symlink_metadata(objects.join("info").join(name)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(TemporaryGitWorktreeError::Io {
                    operation: "inspect alternate object store",
                    source,
                });
            }
        }
    }
    Ok(false)
}

fn commit_contains_gitlink(
    context: &WorktreeAcquisitionContext,
    commit: &str,
) -> Result<bool, TemporaryGitWorktreeError> {
    let arguments = [
        OsString::from("ls-tree"),
        OsString::from("-r"),
        OsString::from("-z"),
        OsString::from("--full-tree"),
        OsString::from("--format=%(objectmode)"),
        OsString::from(commit),
    ];
    let output = run_git_bounded(
        &context.git_executable,
        &context.source_repository,
        &context.empty_git_config,
        &context.empty_hooks_directory,
        "observe commit tree modes",
        arguments.iter().map(OsString::as_os_str),
        None,
        GIT_TREE_MODES_MAX_BYTES,
    )?;
    if output.total_stdout_bytes > GIT_TREE_MODES_MAX_BYTES {
        return Err(TemporaryGitWorktreeError::GitStdoutTooLarge {
            operation: "observe commit tree modes",
            actual: output.total_stdout_bytes,
            maximum: GIT_TREE_MODES_MAX_BYTES,
        });
    }
    if output.bytes.is_empty() {
        return Ok(false);
    }
    let Some(records) = output.bytes.strip_suffix(&[0]) else {
        return Err(TemporaryGitWorktreeError::InvalidGitTreeModeObservation);
    };
    let mut has_gitlink = false;
    for mode in records.split(|byte| *byte == 0) {
        if mode.len() != 6 || !mode.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
            return Err(TemporaryGitWorktreeError::InvalidGitTreeModeObservation);
        }
        has_gitlink |= mode == b"160000";
    }
    Ok(has_gitlink)
}

fn bounded_identity_output(
    output: &BoundedGitOutput,
    operation: &'static str,
    maximum: u64,
) -> Result<String, TemporaryGitWorktreeError> {
    if output.total_stdout_bytes > maximum {
        return Err(TemporaryGitWorktreeError::GitStdoutTooLarge {
            operation,
            actual: output.total_stdout_bytes,
            maximum,
        });
    }
    let text = std::str::from_utf8(&output.bytes)
        .map_err(|_| TemporaryGitWorktreeError::NonUtf8Identity { operation })?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn canonicalize(
    path: &Path,
    operation: &'static str,
) -> Result<PathBuf, TemporaryGitWorktreeError> {
    fs::canonicalize(path).map_err(|source| TemporaryGitWorktreeError::Io { operation, source })
}

fn ensure_path_absent(path: &Path) -> Result<(), TemporaryGitWorktreeError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(TemporaryGitWorktreeError::Io {
            operation: "reserve unique Git control path",
            source: std::io::Error::new(ErrorKind::AlreadyExists, "control path already exists"),
        }),
        Err(source) => Err(TemporaryGitWorktreeError::Io {
            operation: "inspect unique Git control path",
            source,
        }),
    }
}

fn path_exists_including_symlink(path: &Path) -> Result<bool, TemporaryGitWorktreeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(TemporaryGitWorktreeError::Io {
            operation: "verify removed worktree path",
            source,
        }),
    }
}

fn discover_repository_root(
    git_executable: &Path,
    source_input: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
) -> Result<PathBuf, TemporaryGitWorktreeError> {
    let output = run_git_bounded_exact(
        git_executable,
        source_input,
        empty_git_config,
        empty_hooks_directory,
        "discover repository root",
        [OsStr::new("rev-parse"), OsStr::new("--show-toplevel")],
        None,
        GIT_PATH_IDENTITY_MAX_BYTES,
    )?;
    let repository = bounded_identity_output(
        &output,
        "discover repository root",
        GIT_PATH_IDENTITY_MAX_BYTES,
    )?;
    canonicalize(
        Path::new(&repository),
        "canonicalize discovered repository root",
    )
}

fn resolve_base_commit(
    git_executable: &Path,
    source_repository: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
) -> Result<String, TemporaryGitWorktreeError> {
    let output = run_git_bounded_exact(
        git_executable,
        source_repository,
        empty_git_config,
        empty_hooks_directory,
        "resolve base commit",
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--end-of-options"),
            OsStr::new("HEAD^{commit}"),
        ],
        None,
        GIT_IDENTITY_MAX_BYTES,
    )?;
    let base_commit =
        bounded_identity_output(&output, "resolve base commit", GIT_IDENTITY_MAX_BYTES)?;
    if !valid_git_object_identity(&base_commit) {
        return Err(TemporaryGitWorktreeError::InvalidCommitIdentity);
    }
    Ok(base_commit)
}

fn add_detached_worktree(
    git_executable: &Path,
    source_repository: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
    path: &Path,
    base_commit: &str,
) -> Result<(), TemporaryGitWorktreeError> {
    let args = [
        OsString::from("worktree"),
        OsString::from("add"),
        OsString::from("--quiet"),
        OsString::from("--detach"),
        path.as_os_str().to_owned(),
        OsString::from(base_commit),
    ];
    run_git_bounded_exact(
        git_executable,
        source_repository,
        empty_git_config,
        empty_hooks_directory,
        "create detached worktree",
        args.iter().map(OsString::as_os_str),
        None,
        0,
    )?;
    Ok(())
}

fn canonicalize_created_worktree(
    git_executable: &Path,
    source_repository: &Path,
    scratch_root: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
    path: &Path,
) -> Result<PathBuf, TemporaryGitWorktreeError> {
    let result = canonicalize(path, "canonicalize created worktree").and_then(|canonical_path| {
        if canonical_path.parent() == Some(scratch_root) {
            Ok(canonical_path)
        } else {
            Err(TemporaryGitWorktreeError::WorktreeEscapedScratchRoot)
        }
    });
    if result.is_err() {
        rollback_created_worktree(
            git_executable,
            source_repository,
            empty_git_config,
            empty_hooks_directory,
            path,
        );
    }
    result
}

fn rollback_created_worktree(
    git_executable: &Path,
    source_repository: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
    path: &Path,
) {
    let cleanup_args = [
        OsString::from("worktree"),
        OsString::from("remove"),
        OsString::from("--force"),
        path.as_os_str().to_owned(),
    ];
    let _ = run_git_bounded_exact(
        git_executable,
        source_repository,
        empty_git_config,
        empty_hooks_directory,
        "rollback incomplete worktree creation",
        cleanup_args.iter().map(OsString::as_os_str),
        None,
        0,
    );
}

struct BoundedGitOutput {
    bytes: Vec<u8>,
    total_stdout_bytes: u64,
}

struct BoundedPipeOutput {
    bytes: Vec<u8>,
    total_bytes: u64,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the closed Git process boundary receives every path, operation and byte bound explicitly"
)]
fn run_git_bounded_exact<'a>(
    executable: &Path,
    repository: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
    operation: &'static str,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    stdin_bytes: Option<&[u8]>,
    maximum_stdout_bytes: u64,
) -> Result<BoundedGitOutput, TemporaryGitWorktreeError> {
    let output = run_git_bounded(
        executable,
        repository,
        empty_git_config,
        empty_hooks_directory,
        operation,
        arguments,
        stdin_bytes,
        maximum_stdout_bytes,
    )?;
    if output.total_stdout_bytes > maximum_stdout_bytes {
        return Err(TemporaryGitWorktreeError::GitStdoutTooLarge {
            operation,
            actual: output.total_stdout_bytes,
            maximum: maximum_stdout_bytes,
        });
    }
    Ok(output)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the closed Git process boundary receives every path, operation and byte bound explicitly"
)]
fn run_git_bounded<'a>(
    executable: &Path,
    repository: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
    operation: &'static str,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    stdin_bytes: Option<&[u8]>,
    maximum_stdout_bytes: u64,
) -> Result<BoundedGitOutput, TemporaryGitWorktreeError> {
    use std::io::Write as _;

    let mut command = configured_git_command(
        executable,
        repository,
        empty_git_config,
        empty_hooks_directory,
    );
    command
        .args(arguments)
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|source| TemporaryGitWorktreeError::Io { operation, source })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| TemporaryGitWorktreeError::Io {
            operation,
            source: std::io::Error::other("Git stdout pipe was unavailable"),
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| TemporaryGitWorktreeError::Io {
            operation,
            source: std::io::Error::other("Git stderr pipe was unavailable"),
        })?;
    let stdin = child.stdin.take();

    let (status, stdout, stderr, stdin_result) = std::thread::scope(|scope| {
        let stdout_reader = scope.spawn(move || read_pipe_bounded(stdout, maximum_stdout_bytes));
        let stderr_reader = scope.spawn(move || {
            read_pipe_bounded(
                stderr,
                u64::try_from(GIT_STDERR_MAX_BYTES).unwrap_or(u64::MAX),
            )
        });
        let stdin_writer = stdin_bytes.zip(stdin).map(|(bytes, mut pipe)| {
            scope.spawn(move || {
                let result = pipe.write_all(bytes);
                drop(pipe);
                result
            })
        });
        let status = child.wait();
        let stdout = stdout_reader.join();
        let stderr = stderr_reader.join();
        let stdin_result = stdin_writer.map(std::thread::ScopedJoinHandle::join);
        (status, stdout, stderr, stdin_result)
    });
    let status = status.map_err(|source| TemporaryGitWorktreeError::Io { operation, source })?;
    let stdout = join_pipe_reader(stdout, operation)?;
    let stderr = join_pipe_reader(stderr, operation)?;
    if !status.success() {
        return Err(TemporaryGitWorktreeError::Git {
            operation,
            exit_code: status.code(),
            stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        });
    }
    if let Some(result) = stdin_result {
        result
            .map_err(|_| TemporaryGitWorktreeError::Io {
                operation,
                source: std::io::Error::other("Git stdin writer panicked"),
            })?
            .map_err(|source| TemporaryGitWorktreeError::Io { operation, source })?;
    }
    Ok(BoundedGitOutput {
        bytes: stdout.bytes,
        total_stdout_bytes: stdout.total_bytes,
    })
}

fn configured_git_command(
    executable: &Path,
    repository: &Path,
    empty_git_config: &Path,
    empty_hooks_directory: &Path,
) -> Command {
    let mut hooks_configuration = OsString::from("core.hooksPath=");
    hooks_configuration.push(empty_hooks_directory.as_os_str());
    let mut command = Command::new(executable);
    for variable in INHERITED_GIT_ENVIRONMENT {
        command.env_remove(variable);
    }
    command
        .arg("-c")
        .arg(hooks_configuration)
        .arg("-c")
        .arg("color.ui=false")
        .arg("-c")
        .arg("core.autocrlf=false")
        .arg("-c")
        .arg("core.eol=lf")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.pager=cat")
        .arg("-c")
        .arg("core.safecrlf=false")
        .arg("-c")
        .arg("core.untrackedCache=false")
        .arg("-c")
        .arg("submodule.recurse=false")
        .arg("-C")
        .arg(repository)
        .env("GIT_CONFIG_GLOBAL", empty_git_config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0");
    command
}

fn read_pipe_bounded(
    mut reader: impl std::io::Read,
    maximum_retained_bytes: u64,
) -> std::io::Result<BoundedPipeOutput> {
    let mut bytes = Vec::new();
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        let retained = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let keep = maximum_retained_bytes
            .saturating_sub(retained)
            .min(u64::try_from(count).unwrap_or(u64::MAX));
        bytes.extend_from_slice(&buffer[..usize::try_from(keep).unwrap_or(0)]);
    }
    Ok(BoundedPipeOutput { bytes, total_bytes })
}

fn join_pipe_reader(
    result: std::thread::Result<std::io::Result<BoundedPipeOutput>>,
    operation: &'static str,
) -> Result<BoundedPipeOutput, TemporaryGitWorktreeError> {
    result
        .map_err(|_| TemporaryGitWorktreeError::Io {
            operation,
            source: std::io::Error::other("Git output reader panicked"),
        })?
        .map_err(|source| TemporaryGitWorktreeError::Io { operation, source })
}

#[cfg(test)]
fn identity_output(
    output: &std::process::Output,
    operation: &'static str,
) -> Result<String, TemporaryGitWorktreeError> {
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| TemporaryGitWorktreeError::NonUtf8Identity { operation })?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn valid_git_object_identity(identity: &str) -> bool {
    matches!(identity.len(), 40 | 64) && identity.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

/// Derives the closed clean-HEAD workspace binding for one exact Git commit.
#[must_use]
pub fn git_baseline_sha256(base_commit: &str) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(GIT_BASELINE_DIGEST_DOMAIN.len() + base_commit.len());
    bytes.extend_from_slice(GIT_BASELINE_DIGEST_DOMAIN);
    bytes.extend_from_slice(base_commit.as_bytes());
    Sha256Digest::of_bytes(&bytes)
}

fn parse_numstat_changed_paths(
    bytes: &[u8],
) -> Result<Vec<RepositoryRelativePathV1>, TemporaryGitWorktreeError> {
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES {
        return Err(TemporaryGitWorktreeError::ChangedPathsTooLarge {
            actual,
            maximum: GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES,
        });
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let Some(records) = bytes.strip_suffix(&[0]) else {
        return Err(TemporaryGitWorktreeError::InvalidNumstatObservation);
    };
    let mut paths = Vec::new();
    for record in records.split(|byte| *byte == 0) {
        if record.is_empty() {
            return Err(TemporaryGitWorktreeError::InvalidNumstatObservation);
        }
        if paths.len() >= GIT_WORKTREE_CHANGED_PATHS_MAX_ENTRIES {
            return Err(TemporaryGitWorktreeError::ChangedPathCountTooLarge {
                actual: paths.len().saturating_add(1),
                maximum: GIT_WORKTREE_CHANGED_PATHS_MAX_ENTRIES,
            });
        }
        let Some(first_tab) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(TemporaryGitWorktreeError::InvalidNumstatObservation);
        };
        let Some(second_tab_offset) = record[first_tab.saturating_add(1)..]
            .iter()
            .position(|byte| *byte == b'\t')
        else {
            return Err(TemporaryGitWorktreeError::InvalidNumstatObservation);
        };
        let second_tab = first_tab
            .saturating_add(1)
            .saturating_add(second_tab_offset);
        let added = &record[..first_tab];
        let deleted = &record[first_tab.saturating_add(1)..second_tab];
        let path = &record[second_tab.saturating_add(1)..];
        if !valid_numstat_counts(added, deleted) || path.is_empty() {
            return Err(TemporaryGitWorktreeError::InvalidNumstatObservation);
        }
        let components = path
            .split(|byte| *byte == b'/')
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        if !valid_changed_path_components(&components) {
            return Err(TemporaryGitWorktreeError::InvalidNumstatObservation);
        }
        paths.push(RepositoryRelativePathV1::Unix { components });
    }
    paths.sort_unstable_by(|left, right| left.unix_components().cmp(right.unix_components()));
    if paths
        .windows(2)
        .any(|pair| pair[0].unix_components() == pair[1].unix_components())
    {
        return Err(TemporaryGitWorktreeError::InvalidNumstatObservation);
    }
    Ok(paths)
}

fn valid_numstat_counts(added: &[u8], deleted: &[u8]) -> bool {
    let added_binary = added == b"-";
    let deleted_binary = deleted == b"-";
    (added_binary && deleted_binary)
        || (!added_binary
            && !deleted_binary
            && valid_canonical_decimal(added)
            && valid_canonical_decimal(deleted))
}

fn valid_canonical_decimal(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && (value == b"0" || value.first().is_some_and(|byte| *byte != b'0'))
        && std::str::from_utf8(value)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .is_some()
}

fn encode_repository_path(
    path: &RepositoryRelativePathV1,
) -> Result<Vec<u8>, TemporaryGitWorktreeError> {
    if !valid_changed_path_components(path.unix_components()) {
        return Err(TemporaryGitWorktreeError::InvalidRepositoryPath);
    }
    let mut bytes = Vec::new();
    for (index, component) in path.unix_components().iter().enumerate() {
        if index > 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(component);
    }
    Ok(bytes)
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the matching non-Unix implementation fails closed with the same fallible API"
)]
fn literal_pathspec(raw_path: &[u8]) -> Result<OsString, TemporaryGitWorktreeError> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut pathspec = b":(literal)".to_vec();
    pathspec.extend_from_slice(raw_path);
    Ok(OsString::from_vec(pathspec))
}

#[cfg(not(unix))]
fn literal_pathspec(_raw_path: &[u8]) -> Result<OsString, TemporaryGitWorktreeError> {
    Err(TemporaryGitWorktreeError::UnsupportedRepositoryPathPlatform)
}

fn parse_ls_tree_regular_file(
    bytes: &[u8],
    expected_path: &[u8],
) -> Result<bool, TemporaryGitWorktreeError> {
    if bytes.is_empty() {
        return Ok(false);
    }
    let Some(record) = bytes.strip_suffix(&[0]) else {
        return Err(TemporaryGitWorktreeError::InvalidLsTreeObservation);
    };
    if record.is_empty() || record.contains(&0) {
        return Err(TemporaryGitWorktreeError::InvalidLsTreeObservation);
    }
    let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
        return Err(TemporaryGitWorktreeError::InvalidLsTreeObservation);
    };
    let metadata = &record[..tab];
    let observed_path = &record[tab.saturating_add(1)..];
    let fields = metadata.split(|byte| *byte == b' ').collect::<Vec<_>>();
    if fields.len() != 3
        || observed_path != expected_path
        || std::str::from_utf8(fields[2])
            .ok()
            .is_none_or(|object| !valid_git_object_identity(object))
    {
        return Err(TemporaryGitWorktreeError::InvalidLsTreeObservation);
    }
    match (fields[0], fields[1]) {
        (b"100644" | b"100755", b"blob") => Ok(true),
        (b"120000", b"blob") | (b"040000", b"tree") | (b"160000", b"commit") => Ok(false),
        _ => Err(TemporaryGitWorktreeError::InvalidLsTreeObservation),
    }
}

fn changed_paths_are_canonical(paths: &[RepositoryRelativePathV1]) -> bool {
    if paths.len() > GIT_WORKTREE_CHANGED_PATHS_MAX_ENTRIES
        || paths
            .iter()
            .any(|path| !valid_changed_path_components(path.unix_components()))
        || paths
            .windows(2)
            .any(|pair| pair[0].unix_components() >= pair[1].unix_components())
    {
        return false;
    }
    let encoded_bytes = paths.iter().fold(0_u64, |total, path| {
        path.unix_components()
            .iter()
            .fold(total, |path_total, component| {
                path_total
                    .saturating_add(u64::try_from(component.len()).unwrap_or(u64::MAX))
                    .saturating_add(1)
            })
    });
    encoded_bytes <= GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES
}

fn valid_changed_path_components(components: &[Vec<u8>]) -> bool {
    if components.is_empty() || components.len() > GIT_WORKTREE_CHANGED_PATH_MAX_COMPONENTS {
        return false;
    }
    let mut path_bytes = components.len().saturating_sub(1);
    for component in components {
        if component.is_empty()
            || component == b"."
            || component == b".."
            || component.len() > GIT_WORKTREE_CHANGED_PATH_MAX_COMPONENT_BYTES
            || component.contains(&0)
            || component.contains(&b'/')
        {
            return false;
        }
        path_bytes = path_bytes.saturating_add(component.len());
    }
    path_bytes <= GIT_WORKTREE_CHANGED_PATH_MAX_BYTES
}

#[cfg(unix)]
fn machine_worktree_paths(bytes: &[u8]) -> impl Iterator<Item = PathBuf> + '_ {
    use std::os::unix::ffi::OsStrExt as _;
    bytes.split(|byte| *byte == 0).filter_map(|field| {
        field
            .strip_prefix(b"worktree ")
            .map(|value| PathBuf::from(OsStr::from_bytes(value)))
    })
}

#[cfg(not(unix))]
fn machine_worktree_paths(bytes: &[u8]) -> impl Iterator<Item = PathBuf> + '_ {
    bytes.split(|byte| *byte == 0).filter_map(|field| {
        let value = field.strip_prefix(b"worktree ")?;
        String::from_utf8(value.to_vec()).ok().map(PathBuf::from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Output;

    fn git(repository: &Path, arguments: &[&str]) -> Output {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("Git should start");
        assert!(
            output.status.success(),
            "Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn committed_repository() -> tempfile::TempDir {
        let repository = tempfile::tempdir().expect("source repository");
        git(repository.path(), &["init", "--quiet"]);
        git(repository.path(), &["config", "user.name", "BirdCode Test"]);
        git(
            repository.path(),
            &["config", "user.email", "birdcode@example.invalid"],
        );
        fs::write(repository.path().join("tracked.txt"), b"before\n").expect("tracked fixture");
        git(repository.path(), &["add", "tracked.txt"]);
        git(repository.path(), &["commit", "--quiet", "-m", "fixture"]);
        repository
    }

    #[test]
    fn isolated_worktree_captures_exact_diff_and_releases_registration() {
        let repository = committed_repository();
        let scratch = tempfile::tempdir().expect("scratch root");
        let original = fs::read(repository.path().join("tracked.txt")).expect("source bytes");
        let source_head = identity_output(
            &git(repository.path(), &["rev-parse", "HEAD"]),
            "test source head",
        )
        .expect("source identity");

        let mut worktree = TemporaryGitWorktree::create(repository.path(), scratch.path())
            .expect("create worktree");
        let worktree_path = worktree.path().to_path_buf();
        assert_eq!(worktree.base_commit(), source_head);
        assert_eq!(
            fs::read(worktree.path().join("tracked.txt")).expect("worktree bytes"),
            original
        );

        fs::write(worktree.path().join("tracked.txt"), b"after\n").expect("write isolated change");
        let diff = worktree.tracked_diff().expect("capture diff");
        assert!(diff.is_exact());
        assert_eq!(diff.base_commit, source_head);
        assert_eq!(
            diff.changed_paths,
            vec![RepositoryRelativePathV1::Unix {
                components: vec![b"tracked.txt".to_vec()],
            }]
        );
        assert!(
            diff.bytes
                .windows(b"-before\n+after\n".len())
                .any(|window| window == b"-before\n+after\n")
        );
        assert_eq!(
            fs::read(repository.path().join("tracked.txt")).expect("unchanged source"),
            original
        );
        assert!(
            git(repository.path(), &["status", "--porcelain"])
                .stdout
                .is_empty()
        );

        worktree.release().expect("release worktree");
        assert!(!worktree.is_active());
        assert!(!worktree_path.exists());
        let registrations = git(
            repository.path(),
            &["worktree", "list", "--porcelain", "-z"],
        );
        assert!(!machine_worktree_paths(&registrations.stdout).any(|path| path == worktree_path));
    }

    #[test]
    fn clean_committed_head_acquisition_is_exact_pristine_and_descriptor_identified() {
        let repository = committed_repository();
        let scratch = tempfile::tempdir().expect("scratch root");
        let source_head = identity_output(
            &git(repository.path(), &["rev-parse", "HEAD"]),
            "test source head",
        )
        .expect("source identity");

        let mut worktree =
            TemporaryGitWorktree::create_clean_committed_head(repository.path(), scratch.path())
                .expect("clean committed-HEAD acquisition");
        assert_eq!(worktree.base_commit(), source_head);
        assert!(worktree.is_pristine().expect("pristine acquired worktree"));
        let first_identity = worktree.root_identity().expect("held root identity");
        assert_eq!(
            worktree.root_identity().expect("stable root identity"),
            first_identity
        );
        let tracked_path = RepositoryRelativePathV1::Unix {
            components: vec![b"tracked.txt".to_vec()],
        };
        let read = worktree
            .read_utf8_file(&tracked_path)
            .expect("descriptor-confined UTF-8 read");
        assert_eq!(read.path, tracked_path);
        assert_eq!(read.content_utf8, "before\n");
        assert_eq!(read.observation.byte_len, 7);
        assert_eq!(
            read.observation.sha256,
            Sha256Digest::of_bytes(read.content_utf8.as_bytes())
        );

        worktree.release().expect("release acquired worktree");
        assert!(matches!(
            worktree.root_identity(),
            Err(GitWorktreeFileReplaceError::WorktreeNotActive)
        ));
    }

    #[test]
    fn clean_committed_head_rejects_modified_staged_untracked_and_ignored_source_state() {
        fn assert_rejected(repository: &Path) {
            let scratch = tempfile::tempdir().expect("scratch root");
            let error =
                TemporaryGitWorktree::create_clean_committed_head(repository, scratch.path())
                    .expect_err("dirty source must be rejected");
            assert!(matches!(
                error,
                TemporaryGitWorktreeError::SourceRepositoryNotPristine {
                    phase: GitCleanCommittedHeadObservationPhaseV1::BeforeAcquisition,
                }
            ));
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

        let modified = committed_repository();
        fs::write(modified.path().join("tracked.txt"), b"modified\n").expect("modified fixture");
        assert_rejected(modified.path());

        let staged = committed_repository();
        fs::write(staged.path().join("tracked.txt"), b"staged\n").expect("staged fixture");
        git(staged.path(), &["add", "tracked.txt"]);
        assert_rejected(staged.path());

        let untracked = committed_repository();
        fs::write(untracked.path().join("untracked.txt"), b"untracked\n")
            .expect("untracked fixture");
        assert_rejected(untracked.path());

        let ignored = committed_repository();
        fs::write(ignored.path().join(".gitignore"), b"ignored.tmp\n").expect("ignore rule");
        git(ignored.path(), &["add", ".gitignore"]);
        git(
            ignored.path(),
            &["commit", "--quiet", "-m", "ignore fixture"],
        );
        fs::write(ignored.path().join("ignored.tmp"), b"ignored\n").expect("ignored fixture");
        assert_rejected(ignored.path());
    }

    #[test]
    fn clean_committed_head_rejects_sparse_checkout() {
        let repository = committed_repository();
        git(repository.path(), &["sparse-checkout", "init", "--cone"]);
        let scratch = tempfile::tempdir().expect("scratch root");
        let error =
            TemporaryGitWorktree::create_clean_committed_head(repository.path(), scratch.path())
                .expect_err("sparse checkout must be rejected");
        assert!(matches!(
            error,
            TemporaryGitWorktreeError::SparseCheckoutUnsupported {
                phase: GitCleanCommittedHeadObservationPhaseV1::BeforeAcquisition,
            }
        ));
    }

    #[test]
    fn clean_committed_head_rejects_replace_refs_and_legacy_create_neutralizes_them() {
        let repository = committed_repository();
        let original_head = identity_output(
            &git(repository.path(), &["rev-parse", "HEAD"]),
            "original head",
        )
        .expect("original head identity");
        fs::write(repository.path().join("tracked.txt"), b"replacement\n")
            .expect("replacement fixture");
        git(repository.path(), &["add", "tracked.txt"]);
        git(
            repository.path(),
            &["commit", "--quiet", "-m", "replacement fixture"],
        );
        let replacement_head = identity_output(
            &git(repository.path(), &["rev-parse", "HEAD"]),
            "replacement head",
        )
        .expect("replacement head identity");
        git(repository.path(), &["reset", "--hard", &original_head]);
        git(
            repository.path(),
            &["replace", &original_head, &replacement_head],
        );
        assert_eq!(
            git(repository.path(), &["show", "HEAD:tracked.txt"]).stdout,
            b"replacement\n",
            "fixture must demonstrate active replacement semantics"
        );

        let clean_scratch = tempfile::tempdir().expect("clean scratch root");
        let error = TemporaryGitWorktree::create_clean_committed_head(
            repository.path(),
            clean_scratch.path(),
        )
        .expect_err("replace refs must be rejected by the clean profile");
        assert!(matches!(
            error,
            TemporaryGitWorktreeError::ReplaceRefsUnsupported {
                phase: GitCleanCommittedHeadObservationPhaseV1::BeforeAcquisition,
            }
        ));

        let legacy_scratch = tempfile::tempdir().expect("legacy scratch root");
        let mut worktree = TemporaryGitWorktree::create(repository.path(), legacy_scratch.path())
            .expect("legacy profile must neutralize replacement semantics");
        assert_eq!(worktree.base_commit(), original_head);
        assert_eq!(
            fs::read(worktree.path().join("tracked.txt")).expect("legacy worktree content"),
            b"before\n"
        );
        worktree.release().expect("release legacy worktree");
    }

    #[test]
    fn clean_committed_head_rejects_assume_unchanged_and_skip_worktree_index_flags() {
        fn assert_rejected(repository: &Path) {
            let scratch = tempfile::tempdir().expect("scratch root");
            let error =
                TemporaryGitWorktree::create_clean_committed_head(repository, scratch.path())
                    .expect_err("hidden index flags must be rejected");
            assert!(matches!(
                error,
                TemporaryGitWorktreeError::IndexEntryFlagsUnsupported {
                    phase: GitCleanCommittedHeadObservationPhaseV1::BeforeAcquisition,
                }
            ));
        }

        let assume_unchanged = committed_repository();
        git(
            assume_unchanged.path(),
            &["update-index", "--assume-unchanged", "tracked.txt"],
        );
        assert_rejected(assume_unchanged.path());

        let skip_worktree = committed_repository();
        git(
            skip_worktree.path(),
            &["update-index", "--skip-worktree", "tracked.txt"],
        );
        assert_rejected(skip_worktree.path());
    }

    #[test]
    fn worktree_checkout_rejects_repository_filter_configuration() {
        let repository = committed_repository();
        git(
            repository.path(),
            &["config", "filter.danger.process", "/not/executed"],
        );
        let scratch = tempfile::tempdir().expect("scratch root");
        let error = TemporaryGitWorktree::create(repository.path(), scratch.path())
            .expect_err("repository filter configuration must be rejected before checkout");
        assert!(matches!(
            error,
            TemporaryGitWorktreeError::RepositoryFilterConfigurationUnsupported
        ));
    }

    #[cfg(unix)]
    #[test]
    fn clean_committed_head_disables_repository_fsmonitor_executable() {
        use std::os::unix::fs::PermissionsExt as _;

        let repository = committed_repository();
        let hook_directory = tempfile::tempdir().expect("fsmonitor fixture directory");
        let hook = hook_directory.path().join("must-not-run");
        fs::write(&hook, b"#!/bin/sh\nexit 97\n").expect("fsmonitor hook fixture");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755))
            .expect("executable fsmonitor hook");
        git(
            repository.path(),
            &[
                "config",
                "core.fsmonitor",
                hook.to_str().expect("UTF-8 fixture path"),
            ],
        );

        let scratch = tempfile::tempdir().expect("scratch root");
        let mut worktree =
            TemporaryGitWorktree::create_clean_committed_head(repository.path(), scratch.path())
                .expect("command-line fsmonitor disable must override repository executable");
        worktree.release().expect("release worktree");
    }

    #[test]
    fn drop_best_effort_removes_owned_worktree() {
        let repository = committed_repository();
        let scratch = tempfile::tempdir().expect("scratch root");
        let path = {
            let worktree = TemporaryGitWorktree::create(repository.path(), scratch.path())
                .expect("create worktree");
            worktree.path().to_path_buf()
        };
        assert!(!path.exists());
        let registrations = git(
            repository.path(),
            &["worktree", "list", "--porcelain", "-z"],
        );
        assert!(!machine_worktree_paths(&registrations.stdout).any(|entry| entry == path));
    }

    #[test]
    fn scratch_root_may_not_overlap_repository() {
        let repository = committed_repository();
        let error = TemporaryGitWorktree::create(repository.path(), repository.path())
            .expect_err("overlapping root should fail");
        assert!(matches!(error, TemporaryGitWorktreeError::OverlappingRoots));
        assert!(
            git(repository.path(), &["status", "--porcelain"])
                .stdout
                .is_empty(),
            "overlap rejection must not mutate the source repository"
        );
        assert!(
            fs::read_dir(repository.path())
                .expect("source entries")
                .all(|entry| !entry
                    .expect("source entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("birdcode-git-control-"))
        );
    }

    #[test]
    fn object_identity_validation_accepts_sha1_and_sha256_only() {
        assert!(valid_git_object_identity(&"a".repeat(40)));
        assert!(valid_git_object_identity(&"B".repeat(64)));
        assert!(!valid_git_object_identity(&"a".repeat(39)));
        assert!(!valid_git_object_identity(&"g".repeat(40)));
    }

    #[cfg(unix)]
    #[test]
    fn pristine_tree_lookup_and_patch_paths_preserve_exact_raw_names() {
        use std::os::unix::ffi::OsStringExt as _;
        use std::os::unix::fs::symlink;

        let repository = committed_repository();
        let raw_name = if cfg!(target_os = "macos") {
            "literal[*]\n\t日本語.txt".as_bytes().to_vec()
        } else {
            b"literal[*]\n\t\xff.txt".to_vec()
        };
        let raw_os_name = OsString::from_vec(raw_name.clone());
        fs::write(repository.path().join(&raw_os_name), b"raw preimage\n")
            .expect("raw tracked fixture");
        fs::write(repository.path().join(".gitignore"), b"ignored.tmp\n").expect("ignore fixture");
        symlink("tracked.txt", repository.path().join("tracked-link"))
            .expect("tracked symlink fixture");
        git(repository.path(), &["add", "-A"]);
        git(
            repository.path(),
            &["commit", "--quiet", "-m", "raw fixture"],
        );

        let scratch = tempfile::tempdir().expect("scratch root");
        let mut worktree = TemporaryGitWorktree::create(repository.path(), scratch.path())
            .expect("create worktree");
        let raw_path = RepositoryRelativePathV1::Unix {
            components: vec![raw_name.clone()],
        };
        assert!(worktree.is_pristine().expect("initial pristine state"));
        assert!(
            worktree
                .base_commit_tracks_regular_file(&raw_path)
                .expect("raw base lookup")
        );
        assert!(
            !worktree
                .base_commit_tracks_regular_file(&RepositoryRelativePathV1::Unix {
                    components: vec![b"tracked-link".to_vec()],
                })
                .expect("symlink base lookup")
        );
        assert!(
            !worktree
                .base_commit_tracks_regular_file(&RepositoryRelativePathV1::Unix {
                    components: vec![b"missing[*]".to_vec()],
                })
                .expect("literal missing lookup")
        );

        fs::write(worktree.path().join(&raw_os_name), b"raw postimage\n").expect("modify raw path");
        let diff = worktree.tracked_diff().expect("raw path diff");
        assert_eq!(diff.changed_paths, vec![raw_path]);
        fs::write(worktree.path().join(&raw_os_name), b"raw preimage\n").expect("restore raw path");
        assert!(worktree.is_pristine().expect("restored pristine state"));

        let untracked = worktree.path().join("untracked.txt");
        fs::write(&untracked, b"untracked\n").expect("untracked fixture");
        assert!(!worktree.is_pristine().expect("untracked state"));
        fs::remove_file(untracked).expect("remove untracked fixture");
        assert!(worktree.is_pristine().expect("untracked cleanup"));

        let ignored = worktree.path().join("ignored.tmp");
        fs::write(&ignored, b"ignored\n").expect("ignored fixture");
        assert!(!worktree.is_pristine().expect("ignored state"));
        fs::remove_file(ignored).expect("remove ignored fixture");
        assert!(worktree.is_pristine().expect("ignored cleanup"));

        fs::write(worktree.path().join("tracked.txt"), b"tracked change\n")
            .expect("tracked fixture");
        assert!(!worktree.is_pristine().expect("tracked state"));
        worktree.release().expect("release worktree");
    }

    #[test]
    fn changed_path_observation_is_raw_nul_separated_bounded_and_sorted() {
        let paths = parse_numstat_changed_paths(b"1\t0\tzeta\n.rs\0-\t-\tdir/\xff.rs\0")
            .expect("changed paths");
        assert_eq!(
            paths,
            vec![
                RepositoryRelativePathV1::Unix {
                    components: vec![b"dir".to_vec(), b"\xff.rs".to_vec()],
                },
                RepositoryRelativePathV1::Unix {
                    components: vec![b"zeta\n.rs".to_vec()],
                },
            ]
        );
        assert!(changed_paths_are_canonical(&paths));
    }

    #[test]
    fn changed_path_observation_rejects_malformed_counts_paths_and_duplicates() {
        for invalid in [
            b"1\t0\tunterminated".as_slice(),
            b"1\t0\tfirst\0\0".as_slice(),
            b"1\t0\tsame\x000\t1\tsame\0".as_slice(),
            b"1\t0\tparent/../file\0".as_slice(),
            b"x\t0\tfile\0".as_slice(),
            b"-\t0\tfile\0".as_slice(),
            b"01\t0\tfile\0".as_slice(),
        ] {
            assert!(matches!(
                parse_numstat_changed_paths(invalid),
                Err(TemporaryGitWorktreeError::InvalidNumstatObservation)
            ));
        }

        let oversized = vec![
            b'a';
            usize::try_from(GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES)
                .expect("changed-path bound fits usize")
                + 1
        ];
        assert!(matches!(
            parse_numstat_changed_paths(&oversized),
            Err(TemporaryGitWorktreeError::ChangedPathsTooLarge { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_utf8_replace_has_no_effect_then_atomically_updates_only_worktree() {
        use std::os::unix::fs::PermissionsExt as _;

        let repository = committed_repository();
        let scratch = tempfile::tempdir().expect("scratch root");
        let mut worktree = TemporaryGitWorktree::create(repository.path(), scratch.path())
            .expect("create worktree");
        let target = worktree.path().join("tracked.txt");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .expect("set executable fixture");
        let before = fs::read(&target).expect("preimage");
        let expected_preimage_sha256 = Sha256Digest::of_bytes(&before);
        let prepared = worktree
            .prepare_utf8_file_replace(GitWorktreeUtf8FileReplaceRequestV1 {
                path: birdcode_protocol::RepositoryRelativePathV1::Unix {
                    components: vec![b"tracked.txt".to_vec()],
                },
                expected_preimage_sha256: expected_preimage_sha256.clone(),
                replacement_utf8: "after through typed mutation\n".to_owned(),
                max_replacement_bytes: 1024,
            })
            .expect("prepare replacement");
        assert_eq!(fs::read(&target).expect("still preimage"), before);
        assert_eq!(prepared.receipt().preimage.sha256, expected_preimage_sha256);

        let result = worktree
            .execute_prepared_utf8_file_replace(&prepared)
            .expect("execute replacement");
        let after = fs::read(&target).expect("postimage");
        assert_eq!(after, b"after through typed mutation\n");
        assert_eq!(result.postimage.sha256, Sha256Digest::of_bytes(&after));
        assert_eq!(
            fs::metadata(&target)
                .expect("postimage metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(
            fs::read_dir(worktree.path())
                .expect("worktree entries")
                .all(|entry| !entry
                    .expect("worktree entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".birdcode-edit-"))
        );
        assert_eq!(
            fs::read(repository.path().join("tracked.txt")).expect("source remains unchanged"),
            b"before\n"
        );
        assert!(
            !worktree
                .tracked_diff()
                .expect("tracked diff")
                .bytes
                .is_empty()
        );
        worktree.release().expect("release worktree");
    }

    #[cfg(unix)]
    #[test]
    fn preimage_mismatch_and_symlink_target_have_no_mutation_effect() {
        use std::os::unix::fs::symlink;

        let repository = committed_repository();
        let scratch = tempfile::tempdir().expect("scratch root");
        let mut worktree = TemporaryGitWorktree::create(repository.path(), scratch.path())
            .expect("create worktree");
        let target = worktree.path().join("tracked.txt");
        let mismatch = worktree
            .prepare_utf8_file_replace(GitWorktreeUtf8FileReplaceRequestV1 {
                path: birdcode_protocol::RepositoryRelativePathV1::Unix {
                    components: vec![b"tracked.txt".to_vec()],
                },
                expected_preimage_sha256: Sha256Digest::of_bytes(b"not the file"),
                replacement_utf8: "forbidden\n".to_owned(),
                max_replacement_bytes: 1024,
            })
            .expect_err("mismatched preimage should fail");
        assert!(matches!(
            mismatch,
            GitWorktreeFileReplaceError::PreimageMismatch { .. }
        ));
        assert_eq!(fs::read(&target).expect("unchanged target"), b"before\n");

        fs::remove_file(&target).expect("remove worktree target");
        symlink(repository.path().join("tracked.txt"), &target).expect("symlink fixture");
        let symlink_error = worktree
            .prepare_utf8_file_replace(GitWorktreeUtf8FileReplaceRequestV1 {
                path: birdcode_protocol::RepositoryRelativePathV1::Unix {
                    components: vec![b"tracked.txt".to_vec()],
                },
                expected_preimage_sha256: Sha256Digest::of_bytes(b"before\n"),
                replacement_utf8: "forbidden\n".to_owned(),
                max_replacement_bytes: 1024,
            })
            .expect_err("symlink should fail");
        assert!(matches!(
            symlink_error,
            GitWorktreeFileReplaceError::WrongFileType
        ));
        assert_eq!(
            fs::read(repository.path().join("tracked.txt")).expect("external source"),
            b"before\n"
        );
    }
}
