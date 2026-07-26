//! macOS-first workspace isolation, temporary Git worktrees and repository
//! snapshot lifecycle.
//!
//! The crate performs deterministic filesystem and operating-system mechanics.
//! It never writes `BirdCode`'s Store or event log. Instead, every durable
//! boundary returns exact artifacts and Protocol payloads, and later phases
//! require the caller to present the exact committed [`EventEnvelope`].
//!
//! The v1 adapter uses a cooperative in-process writer gate plus identical
//! descriptor-confined source manifests around `hdiutil create`. This is not an
//! APFS-atomic snapshot claim. The resulting disk image is mounted read-only and
//! independently checked through mount flags and a descriptor-relative write
//! probe.

mod artifact;
mod boundary;
mod journal;
mod manager;
mod manifest;
mod platform;
mod plist_decode;
mod recovery;
mod worktree;
mod worktree_edit;

pub use artifact::{
    ArtifactBoundary, ArtifactBoundaryError, CanonicalArtifactBoundary, RetainedArtifact,
};
pub use boundary::{
    ClockBoundary, ClockBoundaryError, CommandBoundary, CommandBoundaryError,
    CommandBoundaryErrorKind, PreparedMacOsCommand, PreparedMacOsRecoveryInspection,
    RawCommandOutput, SystemClock, SystemCommandBoundary,
};
pub use journal::{
    CleanupJournalRecordV1, CleanupStageV1, FileCleanupJournal, RecoveryDispositionV1,
    RecoveryInspectionV1,
};
pub use manager::{
    ActiveSnapshotLease, CapturePrepared, CapturedImage, CommittedSnapshotLease,
    CommittedWriterRevocation, PreparedSnapshot, SnapshotAttachPrepared, SnapshotLeaseBundle,
    SnapshotReleaseBundle, SnapshotReleasePrepared, SnapshotReleaseRequestV1, SnapshotRequestV1,
    WorkspaceManager, WorkspaceManagerConfig, WorkspaceManagerError, WorkspaceWriterPermit,
    WriterRevocationBundle,
};
pub use manifest::{
    ManifestError, ManifestLimitKindV1, RepositoryContentManifestV1, RepositoryManifestEntryV1,
    RepositoryManifestLimitsV1, RepositoryManifestNodeKindV1,
};
pub use platform::{MountPresence, PlatformError};
pub use plist_decode::AttachPlistError;
pub use recovery::{
    CommittedSnapshotLeaseRecoveryV1, RecoveredSnapshotLease, RecoveryBlockedReasonV1,
    RecoveryCommandEvidenceV1, RecoveryCommandKindV1, RecoveryDirectiveAssignmentV1,
    RecoveryEntryOutcomeV1, RecoveryImageObservationV1, RecoveryMountObservationV1,
    RecoveryPathAttestationV1, RecoveryTopologyBlockV1, RecoveryTopologyObservationV1,
    SnapshotRecoveryDirectiveV1, WorkspaceRecoveryEntryV1, WorkspaceRecoveryError,
    WorkspaceRecoveryReportV1, WorkspaceRecoveryRequestV1,
};
pub use worktree::{
    GIT_WORKTREE_CHANGED_PATHS_MAX_BYTES, GIT_WORKTREE_CHANGED_PATHS_MAX_ENTRIES,
    GIT_WORKTREE_DIFF_MAX_BYTES, GIT_WORKTREE_DIFF_MEDIA_TYPE,
    GitCleanCommittedHeadObservationPhaseV1, GitWorktreeDiff, TemporaryGitWorktree,
    TemporaryGitWorktreeError, git_baseline_sha256,
};
pub use worktree_edit::{
    GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES, GitWorktreeFileObservationV1,
    GitWorktreeFileReplaceError, GitWorktreeMutationIoOperation, GitWorktreeUtf8FileReadV1,
    GitWorktreeUtf8FileReplacePreparedV1, GitWorktreeUtf8FileReplaceRequestV1,
    GitWorktreeUtf8FileReplaceResultV1, PreparedGitWorktreeUtf8FileReplace,
};

pub const COMMAND_STDOUT_MEDIA_TYPE: &str =
    "application/vnd.birdcode.workspace-command-stdout.v1+octet-stream";
pub const COMMAND_STDERR_MEDIA_TYPE: &str = birdcode_protocol::WORKSPACE_COMMAND_STDERR_MEDIA_TYPE;
pub const RAW_MACOS_PLIST_MEDIA_TYPE: &str = "application/x-plist";
pub const SOURCE_CONTENT_MANIFEST_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-content-manifest.v1+json";
pub const RECOVERY_HDIUTIL_INFO_MEDIA_TYPE: &str =
    birdcode_protocol::WORKSPACE_RECOVERY_HDIUTIL_INFO_MEDIA_TYPE;
