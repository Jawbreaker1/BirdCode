use birdcode_protocol::{
    RepositoryFileIdentityV1, RepositoryPathViolationV1, RepositoryRelativePathV1,
    RepositoryUnixFileIdentityV1, Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

pub const GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES: u64 = 1024 * 1024;
const GIT_WORKTREE_PREIMAGE_HARD_MAX_BYTES: u64 = 4 * 1024 * 1024;
const GIT_WORKTREE_MAX_PATH_COMPONENTS: usize = 64;
const GIT_WORKTREE_MAX_PATH_BYTES: usize = 4096;
const GIT_WORKTREE_MAX_COMPONENT_BYTES: usize = 255;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitWorktreeFileObservationV1 {
    pub byte_len: u64,
    pub sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitWorktreeUtf8FileReadV1 {
    pub path: RepositoryRelativePathV1,
    pub content_utf8: String,
    pub observation: GitWorktreeFileObservationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWorktreeUtf8FileReplaceRequestV1 {
    pub path: RepositoryRelativePathV1,
    pub expected_preimage_sha256: Sha256Digest,
    pub replacement_utf8: String,
    pub max_replacement_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitWorktreeUtf8FileReplacePreparedV1 {
    pub operation_id: Uuid,
    pub worktree_id: Uuid,
    pub path: RepositoryRelativePathV1,
    pub preimage: GitWorktreeFileObservationV1,
    pub postimage: GitWorktreeFileObservationV1,
}

#[derive(Clone, Debug)]
pub struct PreparedGitWorktreeUtf8FileReplace {
    receipt: GitWorktreeUtf8FileReplacePreparedV1,
    replacement: Vec<u8>,
    #[cfg(unix)]
    unix_mode: rustix::fs::RawMode,
    #[cfg(not(unix))]
    unix_mode: u32,
    preimage_identity: RepositoryFileIdentityV1,
}

impl PreparedGitWorktreeUtf8FileReplace {
    #[must_use]
    pub const fn receipt(&self) -> &GitWorktreeUtf8FileReplacePreparedV1 {
        &self.receipt
    }

    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.receipt.operation_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitWorktreeUtf8FileReplaceResultV1 {
    pub operation_id: Uuid,
    pub worktree_id: Uuid,
    pub path: RepositoryRelativePathV1,
    pub preimage: GitWorktreeFileObservationV1,
    pub postimage: GitWorktreeFileObservationV1,
    pub parent_directory_fsynced: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitWorktreeMutationIoOperation {
    OpenRoot,
    DuplicateRoot,
    OpenParent,
    StatNode,
    OpenFile,
    ReadFile,
    CreateTemporary,
    WriteTemporary,
    SyncTemporary,
    SetPermissions,
    Rename,
    SyncParent,
    RemoveTemporary,
}

#[derive(Debug, Error)]
pub enum GitWorktreeFileReplaceError {
    #[error("worktree mutation is available only on Unix")]
    UnsupportedPlatform,
    #[error("worktree is not active")]
    WorktreeNotActive,
    #[error("a different prepared mutation already owns the worktree writer lane")]
    MutationAlreadyPrepared,
    #[error("the worktree mutation lane requires reconciliation")]
    MutationLanePoisoned,
    #[error("prepared mutation belongs to a different worktree or writer lane")]
    PreparedMutationMismatch,
    #[error("invalid repository path component {component_index:?}: {violation:?}")]
    InvalidPath {
        violation: RepositoryPathViolationV1,
        component_index: Option<u32>,
    },
    #[error("repository path may not address Git administrative metadata")]
    ReservedGitPath,
    #[error("replacement limit must be in 1..={maximum} bytes")]
    InvalidReplacementLimit { maximum: u64 },
    #[error("replacement has {actual} bytes; maximum is {maximum}")]
    ReplacementTooLarge { actual: u64, maximum: u64 },
    #[error("preimage has {actual} bytes; maximum is {maximum}")]
    PreimageTooLarge { actual: u64, maximum: u64 },
    #[error("target preimage is not UTF-8")]
    PreimageNotUtf8,
    #[error("target is not a regular file")]
    WrongFileType,
    #[error("filesystem traversal crossed the worktree device boundary")]
    CrossDeviceBoundary,
    #[error("target changed during exact observation")]
    NodeChanged,
    #[error("preimage SHA-256 does not match the granted digest")]
    PreimageMismatch {
        expected: Sha256Digest,
        observed: Sha256Digest,
    },
    #[error("worktree mutation {operation:?} failed (os error {raw_os_error:?})")]
    Io {
        operation: GitWorktreeMutationIoOperation,
        raw_os_error: Option<i32>,
    },
    #[error("worktree mutation outcome is unknown after {operation:?} (os error {raw_os_error:?})")]
    OutcomeUnknown {
        operation: GitWorktreeMutationIoOperation,
        raw_os_error: Option<i32>,
    },
}

impl GitWorktreeFileReplaceError {
    #[must_use]
    pub const fn may_have_mutated(&self) -> bool {
        matches!(self, Self::OutcomeUnknown { .. })
    }

    fn into_outcome_unknown(self, fallback_operation: GitWorktreeMutationIoOperation) -> Self {
        match self {
            error @ Self::OutcomeUnknown { .. } => error,
            Self::Io {
                operation,
                raw_os_error,
            } => Self::OutcomeUnknown {
                operation,
                raw_os_error,
            },
            _ => Self::OutcomeUnknown {
                operation: fallback_operation,
                raw_os_error: None,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct WorktreeMutationRoot {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(unix)]
    identity: WorktreeRootIdentity,
}

impl WorktreeMutationRoot {
    pub(crate) fn descriptor_identity(
        &self,
    ) -> Result<RepositoryFileIdentityV1, GitWorktreeFileReplaceError> {
        #[cfg(not(unix))]
        {
            Err(GitWorktreeFileReplaceError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            use rustix::fs::fstat;

            let stat = fstat(&self.fd)
                .map_err(|error| io_error(GitWorktreeMutationIoOperation::StatNode, error))?;
            if root_identity(stat) != self.identity {
                return Err(GitWorktreeFileReplaceError::NodeChanged);
            }
            Ok(file_identity(stat))
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorktreeRootIdentity {
    device: u64,
    inode: u64,
}

pub(crate) fn open_worktree_root(
    path: &Path,
) -> Result<WorktreeMutationRoot, GitWorktreeFileReplaceError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(GitWorktreeFileReplaceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, fstat, open};
        let fd = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::OpenRoot, error))?;
        let identity = fstat(&fd)
            .map(root_identity)
            .map_err(|error| io_error(GitWorktreeMutationIoOperation::StatNode, error))?;
        Ok(WorktreeMutationRoot { fd, identity })
    }
}

pub(crate) fn prepare_utf8_file_replace(
    root: &WorktreeMutationRoot,
    worktree_id: Uuid,
    request: GitWorktreeUtf8FileReplaceRequestV1,
) -> Result<PreparedGitWorktreeUtf8FileReplace, GitWorktreeFileReplaceError> {
    #[cfg(not(unix))]
    {
        let _ = (root, worktree_id, request);
        Err(GitWorktreeFileReplaceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        validate_path(&request.path)?;
        if request.max_replacement_bytes == 0
            || request.max_replacement_bytes > GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES
        {
            return Err(GitWorktreeFileReplaceError::InvalidReplacementLimit {
                maximum: GIT_WORKTREE_UTF8_REPLACE_HARD_MAX_BYTES,
            });
        }
        let replacement = request.replacement_utf8.into_bytes();
        let replacement_bytes = u64::try_from(replacement.len()).unwrap_or(u64::MAX);
        if replacement_bytes > request.max_replacement_bytes {
            return Err(GitWorktreeFileReplaceError::ReplacementTooLarge {
                actual: replacement_bytes,
                maximum: request.max_replacement_bytes,
            });
        }
        let (parent, file_name, root_device) = open_parent(root, &request.path)?;
        let observed = observe_file(&parent, file_name, root_device)?;
        if std::str::from_utf8(&observed.bytes).is_err() {
            return Err(GitWorktreeFileReplaceError::PreimageNotUtf8);
        }
        if observed.summary.sha256 != request.expected_preimage_sha256 {
            return Err(GitWorktreeFileReplaceError::PreimageMismatch {
                expected: request.expected_preimage_sha256,
                observed: observed.summary.sha256,
            });
        }
        let postimage = GitWorktreeFileObservationV1 {
            byte_len: replacement_bytes,
            sha256: Sha256Digest::of_bytes(&replacement),
        };
        Ok(PreparedGitWorktreeUtf8FileReplace {
            receipt: GitWorktreeUtf8FileReplacePreparedV1 {
                operation_id: Uuid::now_v7(),
                worktree_id,
                path: request.path,
                preimage: observed.summary,
                postimage,
            },
            replacement,
            unix_mode: observed.unix_mode,
            preimage_identity: observed.identity,
        })
    }
}

pub(crate) fn observe_utf8_file(
    root: &WorktreeMutationRoot,
    path: &RepositoryRelativePathV1,
) -> Result<GitWorktreeFileObservationV1, GitWorktreeFileReplaceError> {
    read_utf8_file(root, path).map(|read| read.observation)
}

pub(crate) fn read_utf8_file(
    root: &WorktreeMutationRoot,
    path: &RepositoryRelativePathV1,
) -> Result<GitWorktreeUtf8FileReadV1, GitWorktreeFileReplaceError> {
    #[cfg(not(unix))]
    {
        let _ = (root, path);
        Err(GitWorktreeFileReplaceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        validate_path(path)?;
        let (parent, file_name, root_device) = open_parent(root, path)?;
        let observed = observe_file(&parent, file_name, root_device)?;
        let content_utf8 = String::from_utf8(observed.bytes)
            .map_err(|_| GitWorktreeFileReplaceError::PreimageNotUtf8)?;
        Ok(GitWorktreeUtf8FileReadV1 {
            path: path.clone(),
            content_utf8,
            observation: observed.summary,
        })
    }
}

pub(crate) fn execute_utf8_file_replace(
    root: &WorktreeMutationRoot,
    worktree_id: Uuid,
    prepared: &PreparedGitWorktreeUtf8FileReplace,
) -> Result<GitWorktreeUtf8FileReplaceResultV1, GitWorktreeFileReplaceError> {
    #[cfg(not(unix))]
    {
        let _ = (root, worktree_id, prepared);
        Err(GitWorktreeFileReplaceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, fsync, openat, renameat};

        if prepared.receipt.worktree_id != worktree_id {
            return Err(GitWorktreeFileReplaceError::PreparedMutationMismatch);
        }
        let (parent, file_name, root_device) = open_parent(root, &prepared.receipt.path)?;
        let current = observe_file(&parent, file_name, root_device)?;
        if current.identity != prepared.preimage_identity
            || current.summary != prepared.receipt.preimage
        {
            return Err(GitWorktreeFileReplaceError::NodeChanged);
        }

        let temporary_name = format!(".birdcode-edit-{}", prepared.receipt.operation_id);
        let temporary_name = temporary_name.as_bytes();
        let temporary_fd = openat(
            &parent,
            temporary_name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::CreateTemporary, error))?;
        let mut renamed = false;
        let result = (|| {
            write_and_verify_temporary(temporary_fd, prepared)?;

            let immediately_before = observe_file(&parent, file_name, root_device)?;
            if immediately_before.identity != prepared.preimage_identity
                || immediately_before.summary != prepared.receipt.preimage
            {
                return Err(GitWorktreeFileReplaceError::NodeChanged);
            }
            renameat(&parent, temporary_name, &parent, file_name)
                .map_err(|error| outcome_unknown(GitWorktreeMutationIoOperation::Rename, error))?;
            renamed = true;
            fsync(&parent).map_err(|error| {
                outcome_unknown(GitWorktreeMutationIoOperation::SyncParent, error)
            })?;
            let postimage = observe_file(&parent, file_name, root_device).map_err(|error| {
                if error.may_have_mutated() {
                    error
                } else {
                    GitWorktreeFileReplaceError::OutcomeUnknown {
                        operation: GitWorktreeMutationIoOperation::ReadFile,
                        raw_os_error: None,
                    }
                }
            })?;
            if postimage.summary != prepared.receipt.postimage {
                return Err(GitWorktreeFileReplaceError::OutcomeUnknown {
                    operation: GitWorktreeMutationIoOperation::ReadFile,
                    raw_os_error: None,
                });
            }
            verify_root_unchanged(root)?;
            Ok(GitWorktreeUtf8FileReplaceResultV1 {
                operation_id: prepared.receipt.operation_id,
                worktree_id,
                path: prepared.receipt.path.clone(),
                preimage: prepared.receipt.preimage.clone(),
                postimage: postimage.summary,
                parent_directory_fsynced: true,
            })
        })();
        if renamed {
            result
                .map_err(|error| error.into_outcome_unknown(GitWorktreeMutationIoOperation::Rename))
        } else {
            cleanup_temporary_before_rename(&parent, temporary_name, result)
        }
    }
}

#[cfg(unix)]
fn cleanup_temporary_before_rename<T>(
    parent: &std::os::fd::OwnedFd,
    temporary_name: &[u8],
    result: Result<T, GitWorktreeFileReplaceError>,
) -> Result<T, GitWorktreeFileReplaceError> {
    use rustix::fs::{AtFlags, fsync, unlinkat};

    unlinkat(parent, temporary_name, AtFlags::empty())
        .map_err(|error| outcome_unknown(GitWorktreeMutationIoOperation::RemoveTemporary, error))?;
    fsync(parent)
        .map_err(|error| outcome_unknown(GitWorktreeMutationIoOperation::SyncParent, error))?;
    result
}

#[cfg(unix)]
fn write_and_verify_temporary(
    temporary_fd: std::os::fd::OwnedFd,
    prepared: &PreparedGitWorktreeUtf8FileReplace,
) -> Result<(), GitWorktreeFileReplaceError> {
    use rustix::fs::{Mode, fchmod};
    use std::io::{Seek as _, SeekFrom, Write as _};
    let mut temporary = std::fs::File::from(temporary_fd);
    temporary
        .write_all(&prepared.replacement)
        .map_err(|error| std_io_error(GitWorktreeMutationIoOperation::WriteTemporary, &error))?;
    fchmod(&temporary, Mode::from_raw_mode(prepared.unix_mode & 0o777))
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::SetPermissions, error))?;
    temporary
        .sync_all()
        .map_err(|error| std_io_error(GitWorktreeMutationIoOperation::SyncTemporary, &error))?;
    temporary
        .seek(SeekFrom::Start(0))
        .map_err(|error| std_io_error(GitWorktreeMutationIoOperation::ReadFile, &error))?;
    let verified = read_at_most(
        &mut temporary,
        u64::try_from(prepared.replacement.len()).unwrap_or(u64::MAX),
        GitWorktreeMutationIoOperation::ReadFile,
    )?;
    if verified != prepared.replacement {
        return Err(GitWorktreeFileReplaceError::NodeChanged);
    }
    Ok(())
}

#[cfg(unix)]
struct FileObservation {
    summary: GitWorktreeFileObservationV1,
    identity: RepositoryFileIdentityV1,
    unix_mode: rustix::fs::RawMode,
    bytes: Vec<u8>,
}

fn validate_path(path: &RepositoryRelativePathV1) -> Result<(), GitWorktreeFileReplaceError> {
    let components = path.unix_components();
    if components.is_empty() {
        return Err(GitWorktreeFileReplaceError::InvalidPath {
            violation: RepositoryPathViolationV1::EmptyFilePath,
            component_index: None,
        });
    }
    if components.len() > GIT_WORKTREE_MAX_PATH_COMPONENTS {
        return Err(GitWorktreeFileReplaceError::InvalidPath {
            violation: RepositoryPathViolationV1::EmbeddedSeparator,
            component_index: None,
        });
    }
    let mut path_bytes = 0_usize;
    for (index, component) in components.iter().enumerate() {
        let component_index = u32::try_from(index).ok();
        let violation = if component.is_empty() {
            Some(RepositoryPathViolationV1::EmptyComponent)
        } else if component == b"." {
            Some(RepositoryPathViolationV1::CurrentDirectoryComponent)
        } else if component == b".." {
            Some(RepositoryPathViolationV1::ParentTraversal)
        } else if component.contains(&b'/') {
            Some(RepositoryPathViolationV1::EmbeddedSeparator)
        } else if component.contains(&0) {
            Some(RepositoryPathViolationV1::EmbeddedNul)
        } else {
            None
        };
        if let Some(violation) = violation {
            return Err(GitWorktreeFileReplaceError::InvalidPath {
                violation,
                component_index,
            });
        }
        if component.len() > GIT_WORKTREE_MAX_COMPONENT_BYTES {
            return Err(GitWorktreeFileReplaceError::ReplacementTooLarge {
                actual: u64::try_from(component.len()).unwrap_or(u64::MAX),
                maximum: u64::try_from(GIT_WORKTREE_MAX_COMPONENT_BYTES).unwrap_or(u64::MAX),
            });
        }
        if component.eq_ignore_ascii_case(b".git") {
            return Err(GitWorktreeFileReplaceError::ReservedGitPath);
        }
        path_bytes = path_bytes
            .saturating_add(component.len())
            .saturating_add(usize::from(index > 0));
    }
    if path_bytes > GIT_WORKTREE_MAX_PATH_BYTES {
        return Err(GitWorktreeFileReplaceError::ReplacementTooLarge {
            actual: u64::try_from(path_bytes).unwrap_or(u64::MAX),
            maximum: u64::try_from(GIT_WORKTREE_MAX_PATH_BYTES).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn open_parent<'a>(
    root: &WorktreeMutationRoot,
    path: &'a RepositoryRelativePathV1,
) -> Result<(std::os::fd::OwnedFd, &'a [u8], u64), GitWorktreeFileReplaceError> {
    use rustix::fs::{Mode, OFlags, fstat, openat};
    use rustix::io::dup;
    let root_device = root.identity.device;
    let (file_name, parents) =
        path.unix_components()
            .split_last()
            .ok_or(GitWorktreeFileReplaceError::InvalidPath {
                violation: RepositoryPathViolationV1::EmptyFilePath,
                component_index: None,
            })?;
    let mut current = dup(&root.fd)
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::DuplicateRoot, error))?;
    for component in parents {
        current = openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::OpenParent, error))?;
        let device = fstat(&current)
            .map(file_identity)
            .map(unix_identity)
            .map(|identity| identity.device)
            .map_err(|error| io_error(GitWorktreeMutationIoOperation::StatNode, error))?;
        if device != root_device {
            return Err(GitWorktreeFileReplaceError::CrossDeviceBoundary);
        }
    }
    Ok((current, file_name, root_device))
}

#[cfg(unix)]
fn observe_file(
    parent: &std::os::fd::OwnedFd,
    file_name: &[u8],
    root_device: u64,
) -> Result<FileObservation, GitWorktreeFileReplaceError> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, openat, statat};
    let listed = statat(parent, file_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::StatNode, error))?;
    if FileType::from_raw_mode(listed.st_mode) != FileType::RegularFile {
        return Err(GitWorktreeFileReplaceError::WrongFileType);
    }
    let listed_identity = file_identity(listed);
    let listed_unix = unix_identity(listed_identity);
    if listed_unix.device != root_device {
        return Err(GitWorktreeFileReplaceError::CrossDeviceBoundary);
    }
    let byte_len = u64::try_from(listed_unix.byte_len)
        .map_err(|_| GitWorktreeFileReplaceError::WrongFileType)?;
    if byte_len > GIT_WORKTREE_PREIMAGE_HARD_MAX_BYTES {
        return Err(GitWorktreeFileReplaceError::PreimageTooLarge {
            actual: byte_len,
            maximum: GIT_WORKTREE_PREIMAGE_HARD_MAX_BYTES,
        });
    }
    let fd = openat(
        parent,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| io_error(GitWorktreeMutationIoOperation::OpenFile, error))?;
    let opened = fstat(&fd)
        .map(file_identity)
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::StatNode, error))?;
    if opened != listed_identity {
        return Err(GitWorktreeFileReplaceError::NodeChanged);
    }
    let mut file = std::fs::File::from(fd);
    let bytes = read_at_most(
        &mut file,
        GIT_WORKTREE_PREIMAGE_HARD_MAX_BYTES,
        GitWorktreeMutationIoOperation::ReadFile,
    )?;
    let observed_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed_len > GIT_WORKTREE_PREIMAGE_HARD_MAX_BYTES {
        return Err(GitWorktreeFileReplaceError::PreimageTooLarge {
            actual: observed_len,
            maximum: GIT_WORKTREE_PREIMAGE_HARD_MAX_BYTES,
        });
    }
    let after = fstat(&file)
        .map(file_identity)
        .map_err(|error| io_error(GitWorktreeMutationIoOperation::StatNode, error))?;
    if after != opened || observed_len != byte_len {
        return Err(GitWorktreeFileReplaceError::NodeChanged);
    }
    Ok(FileObservation {
        summary: GitWorktreeFileObservationV1 {
            byte_len,
            sha256: Sha256Digest::of_bytes(&bytes),
        },
        identity: opened,
        unix_mode: listed.st_mode,
        bytes,
    })
}

#[cfg(unix)]
fn verify_root_unchanged(root: &WorktreeMutationRoot) -> Result<(), GitWorktreeFileReplaceError> {
    use rustix::fs::fstat;
    let observed = fstat(&root.fd)
        .map(root_identity)
        .map_err(|error| outcome_unknown(GitWorktreeMutationIoOperation::StatNode, error))?;
    if observed != root.identity {
        return Err(GitWorktreeFileReplaceError::OutcomeUnknown {
            operation: GitWorktreeMutationIoOperation::StatNode,
            raw_os_error: None,
        });
    }
    Ok(())
}

fn read_at_most(
    reader: &mut impl std::io::Read,
    maximum: u64,
    operation: GitWorktreeMutationIoOperation,
) -> Result<Vec<u8>, GitWorktreeFileReplaceError> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| std_io_error(operation, &error))?;
    Ok(bytes)
}

#[cfg(unix)]
fn file_identity(stat: rustix::fs::Stat) -> RepositoryFileIdentityV1 {
    RepositoryFileIdentityV1::Unix(RepositoryUnixFileIdentityV1 {
        device: u64::try_from(stat.st_dev).unwrap_or(u64::MAX),
        inode: stat.st_ino,
        byte_len: stat.st_size,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

#[cfg(unix)]
fn root_identity(stat: rustix::fs::Stat) -> WorktreeRootIdentity {
    WorktreeRootIdentity {
        device: u64::try_from(stat.st_dev).unwrap_or(u64::MAX),
        inode: stat.st_ino,
    }
}

fn unix_identity(identity: RepositoryFileIdentityV1) -> RepositoryUnixFileIdentityV1 {
    match identity {
        RepositoryFileIdentityV1::Unix(identity) => identity,
    }
}

#[cfg(unix)]
fn io_error(
    operation: GitWorktreeMutationIoOperation,
    error: rustix::io::Errno,
) -> GitWorktreeFileReplaceError {
    GitWorktreeFileReplaceError::Io {
        operation,
        raw_os_error: Some(error.raw_os_error()),
    }
}

fn std_io_error(
    operation: GitWorktreeMutationIoOperation,
    error: &std::io::Error,
) -> GitWorktreeFileReplaceError {
    GitWorktreeFileReplaceError::Io {
        operation,
        raw_os_error: error.raw_os_error(),
    }
}

#[cfg(unix)]
fn outcome_unknown(
    operation: GitWorktreeMutationIoOperation,
    error: rustix::io::Errno,
) -> GitWorktreeFileReplaceError {
    GitWorktreeFileReplaceError::OutcomeUnknown {
        operation,
        raw_os_error: Some(error.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_retains_at_most_maximum_plus_one_byte() {
        let mut reader = std::io::Cursor::new(vec![b'x'; 32]);
        let bytes = read_at_most(&mut reader, 7, GitWorktreeMutationIoOperation::ReadFile)
            .expect("bounded read");
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn every_post_rename_error_requires_reconciliation() {
        let promoted = GitWorktreeFileReplaceError::Io {
            operation: GitWorktreeMutationIoOperation::StatNode,
            raw_os_error: Some(5),
        }
        .into_outcome_unknown(GitWorktreeMutationIoOperation::Rename);
        assert!(matches!(
            promoted,
            GitWorktreeFileReplaceError::OutcomeUnknown {
                operation: GitWorktreeMutationIoOperation::StatNode,
                raw_os_error: Some(5),
            }
        ));

        let promoted = GitWorktreeFileReplaceError::NodeChanged
            .into_outcome_unknown(GitWorktreeMutationIoOperation::Rename);
        assert!(matches!(
            promoted,
            GitWorktreeFileReplaceError::OutcomeUnknown {
                operation: GitWorktreeMutationIoOperation::Rename,
                raw_os_error: None,
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn missing_pre_rename_temporary_requires_reconciliation() {
        use rustix::fs::{Mode, OFlags, open};

        let directory = tempfile::tempdir().expect("temporary parent");
        let parent = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open temporary parent");
        let result: Result<(), GitWorktreeFileReplaceError> = cleanup_temporary_before_rename(
            &parent,
            b".birdcode-edit-missing",
            Err(GitWorktreeFileReplaceError::NodeChanged),
        );
        assert!(matches!(
            result,
            Err(GitWorktreeFileReplaceError::OutcomeUnknown {
                operation: GitWorktreeMutationIoOperation::RemoveTemporary,
                ..
            })
        ));
    }
}
