use birdcode_protocol::{RepositoryFileIdentityV1, Sha256Digest};
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileHashObservation {
    pub byte_len: u64,
    pub sha256: Sha256Digest,
    pub identity: RepositoryFileIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadOnlyMountObservation {
    pub statfs_flags: u64,
    pub mnt_rdonly_mask: u64,
    pub write_open_errno: i32,
    pub mounted_root_identity: RepositoryFileIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountPresence {
    MountedExpected,
    UnmountedExpected,
    Missing,
    DifferentIdentity,
}

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("workspace platform adapter is available only on macOS")]
    UnsupportedPlatform,
    #[error("workspace filesystem operation failed (os error {raw_os_error:?})")]
    Io { raw_os_error: Option<i32> },
    #[error("mounted repository is not kernel read-only")]
    MountNotReadOnly,
    #[error("descriptor-relative write probe returned errno {observed}, expected EROFS=30")]
    WriteProbeMismatch { observed: i32 },
    #[error("descriptor-relative write probe unexpectedly created a file")]
    WriteProbeSucceeded,
    #[error("filesystem node changed during observation")]
    NodeChanged,
    #[error("mount directory must be empty before attach")]
    MountDirectoryNotEmpty,
    #[error("workspace recovery target is not a regular file")]
    NotRegularFile,
}

#[cfg(target_os = "macos")]
pub(crate) fn file_hash(path: &Path) -> Result<FileHashObservation, PlatformError> {
    macos::file_hash(path)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn file_hash(_path: &Path) -> Result<FileHashObservation, PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
pub(crate) fn ensure_empty_directory(
    path: &Path,
) -> Result<RepositoryFileIdentityV1, PlatformError> {
    macos::ensure_empty_directory(path)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn ensure_empty_directory(
    _path: &Path,
) -> Result<RepositoryFileIdentityV1, PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_read_only_mount(
    mount_path: &Path,
    probe_component: &[u8],
) -> Result<ReadOnlyMountObservation, PlatformError> {
    macos::verify_read_only_mount(mount_path, probe_component)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn verify_read_only_mount(
    _mount_path: &Path,
    _probe_component: &[u8],
) -> Result<ReadOnlyMountObservation, PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
pub(crate) fn observe_mount_presence(
    mount_path: &Path,
    mounted_identity: RepositoryFileIdentityV1,
    unmounted_identity: RepositoryFileIdentityV1,
) -> Result<MountPresence, PlatformError> {
    macos::observe_mount_presence(mount_path, mounted_identity, unmounted_identity)
}

pub(crate) fn is_not_found_errno(value: i32) -> bool {
    std::io::Error::from_raw_os_error(value).kind() == std::io::ErrorKind::NotFound
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn observe_mount_presence(
    _mount_path: &Path,
    _mounted_identity: RepositoryFileIdentityV1,
    _unmounted_identity: RepositoryFileIdentityV1,
) -> Result<MountPresence, PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{FileHashObservation, MountPresence, PlatformError, ReadOnlyMountObservation};
    use birdcode_protocol::{RepositoryFileIdentityV1, RepositoryUnixFileIdentityV1, Sha256Digest};
    use rustix::fs::{
        AtFlags, Dir, FileType, Mode, OFlags, StatVfsMountFlags, fstat, fstatvfs, open, openat,
        unlinkat,
    };
    use rustix::io::Errno;
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::path::Path;

    const MNT_RDONLY: u64 = 0x0000_0001;
    const DARWIN_EROFS: i32 = 30;

    pub(super) fn file_hash(path: &Path) -> Result<FileHashObservation, PlatformError> {
        let fd = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)?;
        let before = fstat(&fd).map_err(io_error)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(PlatformError::NotRegularFile);
        }
        let expected_len = u64::try_from(before.st_size).map_err(|_| PlatformError::NodeChanged)?;
        let mut file = std::fs::File::from(fd);
        let mut hasher = Sha256::new();
        let mut observed_len = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
        loop {
            let count = file.read(&mut buffer).map_err(|error| PlatformError::Io {
                raw_os_error: error.raw_os_error(),
            })?;
            if count == 0 {
                break;
            }
            observed_len = observed_len
                .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
                .ok_or(PlatformError::NodeChanged)?;
            hasher.update(&buffer[..count]);
        }
        let after = fstat(&file).map_err(io_error)?;
        if identity(before) != identity(after) || observed_len != expected_len {
            return Err(PlatformError::NodeChanged);
        }
        let sha256 = Sha256Digest::parse(format!("{:x}", hasher.finalize()))
            .map_err(|_| PlatformError::NodeChanged)?;
        Ok(FileHashObservation {
            byte_len: observed_len,
            sha256,
            identity: identity(after),
        })
    }

    pub(super) fn ensure_empty_directory(
        path: &Path,
    ) -> Result<RepositoryFileIdentityV1, PlatformError> {
        let directory = open_directory(path)?;
        let before = fstat(&directory).map(identity).map_err(io_error)?;
        let mut stream = Dir::read_from(&directory).map_err(io_error)?;
        while let Some(entry) = stream.read() {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                return Err(PlatformError::MountDirectoryNotEmpty);
            }
        }
        let after = fstat(&directory).map(identity).map_err(io_error)?;
        if before != after {
            return Err(PlatformError::NodeChanged);
        }
        Ok(after)
    }

    pub(super) fn verify_read_only_mount(
        mount_path: &Path,
        probe_component: &[u8],
    ) -> Result<ReadOnlyMountObservation, PlatformError> {
        let root = open_directory(mount_path)?;
        let statvfs = fstatvfs(&root).map_err(io_error)?;
        let flags = statvfs.f_flag.bits();
        if !statvfs.f_flag.contains(StatVfsMountFlags::RDONLY) || flags & MNT_RDONLY == 0 {
            return Err(PlatformError::MountNotReadOnly);
        }
        let write_open_errno = match openat(
            &root,
            probe_component,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Err(error) if error == Errno::ROFS && error.raw_os_error() == DARWIN_EROFS => {
                DARWIN_EROFS
            }
            Err(error) => {
                return Err(PlatformError::WriteProbeMismatch {
                    observed: error.raw_os_error(),
                });
            }
            Ok(created) => {
                drop(created);
                let _ = unlinkat(&root, probe_component, AtFlags::empty());
                return Err(PlatformError::WriteProbeSucceeded);
            }
        };
        let mounted_root_identity = fstat(&root).map(identity).map_err(io_error)?;
        Ok(ReadOnlyMountObservation {
            statfs_flags: flags,
            mnt_rdonly_mask: MNT_RDONLY,
            write_open_errno,
            mounted_root_identity,
        })
    }

    pub(super) fn observe_mount_presence(
        mount_path: &Path,
        mounted_identity: RepositoryFileIdentityV1,
        unmounted_identity: RepositoryFileIdentityV1,
    ) -> Result<MountPresence, PlatformError> {
        let root = match open_directory(mount_path) {
            Ok(root) => root,
            Err(PlatformError::Io {
                raw_os_error: Some(value),
            }) if value == Errno::NOENT.raw_os_error() => return Ok(MountPresence::Missing),
            Err(error) => return Err(error),
        };
        let observed = fstat(&root).map(identity).map_err(io_error)?;
        if observed == mounted_identity {
            Ok(MountPresence::MountedExpected)
        } else if observed == unmounted_identity {
            Ok(MountPresence::UnmountedExpected)
        } else {
            Ok(MountPresence::DifferentIdentity)
        }
    }

    fn open_directory(path: &Path) -> Result<OwnedFd, PlatformError> {
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)
    }

    fn identity(stat: rustix::fs::Stat) -> RepositoryFileIdentityV1 {
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

    fn io_error(error: Errno) -> PlatformError {
        PlatformError::Io {
            raw_os_error: Some(error.raw_os_error()),
        }
    }
}
