use birdcode_protocol::{RepositoryFileIdentityV1, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryManifestLimitsV1 {
    pub max_depth: u32,
    pub max_entries: u64,
    pub max_component_bytes: u64,
    pub max_path_bytes: u64,
    pub max_file_bytes: u64,
    pub max_total_file_bytes: u64,
    pub max_symlink_bytes: u64,
}

impl Default for RepositoryManifestLimitsV1 {
    fn default() -> Self {
        Self {
            max_depth: 128,
            max_entries: 262_144,
            max_component_bytes: 4_096,
            max_path_bytes: 64 * 1_024,
            max_file_bytes: 2 * 1_024 * 1_024 * 1_024,
            max_total_file_bytes: 32 * 1_024 * 1_024 * 1_024,
            max_symlink_bytes: 64 * 1_024,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryManifestNodeKindV1 {
    Directory,
    RegularFile,
    Symlink,
}

/// One content-comparable entry. Native device/inode/timestamps are excluded
/// because a mounted disk image necessarily has different native identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryManifestEntryV1 {
    pub unix_relative_components: Vec<Vec<u8>>,
    pub kind: RepositoryManifestNodeKindV1,
    pub byte_len: Option<u64>,
    pub content_sha256: Option<Sha256Digest>,
    pub symlink_target: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryContentManifestV1 {
    pub schema_version: u32,
    pub entries: Vec<RepositoryManifestEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestObservation {
    pub root_identity: RepositoryFileIdentityV1,
    pub manifest: RepositoryContentManifestV1,
    pub canonical_bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestLimitKindV1 {
    Depth,
    Entries,
    ComponentBytes,
    PathBytes,
    FileBytes,
    TotalFileBytes,
    SymlinkBytes,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("repository manifest limit {limit:?} exceeded: {actual} > {maximum}")]
    LimitExceeded {
        limit: ManifestLimitKindV1,
        actual: u64,
        maximum: u64,
    },
    #[error("repository manifest encountered an unsupported filesystem node")]
    UnsupportedNode,
    #[error("repository manifest crossed a filesystem device boundary")]
    CrossDeviceBoundary,
    #[error("repository node changed during manifest observation")]
    NodeChanged,
    #[error("repository manifest filesystem operation failed (os error {raw_os_error:?})")]
    Io { raw_os_error: Option<i32> },
    #[error("repository manifest canonical encoding failed")]
    Encoding,
    #[error("repository manifest is unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(unix)]
pub(crate) fn observe(
    root_path: &Path,
    limits: RepositoryManifestLimitsV1,
) -> Result<ManifestObservation, ManifestError> {
    unix::observe(root_path, limits)
}

#[cfg(not(unix))]
pub(crate) fn observe(
    _root_path: &Path,
    _limits: RepositoryManifestLimitsV1,
) -> Result<ManifestObservation, ManifestError> {
    Err(ManifestError::UnsupportedPlatform)
}

#[cfg(unix)]
mod unix {
    use super::{
        ManifestError, ManifestLimitKindV1, ManifestObservation, RepositoryContentManifestV1,
        RepositoryManifestEntryV1, RepositoryManifestLimitsV1, RepositoryManifestNodeKindV1,
    };
    use birdcode_protocol::{RepositoryFileIdentityV1, RepositoryUnixFileIdentityV1, Sha256Digest};
    use rustix::fs::{
        AtFlags, Dir, FileType, Mode, OFlags, fstat, open, openat, readlinkat, statat,
    };
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::path::Path;

    pub(super) fn observe(
        root_path: &Path,
        limits: RepositoryManifestLimitsV1,
    ) -> Result<ManifestObservation, ManifestError> {
        validate_limits(limits)?;
        let root = open(
            root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)?;
        let root_before = descriptor_identity(&root)?;
        let root_device = unix_identity(root_before).device;
        let mut walker = Walker {
            limits,
            root_device,
            entries: vec![RepositoryManifestEntryV1 {
                unix_relative_components: Vec::new(),
                kind: RepositoryManifestNodeKindV1::Directory,
                byte_len: None,
                content_sha256: None,
                symlink_target: None,
            }],
            total_file_bytes: 0,
        };
        walker.walk(&root, &[], 0)?;
        let root_after = descriptor_identity(&root)?;
        if root_before != root_after {
            return Err(ManifestError::NodeChanged);
        }
        let manifest = RepositoryContentManifestV1 {
            schema_version: 1,
            entries: walker.entries,
        };
        let canonical_bytes = serde_json::to_vec(&manifest).map_err(|_| ManifestError::Encoding)?;
        let digest = Sha256Digest::of_bytes(&canonical_bytes);
        Ok(ManifestObservation {
            root_identity: root_after,
            manifest,
            canonical_bytes,
            digest,
        })
    }

    struct Walker {
        limits: RepositoryManifestLimitsV1,
        root_device: u64,
        entries: Vec<RepositoryManifestEntryV1>,
        total_file_bytes: u64,
    }

    impl Walker {
        fn walk(
            &mut self,
            directory: &OwnedFd,
            parent_path: &[Vec<u8>],
            depth: u32,
        ) -> Result<(), ManifestError> {
            if depth > self.limits.max_depth {
                return Err(ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::Depth,
                    actual: u64::from(depth).saturating_add(1),
                    maximum: u64::from(self.limits.max_depth),
                });
            }
            let before = descriptor_identity(directory)?;
            let names = directory_names(directory)?;
            for name in names {
                self.check_component(&name)?;
                let mut path = parent_path.to_vec();
                path.push(name.clone());
                self.check_path(&path)?;
                self.check_entry_capacity()?;
                let stat = statat(directory, name.as_slice(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(io_error)?;
                ensure_device(self.root_device, stat.st_dev)?;
                match FileType::from_raw_mode(stat.st_mode) {
                    FileType::Directory => {
                        let listed = identity(stat);
                        let child = openat(
                            directory,
                            name.as_slice(),
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(io_error)?;
                        if descriptor_identity(&child)? != listed {
                            return Err(ManifestError::NodeChanged);
                        }
                        self.entries.push(RepositoryManifestEntryV1 {
                            unix_relative_components: path.clone(),
                            kind: RepositoryManifestNodeKindV1::Directory,
                            byte_len: None,
                            content_sha256: None,
                            symlink_target: None,
                        });
                        self.walk(&child, &path, depth.saturating_add(1))?;
                    }
                    FileType::RegularFile => {
                        self.read_file(directory, &name, path, identity(stat))?;
                    }
                    FileType::Symlink => {
                        self.read_symlink(directory, &name, path, identity(stat))?;
                    }
                    _ => return Err(ManifestError::UnsupportedNode),
                }
            }
            if before != descriptor_identity(directory)? {
                return Err(ManifestError::NodeChanged);
            }
            Ok(())
        }

        fn read_file(
            &mut self,
            directory: &OwnedFd,
            name: &[u8],
            path: Vec<Vec<u8>>,
            listed_identity: RepositoryFileIdentityV1,
        ) -> Result<(), ManifestError> {
            let byte_len = u64::try_from(unix_identity(listed_identity).byte_len)
                .map_err(|_| ManifestError::UnsupportedNode)?;
            if byte_len > self.limits.max_file_bytes {
                return Err(ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::FileBytes,
                    actual: byte_len,
                    maximum: self.limits.max_file_bytes,
                });
            }
            let next_total = self.total_file_bytes.checked_add(byte_len).ok_or(
                ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::TotalFileBytes,
                    actual: u64::MAX,
                    maximum: self.limits.max_total_file_bytes,
                },
            )?;
            if next_total > self.limits.max_total_file_bytes {
                return Err(ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::TotalFileBytes,
                    actual: next_total,
                    maximum: self.limits.max_total_file_bytes,
                });
            }
            let fd = openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io_error)?;
            if descriptor_identity(&fd)? != listed_identity {
                return Err(ManifestError::NodeChanged);
            }
            let mut file = std::fs::File::from(fd);
            let mut hasher = Sha256::new();
            let mut observed = 0_u64;
            let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
            loop {
                let count = file.read(&mut buffer).map_err(|error| ManifestError::Io {
                    raw_os_error: error.raw_os_error(),
                })?;
                if count == 0 {
                    break;
                }
                observed = observed
                    .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
                    .ok_or(ManifestError::LimitExceeded {
                        limit: ManifestLimitKindV1::FileBytes,
                        actual: u64::MAX,
                        maximum: self.limits.max_file_bytes,
                    })?;
                if observed > byte_len {
                    return Err(ManifestError::NodeChanged);
                }
                hasher.update(&buffer[..count]);
            }
            if observed != byte_len || descriptor_identity_from_file(&file)? != listed_identity {
                return Err(ManifestError::NodeChanged);
            }
            let digest = Sha256Digest::parse(format!("{:x}", hasher.finalize()))
                .map_err(|_| ManifestError::Encoding)?;
            self.total_file_bytes = next_total;
            self.entries.push(RepositoryManifestEntryV1 {
                unix_relative_components: path,
                kind: RepositoryManifestNodeKindV1::RegularFile,
                byte_len: Some(byte_len),
                content_sha256: Some(digest),
                symlink_target: None,
            });
            Ok(())
        }

        fn read_symlink(
            &mut self,
            directory: &OwnedFd,
            name: &[u8],
            path: Vec<Vec<u8>>,
            listed_identity: RepositoryFileIdentityV1,
        ) -> Result<(), ManifestError> {
            let target = readlinkat(directory, name, Vec::new())
                .map_err(io_error)?
                .into_bytes();
            let target_len = u64::try_from(target.len()).unwrap_or(u64::MAX);
            if target_len > self.limits.max_symlink_bytes {
                return Err(ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::SymlinkBytes,
                    actual: target_len,
                    maximum: self.limits.max_symlink_bytes,
                });
            }
            let observed = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map(identity)
                .map_err(io_error)?;
            if observed != listed_identity {
                return Err(ManifestError::NodeChanged);
            }
            self.entries.push(RepositoryManifestEntryV1 {
                unix_relative_components: path,
                kind: RepositoryManifestNodeKindV1::Symlink,
                byte_len: Some(target_len),
                content_sha256: Some(Sha256Digest::of_bytes(&target)),
                symlink_target: Some(target),
            });
            Ok(())
        }

        fn check_entry_capacity(&self) -> Result<(), ManifestError> {
            let next = u64::try_from(self.entries.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            if next > self.limits.max_entries {
                return Err(ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::Entries,
                    actual: next,
                    maximum: self.limits.max_entries,
                });
            }
            Ok(())
        }

        fn check_component(&self, component: &[u8]) -> Result<(), ManifestError> {
            let actual = u64::try_from(component.len()).unwrap_or(u64::MAX);
            if actual > self.limits.max_component_bytes {
                return Err(ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::ComponentBytes,
                    actual,
                    maximum: self.limits.max_component_bytes,
                });
            }
            Ok(())
        }

        fn check_path(&self, path: &[Vec<u8>]) -> Result<(), ManifestError> {
            let actual = path.iter().fold(0_u64, |total, component| {
                total
                    .checked_add(u64::try_from(component.len()).unwrap_or(u64::MAX))
                    .and_then(|value| value.checked_add(1))
                    .unwrap_or(u64::MAX)
            });
            if actual > self.limits.max_path_bytes {
                return Err(ManifestError::LimitExceeded {
                    limit: ManifestLimitKindV1::PathBytes,
                    actual,
                    maximum: self.limits.max_path_bytes,
                });
            }
            Ok(())
        }
    }

    fn directory_names(directory: &OwnedFd) -> Result<Vec<Vec<u8>>, ManifestError> {
        let mut stream = Dir::read_from(directory).map_err(io_error)?;
        let mut names = Vec::new();
        while let Some(entry) = stream.read() {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        names.sort_unstable();
        Ok(names)
    }

    fn descriptor_identity(fd: &OwnedFd) -> Result<RepositoryFileIdentityV1, ManifestError> {
        fstat(fd).map(identity).map_err(io_error)
    }

    fn descriptor_identity_from_file(
        file: &std::fs::File,
    ) -> Result<RepositoryFileIdentityV1, ManifestError> {
        fstat(file).map(identity).map_err(io_error)
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

    fn unix_identity(identity: RepositoryFileIdentityV1) -> RepositoryUnixFileIdentityV1 {
        match identity {
            RepositoryFileIdentityV1::Unix(identity) => identity,
        }
    }

    fn ensure_device(root_device: u64, observed: rustix::fs::Dev) -> Result<(), ManifestError> {
        if u64::try_from(observed).unwrap_or(u64::MAX) != root_device {
            return Err(ManifestError::CrossDeviceBoundary);
        }
        Ok(())
    }

    fn validate_limits(limits: RepositoryManifestLimitsV1) -> Result<(), ManifestError> {
        if limits.max_depth == 0
            || limits.max_entries == 0
            || limits.max_component_bytes == 0
            || limits.max_path_bytes == 0
            || limits.max_file_bytes == 0
            || limits.max_total_file_bytes == 0
            || limits.max_symlink_bytes == 0
        {
            return Err(ManifestError::LimitExceeded {
                limit: ManifestLimitKindV1::Entries,
                actual: 0,
                maximum: 0,
            });
        }
        Ok(())
    }

    fn io_error(error: rustix::io::Errno) -> ManifestError {
        ManifestError::Io {
            raw_os_error: Some(error.raw_os_error()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        ManifestError, ManifestLimitKindV1, RepositoryManifestLimitsV1,
        RepositoryManifestNodeKindV1, observe,
    };
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    #[test]
    fn manifest_is_deterministic_for_multilingual_and_non_utf8_names() {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::write(root.path().join("kod-日本語.rs"), b"same bytes\n")
            .expect("unicode file writes");
        let raw_name = OsString::from_vec(b"raw-\xff".to_vec());
        let raw_name_created = match std::fs::write(root.path().join(&raw_name), b"opaque bytes\n")
        {
            Ok(()) => true,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
                ) || error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error()) =>
            {
                // Some macOS filesystems reject an invalid UTF-8 component
                // before the descriptor walker can observe it. Unix hosts that
                // accept the component still exercise exact byte preservation
                // below.
                false
            }
            Err(error) => panic!("non-utf8 fixture failed unexpectedly: {error}"),
        };
        std::os::unix::fs::symlink("kod-日本語.rs", root.path().join("länk"))
            .expect("symlink writes");

        let first =
            observe(root.path(), RepositoryManifestLimitsV1::default()).expect("first observation");
        let second = observe(root.path(), RepositoryManifestLimitsV1::default())
            .expect("second observation");
        assert_eq!(first.canonical_bytes, second.canonical_bytes);
        assert_eq!(first.digest, second.digest);
        if raw_name_created {
            assert!(first.manifest.entries.iter().any(|entry| {
                entry.unix_relative_components == vec![b"raw-\xff".to_vec()]
                    && entry.kind == RepositoryManifestNodeKindV1::RegularFile
            }));
        }
        assert!(first.manifest.entries.iter().any(|entry| {
            entry.kind == RepositoryManifestNodeKindV1::Symlink
                && entry.symlink_target.as_deref() == Some("kod-日本語.rs".as_bytes())
        }));
    }

    #[test]
    fn manifest_file_limit_fails_closed_without_truncation() {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::write(root.path().join("large"), b"12").expect("fixture writes");
        let limits = RepositoryManifestLimitsV1 {
            max_file_bytes: 1,
            ..RepositoryManifestLimitsV1::default()
        };
        assert!(matches!(
            observe(root.path(), limits),
            Err(ManifestError::LimitExceeded {
                limit: ManifestLimitKindV1::FileBytes,
                actual: 2,
                maximum: 1,
            })
        ));
    }
}
