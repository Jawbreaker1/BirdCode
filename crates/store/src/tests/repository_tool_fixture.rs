use super::*;
use birdcode_protocol::{RepositoryFileIdentityV1, RepositoryRootBindingV1};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

#[cfg(unix)]
pub(crate) fn repository_root_path(store: &Store) -> PathBuf {
    store
        .artifact_root
        .parent()
        .expect("fixture Store has a state directory")
        .join("repository-root")
}

pub(crate) fn repository_root_binding(store: &Store) -> RepositoryRootBindingV1 {
    #[cfg(unix)]
    let descriptor_identity = {
        let root = repository_root_path(store);
        std::fs::create_dir_all(&root).expect("fixture repository root exists");
        let metadata = std::fs::symlink_metadata(root).expect("fixture repository root reads");
        RepositoryFileIdentityV1::Unix(birdcode_protocol::RepositoryUnixFileIdentityV1 {
            device: metadata.dev(),
            inode: metadata.ino(),
            byte_len: i64::try_from(metadata.size()).expect("fixture root size fits i64"),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    };
    #[cfg(not(unix))]
    let descriptor_identity =
        RepositoryFileIdentityV1::Unix(birdcode_protocol::RepositoryUnixFileIdentityV1 {
            device: 1,
            inode: 2,
            byte_len: 0,
            modified_seconds: 1,
            modified_nanoseconds: 0,
            changed_seconds: 1,
            changed_nanoseconds: 0,
        });
    RepositoryRootBindingV1 {
        repository_root_id: "repository-root-v1".to_owned(),
        descriptor_identity,
    }
}
