use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// Filesystem locations owned by one local `BirdCode` runtime instance.
///
/// Callers choose the root directory. Keeping path discovery outside the core
/// runtime makes tests deterministic and leaves macOS, Windows, and Linux
/// packaging free to apply their native conventions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePaths {
    root: PathBuf,
}

impl RuntimePaths {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn database(&self) -> PathBuf {
        self.root.join("birdcode.sqlite3")
    }

    #[must_use]
    pub fn artifacts(&self) -> PathBuf {
        self.root.join("artifacts")
    }

    /// Creates only the directories needed to open the runtime. Existing
    /// state is never removed or rewritten by this operation.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when either directory cannot be created.
    pub fn prepare(&self) -> io::Result<()> {
        prepare_private_directory(&self.root)?;
        prepare_private_directory(&self.artifacts())
    }
}

fn prepare_private_directory(path: &Path) -> io::Result<()> {
    let existed = path.exists();
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "runtime state path is not a real directory: {}",
                path.display()
            ),
        ));
    }
    #[cfg(unix)]
    if existed && metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime state directory is writable by group or others: {}",
                path.display()
            ),
        ));
    }
    #[cfg(unix)]
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::RuntimePaths;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn prepares_stable_runtime_layout() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "birdcode-runtime-paths-{}-{unique}",
            std::process::id()
        ));
        let paths = RuntimePaths::new(&root);

        paths.prepare().expect("runtime paths should be created");

        assert_eq!(paths.database(), root.join("birdcode.sqlite3"));
        assert!(paths.artifacts().is_dir());
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(paths.artifacts())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }

        fs::remove_dir_all(root).expect("test directory should be removable");
    }

    #[cfg(unix)]
    #[test]
    fn preserves_existing_user_selected_root_permissions() {
        let parent = tempfile::TempDir::new().expect("temporary parent should exist");
        let root = parent.path().join("state");
        fs::create_dir(&root).expect("state root should be created");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("fixture permissions should be applied");
        let parent_mode = fs::metadata(parent.path()).unwrap().permissions().mode() & 0o777;

        RuntimePaths::new(&root)
            .prepare()
            .expect("existing state should be usable");

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(root.join("artifacts"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(parent.path()).unwrap().permissions().mode() & 0o777,
            parent_mode
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_shared_writable_existing_runtime_root_without_mutating_it() {
        let parent = tempfile::TempDir::new().expect("temporary parent should exist");
        let root = parent.path().join("shared-state");
        fs::create_dir(&root).expect("state root should be created");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("fixture permissions should be applied");

        let error = RuntimePaths::new(&root)
            .prepare()
            .expect_err("shared-writable state root must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o777
        );
        assert!(!root.join("artifacts").exists());
    }
}
