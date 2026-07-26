use birdcode_protocol::{
    ActorId, EventId, RepositoryFileIdentityV1, RepositorySnapshotLeaseId, RuntimeInstanceId,
    Sha256Digest, WorkspacePath,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[cfg(unix)]
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, open, openat,
    renameat, statat, unlinkat,
};
#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

const JOURNAL_SCHEMA_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
const MAX_ORPHAN_TEMP_FILES: usize = 64;
const MAX_LOCAL_ID_BYTES: usize = 128;
const MAX_SNAPSHOT_ID_BYTES: usize = 128;
const MAX_DEVICE_IDENTIFIER_BYTES: usize = 128;
const RECOVERY_LOCK_NAME: &[u8] = b".recovery.lock";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStageV1 {
    WriterRevoked,
    CreatePrepared,
    CreateOutcomeUnknown,
    CreateCleanupRequired,
    ImageCaptured,
    AttachPrepared,
    AttachOutcomeUnknown,
    MountedDetachRequired,
    LeaseCommitted,
    DetachPrepared,
    DetachOutcomeUnknown,
    DetachedObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupJournalRecordV1 {
    pub schema_version: u32,
    pub local_cleanup_id: String,
    pub snapshot_id: String,
    pub lease_id: RepositorySnapshotLeaseId,
    pub writer_revocation_event_id: EventId,
    pub snapshot_lease_event_id: EventId,
    pub source_path: WorkspacePath,
    pub image_path: WorkspacePath,
    pub mount_path: WorkspacePath,
    pub lifecycle_owner_actor_id: ActorId,
    pub lifecycle_owner_runtime_instance_id: RuntimeInstanceId,
    pub stage: CleanupStageV1,
    pub unmounted_root_identity: Option<RepositoryFileIdentityV1>,
    pub mounted_root_identity: Option<RepositoryFileIdentityV1>,
    pub leaf_device_identifier: Option<String>,
}

impl CleanupJournalRecordV1 {
    #[allow(
        clippy::too_many_arguments,
        reason = "the closed recovery identity is assembled without an intermediate partial record"
    )]
    pub(crate) fn new(
        snapshot_id: String,
        lease_id: RepositorySnapshotLeaseId,
        writer_revocation_event_id: EventId,
        snapshot_lease_event_id: EventId,
        source_path: WorkspacePath,
        image_path: WorkspacePath,
        mount_path: WorkspacePath,
        lifecycle_owner_actor_id: ActorId,
        lifecycle_owner_runtime_instance_id: RuntimeInstanceId,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            local_cleanup_id: Uuid::now_v7().to_string(),
            snapshot_id,
            lease_id,
            writer_revocation_event_id,
            snapshot_lease_event_id,
            source_path,
            image_path,
            mount_path,
            lifecycle_owner_actor_id,
            lifecycle_owner_runtime_instance_id,
            stage: CleanupStageV1::WriterRevoked,
            unmounted_root_identity: None,
            mounted_root_identity: None,
            leaf_device_identifier: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDispositionV1 {
    AbortRevokedWriterCapture,
    InspectCreateOutcome,
    RemoveRejectedImage,
    ResumeCapturedImageAttach,
    InspectAttachOutcome,
    DetachMountedSnapshot,
    ConfirmCommittedLeaseOrDetach,
    InspectDetachOutcome,
    ConfirmReleaseBeforeDeletingImage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryInspectionV1 {
    pub record: CleanupJournalRecordV1,
    pub disposition: RecoveryDispositionV1,
}

/// Fsync-backed cleanup journal confined to one already-open directory.
///
/// Every read, replacement and removal after construction is relative to the
/// retained directory descriptor. A path swap outside that descriptor cannot
/// redirect recovery I/O.
#[derive(Clone, Debug)]
pub struct FileCleanupJournal {
    root: PathBuf,
    #[cfg(unix)]
    root_fd: Arc<OwnedFd>,
    #[cfg(unix)]
    recovery_lock_fd: Arc<OwnedFd>,
    #[cfg(unix)]
    recovery_lock_local: Arc<RwLock<()>>,
}

#[cfg(unix)]
pub(crate) struct JournalRecoveryLock<'a> {
    journal: &'a FileCleanupJournal,
    _local: RwLockWriteGuard<'a, ()>,
}

#[cfg(not(unix))]
pub(crate) struct JournalRecoveryLock<'a>(PhantomData<&'a ()>);

#[cfg(unix)]
struct JournalSharedLock<'a> {
    lock_fd: OwnedFd,
    _local: RwLockReadGuard<'a, ()>,
}

/// An exact journal envelope retained under one live exclusive lifecycle lock.
///
/// This is descriptor evidence, not cleanup authority. Its lifetime prevents
/// the bytes and open record descriptor from outliving the recovery lock that
/// froze journal replacement.
#[cfg(unix)]
#[allow(
    dead_code,
    reason = "the inert cleanup-candidate milestone consumes this capability next"
)]
pub(crate) struct LockedCleanupJournalRecord<'lock, 'journal> {
    envelope_bytes: Vec<u8>,
    record: CleanupJournalRecordV1,
    root_identity: RepositoryFileIdentityV1,
    lock_identity: RepositoryFileIdentityV1,
    record_identity: RepositoryFileIdentityV1,
    _record_file: std::fs::File,
    _recovery_lock: PhantomData<&'lock JournalRecoveryLock<'journal>>,
}

#[cfg(unix)]
impl Drop for JournalRecoveryLock<'_> {
    fn drop(&mut self) {
        let _ = flock(&*self.journal.recovery_lock_fd, FlockOperation::Unlock);
    }
}

#[cfg(unix)]
impl Drop for JournalSharedLock<'_> {
    fn drop(&mut self) {
        let _ = flock(&self.lock_fd, FlockOperation::Unlock);
    }
}

#[cfg(unix)]
impl<'journal> JournalRecoveryLock<'journal> {
    pub(crate) fn load_all_locked(&self) -> Result<Vec<CleanupJournalRecordV1>, JournalError> {
        self.journal.clean_orphan_temporary_files_unlocked()?;
        self.journal.load_all_unlocked()
    }

    pub(crate) fn write_locked(&self, record: &CleanupJournalRecordV1) -> Result<(), JournalError> {
        self.journal.write_unlocked(record)
    }

    pub(crate) fn remove_locked(
        &self,
        lease_id: RepositorySnapshotLeaseId,
    ) -> Result<(), JournalError> {
        self.journal.remove_unlocked(lease_id)
    }

    #[allow(
        dead_code,
        reason = "the inert cleanup-candidate milestone consumes this exact locked view next"
    )]
    pub(crate) fn read_exact_record_locked<'lock>(
        &'lock self,
        lease_id: RepositorySnapshotLeaseId,
    ) -> Result<LockedCleanupJournalRecord<'lock, 'journal>, JournalError> {
        self.journal.clean_orphan_temporary_files_unlocked()?;
        let opened = self
            .journal
            .read_name_open(journal_name(lease_id).as_bytes())?;
        let root_stat = fstat(&*self.journal.root_fd).map_err(JournalError::errno)?;
        let lock_stat = fstat(&*self.journal.recovery_lock_fd).map_err(JournalError::errno)?;
        Ok(LockedCleanupJournalRecord {
            envelope_bytes: opened.envelope_bytes,
            record: opened.record,
            root_identity: file_identity(&root_stat),
            lock_identity: file_identity(&lock_stat),
            record_identity: opened.identity,
            _record_file: opened.file,
            _recovery_lock: PhantomData,
        })
    }
}

#[cfg(unix)]
#[allow(
    dead_code,
    reason = "the inert cleanup-candidate milestone consumes these borrowed views next"
)]
impl LockedCleanupJournalRecord<'_, '_> {
    pub(crate) fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }

    pub(crate) const fn record(&self) -> &CleanupJournalRecordV1 {
        &self.record
    }

    pub(crate) const fn root_identity(&self) -> RepositoryFileIdentityV1 {
        self.root_identity
    }

    pub(crate) const fn lock_identity(&self) -> RepositoryFileIdentityV1 {
        self.lock_identity
    }

    pub(crate) const fn record_identity(&self) -> RepositoryFileIdentityV1 {
        self.record_identity
    }
}

#[cfg(unix)]
struct OpenJournalRecord {
    envelope_bytes: Vec<u8>,
    record: CleanupJournalRecordV1,
    identity: RepositoryFileIdentityV1,
    file: std::fs::File,
}

impl FileCleanupJournal {
    /// Opens a dedicated local recovery directory and removes only bounded,
    /// structurally valid temporary files left by this journal's atomic writer.
    ///
    /// # Errors
    ///
    /// Rejects symlinks, non-directory roots, unknown entries and unsafe or
    /// excessive orphan temporary files.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, JournalError> {
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(JournalError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            std::fs::create_dir_all(root.as_ref()).map_err(JournalError::io)?;
            let root_fd = open(
                root.as_ref(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(JournalError::errno)?;
            let recovery_lock_fd = openat(
                &root_fd,
                RECOVERY_LOCK_NAME,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(JournalError::errno)?;
            let recovery_lock_stat = fstat(&recovery_lock_fd).map_err(JournalError::errno)?;
            if FileType::from_raw_mode(recovery_lock_stat.st_mode) != FileType::RegularFile
                || recovery_lock_stat.st_size != 0
                || recovery_lock_stat.st_nlink != 1
                || recovery_lock_stat.st_mode & 0o777 != 0o600
            {
                return Err(JournalError::UnsafeEntry);
            }
            fsync(&root_fd).map_err(JournalError::errno)?;
            let journal = Self {
                root: root.as_ref().to_path_buf(),
                root_fd: Arc::new(root_fd),
                recovery_lock_fd: Arc::new(recovery_lock_fd),
                recovery_lock_local: Arc::new(RwLock::new(())),
            };
            {
                let _initialization_lock = journal.lock_recovery(false)?;
                journal.clean_orphan_temporary_files_unlocked()?;
                let _ = journal.load_all_unlocked()?;
            }
            Ok(journal)
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn write(&self, record: &CleanupJournalRecordV1) -> Result<(), JournalError> {
        #[cfg(unix)]
        let _lifecycle_lock = self.lock_shared()?;
        self.write_unlocked(record)
    }

    fn write_unlocked(&self, record: &CleanupJournalRecordV1) -> Result<(), JournalError> {
        validate_record(record)?;
        let record_bytes = serde_json::to_vec(record).map_err(|_| JournalError::Encoding)?;
        let envelope = JournalEnvelope {
            schema_version: JOURNAL_SCHEMA_VERSION,
            record_sha256: Sha256Digest::of_bytes(&record_bytes),
            record: record.clone(),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| JournalError::Encoding)?;
        if usize_to_u64(bytes.len()) > MAX_JOURNAL_BYTES {
            return Err(JournalError::TooLarge);
        }

        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(JournalError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let final_name = journal_name(record.lease_id);
            let temporary_name = temporary_name(record.lease_id, Uuid::now_v7());
            let temporary_fd = openat(
                &*self.root_fd,
                temporary_name.as_bytes(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(JournalError::errno)?;
            let mut temporary = std::fs::File::from(temporary_fd);
            let result = (|| {
                temporary.write_all(&bytes).map_err(JournalError::io)?;
                temporary.sync_all().map_err(JournalError::io)?;
                renameat(
                    &*self.root_fd,
                    temporary_name.as_bytes(),
                    &*self.root_fd,
                    final_name.as_bytes(),
                )
                .map_err(JournalError::errno)?;
                fsync(&*self.root_fd).map_err(JournalError::errno)
            })();
            if result.is_err() {
                let _ = unlinkat(&*self.root_fd, temporary_name.as_bytes(), AtFlags::empty());
            }
            result
        }
    }

    pub(crate) fn remove(&self, lease_id: RepositorySnapshotLeaseId) -> Result<(), JournalError> {
        #[cfg(unix)]
        let _lifecycle_lock = self.lock_shared()?;
        self.remove_unlocked(lease_id)
    }

    fn remove_unlocked(&self, lease_id: RepositorySnapshotLeaseId) -> Result<(), JournalError> {
        #[cfg(not(unix))]
        {
            let _ = lease_id;
            Err(JournalError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            match unlinkat(
                &*self.root_fd,
                journal_name(lease_id).as_bytes(),
                AtFlags::empty(),
            ) {
                Ok(()) => fsync(&*self.root_fd).map_err(JournalError::errno),
                Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
                Err(error) => Err(JournalError::errno(error)),
            }
        }
    }

    pub(crate) fn load_all(&self) -> Result<Vec<CleanupJournalRecordV1>, JournalError> {
        #[cfg(unix)]
        let _lifecycle_lock = self.lock_shared()?;
        self.load_all_unlocked()
    }

    fn load_all_unlocked(&self) -> Result<Vec<CleanupJournalRecordV1>, JournalError> {
        #[cfg(not(unix))]
        {
            Err(JournalError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let mut names = self.entry_names()?;
            names.sort();
            names
                .into_iter()
                .filter(|name| {
                    name.as_slice() != RECOVERY_LOCK_NAME && !is_temporary_name(name.as_slice())
                })
                .map(|name| self.read_name(&name))
                .collect()
        }
    }

    /// Takes a non-blocking process/thread exclusive lock spanning recovery's
    /// compare-observe-effect-cleanup transaction.
    pub(crate) fn try_lock_recovery(&self) -> Result<JournalRecoveryLock<'_>, JournalError> {
        #[cfg(unix)]
        {
            self.lock_recovery(true)
        }
        #[cfg(not(unix))]
        {
            Err(JournalError::UnsupportedPlatform)
        }
    }

    #[cfg(unix)]
    fn lock_recovery(&self, nonblocking: bool) -> Result<JournalRecoveryLock<'_>, JournalError> {
        let local = if nonblocking {
            match self.recovery_lock_local.try_write() {
                Ok(local) => local,
                Err(std::sync::TryLockError::WouldBlock) => {
                    return Err(JournalError::RecoveryBusy);
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(JournalError::RecoveryLockUnavailable);
                }
            }
        } else {
            self.recovery_lock_local
                .write()
                .map_err(|_| JournalError::RecoveryLockUnavailable)?
        };
        self.validate_lock_binding(&self.recovery_lock_fd)?;
        let operation = if nonblocking {
            FlockOperation::NonBlockingLockExclusive
        } else {
            FlockOperation::LockExclusive
        };
        match flock(&*self.recovery_lock_fd, operation) {
            Ok(()) => {}
            Err(error)
                if nonblocking
                    && (error == rustix::io::Errno::AGAIN
                        || error == rustix::io::Errno::WOULDBLOCK) =>
            {
                return Err(JournalError::RecoveryBusy);
            }
            Err(error) => return Err(JournalError::errno(error)),
        }
        if let Err(error) = self.validate_lock_binding(&self.recovery_lock_fd) {
            let _ = flock(&*self.recovery_lock_fd, FlockOperation::Unlock);
            return Err(error);
        }
        Ok(JournalRecoveryLock {
            journal: self,
            _local: local,
        })
    }

    #[cfg(unix)]
    fn lock_shared(&self) -> Result<JournalSharedLock<'_>, JournalError> {
        let local = self
            .recovery_lock_local
            .read()
            .map_err(|_| JournalError::RecoveryLockUnavailable)?;
        let lock_fd = openat(
            &*self.root_fd,
            RECOVERY_LOCK_NAME,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(JournalError::errno)?;
        self.validate_lock_binding(&lock_fd)?;
        flock(&lock_fd, FlockOperation::LockShared).map_err(JournalError::errno)?;
        if let Err(error) = self.validate_lock_binding(&lock_fd) {
            let _ = flock(&lock_fd, FlockOperation::Unlock);
            return Err(error);
        }
        Ok(JournalSharedLock {
            lock_fd,
            _local: local,
        })
    }

    #[cfg(unix)]
    fn validate_lock_binding(&self, active_fd: &OwnedFd) -> Result<(), JournalError> {
        let root = fstat(&*self.root_fd).map_err(JournalError::errno)?;
        let named = statat(
            &*self.root_fd,
            RECOVERY_LOCK_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(JournalError::errno)?;
        let canonical = fstat(&*self.recovery_lock_fd).map_err(JournalError::errno)?;
        let active = fstat(active_fd).map_err(JournalError::errno)?;
        if FileType::from_raw_mode(root.st_mode) != FileType::Directory
            || !safe_lock_file(&root, &named)
            || !safe_lock_file(&root, &canonical)
            || !safe_lock_file(&root, &active)
            || !same_node(&named, &canonical)
            || !same_node(&named, &active)
        {
            return Err(JournalError::LockIdentityChanged);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn read_name(&self, name: &[u8]) -> Result<CleanupJournalRecordV1, JournalError> {
        Ok(self.read_name_open(name)?.record)
    }

    #[cfg(unix)]
    fn read_name_open(&self, name: &[u8]) -> Result<OpenJournalRecord, JournalError> {
        if !is_journal_name(name) {
            return Err(JournalError::UnsafeEntry);
        }
        let listed =
            statat(&*self.root_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(JournalError::errno)?;
        if FileType::from_raw_mode(listed.st_mode) != FileType::RegularFile
            || listed.st_size < 0
            || u64::try_from(listed.st_size).unwrap_or(u64::MAX) > MAX_JOURNAL_BYTES
        {
            return Err(JournalError::UnsafeEntry);
        }
        let fd = openat(
            &*self.root_fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(JournalError::errno)?;
        let before = fstat(&fd).map_err(JournalError::errno)?;
        if !same_node(&listed, &before) {
            return Err(JournalError::UnsafeEntry);
        }
        let capacity = usize::try_from(before.st_size).map_err(|_| JournalError::TooLarge)?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut file = std::fs::File::from(fd);
        file.read_to_end(&mut bytes).map_err(JournalError::io)?;
        let after = fstat(&file).map_err(JournalError::errno)?;
        if !same_observation(&before, &after)
            || usize_to_u64(bytes.len()) != u64::try_from(after.st_size).unwrap_or(u64::MAX)
        {
            return Err(JournalError::InvalidRecord);
        }
        let envelope = serde_json::from_slice::<JournalEnvelope>(&bytes)
            .map_err(|_| JournalError::InvalidRecord)?;
        let canonical = serde_json::to_vec(&envelope).map_err(|_| JournalError::Encoding)?;
        let record_bytes =
            serde_json::to_vec(&envelope.record).map_err(|_| JournalError::Encoding)?;
        if canonical != bytes
            || envelope.schema_version != JOURNAL_SCHEMA_VERSION
            || envelope.record_sha256 != Sha256Digest::of_bytes(&record_bytes)
        {
            return Err(JournalError::InvalidRecord);
        }
        validate_record(&envelope.record)?;
        if name != journal_name(envelope.record.lease_id).as_bytes() {
            return Err(JournalError::InvalidRecord);
        }
        Ok(OpenJournalRecord {
            envelope_bytes: bytes,
            record: envelope.record,
            identity: file_identity(&after),
            file,
        })
    }

    #[cfg(unix)]
    fn entry_names(&self) -> Result<Vec<Vec<u8>>, JournalError> {
        let mut stream = Dir::read_from(&*self.root_fd).map_err(JournalError::errno)?;
        let mut names = Vec::new();
        while let Some(entry) = stream.read() {
            let entry = entry.map_err(JournalError::errno)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        Ok(names)
    }

    #[cfg(unix)]
    fn clean_orphan_temporary_files_unlocked(&self) -> Result<(), JournalError> {
        let names = self.entry_names()?;
        let temporary_names = names
            .iter()
            .filter(|name| is_temporary_name(name))
            .collect::<Vec<_>>();
        if temporary_names.len() > MAX_ORPHAN_TEMP_FILES {
            return Err(JournalError::TooManyTemporaryFiles);
        }
        for name in &names {
            if is_journal_name(name) || name.as_slice() == RECOVERY_LOCK_NAME {
                continue;
            }
            if !is_temporary_name(name) {
                return Err(JournalError::UnsafeEntry);
            }
            let stat = statat(&*self.root_fd, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(JournalError::errno)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_size < 0
                || u64::try_from(stat.st_size).unwrap_or(u64::MAX) > MAX_JOURNAL_BYTES
            {
                return Err(JournalError::UnsafeEntry);
            }
            unlinkat(&*self.root_fd, name, AtFlags::empty()).map_err(JournalError::errno)?;
        }
        if !temporary_names.is_empty() {
            fsync(&*self.root_fd).map_err(JournalError::errno)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    schema_version: u32,
    record_sha256: Sha256Digest,
    record: CleanupJournalRecordV1,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("cleanup journal is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("cleanup journal root is not a safe directory")]
    UnsafeRoot,
    #[error("cleanup journal contains an unknown, non-regular or symbolic-link entry")]
    UnsafeEntry,
    #[error("cleanup journal record exceeds the bounded size")]
    TooLarge,
    #[error("cleanup journal contains too many orphan temporary files")]
    TooManyTemporaryFiles,
    #[error("another process or thread already owns workspace recovery")]
    RecoveryBusy,
    #[error("the in-process workspace recovery lock is unavailable")]
    RecoveryLockUnavailable,
    #[error("the named cleanup journal lifecycle lock no longer matches its retained descriptor")]
    LockIdentityChanged,
    #[error("cleanup journal record is invalid or non-canonical")]
    InvalidRecord,
    #[error("cleanup journal encoding failed")]
    Encoding,
    #[error("cleanup journal I/O failed (os error {raw_os_error:?})")]
    Io { raw_os_error: Option<i32> },
}

impl JournalError {
    #[allow(
        clippy::needless_pass_by_value,
        reason = "map_err supplies owned std I/O errors at each filesystem boundary"
    )]
    fn io(error: std::io::Error) -> Self {
        Self::Io {
            raw_os_error: error.raw_os_error(),
        }
    }

    #[cfg(unix)]
    fn errno(error: rustix::io::Errno) -> Self {
        Self::Io {
            raw_os_error: Some(error.raw_os_error()),
        }
    }
}

fn validate_record(record: &CleanupJournalRecordV1) -> Result<(), JournalError> {
    if record.schema_version != JOURNAL_SCHEMA_VERSION
        || !bounded_nonempty(&record.local_cleanup_id, MAX_LOCAL_ID_BYTES)
        || !Uuid::parse_str(&record.local_cleanup_id)
            .is_ok_and(|parsed| parsed.to_string() == record.local_cleanup_id)
        || !bounded_nonempty(&record.snapshot_id, MAX_SNAPSHOT_ID_BYTES)
        || record.writer_revocation_event_id == record.snapshot_lease_event_id
        || record.source_path.unix_bytes().is_none()
        || record.image_path.unix_bytes().is_none()
        || record.mount_path.unix_bytes().is_none()
    {
        return Err(JournalError::InvalidRecord);
    }
    let none = record.unmounted_root_identity.is_none()
        && record.mounted_root_identity.is_none()
        && record.leaf_device_identifier.is_none();
    let attach_prepared = record.unmounted_root_identity.is_some()
        && record.mounted_root_identity.is_none()
        && record.leaf_device_identifier.is_none();
    let mounted = record.unmounted_root_identity.is_some()
        && record.mounted_root_identity.is_some()
        && valid_device_identifier(record.leaf_device_identifier.as_deref());
    let valid_stage_shape = match record.stage {
        CleanupStageV1::WriterRevoked
        | CleanupStageV1::CreatePrepared
        | CleanupStageV1::CreateOutcomeUnknown
        | CleanupStageV1::CreateCleanupRequired
        | CleanupStageV1::ImageCaptured => none,
        CleanupStageV1::AttachPrepared | CleanupStageV1::AttachOutcomeUnknown => attach_prepared,
        CleanupStageV1::MountedDetachRequired
        | CleanupStageV1::LeaseCommitted
        | CleanupStageV1::DetachPrepared
        | CleanupStageV1::DetachOutcomeUnknown
        | CleanupStageV1::DetachedObserved => mounted,
    };
    if !valid_stage_shape {
        return Err(JournalError::InvalidRecord);
    }
    Ok(())
}

fn bounded_nonempty(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

fn valid_device_identifier(value: Option<&str>) -> bool {
    value.is_some_and(|value| bounded_nonempty(value, MAX_DEVICE_IDENTIFIER_BYTES))
}

fn journal_name(lease_id: RepositorySnapshotLeaseId) -> String {
    format!("{lease_id}.json")
}

fn temporary_name(lease_id: RepositorySnapshotLeaseId, temporary_id: Uuid) -> String {
    format!(".{lease_id}.{temporary_id}.tmp")
}

fn is_journal_name(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let Some(uuid) = name.strip_suffix(".json") else {
        return false;
    };
    Uuid::parse_str(uuid).is_ok_and(|parsed| parsed.to_string() == uuid)
}

fn is_temporary_name(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let Some(body) = name
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((lease, temporary)) = body.split_once('.') else {
        return false;
    };
    Uuid::parse_str(lease).is_ok_and(|parsed| parsed.to_string() == lease)
        && Uuid::parse_str(temporary).is_ok_and(|parsed| parsed.to_string() == temporary)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(unix)]
fn same_node(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && FileType::from_raw_mode(right.st_mode) == FileType::RegularFile
}

#[cfg(unix)]
fn same_observation(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    same_node(left, right)
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

#[cfg(unix)]
fn safe_lock_file(root: &rustix::fs::Stat, lock: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(lock.st_mode) == FileType::RegularFile
        && lock.st_size == 0
        && lock.st_nlink == 1
        && lock.st_mode & 0o777 == 0o600
        && lock.st_uid == root.st_uid
}

#[cfg(unix)]
fn file_identity(stat: &rustix::fs::Stat) -> RepositoryFileIdentityV1 {
    RepositoryFileIdentityV1::Unix(birdcode_protocol::RepositoryUnixFileIdentityV1 {
        device: u64::try_from(stat.st_dev).unwrap_or(u64::MAX),
        inode: stat.st_ino,
        byte_len: stat.st_size,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

pub(crate) fn recovery_disposition(stage: CleanupStageV1) -> RecoveryDispositionV1 {
    match stage {
        CleanupStageV1::WriterRevoked => RecoveryDispositionV1::AbortRevokedWriterCapture,
        CleanupStageV1::CreatePrepared | CleanupStageV1::CreateOutcomeUnknown => {
            RecoveryDispositionV1::InspectCreateOutcome
        }
        CleanupStageV1::CreateCleanupRequired => RecoveryDispositionV1::RemoveRejectedImage,
        CleanupStageV1::ImageCaptured => RecoveryDispositionV1::ResumeCapturedImageAttach,
        CleanupStageV1::AttachPrepared | CleanupStageV1::AttachOutcomeUnknown => {
            RecoveryDispositionV1::InspectAttachOutcome
        }
        CleanupStageV1::MountedDetachRequired | CleanupStageV1::LeaseCommitted => {
            RecoveryDispositionV1::ConfirmCommittedLeaseOrDetach
        }
        CleanupStageV1::DetachPrepared | CleanupStageV1::DetachOutcomeUnknown => {
            RecoveryDispositionV1::InspectDetachOutcome
        }
        CleanupStageV1::DetachedObserved => {
            RecoveryDispositionV1::ConfirmReleaseBeforeDeletingImage
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use birdcode_protocol::{
        RepositorySnapshotLeaseId, RepositorySnapshotLocalCleanupId,
        RepositorySnapshotRecoveryJournalStageV1, WorkspacePath,
        WorkspaceSnapshotCleanupJournalEnvelopeV1, WorkspaceSnapshotCleanupJournalRecordV1,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn identity(value: u64) -> RepositoryFileIdentityV1 {
        RepositoryFileIdentityV1::Unix(birdcode_protocol::RepositoryUnixFileIdentityV1 {
            device: value,
            inode: value,
            byte_len: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            changed_seconds: 0,
            changed_nanoseconds: 0,
        })
    }

    fn record(lease: u128) -> CleanupJournalRecordV1 {
        CleanupJournalRecordV1 {
            schema_version: JOURNAL_SCHEMA_VERSION,
            local_cleanup_id: id(99).to_string(),
            snapshot_id: "snapshot-1".to_owned(),
            lease_id: RepositorySnapshotLeaseId::from_uuid(id(lease)),
            writer_revocation_event_id: EventId::from_uuid(id(2)),
            snapshot_lease_event_id: EventId::from_uuid(id(3)),
            source_path: WorkspacePath::from_unix_bytes(b"/source".to_vec()),
            image_path: WorkspacePath::from_unix_bytes(b"/state/image.dmg".to_vec()),
            mount_path: WorkspacePath::from_unix_bytes(b"/state/mount".to_vec()),
            lifecycle_owner_actor_id: ActorId::from_uuid(id(4)),
            lifecycle_owner_runtime_instance_id: RuntimeInstanceId::from_uuid(id(5)),
            stage: CleanupStageV1::AttachOutcomeUnknown,
            unmounted_root_identity: Some(identity(10)),
            mounted_root_identity: None,
            leaf_device_identifier: None,
        }
    }

    fn protocol_stage(stage: CleanupStageV1) -> RepositorySnapshotRecoveryJournalStageV1 {
        match stage {
            CleanupStageV1::WriterRevoked => {
                RepositorySnapshotRecoveryJournalStageV1::WriterRevoked
            }
            CleanupStageV1::CreatePrepared => {
                RepositorySnapshotRecoveryJournalStageV1::CreatePrepared
            }
            CleanupStageV1::CreateOutcomeUnknown => {
                RepositorySnapshotRecoveryJournalStageV1::CreateOutcomeUnknown
            }
            CleanupStageV1::CreateCleanupRequired => {
                RepositorySnapshotRecoveryJournalStageV1::CreateCleanupRequired
            }
            CleanupStageV1::ImageCaptured => {
                RepositorySnapshotRecoveryJournalStageV1::ImageCaptured
            }
            CleanupStageV1::AttachPrepared => {
                RepositorySnapshotRecoveryJournalStageV1::AttachPrepared
            }
            CleanupStageV1::AttachOutcomeUnknown => {
                RepositorySnapshotRecoveryJournalStageV1::AttachOutcomeUnknown
            }
            CleanupStageV1::MountedDetachRequired => {
                RepositorySnapshotRecoveryJournalStageV1::MountedDetachRequired
            }
            CleanupStageV1::LeaseCommitted => {
                RepositorySnapshotRecoveryJournalStageV1::LeaseCommitted
            }
            CleanupStageV1::DetachPrepared => {
                RepositorySnapshotRecoveryJournalStageV1::DetachPrepared
            }
            CleanupStageV1::DetachOutcomeUnknown => {
                RepositorySnapshotRecoveryJournalStageV1::DetachOutcomeUnknown
            }
            CleanupStageV1::DetachedObserved => {
                RepositorySnapshotRecoveryJournalStageV1::DetachedObserved
            }
        }
    }

    fn protocol_record(record: &CleanupJournalRecordV1) -> WorkspaceSnapshotCleanupJournalRecordV1 {
        WorkspaceSnapshotCleanupJournalRecordV1 {
            schema_version: record.schema_version,
            local_cleanup_id: RepositorySnapshotLocalCleanupId::from_uuid(
                Uuid::parse_str(&record.local_cleanup_id).expect("validated local cleanup UUID"),
            ),
            snapshot_id: record.snapshot_id.clone(),
            lease_id: record.lease_id,
            writer_revocation_event_id: record.writer_revocation_event_id,
            snapshot_lease_event_id: record.snapshot_lease_event_id,
            source_path: record.source_path.clone(),
            image_path: record.image_path.clone(),
            mount_path: record.mount_path.clone(),
            lifecycle_owner_actor_id: record.lifecycle_owner_actor_id,
            lifecycle_owner_runtime_instance_id: record.lifecycle_owner_runtime_instance_id,
            stage: protocol_stage(record.stage),
            unmounted_root_identity: record.unmounted_root_identity,
            mounted_root_identity: record.mounted_root_identity,
            leaf_device_identifier: record.leaf_device_identifier.clone(),
        }
    }

    #[test]
    fn atomic_journal_round_trips_exact_canonical_records_with_private_mode() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = FileCleanupJournal::open(temporary.path()).expect("journal opens");
        let expected = record(1);
        journal.write(&expected).expect("record writes");
        assert_eq!(journal.load_all().expect("records load"), vec![expected]);
        let mode = std::fs::metadata(temporary.path().join(format!("{}.json", id(1))))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn protocol_cleanup_journal_mirror_is_byte_identical_to_workspace_wire() {
        let workspace_record = record(2);
        let protocol_record = protocol_record(&workspace_record);
        let workspace_record_bytes =
            serde_json::to_vec(&workspace_record).expect("workspace record encodes");
        assert_eq!(
            serde_json::to_vec(&protocol_record).expect("protocol record encodes"),
            workspace_record_bytes
        );

        let record_sha256 = Sha256Digest::of_bytes(&workspace_record_bytes);
        let workspace_envelope = JournalEnvelope {
            schema_version: JOURNAL_SCHEMA_VERSION,
            record_sha256: record_sha256.clone(),
            record: workspace_record,
        };
        let protocol_envelope = WorkspaceSnapshotCleanupJournalEnvelopeV1 {
            schema_version: JOURNAL_SCHEMA_VERSION,
            record_sha256,
            record: protocol_record,
        };
        assert_eq!(
            serde_json::to_vec(&protocol_envelope).expect("protocol envelope encodes"),
            serde_json::to_vec(&workspace_envelope).expect("workspace envelope encodes")
        );
    }

    #[test]
    fn journal_replaces_one_lease_atomically_and_removes_it() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = FileCleanupJournal::open(temporary.path()).expect("journal opens");
        let mut expected = record(11);
        journal.write(&expected).expect("first write");
        expected.stage = CleanupStageV1::MountedDetachRequired;
        expected.mounted_root_identity = Some(identity(11));
        expected.leaf_device_identifier = Some("disk-leaf".to_owned());
        journal.write(&expected).expect("replacement write");
        assert_eq!(journal.load_all().expect("records load"), vec![expected]);
        journal
            .remove(RepositorySnapshotLeaseId::from_uuid(id(11)))
            .expect("record removal is durable");
        assert!(journal.load_all().expect("records load").is_empty());
    }

    #[test]
    fn open_removes_only_structurally_owned_bounded_orphan_temp_files() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let name = temporary_name(RepositorySnapshotLeaseId::from_uuid(id(22)), id(23));
        std::fs::write(temporary.path().join(&name), b"partial").expect("orphan writes");
        FileCleanupJournal::open(temporary.path()).expect("journal cleans its orphan");
        assert!(!temporary.path().join(name).exists());
    }

    #[test]
    fn open_rejects_unknown_entries_and_symbolic_links() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::write(temporary.path().join("foreign"), b"not ours").expect("foreign writes");
        assert!(matches!(
            FileCleanupJournal::open(temporary.path()),
            Err(JournalError::UnsafeEntry)
        ));

        let temporary = tempfile::tempdir().expect("temporary directory");
        std::os::unix::fs::symlink(
            temporary.path(),
            temporary
                .path()
                .join(journal_name(RepositorySnapshotLeaseId::from_uuid(id(24)))),
        )
        .expect("symlink writes");
        assert!(matches!(
            FileCleanupJournal::open(temporary.path()),
            Err(JournalError::UnsafeEntry)
        ));
    }

    #[test]
    fn stage_specific_optional_fields_are_enforced() {
        let mut invalid = record(31);
        invalid.unmounted_root_identity = None;
        assert!(matches!(
            validate_record(&invalid),
            Err(JournalError::InvalidRecord)
        ));

        let mut invalid = record(32);
        invalid.stage = CleanupStageV1::MountedDetachRequired;
        assert!(matches!(
            validate_record(&invalid),
            Err(JournalError::InvalidRecord)
        ));
    }

    #[test]
    fn local_cleanup_id_must_use_the_protocol_canonical_uuid_wire() {
        let mut invalid = record(33);
        invalid.local_cleanup_id = Uuid::parse_str(&invalid.local_cleanup_id)
            .expect("fixture UUID parses")
            .simple()
            .to_string();
        assert!(matches!(
            validate_record(&invalid),
            Err(JournalError::InvalidRecord)
        ));
    }

    #[test]
    fn independent_journal_handles_exclude_concurrent_recovery() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let first = FileCleanupJournal::open(temporary.path()).expect("first journal");
        let second = FileCleanupJournal::open(temporary.path()).expect("second journal");
        let first_lock = first.try_lock_recovery().expect("first recovery lock");
        assert!(matches!(
            second.try_lock_recovery(),
            Err(JournalError::RecoveryBusy)
        ));
        drop(first_lock);
        assert!(second.try_lock_recovery().is_ok());
    }

    #[test]
    fn exclusive_recovery_uses_locked_io_without_reentering_the_shared_lane() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = FileCleanupJournal::open(temporary.path()).expect("journal opens");
        let expected = record(41);
        let lock = journal.try_lock_recovery().expect("exclusive lock");

        lock.write_locked(&expected).expect("locked write");
        assert_eq!(
            lock.load_all_locked().expect("locked load"),
            vec![expected.clone()]
        );

        let exact = lock
            .read_exact_record_locked(expected.lease_id)
            .expect("exact locked record");
        let record_bytes = serde_json::to_vec(&expected).expect("record encodes");
        let envelope = JournalEnvelope {
            schema_version: JOURNAL_SCHEMA_VERSION,
            record_sha256: Sha256Digest::of_bytes(&record_bytes),
            record: expected.clone(),
        };
        assert_eq!(
            exact.envelope_bytes(),
            serde_json::to_vec(&envelope)
                .expect("envelope encodes")
                .as_slice()
        );
        assert_eq!(exact.record(), &expected);
        assert!(matches!(
            exact.root_identity(),
            RepositoryFileIdentityV1::Unix(_)
        ));
        assert!(matches!(
            exact.lock_identity(),
            RepositoryFileIdentityV1::Unix(_)
        ));
        assert!(matches!(
            exact.record_identity(),
            RepositoryFileIdentityV1::Unix(_)
        ));
        drop(exact);

        lock.remove_locked(expected.lease_id)
            .expect("locked removal");
        assert!(lock.load_all_locked().expect("locked reload").is_empty());
    }

    #[test]
    fn exclusive_recovery_blocks_ordinary_journal_io_until_drop() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = FileCleanupJournal::open(temporary.path()).expect("journal opens");
        let lock = journal.try_lock_recovery().expect("exclusive lock");
        let contender = journal.clone();
        let expected = record(42);
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            started_tx.send(()).expect("start signal");
            done_tx
                .send(contender.write(&expected))
                .expect("completion signal");
        });

        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("contender starts");
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(lock);
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("contender unblocks")
            .expect("ordinary write succeeds");
        thread.join().expect("contender joins");
    }

    #[test]
    fn replacing_the_named_lifecycle_lock_fails_closed() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = FileCleanupJournal::open(temporary.path()).expect("journal opens");
        let named = temporary.path().join(".recovery.lock");
        std::fs::rename(&named, temporary.path().join("detached-lock"))
            .expect("retained lock name moves");
        std::fs::write(&named, []).expect("replacement lock writes");
        std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o600))
            .expect("replacement mode");

        assert!(matches!(
            journal.try_lock_recovery(),
            Err(JournalError::LockIdentityChanged)
        ));
        assert!(matches!(
            journal.load_all(),
            Err(JournalError::LockIdentityChanged)
        ));
    }

    #[test]
    fn subprocess_shared_lifecycle_lock_helper() {
        let Ok(root) = std::env::var("BIRDCODE_JOURNAL_SHARED_LOCK_HELPER_ROOT") else {
            return;
        };
        let ready = PathBuf::from(
            std::env::var("BIRDCODE_JOURNAL_SHARED_LOCK_HELPER_READY").expect("helper ready path"),
        );
        let release = PathBuf::from(
            std::env::var("BIRDCODE_JOURNAL_SHARED_LOCK_HELPER_RELEASE")
                .expect("helper release path"),
        );
        let journal = FileCleanupJournal::open(root).expect("helper journal opens");
        let _shared = journal.lock_shared().expect("helper shared lock");
        std::fs::write(&ready, b"ready").expect("helper signals ready");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !release.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(release.exists(), "parent did not release helper");
    }

    #[test]
    fn subprocess_shared_operation_excludes_exclusive_recovery() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal_root = temporary.path().join("journal");
        let journal = FileCleanupJournal::open(&journal_root).expect("parent journal opens");
        let ready = temporary.path().join("ready");
        let release = temporary.path().join("release");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "journal::tests::subprocess_shared_lifecycle_lock_helper",
                "--nocapture",
            ])
            .env("BIRDCODE_JOURNAL_SHARED_LOCK_HELPER_ROOT", &journal_root)
            .env("BIRDCODE_JOURNAL_SHARED_LOCK_HELPER_READY", &ready)
            .env("BIRDCODE_JOURNAL_SHARED_LOCK_HELPER_RELEASE", &release)
            .spawn()
            .expect("helper spawns");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "helper did not acquire shared lock");
        assert!(matches!(
            journal.try_lock_recovery(),
            Err(JournalError::RecoveryBusy)
        ));

        std::fs::write(&release, b"release").expect("helper release signal");
        assert!(child.wait().expect("helper wait").success());
        assert!(journal.try_lock_recovery().is_ok());
    }
}
