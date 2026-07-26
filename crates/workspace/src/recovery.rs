use crate::boundary::PreparedMacOsRecoveryInspection;
use crate::journal::JournalRecoveryLock;
use crate::manager::WorkspaceManager;
use crate::{
    COMMAND_STDERR_MEDIA_TYPE, COMMAND_STDOUT_MEDIA_TYPE, CleanupJournalRecordV1, CleanupStageV1,
    CommandBoundaryError, CommandBoundaryErrorKind, MountPresence, PlatformError,
    RECOVERY_HDIUTIL_INFO_MEDIA_TYPE, RecoveryDispositionV1, RecoveryInspectionV1,
    RetainedArtifact, WorkspaceManagerError,
};
use birdcode_protocol::{
    CHILD_RECONNAISSANCE_CONTRACT_VERSION, EventEnvelope, EventPayload,
    REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE, REPOSITORY_SNAPSHOT_MANIFEST_MEDIA_TYPE,
    RepositoryCommandArgumentV1, RepositoryExternalImageIdentityV1, RepositoryFileIdentityV1,
    RepositorySnapshotCleanupStateV1, RepositorySnapshotLeaseDocumentV1, RepositorySnapshotLeaseId,
    RepositorySnapshotLeaseModeV1, RepositorySnapshotMacOsDeviceV1,
    RepositorySnapshotManifestDocumentV1, RuntimeClockReading, Sha256Digest, WorkspacePath,
};
use plist::Value;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_RECOVERY_PLIST_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_RECOVERY_IMAGES: usize = 128;
const MAX_RECOVERY_ENTITIES: usize = 256;
const MAX_RECOVERY_DEVICE_BYTES: usize = 128;

/// Parses the one canonical macOS device path accepted as a recovery detach
/// target. Parse followed by structural re-encoding must reproduce every byte,
/// so leading zeroes and values outside the protocol's `u32` identity cannot
/// be relabelled in durable evidence.
pub(crate) fn parse_canonical_device_path(value: &str) -> Option<RepositorySnapshotMacOsDeviceV1> {
    if value.is_empty() || value.len() > MAX_RECOVERY_DEVICE_BYTES {
        return None;
    }
    let body = value.strip_prefix("/dev/disk")?;
    let (disk, partition) = match body.split_once('s') {
        Some((disk, partition)) if !partition.contains('s') => (disk, Some(partition)),
        Some(_) => return None,
        None => (body, None),
    };
    if disk.is_empty()
        || !disk.bytes().all(|byte| byte.is_ascii_digit())
        || partition.is_some_and(|partition| {
            partition.is_empty() || !partition.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    let disk_number = disk.parse::<u32>().ok()?;
    let partition_number = partition.map(str::parse::<u32>).transpose().ok()?;
    let canonical = partition_number.map_or_else(
        || format!("/dev/disk{disk_number}"),
        |partition| format!("/dev/disk{disk_number}s{partition}"),
    );
    (canonical == value).then_some(RepositorySnapshotMacOsDeviceV1 {
        disk_number,
        partition_number,
    })
}

pub(crate) fn valid_device_path(value: &str) -> bool {
    parse_canonical_device_path(value).is_some()
}

/// Exact durable Store material required to resume, rather than abandon, a
/// locally journaled snapshot lease after restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedSnapshotLeaseRecoveryV1 {
    pub lease_event: EventEnvelope,
    pub lease_artifact: RetainedArtifact,
}

/// Fully attested local snapshot state recovered without run-claim authority.
///
/// Recovery can prove that the immutable lease and mounted image still exist,
/// but only Store can attest the current claim. Callers must therefore move
/// this value together with a Store-issued `ActiveLease` handoff through
/// `WorkspaceManager::bind_recovered_snapshot_lease` before preparing release.
#[derive(Debug)]
pub struct RecoveredSnapshotLease {
    pub(crate) snapshot: birdcode_protocol::RepositorySnapshotBindingV1,
    pub(crate) root: birdcode_protocol::RepositoryRootBindingV1,
    pub(crate) mount_path: PathBuf,
    pub(crate) image_path: PathBuf,
    pub(crate) unmounted_root_identity: RepositoryFileIdentityV1,
    pub(crate) expected_image: RepositoryExternalImageIdentityV1,
    pub(crate) lease_event: EventEnvelope,
    pub(crate) record: CleanupJournalRecordV1,
}

impl RecoveredSnapshotLease {
    #[must_use]
    pub fn snapshot(&self) -> &birdcode_protocol::RepositorySnapshotBindingV1 {
        &self.snapshot
    }

    #[must_use]
    pub fn root(&self) -> &birdcode_protocol::RepositoryRootBindingV1 {
        &self.root
    }

    #[must_use]
    pub fn mount_path(&self) -> &Path {
        &self.mount_path
    }
}

/// Recovery never guesses whether an old lease should remain live. The caller
/// must explicitly choose resumption with exact durable evidence or local
/// abandonment for a failed/abandoned run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotRecoveryDirectiveV1 {
    AbandonForFreshCapture,
    ResumeCommittedLease(Box<CommittedSnapshotLeaseRecoveryV1>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryDirectiveAssignmentV1 {
    pub lease_id: RepositorySnapshotLeaseId,
    pub directive: SnapshotRecoveryDirectiveV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceRecoveryRequestV1 {
    /// Must equal a fresh `WorkspaceManager::recovery_inspections()` result
    /// byte-for-byte. This closes the observation/action gap.
    pub inspections: Vec<RecoveryInspectionV1>,
    /// Current process/runtime clock domain used for every newly observed
    /// recovery command. This must never be the abandoned record's old runtime
    /// identity merely for convenience.
    pub recovery_runtime_instance_id: birdcode_protocol::RuntimeInstanceId,
    /// Exactly one assignment is required for every inspection.
    pub directives: Vec<RecoveryDirectiveAssignmentV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPathAttestationV1 {
    pub source_path: WorkspacePath,
    pub image_path: WorkspacePath,
    pub mount_path: WorkspacePath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCommandKindV1 {
    InspectDiskImageTopology,
    DetachExactlyAssociatedMount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCommandEvidenceV1 {
    pub kind: RecoveryCommandKindV1,
    pub executable: WorkspacePath,
    pub argv: Vec<RepositoryCommandArgumentV1>,
    pub exit_code: i32,
    pub stdout: RetainedArtifact,
    pub stderr: RetainedArtifact,
    pub completed_at: RuntimeClockReading,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryTopologyObservationV1 {
    NoExpectedImageOrMountAttached,
    ExactImageMounted { leaf_device_identifier: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryImageObservationV1 {
    Missing,
    RegularFile {
        identity: RepositoryFileIdentityV1,
        byte_len: u64,
        sha256: Sha256Digest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryMountObservationV1 {
    Missing,
    ExactUnmountedDirectory {
        identity: RepositoryFileIdentityV1,
    },
    ExactReadOnlyMount {
        identity: RepositoryFileIdentityV1,
        leaf_device_identifier: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTopologyBlockV1 {
    InspectionCommandFailed,
    InspectionBoundaryNotStarted,
    InspectionBoundaryOutcomeUnknown,
    MalformedOrUnboundedPlist,
    NonUtf8ExpectedPath,
    ExpectedImageAppearsMultipleTimes,
    ExpectedMountAppearsMultipleTimes,
    ExpectedMountBelongsToDifferentImage,
    ExpectedImageAttachedWithoutExpectedMount,
    InvalidMountedDeviceIdentity,
    JournalStageCannotOwnObservedImage,
    JournalStageCannotOwnObservedMount,
    DetachCommandFailed,
    DetachBoundaryNotStarted,
    DetachBoundaryOutcomeUnknown,
    TopologyChangedBeforeDetach,
    DetachCompletedButMountRemains,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryBlockedReasonV1 {
    Topology(RecoveryTopologyBlockV1),
    CommandBoundary(CommandBoundaryError),
    MountPresence(MountPresence),
}

#[derive(Debug)]
pub enum RecoveryEntryOutcomeV1 {
    FreshCaptureReady,
    ActiveLeaseRecovered(Box<RecoveredSnapshotLease>),
    Blocked(RecoveryBlockedReasonV1),
}

#[derive(Debug)]
pub struct WorkspaceRecoveryEntryV1 {
    pub lease_id: RepositorySnapshotLeaseId,
    pub original_stage: CleanupStageV1,
    pub disposition: RecoveryDispositionV1,
    pub paths: RecoveryPathAttestationV1,
    pub topology: Option<RecoveryTopologyObservationV1>,
    pub image: Option<RecoveryImageObservationV1>,
    pub mount: Option<RecoveryMountObservationV1>,
    pub command_evidence: Vec<RecoveryCommandEvidenceV1>,
    pub outcome: RecoveryEntryOutcomeV1,
}

#[derive(Debug)]
pub struct WorkspaceRecoveryReportV1 {
    pub entries: Vec<WorkspaceRecoveryEntryV1>,
    /// True only when every journal record was durably cleaned and no recovered
    /// lease or blocked recovery remains.
    pub fresh_capture_permitted: bool,
}

#[derive(Debug, Error)]
pub enum WorkspaceRecoveryError {
    #[error("recovery inspections are stale, reordered, or substituted")]
    StaleInspectionSet,
    #[error("recovery directives do not bijectively match inspected lease IDs")]
    DirectiveSetMismatch,
    #[error("another process or thread already owns workspace recovery")]
    RecoveryAlreadyRunning,
    #[error("recovery runtime identity is invalid")]
    InvalidRecoveryRuntime,
    #[error("journal paths do not equal the manager-derived confined paths")]
    UnsafeJournalPath,
    #[error("journal mount path has an unexpected filesystem object")]
    UnexpectedMountPath,
    #[error("journal mount directory identity changed")]
    MountIdentityChanged,
    #[error("journal image changed during recovery")]
    ImageChanged,
    #[error("committed snapshot lease recovery evidence is invalid")]
    InvalidCommittedLease,
    #[error("this journal stage cannot resume a committed active lease")]
    InvalidResumeStage,
    #[error(transparent)]
    Manager(#[from] WorkspaceManagerError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
}

struct AttestedPaths {
    wire: RecoveryPathAttestationV1,
    image: PathBuf,
    mount: PathBuf,
}

enum TopologyInspection {
    Observed {
        topology: RecoveryTopologyObservationV1,
        evidence: RecoveryCommandEvidenceV1,
    },
    Blocked {
        reason: RecoveryBlockedReasonV1,
        evidence: Option<RecoveryCommandEvidenceV1>,
    },
}

pub(crate) fn execute(
    manager: &WorkspaceManager,
    request: WorkspaceRecoveryRequestV1,
) -> Result<WorkspaceRecoveryReportV1, WorkspaceRecoveryError> {
    let WorkspaceRecoveryRequestV1 {
        inspections,
        mut directives,
        recovery_runtime_instance_id,
    } = request;
    if recovery_runtime_instance_id.as_uuid().is_nil() {
        return Err(WorkspaceRecoveryError::InvalidRecoveryRuntime);
    }
    let recovery_lock = match manager.journal.try_lock_recovery() {
        Ok(lock) => lock,
        Err(crate::journal::JournalError::RecoveryBusy) => {
            return Err(WorkspaceRecoveryError::RecoveryAlreadyRunning);
        }
        Err(error) => return Err(WorkspaceManagerError::from(error).into()),
    };
    let current = WorkspaceManager::recovery_inspections_locked(&recovery_lock)?;
    if current != inspections {
        return Err(WorkspaceRecoveryError::StaleInspectionSet);
    }
    let mut seen = BTreeSet::new();
    if directives.len() != current.len()
        || directives
            .iter()
            .any(|assignment| !seen.insert(assignment.lease_id))
        || current
            .iter()
            .any(|inspection| !seen.contains(&inspection.record.lease_id))
    {
        return Err(WorkspaceRecoveryError::DirectiveSetMismatch);
    }

    let mut entries = Vec::with_capacity(current.len());
    for inspection in current {
        let index = directives
            .iter()
            .position(|assignment| assignment.lease_id == inspection.record.lease_id)
            .ok_or(WorkspaceRecoveryError::DirectiveSetMismatch)?;
        let directive = directives.swap_remove(index).directive;
        entries.push(recover_one(
            manager,
            &recovery_lock,
            &inspection,
            directive,
            recovery_runtime_instance_id,
        )?);
    }
    let fresh_capture_permitted = entries
        .iter()
        .all(|entry| matches!(entry.outcome, RecoveryEntryOutcomeV1::FreshCaptureReady));
    Ok(WorkspaceRecoveryReportV1 {
        entries,
        fresh_capture_permitted,
    })
}

fn recover_one(
    manager: &WorkspaceManager,
    recovery_lock: &JournalRecoveryLock<'_>,
    inspection: &RecoveryInspectionV1,
    directive: SnapshotRecoveryDirectiveV1,
    recovery_runtime_instance_id: birdcode_protocol::RuntimeInstanceId,
) -> Result<WorkspaceRecoveryEntryV1, WorkspaceRecoveryError> {
    let paths = attest_paths(manager, &inspection.record)?;
    let image = observe_image(&paths.image)?;
    let mut evidence = Vec::new();
    let topology = match inspect_topology(manager, recovery_runtime_instance_id, &paths)? {
        TopologyInspection::Observed {
            topology,
            evidence: observed,
        } => {
            evidence.push(observed);
            topology
        }
        TopologyInspection::Blocked {
            reason,
            evidence: observed,
        } => {
            evidence.extend(observed);
            return Ok(entry(
                inspection,
                paths.wire,
                None,
                Some(image),
                None,
                evidence,
                RecoveryEntryOutcomeV1::Blocked(reason),
            ));
        }
    };
    let mount = match observe_mount(&inspection.record, &paths.mount, &topology) {
        Ok(observation) => observation,
        Err(ObserveMountFailure::Blocked(reason)) => {
            return Ok(entry(
                inspection,
                paths.wire,
                Some(topology),
                Some(image),
                None,
                evidence,
                RecoveryEntryOutcomeV1::Blocked(reason),
            ));
        }
        Err(ObserveMountFailure::Fatal(error)) => return Err(error),
    };

    if inspection.record.stage == CleanupStageV1::WriterRevoked
        && matches!(image, RecoveryImageObservationV1::RegularFile { .. })
    {
        return Ok(entry(
            inspection,
            paths.wire,
            Some(topology),
            Some(image),
            Some(mount),
            evidence,
            RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                RecoveryTopologyBlockV1::JournalStageCannotOwnObservedImage,
            )),
        ));
    }

    match directive {
        SnapshotRecoveryDirectiveV1::ResumeCommittedLease(committed) => {
            let active = recover_active_lease(
                manager,
                recovery_lock,
                &inspection.record,
                &paths,
                &topology,
                &image,
                &mount,
                &committed,
            )?;
            Ok(entry(
                inspection,
                paths.wire,
                Some(topology),
                Some(image),
                Some(mount),
                evidence,
                RecoveryEntryOutcomeV1::ActiveLeaseRecovered(Box::new(active)),
            ))
        }
        SnapshotRecoveryDirectiveV1::AbandonForFreshCapture => abandon(
            manager,
            recovery_lock,
            inspection,
            paths,
            topology,
            image,
            mount,
            evidence,
            recovery_runtime_instance_id,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn entry(
    inspection: &RecoveryInspectionV1,
    paths: RecoveryPathAttestationV1,
    topology: Option<RecoveryTopologyObservationV1>,
    image: Option<RecoveryImageObservationV1>,
    mount: Option<RecoveryMountObservationV1>,
    command_evidence: Vec<RecoveryCommandEvidenceV1>,
    outcome: RecoveryEntryOutcomeV1,
) -> WorkspaceRecoveryEntryV1 {
    WorkspaceRecoveryEntryV1 {
        lease_id: inspection.record.lease_id,
        original_stage: inspection.record.stage,
        disposition: inspection.disposition,
        paths,
        topology,
        image,
        mount,
        command_evidence,
        outcome,
    }
}

fn attest_paths(
    manager: &WorkspaceManager,
    record: &CleanupJournalRecordV1,
) -> Result<AttestedPaths, WorkspaceRecoveryError> {
    let image = manager.images_root.join(format!("{}.dmg", record.lease_id));
    let mount = manager.mounts_root.join(record.lease_id.to_string());
    let source_wire: WorkspacePath = manager.source_path.clone().into();
    let image_wire: WorkspacePath = image.clone().into();
    let mount_wire: WorkspacePath = mount.clone().into();
    if record.source_path != source_wire
        || record.image_path != image_wire
        || record.mount_path != mount_wire
    {
        return Err(WorkspaceRecoveryError::UnsafeJournalPath);
    }
    Ok(AttestedPaths {
        wire: RecoveryPathAttestationV1 {
            source_path: source_wire,
            image_path: image_wire,
            mount_path: mount_wire,
        },
        image,
        mount,
    })
}

fn observe_image(path: &Path) -> Result<RecoveryImageObservationV1, WorkspaceRecoveryError> {
    match crate::platform::file_hash(path) {
        Ok(observed) => Ok(RecoveryImageObservationV1::RegularFile {
            identity: observed.identity,
            byte_len: observed.byte_len,
            sha256: observed.sha256,
        }),
        Err(PlatformError::Io {
            raw_os_error: Some(value),
        }) if crate::platform::is_not_found_errno(value) => Ok(RecoveryImageObservationV1::Missing),
        Err(error) => Err(error.into()),
    }
}

fn inspect_topology(
    manager: &WorkspaceManager,
    recovery_runtime_instance_id: birdcode_protocol::RuntimeInstanceId,
    paths: &AttestedPaths,
) -> Result<TopologyInspection, WorkspaceRecoveryError> {
    let command = PreparedMacOsRecoveryInspection::hdiutil_info();
    let output = match manager.command.inspect_recovery(&command) {
        Ok(output) => output,
        Err(error) => {
            return Ok(TopologyInspection::Blocked {
                reason: RecoveryBlockedReasonV1::CommandBoundary(error),
                evidence: None,
            });
        }
    };
    let completed_at = manager.now(recovery_runtime_instance_id)?;
    let stdout = manager.retain(RECOVERY_HDIUTIL_INFO_MEDIA_TYPE, output.stdout)?;
    let stderr = manager.retain(COMMAND_STDERR_MEDIA_TYPE, output.stderr)?;
    let evidence = RecoveryCommandEvidenceV1 {
        kind: RecoveryCommandKindV1::InspectDiskImageTopology,
        executable: command.executable().to_path_buf().into(),
        argv: command.protocol_argv().to_vec(),
        exit_code: output.exit_code,
        stdout,
        stderr,
        completed_at,
    };
    if output.exit_code != 0 {
        return Ok(TopologyInspection::Blocked {
            reason: RecoveryBlockedReasonV1::Topology(
                RecoveryTopologyBlockV1::InspectionCommandFailed,
            ),
            evidence: Some(evidence),
        });
    }
    match decode_topology(&evidence.stdout.bytes, &paths.image, &paths.mount) {
        Ok(topology) => Ok(TopologyInspection::Observed { topology, evidence }),
        Err(reason) => Ok(TopologyInspection::Blocked {
            reason: RecoveryBlockedReasonV1::Topology(reason),
            evidence: Some(evidence),
        }),
    }
}

enum ObserveMountFailure {
    Blocked(RecoveryBlockedReasonV1),
    Fatal(WorkspaceRecoveryError),
}

fn observe_mount(
    record: &CleanupJournalRecordV1,
    mount_path: &Path,
    topology: &RecoveryTopologyObservationV1,
) -> Result<RecoveryMountObservationV1, ObserveMountFailure> {
    match topology {
        RecoveryTopologyObservationV1::NoExpectedImageOrMountAttached => {
            let Some(unmounted) = record.unmounted_root_identity else {
                return match std::fs::symlink_metadata(mount_path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Ok(RecoveryMountObservationV1::Missing)
                    }
                    Ok(_) => Err(ObserveMountFailure::Fatal(
                        WorkspaceRecoveryError::UnexpectedMountPath,
                    )),
                    Err(error) => Err(ObserveMountFailure::Fatal(WorkspaceRecoveryError::Manager(
                        WorkspaceManagerError::Io {
                            raw_os_error: error.raw_os_error(),
                        },
                    ))),
                };
            };
            match crate::platform::ensure_empty_directory(mount_path) {
                Ok(identity) if identity == unmounted => {
                    Ok(RecoveryMountObservationV1::ExactUnmountedDirectory { identity })
                }
                Ok(_) => Err(ObserveMountFailure::Fatal(
                    WorkspaceRecoveryError::MountIdentityChanged,
                )),
                Err(PlatformError::Io {
                    raw_os_error: Some(value),
                }) if crate::platform::is_not_found_errno(value) => {
                    Ok(RecoveryMountObservationV1::Missing)
                }
                Err(error) => Err(ObserveMountFailure::Fatal(error.into())),
            }
        }
        RecoveryTopologyObservationV1::ExactImageMounted {
            leaf_device_identifier,
        } => {
            if matches!(
                record.stage,
                CleanupStageV1::WriterRevoked
                    | CleanupStageV1::CreatePrepared
                    | CleanupStageV1::CreateOutcomeUnknown
                    | CleanupStageV1::CreateCleanupRequired
                    | CleanupStageV1::ImageCaptured
            ) {
                return Err(ObserveMountFailure::Blocked(
                    RecoveryBlockedReasonV1::Topology(
                        RecoveryTopologyBlockV1::JournalStageCannotOwnObservedMount,
                    ),
                ));
            }
            let Some(unmounted) = record.unmounted_root_identity else {
                return Err(ObserveMountFailure::Fatal(
                    WorkspaceRecoveryError::MountIdentityChanged,
                ));
            };
            let observation = crate::platform::verify_read_only_mount(
                mount_path,
                format!(".birdcode-recovery-probe-{}", record.lease_id).as_bytes(),
            )
            .map_err(|error| ObserveMountFailure::Fatal(error.into()))?;
            if observation.mounted_root_identity == unmounted
                || record
                    .mounted_root_identity
                    .is_some_and(|expected| expected != observation.mounted_root_identity)
                || record
                    .leaf_device_identifier
                    .as_deref()
                    .is_some_and(|expected| expected != leaf_device_identifier)
            {
                return Err(ObserveMountFailure::Fatal(
                    WorkspaceRecoveryError::MountIdentityChanged,
                ));
            }
            Ok(RecoveryMountObservationV1::ExactReadOnlyMount {
                identity: observation.mounted_root_identity,
                leaf_device_identifier: leaf_device_identifier.clone(),
            })
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one recovery cleanup gate retains every observation while preserving journal-before-effect ordering"
)]
fn abandon(
    manager: &WorkspaceManager,
    recovery_lock: &JournalRecoveryLock<'_>,
    inspection: &RecoveryInspectionV1,
    paths: AttestedPaths,
    topology: RecoveryTopologyObservationV1,
    image: RecoveryImageObservationV1,
    mount: RecoveryMountObservationV1,
    mut evidence: Vec<RecoveryCommandEvidenceV1>,
    recovery_runtime_instance_id: birdcode_protocol::RuntimeInstanceId,
) -> Result<WorkspaceRecoveryEntryV1, WorkspaceRecoveryError> {
    let mut cleanup_record = inspection.record.clone();
    let mut final_mount = mount.clone();
    let topology_is_absent = match &topology {
        RecoveryTopologyObservationV1::NoExpectedImageOrMountAttached => true,
        RecoveryTopologyObservationV1::ExactImageMounted {
            leaf_device_identifier,
        } => {
            let RecoveryMountObservationV1::ExactReadOnlyMount { identity, .. } = &mount else {
                return Err(WorkspaceRecoveryError::MountIdentityChanged);
            };
            let original = cleanup_record.clone();
            cleanup_record.stage = CleanupStageV1::DetachPrepared;
            cleanup_record.mounted_root_identity = Some(*identity);
            cleanup_record.leaf_device_identifier = Some(leaf_device_identifier.clone());
            recovery_lock
                .write_locked(&cleanup_record)
                .map_err(WorkspaceManagerError::from)?;
            match inspect_topology(manager, recovery_runtime_instance_id, &paths)? {
                TopologyInspection::Observed {
                    topology: confirmed,
                    evidence: observation,
                } if confirmed == topology => {
                    evidence.push(observation);
                    match observe_mount(&cleanup_record, &paths.mount, &confirmed) {
                        Ok(confirmed_mount) if confirmed_mount == mount => {}
                        Ok(_) | Err(ObserveMountFailure::Blocked(_)) => {
                            recovery_lock
                                .write_locked(&original)
                                .map_err(WorkspaceManagerError::from)?;
                            return Ok(entry(
                                inspection,
                                paths.wire,
                                Some(confirmed),
                                Some(image),
                                Some(mount),
                                evidence,
                                RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                                    RecoveryTopologyBlockV1::TopologyChangedBeforeDetach,
                                )),
                            ));
                        }
                        Err(ObserveMountFailure::Fatal(error)) => {
                            recovery_lock
                                .write_locked(&original)
                                .map_err(WorkspaceManagerError::from)?;
                            return Err(error);
                        }
                    }
                }
                TopologyInspection::Observed {
                    topology: changed,
                    evidence: observation,
                } => {
                    evidence.push(observation);
                    recovery_lock
                        .write_locked(&original)
                        .map_err(WorkspaceManagerError::from)?;
                    return Ok(entry(
                        inspection,
                        paths.wire,
                        Some(changed),
                        Some(image),
                        Some(mount),
                        evidence,
                        RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                            RecoveryTopologyBlockV1::TopologyChangedBeforeDetach,
                        )),
                    ));
                }
                TopologyInspection::Blocked {
                    reason,
                    evidence: observation,
                } => {
                    evidence.extend(observation);
                    recovery_lock
                        .write_locked(&original)
                        .map_err(WorkspaceManagerError::from)?;
                    return Ok(entry(
                        inspection,
                        paths.wire,
                        Some(topology),
                        Some(image),
                        Some(mount),
                        evidence,
                        RecoveryEntryOutcomeV1::Blocked(reason),
                    ));
                }
            }
            let command = super::manager::recovery_detach_device_command(leaf_device_identifier)
                .ok_or(WorkspaceRecoveryError::MountIdentityChanged)?;
            let output = match manager.command.run(&command) {
                Ok(output) => output,
                Err(error) if error.kind == CommandBoundaryErrorKind::NotStarted => {
                    recovery_lock
                        .write_locked(&original)
                        .map_err(WorkspaceManagerError::from)?;
                    return Ok(entry(
                        inspection,
                        paths.wire,
                        Some(topology),
                        Some(image),
                        Some(mount),
                        evidence,
                        RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::CommandBoundary(
                            error,
                        )),
                    ));
                }
                Err(error) => {
                    cleanup_record.stage = CleanupStageV1::DetachOutcomeUnknown;
                    recovery_lock
                        .write_locked(&cleanup_record)
                        .map_err(WorkspaceManagerError::from)?;
                    return Ok(entry(
                        inspection,
                        paths.wire,
                        Some(topology),
                        Some(image),
                        Some(mount),
                        evidence,
                        RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::CommandBoundary(
                            error,
                        )),
                    ));
                }
            };
            let completed_at = manager.now(recovery_runtime_instance_id)?;
            let stdout = manager.retain(COMMAND_STDOUT_MEDIA_TYPE, output.stdout)?;
            let stderr = manager.retain(COMMAND_STDERR_MEDIA_TYPE, output.stderr)?;
            evidence.push(RecoveryCommandEvidenceV1 {
                kind: RecoveryCommandKindV1::DetachExactlyAssociatedMount,
                executable: command.executable().to_path_buf().into(),
                argv: command.protocol_argv().to_vec(),
                exit_code: output.exit_code,
                stdout,
                stderr,
                completed_at,
            });
            if output.exit_code != 0 {
                cleanup_record.stage = CleanupStageV1::DetachOutcomeUnknown;
                recovery_lock
                    .write_locked(&cleanup_record)
                    .map_err(WorkspaceManagerError::from)?;
                return Ok(entry(
                    inspection,
                    paths.wire,
                    Some(topology),
                    Some(image),
                    Some(mount),
                    evidence,
                    RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                        RecoveryTopologyBlockV1::DetachCommandFailed,
                    )),
                ));
            }
            match inspect_topology(manager, recovery_runtime_instance_id, &paths)? {
                TopologyInspection::Observed {
                    topology: RecoveryTopologyObservationV1::NoExpectedImageOrMountAttached,
                    evidence: observation,
                } => evidence.push(observation),
                TopologyInspection::Observed {
                    topology: still_mounted,
                    evidence: observation,
                } => {
                    evidence.push(observation);
                    cleanup_record.stage = CleanupStageV1::DetachOutcomeUnknown;
                    recovery_lock
                        .write_locked(&cleanup_record)
                        .map_err(WorkspaceManagerError::from)?;
                    return Ok(entry(
                        inspection,
                        paths.wire,
                        Some(still_mounted),
                        Some(image),
                        Some(mount),
                        evidence,
                        RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                            RecoveryTopologyBlockV1::DetachCompletedButMountRemains,
                        )),
                    ));
                }
                TopologyInspection::Blocked {
                    reason,
                    evidence: observation,
                } => {
                    evidence.extend(observation);
                    cleanup_record.stage = CleanupStageV1::DetachOutcomeUnknown;
                    recovery_lock
                        .write_locked(&cleanup_record)
                        .map_err(WorkspaceManagerError::from)?;
                    return Ok(entry(
                        inspection,
                        paths.wire,
                        Some(topology),
                        Some(image),
                        Some(mount),
                        evidence,
                        RecoveryEntryOutcomeV1::Blocked(reason),
                    ));
                }
            }
            final_mount = observe_unmounted_mount(&cleanup_record, &paths.mount)?;
            cleanup_record.stage = CleanupStageV1::DetachedObserved;
            recovery_lock
                .write_locked(&cleanup_record)
                .map_err(WorkspaceManagerError::from)?;
            false
        }
    };

    if topology_is_absent {
        match inspect_topology(manager, recovery_runtime_instance_id, &paths)? {
            TopologyInspection::Observed {
                topology: RecoveryTopologyObservationV1::NoExpectedImageOrMountAttached,
                evidence: observation,
            } => evidence.push(observation),
            TopologyInspection::Observed {
                topology: still_mounted,
                evidence: observation,
            } => {
                evidence.push(observation);
                return Ok(entry(
                    inspection,
                    paths.wire,
                    Some(still_mounted),
                    Some(image),
                    Some(final_mount),
                    evidence,
                    RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                        RecoveryTopologyBlockV1::DetachCompletedButMountRemains,
                    )),
                ));
            }
            TopologyInspection::Blocked {
                reason,
                evidence: observation,
            } => {
                evidence.extend(observation);
                return Ok(entry(
                    inspection,
                    paths.wire,
                    Some(topology),
                    Some(image),
                    Some(final_mount),
                    evidence,
                    RecoveryEntryOutcomeV1::Blocked(reason),
                ));
            }
        }
    }

    remove_exact_image(&paths.image, &image)?;
    remove_exact_mount(&paths.mount, &final_mount)?;
    recovery_lock
        .remove_locked(cleanup_record.lease_id)
        .map_err(WorkspaceManagerError::from)?;
    manager.reconcile_writer_gate_from_journal_locked(recovery_lock)?;
    Ok(entry(
        inspection,
        paths.wire,
        Some(RecoveryTopologyObservationV1::NoExpectedImageOrMountAttached),
        Some(image),
        Some(final_mount),
        evidence,
        RecoveryEntryOutcomeV1::FreshCaptureReady,
    ))
}

fn observe_unmounted_mount(
    record: &CleanupJournalRecordV1,
    mount_path: &Path,
) -> Result<RecoveryMountObservationV1, WorkspaceRecoveryError> {
    let Some(unmounted) = record.unmounted_root_identity else {
        return Err(WorkspaceRecoveryError::MountIdentityChanged);
    };
    let Some(mounted) = record.mounted_root_identity else {
        return Err(WorkspaceRecoveryError::MountIdentityChanged);
    };
    match crate::platform::observe_mount_presence(mount_path, mounted, unmounted)? {
        MountPresence::UnmountedExpected => {
            Ok(RecoveryMountObservationV1::ExactUnmountedDirectory {
                identity: unmounted,
            })
        }
        MountPresence::Missing => Ok(RecoveryMountObservationV1::Missing),
        presence => Err(WorkspaceRecoveryError::Manager(
            WorkspaceManagerError::UnmountNotVerified { presence },
        )),
    }
}

fn remove_exact_image(
    path: &Path,
    expected: &RecoveryImageObservationV1,
) -> Result<(), WorkspaceRecoveryError> {
    let current = observe_image(path)?;
    if &current != expected {
        return Err(WorkspaceRecoveryError::ImageChanged);
    }
    if matches!(current, RecoveryImageObservationV1::RegularFile { .. }) {
        std::fs::remove_file(path).map_err(|error| {
            WorkspaceRecoveryError::Manager(WorkspaceManagerError::Io {
                raw_os_error: error.raw_os_error(),
            })
        })?;
    }
    Ok(())
}

fn remove_exact_mount(
    path: &Path,
    expected: &RecoveryMountObservationV1,
) -> Result<(), WorkspaceRecoveryError> {
    match expected {
        RecoveryMountObservationV1::Missing => match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(WorkspaceRecoveryError::UnexpectedMountPath),
            Err(error) => Err(WorkspaceRecoveryError::Manager(WorkspaceManagerError::Io {
                raw_os_error: error.raw_os_error(),
            })),
        },
        RecoveryMountObservationV1::ExactUnmountedDirectory { identity } => {
            let current = crate::platform::ensure_empty_directory(path)?;
            if current != *identity {
                return Err(WorkspaceRecoveryError::MountIdentityChanged);
            }
            std::fs::remove_dir(path).map_err(|error| {
                WorkspaceRecoveryError::Manager(WorkspaceManagerError::Io {
                    raw_os_error: error.raw_os_error(),
                })
            })
        }
        RecoveryMountObservationV1::ExactReadOnlyMount { .. } => Err(
            WorkspaceRecoveryError::Manager(WorkspaceManagerError::UnmountNotVerified {
                presence: MountPresence::MountedExpected,
            }),
        ),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn recover_active_lease(
    manager: &WorkspaceManager,
    recovery_lock: &JournalRecoveryLock<'_>,
    record: &CleanupJournalRecordV1,
    paths: &AttestedPaths,
    topology: &RecoveryTopologyObservationV1,
    image: &RecoveryImageObservationV1,
    mount: &RecoveryMountObservationV1,
    committed: &CommittedSnapshotLeaseRecoveryV1,
) -> Result<RecoveredSnapshotLease, WorkspaceRecoveryError> {
    if !matches!(
        record.stage,
        CleanupStageV1::MountedDetachRequired
            | CleanupStageV1::LeaseCommitted
            | CleanupStageV1::DetachPrepared
            | CleanupStageV1::DetachOutcomeUnknown
    ) {
        return Err(WorkspaceRecoveryError::InvalidResumeStage);
    }
    let RecoveryTopologyObservationV1::ExactImageMounted {
        leaf_device_identifier,
    } = topology
    else {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    };
    let RecoveryMountObservationV1::ExactReadOnlyMount { identity, .. } = mount else {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    };
    let RecoveryImageObservationV1::RegularFile {
        byte_len, sha256, ..
    } = image
    else {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    };
    committed
        .lease_artifact
        .verify(REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE)
        .map_err(|_| WorkspaceRecoveryError::InvalidCommittedLease)?;
    let document: RepositorySnapshotLeaseDocumentV1 =
        serde_json::from_slice(&committed.lease_artifact.bytes)
            .map_err(|_| WorkspaceRecoveryError::InvalidCommittedLease)?;
    if serde_json::to_vec(&document).map_err(|_| WorkspaceRecoveryError::InvalidCommittedLease)?
        != committed.lease_artifact.bytes
    {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    }
    let EventPayload::RepositorySnapshotLeaseIssued(payload) = &committed.lease_event.payload
    else {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    };
    let Some(run_id) = committed.lease_event.run_id else {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    };
    if committed.lease_event.id != record.snapshot_lease_event_id
        || committed.lease_event.id.as_uuid().is_nil()
        || committed.lease_event.session_id.as_uuid().is_nil()
        || run_id.as_uuid().is_nil()
        || committed.lease_event.actor_id != record.lifecycle_owner_actor_id
        || committed.lease_event.causal_parent != Some(payload.claim_event_id)
        || committed.lease_event.provenance.backend.is_some()
        || committed.lease_event.provenance.raw_artifact.as_ref()
            != Some(&committed.lease_artifact.artifact)
        || payload.issuer_actor_id != record.lifecycle_owner_actor_id
        || payload.claim_event_id.as_uuid().is_nil()
        || payload.claim_id.as_uuid().is_nil()
        || payload.claim_runtime_instance_id != record.lifecycle_owner_runtime_instance_id
        || payload.claim_generation == 0
        || document.schema_version != CHILD_RECONNAISSANCE_CONTRACT_VERSION
        || document.lease_id != record.lease_id
        || document.mode != RepositorySnapshotLeaseModeV1::MacOsCooperativeQuiescedReadOnlyDiskImage
        || document.snapshot_id != record.snapshot_id
        || document.macos_read_only_mount.source_path != record.source_path
        || document.macos_read_only_mount.image_path != record.image_path
        || document.macos_read_only_mount.mount_path != record.mount_path
        || document.macos_read_only_mount.leaf_device_identifier != *leaf_device_identifier
        || document.macos_read_only_mount.lifecycle_owner_actor_id
            != record.lifecycle_owner_actor_id
        || document
            .macos_read_only_mount
            .lifecycle_owner_runtime_instance_id
            != record.lifecycle_owner_runtime_instance_id
        || document.macos_read_only_mount.cleanup_state
            != RepositorySnapshotCleanupStateV1::MountedDetachRequired
        || document.macos_read_only_mount.statfs_receipt.mount_path != record.mount_path
        || document
            .macos_read_only_mount
            .statfs_receipt
            .leaf_device_identifier
            != *leaf_device_identifier
        || document
            .macos_read_only_mount
            .statfs_receipt
            .mounted_root_identity
            != *identity
        || document.root.descriptor_identity != *identity
        || document.macos_read_only_mount.image.byte_len != *byte_len
        || document.macos_read_only_mount.image.sha256 != *sha256
        || document.macos_read_only_mount.image_hash_receipt.path != record.image_path
        || document.macos_read_only_mount.image_hash_receipt.byte_len != *byte_len
        || document.macos_read_only_mount.image_hash_receipt.sha256 != *sha256
        || document.declared_snapshot_digest
            != document.macos_read_only_mount.post_mount_manifest_digest
        || payload.root != document.root
        || payload.snapshot.snapshot_id != document.snapshot_id
        || payload.snapshot.declared_snapshot_digest != document.declared_snapshot_digest
        || payload.snapshot.immutability_lease.lease_id != document.lease_id
        || payload.snapshot.immutability_lease.mode != document.mode
        || payload.snapshot.immutability_lease.lease_artifact != committed.lease_artifact.artifact
        || payload.snapshot.immutability_lease.lease_digest != committed.lease_artifact.digest
    {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    }
    let mounted_manifest = crate::manifest::observe(&paths.mount, manager.manifest_limits)
        .map_err(WorkspaceManagerError::from)?;
    let snapshot_manifest_document = RepositorySnapshotManifestDocumentV1 {
        schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        snapshot_id: document.snapshot_id.clone(),
        source_path: record.source_path.clone(),
        source_root_identity: document
            .macos_read_only_mount
            .source_quiescence
            .source_identity_after,
        mounted_root_identity: *identity,
        entries_digest: mounted_manifest.digest.clone(),
    };
    let snapshot_manifest_bytes = serde_json::to_vec(&snapshot_manifest_document)
        .map_err(|_| WorkspaceRecoveryError::InvalidCommittedLease)?;
    let snapshot_manifest_digest = Sha256Digest::of_bytes(&snapshot_manifest_bytes);
    if mounted_manifest.root_identity != *identity
        || mounted_manifest.digest
            != document
                .macos_read_only_mount
                .source_quiescence
                .source_manifest_after
        || snapshot_manifest_digest != document.declared_snapshot_digest
        || document
            .macos_read_only_mount
            .post_mount_manifest_artifact
            .sha256
            != snapshot_manifest_digest.as_str()
        || document
            .macos_read_only_mount
            .post_mount_manifest_artifact
            .size_bytes
            != u64::try_from(snapshot_manifest_bytes.len()).unwrap_or(u64::MAX)
        || document
            .macos_read_only_mount
            .post_mount_manifest_artifact
            .media_type
            != REPOSITORY_SNAPSHOT_MANIFEST_MEDIA_TYPE
    {
        return Err(WorkspaceRecoveryError::InvalidCommittedLease);
    }
    let unmounted_root_identity = record
        .unmounted_root_identity
        .ok_or(WorkspaceRecoveryError::InvalidCommittedLease)?;
    let mut active_record = record.clone();
    active_record.stage = CleanupStageV1::LeaseCommitted;
    recovery_lock
        .write_locked(&active_record)
        .map_err(WorkspaceManagerError::from)?;
    Ok(RecoveredSnapshotLease {
        snapshot: payload.snapshot.clone(),
        root: payload.root.clone(),
        mount_path: paths.mount.clone(),
        image_path: paths.image.clone(),
        unmounted_root_identity,
        expected_image: RepositoryExternalImageIdentityV1 {
            format: document.macos_read_only_mount.image.format,
            byte_len: *byte_len,
            sha256: sha256.clone(),
        },
        lease_event: committed.lease_event.clone(),
        record: active_record,
    })
}

fn decode_topology(
    bytes: &[u8],
    expected_image: &Path,
    expected_mount: &Path,
) -> Result<RecoveryTopologyObservationV1, RecoveryTopologyBlockV1> {
    if bytes.len() > MAX_RECOVERY_PLIST_BYTES {
        return Err(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist);
    }
    let expected_image = expected_image
        .to_str()
        .ok_or(RecoveryTopologyBlockV1::NonUtf8ExpectedPath)?;
    let expected_mount = expected_mount
        .to_str()
        .ok_or(RecoveryTopologyBlockV1::NonUtf8ExpectedPath)?;
    let value = Value::from_reader(Cursor::new(bytes))
        .map_err(|_| RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
    let root = value
        .as_dictionary()
        .ok_or(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
    let images = root
        .get("images")
        .and_then(Value::as_array)
        .ok_or(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
    if images.len() > MAX_RECOVERY_IMAGES {
        return Err(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist);
    }

    let mut expected_image_count = 0_usize;
    let mut expected_mount_count = 0_usize;
    let mut matching_device = None;
    let mut total_entities = 0_usize;
    for image in images {
        let dictionary = image
            .as_dictionary()
            .ok_or(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
        let image_path = dictionary
            .get("image-path")
            .and_then(Value::as_string)
            .ok_or(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
        let entities = dictionary
            .get("system-entities")
            .and_then(Value::as_array)
            .ok_or(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
        total_entities = total_entities
            .checked_add(entities.len())
            .ok_or(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
        if total_entities > MAX_RECOVERY_ENTITIES {
            return Err(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist);
        }
        let image_matches = image_path == expected_image;
        if image_matches {
            expected_image_count += 1;
        }
        for entity in entities {
            let entity = entity
                .as_dictionary()
                .ok_or(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist)?;
            let mount = entity.get("mount-point").and_then(Value::as_string);
            if mount == Some(expected_mount) {
                expected_mount_count += 1;
                if !image_matches {
                    return Err(RecoveryTopologyBlockV1::ExpectedMountBelongsToDifferentImage);
                }
                let device = entity
                    .get("dev-entry")
                    .and_then(Value::as_string)
                    .filter(|value| valid_device_path(value))
                    .ok_or(RecoveryTopologyBlockV1::InvalidMountedDeviceIdentity)?;
                matching_device = Some(device.to_owned());
            }
        }
    }
    if expected_image_count > 1 {
        return Err(RecoveryTopologyBlockV1::ExpectedImageAppearsMultipleTimes);
    }
    if expected_mount_count > 1 {
        return Err(RecoveryTopologyBlockV1::ExpectedMountAppearsMultipleTimes);
    }
    match (expected_image_count, expected_mount_count, matching_device) {
        (0, 0, None) => Ok(RecoveryTopologyObservationV1::NoExpectedImageOrMountAttached),
        (1, 1, Some(leaf_device_identifier)) => {
            Ok(RecoveryTopologyObservationV1::ExactImageMounted {
                leaf_device_identifier,
            })
        }
        (1, 0, None) => Err(RecoveryTopologyBlockV1::ExpectedImageAttachedWithoutExpectedMount),
        _ => Err(RecoveryTopologyBlockV1::MalformedOrUnboundedPlist),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::{
        ArtifactBoundary, CanonicalArtifactBoundary, ClockBoundary, ClockBoundaryError,
        CommandBoundary, RawCommandOutput, WorkspaceManagerConfig,
    };
    use birdcode_protocol::{ActorId, EventId, RepositoryUnixFileIdentityV1, RuntimeInstanceId};
    use chrono::Utc;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct FakeCommandBoundary {
        inspections: Mutex<VecDeque<Result<RawCommandOutput, CommandBoundaryError>>>,
        effects: Mutex<VecDeque<Result<RawCommandOutput, CommandBoundaryError>>>,
    }

    impl FakeCommandBoundary {
        fn inspections(outputs: Vec<RawCommandOutput>) -> Self {
            Self {
                inspections: Mutex::new(outputs.into_iter().map(Ok).collect::<VecDeque<_>>()),
                effects: Mutex::new(VecDeque::new()),
            }
        }

        fn inspection_errors(errors: Vec<CommandBoundaryError>) -> Self {
            Self {
                inspections: Mutex::new(errors.into_iter().map(Err).collect()),
                effects: Mutex::new(VecDeque::new()),
            }
        }
    }

    impl CommandBoundary for FakeCommandBoundary {
        fn run(
            &self,
            _command: &crate::PreparedMacOsCommand,
        ) -> Result<RawCommandOutput, CommandBoundaryError> {
            self.effects
                .lock()
                .expect("effect queue")
                .pop_front()
                .expect("unexpected recovery effect")
        }

        fn inspect_recovery(
            &self,
            _command: &PreparedMacOsRecoveryInspection,
        ) -> Result<RawCommandOutput, CommandBoundaryError> {
            self.inspections
                .lock()
                .expect("inspection queue")
                .pop_front()
                .expect("expected recovery inspection")
        }
    }

    #[derive(Default)]
    struct FakeClock {
        next: AtomicU64,
    }

    impl ClockBoundary for FakeClock {
        fn now(
            &self,
            runtime_instance_id: RuntimeInstanceId,
        ) -> Result<RuntimeClockReading, ClockBoundaryError> {
            Ok(RuntimeClockReading {
                runtime_instance_id,
                monotonic_nanos: self.next.fetch_add(1, Ordering::SeqCst),
                observed_at: Utc::now(),
            })
        }
    }

    struct Fixture {
        _source: tempfile::TempDir,
        _state: tempfile::TempDir,
        manager: WorkspaceManager,
        image_path: PathBuf,
        mount_path: PathBuf,
    }

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn identity(value: u64) -> RepositoryFileIdentityV1 {
        RepositoryFileIdentityV1::Unix(RepositoryUnixFileIdentityV1 {
            device: value,
            inode: value,
            byte_len: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            changed_seconds: 0,
            changed_nanoseconds: 0,
        })
    }

    fn output(stdout: Vec<u8>) -> RawCommandOutput {
        RawCommandOutput {
            exit_code: 0,
            stdout,
            stderr: Vec::new(),
        }
    }

    fn empty_info() -> Vec<u8> {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>images</key><array></array></dict></plist>"#
            .to_vec()
    }

    fn attached_without_mount_info(image: &Path) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>images</key><array><dict>
<key>image-path</key><string>{}</string><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/disk77</string></dict>
</array></dict></array></dict></plist>"#,
            image.display()
        )
        .into_bytes()
    }

    fn has_unmounted_identity(stage: CleanupStageV1) -> bool {
        matches!(
            stage,
            CleanupStageV1::AttachPrepared
                | CleanupStageV1::AttachOutcomeUnknown
                | CleanupStageV1::MountedDetachRequired
                | CleanupStageV1::LeaseCommitted
                | CleanupStageV1::DetachPrepared
                | CleanupStageV1::DetachOutcomeUnknown
                | CleanupStageV1::DetachedObserved
        )
    }

    fn has_mounted_identity(stage: CleanupStageV1) -> bool {
        matches!(
            stage,
            CleanupStageV1::MountedDetachRequired
                | CleanupStageV1::LeaseCommitted
                | CleanupStageV1::DetachPrepared
                | CleanupStageV1::DetachOutcomeUnknown
                | CleanupStageV1::DetachedObserved
        )
    }

    fn has_image(stage: CleanupStageV1) -> bool {
        stage != CleanupStageV1::WriterRevoked
    }

    fn fixture(stage: CleanupStageV1, command: Arc<dyn CommandBoundary>) -> Fixture {
        let source = tempfile::tempdir().expect("source");
        let recovery_root = tempfile::tempdir().expect("state");
        std::fs::write(source.path().join("source.rs"), b"fn main() {}\n").expect("source file");
        let config = WorkspaceManagerConfig::new(source.path(), recovery_root.path());
        let manager = WorkspaceManager::open_with_boundaries(
            config.clone(),
            Arc::clone(&command),
            Arc::new(CanonicalArtifactBoundary) as Arc<dyn ArtifactBoundary>,
            Arc::new(FakeClock::default()),
        )
        .expect("initial manager");
        let lease_id = RepositorySnapshotLeaseId::from_uuid(id(700));
        let image_path = manager.images_root.join(format!("{lease_id}.dmg"));
        let mount_path = manager.mounts_root.join(lease_id.to_string());
        if has_image(stage) {
            std::fs::write(&image_path, b"owned recovery image").expect("image fixture");
        }
        let mut record = CleanupJournalRecordV1::new(
            "snapshot-recovery".to_owned(),
            lease_id,
            EventId::from_uuid(id(701)),
            EventId::from_uuid(id(702)),
            manager.source_path.clone().into(),
            image_path.clone().into(),
            mount_path.clone().into(),
            ActorId::from_uuid(id(703)),
            RuntimeInstanceId::from_uuid(id(704)),
        );
        record.stage = stage;
        if has_unmounted_identity(stage) {
            std::fs::create_dir(&mount_path).expect("mount fixture");
            record.unmounted_root_identity = Some(
                crate::platform::ensure_empty_directory(&mount_path).expect("unmounted identity"),
            );
        }
        if has_mounted_identity(stage) {
            record.mounted_root_identity = Some(identity(99));
            record.leaf_device_identifier = Some("/dev/disk99s1".to_owned());
        }
        manager.journal.write(&record).expect("journal fixture");
        drop(manager);
        let manager = WorkspaceManager::open_with_boundaries(
            config,
            command,
            Arc::new(CanonicalArtifactBoundary),
            Arc::new(FakeClock::default()),
        )
        .expect("restarted manager");
        Fixture {
            _source: source,
            _state: recovery_root,
            manager,
            image_path,
            mount_path,
        }
    }

    fn abandon_request(manager: &WorkspaceManager) -> WorkspaceRecoveryRequestV1 {
        let inspections = manager.recovery_inspections().expect("inspections");
        let directives = inspections
            .iter()
            .map(|inspection| RecoveryDirectiveAssignmentV1 {
                lease_id: inspection.record.lease_id,
                directive: SnapshotRecoveryDirectiveV1::AbandonForFreshCapture,
            })
            .collect();
        WorkspaceRecoveryRequestV1 {
            inspections,
            directives,
            recovery_runtime_instance_id: RuntimeInstanceId::from_uuid(id(705)),
        }
    }

    #[test]
    fn topology_requires_a_bijective_exact_image_mount_and_device_binding() {
        let exact = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>images</key><array><dict>
<key>image-path</key><string>/state/images/lease.dmg</string>
<key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk9s1</string>
<key>mount-point</key><string>/state/mounts/lease</string></dict></array>
</dict></array></dict></plist>"#;
        assert_eq!(
            decode_topology(
                exact,
                Path::new("/state/images/lease.dmg"),
                Path::new("/state/mounts/lease")
            ),
            Ok(RecoveryTopologyObservationV1::ExactImageMounted {
                leaf_device_identifier: "/dev/disk9s1".to_owned(),
            })
        );

        let conflicting = String::from_utf8(exact.to_vec())
            .expect("fixture")
            .replace("/state/images/lease.dmg", "/foreign/image.dmg");
        assert_eq!(
            decode_topology(
                conflicting.as_bytes(),
                Path::new("/state/images/lease.dmg"),
                Path::new("/state/mounts/lease")
            ),
            Err(RecoveryTopologyBlockV1::ExpectedMountBelongsToDifferentImage)
        );
    }

    #[test]
    fn topology_blocks_an_attached_image_without_the_exact_expected_mount() {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>images</key><array><dict>
<key>image-path</key><string>/state/images/lease.dmg</string>
<key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk9</string></dict></array>
</dict></array></dict></plist>"#;
        assert_eq!(
            decode_topology(
                plist,
                Path::new("/state/images/lease.dmg"),
                Path::new("/state/mounts/lease")
            ),
            Err(RecoveryTopologyBlockV1::ExpectedImageAttachedWithoutExpectedMount)
        );
    }

    #[test]
    fn recovery_device_target_has_a_closed_absolute_grammar() {
        assert!(valid_device_path("/dev/disk1"));
        assert!(valid_device_path("/dev/disk123s45"));
        for rejected in [
            "disk1",
            "/dev/disk",
            "/dev/disk1s",
            "/dev/disk1s2s3",
            "/dev/disk-1",
            "/dev/disk1/../../disk2",
            "/dev/rdisk1",
            "/dev/disk01",
            "/dev/disk1s02",
            "/dev/disk4294967296",
            "/dev/disk1s4294967296",
        ] {
            assert!(!valid_device_path(rejected), "{rejected}");
        }
        assert_eq!(
            parse_canonical_device_path("/dev/disk123s45"),
            Some(RepositorySnapshotMacOsDeviceV1 {
                disk_number: 123,
                partition_number: Some(45),
            })
        );
        let command = crate::manager::recovery_detach_device_command("/dev/disk123s45")
            .expect("validated target builds");
        assert_eq!(
            command.native_argv(),
            ["detach", "/dev/disk123s45"].map(std::ffi::OsString::from)
        );
        assert!(crate::manager::recovery_detach_device_command("/tmp/not-a-device").is_none());
    }

    #[test]
    fn topology_rejects_duplicate_image_or_mount_associations() {
        let duplicate_image = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>images</key><array>
<dict><key>image-path</key><string>/state/images/lease.dmg</string><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/disk9s1</string><key>mount-point</key><string>/state/mounts/lease</string></dict>
</array></dict>
<dict><key>image-path</key><string>/state/images/lease.dmg</string><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/disk10s1</string><key>mount-point</key><string>/state/mounts/lease</string></dict>
</array></dict>
</array></dict></plist>"#;
        assert_eq!(
            decode_topology(
                duplicate_image,
                Path::new("/state/images/lease.dmg"),
                Path::new("/state/mounts/lease")
            ),
            Err(RecoveryTopologyBlockV1::ExpectedImageAppearsMultipleTimes)
        );

        let duplicate_mount = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>images</key><array><dict>
<key>image-path</key><string>/state/images/lease.dmg</string><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/disk9s1</string><key>mount-point</key><string>/state/mounts/lease</string></dict>
<dict><key>dev-entry</key><string>/dev/disk9s2</string><key>mount-point</key><string>/state/mounts/lease</string></dict>
</array></dict></array></dict></plist>"#;
        assert_eq!(
            decode_topology(
                duplicate_mount,
                Path::new("/state/images/lease.dmg"),
                Path::new("/state/mounts/lease")
            ),
            Err(RecoveryTopologyBlockV1::ExpectedMountAppearsMultipleTimes)
        );
    }

    #[test]
    fn every_journal_crash_cut_cleans_idempotently_after_two_absent_observations() {
        let stages = [
            CleanupStageV1::WriterRevoked,
            CleanupStageV1::CreatePrepared,
            CleanupStageV1::CreateOutcomeUnknown,
            CleanupStageV1::CreateCleanupRequired,
            CleanupStageV1::ImageCaptured,
            CleanupStageV1::AttachPrepared,
            CleanupStageV1::AttachOutcomeUnknown,
            CleanupStageV1::MountedDetachRequired,
            CleanupStageV1::LeaseCommitted,
            CleanupStageV1::DetachPrepared,
            CleanupStageV1::DetachOutcomeUnknown,
            CleanupStageV1::DetachedObserved,
        ];
        for stage in stages {
            let command = Arc::new(FakeCommandBoundary::inspections(vec![
                output(empty_info()),
                output(empty_info()),
            ]));
            let fixture = fixture(stage, command);
            let report = fixture
                .manager
                .recover_inspections(abandon_request(&fixture.manager))
                .unwrap_or_else(|error| panic!("{stage:?} recovery failed: {error}"));
            assert!(report.fresh_capture_permitted, "{stage:?}");
            assert_eq!(report.entries.len(), 1, "{stage:?}");
            assert!(matches!(
                report.entries[0].outcome,
                RecoveryEntryOutcomeV1::FreshCaptureReady
            ));
            assert_eq!(report.entries[0].command_evidence.len(), 2, "{stage:?}");
            assert!(report.entries[0].command_evidence.iter().all(|command| {
                command.completed_at.runtime_instance_id == RuntimeInstanceId::from_uuid(id(705))
                    && command.completed_at.runtime_instance_id
                        != RuntimeInstanceId::from_uuid(id(704))
            }));
            assert!(!fixture.image_path.exists(), "{stage:?}");
            assert!(!fixture.mount_path.exists(), "{stage:?}");
            assert!(
                fixture
                    .manager
                    .recovery_inspections()
                    .expect("empty recovery")
                    .is_empty(),
                "{stage:?}"
            );
            assert!(fixture.manager.acquire_writer().is_ok(), "{stage:?}");

            let repeated = fixture
                .manager
                .recover_inspections(WorkspaceRecoveryRequestV1 {
                    inspections: Vec::new(),
                    directives: Vec::new(),
                    recovery_runtime_instance_id: RuntimeInstanceId::from_uuid(id(705)),
                })
                .expect("empty recovery is idempotent");
            assert!(repeated.fresh_capture_permitted);
            assert!(repeated.entries.is_empty());
        }
    }

    #[test]
    fn ambiguous_attachment_is_manual_intervention_and_preserves_every_owned_path() {
        let command = Arc::new(FakeCommandBoundary::inspections(vec![output(empty_info())]));
        let fixture = fixture(CleanupStageV1::AttachOutcomeUnknown, command.clone());
        command
            .inspections
            .lock()
            .expect("inspection queue")
            .clear();
        command
            .inspections
            .lock()
            .expect("inspection queue")
            .push_back(Ok(output(attached_without_mount_info(&fixture.image_path))));
        let before = fixture.manager.recovery_inspections().expect("before");
        let report = fixture
            .manager
            .recover_inspections(abandon_request(&fixture.manager))
            .expect("ambiguity is a typed outcome");
        assert!(!report.fresh_capture_permitted);
        assert!(matches!(
            report.entries[0].outcome,
            RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                RecoveryTopologyBlockV1::ExpectedImageAttachedWithoutExpectedMount
            ))
        ));
        assert_eq!(report.entries[0].command_evidence.len(), 1);
        assert_eq!(
            report.entries[0].command_evidence[0].stdout.bytes,
            attached_without_mount_info(&fixture.image_path)
        );
        assert!(fixture.image_path.exists());
        assert!(fixture.mount_path.exists());
        assert_eq!(
            fixture.manager.recovery_inspections().expect("after"),
            before
        );
    }

    #[test]
    fn inspection_boundary_uncertainty_blocks_without_mutation_or_effect_retry() {
        let command = Arc::new(FakeCommandBoundary::inspection_errors(vec![
            CommandBoundaryError {
                kind: CommandBoundaryErrorKind::OutcomeUnknown,
                raw_os_error: Some(5),
            },
        ]));
        let fixture = fixture(CleanupStageV1::CreateOutcomeUnknown, command);
        let before = fixture.manager.recovery_inspections().expect("before");
        let report = fixture
            .manager
            .recover_inspections(abandon_request(&fixture.manager))
            .expect("uncertainty is a typed block");
        assert!(matches!(
            &report.entries[0].outcome,
            RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::CommandBoundary(
                CommandBoundaryError {
                    kind: CommandBoundaryErrorKind::OutcomeUnknown,
                    ..
                }
            ))
        ));
        assert!(report.entries[0].command_evidence.is_empty());
        assert!(fixture.image_path.exists());
        assert_eq!(
            fixture.manager.recovery_inspections().expect("after"),
            before
        );
    }

    #[test]
    fn stale_inspection_and_non_bijective_directives_are_rejected_before_observation() {
        let command = Arc::new(FakeCommandBoundary::inspections(Vec::new()));
        let fixture = fixture(CleanupStageV1::WriterRevoked, command);
        let mut stale = abandon_request(&fixture.manager);
        stale.inspections[0].record.snapshot_id = "substituted".to_owned();
        assert!(matches!(
            fixture.manager.recover_inspections(stale),
            Err(WorkspaceRecoveryError::StaleInspectionSet)
        ));

        let mut missing = abandon_request(&fixture.manager);
        missing.directives.clear();
        assert!(matches!(
            fixture.manager.recover_inspections(missing),
            Err(WorkspaceRecoveryError::DirectiveSetMismatch)
        ));
    }

    #[test]
    fn recovery_lock_spans_the_exact_inspection_action_transaction() {
        let command = Arc::new(FakeCommandBoundary::inspections(Vec::new()));
        let fixture = fixture(CleanupStageV1::WriterRevoked, command);
        let request = abandon_request(&fixture.manager);
        let lock = fixture
            .manager
            .journal
            .try_lock_recovery()
            .expect("simulated competing recovery owns lock");
        assert!(matches!(
            fixture.manager.recover_inspections(request),
            Err(WorkspaceRecoveryError::RecoveryAlreadyRunning)
        ));
        drop(lock);
        assert_eq!(
            fixture
                .manager
                .recovery_inspections()
                .expect("journal unchanged")
                .len(),
            1
        );
    }

    #[test]
    fn writer_revoked_stage_never_claims_an_unexpected_image_as_owned() {
        let command = Arc::new(FakeCommandBoundary::inspections(vec![output(empty_info())]));
        let fixture = fixture(CleanupStageV1::WriterRevoked, command);
        std::fs::write(&fixture.image_path, b"foreign replacement").expect("foreign image");
        let report = fixture
            .manager
            .recover_inspections(abandon_request(&fixture.manager))
            .expect("unexpected image is typed block");
        assert!(matches!(
            report.entries[0].outcome,
            RecoveryEntryOutcomeV1::Blocked(RecoveryBlockedReasonV1::Topology(
                RecoveryTopologyBlockV1::JournalStageCannotOwnObservedImage
            ))
        ));
        assert!(fixture.image_path.exists());
        assert_eq!(
            fixture
                .manager
                .recovery_inspections()
                .expect("journal retained")
                .len(),
            1
        );
    }
}
