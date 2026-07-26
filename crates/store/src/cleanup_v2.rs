//! Fail-closed validation for the recursive material carried by a cleanup-v2
//! grant. This module deliberately does not issue, redeem, or admit cleanup
//! authority.

#![allow(
    dead_code,
    reason = "A2 validates future Store-owned cleanup material while A1 admission remains inert"
)]

use super::{
    StoreError, artifact_path_at, digest_matches_artifact, read_canonical_json_artifact,
    read_verified_artifact,
};
use birdcode_protocol::{
    ActorId, ArtifactRef, EventId, REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION,
    REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_INSPECTION_MEDIA_TYPE,
    REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_TOPOLOGY_INSPECTION_V2_MEDIA_TYPE,
    REPOSITORY_SNAPSHOT_CLEANUP_PROCESS_INSPECTION_MEDIA_TYPE,
    REPOSITORY_SNAPSHOT_CLEANUP_SAFETY_EVIDENCE_MEDIA_TYPE,
    REPOSITORY_SNAPSHOT_RECOVERY_V2_CONTRACT_VERSION, RepositoryFileIdentityV1,
    RepositorySnapshotCleanupEffectFenceObservationV1,
    RepositorySnapshotCleanupEffectObservationV1, RepositorySnapshotCleanupEffectScopeV2,
    RepositorySnapshotCleanupGrantedV1, RepositorySnapshotCleanupInitialInspectionDocumentV1,
    RepositorySnapshotCleanupInitialInspectionPhaseV2, RepositorySnapshotCleanupInspectOperationV2,
    RepositorySnapshotCleanupKindV1, RepositorySnapshotCleanupMountReaderObservationV1,
    RepositorySnapshotCleanupProcessIdentityV1,
    RepositorySnapshotCleanupProcessInspectionDocumentV1,
    RepositorySnapshotCleanupProcessInspectionSetV1,
    RepositorySnapshotCleanupSafetyEvidenceDocumentV1, RepositorySnapshotLeaseId,
    RepositorySnapshotLocalCleanupId, RepositorySnapshotRecoveryId,
    RepositorySnapshotRecoveryImageObservationV1, RepositorySnapshotRecoveryMountObservationV1,
    RepositorySnapshotRecoveryPathsV1, RepositorySnapshotRecoveryTopologyObservationV1, RunId,
    RuntimeClockReading, RuntimeInstanceId, SessionId, Sha256Digest,
    WORKSPACE_COMMAND_STDERR_MEDIA_TYPE, WORKSPACE_RECOVERY_HDIUTIL_INFO_MEDIA_TYPE, WorkspacePath,
};
use std::path::Path;

/// Store-owned candidate identity. In particular, `paths` and
/// `local_cleanup_id` are supplied by a future internal preparation step; the
/// validator never promotes the values embedded in an untrusted grant into
/// their own expected values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExpectedRepositorySnapshotCleanupSafetyCandidateV1 {
    pub session_id: SessionId,
    pub run_id: RunId,
    pub cleanup_grant_event_id: EventId,
    pub cleanup_grant_id: birdcode_protocol::RepositorySnapshotCleanupGrantId,
    pub cleanup_grant_generation: u64,
    pub recovery_id: RepositorySnapshotRecoveryId,
    pub local_cleanup_id: RepositorySnapshotLocalCleanupId,
    pub kind: RepositorySnapshotCleanupKindV1,
    pub snapshot_id: String,
    pub lease_id: RepositorySnapshotLeaseId,
    pub snapshot_lease_event_id: EventId,
    pub writer_revocation_event_id: EventId,
    pub paths: RepositorySnapshotRecoveryPathsV1,
    pub cleanup_actor_id: ActorId,
    pub cleanup_runtime_instance_id: RuntimeInstanceId,
    pub process_registry_generation: u64,
    pub effect_fence_generation: u64,
    pub inspected_processes: RepositorySnapshotCleanupProcessInspectionSetV1,
    pub topology_inspection_executable: WorkspacePath,
}

impl ExpectedRepositorySnapshotCleanupSafetyCandidateV1 {
    fn scope(&self) -> RepositorySnapshotCleanupEffectScopeV2 {
        RepositorySnapshotCleanupEffectScopeV2 {
            session_id: self.session_id,
            run_id: self.run_id,
            cleanup_grant_event_id: self.cleanup_grant_event_id,
            cleanup_grant_id: self.cleanup_grant_id,
            cleanup_grant_generation: self.cleanup_grant_generation,
            recovery_id: self.recovery_id,
            local_cleanup_id: self.local_cleanup_id,
            snapshot_id: self.snapshot_id.clone(),
            lease_id: self.lease_id,
            snapshot_lease_event_id: self.snapshot_lease_event_id,
            writer_revocation_event_id: self.writer_revocation_event_id,
            paths: self.paths.clone(),
        }
    }
}

fn reject() -> Result<(), StoreError> {
    Err(StoreError::InvalidStateEvent)
}

fn digest_and_artifact_match(digest: &Sha256Digest, artifact: &ArtifactRef) -> bool {
    digest_matches_artifact(digest, artifact)
}

fn verify_raw_artifact(
    artifact_root: &Path,
    artifact: &ArtifactRef,
    digest: &Sha256Digest,
    expected_media_type: &str,
) -> Result<(), StoreError> {
    if artifact.media_type != expected_media_type || !digest_and_artifact_match(digest, artifact) {
        return reject();
    }
    read_verified_artifact(
        &artifact_path_at(artifact_root, &artifact.sha256)?,
        artifact,
    )?;
    Ok(())
}

fn read_exact_canonical<T>(
    artifact_root: &Path,
    artifact: &ArtifactRef,
    digest: &Sha256Digest,
    expected_media_type: &str,
    inline: &T,
) -> Result<(), StoreError>
where
    T: serde::de::DeserializeOwned + serde::Serialize + Eq,
{
    if !digest_and_artifact_match(digest, artifact) {
        return reject();
    }
    let retained = read_canonical_json_artifact::<T>(artifact_root, artifact, expected_media_type)?;
    if &retained != inline {
        return reject();
    }
    Ok(())
}

fn flat_safety_scope_matches(
    document: &RepositorySnapshotCleanupSafetyEvidenceDocumentV1,
    expected: &ExpectedRepositorySnapshotCleanupSafetyCandidateV1,
) -> bool {
    document.session_id == expected.session_id
        && document.run_id == expected.run_id
        && document.cleanup_grant_event_id == expected.cleanup_grant_event_id
        && document.cleanup_grant_id == expected.cleanup_grant_id
        && document.cleanup_grant_generation == expected.cleanup_grant_generation
        && document.recovery_id == expected.recovery_id
        && document.local_cleanup_id == expected.local_cleanup_id
        && document.snapshot_id == expected.snapshot_id
        && document.lease_id == expected.lease_id
        && document.snapshot_lease_event_id == expected.snapshot_lease_event_id
        && document.writer_revocation_event_id == expected.writer_revocation_event_id
}

fn flat_process_scope_matches(
    document: &RepositorySnapshotCleanupProcessInspectionDocumentV1,
    expected: &ExpectedRepositorySnapshotCleanupSafetyCandidateV1,
) -> bool {
    document.session_id == expected.session_id
        && document.run_id == expected.run_id
        && document.cleanup_grant_event_id == expected.cleanup_grant_event_id
        && document.cleanup_grant_id == expected.cleanup_grant_id
        && document.cleanup_grant_generation == expected.cleanup_grant_generation
        && document.recovery_id == expected.recovery_id
        && document.local_cleanup_id == expected.local_cleanup_id
        && document.snapshot_id == expected.snapshot_id
        && document.lease_id == expected.lease_id
        && document.snapshot_lease_event_id == expected.snapshot_lease_event_id
        && document.mount_path == expected.paths.mount_path
}

fn flat_initial_scope_matches(
    document: &RepositorySnapshotCleanupInitialInspectionDocumentV1,
    expected: &ExpectedRepositorySnapshotCleanupSafetyCandidateV1,
) -> bool {
    document.session_id == expected.session_id
        && document.run_id == expected.run_id
        && document.cleanup_grant_event_id == expected.cleanup_grant_event_id
        && document.cleanup_grant_id == expected.cleanup_grant_id
        && document.cleanup_grant_generation == expected.cleanup_grant_generation
        && document.recovery_id == expected.recovery_id
        && document.local_cleanup_id == expected.local_cleanup_id
        && document.snapshot_id == expected.snapshot_id
        && document.lease_id == expected.lease_id
        && document.snapshot_lease_event_id == expected.snapshot_lease_event_id
        && document.writer_revocation_event_id == expected.writer_revocation_event_id
        && document.paths == expected.paths
}

fn process_key(process: &RepositorySnapshotCleanupProcessIdentityV1) -> (u32, i64, u32) {
    match process {
        RepositorySnapshotCleanupProcessIdentityV1::MacOs {
            process_id,
            start_time_seconds,
            start_time_microseconds,
        } => (*process_id, *start_time_seconds, *start_time_microseconds),
    }
}

fn valid_exact_process_set(processes: &RepositorySnapshotCleanupProcessInspectionSetV1) -> bool {
    let processes = processes.as_slice();
    processes.iter().all(|process| {
        let (process_id, seconds, microseconds) = process_key(process);
        process_id != 0 && seconds >= 0 && microseconds < 1_000_000
    }) && processes.windows(2).all(|pair| {
        let left = process_key(&pair[0]);
        let right = process_key(&pair[1]);
        left < right && left.0 != right.0
    })
}

fn valid_file_identity(identity: RepositoryFileIdentityV1) -> bool {
    let RepositoryFileIdentityV1::Unix(identity) = identity;
    identity.byte_len >= 0
        && (0..1_000_000_000).contains(&identity.modified_nanoseconds)
        && (0..1_000_000_000).contains(&identity.changed_nanoseconds)
}

fn valid_image_observation(image: &RepositorySnapshotRecoveryImageObservationV1) -> bool {
    match image {
        RepositorySnapshotRecoveryImageObservationV1::Missing => true,
        RepositorySnapshotRecoveryImageObservationV1::ExactRegularFile { identity, image } => {
            valid_file_identity(*identity)
                && image.byte_len > 0
                && u64::try_from(match identity {
                    RepositoryFileIdentityV1::Unix(identity) => identity.byte_len,
                }) == Ok(image.byte_len)
        }
    }
}

fn valid_mount_observation(mount: RepositorySnapshotRecoveryMountObservationV1) -> bool {
    match mount {
        RepositorySnapshotRecoveryMountObservationV1::Missing => true,
        RepositorySnapshotRecoveryMountObservationV1::ExactUnmountedDirectory { identity }
        | RepositorySnapshotRecoveryMountObservationV1::ExactReadOnlyMount { identity, .. } => {
            valid_file_identity(identity)
        }
    }
}

fn valid_initial_topology_matrix(
    topology: RepositorySnapshotRecoveryTopologyObservationV1,
    image: &RepositorySnapshotRecoveryImageObservationV1,
    mount: RepositorySnapshotRecoveryMountObservationV1,
) -> bool {
    valid_image_observation(image)
        && valid_mount_observation(mount)
        && match (topology, image, mount) {
            (
                RepositorySnapshotRecoveryTopologyObservationV1::NoExpectedImageOrMountAttached,
                RepositorySnapshotRecoveryImageObservationV1::Missing
                | RepositorySnapshotRecoveryImageObservationV1::ExactRegularFile { .. },
                RepositorySnapshotRecoveryMountObservationV1::Missing
                | RepositorySnapshotRecoveryMountObservationV1::ExactUnmountedDirectory { .. },
            ) => true,
            (
                RepositorySnapshotRecoveryTopologyObservationV1::ExactImageMounted {
                    leaf_device: topology_device,
                },
                RepositorySnapshotRecoveryImageObservationV1::ExactRegularFile { .. },
                RepositorySnapshotRecoveryMountObservationV1::ExactReadOnlyMount {
                    leaf_device: mount_device,
                    ..
                },
            ) => topology_device == mount_device,
            _ => false,
        }
}

fn clock_in_runtime(reading: &RuntimeClockReading, runtime: RuntimeInstanceId) -> bool {
    reading.runtime_instance_id == runtime && reading.monotonic_nanos != 0
}

fn ordered_clocks(
    earlier: &RuntimeClockReading,
    later: &RuntimeClockReading,
    runtime: RuntimeInstanceId,
) -> bool {
    clock_in_runtime(earlier, runtime)
        && clock_in_runtime(later, runtime)
        && earlier.monotonic_nanos <= later.monotonic_nanos
        && earlier.observed_at <= later.observed_at
}

fn grant_matches_expected_candidate(
    grant: &RepositorySnapshotCleanupGrantedV1,
    expected: &ExpectedRepositorySnapshotCleanupSafetyCandidateV1,
) -> bool {
    grant.session_id == expected.session_id
        && grant.run_id == expected.run_id
        && grant.cleanup_grant_event_id == expected.cleanup_grant_event_id
        && grant.cleanup_grant_id == expected.cleanup_grant_id
        && grant.cleanup_grant_generation == expected.cleanup_grant_generation
        && grant.recovery_id == expected.recovery_id
        && grant.local_cleanup_id == expected.local_cleanup_id
        && grant.kind == expected.kind
        && grant.snapshot_id == expected.snapshot_id
        && grant.lease_id == expected.lease_id
        && grant.snapshot_lease_event_id == expected.snapshot_lease_event_id
        && grant.writer_revocation_event_id == expected.writer_revocation_event_id
        && grant.cleanup_actor_id == expected.cleanup_actor_id
        && grant.cleanup_runtime_instance_id == expected.cleanup_runtime_instance_id
}

/// Validates every recursively retained artifact and every duplicated cleanup
/// scope field. Success is evidence validation only; callers must not treat it
/// as cleanup authority.
#[allow(
    clippy::too_many_lines,
    reason = "the recursive safety gate keeps every nested authority binding visibly fail-closed"
)]
pub(super) fn validate_repository_snapshot_cleanup_safety_material(
    artifact_root: &Path,
    grant: &RepositorySnapshotCleanupGrantedV1,
    expected: &ExpectedRepositorySnapshotCleanupSafetyCandidateV1,
) -> Result<(), StoreError> {
    if grant.schema_version != REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION
        || expected.cleanup_grant_generation == 0
        || expected.process_registry_generation == 0
        || expected.effect_fence_generation == 0
        || !grant_matches_expected_candidate(grant, expected)
        || !valid_exact_process_set(&expected.inspected_processes)
    {
        return reject();
    }

    let retained_safety = &grant.safety_evidence;
    read_exact_canonical(
        artifact_root,
        &retained_safety.evidence_artifact,
        &retained_safety.evidence_digest,
        REPOSITORY_SNAPSHOT_CLEANUP_SAFETY_EVIDENCE_MEDIA_TYPE,
        &retained_safety.evidence,
    )?;
    let safety = &retained_safety.evidence;
    if safety.schema_version != REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION
        || !flat_safety_scope_matches(safety, expected)
    {
        return reject();
    }

    let retained_process = &safety.process_quiescence;
    read_exact_canonical(
        artifact_root,
        &retained_process.inspection_artifact,
        &retained_process.inspection_digest,
        REPOSITORY_SNAPSHOT_CLEANUP_PROCESS_INSPECTION_MEDIA_TYPE,
        &retained_process.inspection,
    )?;
    let process = &retained_process.inspection;
    if process.schema_version != REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION
        || !flat_process_scope_matches(process, expected)
        || process.guardian_actor_id != expected.cleanup_actor_id
        || process.guardian_runtime_instance_id != expected.cleanup_runtime_instance_id
        || process.process_registry_generation != expected.process_registry_generation
        || process.effect_fence_generation != expected.effect_fence_generation
        || process.effect_fence
            != RepositorySnapshotCleanupEffectFenceObservationV1::ArmedRejectingNewMountReadersAndSnapshotEffects
        || process.inspected_processes != expected.inspected_processes
        || process.mount_readers
            != RepositorySnapshotCleanupMountReaderObservationV1::NoGuardianOwnedProcessReferencesMount
        || process.snapshot_effects
            != RepositorySnapshotCleanupEffectObservationV1::NoGuardianOwnedSnapshotEffectInFlight
        || !valid_exact_process_set(&process.inspected_processes)
    {
        return reject();
    }

    let retained_initial = &safety.initial_inspection;
    read_exact_canonical(
        artifact_root,
        &retained_initial.inspection_artifact,
        &retained_initial.inspection_digest,
        REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_INSPECTION_MEDIA_TYPE,
        &retained_initial.inspection,
    )?;
    let initial = &retained_initial.inspection;
    if initial.schema_version != REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION
        || !flat_initial_scope_matches(initial, expected)
    {
        return reject();
    }

    let retained_topology = &initial.topology_inspection;
    read_exact_canonical(
        artifact_root,
        &retained_topology.inspection_artifact,
        &retained_topology.inspection_digest,
        REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_TOPOLOGY_INSPECTION_V2_MEDIA_TYPE,
        &retained_topology.inspection,
    )?;
    let topology = &retained_topology.inspection;
    if topology.schema_version != REPOSITORY_SNAPSHOT_RECOVERY_V2_CONTRACT_VERSION
        || topology.scope != expected.scope()
        || topology.phase != RepositorySnapshotCleanupInitialInspectionPhaseV2::PreGrantInitial
        || topology.operation
            != RepositorySnapshotCleanupInspectOperationV2::InspectDiskImageTopology
        || topology.executable != expected.topology_inspection_executable
        || topology.exit_code != 0
        || initial.topology != topology.topology
        || initial.image != topology.image
        || initial.mount != topology.mount
        || !valid_initial_topology_matrix(topology.topology, &topology.image, topology.mount)
    {
        return reject();
    }
    verify_raw_artifact(
        artifact_root,
        &topology.stdout_artifact,
        &topology.stdout_digest,
        WORKSPACE_RECOVERY_HDIUTIL_INFO_MEDIA_TYPE,
    )?;
    verify_raw_artifact(
        artifact_root,
        &topology.stderr_artifact,
        &topology.stderr_digest,
        WORKSPACE_COMMAND_STDERR_MEDIA_TYPE,
    )?;

    let runtime = expected.cleanup_runtime_instance_id;
    if !ordered_clocks(&process.observed_at, &topology.completed_at, runtime)
        || !ordered_clocks(&topology.completed_at, &initial.observed_at, runtime)
        || !ordered_clocks(&initial.observed_at, &safety.observed_at, runtime)
        || !ordered_clocks(&safety.observed_at, &grant.granted_at, runtime)
        || grant.grant_expires_at <= grant.granted_at.observed_at
    {
        return reject();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::put_artifact_at;
    use birdcode_protocol::{
        CancellationRequestId, RepositoryExternalImageIdentityV1, RepositoryFileIdentityV1,
        RepositorySnapshotCleanupBoundaryV1, RepositorySnapshotCleanupEffectFenceObservationV1,
        RepositorySnapshotCleanupEffectObservationV1, RepositorySnapshotCleanupGrantId,
        RepositorySnapshotCleanupInitialInspectionPhaseV2,
        RepositorySnapshotCleanupInitialTopologyInspectionDocumentV2,
        RepositorySnapshotCleanupInspectOperationV2,
        RepositorySnapshotCleanupMountReaderObservationV1, RepositorySnapshotImageFormatV1,
        RepositorySnapshotMacOsDeviceV1, RepositorySnapshotRetainedCleanupInitialInspectionV1,
        RepositorySnapshotRetainedCleanupInitialTopologyInspectionV2,
        RepositorySnapshotRetainedCleanupProcessInspectionV1,
        RepositorySnapshotRetainedCleanupSafetyEvidenceV1, RepositoryUnixFileIdentityV1,
        RunClaimId,
    };
    use chrono::{DateTime, Duration, Utc};
    use serde::Serialize;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct Fixture {
        _directory: TempDir,
        artifact_root: PathBuf,
        expected: ExpectedRepositorySnapshotCleanupSafetyCandidateV1,
        grant: RepositorySnapshotCleanupGrantedV1,
    }

    fn fixed_time(second: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-22T12:00:00Z")
            .expect("fixed test clock parses")
            .with_timezone(&Utc)
            + Duration::seconds(second)
    }

    fn clock(runtime: RuntimeInstanceId, second: i64) -> RuntimeClockReading {
        RuntimeClockReading {
            runtime_instance_id: runtime,
            monotonic_nanos: u64::try_from(second).expect("positive fixture second") * 1_000,
            observed_at: fixed_time(second),
        }
    }

    fn digest_for(artifact: &ArtifactRef) -> Sha256Digest {
        Sha256Digest::parse(artifact.sha256.clone()).expect("Store creates a canonical digest")
    }

    fn put_json<T: Serialize>(root: &Path, value: &T, media_type: &str) -> ArtifactRef {
        put_artifact_at(
            root,
            &serde_json::to_vec(value).expect("fixture JSON encodes"),
            media_type.to_owned(),
        )
        .expect("fixture artifact persists")
    }

    fn identity(inode: u64) -> RepositoryFileIdentityV1 {
        RepositoryFileIdentityV1::Unix(RepositoryUnixFileIdentityV1 {
            device: 7,
            inode,
            byte_len: 32,
            modified_seconds: 1,
            modified_nanoseconds: 2,
            changed_seconds: 3,
            changed_nanoseconds: 4,
        })
    }

    impl Fixture {
        #[allow(
            clippy::too_many_lines,
            reason = "one canonical fixture spells out the complete recursive safety contract"
        )]
        fn canonical() -> Self {
            let directory = TempDir::new().expect("temporary directory is created");
            let artifact_root = directory.path().join("artifacts");
            let cleanup_runtime_instance_id = RuntimeInstanceId::new();
            let cleanup_actor_id = ActorId::new();
            let processes = RepositorySnapshotCleanupProcessInspectionSetV1::try_from_vec(vec![
                RepositorySnapshotCleanupProcessIdentityV1::MacOs {
                    process_id: 41,
                    start_time_seconds: 1_721_649_600,
                    start_time_microseconds: 12,
                },
                RepositorySnapshotCleanupProcessIdentityV1::MacOs {
                    process_id: 42,
                    start_time_seconds: 1_721_649_601,
                    start_time_microseconds: 13,
                },
            ])
            .expect("fixture process set is bounded");
            let expected = ExpectedRepositorySnapshotCleanupSafetyCandidateV1 {
                session_id: SessionId::new(),
                run_id: RunId::new(),
                cleanup_grant_event_id: EventId::new(),
                cleanup_grant_id: RepositorySnapshotCleanupGrantId::new(),
                cleanup_grant_generation: 1,
                recovery_id: RepositorySnapshotRecoveryId::new(),
                local_cleanup_id: RepositorySnapshotLocalCleanupId::new(),
                kind: RepositorySnapshotCleanupKindV1::CaptureAbandonment,
                snapshot_id: "snapshot-cleanup-a2".to_owned(),
                lease_id: RepositorySnapshotLeaseId::new(),
                snapshot_lease_event_id: EventId::new(),
                writer_revocation_event_id: EventId::new(),
                paths: RepositorySnapshotRecoveryPathsV1 {
                    source_path: PathBuf::from("/repo").into(),
                    image_path: PathBuf::from("/state/images/snapshot-cleanup-a2.dmg").into(),
                    mount_path: PathBuf::from("/state/mounts/snapshot-cleanup-a2").into(),
                },
                cleanup_actor_id,
                cleanup_runtime_instance_id,
                process_registry_generation: 7,
                effect_fence_generation: 9,
                inspected_processes: processes.clone(),
                topology_inspection_executable: PathBuf::from("/usr/bin/hdiutil").into(),
            };

            let stdout_artifact = put_artifact_at(
                &artifact_root,
                b"bplist00-cleanup-topology",
                WORKSPACE_RECOVERY_HDIUTIL_INFO_MEDIA_TYPE.to_owned(),
            )
            .expect("stdout persists");
            let stderr_artifact = put_artifact_at(
                &artifact_root,
                b"",
                WORKSPACE_COMMAND_STDERR_MEDIA_TYPE.to_owned(),
            )
            .expect("stderr persists");
            let topology_document = RepositorySnapshotCleanupInitialTopologyInspectionDocumentV2 {
                schema_version: REPOSITORY_SNAPSHOT_RECOVERY_V2_CONTRACT_VERSION,
                scope: expected.scope(),
                phase: RepositorySnapshotCleanupInitialInspectionPhaseV2::PreGrantInitial,
                operation: RepositorySnapshotCleanupInspectOperationV2::InspectDiskImageTopology,
                executable: expected.topology_inspection_executable.clone(),
                exit_code: 0,
                stdout_digest: digest_for(&stdout_artifact),
                stdout_artifact,
                stderr_digest: digest_for(&stderr_artifact),
                stderr_artifact,
                topology:
                    RepositorySnapshotRecoveryTopologyObservationV1::NoExpectedImageOrMountAttached,
                image: RepositorySnapshotRecoveryImageObservationV1::ExactRegularFile {
                    identity: identity(11),
                    image: RepositoryExternalImageIdentityV1 {
                        format: RepositorySnapshotImageFormatV1::Udro,
                        byte_len: 32,
                        sha256: Sha256Digest::parse("a".repeat(Sha256Digest::HEX_LENGTH))
                            .expect("fixture image digest is canonical"),
                    },
                },
                mount: RepositorySnapshotRecoveryMountObservationV1::ExactUnmountedDirectory {
                    identity: identity(12),
                },
                completed_at: clock(cleanup_runtime_instance_id, 2),
            };
            let topology_artifact = put_json(
                &artifact_root,
                &topology_document,
                REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_TOPOLOGY_INSPECTION_V2_MEDIA_TYPE,
            );
            let topology_inspection =
                RepositorySnapshotRetainedCleanupInitialTopologyInspectionV2 {
                    inspection_digest: digest_for(&topology_artifact),
                    inspection_artifact: topology_artifact,
                    inspection: topology_document.clone(),
                };

            let process_document = RepositorySnapshotCleanupProcessInspectionDocumentV1 {
                schema_version: REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION,
                session_id: expected.session_id,
                run_id: expected.run_id,
                cleanup_grant_event_id: expected.cleanup_grant_event_id,
                cleanup_grant_id: expected.cleanup_grant_id,
                cleanup_grant_generation: expected.cleanup_grant_generation,
                recovery_id: expected.recovery_id,
                local_cleanup_id: expected.local_cleanup_id,
                snapshot_id: expected.snapshot_id.clone(),
                lease_id: expected.lease_id,
                snapshot_lease_event_id: expected.snapshot_lease_event_id,
                mount_path: expected.paths.mount_path.clone(),
                guardian_actor_id: cleanup_actor_id,
                guardian_runtime_instance_id: cleanup_runtime_instance_id,
                process_registry_generation: expected.process_registry_generation,
                effect_fence_generation: expected.effect_fence_generation,
                effect_fence: RepositorySnapshotCleanupEffectFenceObservationV1::ArmedRejectingNewMountReadersAndSnapshotEffects,
                inspected_processes: processes,
                mount_readers: RepositorySnapshotCleanupMountReaderObservationV1::NoGuardianOwnedProcessReferencesMount,
                snapshot_effects: RepositorySnapshotCleanupEffectObservationV1::NoGuardianOwnedSnapshotEffectInFlight,
                observed_at: clock(cleanup_runtime_instance_id, 1),
            };
            let process_artifact = put_json(
                &artifact_root,
                &process_document,
                REPOSITORY_SNAPSHOT_CLEANUP_PROCESS_INSPECTION_MEDIA_TYPE,
            );
            let process_quiescence = RepositorySnapshotRetainedCleanupProcessInspectionV1 {
                inspection_digest: digest_for(&process_artifact),
                inspection_artifact: process_artifact,
                inspection: process_document,
            };

            let initial_document = RepositorySnapshotCleanupInitialInspectionDocumentV1 {
                schema_version: REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION,
                session_id: expected.session_id,
                run_id: expected.run_id,
                cleanup_grant_event_id: expected.cleanup_grant_event_id,
                cleanup_grant_id: expected.cleanup_grant_id,
                cleanup_grant_generation: expected.cleanup_grant_generation,
                recovery_id: expected.recovery_id,
                local_cleanup_id: expected.local_cleanup_id,
                snapshot_id: expected.snapshot_id.clone(),
                lease_id: expected.lease_id,
                snapshot_lease_event_id: expected.snapshot_lease_event_id,
                writer_revocation_event_id: expected.writer_revocation_event_id,
                paths: expected.paths.clone(),
                topology: topology_document.topology,
                image: topology_document.image.clone(),
                mount: topology_document.mount,
                topology_inspection,
                observed_at: clock(cleanup_runtime_instance_id, 3),
            };
            let initial_artifact = put_json(
                &artifact_root,
                &initial_document,
                REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_INSPECTION_MEDIA_TYPE,
            );
            let initial_inspection = RepositorySnapshotRetainedCleanupInitialInspectionV1 {
                inspection_digest: digest_for(&initial_artifact),
                inspection_artifact: initial_artifact,
                inspection: initial_document,
            };

            let safety_document = RepositorySnapshotCleanupSafetyEvidenceDocumentV1 {
                schema_version: REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION,
                session_id: expected.session_id,
                run_id: expected.run_id,
                cleanup_grant_event_id: expected.cleanup_grant_event_id,
                cleanup_grant_id: expected.cleanup_grant_id,
                cleanup_grant_generation: expected.cleanup_grant_generation,
                recovery_id: expected.recovery_id,
                local_cleanup_id: expected.local_cleanup_id,
                snapshot_id: expected.snapshot_id.clone(),
                lease_id: expected.lease_id,
                snapshot_lease_event_id: expected.snapshot_lease_event_id,
                writer_revocation_event_id: expected.writer_revocation_event_id,
                process_quiescence,
                initial_inspection,
                observed_at: clock(cleanup_runtime_instance_id, 4),
            };
            let safety_artifact = put_json(
                &artifact_root,
                &safety_document,
                REPOSITORY_SNAPSHOT_CLEANUP_SAFETY_EVIDENCE_MEDIA_TYPE,
            );
            let safety_evidence = RepositorySnapshotRetainedCleanupSafetyEvidenceV1 {
                evidence_digest: digest_for(&safety_artifact),
                evidence_artifact: safety_artifact,
                evidence: safety_document,
            };

            let grant = RepositorySnapshotCleanupGrantedV1 {
                schema_version: REPOSITORY_SNAPSHOT_CLEANUP_CONTRACT_VERSION,
                session_id: expected.session_id,
                run_id: expected.run_id,
                cleanup_grant_event_id: expected.cleanup_grant_event_id,
                cleanup_grant_id: expected.cleanup_grant_id,
                cleanup_grant_generation: expected.cleanup_grant_generation,
                recovery_id: expected.recovery_id,
                local_cleanup_id: expected.local_cleanup_id,
                closure_event_id: EventId::new(),
                workspace_finalized_event_id: EventId::new(),
                kind: expected.kind,
                boundary: RepositorySnapshotCleanupBoundaryV1::CancellationRequested {
                    cancellation_request_event_id: EventId::new(),
                    cancellation_request_id: CancellationRequestId::new(),
                    cancellation_generation: 1,
                },
                lifecycle_tail_event_id: expected.writer_revocation_event_id,
                snapshot_id: expected.snapshot_id.clone(),
                lease_id: expected.lease_id,
                snapshot_lease_event_id: expected.snapshot_lease_event_id,
                writer_revocation_event_id: expected.writer_revocation_event_id,
                lifecycle_owner_actor_id: ActorId::new(),
                lifecycle_owner_runtime_instance_id: RuntimeInstanceId::new(),
                source_claim_event_id: EventId::new(),
                source_claim_id: RunClaimId::new(),
                source_claim_generation: 1,
                source_claim_actor_id: ActorId::new(),
                source_claim_runtime_instance_id: RuntimeInstanceId::new(),
                cancellation_generation: 1,
                cleanup_actor_id,
                cleanup_runtime_instance_id,
                safety_evidence,
                granted_at: clock(cleanup_runtime_instance_id, 5),
                grant_expires_at: fixed_time(60),
            };
            Self {
                _directory: directory,
                artifact_root,
                expected,
                grant,
            }
        }

        fn recanonicalize(&mut self) {
            let safety = &mut self.grant.safety_evidence.evidence;
            let topology = &mut safety.initial_inspection.inspection.topology_inspection;
            let artifact = put_json(
                &self.artifact_root,
                &topology.inspection,
                REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_TOPOLOGY_INSPECTION_V2_MEDIA_TYPE,
            );
            topology.inspection_digest = digest_for(&artifact);
            topology.inspection_artifact = artifact;

            let initial = &mut safety.initial_inspection;
            let artifact = put_json(
                &self.artifact_root,
                &initial.inspection,
                REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_INSPECTION_MEDIA_TYPE,
            );
            initial.inspection_digest = digest_for(&artifact);
            initial.inspection_artifact = artifact;

            let process = &mut safety.process_quiescence;
            let artifact = put_json(
                &self.artifact_root,
                &process.inspection,
                REPOSITORY_SNAPSHOT_CLEANUP_PROCESS_INSPECTION_MEDIA_TYPE,
            );
            process.inspection_digest = digest_for(&artifact);
            process.inspection_artifact = artifact;

            let artifact = put_json(
                &self.artifact_root,
                safety,
                REPOSITORY_SNAPSHOT_CLEANUP_SAFETY_EVIDENCE_MEDIA_TYPE,
            );
            self.grant.safety_evidence.evidence_digest = digest_for(&artifact);
            self.grant.safety_evidence.evidence_artifact = artifact;
        }

        fn recanonicalize_safety_only(&mut self) {
            let artifact = put_json(
                &self.artifact_root,
                &self.grant.safety_evidence.evidence,
                REPOSITORY_SNAPSHOT_CLEANUP_SAFETY_EVIDENCE_MEDIA_TYPE,
            );
            self.grant.safety_evidence.evidence_digest = digest_for(&artifact);
            self.grant.safety_evidence.evidence_artifact = artifact;
        }

        fn recanonicalize_initial_and_safety_only(&mut self) {
            let initial = &mut self.grant.safety_evidence.evidence.initial_inspection;
            let artifact = put_json(
                &self.artifact_root,
                &initial.inspection,
                REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_INSPECTION_MEDIA_TYPE,
            );
            initial.inspection_digest = digest_for(&artifact);
            initial.inspection_artifact = artifact;
            self.recanonicalize_safety_only();
        }

        fn validate(&self) -> Result<(), StoreError> {
            validate_repository_snapshot_cleanup_safety_material(
                &self.artifact_root,
                &self.grant,
                &self.expected,
            )
        }
    }

    #[test]
    fn canonical_recursive_cleanup_safety_material_is_accepted_as_evidence_only() {
        Fixture::canonical()
            .validate()
            .expect("canonical recursively bound material should validate");
    }

    #[test]
    fn candidate_paths_cannot_be_self_authorized_by_canonical_inline_material() {
        let mut fixture = Fixture::canonical();
        fixture.expected.paths.image_path = PathBuf::from("/different/expected.dmg").into();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn canonical_scope_substitution_is_rejected_after_all_artifacts_are_rehashed() {
        let mut fixture = Fixture::canonical();
        fixture
            .grant
            .safety_evidence
            .evidence
            .initial_inspection
            .inspection
            .topology_inspection
            .inspection
            .scope
            .local_cleanup_id = RepositorySnapshotLocalCleanupId::new();
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn canonical_process_set_substitution_is_rejected_after_rehash() {
        let mut fixture = Fixture::canonical();
        fixture
            .grant
            .safety_evidence
            .evidence
            .process_quiescence
            .inspection
            .inspected_processes =
            RepositorySnapshotCleanupProcessInspectionSetV1::try_from_vec(vec![
                RepositorySnapshotCleanupProcessIdentityV1::MacOs {
                    process_id: 99,
                    start_time_seconds: 1_721_649_699,
                    start_time_microseconds: 99,
                },
            ])
            .expect("mutated set is protocol-bounded");
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn duplicate_process_identity_is_rejected_even_when_expected_and_canonical() {
        let mut fixture = Fixture::canonical();
        let process = RepositorySnapshotCleanupProcessIdentityV1::MacOs {
            process_id: 41,
            start_time_seconds: 1_721_649_600,
            start_time_microseconds: 12,
        };
        let duplicate = RepositorySnapshotCleanupProcessInspectionSetV1::try_from_vec(vec![
            process.clone(),
            process,
        ])
        .expect("duplicates remain within the wire bound");
        fixture.expected.inspected_processes = duplicate.clone();
        fixture
            .grant
            .safety_evidence
            .evidence
            .process_quiescence
            .inspection
            .inspected_processes = duplicate;
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn one_pid_cannot_claim_two_start_times_in_one_exact_registry_snapshot() {
        let mut fixture = Fixture::canonical();
        let ambiguous = RepositorySnapshotCleanupProcessInspectionSetV1::try_from_vec(vec![
            RepositorySnapshotCleanupProcessIdentityV1::MacOs {
                process_id: 41,
                start_time_seconds: 1_721_649_600,
                start_time_microseconds: 12,
            },
            RepositorySnapshotCleanupProcessIdentityV1::MacOs {
                process_id: 41,
                start_time_seconds: 1_721_649_601,
                start_time_microseconds: 13,
            },
        ])
        .expect("PID-reuse ambiguity remains within the protocol wire bound");
        fixture.expected.inspected_processes = ambiguous.clone();
        fixture
            .grant
            .safety_evidence
            .evidence
            .process_quiescence
            .inspection
            .inspected_processes = ambiguous;
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn negative_process_start_time_is_rejected_even_when_expected_and_canonical() {
        let mut fixture = Fixture::canonical();
        let invalid = RepositorySnapshotCleanupProcessInspectionSetV1::try_from_vec(vec![
            RepositorySnapshotCleanupProcessIdentityV1::MacOs {
                process_id: 41,
                start_time_seconds: -1,
                start_time_microseconds: 12,
            },
        ])
        .expect("negative time remains within the protocol wire shape");
        fixture.expected.inspected_processes = invalid.clone();
        fixture
            .grant
            .safety_evidence
            .evidence
            .process_quiescence
            .inspection
            .inspected_processes = invalid;
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn unknown_closed_process_observations_are_rejected_as_canonical_json() {
        for field in ["effect_fence", "mount_readers", "snapshot_effects"] {
            let mut fixture = Fixture::canonical();
            let mut document = serde_json::to_value(
                &fixture
                    .grant
                    .safety_evidence
                    .evidence
                    .process_quiescence
                    .inspection,
            )
            .expect("typed process document encodes");
            document[field] = serde_json::json!("untrusted_observation");
            let bytes = serde_json::to_vec(&document).expect("mutated document encodes");
            let artifact = put_artifact_at(
                &fixture.artifact_root,
                &bytes,
                REPOSITORY_SNAPSHOT_CLEANUP_PROCESS_INSPECTION_MEDIA_TYPE.to_owned(),
            )
            .expect("mutated process artifact persists");
            let retained = &mut fixture.grant.safety_evidence.evidence.process_quiescence;
            retained.inspection_digest = digest_for(&artifact);
            retained.inspection_artifact = artifact;
            fixture.recanonicalize_safety_only();
            assert!(
                matches!(fixture.validate(), Err(StoreError::InvalidStateEvent)),
                "unknown {field} must fail closed"
            );
        }
    }

    #[test]
    fn unknown_closed_topology_phase_and_operation_are_rejected_as_canonical_json() {
        for field in ["phase", "operation"] {
            let mut fixture = Fixture::canonical();
            let mut document = serde_json::to_value(
                &fixture
                    .grant
                    .safety_evidence
                    .evidence
                    .initial_inspection
                    .inspection
                    .topology_inspection
                    .inspection,
            )
            .expect("typed topology document encodes");
            document[field] = serde_json::json!("untrusted_operation");
            let bytes = serde_json::to_vec(&document).expect("mutated document encodes");
            let artifact = put_artifact_at(
                &fixture.artifact_root,
                &bytes,
                REPOSITORY_SNAPSHOT_CLEANUP_INITIAL_TOPOLOGY_INSPECTION_V2_MEDIA_TYPE.to_owned(),
            )
            .expect("mutated topology artifact persists");
            let retained = &mut fixture
                .grant
                .safety_evidence
                .evidence
                .initial_inspection
                .inspection
                .topology_inspection;
            retained.inspection_digest = digest_for(&artifact);
            retained.inspection_artifact = artifact;
            fixture.recanonicalize_initial_and_safety_only();
            assert!(
                matches!(fixture.validate(), Err(StoreError::InvalidStateEvent)),
                "unknown topology {field} must fail closed"
            );
        }
    }

    #[test]
    fn impossible_mounted_topology_matrix_is_rejected_when_canonical() {
        let mut fixture = Fixture::canonical();
        let topology = &mut fixture
            .grant
            .safety_evidence
            .evidence
            .initial_inspection
            .inspection
            .topology_inspection
            .inspection;
        topology.topology = RepositorySnapshotRecoveryTopologyObservationV1::ExactImageMounted {
            leaf_device: RepositorySnapshotMacOsDeviceV1 {
                disk_number: 4,
                partition_number: Some(1),
            },
        };
        fixture
            .grant
            .safety_evidence
            .evidence
            .initial_inspection
            .inspection
            .topology = topology.topology;
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn contradictory_image_identity_length_is_rejected_when_canonical() {
        let mut fixture = Fixture::canonical();
        let initial = &mut fixture
            .grant
            .safety_evidence
            .evidence
            .initial_inspection
            .inspection;
        let topology = &mut initial.topology_inspection.inspection;
        let RepositorySnapshotRecoveryImageObservationV1::ExactRegularFile {
            identity: RepositoryFileIdentityV1::Unix(identity),
            ..
        } = &mut topology.image
        else {
            panic!("fixture image is an exact regular file");
        };
        identity.byte_len = 31;
        initial.image = topology.image.clone();
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn cross_runtime_clock_substitution_is_rejected_when_canonical() {
        let mut fixture = Fixture::canonical();
        fixture
            .grant
            .safety_evidence
            .evidence
            .initial_inspection
            .inspection
            .topology_inspection
            .inspection
            .completed_at
            .runtime_instance_id = RuntimeInstanceId::new();
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn stdout_artifact_and_digest_must_remain_one_exact_pair() {
        let mut fixture = Fixture::canonical();
        let substituted = put_artifact_at(
            &fixture.artifact_root,
            b"different valid plist bytes",
            WORKSPACE_RECOVERY_HDIUTIL_INFO_MEDIA_TYPE.to_owned(),
        )
        .expect("substitute artifact persists");
        fixture
            .grant
            .safety_evidence
            .evidence
            .initial_inspection
            .inspection
            .topology_inspection
            .inspection
            .stdout_artifact = substituted;
        fixture.recanonicalize();
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn arbitrary_content_addressed_plist_remains_a_workspace_bridge_gap_not_authority() {
        let mut fixture = Fixture::canonical();
        let substituted = put_artifact_at(
            &fixture.artifact_root,
            b"arbitrary bytes with the exact closed media type",
            WORKSPACE_RECOVERY_HDIUTIL_INFO_MEDIA_TYPE.to_owned(),
        )
        .expect("substitute artifact persists");
        let topology = &mut fixture
            .grant
            .safety_evidence
            .evidence
            .initial_inspection
            .inspection
            .topology_inspection
            .inspection;
        topology.stdout_digest = digest_for(&substituted);
        topology.stdout_artifact = substituted;
        fixture.recanonicalize();
        fixture
            .validate()
            .expect("A2 proves recursive byte provenance, not the deferred Workspace plist decode");
    }

    #[test]
    fn noncanonical_nested_artifact_bytes_are_rejected() {
        let mut fixture = Fixture::canonical();
        let document = fixture
            .grant
            .safety_evidence
            .evidence
            .process_quiescence
            .inspection
            .clone();
        let pretty = serde_json::to_vec_pretty(&document).expect("pretty JSON encodes");
        let artifact = put_artifact_at(
            &fixture.artifact_root,
            &pretty,
            REPOSITORY_SNAPSHOT_CLEANUP_PROCESS_INSPECTION_MEDIA_TYPE.to_owned(),
        )
        .expect("noncanonical artifact persists");
        let retained = &mut fixture.grant.safety_evidence.evidence.process_quiescence;
        retained.inspection_digest = digest_for(&artifact);
        retained.inspection_artifact = artifact;
        let safety = &fixture.grant.safety_evidence.evidence;
        let artifact = put_json(
            &fixture.artifact_root,
            safety,
            REPOSITORY_SNAPSHOT_CLEANUP_SAFETY_EVIDENCE_MEDIA_TYPE,
        );
        fixture.grant.safety_evidence.evidence_digest = digest_for(&artifact);
        fixture.grant.safety_evidence.evidence_artifact = artifact;
        assert!(matches!(
            fixture.validate(),
            Err(StoreError::InvalidStateEvent)
        ));
    }
}
