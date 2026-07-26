#![cfg(target_os = "macos")]

use birdcode_protocol::{
    ActorId, BackendKind, BackendSelection, CreateSessionRequest, EventEnvelope, EventId,
    EventPayload, InputItem, NewEvent, PlanAcceptanceContract, Provenance,
    RepositorySnapshotCaptureClaimAdoptionId, RepositorySnapshotLeaseId, Run, RunClaimId,
    RunClaimed, RunLimits, RunPurpose, RunSpec, RunState, RuntimeClockReading, RuntimeInstanceId,
    Session,
};
use birdcode_store::{
    ParallelReconClaimRefreshAuthority, ParallelReconClaimRefreshOutcome,
    ParallelReconSnapshotClaimHandoffOutcomeV1, ParallelReconSnapshotClaimHandoffV1, Store,
};
use birdcode_workspace::{
    CanonicalArtifactBoundary, CommandBoundary, CommandBoundaryError,
    CommittedSnapshotLeaseRecoveryV1, PreparedMacOsCommand, PreparedMacOsRecoveryInspection,
    RawCommandOutput, RecoveryDirectiveAssignmentV1, RecoveryEntryOutcomeV1,
    SnapshotRecoveryDirectiveV1, SnapshotReleaseRequestV1, SnapshotRequestV1, SystemClock,
    SystemCommandBoundary, WorkspaceManager, WorkspaceManagerConfig, WorkspaceRecoveryRequestV1,
};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

struct CleanupGuard {
    image_path: PathBuf,
    mount_path: PathBuf,
}

#[derive(Default)]
struct RecordingSystemCommandBoundary {
    outputs: Mutex<Vec<RawCommandOutput>>,
}

impl CommandBoundary for RecordingSystemCommandBoundary {
    fn run(
        &self,
        command: &PreparedMacOsCommand,
    ) -> Result<RawCommandOutput, CommandBoundaryError> {
        let output = SystemCommandBoundary.run(command)?;
        self.outputs
            .lock()
            .expect("recording boundary lock")
            .push(output.clone());
        Ok(output)
    }

    fn inspect_recovery(
        &self,
        command: &PreparedMacOsRecoveryInspection,
    ) -> Result<RawCommandOutput, CommandBoundaryError> {
        let output = SystemCommandBoundary.inspect_recovery(command)?;
        self.outputs
            .lock()
            .expect("recording boundary lock")
            .push(output.clone());
        Ok(output)
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.mount_path.exists() {
            let _ = Command::new("/usr/bin/hdiutil")
                .args(["detach", "-force"])
                .arg(&self.mount_path)
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LANG", "C")
                .status();
        }
        let _ = std::fs::remove_file(&self.image_path);
        let _ = std::fs::remove_dir(&self.mount_path);
    }
}

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

struct SmokeClaim {
    handoff: ParallelReconSnapshotClaimHandoffV1,
    event: EventEnvelope,
}

#[allow(
    clippy::too_many_lines,
    reason = "the smoke fixture persists one complete Store-issued claim history"
)]
fn store_issued_claim(workspace_root: &Path) -> SmokeClaim {
    let directory = tempfile::tempdir().expect("Store fixture directory");
    let mut store = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("Store fixture opens");
    let actor_id = ActorId::new();
    let runtime_instance_id = RuntimeInstanceId::new();
    let provenance = || Provenance {
        producer: "birdcode-workspace-macos-smoke".to_owned(),
        backend: None,
        raw_artifact: None,
    };
    let session = Session::new(CreateSessionRequest {
        workspace_root: workspace_root.to_path_buf().into(),
        title: Some("macOS workspace smoke".to_owned()),
    });
    let session_created = store
        .create_session(
            &session,
            NewEvent {
                session_id: session.id,
                run_id: None,
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::SessionCreated {
                    session: session.clone(),
                },
            },
        )
        .expect("Store session persists");
    let run = Run::new(RunSpec {
        session_id: session.id,
        purpose: RunPurpose::ParallelRepositoryReconnaissanceV1,
        plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
        backend: BackendSelection {
            backend_id: "workspace-smoke".to_owned(),
            kind: BackendKind::Model,
            model: Some("fixture".to_owned()),
            reasoning_effort: None,
        },
        input: vec![InputItem::Text {
            text: "exercise the real macOS snapshot adapter".to_owned(),
        }],
        limits: RunLimits {
            max_output_tokens: Some(1_024),
            max_wall_time_seconds: Some(600),
            max_subagents: 2,
        },
    });
    let run_created = store
        .create_run(
            &run,
            NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(session_created.id),
                provenance: provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            },
        )
        .expect("Store run persists");
    let now = Utc::now();
    let claim = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(run_created.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id,
                claim_generation: 1,
                cancellation_generation: 0,
                lease_expires_at: now + chrono::Duration::minutes(30),
            }),
        })
        .expect("Store claim persists");
    store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(claim.id),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        })
        .expect("Store run starts");
    let outcome = store
        .refresh_parallel_recon_claim(
            run.id,
            ParallelReconClaimRefreshAuthority {
                actor_id,
                runtime_instance_id,
                renewal_claim_id: RunClaimId::new(),
                snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
                child_adoption_ids: [
                    birdcode_protocol::ChildClaimAdoptionId::new(),
                    birdcode_protocol::ChildClaimAdoptionId::new(),
                ],
                refreshed_at: RuntimeClockReading {
                    runtime_instance_id,
                    monotonic_nanos: 1,
                    observed_at: now,
                },
                fresh_through: now + chrono::Duration::minutes(1),
                renewed_lease_expires_at: now + chrono::Duration::minutes(45),
            },
        )
        .expect("Store resolves fresh snapshot authority");
    let ParallelReconClaimRefreshOutcome::Fresh {
        claim,
        snapshot_claim: ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(handoff),
        ..
    } = outcome
    else {
        panic!("fresh Store fixture must issue pre-capture authority")
    };
    SmokeClaim {
        handoff,
        event: claim.event,
    }
}

fn committed(
    claim: &EventEnvelope,
    event_id: EventId,
    sequence: u64,
    causal_parent: EventId,
    raw_artifact: birdcode_protocol::ArtifactRef,
    payload: EventPayload,
) -> EventEnvelope {
    EventEnvelope {
        id: event_id,
        sequence,
        session_id: claim.session_id,
        run_id: claim.run_id,
        actor_id: claim.actor_id,
        causal_parent: Some(causal_parent),
        occurred_at: Utc::now(),
        provenance: Provenance {
            producer: "birdcode-workspace-macos-smoke".to_owned(),
            backend: None,
            raw_artifact: Some(raw_artifact),
        },
        payload,
    }
}

#[test]
#[ignore = "executes the real macOS hdiutil create/attach/detach lifecycle"]
#[allow(
    clippy::too_many_lines,
    reason = "the smoke intentionally exercises the complete one-shot lifecycle in sequence"
)]
fn real_udro_snapshot_is_read_only_content_exact_and_released() {
    assert_eq!(
        std::env::var("BIRDCODE_RUN_MACOS_HDIUTIL_SMOKE").as_deref(),
        Ok("1"),
        "set BIRDCODE_RUN_MACOS_HDIUTIL_SMOKE=1 for the explicit real-mount smoke"
    );
    let source = tempfile::tempdir().expect("source tempdir");
    let state = tempfile::tempdir().expect("state tempdir");
    std::fs::create_dir(source.path().join("src")).expect("source directory");
    std::fs::write(
        source.path().join("src").join("kod-日本語.rs"),
        b"fn main() { println!(\"fly\"); }\n",
    )
    .expect("source fixture");
    std::os::unix::fs::symlink(
        Path::new("src").join("kod-日本語.rs"),
        source.path().join("entry-link"),
    )
    .expect("source symlink");

    let SmokeClaim {
        handoff,
        event: claim_event,
    } = store_issued_claim(source.path());
    let request = SnapshotRequestV1 {
        writer_revocation_event_id: EventId::from_uuid(id(7)),
        snapshot_lease_event_id: EventId::from_uuid(id(8)),
        snapshot_lease_id: RepositorySnapshotLeaseId::from_uuid(id(9)),
        snapshot_id: "macos-smoke-snapshot".to_owned(),
        repository_root_id: "macos-smoke-root".to_owned(),
        workspace_writer_lease_id: "macos-smoke-writer".to_owned(),
    };
    let image_path = state
        .path()
        .join("images")
        .join(format!("{}.dmg", request.snapshot_lease_id));
    let mount_path = state
        .path()
        .join("mounts")
        .join(request.snapshot_lease_id.to_string());
    let cleanup = CleanupGuard {
        image_path,
        mount_path,
    };
    let commands = Arc::new(RecordingSystemCommandBoundary::default());
    let manager = WorkspaceManager::open_with_boundaries(
        WorkspaceManagerConfig::new(source.path(), state.path()),
        commands.clone(),
        Arc::new(CanonicalArtifactBoundary),
        Arc::new(SystemClock::new()),
    )
    .expect("workspace manager opens");
    let prepared = manager
        .prepare_snapshot(request.clone(), handoff)
        .expect("snapshot prepares");
    let writer = manager.revoke_writers(prepared).expect("writers revoke");
    let writer_event = committed(
        &claim_event,
        writer.event_id,
        claim_event.sequence + 1,
        claim_event.id,
        writer.evidence.artifact.clone(),
        EventPayload::RepositoryWriterLeaseRevoked(writer.payload.clone()),
    );
    let writer = manager
        .confirm_writer_revocation(writer, &writer_event)
        .expect("writer event confirms");
    let captured = manager
        .execute_capture(manager.prepare_capture(writer).expect("capture prepares"))
        .expect("UDRO image captures");
    assert!(captured.image.byte_len > 0);
    let lease =
        match manager.execute_attach(manager.prepare_attach(captured).expect("attach prepares")) {
            Ok(lease) => lease,
            Err(error) => {
                let outputs = commands.outputs.lock().expect("recorded outputs");
                let plist = outputs.last().map_or_else(String::new, |output| {
                    String::from_utf8_lossy(&output.stdout).into_owned()
                });
                panic!("image attach failed: {error:?}; raw plist:\n{plist}");
            }
        };
    assert_eq!(
        lease.mounted_content_manifest.digest,
        lease
            .lease_document
            .macos_read_only_mount
            .source_quiescence
            .source_manifest_after
    );
    assert_eq!(
        lease
            .lease_document
            .macos_read_only_mount
            .statfs_receipt
            .write_open_errno,
        30
    );
    let lease_event = committed(
        &claim_event,
        lease.event_id,
        claim_event.sequence + 2,
        claim_event.id,
        lease.lease.artifact.clone(),
        EventPayload::RepositorySnapshotLeaseIssued(lease.payload.clone()),
    );
    let active = manager
        .activate_snapshot_lease(
            manager
                .confirm_snapshot_lease(lease, &lease_event)
                .expect("lease event confirms"),
        )
        .expect("lease activates");
    let release_request = SnapshotReleaseRequestV1 {
        release_event_id: EventId::from_uuid(id(10)),
        causal_parent_event_id: request.snapshot_lease_event_id,
    };
    let release = manager
        .execute_release(
            manager
                .prepare_release(active, release_request)
                .expect("release prepares"),
        )
        .expect("snapshot detaches");
    let release_event = committed(
        &claim_event,
        release.event_id,
        claim_event.sequence + 3,
        request.snapshot_lease_event_id,
        release.release.artifact.clone(),
        EventPayload::RepositorySnapshotLeaseReleased(release.payload.clone()),
    );
    manager
        .confirm_release(release, &release_event)
        .expect("release event confirms and cleanup completes");
    assert!(
        manager
            .recovery_inspections()
            .expect("journal reads")
            .is_empty()
    );
    assert!(!cleanup.image_path.exists());
    assert!(!cleanup.mount_path.exists());
}

#[test]
#[ignore = "executes real hdiutil recovery inspection and detach"]
#[allow(
    clippy::too_many_lines,
    reason = "the smoke exercises both exact active reconstruction and abandoned-run cleanup"
)]
fn real_committed_lease_is_recovered_then_abandoned_without_repeating_create_or_attach() {
    assert_eq!(
        std::env::var("BIRDCODE_RUN_MACOS_HDIUTIL_SMOKE").as_deref(),
        Ok("1"),
        "set BIRDCODE_RUN_MACOS_HDIUTIL_SMOKE=1 for the explicit real-mount smoke"
    );
    let source = tempfile::tempdir().expect("source tempdir");
    let state = tempfile::tempdir().expect("state tempdir");
    std::fs::write(
        source.path().join("recovery-日本語.rs"),
        b"pub fn fly() {}\n",
    )
    .expect("source fixture");

    let SmokeClaim {
        handoff,
        event: claim_event,
    } = store_issued_claim(source.path());
    let request = SnapshotRequestV1 {
        writer_revocation_event_id: EventId::from_uuid(id(107)),
        snapshot_lease_event_id: EventId::from_uuid(id(108)),
        snapshot_lease_id: RepositorySnapshotLeaseId::from_uuid(id(109)),
        snapshot_id: "macos-recovery-smoke".to_owned(),
        repository_root_id: "macos-recovery-root".to_owned(),
        workspace_writer_lease_id: "macos-recovery-writer".to_owned(),
    };
    let image_path = state
        .path()
        .join("images")
        .join(format!("{}.dmg", request.snapshot_lease_id));
    let mount_path = state
        .path()
        .join("mounts")
        .join(request.snapshot_lease_id.to_string());
    let cleanup = CleanupGuard {
        image_path,
        mount_path,
    };
    let commands = Arc::new(RecordingSystemCommandBoundary::default());
    let manager = WorkspaceManager::open_with_boundaries(
        WorkspaceManagerConfig::new(source.path(), state.path()),
        commands.clone(),
        Arc::new(CanonicalArtifactBoundary),
        Arc::new(SystemClock::new()),
    )
    .expect("workspace manager opens");
    let prepared = manager
        .prepare_snapshot(request.clone(), handoff)
        .expect("snapshot prepares");
    let writer = manager.revoke_writers(prepared).expect("writers revoke");
    let writer_event = committed(
        &claim_event,
        writer.event_id,
        claim_event.sequence + 1,
        claim_event.id,
        writer.evidence.artifact.clone(),
        EventPayload::RepositoryWriterLeaseRevoked(writer.payload.clone()),
    );
    let writer = manager
        .confirm_writer_revocation(writer, &writer_event)
        .expect("writer commit confirms");
    let captured = manager
        .execute_capture(manager.prepare_capture(writer).expect("capture prepares"))
        .expect("image captures");
    let lease = manager
        .execute_attach(manager.prepare_attach(captured).expect("attach prepares"))
        .expect("image attaches");
    let lease_event = committed(
        &claim_event,
        lease.event_id,
        claim_event.sequence + 2,
        claim_event.id,
        lease.lease.artifact.clone(),
        EventPayload::RepositorySnapshotLeaseIssued(lease.payload.clone()),
    );
    let recovery_material = CommittedSnapshotLeaseRecoveryV1 {
        lease_event: lease_event.clone(),
        lease_artifact: lease.lease.clone(),
    };
    let active = manager
        .activate_snapshot_lease(
            manager
                .confirm_snapshot_lease(lease, &lease_event)
                .expect("lease commit confirms"),
        )
        .expect("lease activates");
    drop(active);
    drop(manager);

    let manager = WorkspaceManager::open_with_boundaries(
        WorkspaceManagerConfig::new(source.path(), state.path()),
        commands.clone(),
        Arc::new(CanonicalArtifactBoundary),
        Arc::new(SystemClock::new()),
    )
    .expect("manager restarts");
    let inspections = manager.recovery_inspections().expect("journal inspects");
    let mut resumed = manager
        .recover_inspections(WorkspaceRecoveryRequestV1 {
            directives: vec![RecoveryDirectiveAssignmentV1 {
                lease_id: request.snapshot_lease_id,
                directive: SnapshotRecoveryDirectiveV1::ResumeCommittedLease(Box::new(
                    recovery_material,
                )),
            }],
            inspections,
            recovery_runtime_instance_id: RuntimeInstanceId::from_uuid(id(206)),
        })
        .expect("committed lease recovers");
    assert!(!resumed.fresh_capture_permitted);
    let recovered = match resumed.entries.pop().expect("one recovery").outcome {
        RecoveryEntryOutcomeV1::ActiveLeaseRecovered(active) => active,
        outcome => panic!("expected active lease recovery, got {outcome:?}"),
    };
    assert_eq!(
        recovered.mount_path(),
        std::fs::canonicalize(&cleanup.mount_path)
            .expect("mounted recovery path canonicalizes")
            .as_path()
    );
    drop(recovered);
    drop(manager);

    let manager = WorkspaceManager::open_with_boundaries(
        WorkspaceManagerConfig::new(source.path(), state.path()),
        commands,
        Arc::new(CanonicalArtifactBoundary),
        Arc::new(SystemClock::new()),
    )
    .expect("manager restarts for abandoned-run cleanup");
    let inspections = manager.recovery_inspections().expect("journal inspects");
    let abandoned = manager
        .recover_inspections(WorkspaceRecoveryRequestV1 {
            directives: vec![RecoveryDirectiveAssignmentV1 {
                lease_id: request.snapshot_lease_id,
                directive: SnapshotRecoveryDirectiveV1::AbandonForFreshCapture,
            }],
            inspections,
            recovery_runtime_instance_id: RuntimeInstanceId::from_uuid(id(207)),
        })
        .expect("exactly owned mount is cleaned");
    assert!(abandoned.fresh_capture_permitted);
    assert!(matches!(
        abandoned.entries[0].outcome,
        RecoveryEntryOutcomeV1::FreshCaptureReady
    ));
    assert!(abandoned.entries[0].command_evidence.len() >= 3);
    assert!(!cleanup.image_path.exists());
    assert!(!cleanup.mount_path.exists());
    assert!(
        manager
            .recovery_inspections()
            .expect("journal empty")
            .is_empty()
    );
}
