use super::*;

pub(super) fn request() -> SnapshotRequestV1 {
    SnapshotRequestV1 {
        writer_revocation_event_id: EventId::from_uuid(uuid(7)),
        snapshot_lease_event_id: EventId::from_uuid(uuid(8)),
        snapshot_lease_id: RepositorySnapshotLeaseId::from_uuid(uuid(9)),
        snapshot_id: "snapshot-language-neutral".to_owned(),
        repository_root_id: "repository-root".to_owned(),
        workspace_writer_lease_id: "writer-lease".to_owned(),
    }
}

pub(super) fn committed(
    authority: &SnapshotRuntimeAuthorityV1,
    id: EventId,
    causal_parent: EventId,
    payload: EventPayload,
    raw_artifact: ArtifactRef,
) -> EventEnvelope {
    EventEnvelope {
        id,
        sequence: authority.claim_sequence.expect("durable claim sequence") + 1,
        session_id: authority.session_id,
        run_id: Some(authority.run_id),
        actor_id: authority.issuer_actor_id,
        causal_parent: Some(causal_parent),
        occurred_at: Utc::now(),
        provenance: Provenance {
            producer: "workspace-manager-test".to_owned(),
            backend: None,
            raw_artifact: Some(raw_artifact),
        },
        payload,
    }
}

pub(super) fn capture_prepared(manager: &WorkspaceManager) -> CapturePrepared {
    let request = request();
    let prepared = manager
        .prepare_snapshot(request.clone(), store_issued_fresh_handoff(manager))
        .expect("snapshot prepares");
    let bundle = manager.revoke_writers(prepared).expect("writers revoke");
    let event = committed(
        &bundle.prepared.claim_cursor.current,
        bundle.event_id,
        bundle.prepared.claim_cursor.current.claim_event_id,
        EventPayload::RepositoryWriterLeaseRevoked(bundle.payload.clone()),
        bundle.evidence.artifact.clone(),
    );
    let committed = manager
        .confirm_writer_revocation(bundle, &event)
        .expect("exact commit confirms");
    manager
        .prepare_capture(committed)
        .expect("capture prepares")
}

pub(super) fn committed_writer(manager: &WorkspaceManager) -> CommittedWriterRevocation {
    committed_writer_with_store(manager).0
}

pub(super) fn committed_writer_with_store(
    manager: &WorkspaceManager,
) -> (CommittedWriterRevocation, StoreClaimHarness) {
    let (mut store_harness, claim_handoff) = StoreClaimHarness::new(&manager.source_path);
    let request = request();
    let prepared = manager
        .prepare_snapshot(request, claim_handoff)
        .expect("snapshot prepares");
    let bundle = manager.revoke_writers(prepared).expect("writers revoke");
    let event = store_harness.append_writer_event(&bundle);
    let committed = manager
        .confirm_writer_revocation(bundle, &event)
        .expect("writer commit confirms");
    (committed, store_harness)
}

pub(super) fn adoption_events(writer: &WriterRevocationBundle) -> (EventEnvelope, EventEnvelope) {
    let cursor = &writer.prepared.claim_cursor;
    let prior = &cursor.current;
    let capture_tail = cursor
        .capture_tail_event_id
        .expect("committed capture tail exists");
    let capture_clock = cursor.capture_clock.as_ref().expect("capture clock exists");
    let adopted_at = RuntimeClockReading {
        runtime_instance_id: prior.claim_runtime_instance_id,
        monotonic_nanos: capture_clock.monotonic_nanos + 1,
        observed_at: capture_clock.observed_at + chrono::Duration::milliseconds(1),
    };
    let claim_occurred_at = adopted_at.observed_at + chrono::Duration::milliseconds(1);
    let mut claim = cursor.current_claim_event.clone();
    claim.id = EventId::from_uuid(uuid(101));
    claim.sequence = prior.claim_sequence.expect("claim sequence") + 2;
    claim.causal_parent = Some(EventId::from_uuid(uuid(2_101)));
    claim.occurred_at = claim_occurred_at;
    let EventPayload::RunClaimed(new_claim) = &mut claim.payload else {
        unreachable!("claim helper always emits RunClaimed")
    };
    new_claim.claim_id = RunClaimId::from_uuid(uuid(1_101));
    new_claim.claim_generation = prior.claim_generation + 1;
    new_claim.lease_expires_at = claim_occurred_at + chrono::Duration::minutes(10);
    let request = &writer.prepared.request;
    let adoption = EventEnvelope {
        id: EventId::from_uuid(uuid(102)),
        sequence: claim.sequence + 1,
        session_id: prior.session_id,
        run_id: Some(prior.run_id),
        actor_id: prior.issuer_actor_id,
        causal_parent: Some(capture_tail),
        occurred_at: claim_occurred_at + chrono::Duration::milliseconds(1),
        provenance: Provenance {
            producer: PARALLEL_RECON_CLAIM_REFRESH_PRODUCER.to_owned(),
            backend: None,
            raw_artifact: None,
        },
        payload: EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(
            RepositorySnapshotCaptureClaimAdoptedV1 {
                adoption_id: RepositorySnapshotCaptureClaimAdoptionId::from_uuid(uuid(103)),
                issuer_actor_id: prior.issuer_actor_id,
                snapshot_id: request.snapshot_id.clone(),
                lease_id: request.snapshot_lease_id,
                snapshot_lease_event_id: request.snapshot_lease_event_id,
                workspace_writer_lease_id: request.workspace_writer_lease_id.clone(),
                writer_lease_generation: writer.writer_generation,
                writer_revocation_event_id: request.writer_revocation_event_id,
                prior_claim_event_id: prior.claim_event_id,
                prior_claim_id: prior.claim_id,
                prior_claim_generation: prior.claim_generation,
                prior_runtime_instance_id: prior.claim_runtime_instance_id,
                new_claim_event_id: claim.id,
                new_claim_id: new_claim.claim_id,
                new_claim_generation: new_claim.claim_generation,
                new_runtime_instance_id: new_claim.runtime_instance_id,
                cancellation_generation: new_claim.cancellation_generation,
                adopted_at,
            },
        ),
    };
    (claim, adoption)
}

pub(super) fn adoption_payload_mut(
    event: &mut EventEnvelope,
) -> &mut RepositorySnapshotCaptureClaimAdoptedV1 {
    let EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(payload) = &mut event.payload else {
        panic!("adoption fixture payload")
    };
    payload
}

fn retained(media_type: &'static str, bytes: &[u8]) -> Artifact {
    CanonicalArtifactBoundary
        .retain(media_type, bytes.to_vec())
        .expect("canonical artifact")
}

pub(super) fn synthetic_captured_image(manager: &WorkspaceManager) -> CapturedImage {
    synthetic_captured_image_from_committed(committed_writer(manager))
}

pub(super) fn synthetic_captured_image_with_store(
    manager: &WorkspaceManager,
) -> (CapturedImage, StoreClaimHarness) {
    let (committed, store_harness) = committed_writer_with_store(manager);
    (
        synthetic_captured_image_from_committed(committed),
        store_harness,
    )
}

fn synthetic_captured_image_from_committed(committed: CommittedWriterRevocation) -> CapturedImage {
    let mut writer = committed.bundle;
    let prior_clock = writer
        .prepared
        .claim_cursor
        .capture_clock
        .as_ref()
        .expect("writer clock")
        .clone();
    let capture_completed_at = RuntimeClockReading {
        runtime_instance_id: prior_clock.runtime_instance_id,
        monotonic_nanos: prior_clock.monotonic_nanos + 10,
        observed_at: prior_clock.observed_at,
    };
    writer.prepared.claim_cursor.capture_clock = Some(capture_completed_at.clone());
    let stdout = retained(COMMAND_STDOUT_MEDIA_TYPE, b"create stdout");
    let stderr = retained(COMMAND_STDERR_MEDIA_TYPE, b"create stderr");
    let image_bytes = b"synthetic udro image";
    let image_digest = Sha256Digest::of_bytes(image_bytes);
    let command = create_command(&writer.prepared.source_path, &writer.prepared.image_path);
    let create_receipt =
        command_receipt(&command, 0, &stdout, &stderr, capture_completed_at.clone());
    let source_after = writer.source_before.clone();
    let source_after_artifact = writer.source_manifest_artifact.clone();
    let mut record = writer.record.clone();
    record.stage = crate::CleanupStageV1::ImageCaptured;
    CapturedImage {
        create_receipt,
        create_stdout: stdout,
        create_stderr: stderr,
        image: RepositoryExternalImageIdentityV1 {
            format: RepositorySnapshotImageFormatV1::Udro,
            byte_len: u64::try_from(image_bytes.len()).expect("small fixture"),
            sha256: image_digest.clone(),
        },
        image_hash_receipt: RepositoryFileHashReceiptV1 {
            path: writer.prepared.image_path.clone().into(),
            byte_len: u64::try_from(image_bytes.len()).expect("small fixture"),
            sha256: image_digest,
            completed_at: capture_completed_at.clone(),
        },
        source_after,
        source_after_artifact,
        capture_completed_at,
        record,
        writer,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the synthetic lease spells out every closed Protocol field used by the typestate"
)]
pub(super) fn synthetic_lease_bundle(manager: &WorkspaceManager) -> SnapshotLeaseBundle {
    synthetic_lease_bundle_from_captured(synthetic_captured_image(manager))
}

pub(super) fn synthetic_lease_bundle_with_store(
    manager: &WorkspaceManager,
) -> (SnapshotLeaseBundle, StoreClaimHarness) {
    let (captured, store_harness) = synthetic_captured_image_with_store(manager);
    (
        synthetic_lease_bundle_from_captured(captured),
        store_harness,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the Store-valid synthetic lease retains every closed protocol evidence field"
)]
fn synthetic_lease_bundle_from_captured(mut captured: CapturedImage) -> SnapshotLeaseBundle {
    let prior_clock = captured
        .writer
        .prepared
        .claim_cursor
        .capture_clock
        .as_ref()
        .expect("capture fence")
        .clone();
    let lease_observed_at = RuntimeClockReading {
        runtime_instance_id: prior_clock.runtime_instance_id,
        monotonic_nanos: prior_clock.monotonic_nanos + 10,
        observed_at: prior_clock.observed_at,
    };
    captured.writer.prepared.claim_cursor.capture_clock = Some(lease_observed_at.clone());
    let request = &captured.writer.prepared.request;
    let root_identity = captured.source_after.root_identity;
    let root = RepositoryRootBindingV1 {
        repository_root_id: request.repository_root_id.clone(),
        descriptor_identity: root_identity,
    };
    let attach_evidence_document = RepositoryMacOsAttachEvidenceV1 {
        schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        leaf_device_identifier: "/dev/disk99s1".to_owned(),
        mount_path: captured.writer.prepared.mount_path.clone().into(),
        read_only: true,
    };
    let attach_evidence = retained(
        REPOSITORY_MACOS_ATTACH_EVIDENCE_MEDIA_TYPE,
        &serde_json::to_vec(&attach_evidence_document).expect("attach evidence encodes"),
    );
    let raw_attach_plist = retained(RAW_MACOS_PLIST_MEDIA_TYPE, b"synthetic plist");
    let attach_stderr = retained(COMMAND_STDERR_MEDIA_TYPE, b"attach stderr");
    let snapshot_manifest_document = RepositorySnapshotManifestDocumentV1 {
        schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        snapshot_id: request.snapshot_id.clone(),
        source_path: captured.writer.prepared.source_path.clone().into(),
        source_root_identity: captured.source_after.root_identity,
        mounted_root_identity: root_identity,
        entries_digest: captured.source_after.digest.clone(),
    };
    let snapshot_manifest = retained(
        REPOSITORY_SNAPSHOT_MANIFEST_MEDIA_TYPE,
        &serde_json::to_vec(&snapshot_manifest_document).expect("snapshot manifest encodes"),
    );
    let mounted_content_manifest = retained(
        SOURCE_CONTENT_MANIFEST_MEDIA_TYPE,
        &captured.source_after.canonical_bytes,
    );
    let attach_receipt = command_receipt(
        &attach_command(
            &captured.writer.prepared.mount_path,
            &captured.writer.prepared.image_path,
        ),
        0,
        &attach_evidence,
        &attach_stderr,
        lease_observed_at.clone(),
    );
    let source_quiescence = RepositorySourceQuiescenceV1 {
        workspace_writer_lease_id: request.workspace_writer_lease_id.clone(),
        writer_lease_generation: captured.writer.writer_generation,
        writer_lease_event_id: request.writer_revocation_event_id,
        writer_lease_evidence_artifact: captured.writer.evidence.artifact.clone(),
        writer_lease_evidence_digest: captured.writer.evidence.digest.clone(),
        writers_revoked_at: captured.writer.revoked_at.clone(),
        source_identity_before: captured.writer.source_before.root_identity,
        source_identity_after: captured.source_after.root_identity,
        source_manifest_before: captured.writer.source_before.digest.clone(),
        source_manifest_after: captured.source_after.digest.clone(),
        capture_completed_at: captured.capture_completed_at.clone(),
    };
    let mount_evidence = RepositoryMacOsReadOnlyMountEvidenceV1 {
        source_quiescence,
        image: captured.image.clone(),
        create_receipt: captured.create_receipt.clone(),
        attach_receipt,
        attach_plist_artifact: attach_evidence.artifact.clone(),
        source_path: captured.writer.prepared.source_path.clone().into(),
        image_path: captured.writer.prepared.image_path.clone().into(),
        mount_path: captured.writer.prepared.mount_path.clone().into(),
        leaf_device_identifier: "/dev/disk99s1".to_owned(),
        image_hash_receipt: captured.image_hash_receipt.clone(),
        statfs_receipt: RepositoryMacOsStatFsReceiptV1 {
            mount_path: captured.writer.prepared.mount_path.clone().into(),
            statfs_flags: 1,
            mnt_rdonly_mask: 1,
            leaf_device_identifier: "/dev/disk99s1".to_owned(),
            mounted_root_identity: root_identity,
            write_open_errno: 30,
            observed_at: lease_observed_at,
        },
        post_mount_manifest_artifact: snapshot_manifest.artifact.clone(),
        post_mount_manifest_digest: snapshot_manifest.digest.clone(),
        lifecycle_owner_actor_id: captured
            .writer
            .prepared
            .claim_cursor
            .current
            .issuer_actor_id,
        lifecycle_owner_runtime_instance_id: captured
            .writer
            .prepared
            .claim_cursor
            .current
            .claim_runtime_instance_id,
        cleanup_state: RepositorySnapshotCleanupStateV1::MountedDetachRequired,
    };
    let lease_document = RepositorySnapshotLeaseDocumentV1 {
        schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        lease_id: request.snapshot_lease_id,
        mode: RepositorySnapshotLeaseModeV1::MacOsCooperativeQuiescedReadOnlyDiskImage,
        snapshot_id: request.snapshot_id.clone(),
        declared_snapshot_digest: snapshot_manifest.digest.clone(),
        root: root.clone(),
        macos_read_only_mount: mount_evidence,
    };
    let lease = retained(
        REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE,
        &serde_json::to_vec(&lease_document).expect("lease document encodes"),
    );
    let snapshot = RepositorySnapshotBindingV1 {
        snapshot_id: request.snapshot_id.clone(),
        declared_snapshot_digest: snapshot_manifest.digest.clone(),
        immutability_lease: RepositorySnapshotLeaseBindingV1 {
            lease_id: request.snapshot_lease_id,
            mode: RepositorySnapshotLeaseModeV1::MacOsCooperativeQuiescedReadOnlyDiskImage,
            lease_artifact: lease.artifact.clone(),
            lease_digest: lease.digest.clone(),
        },
    };
    let authority = &captured.writer.prepared.claim_cursor.current;
    let payload = RepositorySnapshotLeaseIssuedV1 {
        issuer_actor_id: authority.issuer_actor_id,
        claim_event_id: authority.claim_event_id,
        claim_id: authority.claim_id,
        claim_generation: authority.claim_generation,
        claim_runtime_instance_id: authority.claim_runtime_instance_id,
        cancellation_generation: authority.cancellation_generation,
        snapshot,
        root,
    };
    let mut record = captured.record.clone();
    record.stage = crate::CleanupStageV1::MountedDetachRequired;
    SnapshotLeaseBundle {
        event_id: request.snapshot_lease_event_id,
        payload,
        lease_document,
        lease,
        attach_evidence,
        raw_attach_plist,
        attach_stderr,
        snapshot_manifest,
        mounted_content_manifest,
        unmounted_root_identity: root_identity,
        prepared: captured,
        record,
    }
}

pub(super) fn active_lease_with_store(
    manager: &WorkspaceManager,
) -> (ActiveSnapshotLease, StoreClaimHarness) {
    let (bundle, mut store_harness) = synthetic_lease_bundle_with_store(manager);
    let lease_event = store_harness.append_lease_event(&bundle);
    require_committed_event(
        &lease_event,
        bundle.event_id,
        &bundle.prepared.writer.prepared.claim_cursor.current,
        bundle
            .prepared
            .writer
            .prepared
            .claim_cursor
            .current
            .claim_event_id,
        &EventPayload::RepositorySnapshotLeaseIssued(bundle.payload.clone()),
        &bundle.lease.artifact,
    )
    .expect("Store lease exactly binds Workspace output");
    let active = ActiveSnapshotLease {
        snapshot: bundle.payload.snapshot,
        root: bundle.payload.root,
        mount_path: bundle.prepared.writer.prepared.mount_path,
        image_path: bundle.prepared.writer.prepared.image_path,
        unmounted_root_identity: bundle.unmounted_root_identity,
        expected_image: bundle.prepared.image,
        lease_event,
        claim_cursor: bundle.prepared.writer.prepared.claim_cursor,
        record: bundle.record,
    };
    (active, store_harness)
}

pub(super) fn synthetic_release_bundle(active: ActiveSnapshotLease) -> SnapshotReleaseBundle {
    let authority = &active.claim_cursor.current;
    let stdout = retained(COMMAND_STDOUT_MEDIA_TYPE, b"detach stdout");
    let stderr = retained(COMMAND_STDERR_MEDIA_TYPE, b"detach stderr");
    let completed_at = RuntimeClockReading {
        runtime_instance_id: authority.claim_runtime_instance_id,
        monotonic_nanos: 100,
        observed_at: authority.claim_occurred_at.expect("claim time"),
    };
    let detach_receipt = command_receipt(
        &detach_command(&active.mount_path),
        0,
        &stdout,
        &stderr,
        completed_at,
    );
    let release_document = RepositorySnapshotReleaseDocumentV1 {
        schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        lease_id: active.snapshot.immutability_lease.lease_id,
        lease_event_id: active.lease_event.id,
        detach_receipt,
        unmounted_verified: true,
    };
    let release = retained(REPOSITORY_SNAPSHOT_RELEASE_MEDIA_TYPE, b"synthetic release");
    let payload = RepositorySnapshotLeaseReleasedV1 {
        issuer_actor_id: authority.issuer_actor_id,
        claim_event_id: authority.claim_event_id,
        claim_id: authority.claim_id,
        claim_generation: authority.claim_generation,
        claim_runtime_instance_id: authority.claim_runtime_instance_id,
        cancellation_generation: authority.cancellation_generation,
        lease_event_id: active.lease_event.id,
        release_artifact: release.artifact.clone(),
        release_digest: release.digest.clone(),
    };
    SnapshotReleaseBundle {
        event_id: EventId::from_uuid(uuid(180)),
        payload,
        release_document,
        release,
        detach_stdout: stdout,
        detach_stderr: stderr,
        image_path: active.image_path,
        mount_path: active.mount_path,
        unmounted_root_identity: active.unmounted_root_identity,
        expected_image: active.expected_image,
        claim_cursor: active.claim_cursor,
        causal_parent_event_id: active.lease_event.id,
        lease_id: active.snapshot.immutability_lease.lease_id,
    }
}
