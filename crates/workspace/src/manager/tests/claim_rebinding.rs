use super::*;

#[test]
fn authentic_fresh_handoff_is_only_an_exact_current_noop() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let (mut owner, initial) = StoreClaimHarness::new(&workspace.source_path);
    let prepared = workspace
        .prepare_snapshot(request(), initial)
        .expect("Store-issued pre-capture handoff prepares");
    let exact_claim = prepared.claim_cursor.current_claim_event.clone();
    let prepared = workspace
        .rebind_prepared_snapshot_claim(prepared, owner.fresh_pre_capture())
        .expect("Fresh exact-current handoff is an idempotent no-op");
    assert_eq!(prepared.claim_cursor.current_claim_event, exact_claim);

    let (_foreign_store, foreign) = StoreClaimHarness::new(&workspace.source_path);
    assert!(matches!(
        workspace.rebind_prepared_snapshot_claim(prepared, foreign),
        Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff)
    ));
}

#[test]
fn authentic_active_lease_handoff_cannot_cross_local_lease_envelopes() {
    let command = || {
        Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        }))) as Arc<dyn CommandBoundary>
    };
    let (_source_a, _state_a, workspace_a) =
        manager(command(), Arc::new(CanonicalArtifactBoundary));
    let (active_a, _store_a) = active_lease_with_store(&workspace_a);
    let (_source_b, _state_b, workspace_b) =
        manager(command(), Arc::new(CanonicalArtifactBoundary));
    let (_active_b, mut store_b) = active_lease_with_store(&workspace_b);
    let foreign = store_b.active_lease_handoff(false);
    assert!(matches!(
        workspace_a.rebind_active_snapshot_release_claim(active_a, foreign),
        Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff)
    ));

    let (_source_c, _state_c, workspace_c) =
        manager(command(), Arc::new(CanonicalArtifactBoundary));
    let (active_c, _store_c) = active_lease_with_store(&workspace_c);
    let recovered_c = crate::recovery::RecoveredSnapshotLease {
        snapshot: active_c.snapshot,
        root: active_c.root,
        mount_path: active_c.mount_path,
        image_path: active_c.image_path,
        unmounted_root_identity: active_c.unmounted_root_identity,
        expected_image: active_c.expected_image,
        lease_event: active_c.lease_event,
        record: active_c.record,
    };
    let (_source_d, _state_d, workspace_d) =
        manager(command(), Arc::new(CanonicalArtifactBoundary));
    let (_active_d, mut store_d) = active_lease_with_store(&workspace_d);
    let foreign = store_d.active_lease_handoff(false);
    assert!(matches!(
        workspace_c.bind_recovered_snapshot_lease(recovered_c, foreign),
        Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff)
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one typestate matrix demonstrates each allowed pre-effect release rebind"
)]
fn pre_effect_and_release_typestates_rebind_but_completed_detach_requires_recovery() {
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (mut store_harness, claim_handoff) = StoreClaimHarness::new(&workspace.source_path);
        let prepared = workspace
            .prepare_snapshot(request(), claim_handoff)
            .expect("snapshot prepares");
        let claim_handoff = store_harness.renew_pre_capture();
        let expected_claim = store_harness.current_claim.id;
        let prepared = workspace
            .rebind_prepared_snapshot_claim(prepared, claim_handoff)
            .expect("uncommitted snapshot renews after a gap");
        assert_eq!(prepared.claim_cursor.current.claim_event_id, expected_claim);
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (mut store_harness, claim_handoff) = StoreClaimHarness::new(&workspace.source_path);
        let prepared = workspace
            .prepare_snapshot(request(), claim_handoff)
            .expect("snapshot prepares");
        let writer = workspace.revoke_writers(prepared).expect("writers revoke");
        let claim_handoff = store_harness.renew_pre_capture();
        let expected_claim = store_harness.current_claim.id;
        let writer = workspace
            .rebind_writer_revocation_claim(writer, claim_handoff)
            .expect("precommit writer evidence renews contiguously");
        assert_eq!(writer.payload.claim_event_id, expected_claim);
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (active, mut store_harness) = active_lease_with_store(&workspace);
        let claim_handoff = store_harness.active_lease_handoff(true);
        let expected_claim = store_harness.current_claim.id;
        let active = workspace
            .rebind_active_snapshot_release_claim(active, claim_handoff)
            .expect("active lease adopts restart claim after expiry");
        assert_eq!(active.claim_cursor.current.claim_event_id, expected_claim);
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (active, mut store_harness) = active_lease_with_store(&workspace);
        let prepared = SnapshotReleasePrepared {
            command: detach_command(&active.mount_path),
            record: active.record.clone(),
            request: SnapshotReleaseRequestV1 {
                release_event_id: EventId::from_uuid(uuid(181)),
                causal_parent_event_id: active.lease_event.id,
            },
            active,
        };
        let claim_handoff = store_harness.active_lease_handoff(true);
        let expected_claim = store_harness.current_claim.id;
        let prepared = workspace
            .rebind_snapshot_release_prepared_claim(prepared, claim_handoff)
            .expect("unexecuted detach adopts takeover claim after expiry");
        assert_eq!(
            prepared.active.claim_cursor.current.claim_event_id,
            expected_claim
        );
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (active, mut store_harness) = active_lease_with_store(&workspace);
        let released = synthetic_release_bundle(active);
        let claim_handoff = store_harness.active_lease_handoff(false);
        assert!(matches!(
            workspace.rebind_snapshot_release_bundle_claim(released, claim_handoff),
            Err(WorkspaceManagerError::ReleaseRequiresRecovery)
        ));
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (active, mut store_harness) = active_lease_with_store(&workspace);
        let recovered = crate::recovery::RecoveredSnapshotLease {
            snapshot: active.snapshot,
            root: active.root,
            mount_path: active.mount_path,
            image_path: active.image_path,
            unmounted_root_identity: active.unmounted_root_identity,
            expected_image: active.expected_image,
            lease_event: active.lease_event,
            record: active.record,
        };
        let claim_handoff = store_harness.active_lease_handoff(false);
        let rebound = workspace
            .bind_recovered_snapshot_lease(recovered, claim_handoff)
            .expect("Store active-lease authority binds recovered local state");
        assert_eq!(
            rebound.claim_cursor.current_claim_event,
            store_harness.current_claim
        );
    }
}
