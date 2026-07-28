use super::*;

#[test]
fn committed_and_prepared_capture_adoption_is_exact_and_consuming() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, manager_one) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let (committed, mut store_harness) = committed_writer_with_store(&manager_one);
    let claim_handoff = store_harness.renew_open_capture();
    let expected_claim = store_harness.current_claim.id;
    let committed = manager_one
        .adopt_committed_writer_revocation_claim(committed, claim_handoff)
        .expect("committed writer adopts exact renewal");
    assert_eq!(
        committed
            .bundle
            .prepared
            .claim_cursor
            .current
            .claim_event_id,
        expected_claim
    );
    assert_ne!(
        committed.bundle.prepared.claim_cursor.capture_tail_event_id,
        Some(expected_claim)
    );

    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, manager_two) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let prepared = manager_two
        .prepare_capture(committed_writer(&manager_two))
        .expect("capture prepares");
    assert!(matches!(
        manager_two
            .adopt_capture_prepared_claim(prepared, store_issued_fresh_handoff(&manager_two),),
        Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff)
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the substitution matrix names every closed adoption binding in one regression"
)]
fn capture_adoption_rejects_scope_identity_sequence_and_clock_substitution() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let committed = committed_writer(&workspace);
    let mut writer = committed.bundle;
    let (valid_claim, valid_adoption) = adoption_events(&writer);

    macro_rules! reject {
        ($label:literal, $mutate:expr) => {{
            let mut claim = valid_claim.clone();
            let mut adoption = valid_adoption.clone();
            ($mutate)(&mut claim, &mut adoption);
            let previous_claim = writer.prepared.claim_cursor.current_claim_event.clone();
            assert!(
                matches!(
                    apply_capture_adoption(&mut writer, &previous_claim, &claim, &adoption,),
                    Err(WorkspaceManagerError::InvalidClaimTransition
                        | WorkspaceManagerError::InvalidCaptureAdoption
                        | WorkspaceManagerError::InvalidClaimEnvelope)
                ),
                "{}",
                $label
            );
        }};
    }

    reject!(
        "capture-tail sequence",
        |claim: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            claim.sequence = writer
                .prepared
                .claim_cursor
                .capture_tail_sequence
                .expect("capture tail sequence");
            adoption.sequence = claim.sequence + 1;
        }
    );
    reject!(
        "adoption adjacency",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| adoption.sequence += 1
    );
    reject!(
        "session",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption.session_id = SessionId::from_uuid(uuid(501));
        }
    );
    reject!("run", |_: &mut EventEnvelope,
                    adoption: &mut EventEnvelope| {
        adoption.run_id = Some(RunId::from_uuid(uuid(502)));
    });
    reject!(
        "actor",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption.actor_id = ActorId::from_uuid(uuid(503));
        }
    );
    reject!(
        "causal parent",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption.causal_parent = Some(EventId::from_uuid(uuid(504)));
        }
    );
    reject!(
        "producer",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption.provenance.producer = "substituted".to_owned();
        }
    );
    reject!(
        "raw provenance",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption.provenance.raw_artifact = Some(ArtifactRef {
                sha256: "0".repeat(Sha256Digest::HEX_LENGTH),
                size_bytes: 0,
                media_type: "application/octet-stream".to_owned(),
            });
        }
    );
    reject!(
        "adoption id",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).adoption_id =
                RepositorySnapshotCaptureClaimAdoptionId::from_uuid(Uuid::nil());
        }
    );
    reject!(
        "issuer",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).issuer_actor_id = ActorId::from_uuid(uuid(505));
        }
    );
    reject!(
        "snapshot",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption)
                .snapshot_id
                .push_str("-forged");
        }
    );
    reject!(
        "lease",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).lease_id =
                RepositorySnapshotLeaseId::from_uuid(uuid(506));
        }
    );
    reject!(
        "lease event",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).snapshot_lease_event_id = EventId::from_uuid(uuid(507));
        }
    );
    reject!(
        "writer lease",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption)
                .workspace_writer_lease_id
                .push_str("-forged");
        }
    );
    reject!(
        "writer generation",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).writer_lease_generation += 1;
        }
    );
    reject!(
        "writer event",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).writer_revocation_event_id =
                EventId::from_uuid(uuid(508));
        }
    );
    reject!(
        "prior claim event",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).prior_claim_event_id = EventId::from_uuid(uuid(509));
        }
    );
    reject!(
        "prior claim id",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).prior_claim_id = RunClaimId::from_uuid(uuid(510));
        }
    );
    reject!(
        "prior generation",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).prior_claim_generation += 1;
        }
    );
    reject!(
        "prior runtime",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).prior_runtime_instance_id =
                RuntimeInstanceId::from_uuid(uuid(511));
        }
    );
    reject!(
        "new claim event",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).new_claim_event_id = EventId::from_uuid(uuid(512));
        }
    );
    reject!(
        "new claim id",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).new_claim_id = RunClaimId::from_uuid(uuid(513));
        }
    );
    reject!(
        "new generation",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).new_claim_generation += 1;
        }
    );
    reject!(
        "new runtime",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).new_runtime_instance_id =
                RuntimeInstanceId::from_uuid(uuid(514));
        }
    );
    reject!(
        "cancellation generation",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).cancellation_generation += 1;
        }
    );
    reject!(
        "clock runtime",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption)
                .adopted_at
                .runtime_instance_id = RuntimeInstanceId::from_uuid(uuid(515));
        }
    );
    reject!(
        "clock zero",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).adopted_at.monotonic_nanos = 0;
        }
    );
    reject!(
        "clock monotonic order",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).adopted_at.monotonic_nanos = writer
                .prepared
                .claim_cursor
                .capture_clock
                .as_ref()
                .expect("capture clock")
                .monotonic_nanos
                .saturating_sub(1);
        }
    );
    reject!(
        "clock wall order",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).adopted_at.observed_at = writer
                .prepared
                .claim_cursor
                .capture_clock
                .as_ref()
                .expect("capture clock")
                .observed_at
                - chrono::Duration::milliseconds(1);
        }
    );
    reject!(
        "refresh clock after claim",
        |claim: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption_payload_mut(adoption).adopted_at.observed_at =
                claim.occurred_at + chrono::Duration::milliseconds(1);
            adoption.occurred_at = claim.occurred_at + chrono::Duration::milliseconds(2);
        }
    );
    reject!(
        "claim after adoption event",
        |claim: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            claim.occurred_at = adoption.occurred_at + chrono::Duration::milliseconds(1);
            let EventPayload::RunClaimed(payload) = &mut claim.payload else {
                unreachable!("claim fixture")
            };
            payload.lease_expires_at = claim.occurred_at + chrono::Duration::minutes(1);
        }
    );
    reject!(
        "prior lease does not cover adoption",
        |_: &mut EventEnvelope, adoption: &mut EventEnvelope| {
            adoption.occurred_at = writer
                .prepared
                .claim_cursor
                .current
                .claim_lease_expires_at
                .expect("prior lease");
        }
    );
}

#[test]
fn adoption_rejects_a_clock_before_the_latest_capture_or_attach_fence() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, manager_one) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let mut captured = synthetic_captured_image(&manager_one);
    let capture_fence = captured
        .writer
        .prepared
        .claim_cursor
        .capture_clock
        .as_ref()
        .expect("capture fence")
        .clone();
    let (claim, mut adoption) = adoption_events(&captured.writer);
    let payload = adoption_payload_mut(&mut adoption);
    payload.adopted_at.monotonic_nanos = capture_fence.monotonic_nanos - 1;
    payload.adopted_at.observed_at = capture_fence.observed_at - chrono::Duration::milliseconds(1);
    let previous_claim = captured
        .writer
        .prepared
        .claim_cursor
        .current_claim_event
        .clone();
    assert!(matches!(
        apply_capture_adoption(&mut captured.writer, &previous_claim, &claim, &adoption,),
        Err(WorkspaceManagerError::InvalidCaptureAdoption)
    ));

    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, manager_two) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let mut lease = synthetic_lease_bundle(&manager_two);
    let attach_fence = lease
        .prepared
        .writer
        .prepared
        .claim_cursor
        .capture_clock
        .as_ref()
        .expect("attach fence")
        .clone();
    let (claim, mut adoption) = adoption_events(&lease.prepared.writer);
    let payload = adoption_payload_mut(&mut adoption);
    payload.adopted_at.monotonic_nanos = attach_fence.monotonic_nanos - 1;
    payload.adopted_at.observed_at = attach_fence.observed_at - chrono::Duration::milliseconds(1);
    let previous_claim = lease
        .prepared
        .writer
        .prepared
        .claim_cursor
        .current_claim_event
        .clone();
    assert!(matches!(
        apply_capture_adoption(
            &mut lease.prepared.writer,
            &previous_claim,
            &claim,
            &adoption,
        ),
        Err(WorkspaceManagerError::InvalidCaptureAdoption)
    ));
}

#[test]
fn every_open_capture_typestate_consumes_the_exact_adoption() {
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (committed, mut store_harness) = committed_writer_with_store(&workspace);
        let prepared = workspace
            .prepare_capture(committed)
            .expect("capture prepares");
        let claim_handoff = store_harness.renew_open_capture();
        let expected_claim = store_harness.current_claim.id;
        let prepared = workspace
            .adopt_capture_prepared_claim(prepared, claim_handoff)
            .expect("prepared capture adopts");
        assert_eq!(
            prepared.writer.prepared.claim_cursor.current.claim_event_id,
            expected_claim
        );
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (captured, mut store_harness) = synthetic_captured_image_with_store(&workspace);
        let claim_handoff = store_harness.renew_open_capture();
        let expected_claim = store_harness.current_claim.id;
        let captured = workspace
            .adopt_captured_image_claim(captured, claim_handoff)
            .expect("captured image adopts");
        assert_eq!(
            captured.writer.prepared.claim_cursor.current.claim_event_id,
            expected_claim
        );
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (captured, mut store_harness) = synthetic_captured_image_with_store(&workspace);
        let claim_handoff = store_harness.renew_open_capture();
        let expected_claim = store_harness.current_claim.id;
        let prepared = SnapshotAttachPrepared {
            command: attach_command(
                &captured.writer.prepared.mount_path,
                &captured.writer.prepared.image_path,
            ),
            unmounted_root_identity: captured.source_after.root_identity,
            record: captured.record.clone(),
            captured,
        };
        let prepared = workspace
            .adopt_snapshot_attach_prepared_claim(prepared, claim_handoff)
            .expect("attach-prepared capture adopts");
        assert_eq!(
            prepared
                .captured
                .writer
                .prepared
                .claim_cursor
                .current
                .claim_event_id,
            expected_claim
        );
    }
    {
        let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })));
        let (_source, _state, workspace) = manager(command, Arc::new(CanonicalArtifactBoundary));
        let (lease, mut store_harness) = synthetic_lease_bundle_with_store(&workspace);
        let claim_handoff = store_harness.renew_open_capture();
        let expected_claim = store_harness.current_claim.id;
        let lease = workspace
            .adopt_snapshot_lease_bundle_claim(lease, claim_handoff)
            .expect("lease bundle adopts");
        assert_eq!(
            lease
                .prepared
                .writer
                .prepared
                .claim_cursor
                .current
                .claim_event_id,
            expected_claim
        );
        assert_eq!(lease.payload.claim_event_id, expected_claim);
    }
}
