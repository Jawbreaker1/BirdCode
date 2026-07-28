use super::*;

#[allow(clippy::too_many_arguments)]
fn claim_event(
    event_id: u128,
    sequence: u64,
    actor_id: u128,
    runtime_instance_id: u128,
    claim_generation: u64,
    cancellation_generation: u64,
    occurred_at: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
) -> EventEnvelope {
    EventEnvelope {
        id: EventId::from_uuid(uuid(event_id)),
        sequence,
        session_id: SessionId::from_uuid(uuid(1)),
        run_id: Some(RunId::from_uuid(uuid(2))),
        actor_id: ActorId::from_uuid(uuid(actor_id)),
        causal_parent: Some(EventId::from_uuid(uuid(event_id + 2_000))),
        occurred_at,
        provenance: Provenance {
            producer: "workspace-manager-test".to_owned(),
            backend: None,
            raw_artifact: None,
        },
        payload: EventPayload::RunClaimed(RunClaimed {
            claim_id: RunClaimId::from_uuid(uuid(event_id + 1_000)),
            runtime_instance_id: RuntimeInstanceId::from_uuid(uuid(runtime_instance_id)),
            claim_generation,
            cancellation_generation,
            lease_expires_at,
        }),
    }
}

#[test]
fn claim_authority_requires_an_exact_durable_envelope() {
    let occurred_at = Utc::now();
    let valid = claim_event(
        4,
        1,
        3,
        6,
        1,
        0,
        occurred_at,
        occurred_at + chrono::Duration::minutes(10),
    );
    let authority = SnapshotRuntimeAuthorityV1::from_claim_event(&valid).expect("claim is exact");
    assert_eq!(authority.session_id, valid.session_id);
    assert_eq!(authority.run_id, valid.run_id.expect("run scope"));
    assert_eq!(authority.claim_event_id, valid.id);

    let mut forged = valid.clone();
    forged.run_id = None;
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
    let mut forged = valid.clone();
    forged.sequence = 0;
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
    let mut forged = valid.clone();
    forged.causal_parent = None;
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
    let mut forged = valid.clone();
    forged.provenance.producer.clear();
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
    let mut forged = valid.clone();
    forged.provenance.raw_artifact = Some(ArtifactRef {
        sha256: "0".repeat(Sha256Digest::HEX_LENGTH),
        size_bytes: 0,
        media_type: "application/octet-stream".to_owned(),
    });
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
    let mut forged = valid.clone();
    forged.payload = EventPayload::RunStateChanged {
        from: RunState::Queued,
        to: RunState::Running,
    };
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
    let mut forged = valid.clone();
    let EventPayload::RunClaimed(claim) = &mut forged.payload else {
        unreachable!("claim fixture")
    };
    claim.claim_generation = 0;
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
    let mut forged = valid;
    let EventPayload::RunClaimed(claim) = &mut forged.payload else {
        unreachable!("claim fixture")
    };
    claim.lease_expires_at = forged.occurred_at;
    assert!(matches!(
        SnapshotRuntimeAuthorityV1::from_claim_event(&forged),
        Err(WorkspaceManagerError::InvalidClaimEnvelope)
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one transition matrix regression keeps live/gap/recovery cases adjacent"
)]
fn exact_claim_transition_allows_expired_reassignment_but_capture_stays_contiguous() {
    let occurred_at = Utc::now();
    let prior_event = claim_event(
        4,
        1,
        3,
        6,
        1,
        0,
        occurred_at,
        occurred_at + chrono::Duration::minutes(1),
    );
    let cursor = SnapshotClaimCursor::from_claim_event(&prior_event).expect("prior claim is exact");
    let prior = &cursor.current;

    let live_renewal = claim_event(
        101,
        2,
        3,
        6,
        2,
        0,
        occurred_at + chrono::Duration::seconds(30),
        occurred_at + chrono::Duration::minutes(2),
    );
    assert!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &live_renewal,
            ClaimTransitionPolicy::SameOwnerOnly,
        )
        .is_ok()
    );

    let after_expiry = occurred_at + chrono::Duration::minutes(1);
    let same_owner_gap = claim_event(
        102,
        3,
        3,
        6,
        2,
        0,
        after_expiry,
        after_expiry + chrono::Duration::minutes(1),
    );
    assert!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &same_owner_gap,
            ClaimTransitionPolicy::AllowExpiredTakeover
        )
        .is_ok()
    );
    assert!(matches!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &same_owner_gap,
            ClaimTransitionPolicy::SameOwnerOnly
        ),
        Err(WorkspaceManagerError::InvalidClaimTransition)
    ));

    let restarted_runtime = claim_event(
        103,
        4,
        3,
        66,
        2,
        0,
        after_expiry,
        after_expiry + chrono::Duration::minutes(1),
    );
    assert!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &restarted_runtime,
            ClaimTransitionPolicy::AllowExpiredTakeover
        )
        .is_ok()
    );

    let expired_runtime_relabel = claim_event(
        104,
        5,
        33,
        6,
        2,
        0,
        after_expiry,
        after_expiry + chrono::Duration::minutes(1),
    );
    assert!(matches!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &expired_runtime_relabel,
            ClaimTransitionPolicy::AllowExpiredTakeover
        ),
        Err(WorkspaceManagerError::InvalidClaimTransition)
    ));

    let expired_takeover = claim_event(
        105,
        6,
        33,
        66,
        2,
        0,
        after_expiry,
        after_expiry + chrono::Duration::minutes(1),
    );
    assert!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &expired_takeover,
            ClaimTransitionPolicy::AllowExpiredTakeover
        )
        .is_ok()
    );

    let live_restart = claim_event(
        106,
        7,
        3,
        66,
        2,
        0,
        occurred_at + chrono::Duration::seconds(30),
        occurred_at + chrono::Duration::minutes(2),
    );
    assert!(matches!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &live_restart,
            ClaimTransitionPolicy::AllowExpiredTakeover
        ),
        Err(WorkspaceManagerError::InvalidClaimTransition)
    ));

    let live_runtime_relabel = claim_event(
        107,
        8,
        33,
        6,
        2,
        0,
        occurred_at + chrono::Duration::seconds(30),
        occurred_at + chrono::Duration::minutes(2),
    );
    assert!(matches!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &live_runtime_relabel,
            ClaimTransitionPolicy::AllowExpiredTakeover
        ),
        Err(WorkspaceManagerError::InvalidClaimTransition)
    ));

    let live_takeover = claim_event(
        108,
        9,
        33,
        66,
        2,
        0,
        occurred_at + chrono::Duration::seconds(30),
        occurred_at + chrono::Duration::minutes(2),
    );
    assert!(matches!(
        validate_next_claim(
            &cursor,
            &prior_event,
            &live_takeover,
            ClaimTransitionPolicy::AllowExpiredTakeover
        ),
        Err(WorkspaceManagerError::InvalidClaimTransition)
    ));

    let mut forged_claims = Vec::new();
    let mut forged = live_renewal.clone();
    forged.session_id = SessionId::from_uuid(uuid(700));
    forged_claims.push(forged);
    let mut forged = live_renewal.clone();
    forged.run_id = Some(RunId::from_uuid(uuid(701)));
    forged_claims.push(forged);
    let mut forged = live_renewal.clone();
    forged.sequence = prior.claim_sequence.expect("claim sequence");
    forged_claims.push(forged);
    let mut forged = live_renewal.clone();
    forged.occurred_at =
        prior.claim_occurred_at.expect("claim time") - chrono::Duration::milliseconds(1);
    forged_claims.push(forged);
    let mut forged = live_renewal.clone();
    forged.id = prior.claim_event_id;
    forged_claims.push(forged);
    let mut forged = live_renewal.clone();
    let EventPayload::RunClaimed(claim) = &mut forged.payload else {
        unreachable!("claim fixture")
    };
    claim.claim_id = prior.claim_id;
    forged_claims.push(forged);
    let mut forged = live_renewal.clone();
    let EventPayload::RunClaimed(claim) = &mut forged.payload else {
        unreachable!("claim fixture")
    };
    claim.claim_generation += 1;
    forged_claims.push(forged);
    let mut forged = live_renewal;
    let EventPayload::RunClaimed(claim) = &mut forged.payload else {
        unreachable!("claim fixture")
    };
    claim.cancellation_generation += 1;
    forged_claims.push(forged);
    for forged in forged_claims {
        assert!(matches!(
            validate_next_claim(
                &cursor,
                &prior_event,
                &forged,
                ClaimTransitionPolicy::AllowExpiredTakeover
            ),
            Err(WorkspaceManagerError::InvalidClaimTransition)
        ));
    }
}
