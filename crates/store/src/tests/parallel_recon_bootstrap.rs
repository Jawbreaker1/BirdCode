use super::*;

fn start_authority(
    runtime_instance_id: RuntimeInstanceId,
    monotonic_nanos: u64,
) -> ChildRepositoryExplorerAttemptStartAuthority {
    ChildRepositoryExplorerAttemptStartAuthority {
        event_id: EventId::new(),
        attempt_id: ChildAttemptId::new(),
        local_plan_id: birdcode_protocol::ChildLocalPlanId::new(),
        started_at: RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos,
            observed_at: Utc::now(),
        },
    }
}

fn bootstrap_authority(
    fixture: &ExactPairFixture,
    pair: ParallelReconExactPairIssuanceAuthority,
) -> ParallelReconBootstrapAuthority {
    ParallelReconBootstrapAuthority {
        pair,
        starts: [
            start_authority(fixture.runtime_instance_id, 30),
            start_authority(fixture.runtime_instance_id, 31),
        ],
    }
}

fn default_bootstrap_authority(fixture: &ExactPairFixture) -> ParallelReconBootstrapAuthority {
    bootstrap_authority(fixture, fixture.authority.clone())
}

fn bootstrap_events(store: &Store, run_id: RunId) -> Vec<EventEnvelope> {
    store
        .events_for_run_after(run_id, 0)
        .expect("run history reads")
        .events
        .into_iter()
        .filter(|event| {
            matches!(
                event.payload,
                EventPayload::ChildDelegationAuthorizedV2(_)
                    | EventPayload::ChildWorkOrderIssued(_)
                    | EventPayload::ChildExecutionStarted(_)
            )
        })
        .collect()
}

fn appended_material(outcome: ParallelReconBootstrapOutcome) -> ParallelReconBootstrapMaterial {
    let ParallelReconBootstrapOutcome::Appended { material } = outcome else {
        panic!("fresh bootstrap appends")
    };
    material
}

pub(crate) fn bootstrap_default_exact_pair(
    fixture: &mut ExactPairFixture,
) -> ParallelReconBootstrapMaterial {
    let authority = default_bootstrap_authority(fixture);
    appended_material(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority)
            .expect("default exact-pair bootstrap commits"),
    )
}

#[test]
fn fresh_bootstrap_commits_exact_contiguous_six_and_store_derived_starts() {
    let mut fixture = default_exact_pair_fixture();
    let authority = default_bootstrap_authority(&fixture);
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());

    let material = appended_material(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority.clone())
            .expect("fresh bootstrap commits"),
    );
    let events = bootstrap_events(&fixture.store, fixture.run.id);
    assert_eq!(events.len(), 6);
    assert!(
        events
            .windows(2)
            .all(|pair| { pair[0].sequence.checked_add(1) == Some(pair[1].sequence) })
    );
    assert!(matches!(
        events[0].payload,
        EventPayload::ChildDelegationAuthorizedV2(_)
    ));
    assert!(matches!(
        events[1].payload,
        EventPayload::ChildDelegationAuthorizedV2(_)
    ));
    assert!(matches!(
        events[2].payload,
        EventPayload::ChildWorkOrderIssued(_)
    ));
    assert!(matches!(
        events[3].payload,
        EventPayload::ChildWorkOrderIssued(_)
    ));
    assert!(matches!(
        events[4].payload,
        EventPayload::ChildExecutionStarted(_)
    ));
    assert!(matches!(
        events[5].payload,
        EventPayload::ChildExecutionStarted(_)
    ));

    for index in 0..2 {
        let child = &material.children[index];
        assert_eq!(child.started_event.id, authority.starts[index].event_id);
        assert_eq!(
            child.authorization_event.id,
            authority.pair.children[index].authorization_event_id
        );
        assert_eq!(
            child.issuance_event.id,
            authority.pair.children[index].issuance_event_id
        );
        assert!(child.projection.spec.run_deadline.is_some());
        assert!(matches!(
            child.projection.recovery,
            ChildRecoveryState::ReadyForModel
        ));
        let EventPayload::ChildExecutionStarted(started) = &child.started_event.payload else {
            panic!("start event stays typed")
        };
        assert_eq!(
            started.binding.work_order_id,
            child.projection.spec.work_order_id
        );
        assert_eq!(
            started.binding.execution_id,
            child.projection.spec.execution_id
        );
        assert_eq!(
            started.binding.attempt_id,
            authority.starts[index].attempt_id
        );
        assert_eq!(started.local_plan_id, authority.starts[index].local_plan_id);
        assert_eq!(started.backend_model, child.projection.spec.resolved_model);
        assert_eq!(started.model_lineage, child.projection.spec.model_lineage);
        assert_eq!(
            child.started_event.actor_id,
            child.projection.spec.child_event_actor_id
        );
    }
}

#[test]
fn late_second_start_storage_failure_rolls_back_all_six_events() {
    let mut fixture = default_exact_pair_fixture();
    let authority = default_bootstrap_authority(&fixture);
    let identity_rows_before = fixture
        .store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_identity_projection",
            [],
            |row| row.get::<_, u64>(0),
        )
        .expect("identity row count reads");
    fixture
        .store
        .connection
        .execute_batch(
            "CREATE TEMP TRIGGER reject_second_bootstrap_start
             BEFORE INSERT ON events
             WHEN json_extract(NEW.value_json, '$.payload.type') = 'child_execution_started'
              AND (
                  SELECT COUNT(*) FROM events
                  WHERE run_id = NEW.run_id
                    AND json_extract(value_json, '$.payload.type') = 'child_execution_started'
              ) = 1
             BEGIN
                 SELECT RAISE(ABORT, 'injected second-start failure');
             END;",
        )
        .expect("test-only failure trigger installs");

    assert!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority)
            .is_err()
    );
    assert!(
        bootstrap_events(&fixture.store, fixture.run.id).is_empty(),
        "the first five inserts must roll back with the rejected sixth"
    );
    let identity_rows_after = fixture
        .store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_identity_projection",
            [],
            |row| row.get::<_, u64>(0),
        )
        .expect("identity row count re-reads");
    assert_eq!(identity_rows_after, identity_rows_before);
}

#[test]
fn exact_replay_and_reopen_return_the_original_complete_bundle() {
    let mut fixture = default_exact_pair_fixture();
    let authority = default_bootstrap_authority(&fixture);
    let run_id = fixture.run.id;
    let accepted_event_id = fixture.accepted_event.id;
    let session_id = fixture.session.id;
    let actor_id = fixture.actor_id;
    let appended = appended_material(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(run_id, authority.clone())
            .expect("bootstrap appends"),
    );
    let database = fixture.database.clone();
    let artifacts = fixture.artifacts.clone();
    drop(fixture.store);

    let mut reopened = Store::open(database, artifacts).expect("Store reopens");
    let replay = reopened
        .bootstrap_parallel_recon_exact_pair(run_id, authority.clone())
        .expect("exact authority replay coalesces");
    let ParallelReconBootstrapOutcome::AlreadyPresent { material } = replay else {
        panic!("reopen replay is already present")
    };
    assert_eq!(material, appended);
    assert_eq!(
        reopened
            .recover_parallel_recon_bootstrap(run_id, accepted_event_id)
            .expect("bootstrap recovery replays")
            .expect("complete bootstrap exists"),
        appended
    );
    reopened
        .append_event(NewEvent {
            session_id,
            run_id: Some(run_id),
            actor_id,
            causal_parent: Some(material.children[1].started_event.id),
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: birdcode_protocol::CancellationRequestId::new(),
                cancellation_generation: 1,
            }),
        })
        .expect("later cancellation commits");
    let after_cancellation = reopened
        .bootstrap_parallel_recon_exact_pair(run_id, authority)
        .expect("exact committed bootstrap remains idempotent after cancellation");
    let ParallelReconBootstrapOutcome::AlreadyPresent { material: retried } = after_cancellation
    else {
        panic!("historical bootstrap remains already present")
    };
    for index in 0..2 {
        assert_eq!(
            retried.children[index].started_event.id,
            material.children[index].started_event.id
        );
    }
    assert_eq!(bootstrap_events(&reopened, run_id).len(), 6);
}

#[test]
fn legacy_issue_only_history_fails_closed() {
    let mut fixture = default_exact_pair_fixture();
    let authority = default_bootstrap_authority(&fixture);
    assert!(matches!(
        fixture
            .store
            .issue_parallel_recon_exact_pair(fixture.run.id, fixture.authority.clone())
            .expect("test-only legacy issue commits"),
        ParallelReconExactPairIssuanceOutcome::Appended { .. }
    ));
    assert_eq!(bootstrap_events(&fixture.store, fixture.run.id).len(), 4);
    assert!(matches!(
        fixture
            .store
            .recover_parallel_recon_bootstrap(fixture.run.id, fixture.accepted_event.id,),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::InvalidStateEvent)
    ));
    assert_eq!(bootstrap_events(&fixture.store, fixture.run.id).len(), 4);
}

#[test]
fn concurrent_different_authorities_commit_one_complete_winner() {
    let fixture = default_exact_pair_fixture();
    let first = default_bootstrap_authority(&fixture);
    let mut second_pair = exact_pair_identity_authority();
    second_pair.accepted_planner_turn_event_id = fixture.accepted_event.id;
    second_pair.snapshot_lease_event_id = fixture.lease_event.id;
    let second = bootstrap_authority(&fixture, second_pair);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = [first, second]
        .into_iter()
        .map(|authority| {
            let barrier = std::sync::Arc::clone(&barrier);
            let database = fixture.database.clone();
            let artifacts = fixture.artifacts.clone();
            let run_id = fixture.run.id;
            std::thread::spawn(move || {
                let mut store = Store::open(database, artifacts).expect("concurrent Store opens");
                barrier.wait();
                store.bootstrap_parallel_recon_exact_pair(run_id, authority)
            })
        })
        .collect::<Vec<_>>();
    let database = fixture.database.clone();
    let artifacts = fixture.artifacts.clone();
    let run_id = fixture.run.id;
    let accepted_event_id = fixture.accepted_event.id;
    drop(fixture.store);
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().expect("caller does not panic"))
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );

    let reopened = Store::open(database, artifacts).expect("winner Store reopens");
    assert_eq!(bootstrap_events(&reopened, run_id).len(), 6);
    assert!(
        reopened
            .recover_parallel_recon_bootstrap(run_id, accepted_event_id)
            .expect("winner history is valid")
            .is_some()
    );
}

#[test]
fn cancellation_before_bootstrap_commits_no_child_events() {
    let mut fixture = default_exact_pair_fixture();
    let authority = default_bootstrap_authority(&fixture);
    fixture
        .store
        .append_event(NewEvent {
            session_id: fixture.session.id,
            run_id: Some(fixture.run.id),
            actor_id: fixture.actor_id,
            causal_parent: Some(fixture.lease_event.id),
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: birdcode_protocol::CancellationRequestId::new(),
                cancellation_generation: 1,
            }),
        })
        .expect("cancellation commits before bootstrap");

    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
}

#[test]
fn zero_start_clock_commits_nothing() {
    let mut fixture = default_exact_pair_fixture();
    let mut authority = default_bootstrap_authority(&fixture);
    authority.starts[0].started_at.monotonic_nanos = 0;
    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
}

#[test]
fn start_clock_before_real_claim_renewal_commits_nothing() {
    let mut fixture = default_exact_pair_fixture();
    let authority = default_bootstrap_authority(&fixture);
    let latest_start = authority
        .starts
        .iter()
        .map(|start| start.started_at.observed_at)
        .max()
        .expect("exact pair has starts");
    let renewed_at = latest_start + chrono::Duration::milliseconds(1);
    while Utc::now() < renewed_at {
        std::thread::yield_now();
    }
    let actor_id = fixture.actor_id;
    let runtime_instance_id = fixture.runtime_instance_id;
    let renewed = append_fixture_claim_at(
        &mut fixture,
        actor_id,
        runtime_instance_id,
        renewed_at,
        renewed_at + chrono::Duration::minutes(20),
    );
    assert!(
        authority
            .starts
            .iter()
            .all(|start| start.started_at.observed_at < renewed.occurred_at)
    );
    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
}

#[test]
fn elapsed_store_derived_deadline_commits_nothing() {
    let mut fixture = exact_pair_fixture_at(
        vec![
            exact_pair_planned_work_order("left", "Inspect the left boundary"),
            exact_pair_planned_work_order("right", "Inspect the right boundary"),
        ],
        "/tmp/birdcode-source",
        0,
    );
    let authority = default_bootstrap_authority(&fixture);
    let deadline = expected_run_deadline(&fixture.run)
        .expect("deadline derives")
        .expect("fixture has a deadline");
    assert!(deadline <= Utc::now());
    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
}

#[test]
fn closed_snapshot_lease_commits_nothing() {
    let mut fixture = default_exact_pair_fixture();
    let runtime_instance_id = fixture.runtime_instance_id;
    let release = snapshot_release_event(
        &mut fixture,
        RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos: 100,
            observed_at: Utc::now(),
        },
    );
    fixture
        .store
        .append_event(release)
        .expect("snapshot release closes the active lease");
    assert!(matches!(
        fixture
            .store
            .repository_snapshot_lifecycle(fixture.run.id)
            .expect("closed snapshot replays"),
        RepositorySnapshotLifecycleProjection::ClosedLease { .. }
    ));
    let authority = default_bootstrap_authority(&fixture);
    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
}

#[test]
fn clean_identity_collision_commits_nothing() {
    let mut fixture = default_exact_pair_fixture();
    let mut authority = default_bootstrap_authority(&fixture);
    authority.starts[0].event_id = fixture.lease_event.id;
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::IdentifiedEventConflict | StoreError::InvalidStateEvent)
    ));
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
}

#[test]
fn nil_pair_identity_commits_nothing() {
    let mut fixture = default_exact_pair_fixture();
    let mut authority = default_bootstrap_authority(&fixture);
    authority.pair.children[0].work_order_id = ChildWorkOrderId::from_uuid(uuid::Uuid::nil());
    assert!(matches!(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(fixture.run.id, authority),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(bootstrap_events(&fixture.store, fixture.run.id).is_empty());
}

#[test]
fn public_append_paths_cannot_start_another_parallel_recon_attempt() {
    let mut fixture = default_exact_pair_fixture();
    let material = appended_material(
        fixture
            .store
            .bootstrap_parallel_recon_exact_pair(
                fixture.run.id,
                default_bootstrap_authority(&fixture),
            )
            .expect("bootstrap commits"),
    );
    let started = &material.children[0].started_event;
    assert!(matches!(
        fixture.store.append_event(new_event_from_envelope(started)),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        fixture.store.append_identified_event(IdentifiedNewEvent {
            event_id: EventId::new(),
            event: new_event_from_envelope(started),
        }),
        Err(StoreError::InvalidStateEvent)
    ));
    assert_eq!(bootstrap_events(&fixture.store, fixture.run.id).len(), 6);
}
