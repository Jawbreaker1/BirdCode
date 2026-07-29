use super::*;
use crate::{
    ChildToolDispatchPreparationOutcome, EventEnvelope, IdentifiedNewEvent, NewEvent,
    ParallelReconClaimRefreshAuthority, ParallelReconClaimRefreshOutcome,
    RepositorySnapshotCaptureClaimAdoptionId, Store, StoreError, TransactionBehavior,
    latest_broker_epoch_before, latest_claim_for_run, latest_run_event, load_event_by_id,
    new_event_from_envelope,
    store_child_dispatch::tool::tests::{
        ReadyToolFixture, clock, mock_lane, provenance, ready_tool_fixture, tool_authority,
    },
};
use birdcode_protocol::{
    ActorId, CancellationRequestId, CancellationRequested, ChildClaimAdoptionId, EventId,
    EventPayload, RepositoryBrokerEpochActivatedV1, RepositoryBrokerEpochStateV1,
    RepositoryBrokerInstanceId, RunClaimed, RuntimeInstanceId,
};
use chrono::Utc;
use std::sync::{Arc, Barrier};

struct PreparedFixture {
    ready: ReadyToolFixture,
    evidence: ChildToolPreparedEvidence,
    dispatch: ChildToolDispatchHandoff,
}

fn prepared_fixture() -> PreparedFixture {
    let mut ready = ready_tool_fixture();
    let (lane, _) = mock_lane(ready.receipt_authority.clone(), ready.epoch.clone(), false);
    let outcome = ready
        .fixture
        .store
        .prepare_child_repository_explorer_tool_dispatch(
            ready.fixture.run.id,
            ready.work_order_id,
            tool_authority(ready.fixture.runtime_instance_id),
            &lane,
        )
        .expect("tool preparation commits");
    let ChildToolDispatchPreparationOutcome::Appended { evidence, dispatch } = outcome else {
        panic!("fixture preparation is fresh");
    };
    PreparedFixture {
        ready,
        evidence,
        dispatch,
    }
}

/// Fabricates a private duplicate solely to exercise defense against an
/// impossible public duplicate, internal race, or wiring defect.
fn duplicate_dispatch_for_internal_defense(
    dispatch: &ChildToolDispatchHandoff,
) -> ChildToolDispatchHandoff {
    ChildToolDispatchHandoff {
        material: Box::new(ChildToolDispatchMaterial {
            prepared_event: dispatch.material.prepared_event.clone(),
            prepared: dispatch.material.prepared.clone(),
            lane: dispatch.material.lane.clone(),
        }),
    }
}

fn assert_exact_started_payload(
    started_event: &EventEnvelope,
    prepared_event: &EventEnvelope,
    authority: &ChildRepositoryExplorerToolDispatchStartAuthority,
    claim_event: &EventEnvelope,
    epoch_event: &EventEnvelope,
) {
    let EventPayload::ChildToolPreparedV2(prepared) = &prepared_event.payload else {
        panic!("fixture Prepared remains typed");
    };
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        panic!("fixture claim remains typed");
    };
    let EventPayload::RepositoryBrokerEpochActivatedV1(epoch) = &epoch_event.payload else {
        panic!("fixture epoch remains typed");
    };
    let EventPayload::ChildToolDispatchStartedV2(started) = &started_event.payload else {
        panic!("persisted start remains typed");
    };
    assert_eq!(started_event.id, authority.event_id);
    assert_eq!(started_event.session_id, prepared_event.session_id);
    assert_eq!(started_event.run_id, prepared_event.run_id);
    assert_eq!(started_event.actor_id, prepared_event.actor_id);
    assert_eq!(started_event.causal_parent, Some(prepared_event.id));
    assert_eq!(
        started_event.provenance.producer,
        CHILD_TOOL_DISPATCH_START_PRODUCER
    );
    assert_eq!(
        started_event.provenance.backend,
        prepared_event.provenance.backend
    );
    assert!(started_event.provenance.raw_artifact.is_none());
    assert_eq!(started.binding, prepared.binding);
    assert_eq!(started.tool_call_id, prepared.tool_call_id);
    assert_eq!(started.prepared_event_id, prepared_event.id);
    assert_eq!(started.action_binding, prepared.action_binding);
    assert_eq!(
        started.prepared_receipt_digest,
        prepared.prepared_receipt_digest
    );
    assert_eq!(started.claim_event_id, claim_event.id);
    assert_eq!(started.claim_id, claim.claim_id);
    assert_eq!(started.claim_generation, claim.claim_generation);
    assert_eq!(started.runtime_instance_id, claim.runtime_instance_id);
    assert_eq!(
        started.cancellation_generation,
        claim.cancellation_generation
    );
    assert_eq!(started.broker_epoch_activation_event_id, epoch_event.id);
    assert_eq!(
        started.broker_instance_id,
        epoch.state.active_broker_instance_id
    );
    assert_eq!(started.broker_instance_id, prepared.broker_instance_id);
    assert_eq!(started.started_at, authority.started_at);
}

fn start_authority(
    runtime_instance_id: RuntimeInstanceId,
    monotonic_nanos: u64,
) -> ChildRepositoryExplorerToolDispatchStartAuthority {
    ChildRepositoryExplorerToolDispatchStartAuthority {
        event_id: EventId::new(),
        started_at: clock(runtime_instance_id, monotonic_nanos),
    }
}

fn refresh_authority(
    ready: &ReadyToolFixture,
    runtime_instance_id: RuntimeInstanceId,
) -> ParallelReconClaimRefreshAuthority {
    let now = Utc::now();
    let current_claim = latest_claim_for_run(
        &ready.fixture.store.connection,
        ready.fixture.run.spec.session_id,
        ready.fixture.run.id,
    )
    .expect("claim lookup succeeds")
    .expect("claim exists");
    let EventPayload::RunClaimed(current_claim) = current_claim.payload else {
        panic!("latest claim remains typed");
    };
    let fresh_through = std::cmp::max(
        now + chrono::Duration::minutes(20),
        current_claim.lease_expires_at + chrono::Duration::seconds(1),
    );
    ParallelReconClaimRefreshAuthority {
        actor_id: ready.fixture.actor_id,
        runtime_instance_id,
        renewal_claim_id: birdcode_protocol::RunClaimId::new(),
        snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
        child_adoption_ids: [ChildClaimAdoptionId::new(), ChildClaimAdoptionId::new()],
        refreshed_at: clock(runtime_instance_id, 70),
        fresh_through,
        renewed_lease_expires_at: fresh_through + chrono::Duration::minutes(10),
    }
}

fn assert_recovery_and_public_rejection(
    ready: &mut ReadyToolFixture,
    prepared: &ChildToolPreparedEvidence,
    evidence: &ChildToolDispatchStartedEvidence,
) {
    let recovery = ready
        .fixture
        .store
        .recover_child_repository_explorer_tool_dispatch(ready.fixture.run.id, ready.work_order_id)
        .expect("started recovery validates")
        .expect("pending tool remains");
    assert_eq!(&recovery.prepared, prepared);
    assert_eq!(recovery.started, Some(evidence.clone()));
    let reopened =
        Store::open(&ready.fixture.database, &ready.fixture.artifacts).expect("Store reopens");
    assert_eq!(
        reopened
            .recover_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
            )
            .expect("reopened replay validates")
            .expect("started tool remains pending")
            .started,
        Some(evidence.clone())
    );
    let public_event = new_event_from_envelope(&evidence.started_event);
    assert!(matches!(
        ready.fixture.store.append_event(public_event.clone()),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        ready
            .fixture
            .store
            .append_identified_event(IdentifiedNewEvent {
                event_id: evidence.started_event.id,
                event: public_event.clone(),
            }),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        ready
            .fixture
            .store
            .append_event_before_deadline(public_event, Utc::now() + chrono::Duration::minutes(1),),
        Err(StoreError::InvalidStateEvent)
    ));
}

#[test]
fn fresh_start_reopens_as_evidence_only_and_exact_retry_never_reissues_authority() {
    fn assert_send_static<T: Send + 'static>() {}

    assert_send_static::<ChildToolExecutionHandoff>();
    assert_eq!(
        std::mem::size_of::<ChildToolExecutionHandoff>(),
        std::mem::size_of::<usize>()
    );
    let mut fixture = prepared_fixture();
    let retry_dispatch = duplicate_dispatch_for_internal_defense(&fixture.dispatch);
    let poisoned_lane_dispatch = duplicate_dispatch_for_internal_defense(&fixture.dispatch);
    let poisoned_lane = poisoned_lane_dispatch.material.lane.clone();
    let authority = start_authority(fixture.ready.fixture.runtime_instance_id, 70);
    let claim_event = latest_claim_for_run(
        &fixture.ready.fixture.store.connection,
        fixture.ready.fixture.run.spec.session_id,
        fixture.ready.fixture.run.id,
    )
    .expect("claim lookup succeeds")
    .expect("claim exists");
    let epoch_event = latest_broker_epoch_before(
        &fixture.ready.fixture.store.connection,
        fixture.ready.fixture.run.spec.session_id,
        fixture.ready.fixture.run.id,
        MAX_SQLITE_INTEGER_U64,
    )
    .expect("epoch lookup succeeds")
    .expect("epoch exists");
    let outcome = fixture
        .ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(authority.clone(), fixture.dispatch)
        .expect("fresh start commits");
    let ChildToolDispatchStartOutcome::Appended {
        evidence,
        execution,
    } = outcome
    else {
        panic!("fresh start returns opaque execution authority");
    };
    assert_exact_started_payload(
        &evidence.started_event,
        &fixture.evidence.prepared_event,
        &authority,
        &claim_event,
        &epoch_event,
    );
    assert_eq!(execution.started_event(), evidence.started_event.as_ref());
    assert_eq!(
        execution.broker_instance_id(),
        fixture.ready.epoch.active_broker_instance_id
    );
    drop(execution);

    let replay = fixture
        .ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(authority.clone(), retry_dispatch)
        .expect("exact start retry converges");
    let ChildToolDispatchStartOutcome::AlreadyPresent {
        evidence: replay_evidence,
    } = replay
    else {
        panic!("exact retry is evidence-only");
    };
    assert_eq!(replay_evidence, evidence);

    assert!(
        std::thread::spawn(move || {
            let mut state = poisoned_lane
                .inner
                .publication
                .lock()
                .expect("fixture lane starts available");
            *state = ToolLaneState::Tainted;
            panic!("fixture poisons the tainted lane");
        })
        .join()
        .is_err()
    );
    assert!(matches!(
        fixture
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(authority, poisoned_lane_dispatch),
        Ok(ChildToolDispatchStartOutcome::AlreadyPresent {
            evidence: poisoned_evidence
        }) if poisoned_evidence == evidence
    ));

    assert_recovery_and_public_rejection(&mut fixture.ready, &fixture.evidence, &evidence);
}

#[test]
fn invalid_clock_rolls_back_and_returns_the_same_affine_dispatch_for_retry() {
    let mut fixture = prepared_fixture();
    let authority = start_authority(fixture.ready.fixture.runtime_instance_id, 59);
    let Err(error) = fixture
        .ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(authority.clone(), fixture.dispatch)
    else {
        panic!("clock before Prepared is rejected");
    };
    let (_, dispatch) = error
        .into_rejected()
        .expect("proven rollback preserves authority");
    let retry = ChildRepositoryExplorerToolDispatchStartAuthority {
        event_id: authority.event_id,
        started_at: clock(fixture.ready.fixture.runtime_instance_id, 70),
    };
    assert!(matches!(
        fixture
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(retry, dispatch),
        Ok(ChildToolDispatchStartOutcome::Appended { .. })
    ));
}

#[test]
fn writer_lock_is_a_safe_precommit_rejection_and_same_dispatch_retries() {
    let mut fixture = prepared_fixture();
    let authority = start_authority(fixture.ready.fixture.runtime_instance_id, 70);
    let mut blocker = Store::open(
        &fixture.ready.fixture.database,
        &fixture.ready.fixture.artifacts,
    )
    .expect("second Store opens");
    fixture
        .ready
        .fixture
        .store
        .connection
        .busy_timeout(std::time::Duration::ZERO)
        .expect("fixture disables busy waiting");
    let blocker_transaction = blocker
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("second Store owns the writer lock");
    let Err(error) = fixture
        .ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(authority.clone(), fixture.dispatch)
    else {
        panic!("writer lock rejects before any commit attempt");
    };
    let (reason, dispatch) = error
        .into_rejected()
        .expect("safe transaction-open failure preserves dispatch");
    assert!(matches!(reason, ChildToolDispatchStartRejection::Store(_)));
    blocker_transaction
        .rollback()
        .expect("fixture writer lock releases");
    assert!(matches!(
        fixture
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(authority, dispatch),
        Ok(ChildToolDispatchStartOutcome::Appended { .. })
    ));
}

#[test]
fn event_insert_fault_rolls_back_and_same_dispatch_retries() {
    let mut fixture = prepared_fixture();
    let authority = start_authority(fixture.ready.fixture.runtime_instance_id, 70);
    fixture
        .ready
        .fixture
        .store
        .connection
        .execute_batch(
            "CREATE TEMP TRIGGER child_tool_start_insert_fault
             BEFORE INSERT ON events BEGIN
                 SELECT RAISE(ABORT, 'fixture child tool start insert fault');
             END;",
        )
        .expect("fixture insert fault installs");
    let Err(error) = fixture
        .ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(authority.clone(), fixture.dispatch)
    else {
        panic!("injected event insert aborts");
    };
    let (_, dispatch) = error
        .into_rejected()
        .expect("rolled-back insert preserves dispatch");
    assert!(
        load_event_by_id(&fixture.ready.fixture.store.connection, authority.event_id)
            .expect("event identity remains readable")
            .is_none()
    );
    fixture
        .ready
        .fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER child_tool_start_insert_fault;")
        .expect("fixture insert fault removes");
    assert!(matches!(
        fixture
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(authority, dispatch),
        Ok(ChildToolDispatchStartOutcome::Appended { .. })
    ));
}

#[test]
fn concurrent_stores_converge_to_one_start_and_one_execution_authority() {
    let fixture = prepared_fixture();
    let competing_dispatch = duplicate_dispatch_for_internal_defense(&fixture.dispatch);
    let authority = start_authority(fixture.ready.fixture.runtime_instance_id, 70);
    let claim_event = latest_claim_for_run(
        &fixture.ready.fixture.store.connection,
        fixture.ready.fixture.run.spec.session_id,
        fixture.ready.fixture.run.id,
    )
    .expect("claim lookup succeeds")
    .expect("claim exists");
    let epoch_event = latest_broker_epoch_before(
        &fixture.ready.fixture.store.connection,
        fixture.ready.fixture.run.spec.session_id,
        fixture.ready.fixture.run.id,
        MAX_SQLITE_INTEGER_U64,
    )
    .expect("epoch lookup succeeds")
    .expect("epoch exists");
    let left_store = Store::open(
        &fixture.ready.fixture.database,
        &fixture.ready.fixture.artifacts,
    )
    .expect("left Store opens");
    let right_store = Store::open(
        &fixture.ready.fixture.database,
        &fixture.ready.fixture.artifacts,
    )
    .expect("right Store opens");
    let barrier = Arc::new(Barrier::new(2));
    let left_barrier = Arc::clone(&barrier);
    let left_authority = authority.clone();
    let left = std::thread::spawn(move || {
        let mut store = left_store;
        left_barrier.wait();
        match store.start_child_repository_explorer_tool_dispatch(left_authority, fixture.dispatch)
        {
            Ok(ChildToolDispatchStartOutcome::Appended {
                evidence,
                execution,
            }) => {
                assert_eq!(execution.started_event(), evidence.started_event.as_ref());
                drop(execution);
                (true, evidence.started_event.id)
            }
            Ok(ChildToolDispatchStartOutcome::AlreadyPresent { evidence }) => {
                (false, evidence.started_event.id)
            }
            Err(error) => panic!("left start converges: {error:?}"),
        }
    });
    let right_authority = authority.clone();
    let right = std::thread::spawn(move || {
        let mut store = right_store;
        barrier.wait();
        match store
            .start_child_repository_explorer_tool_dispatch(right_authority, competing_dispatch)
        {
            Ok(ChildToolDispatchStartOutcome::Appended {
                evidence,
                execution,
            }) => {
                assert_eq!(execution.started_event(), evidence.started_event.as_ref());
                drop(execution);
                (true, evidence.started_event.id)
            }
            Ok(ChildToolDispatchStartOutcome::AlreadyPresent { evidence }) => {
                (false, evidence.started_event.id)
            }
            Err(error) => panic!("right start converges: {error:?}"),
        }
    });
    let left = left.join().expect("left start thread joins");
    let right = right.join().expect("right start thread joins");
    assert_ne!(left.0, right.0, "exactly one thread receives execution");
    assert_eq!(left.1, authority.event_id);
    assert_eq!(right.1, authority.event_id);
    let persisted = load_event_by_id(&fixture.ready.fixture.store.connection, authority.event_id)
        .expect("persisted start reads")
        .expect("one start exists");
    assert_exact_started_payload(
        &persisted,
        &fixture.evidence.prepared_event,
        &authority,
        &claim_event,
        &epoch_event,
    );
    let count: u64 = fixture
        .ready
        .fixture
        .store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE id = ?1",
            [authority.event_id.to_string()],
            |row| row.get(0),
        )
        .expect("persisted start count reads");
    assert_eq!(count, 1);
}

#[test]
fn cancellation_and_broker_rotation_destroy_stale_start_authority() {
    let mut cancelled = prepared_fixture();
    cancelled
        .ready
        .fixture
        .store
        .append_event(NewEvent {
            session_id: cancelled.ready.fixture.run.spec.session_id,
            run_id: Some(cancelled.ready.fixture.run.id),
            actor_id: cancelled.ready.fixture.actor_id,
            causal_parent: Some(cancelled.evidence.prepared_event.id),
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: CancellationRequestId::new(),
                cancellation_generation: 1,
            }),
        })
        .expect("cancellation persists");
    assert!(matches!(
        cancelled
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(
                start_authority(cancelled.ready.fixture.runtime_instance_id, 70),
                cancelled.dispatch,
            ),
        Err(ChildToolDispatchStartError::NoLongerStartable(_))
    ));

    let mut rotated = prepared_fixture();
    let next_epoch = RepositoryBrokerEpochStateV1 {
        active_broker_instance_id: RepositoryBrokerInstanceId::new(),
        closed_broker_instance_ids: vec![rotated.ready.epoch.active_broker_instance_id],
    };
    rotated
        .ready
        .fixture
        .store
        .append_event(NewEvent {
            session_id: rotated.ready.fixture.run.spec.session_id,
            run_id: Some(rotated.ready.fixture.run.id),
            actor_id: rotated.ready.fixture.actor_id,
            causal_parent: Some(rotated.evidence.prepared_event.id),
            provenance: provenance(),
            payload: EventPayload::RepositoryBrokerEpochActivatedV1(
                RepositoryBrokerEpochActivatedV1 {
                    previous_active_broker_instance_id: Some(
                        rotated.ready.epoch.active_broker_instance_id,
                    ),
                    state: next_epoch,
                    activated_at: clock(rotated.ready.fixture.runtime_instance_id, 70),
                },
            ),
        })
        .expect("replacement epoch persists");
    assert!(matches!(
        rotated
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(
                start_authority(rotated.ready.fixture.runtime_instance_id, 80),
                rotated.dispatch,
            ),
        Err(ChildToolDispatchStartError::NoLongerStartable(_))
    ));
}

#[test]
fn contiguous_same_runtime_renewal_can_start() {
    let mut renewed = prepared_fixture();
    let refresh = refresh_authority(&renewed.ready, renewed.ready.fixture.runtime_instance_id);
    assert!(matches!(
        renewed
            .ready
            .fixture
            .store
            .refresh_parallel_recon_claim(renewed.ready.fixture.run.id, refresh),
        Ok(ParallelReconClaimRefreshOutcome::Renewed { .. })
    ));
    assert!(matches!(
        renewed
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(
                start_authority(renewed.ready.fixture.runtime_instance_id, 80),
                renewed.dispatch,
            ),
        Ok(ChildToolDispatchStartOutcome::Appended { .. })
    ));
}

#[test]
fn cross_runtime_takeover_cannot_start_prepared_dispatch() {
    let mut takeover = prepared_fixture();
    let mut prior = latest_claim_for_run(
        &takeover.ready.fixture.store.connection,
        takeover.ready.fixture.run.spec.session_id,
        takeover.ready.fixture.run.id,
    )
    .expect("claim lookup succeeds")
    .expect("claim exists");
    let historical_tail = latest_run_event(
        &takeover.ready.fixture.store.connection,
        takeover.ready.fixture.run.spec.session_id,
        takeover.ready.fixture.run.id,
    )
    .expect("historical tail reads");
    let EventPayload::RunClaimed(RunClaimed {
        lease_expires_at, ..
    }) = &mut prior.payload
    else {
        panic!("latest claim stays typed");
    };
    *lease_expires_at = historical_tail.occurred_at + chrono::Duration::nanoseconds(1);
    assert!(*lease_expires_at < Utc::now());
    takeover
        .ready
        .fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER events_are_immutable_on_update;")
        .expect("fixture may model an expired durable claim");
    takeover
        .ready
        .fixture
        .store
        .connection
        .execute(
            "UPDATE events SET value_json = ?1 WHERE id = ?2",
            rusqlite::params![
                serde_json::to_string(&prior).expect("claim encodes"),
                prior.id.to_string()
            ],
        )
        .expect("fixture claim expiry persists");
    let replacement_runtime = RuntimeInstanceId::new();
    let replacement_actor = ActorId::new();
    let EventPayload::RunClaimed(prior_claim) = &prior.payload else {
        panic!("expired claim remains typed");
    };
    let takeover_parent = latest_run_event(
        &takeover.ready.fixture.store.connection,
        takeover.ready.fixture.run.spec.session_id,
        takeover.ready.fixture.run.id,
    )
    .expect("takeover parent reads");
    takeover
        .ready
        .fixture
        .store
        .append_event(NewEvent {
            session_id: takeover.ready.fixture.run.spec.session_id,
            run_id: Some(takeover.ready.fixture.run.id),
            actor_id: replacement_actor,
            causal_parent: Some(takeover_parent.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: birdcode_protocol::RunClaimId::new(),
                runtime_instance_id: replacement_runtime,
                claim_generation: prior_claim
                    .claim_generation
                    .checked_add(1)
                    .expect("claim generation increments"),
                cancellation_generation: prior_claim.cancellation_generation,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        })
        .expect("expired claim admits a replacement owner");
    assert!(matches!(
        takeover
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(
                start_authority(replacement_runtime, 80),
                takeover.dispatch,
            ),
        Err(ChildToolDispatchStartError::NoLongerStartable(_))
    ));
}

#[test]
fn a_second_start_identity_or_corrupt_replay_never_returns_old_authority() {
    let mut fixture = prepared_fixture();
    let other_id_dispatch = duplicate_dispatch_for_internal_defense(&fixture.dispatch);
    let corrupt_replay_dispatch = duplicate_dispatch_for_internal_defense(&fixture.dispatch);
    let authority = start_authority(fixture.ready.fixture.runtime_instance_id, 70);
    let outcome = fixture
        .ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(authority.clone(), fixture.dispatch)
        .expect("first start commits");
    let ChildToolDispatchStartOutcome::Appended { evidence, .. } = outcome else {
        panic!("first start is fresh");
    };

    assert!(matches!(
        fixture
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(
                start_authority(fixture.ready.fixture.runtime_instance_id, 71),
                other_id_dispatch,
            ),
        Err(ChildToolDispatchStartError::NoLongerStartable(_))
    ));

    let mut corrupted = (*evidence.started_event).clone();
    corrupted.provenance.producer = "forged-child-tool-dispatch-start".to_owned();
    fixture
        .ready
        .fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER events_are_immutable_on_update;")
        .expect("fixture may corrupt the producer");
    fixture
        .ready
        .fixture
        .store
        .connection
        .execute(
            "UPDATE events SET value_json = ?1 WHERE id = ?2",
            rusqlite::params![
                serde_json::to_string(&corrupted).expect("corrupt event encodes"),
                corrupted.id.to_string()
            ],
        )
        .expect("fixture producer corruption persists");
    assert!(matches!(
        fixture
            .ready
            .fixture
            .store
            .recover_child_repository_explorer_tool_dispatch(
                fixture.ready.fixture.run.id,
                fixture.ready.work_order_id,
            ),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        fixture
            .ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(authority, corrupt_replay_dispatch),
        Err(ChildToolDispatchStartError::NoLongerStartable(_))
    ));
}
