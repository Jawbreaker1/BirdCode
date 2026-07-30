#![cfg(unix)]

use super::*;
use crate::store_child_dispatch::tool::tests::{
    ReadyToolFixture, clock, ready_tool_fixture, tool_authority,
};
use crate::tests::repository_tool_fixture::repository_root_path;
use crate::{
    ChildRecoveryState, ChildToolDispatchPreparationOutcome, ChildToolDispatchStartOutcome,
    EventPayload, IdentifiedNewEvent, Store, StoreError, TransactionBehavior, artifact_path_at,
    load_event_by_id, new_event_from_envelope, read_verified_artifact,
};
use birdcode_protocol::{
    ChildPreviousToolContextV1, EventId, RepositoryToolObservedTerminalV2, RepositoryToolResultV2,
    decode_repository_tool_result_v2,
};
use birdcode_tooling::RepositoryToolBroker;
use chrono::{Duration, Utc};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct StartedFixture {
    ready: ReadyToolFixture,
    lane: crate::ChildRepositoryToolLane,
    started: crate::ChildToolDispatchStartedEvidence,
    execution: crate::ChildToolExecutionHandoff,
}

fn started_fixture() -> StartedFixture {
    let mut ready = ready_tool_fixture();
    let broker = RepositoryToolBroker::open(
        repository_root_path(&ready.fixture.store),
        ready.receipt_authority.clone(),
        ready.epoch.clone(),
    )
    .expect("real descriptor-confined broker opens");
    let lane = crate::ChildRepositoryToolLane::new(broker);
    let prepared = ready
        .fixture
        .store
        .prepare_child_repository_explorer_tool_dispatch(
            ready.fixture.run.id,
            ready.work_order_id,
            tool_authority(ready.fixture.runtime_instance_id),
            &lane,
        )
        .expect("real broker preparation commits");
    let ChildToolDispatchPreparationOutcome::Appended { dispatch, .. } = prepared else {
        panic!("fixture preparation is fresh");
    };
    let started = ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(
            crate::ChildRepositoryExplorerToolDispatchStartAuthority {
                event_id: EventId::new(),
                started_at: clock(ready.fixture.runtime_instance_id, 70),
            },
            dispatch,
        )
        .expect("durable dispatch start commits");
    let ChildToolDispatchStartOutcome::Appended {
        evidence,
        execution,
    } = started
    else {
        panic!("fresh start releases execution authority");
    };
    StartedFixture {
        ready,
        lane,
        started: evidence,
        execution,
    }
}

fn execute_once(
    fixture: &mut Store,
    execution: crate::ChildToolExecutionHandoff,
    runtime_instance_id: birdcode_protocol::RuntimeInstanceId,
    callbacks: &Arc<AtomicU64>,
) -> crate::ChildToolObservedCommitHandoff {
    let callbacks = Arc::clone(callbacks);
    fixture
        .execute_child_repository_explorer_tool_dispatch(execution, move || {
            callbacks.fetch_add(1, Ordering::SeqCst);
            clock(runtime_instance_id, 80)
        })
        .expect("real descriptor-confined read completes")
}

fn assert_ready_for_model(
    store: &Store,
    run_id: birdcode_protocol::RunId,
    work_order_id: birdcode_protocol::ChildWorkOrderId,
    terminal_id: EventId,
) {
    let projection = store
        .child_work_order_projection(run_id, work_order_id)
        .expect("child replay succeeds")
        .expect("child projection exists");
    assert_eq!(projection.recovery, ChildRecoveryState::ReadyForModel);
    assert!(matches!(
        projection.previous_tool,
        Some(ChildPreviousToolContextV1::Observed {
            terminal_event_id,
            ..
        }) if terminal_event_id == terminal_id
    ));
    assert_eq!(
        projection
            .latest_effect_event
            .expect("known terminal is the latest effect")
            .id,
        terminal_id
    );
}

#[test]
fn real_started_tree_executes_commits_and_reopens_as_ready_for_model() {
    let StartedFixture {
        mut ready,
        lane,
        started,
        execution,
    } = started_fixture();
    let callbacks = Arc::new(AtomicU64::new(0));
    let observed = execute_once(
        &mut ready.fixture.store,
        execution,
        ready.fixture.runtime_instance_id,
        &callbacks,
    );
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    let terminal_receipt = observed.terminal_receipt_artifact().clone();
    let authority = ChildRepositoryExplorerToolObservedCommitAuthority {
        event_id: EventId::new(),
    };
    let outcome = ready
        .fixture
        .store
        .commit_child_repository_explorer_tool_observation(authority.clone(), observed)
        .expect("known terminal commits");
    let ChildToolObservedCommitOutcome::Appended { evidence } = outcome else {
        panic!("fresh known terminal appends");
    };
    assert_eq!(evidence.observed_event.id, authority.event_id);
    assert_eq!(
        evidence.observed_event.causal_parent,
        Some(started.started_event.id)
    );
    assert_eq!(
        evidence.observed_event.provenance.producer,
        CHILD_TOOL_OBSERVED_PRODUCER
    );
    assert_eq!(
        evidence.observed_event.provenance.raw_artifact,
        Some(terminal_receipt)
    );
    let EventPayload::ChildToolObservedV2(observed) = &evidence.observed_event.payload else {
        panic!("terminal event remains typed");
    };
    let RepositoryToolObservedTerminalV2::Succeeded { result_artifact } = &observed.terminal else {
        panic!("empty root tree succeeds");
    };
    let bytes = read_verified_artifact(
        &artifact_path_at(&ready.fixture.artifacts, &result_artifact.sha256)
            .expect("result path is valid"),
        result_artifact,
    )
    .expect("result artifact is retained");
    let RepositoryToolResultV2::RepositoryTree(tree) =
        decode_repository_tool_result_v2(&bytes).expect("result uses canonical Protocol codec")
    else {
        panic!("fixture action returns a tree");
    };
    assert!(tree.entries.is_empty());
    assert!(lane.is_healthy());
    assert_ready_for_model(
        &ready.fixture.store,
        ready.fixture.run.id,
        ready.work_order_id,
        authority.event_id,
    );
    assert!(
        ready
            .fixture
            .store
            .recover_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
            )
            .expect("terminal recovery lookup succeeds")
            .is_none()
    );
    let reopened =
        Store::open(&ready.fixture.database, &ready.fixture.artifacts).expect("Store reopens");
    assert_ready_for_model(
        &reopened,
        ready.fixture.run.id,
        ready.work_order_id,
        authority.event_id,
    );
}

#[test]
fn observed_insert_rollback_returns_same_result_without_reexecution() {
    let StartedFixture {
        mut ready,
        execution,
        ..
    } = started_fixture();
    let callbacks = Arc::new(AtomicU64::new(0));
    let observed = execute_once(
        &mut ready.fixture.store,
        execution,
        ready.fixture.runtime_instance_id,
        &callbacks,
    );
    let authority = ChildRepositoryExplorerToolObservedCommitAuthority {
        event_id: EventId::new(),
    };
    ready
        .fixture
        .store
        .connection
        .execute_batch(
            "CREATE TEMP TRIGGER child_tool_observed_insert_fault
             BEFORE INSERT ON events BEGIN
                 SELECT RAISE(ABORT, 'fixture child tool observed insert fault');
             END;",
        )
        .expect("fixture insert fault installs");
    let error = ready
        .fixture
        .store
        .commit_child_repository_explorer_tool_observation(authority.clone(), observed)
        .expect_err("injected event insert aborts");
    let (_, observed) = error
        .into_rejected()
        .expect("proven rollback preserves the known result");
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    assert!(
        load_event_by_id(&ready.fixture.store.connection, authority.event_id)
            .expect("event identity remains readable")
            .is_none()
    );
    ready
        .fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER child_tool_observed_insert_fault;")
        .expect("fixture insert fault removes");
    assert!(matches!(
        ready
            .fixture
            .store
            .commit_child_repository_explorer_tool_observation(authority, observed),
        Ok(ChildToolObservedCommitOutcome::Appended { .. })
    ));
    assert_eq!(
        callbacks.load(Ordering::SeqCst),
        1,
        "commit retry must never re-run the repository effect"
    );
}

#[test]
fn store_owned_observed_rejects_every_public_append_path_before_idempotency() {
    let StartedFixture {
        mut ready,
        execution,
        ..
    } = started_fixture();
    let callbacks = Arc::new(AtomicU64::new(0));
    let observed = execute_once(
        &mut ready.fixture.store,
        execution,
        ready.fixture.runtime_instance_id,
        &callbacks,
    );
    let authority = ChildRepositoryExplorerToolObservedCommitAuthority {
        event_id: EventId::new(),
    };
    let transaction = ready
        .fixture
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("fixture read transaction opens");
    let public_event =
        *derive_observed_event(&transaction, &ready.fixture.artifacts, observed.material())
            .expect("private terminal event derives");
    transaction
        .rollback()
        .expect("fixture derivation transaction rolls back");
    assert!(matches!(
        ready.fixture.store.append_event(public_event.clone()),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        ready
            .fixture
            .store
            .append_identified_event(IdentifiedNewEvent {
                event_id: authority.event_id,
                event: public_event.clone(),
            }),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        ready
            .fixture
            .store
            .append_event_before_deadline(public_event, Utc::now() + Duration::minutes(1),),
        Err(StoreError::InvalidStateEvent)
    ));
    let committed = ready
        .fixture
        .store
        .commit_child_repository_explorer_tool_observation(authority.clone(), observed)
        .expect("private terminal commit succeeds");
    let ChildToolObservedCommitOutcome::Appended { evidence } = committed else {
        panic!("private terminal is fresh");
    };
    assert!(matches!(
        ready
            .fixture
            .store
            .append_identified_event(IdentifiedNewEvent {
                event_id: authority.event_id,
                event: new_event_from_envelope(&evidence.observed_event),
            }),
        Err(StoreError::InvalidStateEvent)
    ));
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
}
