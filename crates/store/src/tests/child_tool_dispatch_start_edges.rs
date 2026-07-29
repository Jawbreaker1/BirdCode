use super::*;
use crate::{
    ChildToolDispatchHandoff, ChildToolDispatchPreparationOutcome, ChildToolPreparedEvidence,
    EventPayload, Store, StoreError, TransactionBehavior, latest_claim_for_run,
    store_child_dispatch::tool::tests::{
        ReadyToolFixture, clock, mock_lane, ready_tool_fixture, tool_authority,
    },
};
use birdcode_protocol::{EventId, RunClaimed};
use chrono::{Duration, Utc};

fn prepared_fixture() -> (
    ReadyToolFixture,
    ChildToolPreparedEvidence,
    ChildToolDispatchHandoff,
) {
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
    (ready, evidence, dispatch)
}

fn authority(
    event_id: EventId,
    ready: &ReadyToolFixture,
) -> ChildRepositoryExplorerToolDispatchStartAuthority {
    ChildRepositoryExplorerToolDispatchStartAuthority {
        event_id,
        started_at: clock(ready.fixture.runtime_instance_id, 70),
    }
}

#[test]
fn future_start_within_lease_returns_dispatch_and_valid_retry_succeeds() {
    let (mut ready, _, dispatch) = prepared_fixture();
    let claim_event = latest_claim_for_run(
        &ready.fixture.store.connection,
        ready.fixture.run.spec.session_id,
        ready.fixture.run.id,
    )
    .expect("claim lookup succeeds")
    .expect("claim exists");
    let EventPayload::RunClaimed(RunClaimed {
        lease_expires_at, ..
    }) = claim_event.payload
    else {
        panic!("latest claim remains typed");
    };
    let future_observation = Utc::now() + Duration::seconds(30);
    assert!(
        future_observation < lease_expires_at,
        "fixture future remains within the active lease"
    );
    let event_id = EventId::new();
    let mut future_authority = authority(event_id, &ready);
    future_authority.started_at.observed_at = future_observation;
    let Err(error) = ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(future_authority, dispatch)
    else {
        panic!("future runtime observation is rejected");
    };
    let (reason, dispatch) = error
        .into_rejected()
        .expect("pre-commit clock rejection preserves the affine dispatch");
    assert!(matches!(
        reason,
        ChildToolDispatchStartRejection::Store(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        ready
            .fixture
            .store
            .start_child_repository_explorer_tool_dispatch(authority(event_id, &ready), dispatch,),
        Ok(ChildToolDispatchStartOutcome::Appended { .. })
    ));
}

#[test]
fn replay_rejects_start_clock_after_its_durable_envelope() {
    let (mut ready, _, dispatch) = prepared_fixture();
    let start_authority = authority(EventId::new(), &ready);
    let outcome = ready
        .fixture
        .store
        .start_child_repository_explorer_tool_dispatch(start_authority, dispatch)
        .expect("valid start commits");
    let ChildToolDispatchStartOutcome::Appended {
        evidence,
        execution,
    } = outcome
    else {
        panic!("fixture start is fresh");
    };
    drop(execution);
    let mut corrupted = (*evidence.started_event).clone();
    let occurred_at = corrupted.occurred_at;
    let EventPayload::ChildToolDispatchStartedV2(started) = &mut corrupted.payload else {
        panic!("fixture start remains typed");
    };
    started.started_at.observed_at = occurred_at + Duration::nanoseconds(1);
    ready
        .fixture
        .store
        .connection
        .execute_batch("DROP TRIGGER events_are_immutable_on_update;")
        .expect("fixture may corrupt historical time");
    ready
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
        .expect("future historical clock persists");
    assert!(matches!(
        ready
            .fixture
            .store
            .recover_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
            ),
        Err(StoreError::InvalidStateEvent)
    ));
}

#[test]
fn tainted_lane_dominates_second_exact_identity_error() {
    let (mut ready, prepared, dispatch) = prepared_fixture();
    let lane = dispatch.material.lane.clone();
    let mut lane_guard = lane
        .inner
        .publication
        .lock()
        .expect("fixture lane is available");
    *lane_guard = ToolLaneState::Tainted;
    let start_authority = authority(prepared.prepared_event.id, &ready);
    let artifact_root = ready.fixture.artifacts.clone();
    assert!(matches!(
        start_missing_dispatch(
            &mut ready.fixture.store.connection,
            &artifact_root,
            &start_authority,
            dispatch,
            lane_guard,
        ),
        Err(ChildToolDispatchStartError::NoLongerStartable(
            ChildToolDispatchStartRejection::LaneRequiresReconciliation
        ))
    ));
}

#[test]
fn tainted_lane_dominates_immediate_transaction_open_error() {
    let (mut ready, _, dispatch) = prepared_fixture();
    let mut blocker =
        Store::open(&ready.fixture.database, &ready.fixture.artifacts).expect("second Store opens");
    ready
        .fixture
        .store
        .connection
        .busy_timeout(std::time::Duration::ZERO)
        .expect("fixture disables busy waiting");
    let blocker_transaction = blocker
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("second Store owns the writer lock");
    let lane = dispatch.material.lane.clone();
    let mut lane_guard = lane
        .inner
        .publication
        .lock()
        .expect("fixture lane is available");
    *lane_guard = ToolLaneState::Tainted;
    let start_authority = authority(EventId::new(), &ready);
    let artifact_root = ready.fixture.artifacts.clone();
    assert!(matches!(
        start_missing_dispatch(
            &mut ready.fixture.store.connection,
            &artifact_root,
            &start_authority,
            dispatch,
            lane_guard,
        ),
        Err(ChildToolDispatchStartError::NoLongerStartable(
            ChildToolDispatchStartRejection::LaneRequiresReconciliation
        ))
    ));
    blocker_transaction
        .rollback()
        .expect("fixture writer lock releases");
}
