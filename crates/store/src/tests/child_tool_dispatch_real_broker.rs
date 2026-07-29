#![cfg(unix)]

use super::tests::{ready_tool_fixture, tool_authority};
use super::*;
use crate::tests::repository_tool_fixture::repository_root_path;

#[test]
fn public_real_broker_lane_commits_exact_prepared_boundary() {
    let mut ready = ready_tool_fixture();
    let broker = RepositoryToolBroker::open(
        repository_root_path(&ready.fixture.store),
        ready.receipt_authority.clone(),
        ready.epoch.clone(),
    )
    .expect("real descriptor-confined broker opens");
    let lane = ChildRepositoryToolLane::new(broker);
    let authority = tool_authority(ready.fixture.runtime_instance_id);
    let outcome = ready
        .fixture
        .store
        .prepare_child_repository_explorer_tool_dispatch(
            ready.fixture.run.id,
            ready.work_order_id,
            authority.clone(),
            &lane,
        )
        .expect("real broker preparation commits");
    let ChildToolDispatchPreparationOutcome::Appended { evidence, dispatch } = outcome else {
        panic!("fresh real broker preparation owns the affine handoff")
    };
    assert_eq!(evidence.prepared_event.id, authority.event_id);
    assert_eq!(dispatch.prepared_event(), &evidence.prepared_event);
    assert_eq!(
        dispatch.broker_instance_id(),
        ready.epoch.active_broker_instance_id
    );
    assert!(lane.is_healthy());
}
