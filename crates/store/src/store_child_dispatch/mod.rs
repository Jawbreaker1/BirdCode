//! Store-owned child effect dispatch and public replay projection types.

mod model;
mod projection_types;
mod recovery;
mod replay;
mod tool;
mod tool_start;

pub(super) const CHILD_TOOL_DISPATCH_START_PRODUCER: &str =
    "birdcode-store-child-repository-tool-dispatch-start-v1";

pub use model::{
    ChildModelDispatchHandoff, ChildModelDispatchPreparationOutcome, ChildModelPreparedEvidence,
};
pub use projection_types::{
    ChildPendingEffectProjection, ChildRecoveryState, ChildSuppliedResultProjection,
};
pub(super) use recovery::{
    child_claim_matches, child_history, child_recovery_state, durable_run_for_claim_refresh,
    load_child_replay, nonterminal_child_replays_for_claim_refresh, project_child_work_order,
    work_order_for_execution,
};
pub(super) use replay::{
    PendingChildTool, PendingChildToolAuthorization, replay_child_tool_dispatch_started_v2,
    replay_child_tool_observed_v2, replay_child_tool_prepared_v2, replay_child_tool_unknown_v2,
};
pub(crate) use tool::repository_broker_epoch_identity_is_unused;
pub use tool::{
    ChildRepositoryExplorerToolPreparationAuthority, ChildRepositoryToolLane,
    ChildToolDispatchError, ChildToolDispatchHandoff, ChildToolDispatchPreparationOutcome,
    ChildToolPreparedEvidence,
};
pub use tool_start::{
    ChildRepositoryExplorerToolDispatchStartAuthority, ChildToolDispatchRecovery,
    ChildToolDispatchStartError, ChildToolDispatchStartOutcome, ChildToolDispatchStartRejection,
    ChildToolDispatchStartedEvidence, ChildToolExecutionHandoff,
};
