//! Narrow runtime boundary for one repository-explorer child.
//!
//! Initial child admission belongs to Store's atomic exact-pair bootstrap.
//! The real child engine will be launched in parallel in the next bounded
//! slice. It must rederive work-order semantics, repository authority,
//! deadline, execution binding, and current claim from Store before every
//! model or tool effect.

#![allow(
    dead_code,
    reason = "the fail-closed child-engine interface lands before supervisor wiring"
)]

use crate::{
    model_call_scheduler::ModelCallScheduler,
    recon::{ReconModelProfile, ReconRuntimeClock},
    supervisor::{RunSupervisorConfig, SupervisorRunError},
};
use birdcode_backends::ModelBackend;
use birdcode_protocol::{ChildExecutionId, ChildWorkOrderId, EventEnvelope, EventId, RunId};
use birdcode_runtime::RuntimePaths;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Caller-owned mechanical handles for one child engine. Event and work-order
/// identities are Store lookup keys, not trusted copies of semantic content.
/// The caller cannot provide a deadline or a synthetic start rendezvous.
pub(crate) struct ChildEngineInput {
    pub paths: RuntimePaths,
    pub run_id: RunId,
    pub authorization_event_id: EventId,
    pub work_order_id: ChildWorkOrderId,
    pub backend: Arc<dyn ModelBackend>,
    pub model_profile: ReconModelProfile,
    pub scheduler: ModelCallScheduler,
    pub config: RunSupervisorConfig,
    pub cancellation: CancellationToken,
    pub shutdown: CancellationToken,
    pub clock: Arc<ReconRuntimeClock>,
}

/// Store-committed terminal identity returned by one real child task. A
/// successful execution has an exact handoff envelope; failed or cancelled
/// executions do not invent one.
pub(crate) struct ChildEngineTerminal {
    pub work_order_id: ChildWorkOrderId,
    pub execution_id: ChildExecutionId,
    pub started_event: EventEnvelope,
    pub terminal_event: EventEnvelope,
    pub handoff_event: Option<EventEnvelope>,
}

/// One-child Store-total model → action → broker → handoff engine.
///
/// The fail-closed stub keeps the intended interface explicit. The product
/// capability flag must remain disabled until this function is implemented,
/// two real engines are spawned before the first join, and their terminal
/// overlap and evidence are verified from Store.
#[allow(
    clippy::unused_async,
    reason = "the deliberate fail-closed stub preserves the next slice's async engine interface"
)]
pub(crate) async fn run_child_repository_explorer(
    _input: ChildEngineInput,
) -> Result<ChildEngineTerminal, SupervisorRunError> {
    Err(SupervisorRunError::InvalidState(
        "repository-explorer child engine is not implemented".to_owned(),
    ))
}
