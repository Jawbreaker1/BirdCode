//! Public child replay projection value types.

use super::super::{ArtifactRef, ChildExecutionOutcome, ChildToolCallId, EventEnvelope, EventId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildPendingEffectProjection {
    Model { prepared_event: EventEnvelope },
    Tool { prepared_event: EventEnvelope },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildRecoveryState {
    AwaitingAttempt,
    ReadyForModel,
    ReadyForTool,
    PendingEffect(ChildPendingEffectProjection),
    ReadyForHandoff,
    ReadyToFinishAttempt,
    Retryable {
        terminal_event: EventEnvelope,
        outcome: ChildExecutionOutcome,
    },
    Terminal {
        terminal_event: EventEnvelope,
        outcome: ChildExecutionOutcome,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildSuppliedResultProjection {
    pub tool_call_id: ChildToolCallId,
    pub supplied_on_model_call_ordinal: u32,
    pub supplied_on_prepared_event_id: EventId,
    pub result_artifact: ArtifactRef,
}
