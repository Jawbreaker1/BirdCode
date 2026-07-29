//! Public child replay projection value types.

use super::super::{ArtifactRef, ChildToolCallId, EventId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildSuppliedResultProjection {
    pub tool_call_id: ChildToolCallId,
    pub supplied_on_model_call_ordinal: u32,
    pub supplied_on_prepared_event_id: EventId,
    pub result_artifact: ArtifactRef,
}
