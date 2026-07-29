//! Protocol-v7 repository-tool terminal, epoch, and durable projection wires.

use super::{
    ArtifactRef, ChildCancellationCauseV1, ChildExecutionBinding, ChildModelVisibleJsonV1,
    ChildToolCallId, ChildToolUnknownBoundary, ChildToolUnknownReason,
    ChildValidatedActionBindingV1, EventEnvelope, EventId, RepositoryBrokerClockV1,
    RepositoryBrokerInstanceId, RepositoryCleanupReportV2, RepositoryFilesystemEffectV1,
    RepositoryInterruptionBoundaryV1, RepositoryToolFailureV1, RepositoryToolPreparationDenialV2,
    RepositoryToolResultV2, RepositoryUnretainedEvidenceDigestV1, RunClaimId, RuntimeClockReading,
    RuntimeInstanceId, Sha256Digest,
};
use serde::{Deserialize, Serialize};

/// Small mechanically known terminal for broker v2. Successful result bytes
/// are referenced, never duplicated in the receipt. A failed operation may
/// disclose only a separate digest for an unretained partial observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "status", rename_all = "snake_case")]
pub enum RepositoryToolObservedTerminalV2 {
    Succeeded {
        result_artifact: ArtifactRef,
    },
    Failed {
        failure: RepositoryToolFailureV1,
        evidence_artifact: ArtifactRef,
        unretained_partial: Option<RepositoryUnretainedEvidenceDigestV1>,
    },
    AuthorizationDenied {
        denial: RepositoryToolPreparationDenialV2,
        evidence_artifact: ArtifactRef,
    },
}

/// Canonical broker-v2 terminal receipt for a known outcome. It contains no
/// operation, result body, inline evidence bytes or second copy of authority;
/// those remain bound through the exact Prepared receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryToolObservedReceiptV2 {
    pub schema_version: u32,
    pub binding: ChildExecutionBinding,
    pub tool_call_id: ChildToolCallId,
    pub prepared_event_id: EventId,
    pub action_binding: ChildValidatedActionBindingV1,
    pub prepared_receipt_artifact: ArtifactRef,
    pub prepared_receipt_digest: Sha256Digest,
    pub terminal: RepositoryToolObservedTerminalV2,
    pub broker_completed_at: RepositoryBrokerClockV1,
    pub elapsed_nanoseconds: u64,
    pub effect: RepositoryFilesystemEffectV1,
    pub cleanup: RepositoryCleanupReportV2,
    pub runtime_finished_at: RuntimeClockReading,
}

/// Typed provenance for recording an unknown outcome either in the original
/// broker epoch or after a runtime proves that epoch was abandoned. Recovery
/// never fabricates a monotonic reading from the abandoned broker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "source", rename_all = "snake_case")]
pub enum RepositoryToolUnknownTimingV2 {
    BrokerRecorded {
        recorded_at: RepositoryBrokerClockV1,
        elapsed_nanoseconds: u64,
    },
    RuntimeReconciled {
        abandoned_broker_instance_id: RepositoryBrokerInstanceId,
    },
}

/// Canonical broker-v2 unknown receipt. There is intentionally no partial
/// artifact field: unknowable bytes cannot acquire durable authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryToolUnknownReceiptV2 {
    pub schema_version: u32,
    pub binding: ChildExecutionBinding,
    pub tool_call_id: ChildToolCallId,
    pub prepared_event_id: EventId,
    pub action_binding: ChildValidatedActionBindingV1,
    pub prepared_receipt_artifact: ArtifactRef,
    pub prepared_receipt_digest: Sha256Digest,
    pub boundary: RepositoryInterruptionBoundaryV1,
    pub cancellation: Option<ChildCancellationCauseV1>,
    pub unknown_evidence_artifact: ArtifactRef,
    pub timing: RepositoryToolUnknownTimingV2,
    pub effect: RepositoryFilesystemEffectV1,
    pub cleanup: RepositoryCleanupReportV2,
    pub runtime_boundary_at: RuntimeClockReading,
}

/// Store projection used to reject reuse of a closed broker UUID across
/// runtime recovery. The closed list is canonicalized and validated by Store;
/// Protocol carries it losslessly without inventing ordering semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBrokerEpochStateV1 {
    pub active_broker_instance_id: RepositoryBrokerInstanceId,
    pub closed_broker_instance_ids: Vec<RepositoryBrokerInstanceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBrokerEpochActivatedV1 {
    pub previous_active_broker_instance_id: Option<RepositoryBrokerInstanceId>,
    pub state: RepositoryBrokerEpochStateV1,
    pub activated_at: RuntimeClockReading,
}

/// Exact successful result supplied once, separately from the small observed
/// receipt, to the next repository-explorer turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRepositoryExplorerObservedToolEvidenceV1 {
    pub tool_call_id: ChildToolCallId,
    pub observed_event_id: EventId,
    pub supplied_on_model_call_ordinal: u32,
    pub result_artifact: ArtifactRef,
    pub result: RepositoryToolResultV2,
}

/// Cumulative transcript state for the separately supplied successful result.
/// Exact typed bytes are carried on one turn; later turns retain only an
/// explicit artifact identity and the ordinal on which Store supplied them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "availability", rename_all = "snake_case")]
pub enum ChildRepositoryExplorerObservedToolResultV1 {
    Supplied {
        evidence: ChildRepositoryExplorerObservedToolEvidenceV1,
    },
    PreviouslySupplied {
        result_artifact: ArtifactRef,
        supplied_on_model_call_ordinal: u32,
        supplied_on_prepared_event_id: EventId,
        supplied_on_prepared_event_json: ChildModelVisibleJsonV1<EventEnvelope>,
    },
}

/// Protocol-v7 durable projection of a known broker-v2 terminal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChildToolObservedV2 {
    pub binding: ChildExecutionBinding,
    pub tool_call_id: ChildToolCallId,
    pub prepared_event_id: EventId,
    pub action_binding: ChildValidatedActionBindingV1,
    pub prepared_receipt_digest: Sha256Digest,
    pub terminal_receipt_artifact: ArtifactRef,
    pub terminal_receipt_digest: Sha256Digest,
    pub finished_at: RuntimeClockReading,
    pub terminal: RepositoryToolObservedTerminalV2,
}

/// Protocol-v7 durable projection of an unknowable broker-v2 terminal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChildToolOutcomeUnknownV2 {
    pub binding: ChildExecutionBinding,
    pub tool_call_id: ChildToolCallId,
    pub prepared_event_id: EventId,
    pub action_binding: ChildValidatedActionBindingV1,
    pub prepared_receipt_digest: Sha256Digest,
    pub terminal_receipt_artifact: ArtifactRef,
    pub terminal_receipt_digest: Sha256Digest,
    pub boundary_at: RuntimeClockReading,
    pub reason: ChildToolUnknownReason,
    pub boundary: ChildToolUnknownBoundary,
    pub cancellation: Option<ChildCancellationCauseV1>,
    pub timing: RepositoryToolUnknownTimingV2,
}

/// Protocol-v9 durable pre-effect fence for one exact broker-v2 tool call.
///
/// The record repeats only query-critical identities from the authoritative
/// Prepared receipt and active Store state. It proves that Store admitted one
/// dispatch start; it is evidence, not independently executable authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChildToolDispatchStartedV2 {
    pub binding: ChildExecutionBinding,
    pub tool_call_id: ChildToolCallId,
    pub prepared_event_id: EventId,
    pub action_binding: ChildValidatedActionBindingV1,
    pub prepared_receipt_digest: Sha256Digest,
    pub claim_event_id: EventId,
    pub claim_id: RunClaimId,
    pub claim_generation: u64,
    pub runtime_instance_id: RuntimeInstanceId,
    pub cancellation_generation: u64,
    pub broker_epoch_activation_event_id: EventId,
    pub broker_instance_id: RepositoryBrokerInstanceId,
    pub started_at: RuntimeClockReading,
}
