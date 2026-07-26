//! Platform transport types around the canonical protocol-v7 repository broker wire.
//!
//! Authority, operations, results and durable receipts intentionally live in
//! `birdcode_protocol`.  The types in this module carry exact artifact bytes
//! between the broker and a caller-owned artifact store; they do not define a
//! second authorization or receipt model.

use birdcode_protocol::{
    ArtifactRef, EventId, RepositoryBrokerInstanceId, RepositoryInterruptionBoundaryV1,
    RepositoryToolCanonicalParametersV1, RepositoryToolObservedReceiptV2,
    RepositoryToolPreparedReceiptV2, RepositoryToolUnknownReceiptV2, RuntimeClockReading,
    Sha256Digest,
};
use thiserror::Error;

/// One exact, retained content-addressed artifact.
///
/// Protocol owns the `ArtifactRef`; this wrapper is only the in-process byte
/// transport used by a daemon to persist those bytes before appending the
/// corresponding durable event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedArtifactV2 {
    pub artifact: ArtifactRef,
    pub bytes: Vec<u8>,
}

impl RetainedArtifactV2 {
    #[must_use]
    pub(crate) fn from_bytes(media_type: &str, bytes: Vec<u8>) -> Self {
        let digest = Sha256Digest::of_bytes(&bytes);
        Self {
            artifact: ArtifactRef {
                sha256: digest.as_str().to_owned(),
                size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                media_type: media_type.to_owned(),
            },
            bytes,
        }
    }

    /// Verifies exact size and SHA-256 binding without interpreting media bytes.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.artifact.size_bytes == u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
            && self.artifact.sha256 == Sha256Digest::of_bytes(&self.bytes).as_str()
    }
}

/// Caller-owned identities and wall/monotonic runtime observation for Prepare.
///
/// Every semantic and authority-bearing field is inside canonical Protocol
/// parameters. The broker allocates only its monotonically increasing call
/// sequence and broker-local clock reading.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryToolPrepareInputV2 {
    pub parameters: RepositoryToolCanonicalParametersV1,
    pub runtime_prepared_at: RuntimeClockReading,
}

/// Canonical Prepared receipt plus the two exact artifacts a caller must
/// persist before it invokes `execute` or `record_interruption`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRepositoryToolCallV2 {
    pub receipt: RepositoryToolPreparedReceiptV2,
    pub canonical_parameters: RetainedArtifactV2,
    pub prepared_receipt: RetainedArtifactV2,
}

/// Caller-owned durable Prepared event identity and runtime finish reading.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryToolExecuteInputV2 {
    pub prepared: PreparedRepositoryToolCallV2,
    pub prepared_event_id: EventId,
    pub runtime_finished_at: RuntimeClockReading,
}

/// Caller-owned information for closing an unexecuted Prepared call in the
/// active broker epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryToolInterruptionInputV2 {
    pub prepared: PreparedRepositoryToolCallV2,
    pub prepared_event_id: EventId,
    pub boundary: RepositoryInterruptionBoundaryV1,
    pub cancellation: Option<birdcode_protocol::ChildCancellationCauseV1>,
    pub runtime_boundary_at: RuntimeClockReading,
}

/// Caller-owned proof boundary for reconciling a Prepared call whose broker
/// epoch is durably closed. The active broker checks the abandoned UUID against
/// its Protocol epoch state and never fabricates a clock from that old epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryToolRestartReconciliationInputV2 {
    pub prepared: PreparedRepositoryToolCallV2,
    pub prepared_event_id: EventId,
    pub boundary: RepositoryInterruptionBoundaryV1,
    pub cancellation: Option<birdcode_protocol::ChildCancellationCauseV1>,
    pub runtime_boundary_at: RuntimeClockReading,
}

/// Canonical known terminal plus every newly produced exact artifact.
///
/// A successful result appears only as the Protocol-v7 result artifact in
/// `supporting_artifacts`; the terminal receipt contains only its `ArtifactRef`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRepositoryToolCallV2 {
    pub receipt: RepositoryToolObservedReceiptV2,
    pub terminal_receipt: RetainedArtifactV2,
    pub supporting_artifacts: Vec<RetainedArtifactV2>,
}

/// Canonical unknown terminal plus its exact unknown-evidence artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownRepositoryToolCallV2 {
    pub receipt: RepositoryToolUnknownReceiptV2,
    pub terminal_receipt: RetainedArtifactV2,
    pub supporting_artifacts: Vec<RetainedArtifactV2>,
}

/// Exact terminal outcome emitted by the broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryToolTerminalV2 {
    Observed(ObservedRepositoryToolCallV2),
    Unknown(UnknownRepositoryToolCallV2),
}

/// Compile-time platform capability exposed without implying cross-platform
/// parity. Protocol-v7 repository paths and this adapter are Unix-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryToolPlatformSupportV2 {
    UnixDescriptorConfined,
    Unsupported,
}

#[must_use]
pub const fn repository_tool_platform_support_v2() -> RepositoryToolPlatformSupportV2 {
    #[cfg(unix)]
    {
        RepositoryToolPlatformSupportV2::UnixDescriptorConfined
    }
    #[cfg(not(unix))]
    {
        RepositoryToolPlatformSupportV2::Unsupported
    }
}

/// Non-durable platform/broker failure. These errors never masquerade as an
/// authorization denial. Once a Prepared effect has become indeterminate, the
/// runtime must use restart reconciliation rather than retrying execution.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RepositoryBrokerErrorV2 {
    #[error("canonical {artifact} JSON could not be encoded")]
    CanonicalEncoding { artifact: &'static str },
    #[error("artifact {artifact} failed exact size or SHA-256 validation")]
    ArtifactBindingMismatch { artifact: &'static str },
    #[error("prepared receipt is not the exact canonical receipt registered by this broker")]
    PreparedSubstitution,
    #[error("prepared call belongs to a different broker epoch")]
    WrongBrokerEpoch,
    #[error("prepared call was not issued by this broker")]
    UnissuedPreparedCall,
    #[error("prepared call has already reached an execute/terminal boundary")]
    PreparedCallAlreadyConsumed,
    #[error("tool call id was already prepared in this broker epoch")]
    DuplicateToolCallId,
    #[error("broker state lock is unavailable")]
    BrokerStateUnavailable,
    #[error("terminal receipt has {actual} bytes; maximum is {maximum}")]
    TerminalReceiptTooLarge { actual: u64, maximum: u64 },
    #[error("prepared receipt has {actual} bytes; maximum is {maximum}")]
    PreparedReceiptTooLarge { actual: u64, maximum: u64 },
    #[error("canonical parameters have {actual} bytes; maximum is {maximum}")]
    CanonicalParametersTooLarge { actual: u64, maximum: u64 },
    #[error("abandoned broker {broker_instance_id} is not in the closed epoch set")]
    BrokerEpochNotClosed {
        broker_instance_id: RepositoryBrokerInstanceId,
    },
    #[error("interruption boundary and cancellation metadata are inconsistent")]
    InvalidInterruptionMetadata,
    #[error("broker output failed exact validation for a durable Protocol projection")]
    InvalidDurableProjection,
    #[error("unknown event reason/boundary does not match the broker interruption receipt")]
    UnknownProjectionMismatch,
}

pub(crate) fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::of_bytes(bytes)
}
