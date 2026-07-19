//! Canonical, transport-independent protocol types for `BirdCode`.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

/// Canonical request/response protocol version.
///
/// Version 4 adds closed, content-addressed provenance for durable failures
/// before a root-planner inference is prepared. It retains version 3's
/// client-assigned run identities and provider-neutral planning events.
pub const PROTOCOL_VERSION: u32 = 4;

/// Version of the path representation nested inside protocol messages.
pub const WORKSPACE_PATH_WIRE_VERSION: u32 = 1;

/// Maximum number of raw artifact bytes carried by one JSON-lines response.
///
/// Artifact reads are deliberately paginated. The base64 representation of a
/// maximum-sized chunk is well below the protocol client's response-frame cap,
/// leaving ample room for the response envelope and artifact identity.
pub const MAX_ARTIFACT_CHUNK_BYTES: u32 = 256 * 1024;

/// Maximum canonical base64 character count for one artifact chunk.
pub const MAX_ARTIFACT_CHUNK_BASE64_BYTES: usize =
    (MAX_ARTIFACT_CHUNK_BYTES as usize).div_ceil(3) * 4;

/// A lossless workspace path at the canonical wire boundary.
///
/// Unix paths are byte strings, while Windows paths are sequences of UTF-16
/// code units. Keeping those representations distinct preserves Unix bytes
/// that are not UTF-8 and unpaired Windows surrogates. Conversion to a native
/// [`PathBuf`] is deliberately allowed only on a compatible host family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspacePath {
    wire_version: u32,
    representation: WorkspacePathRepresentation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "encoding", rename_all = "snake_case")]
enum WorkspacePathRepresentation {
    UnixBytes { bytes: Vec<u8> },
    WindowsUtf16 { code_units: Vec<u16> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspacePathWire {
    wire_version: u32,
    representation: WorkspacePathRepresentation,
}

impl<'de> Deserialize<'de> for WorkspacePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WorkspacePathWire::deserialize(deserializer)?;
        if wire.wire_version != WORKSPACE_PATH_WIRE_VERSION {
            return Err(serde::de::Error::custom(format_args!(
                "unsupported workspace path wire version {}; expected {}",
                wire.wire_version, WORKSPACE_PATH_WIRE_VERSION
            )));
        }
        Ok(Self {
            wire_version: wire.wire_version,
            representation: wire.representation,
        })
    }
}

impl WorkspacePath {
    /// Creates an explicitly Unix-encoded path from its exact bytes.
    #[must_use]
    pub const fn from_unix_bytes(bytes: Vec<u8>) -> Self {
        Self {
            wire_version: WORKSPACE_PATH_WIRE_VERSION,
            representation: WorkspacePathRepresentation::UnixBytes { bytes },
        }
    }

    /// Creates an explicitly Windows-encoded path from exact UTF-16 units.
    #[must_use]
    pub const fn from_windows_utf16(code_units: Vec<u16>) -> Self {
        Self {
            wire_version: WORKSPACE_PATH_WIRE_VERSION,
            representation: WorkspacePathRepresentation::WindowsUtf16 { code_units },
        }
    }

    /// Returns the path wire-representation version.
    #[must_use]
    pub const fn wire_version(&self) -> u32 {
        self.wire_version
    }

    /// Returns the exact Unix path bytes, when this is a Unix path.
    #[must_use]
    pub fn unix_bytes(&self) -> Option<&[u8]> {
        match &self.representation {
            WorkspacePathRepresentation::UnixBytes { bytes } => Some(bytes),
            WorkspacePathRepresentation::WindowsUtf16 { .. } => None,
        }
    }

    /// Returns the exact Windows UTF-16 units, when this is a Windows path.
    #[must_use]
    pub fn windows_utf16(&self) -> Option<&[u16]> {
        match &self.representation {
            WorkspacePathRepresentation::WindowsUtf16 { code_units } => Some(code_units),
            WorkspacePathRepresentation::UnixBytes { .. } => None,
        }
    }

    /// Converts this wire value to a native path without lossy text decoding.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspacePathError::PlatformMismatch`] when the path was
    /// encoded for the other operating-system family.
    #[cfg(unix)]
    pub fn to_native(&self) -> Result<PathBuf, WorkspacePathError> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        match &self.representation {
            WorkspacePathRepresentation::UnixBytes { bytes } => {
                Ok(PathBuf::from(OsString::from_vec(bytes.clone())))
            }
            WorkspacePathRepresentation::WindowsUtf16 { .. } => {
                Err(WorkspacePathError::PlatformMismatch {
                    encoded_for: "windows",
                    native_family: "unix",
                })
            }
        }
    }

    /// Converts this wire value to a native path without lossy text decoding.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspacePathError::PlatformMismatch`] when the path was
    /// encoded for the other operating-system family.
    #[cfg(windows)]
    pub fn to_native(&self) -> Result<PathBuf, WorkspacePathError> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        match &self.representation {
            WorkspacePathRepresentation::WindowsUtf16 { code_units } => {
                Ok(PathBuf::from(OsString::from_wide(code_units)))
            }
            WorkspacePathRepresentation::UnixBytes { .. } => {
                Err(WorkspacePathError::PlatformMismatch {
                    encoded_for: "unix",
                    native_family: "windows",
                })
            }
        }
    }
}

#[cfg(unix)]
impl From<PathBuf> for WorkspacePath {
    fn from(path: PathBuf) -> Self {
        use std::os::unix::ffi::OsStrExt;

        Self::from_unix_bytes(path.as_os_str().as_bytes().to_vec())
    }
}

#[cfg(windows)]
impl From<PathBuf> for WorkspacePath {
    fn from(path: PathBuf) -> Self {
        use std::os::windows::ffi::OsStrExt;

        Self::from_windows_utf16(path.as_os_str().encode_wide().collect())
    }
}

/// Failure to convert a foreign-family workspace path to a native path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspacePathError {
    PlatformMismatch {
        encoded_for: &'static str,
        native_family: &'static str,
    },
}

impl fmt::Display for WorkspacePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlatformMismatch {
                encoded_for,
                native_family,
            } => write!(
                formatter,
                "workspace path is encoded for {encoded_for}, not native {native_family}"
            ),
        }
    }
}

impl std::error::Error for WorkspacePathError {}

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(ActorId);
uuid_id!(CancellationRequestId);
uuid_id!(EventId);
uuid_id!(InferenceAttemptId);
uuid_id!(PlanProposalId);
uuid_id!(ReadOperationId);
uuid_id!(RequestId);
uuid_id!(RunClaimId);
uuid_id!(RunId);
uuid_id!(RuntimeInstanceId);
uuid_id!(SessionId);
uuid_id!(TokenReservationId);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientRequest {
    pub id: RequestId,
    #[serde(flatten)]
    pub command: ClientCommand,
}

impl ClientRequest {
    #[must_use]
    pub fn new(command: ClientCommand) -> Self {
        Self {
            id: RequestId::new(),
            command,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "method",
    content = "params",
    rename_all = "snake_case"
)]
pub enum ClientCommand {
    Initialize(InitializeRequest),
    Health,
    DiscoverModels,
    CreateSession(CreateSessionRequest),
    GetSession {
        session_id: SessionId,
    },
    CreateRun(CreateRunRequest),
    GetRun {
        run_id: RunId,
    },
    GetEvents {
        session_id: SessionId,
        after_sequence: u64,
    },
    CancelRun {
        run_id: RunId,
    },
    /// Reads bytes only from the content-addressed artifact named by the exact
    /// reference. No storage or filesystem path crosses the wire boundary.
    GetArtifact(GetArtifactRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InitializeRequest {
    pub protocol_version: u32,
    pub client: ClientIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerResponse {
    pub request_id: RequestId,
    #[serde(flatten)]
    pub outcome: ResponseOutcome,
}

impl ServerResponse {
    #[must_use]
    pub const fn success(request_id: RequestId, result: ServerResult) -> Self {
        Self {
            request_id,
            outcome: ResponseOutcome::Success { result },
        }
    }

    #[must_use]
    pub const fn error(request_id: RequestId, error: ProtocolError) -> Self {
        Self {
            request_id,
            outcome: ResponseOutcome::Error { error },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResponseOutcome {
    Success { result: ServerResult },
    Error { error: ProtocolError },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ServerResult {
    Initialized(InitializeResult),
    Health(Health),
    BackendCatalog(BackendCatalog),
    Session(Session),
    Run(Run),
    EventPage(EventPage),
    CancellationReceipt(CancellationReceipt),
    ArtifactChunk(ArtifactChunk),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InitializeResult {
    pub protocol_version: u32,
    pub server: ServerIdentity,
    pub capabilities: RuntimeCapabilities,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeCapabilities {
    pub supported: BTreeSet<RuntimeCapability>,
}

impl RuntimeCapabilities {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = RuntimeCapability>) -> Self {
        Self {
            supported: capabilities.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn supports(&self, capability: RuntimeCapability) -> bool {
        self.supported.contains(&capability)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCapability {
    DurableSessions,
    DurableRootPlanning,
    EventReplay,
    Streaming,
    Cancellation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Health {
    pub protocol_version: u32,
    pub status: HealthStatus,
    pub platform: String,
    pub architecture: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ready,
    Degraded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    IncompatibleProtocol,
    NotFound,
    Conflict,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateSessionRequest {
    pub workspace_root: WorkspacePath,
    pub title: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Session {
    pub id: SessionId,
    pub workspace_root: WorkspacePath,
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Session {
    #[must_use]
    pub fn new(request: CreateSessionRequest) -> Self {
        Self {
            id: SessionId::new(),
            workspace_root: request.workspace_root,
            title: request.title,
            created_at: Utc::now(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRunRequest {
    /// Stable idempotency identity allocated by the client before submission.
    pub run_id: RunId,
    pub spec: RunSpec,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    pub session_id: SessionId,
    pub purpose: RunPurpose,
    pub backend: BackendSelection,
    pub input: Vec<InputItem>,
    pub limits: RunLimits,
}

/// The authority boundary for a run.
///
/// `Execute` has been reserved since protocol v3 so future clients do not need to
/// reinterpret a plan-only run as an implementation run. A runtime must reject
/// it unless it explicitly implements execution semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPurpose {
    PlanOnly,
    Execute,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendSelection {
    pub backend_id: String,
    pub kind: BackendKind,
    pub model: Option<String>,
    pub reasoning_effort: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Model,
    Agent,
}

/// Exact backend/model identity resolved for an inference attempt.
///
/// This is intentionally separate from [`BackendSelection`]: a prepared
/// durable attempt cannot retain an unresolved optional model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendModelIdentity {
    pub backend_id: String,
    pub kind: BackendKind,
    pub model_id: String,
}

/// Provider-neutral result of model discovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCatalog {
    pub discovered_at: DateTime<Utc>,
    pub models: Vec<DiscoveredModel>,
}

/// A model reported by a configured backend.
///
/// Catalog entries are inventory only: they do not grant tools, permissions,
/// or runtime capabilities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredModel {
    pub identity: BackendModelIdentity,
    pub display_name: Option<String>,
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendCapabilities {
    pub supported: BTreeSet<BackendCapability>,
}

impl BackendCapabilities {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = BackendCapability>) -> Self {
        Self {
            supported: capabilities.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn supports(&self, capability: BackendCapability) -> bool {
        self.supported.contains(&capability)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendCapability {
    Streaming,
    Tools,
    StructuredOutput,
    ParallelToolCalls,
    Cancellation,
    DurableThreads,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InputItem {
    Text { text: String },
    Artifact { artifact: ArtifactRef },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    pub max_output_tokens: Option<u64>,
    pub max_wall_time_seconds: Option<u64>,
    /// Delegation is authority, so the neutral wire default grants none.
    /// Future Execute constructors must opt into a bounded value explicitly.
    pub max_subagents: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Run {
    pub id: RunId,
    pub spec: RunSpec,
    pub state: RunState,
    pub created_at: DateTime<Utc>,
}

impl Run {
    #[must_use]
    pub fn new(spec: RunSpec) -> Self {
        Self::with_id(RunId::new(), spec)
    }

    /// Creates a run using the identity allocated by its client.
    #[must_use]
    pub fn with_id(id: RunId, spec: RunSpec) -> Self {
        Self {
            id,
            spec,
            state: RunState::Queued,
            created_at: Utc::now(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    Waiting,
    Completed,
    Failed,
    Cancelled,
}

/// Server acknowledgement for a durable cancellation request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReceipt {
    pub run_id: RunId,
    pub cancellation_request_id: CancellationRequestId,
    pub cancellation_generation: u64,
    pub disposition: CancellationDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationDisposition {
    Recorded,
    AlreadyRequested,
    RunAlreadyTerminal,
}

/// Canonical lower-case SHA-256 digest used to bind plan revisions.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub const HEX_LENGTH: usize = 64;

    /// Parses a canonical lower-case SHA-256 hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`Sha256DigestError`] for the wrong length or non-canonical
    /// characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, Sha256DigestError> {
        let value = value.into();
        if value.len() != Self::HEX_LENGTH {
            return Err(Sha256DigestError::InvalidLength {
                actual: value.len(),
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Sha256DigestError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sha256DigestError {
    InvalidLength { actual: usize },
    InvalidCharacter,
}

impl fmt::Display for Sha256DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual } => write!(
                formatter,
                "SHA-256 digest must contain exactly 64 hexadecimal characters; got {actual}"
            ),
            Self::InvalidCharacter => formatter.write_str(
                "SHA-256 digest must contain only canonical lower-case hexadecimal characters",
            ),
        }
    }
}

impl std::error::Error for Sha256DigestError {}

/// A durably reserved token budget for exactly one model attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenReservation {
    pub id: TokenReservationId,
    pub reserved_tokens: u64,
    pub max_output_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cached_input_tokens: Option<u64>,
}

/// Exclusive durable claim on a run. It conveys ownership, never additional
/// permissions or capabilities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunClaimed {
    pub claim_id: RunClaimId,
    pub runtime_instance_id: RuntimeInstanceId,
    pub claim_generation: u64,
    pub cancellation_generation: u64,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRequested {
    pub cancellation_request_id: CancellationRequestId,
    pub cancellation_generation: u64,
}

/// Durable terminal cause for a root-planning run that failed before an
/// inference attempt reached [`PlannerInferencePrepared`].
///
/// The exact live claim is named explicitly instead of inferred from actor
/// identity. `evidence_artifact` contains the complete diagnostic observation;
/// `phase` and `reason` are the closed semantic projection used by replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPlanningFailed {
    pub claim_event_id: EventId,
    pub claim_id: RunClaimId,
    pub cancellation_generation: u64,
    pub phase: RootPlanningFailurePhase,
    pub reason: RootPlanningFailureReason,
    pub evidence_artifact: ArtifactRef,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootPlanningFailurePhase {
    Preflight,
    ModelDiscovery,
    PromptPreparation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootPlanningFailureReason {
    InvalidWallDeadline,
    InvalidRunConfiguration,
    BackendDiscoveryFailed,
    DiscoveryTimedOut,
    InvalidDiscoveryCatalog,
    SelectedModelUnavailable,
    WallDeadlineExceeded,
    PromptCompilationFailed,
    DurableStateConflict,
}

/// Durable pre-call record. This must be acknowledged by storage before any
/// bytes are sent to the selected backend.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerInferencePrepared {
    pub attempt_id: InferenceAttemptId,
    /// Present only when this is a new, explicitly authorized retry attempt.
    pub parent_attempt_id: Option<InferenceAttemptId>,
    pub backend_model: BackendModelIdentity,
    pub prompt_artifact: ArtifactRef,
    pub prompt_manifest_digest: Sha256Digest,
    pub request_artifact: ArtifactRef,
    pub token_reservation: TokenReservation,
    pub plan_revision: u64,
    pub plan_digest: Sha256Digest,
    pub obligation_snapshot_digest: Sha256Digest,
    pub acceptance_policy_digest: Sha256Digest,
    pub context_manifest_digest: Sha256Digest,
    pub planner_policy_digest: Sha256Digest,
    pub cancellation_generation: u64,
}

/// Durable post-call record bound to one prepared attempt and reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerInferenceObserved {
    pub attempt_id: InferenceAttemptId,
    pub token_reservation_id: TokenReservationId,
    pub prepared_event_id: EventId,
    pub normalized_complete_evidence_artifact: ArtifactRef,
    pub outcome: PlannerInferenceObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "status", rename_all = "snake_case")]
pub enum PlannerInferenceObservation {
    Succeeded {
        reported_backend_model: BackendModelIdentity,
        token_usage: TokenUsage,
    },
    Failed {
        error: PlannerInferenceError,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerInferenceError {
    pub kind: PlannerInferenceErrorKind,
    pub retry: RetryDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerInferenceErrorKind {
    Transport,
    Timeout,
    Authentication,
    RateLimited,
    ProviderRejected,
    ProtocolViolation,
    InvalidStructuredResponse,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    Never,
    RequiresNewAttempt,
}

/// Reconciliation marker for a prepared attempt whose post-call outcome can no
/// longer be established. Its reservation remains consumed conservatively.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerInferenceOutcomeUnknown {
    pub attempt_id: InferenceAttemptId,
    pub token_reservation_id: TokenReservationId,
    pub prepared_event_id: EventId,
    pub reason: UnknownInferenceOutcomeReason,
    pub cancellation_generation: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownInferenceOutcomeReason {
    RuntimeRestartedBeforeObservation,
    ClaimExpiredBeforeObservation,
    EvidenceCommitIndeterminate,
}

/// Read-only operation requested by the planner. This type describes an
/// operation but does not grant filesystem authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "operation", rename_all = "snake_case")]
pub enum ReadOperation {
    ListDirectory {
        path: WorkspacePath,
    },
    ReadFile {
        path: WorkspacePath,
        offset_bytes: u64,
        max_bytes: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOperationPrepared {
    pub operation_id: ReadOperationId,
    pub operation: ReadOperation,
    pub request_artifact: ArtifactRef,
    pub plan_revision: u64,
    pub plan_digest: Sha256Digest,
    pub cancellation_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOperationObserved {
    pub operation_id: ReadOperationId,
    pub prepared_event_id: EventId,
    pub normalized_complete_evidence_artifact: ArtifactRef,
    pub outcome: ReadOperationObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "status", rename_all = "snake_case")]
pub enum ReadOperationObservation {
    Succeeded {
        bytes_read: u64,
        entries_read: u64,
        truncated: bool,
    },
    Failed {
        error: ReadOperationError,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperationError {
    NotFound,
    PermissionDenied,
    InvalidRange,
    WrongFileType,
    ChangedDuringRead,
    Io,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanProposalRejected {
    pub proposal_id: PlanProposalId,
    pub inference_attempt_id: InferenceAttemptId,
    pub observed_event_id: EventId,
    pub proposal_artifact: ArtifactRef,
    pub base_plan_revision: u64,
    pub base_plan_digest: Sha256Digest,
    pub reason: PlanProposalRejectionReason,
    pub validation_evidence_artifact: ArtifactRef,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanProposalRejectionReason {
    InvalidSchema,
    StaleBaseRevision,
    StaleBaseDigest,
    ProtectedAuthorityMutation,
    ObligationCoverageIncomplete,
    DependencyCycle,
    PolicyLimitExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanProposalAccepted {
    pub proposal_id: PlanProposalId,
    pub inference_attempt_id: InferenceAttemptId,
    pub observed_event_id: EventId,
    pub proposal_artifact: ArtifactRef,
    pub previous_plan_revision: u64,
    pub previous_plan_digest: Sha256Digest,
    pub accepted_plan_revision: u64,
    pub accepted_plan_digest: Sha256Digest,
    pub accepted_plan_artifact: ArtifactRef,
    pub validation_evidence_artifact: ArtifactRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub id: EventId,
    pub sequence: u64,
    pub session_id: SessionId,
    pub run_id: Option<RunId>,
    pub actor_id: ActorId,
    pub causal_parent: Option<EventId>,
    pub occurred_at: DateTime<Utc>,
    pub provenance: Provenance,
    pub payload: EventPayload,
}

/// Replay page returned by `get_events`.
///
/// Events are decoded canonical store records, not transport-encoded byte
/// blobs. `next_sequence` is the cursor to use for the following page.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventPage {
    pub events: Vec<EventEnvelope>,
    pub next_sequence: u64,
    pub has_more: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewEvent {
    pub session_id: SessionId,
    pub run_id: Option<RunId>,
    pub actor_id: ActorId,
    pub causal_parent: Option<EventId>,
    pub provenance: Provenance,
    pub payload: EventPayload,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub producer: String,
    pub backend: Option<BackendSelection>,
    pub raw_artifact: Option<ArtifactRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "data",
    rename_all = "snake_case"
)]
pub enum EventPayload {
    SessionCreated {
        session: Session,
    },
    UserInput {
        items: Vec<InputItem>,
    },
    RunCreated {
        run: Run,
    },
    RunStateChanged {
        from: RunState,
        to: RunState,
    },
    RunClaimed(RunClaimed),
    CancellationRequested(CancellationRequested),
    RootPlanningFailed(RootPlanningFailed),
    PlannerInferencePrepared(PlannerInferencePrepared),
    PlannerInferenceObserved(PlannerInferenceObserved),
    PlannerInferenceOutcomeUnknown(PlannerInferenceOutcomeUnknown),
    ReadOperationPrepared(ReadOperationPrepared),
    ReadOperationObserved(ReadOperationObserved),
    PlanProposalRejected(PlanProposalRejected),
    PlanProposalAccepted(PlanProposalAccepted),
    /// Legacy extension envelope for non-core backend telemetry only.
    ///
    /// Durable root planning MUST NOT encode inference, reads, proposals,
    /// cancellation, claims, or lifecycle transitions through this variant.
    /// Those records use the typed variants above so storage can enforce their
    /// causal and budget invariants.
    BackendEvent {
        event_type: String,
        data: serde_json::Value,
    },
    ArtifactStored {
        artifact: ArtifactRef,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
}

/// One bounded read from an exact content-addressed artifact.
///
/// The request intentionally contains no path. `artifact` is matched in full
/// (digest, byte length, and media type), preventing a digest-only lookup from
/// silently changing the metadata contract observed by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GetArtifactRequest {
    artifact: ArtifactRef,
    offset: u64,
    max_bytes: u32,
}

impl GetArtifactRequest {
    /// Creates a bounded artifact read.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactReadContractError`] when the reference digest is not
    /// canonical SHA-256, the requested range starts beyond the exact artifact,
    /// or `max_bytes` is outside `1..=MAX_ARTIFACT_CHUNK_BYTES`.
    pub fn new(
        artifact: ArtifactRef,
        offset: u64,
        max_bytes: u32,
    ) -> Result<Self, ArtifactReadContractError> {
        validate_artifact_ref(&artifact)?;
        if max_bytes == 0 || max_bytes > MAX_ARTIFACT_CHUNK_BYTES {
            return Err(ArtifactReadContractError::InvalidMaxBytes { actual: max_bytes });
        }
        if offset > artifact.size_bytes {
            return Err(ArtifactReadContractError::OffsetBeyondArtifact {
                offset,
                size_bytes: artifact.size_bytes,
            });
        }
        Ok(Self {
            artifact,
            offset,
            max_bytes,
        })
    }

    #[must_use]
    pub const fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn max_bytes(&self) -> u32 {
        self.max_bytes
    }
}

impl<'de> Deserialize<'de> for GetArtifactRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            artifact: ArtifactRef,
            offset: u64,
            max_bytes: u32,
        }

        let wire = WireRequest::deserialize(deserializer)?;
        Self::new(wire.artifact, wire.offset, wire.max_bytes).map_err(serde::de::Error::custom)
    }
}

/// A bounded, canonically base64-encoded page of artifact bytes.
///
/// Construction and deserialization enforce cursor continuity against the
/// exact artifact size. A non-terminal empty page is forbidden so a caller can
/// always make progress by repeatedly requesting `next_offset`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactChunk {
    artifact: ArtifactRef,
    offset: u64,
    next_offset: u64,
    eof: bool,
    #[serde(with = "canonical_base64")]
    data_base64: Vec<u8>,
}

impl ArtifactChunk {
    /// Creates one response page and derives its authoritative next cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactReadContractError`] if the reference or range is
    /// invalid, if data exceeds [`MAX_ARTIFACT_CHUNK_BYTES`], or if `eof` does
    /// not exactly match reaching the declared artifact size.
    pub fn new(
        artifact: ArtifactRef,
        offset: u64,
        data: Vec<u8>,
        eof: bool,
    ) -> Result<Self, ArtifactReadContractError> {
        validate_artifact_ref(&artifact)?;
        if offset > artifact.size_bytes {
            return Err(ArtifactReadContractError::OffsetBeyondArtifact {
                offset,
                size_bytes: artifact.size_bytes,
            });
        }
        if data.len() > MAX_ARTIFACT_CHUNK_BYTES as usize {
            return Err(ArtifactReadContractError::ChunkTooLarge { actual: data.len() });
        }
        if data.is_empty() && offset < artifact.size_bytes {
            return Err(ArtifactReadContractError::EmptyNonTerminalChunk);
        }
        let data_length =
            u64::try_from(data.len()).map_err(|_| ArtifactReadContractError::RangeOverflow)?;
        let next_offset = offset
            .checked_add(data_length)
            .ok_or(ArtifactReadContractError::RangeOverflow)?;
        if next_offset > artifact.size_bytes {
            return Err(ArtifactReadContractError::ChunkBeyondArtifact {
                next_offset,
                size_bytes: artifact.size_bytes,
            });
        }
        let expected_eof = next_offset == artifact.size_bytes;
        if eof != expected_eof {
            return Err(ArtifactReadContractError::InvalidEndOfFile {
                expected: expected_eof,
                actual: eof,
            });
        }
        Ok(Self {
            artifact,
            offset,
            next_offset,
            eof,
            data_base64: data,
        })
    }

    #[must_use]
    pub const fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }

    #[must_use]
    pub const fn eof(&self) -> bool {
        self.eof
    }

    /// Returns the decoded raw bytes. The wire representation is canonical
    /// RFC 4648 base64 using the standard alphabet and required padding.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data_base64
    }

    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data_base64
    }
}

impl<'de> Deserialize<'de> for ArtifactChunk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireChunk {
            artifact: ArtifactRef,
            offset: u64,
            next_offset: u64,
            eof: bool,
            #[serde(with = "canonical_base64")]
            data_base64: Vec<u8>,
        }

        let wire = WireChunk::deserialize(deserializer)?;
        let chunk = Self::new(wire.artifact, wire.offset, wire.data_base64, wire.eof)
            .map_err(serde::de::Error::custom)?;
        if wire.next_offset != chunk.next_offset {
            return Err(serde::de::Error::custom(
                ArtifactReadContractError::InvalidNextOffset {
                    expected: chunk.next_offset,
                    actual: wire.next_offset,
                },
            ));
        }
        Ok(chunk)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactReadContractError {
    InvalidDigest,
    InvalidMaxBytes { actual: u32 },
    OffsetBeyondArtifact { offset: u64, size_bytes: u64 },
    ChunkTooLarge { actual: usize },
    EmptyNonTerminalChunk,
    RangeOverflow,
    ChunkBeyondArtifact { next_offset: u64, size_bytes: u64 },
    InvalidEndOfFile { expected: bool, actual: bool },
    InvalidNextOffset { expected: u64, actual: u64 },
}

impl fmt::Display for ArtifactReadContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigest => formatter
                .write_str("artifact digest must be canonical lower-case SHA-256 hexadecimal"),
            Self::InvalidMaxBytes { actual } => write!(
                formatter,
                "artifact max_bytes must be in 1..={MAX_ARTIFACT_CHUNK_BYTES}; got {actual}"
            ),
            Self::OffsetBeyondArtifact { offset, size_bytes } => write!(
                formatter,
                "artifact offset {offset} exceeds declared size {size_bytes}"
            ),
            Self::ChunkTooLarge { actual } => write!(
                formatter,
                "artifact chunk contains {actual} raw bytes; maximum is {MAX_ARTIFACT_CHUNK_BYTES}"
            ),
            Self::EmptyNonTerminalChunk => {
                formatter.write_str("artifact chunk cannot be empty before end-of-file")
            }
            Self::RangeOverflow => formatter.write_str("artifact chunk range overflows u64"),
            Self::ChunkBeyondArtifact {
                next_offset,
                size_bytes,
            } => write!(
                formatter,
                "artifact next offset {next_offset} exceeds declared size {size_bytes}"
            ),
            Self::InvalidEndOfFile { expected, actual } => write!(
                formatter,
                "artifact eof must be {expected} at the derived next offset; got {actual}"
            ),
            Self::InvalidNextOffset { expected, actual } => write!(
                formatter,
                "artifact next_offset must be {expected}; got {actual}"
            ),
        }
    }
}

impl std::error::Error for ArtifactReadContractError {}

fn validate_artifact_ref(artifact: &ArtifactRef) -> Result<(), ArtifactReadContractError> {
    Sha256Digest::parse(artifact.sha256.clone())
        .map(|_| ())
        .map_err(|_| ArtifactReadContractError::InvalidDigest)
}

mod canonical_base64 {
    use super::{BASE64_STANDARD, MAX_ARTIFACT_CHUNK_BASE64_BYTES};
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > MAX_ARTIFACT_CHUNK_BASE64_BYTES {
            return Err(serde::de::Error::custom(format_args!(
                "artifact base64 payload exceeds {MAX_ARTIFACT_CHUNK_BASE64_BYTES} characters"
            )));
        }
        let bytes = BASE64_STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        if BASE64_STANDARD.encode(&bytes) != encoded {
            return Err(serde::de::Error::custom(
                "artifact payload is not canonical standard base64",
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(byte: char, media_type: &str) -> ArtifactRef {
        ArtifactRef {
            sha256: byte.to_string().repeat(Sha256Digest::HEX_LENGTH),
            size_bytes: 128,
            media_type: media_type.to_owned(),
        }
    }

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(byte.to_string().repeat(Sha256Digest::HEX_LENGTH))
            .expect("test digest should be canonical")
    }

    fn provenance(backend_model: &BackendModelIdentity) -> Provenance {
        Provenance {
            producer: "birdcode-test-runtime".to_owned(),
            backend: Some(BackendSelection {
                backend_id: backend_model.backend_id.clone(),
                kind: backend_model.kind,
                model: Some(backend_model.model_id.clone()),
                reasoning_effort: None,
            }),
            raw_artifact: Some(artifact('f', "application/json")),
        }
    }

    #[test]
    fn request_round_trip_preserves_multilingual_text() {
        let request = ClientRequest::new(ClientCommand::CreateRun(CreateRunRequest {
            run_id: RunId::new(),
            spec: RunSpec {
                session_id: SessionId::new(),
                purpose: RunPurpose::PlanOnly,
                backend: BackendSelection {
                    backend_id: "ollama-local".to_owned(),
                    kind: BackendKind::Model,
                    model: Some("test-model".to_owned()),
                    reasoning_effort: None,
                },
                input: vec![InputItem::Text {
                    text: "Hej, 世界 och مرحباً 👋".to_owned(),
                }],
                limits: RunLimits::default(),
            },
        }));

        let encoded = serde_json::to_vec(&request).expect("request should serialize");
        let decoded: ClientRequest =
            serde_json::from_slice(&encoded).expect("request should deserialize");

        assert_eq!(decoded, request);
    }

    #[test]
    fn default_run_limits_grant_no_delegation_authority() {
        assert_eq!(RunLimits::default().max_subagents, 0);
    }

    #[test]
    fn run_with_id_preserves_client_allocated_identity() {
        let run_id = RunId::new();
        let spec = RunSpec {
            session_id: SessionId::new(),
            purpose: RunPurpose::PlanOnly,
            backend: BackendSelection {
                backend_id: "lmstudio-local".to_owned(),
                kind: BackendKind::Model,
                model: Some("gemma-4-26b".to_owned()),
                reasoning_effort: None,
            },
            input: vec![InputItem::Text {
                text: "Planera utan att ändra arbetsytan.".to_owned(),
            }],
            limits: RunLimits::default(),
        };

        let run = Run::with_id(run_id, spec);

        assert_eq!(run.id, run_id);
        assert_eq!(run.spec.purpose, RunPurpose::PlanOnly);
    }

    #[test]
    fn durable_planner_events_round_trip_with_explicit_causal_bindings() {
        let session_id = SessionId::new();
        let run_id = RunId::new();
        let actor_id = ActorId::new();
        let attempt_id = InferenceAttemptId::new();
        let reservation_id = TokenReservationId::new();
        let prepared_event_id = EventId::new();
        let observed_event_id = EventId::new();
        let backend_model = BackendModelIdentity {
            backend_id: "lmstudio-local".to_owned(),
            kind: BackendKind::Model,
            model_id: "gemma-4-26b-it-q8".to_owned(),
        };
        let common_provenance = provenance(&backend_model);
        let prepared = EventEnvelope {
            id: prepared_event_id,
            sequence: 41,
            session_id,
            run_id: Some(run_id),
            actor_id,
            causal_parent: None,
            occurred_at: Utc::now(),
            provenance: common_provenance.clone(),
            payload: EventPayload::PlannerInferencePrepared(PlannerInferencePrepared {
                attempt_id,
                parent_attempt_id: None,
                backend_model: backend_model.clone(),
                prompt_artifact: artifact('a', "application/vnd.birdcode.prompt+json"),
                prompt_manifest_digest: digest('5'),
                request_artifact: artifact('b', "application/json"),
                token_reservation: TokenReservation {
                    id: reservation_id,
                    reserved_tokens: 4_096,
                    max_output_tokens: 2_048,
                },
                plan_revision: 7,
                plan_digest: digest('c'),
                obligation_snapshot_digest: digest('1'),
                acceptance_policy_digest: digest('2'),
                context_manifest_digest: digest('3'),
                planner_policy_digest: digest('4'),
                cancellation_generation: 2,
            }),
        };
        let observed = EventEnvelope {
            id: observed_event_id,
            sequence: 42,
            session_id,
            run_id: Some(run_id),
            actor_id,
            causal_parent: Some(prepared_event_id),
            occurred_at: Utc::now(),
            provenance: common_provenance,
            payload: EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                attempt_id,
                token_reservation_id: reservation_id,
                prepared_event_id,
                normalized_complete_evidence_artifact: artifact(
                    'd',
                    "application/vnd.birdcode.inference-evidence+json",
                ),
                outcome: PlannerInferenceObservation::Succeeded {
                    reported_backend_model: backend_model,
                    token_usage: TokenUsage {
                        input_tokens: 512,
                        output_tokens: 768,
                        total_tokens: 1_280,
                        cached_input_tokens: Some(128),
                    },
                },
            }),
        };
        let page = EventPage {
            events: vec![prepared.clone(), observed.clone()],
            next_sequence: 43,
            has_more: false,
        };

        let encoded = serde_json::to_vec(&page).expect("event page should serialize");
        let decoded: EventPage =
            serde_json::from_slice(&encoded).expect("event page should deserialize");

        assert_eq!(decoded, page);
        assert_eq!(observed.causal_parent, Some(prepared.id));
        let EventPayload::PlannerInferencePrepared(prepared_payload) = prepared.payload else {
            panic!("expected prepared inference event")
        };
        let EventPayload::PlannerInferenceObserved(observed_payload) = observed.payload else {
            panic!("expected observed inference event")
        };
        assert_eq!(observed_payload.attempt_id, prepared_payload.attempt_id);
        assert_eq!(prepared_payload.parent_attempt_id, None);
        assert_eq!(prepared_payload.obligation_snapshot_digest, digest('1'));
        assert_eq!(prepared_payload.acceptance_policy_digest, digest('2'));
        assert_eq!(prepared_payload.context_manifest_digest, digest('3'));
        assert_eq!(prepared_payload.planner_policy_digest, digest('4'));
        assert_eq!(prepared_payload.prompt_manifest_digest, digest('5'));
        assert_eq!(
            observed_payload.token_reservation_id,
            prepared_payload.token_reservation.id
        );
        assert_eq!(observed_payload.prepared_event_id, prepared.id);
    }

    #[test]
    fn root_planning_failure_round_trips_as_a_closed_typed_event() {
        let claim_event_id = EventId::new();
        let evidence = artifact('e', "application/vnd.birdcode.root-planning-failure+json");
        let payload = EventPayload::RootPlanningFailed(RootPlanningFailed {
            claim_event_id,
            claim_id: RunClaimId::new(),
            cancellation_generation: 0,
            phase: RootPlanningFailurePhase::ModelDiscovery,
            reason: RootPlanningFailureReason::BackendDiscoveryFailed,
            evidence_artifact: evidence,
        });

        let encoded = serde_json::to_value(&payload).expect("failure event should serialize");
        assert_eq!(encoded["type"], "root_planning_failed");
        assert_eq!(encoded["data"]["phase"], "model_discovery");
        assert_eq!(encoded["data"]["reason"], "backend_discovery_failed");
        let decoded: EventPayload =
            serde_json::from_value(encoded.clone()).expect("failure event should deserialize");
        assert_eq!(decoded, payload);

        let mut untyped = encoded;
        untyped["data"]["message"] = serde_json::json!("do not classify this string");
        serde_json::from_value::<EventPayload>(untyped)
            .expect_err("the typed failure event must reject unclassified fields");
    }

    #[test]
    fn typed_protocol_shapes_reject_unknown_fields() {
        let session_id = SessionId::new();
        let run_id = RunId::new();
        let command = ClientCommand::GetEvents {
            session_id,
            after_sequence: 12,
        };
        let mut command_json = serde_json::to_value(command).expect("command should serialize");
        command_json["params"]["unexpected"] = serde_json::json!(true);
        serde_json::from_value::<ClientCommand>(command_json)
            .expect_err("get_events must reject unknown fields");

        let create = CreateRunRequest {
            run_id,
            spec: RunSpec {
                session_id,
                purpose: RunPurpose::PlanOnly,
                backend: BackendSelection {
                    backend_id: "ollama-local".to_owned(),
                    kind: BackendKind::Model,
                    model: Some("qwen".to_owned()),
                    reasoning_effort: None,
                },
                input: Vec::new(),
                limits: RunLimits::default(),
            },
        };
        let mut create_json = serde_json::to_value(create).expect("create run should serialize");
        create_json["unexpected"] = serde_json::json!(true);
        serde_json::from_value::<CreateRunRequest>(create_json)
            .expect_err("create_run must reject unknown fields");

        let prepared = EventPayload::PlannerInferencePrepared(PlannerInferencePrepared {
            attempt_id: InferenceAttemptId::new(),
            parent_attempt_id: Some(InferenceAttemptId::new()),
            backend_model: BackendModelIdentity {
                backend_id: "lmstudio-local".to_owned(),
                kind: BackendKind::Model,
                model_id: "gemma".to_owned(),
            },
            prompt_artifact: artifact('a', "application/json"),
            prompt_manifest_digest: digest('5'),
            request_artifact: artifact('b', "application/json"),
            token_reservation: TokenReservation {
                id: TokenReservationId::new(),
                reserved_tokens: 1_024,
                max_output_tokens: 512,
            },
            plan_revision: 0,
            plan_digest: digest('c'),
            obligation_snapshot_digest: digest('1'),
            acceptance_policy_digest: digest('2'),
            context_manifest_digest: digest('3'),
            planner_policy_digest: digest('4'),
            cancellation_generation: 0,
        });
        let mut prepared_json =
            serde_json::to_value(prepared).expect("prepared event should serialize");
        prepared_json["data"]["untyped_core_data"] = serde_json::json!({"leak": true});
        serde_json::from_value::<EventPayload>(prepared_json)
            .expect_err("typed planner payloads must reject unknown fields");

        serde_json::from_value::<EventPage>(serde_json::json!({
            "events": [],
            "next_sequence": 1,
            "has_more": false,
            "encoded_events": "forbidden"
        }))
        .expect_err("event pages must expose decoded events only");
    }

    #[test]
    fn artifact_read_round_trip_is_exact_bounded_and_path_free() {
        let mut artifact = artifact('a', "application/jsonl");
        artifact.size_bytes = 10;
        let request = GetArtifactRequest::new(artifact.clone(), 4, 64)
            .expect("bounded artifact request should be valid");
        let command = ClientCommand::GetArtifact(request.clone());

        let command_json = serde_json::to_value(&command).expect("command should serialize");
        assert_eq!(command_json["method"], "get_artifact");
        assert_eq!(
            command_json["params"]["artifact"]["sha256"],
            artifact.sha256
        );
        assert_eq!(command_json["params"]["offset"], 4);
        assert_eq!(command_json["params"]["max_bytes"], 64);
        assert!(command_json["params"].get("path").is_none());
        assert_eq!(
            serde_json::from_value::<ClientCommand>(command_json)
                .expect("command should deserialize"),
            command
        );

        let chunk = ArtifactChunk::new(artifact.clone(), 4, vec![0, 1, 2, 3, 254, 255], true)
            .expect("terminal artifact chunk should be valid");
        let result = ServerResult::ArtifactChunk(chunk.clone());
        let result_json = serde_json::to_value(&result).expect("result should serialize");

        assert_eq!(result_json["type"], "artifact_chunk");
        assert_eq!(result_json["data"]["offset"], 4);
        assert_eq!(result_json["data"]["next_offset"], 10);
        assert_eq!(result_json["data"]["eof"], true);
        assert_eq!(result_json["data"]["data_base64"], "AAECA/7/");
        assert_eq!(
            serde_json::from_value::<ServerResult>(result_json).expect("result should deserialize"),
            result
        );
        assert_eq!(chunk.artifact(), &artifact);
        assert_eq!(chunk.data(), &[0, 1, 2, 3, 254, 255]);
        assert_eq!(chunk.next_offset(), 10);
        assert!(chunk.eof());
    }

    #[test]
    fn artifact_request_rejects_unbounded_ranges_and_path_injection() {
        let artifact = artifact('b', "application/octet-stream");
        assert!(matches!(
            GetArtifactRequest::new(artifact.clone(), 0, 0),
            Err(ArtifactReadContractError::InvalidMaxBytes { actual: 0 })
        ));
        assert!(matches!(
            GetArtifactRequest::new(artifact.clone(), 0, MAX_ARTIFACT_CHUNK_BYTES + 1),
            Err(ArtifactReadContractError::InvalidMaxBytes { .. })
        ));
        assert!(matches!(
            GetArtifactRequest::new(artifact.clone(), artifact.size_bytes + 1, 1),
            Err(ArtifactReadContractError::OffsetBeyondArtifact { .. })
        ));

        let mut forged_digest = artifact.clone();
        forged_digest.sha256 = "A".repeat(Sha256Digest::HEX_LENGTH);
        assert!(matches!(
            GetArtifactRequest::new(forged_digest, 0, 1),
            Err(ArtifactReadContractError::InvalidDigest)
        ));

        let mut value = serde_json::to_value(
            GetArtifactRequest::new(artifact, 0, 1).expect("request should be valid"),
        )
        .expect("request should serialize");
        value["path"] = serde_json::json!("/private/forbidden");
        serde_json::from_value::<GetArtifactRequest>(value)
            .expect_err("artifact transport must reject path injection");
    }

    #[test]
    fn artifact_chunk_rejects_noncanonical_or_inconsistent_pages() {
        let mut artifact = artifact('c', "application/octet-stream");
        artifact.size_bytes = 3;
        let chunk = ArtifactChunk::new(artifact.clone(), 0, vec![0, 1, 2], true)
            .expect("chunk should be valid");
        let canonical = serde_json::to_value(chunk).expect("chunk should serialize");

        let mut noncanonical = canonical.clone();
        noncanonical["data_base64"] = serde_json::json!("AAEC====");
        serde_json::from_value::<ArtifactChunk>(noncanonical)
            .expect_err("noncanonical padding must be rejected");

        let mut wrong_cursor = canonical.clone();
        wrong_cursor["next_offset"] = serde_json::json!(2);
        serde_json::from_value::<ArtifactChunk>(wrong_cursor)
            .expect_err("next cursor must match decoded byte length");

        let mut wrong_eof = canonical;
        wrong_eof["eof"] = serde_json::json!(false);
        serde_json::from_value::<ArtifactChunk>(wrong_eof)
            .expect_err("eof must match the exact artifact size");

        assert!(matches!(
            ArtifactChunk::new(
                artifact.clone(),
                0,
                vec![0; MAX_ARTIFACT_CHUNK_BYTES as usize + 1],
                false,
            ),
            Err(ArtifactReadContractError::ChunkTooLarge { .. })
        ));
        assert!(matches!(
            ArtifactChunk::new(artifact.clone(), 0, Vec::new(), false),
            Err(ArtifactReadContractError::EmptyNonTerminalChunk)
        ));

        let oversized_encoded = "A".repeat(MAX_ARTIFACT_CHUNK_BASE64_BYTES + 4);
        serde_json::from_value::<ArtifactChunk>(serde_json::json!({
            "artifact": artifact,
            "offset": 0,
            "next_offset": 0,
            "eof": false,
            "data_base64": oversized_encoded
        }))
        .expect_err("encoded chunks must be rejected before an oversized decode");
    }

    #[test]
    fn sha256_digest_rejects_noncanonical_values() {
        assert!(Sha256Digest::parse("a".repeat(63)).is_err());
        assert!(Sha256Digest::parse("A".repeat(64)).is_err());
        assert!(Sha256Digest::parse("g".repeat(64)).is_err());
        assert_eq!(digest('0').as_str(), "0".repeat(64));
    }

    #[test]
    fn response_shape_cannot_be_success_and_error_at_once() {
        let response = ServerResponse::success(
            RequestId::new(),
            ServerResult::Health(Health {
                protocol_version: PROTOCOL_VERSION,
                status: HealthStatus::Ready,
                platform: "macos".to_owned(),
                architecture: "aarch64".to_owned(),
            }),
        );

        let value = serde_json::to_value(response).expect("response should serialize");
        assert_eq!(value["status"], "success");
        assert!(value.get("error").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unix_workspace_path_round_trip_preserves_non_utf8_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let bytes = b"/tmp/BirdCode-\xff-\xfe".to_vec();
        let native = PathBuf::from(OsString::from_vec(bytes.clone()));
        let path = WorkspacePath::from(native);

        let encoded = serde_json::to_vec(&path).expect("workspace path should serialize");
        let decoded: WorkspacePath =
            serde_json::from_slice(&encoded).expect("workspace path should deserialize");
        let restored = decoded.to_native().expect("Unix path should be native");

        assert_eq!(decoded.wire_version(), WORKSPACE_PATH_WIRE_VERSION);
        assert_eq!(decoded.unix_bytes(), Some(bytes.as_slice()));
        assert_eq!(restored.as_os_str().as_bytes(), bytes);
    }

    #[test]
    fn windows_workspace_path_wire_preserves_unpaired_utf16() {
        let code_units = vec![
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            0xd800,
            u16::from(b'x'),
        ];
        let path = WorkspacePath::from_windows_utf16(code_units.clone());

        let encoded = serde_json::to_value(&path).expect("workspace path should serialize");
        assert_eq!(
            encoded,
            serde_json::json!({
                "wire_version": 1,
                "representation": {
                    "encoding": "windows_utf16",
                    "code_units": code_units,
                },
            })
        );
        let decoded: WorkspacePath =
            serde_json::from_value(encoded).expect("workspace path should deserialize");

        assert_eq!(decoded.windows_utf16(), Some(code_units.as_slice()));
    }

    #[cfg(unix)]
    #[test]
    fn foreign_windows_workspace_path_is_not_lossily_converted_on_unix() {
        let path = WorkspacePath::from_windows_utf16(vec![0xd800]);

        assert!(matches!(
            path.to_native(),
            Err(WorkspacePathError::PlatformMismatch {
                encoded_for: "windows",
                native_family: "unix",
            })
        ));
    }

    #[test]
    fn workspace_path_rejects_unknown_wire_version() {
        let error = serde_json::from_value::<WorkspacePath>(serde_json::json!({
            "wire_version": WORKSPACE_PATH_WIRE_VERSION + 1,
            "representation": {
                "encoding": "unix_bytes",
                "bytes": [47, 116, 109, 112],
            },
        }))
        .expect_err("unknown path wire versions must fail closed");

        assert!(
            error
                .to_string()
                .contains("unsupported workspace path wire version")
        );
    }

    #[test]
    fn protocol_v4_create_session_rejects_legacy_string_paths() {
        let error = serde_json::from_value::<CreateSessionRequest>(serde_json::json!({
            "workspace_root": "/tmp/protocol-v1-path",
            "title": null,
        }))
        .expect_err("protocol v4 must not accept protocol-v1 PathBuf strings");

        assert!(error.to_string().contains("invalid type: string"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_round_trip_preserves_unpaired_utf16() {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let code_units = vec![u16::from(b'C'), u16::from(b':'), u16::from(b'\\'), 0xd800];
        let native = PathBuf::from(OsString::from_wide(&code_units));
        let wire = WorkspacePath::from(native);
        let restored = wire.to_native().expect("Windows path should be native");

        assert_eq!(
            restored.as_os_str().encode_wide().collect::<Vec<_>>(),
            code_units
        );
    }
}
