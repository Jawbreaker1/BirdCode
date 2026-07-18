//! Canonical, transport-independent protocol types for `BirdCode`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

/// Canonical request/response protocol version.
///
/// Version 2 replaces serde's platform-dependent `PathBuf` JSON encoding with
/// an explicit, lossless [`WorkspacePath`] wire value.
pub const PROTOCOL_VERSION: u32 = 2;

/// Version of the path representation nested inside protocol messages.
pub const WORKSPACE_PATH_WIRE_VERSION: u32 = 1;

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
uuid_id!(EventId);
uuid_id!(RequestId);
uuid_id!(RunId);
uuid_id!(SessionId);

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
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum ClientCommand {
    Initialize(InitializeRequest),
    Health,
    CreateSession(CreateSessionRequest),
    GetSession { session_id: SessionId },
    CreateRun(CreateRunRequest),
    GetRun { run_id: RunId },
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
    Session(Session),
    Run(Run),
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
pub struct CreateRunRequest {
    pub spec: RunSpec,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunSpec {
    pub session_id: SessionId,
    pub backend: BackendSelection,
    pub input: Vec<InputItem>,
    pub limits: RunLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunLimits {
    pub max_output_tokens: Option<u64>,
    pub max_wall_time_seconds: Option<u64>,
    pub max_subagents: u32,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            max_output_tokens: None,
            max_wall_time_seconds: None,
            max_subagents: 4,
        }
    }
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
        Self {
            id: RunId::new(),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewEvent {
    pub session_id: SessionId,
    pub run_id: Option<RunId>,
    pub actor_id: ActorId,
    pub causal_parent: Option<EventId>,
    pub provenance: Provenance,
    pub payload: EventPayload,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Provenance {
    pub producer: String,
    pub backend: Option<BackendSelection>,
    pub raw_artifact: Option<ArtifactRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
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
    BackendEvent {
        event_type: String,
        data: serde_json::Value,
    },
    ArtifactStored {
        artifact: ArtifactRef,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRef {
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_preserves_multilingual_text() {
        let request = ClientRequest::new(ClientCommand::CreateRun(CreateRunRequest {
            spec: RunSpec {
                session_id: SessionId::new(),
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
    fn protocol_v2_create_session_rejects_legacy_string_paths() {
        let error = serde_json::from_value::<CreateSessionRequest>(serde_json::json!({
            "workspace_root": "/tmp/protocol-v1-path",
            "title": null,
        }))
        .expect_err("protocol v2 must not accept protocol-v1 PathBuf strings");

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
