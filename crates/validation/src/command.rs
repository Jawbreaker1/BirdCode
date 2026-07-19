use crate::{Sha256Digest, TargetId};
use birdcode_protocol::WorkspacePath;
use serde::{Deserialize, Serialize};

/// Hard ceilings enforced by an execution adapter and rechecked in provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBounds {
    pub max_records: u32,
    pub max_attempts: u32,
    pub max_checks: u32,
    pub max_check_evidence_items: u32,
    pub max_total_evidence_items: u32,
    pub max_total_elapsed_ms: u64,
    pub max_timeout_ms: u64,
    pub max_argv_items: u32,
    pub max_argument_bytes: u64,
    pub max_path_bytes: u64,
    pub max_environment_entries: u32,
    pub max_environment_bytes: u64,
    pub max_toolchain_entries: u32,
    pub max_metadata_bytes: u64,
    pub max_url_bytes: u64,
    pub max_storage_ref_bytes: u64,
    pub max_stdin_bytes: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_artifacts: u32,
    pub max_artifact_bytes: u64,
    pub max_total_artifact_bytes: u64,
    pub max_runtime_log_bytes: u64,
    pub max_trace_bytes: u64,
    pub max_screenshots: u32,
    pub max_videos: u32,
}

impl Default for ExecutionBounds {
    fn default() -> Self {
        Self {
            max_records: 4_096,
            max_attempts: 512,
            max_checks: 512,
            max_check_evidence_items: 128,
            max_total_evidence_items: 4_096,
            max_total_elapsed_ms: 7_200_000,
            max_timeout_ms: 900_000,
            max_argv_items: 512,
            max_argument_bytes: 1_048_576,
            max_path_bytes: 1_048_576,
            max_environment_entries: 256,
            max_environment_bytes: 1_048_576,
            max_toolchain_entries: 128,
            max_metadata_bytes: 1_048_576,
            max_url_bytes: 16_384,
            max_storage_ref_bytes: 4_096,
            max_stdin_bytes: 1_048_576,
            max_stdout_bytes: 16_777_216,
            max_stderr_bytes: 16_777_216,
            max_artifacts: 512,
            max_artifact_bytes: 268_435_456,
            max_total_artifact_bytes: 1_073_741_824,
            max_runtime_log_bytes: 67_108_864,
            max_trace_bytes: 268_435_456,
            max_screenshots: 128,
            max_videos: 16,
        }
    }
}

/// Per-command output capture request; it cannot exceed the run bounds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureLimits {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

/// A value retained directly or referenced without persisting a secret.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "retention", rename_all = "snake_case")]
pub enum EnvironmentValue {
    PlainText {
        value: NativeArgument,
    },
    SecretReference {
        reference: TargetId,
        encoding: NativeEncoding,
        resolved_bytes: u64,
    },
    Sha256Only {
        sha256: Sha256Digest,
        encoding: NativeEncoding,
        resolved_bytes: u64,
    },
    Redacted {
        encoding: NativeEncoding,
        resolved_bytes: u64,
    },
}

impl EnvironmentValue {
    #[must_use]
    pub fn resolved_bytes(&self) -> u64 {
        match self {
            Self::PlainText { value } => u64::try_from(value.encoded_bytes()).unwrap_or(u64::MAX),
            Self::SecretReference { resolved_bytes, .. }
            | Self::Sha256Only { resolved_bytes, .. }
            | Self::Redacted { resolved_bytes, .. } => *resolved_bytes,
        }
    }

    #[must_use]
    pub const fn encoding(&self) -> NativeEncoding {
        match self {
            Self::PlainText { value } => value.encoding(),
            Self::SecretReference { encoding, .. }
            | Self::Sha256Only { encoding, .. }
            | Self::Redacted { encoding, .. } => *encoding,
        }
    }

    #[must_use]
    pub fn retained_metadata_bytes(&self) -> usize {
        match self {
            Self::PlainText { value } => value.encoded_bytes(),
            Self::SecretReference { reference, .. } => reference.as_str().len(),
            Self::Sha256Only { .. } => 32,
            Self::Redacted { .. } => 0,
        }
    }
}

/// Retained argv value; secret material is represented only by a broker key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "retention", rename_all = "snake_case")]
pub enum RetainedArgument {
    PlainText {
        value: NativeArgument,
    },
    SecretReference {
        reference: TargetId,
        encoding: NativeEncoding,
        resolved_bytes: u64,
    },
    Sha256Only {
        sha256: Sha256Digest,
        encoding: NativeEncoding,
        resolved_bytes: u64,
    },
    Redacted {
        encoding: NativeEncoding,
        resolved_bytes: u64,
    },
}

impl RetainedArgument {
    #[must_use]
    pub fn resolved_bytes(&self) -> u64 {
        match self {
            Self::PlainText { value } => u64::try_from(value.encoded_bytes()).unwrap_or(u64::MAX),
            Self::SecretReference { resolved_bytes, .. }
            | Self::Sha256Only { resolved_bytes, .. }
            | Self::Redacted { resolved_bytes, .. } => *resolved_bytes,
        }
    }

    #[must_use]
    pub const fn encoding(&self) -> NativeEncoding {
        match self {
            Self::PlainText { value } => value.encoding(),
            Self::SecretReference { encoding, .. }
            | Self::Sha256Only { encoding, .. }
            | Self::Redacted { encoding, .. } => *encoding,
        }
    }
}

/// Retained stdin bytes; secret material is represented only by a broker key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "retention", rename_all = "snake_case")]
pub enum RetainedStdin {
    PlainText {
        bytes: Vec<u8>,
    },
    SecretReference {
        reference: TargetId,
        resolved_bytes: u64,
    },
    Sha256Only {
        sha256: Sha256Digest,
        resolved_bytes: u64,
    },
    Redacted {
        resolved_bytes: u64,
    },
}

impl RetainedStdin {
    #[must_use]
    pub fn resolved_bytes(&self) -> u64 {
        match self {
            Self::PlainText { bytes } => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            Self::SecretReference { resolved_bytes, .. }
            | Self::Sha256Only { resolved_bytes, .. }
            | Self::Redacted { resolved_bytes } => *resolved_bytes,
        }
    }
}

/// Lossless native argv/environment value for Unix and Windows families.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "encoding", rename_all = "snake_case")]
pub enum NativeArgument {
    UnixBytes { bytes: Vec<u8> },
    WindowsUtf16 { code_units: Vec<u16> },
}

impl NativeArgument {
    #[must_use]
    pub const fn from_unix_bytes(bytes: Vec<u8>) -> Self {
        Self::UnixBytes { bytes }
    }

    #[must_use]
    pub const fn from_windows_utf16(code_units: Vec<u16>) -> Self {
        Self::WindowsUtf16 { code_units }
    }

    #[must_use]
    pub fn encoded_bytes(&self) -> usize {
        match self {
            Self::UnixBytes { bytes } => bytes.len(),
            Self::WindowsUtf16 { code_units } => code_units.len().saturating_mul(2),
        }
    }

    #[must_use]
    pub const fn encoding(&self) -> NativeEncoding {
        match self {
            Self::UnixBytes { .. } => NativeEncoding::UnixBytes,
            Self::WindowsUtf16 { .. } => NativeEncoding::WindowsUtf16,
        }
    }

    #[must_use]
    pub fn contains_nul(&self) -> bool {
        match self {
            Self::UnixBytes { bytes } => bytes.contains(&0),
            Self::WindowsUtf16 { code_units } => code_units.contains(&0),
        }
    }
}

/// Wire encoding family for a native command value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeEncoding {
    UnixBytes,
    WindowsUtf16,
}

/// Environment entry retained without forcing Unicode or persisting secrets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEntry {
    pub name: NativeArgument,
    pub value: EnvironmentValue,
}

/// Command contract using an executable and argv, never a shell command string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub executable: WorkspacePath,
    pub arguments: Vec<RetainedArgument>,
    pub working_directory: WorkspacePath,
    pub environment: Vec<EnvironmentEntry>,
    pub stdin: Option<RetainedStdin>,
    pub capture: CaptureLimits,
}

/// Operating system reported by the execution environment, never inferred.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "family", rename_all = "snake_case")]
pub enum OperatingSystem {
    MacOs,
    Windows,
    Linux,
    Android,
    IosSimulator,
    IpadOsSimulator,
    TvOsSimulator,
    WatchOsSimulator,
    VisionOsSimulator,
    Other { platform_id: TargetId },
}

/// Exact tool version retained for reproduction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainEntry {
    pub tool_id: TargetId,
    pub version: String,
    pub executable_sha256: Option<Sha256Digest>,
}

/// Explicit environment/toolchain snapshot supplied by an adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSnapshot {
    pub operating_system: OperatingSystem,
    pub architecture: String,
    pub os_version: String,
    pub locale: Option<String>,
    pub selected_variables: Vec<EnvironmentEntry>,
    pub toolchain: Vec<ToolchainEntry>,
}

/// Normalized process outcome retained independently of provider/model details.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ProcessExit {
    Exited { code: i32 },
    Signaled { signal: i32 },
    TimedOut,
    Cancelled,
    LaunchFailed { failure_code: TargetId },
}
