use crate::{TargetId, provenance::AttemptId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

const SHA256_BYTES: usize = 32;
const SHA256_HEX_BYTES: usize = SHA256_BYTES * 2;

/// SHA-256 digest serialized as exactly 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; SHA256_BYTES]);

impl Sha256Digest {
    #[must_use]
    pub fn of_bytes(value: &[u8]) -> Self {
        Self(Sha256::digest(value).into())
    }

    #[must_use]
    pub const fn from_array(value: [u8; SHA256_BYTES]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_BYTES] {
        &self.0
    }

    /// Parses the canonical lowercase wire representation.
    ///
    /// # Errors
    ///
    /// Rejects incorrect length, uppercase, and non-hexadecimal input.
    pub fn parse_hex(value: &str) -> Result<Self, DigestError> {
        let bytes = value.as_bytes();
        if bytes.len() != SHA256_HEX_BYTES {
            return Err(DigestError::WrongLength {
                actual: bytes.len(),
            });
        }

        let mut digest = [0_u8; SHA256_BYTES];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            digest[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(digest))
    }
}

fn hex_nibble(byte: u8) -> Result<u8, DigestError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(DigestError::NonCanonicalHex),
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = [0_u8; SHA256_HEX_BYTES];
        for (index, byte) in self.0.iter().copied().enumerate() {
            output[index * 2] = HEX[usize::from(byte >> 4)];
            output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        let value = std::str::from_utf8(&output).map_err(|_| fmt::Error)?;
        formatter.write_str(value)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// Canonical digest parsing failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DigestError {
    #[error("SHA-256 digest has {actual} characters; expected 64")]
    WrongLength { actual: usize },
    #[error("SHA-256 digest must use lowercase hexadecimal characters")]
    NonCanonicalHex,
}

/// Structural failure for an opaque evidence identity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{field} must be a non-nil UUID v4; received UUID v{actual}")]
pub struct EvidenceIdError {
    field: &'static str,
    actual: usize,
}

macro_rules! opaque_evidence_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Imports an opaque identity without allowing timestamp-bearing IDs.
            ///
            /// # Errors
            ///
            /// Rejects nil and non-v4 UUIDs.
            pub fn try_from_uuid(value: Uuid) -> Result<Self, EvidenceIdError> {
                let actual = value.get_version_num();
                if value.is_nil() || actual != 4 {
                    return Err(EvidenceIdError {
                        field: $field,
                        actual,
                    });
                }
                Ok(Self(value))
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

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::try_from_uuid(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_evidence_id!(ArtifactId, "artifact_id");
opaque_evidence_id!(CheckId, "check_id");

/// Artifact role declared by an adapter, never inferred from a path or MIME type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ArtifactKind {
    StdoutLog,
    StderrLog,
    RuntimeLog,
    CompilerOutput,
    TestReport,
    AccessibilitySnapshot,
    DomSnapshot,
    ApiTranscript,
    ProcessState,
    Trace,
    Screenshot,
    Video,
    BuildProduct,
    Auxiliary,
}

impl ArtifactKind {
    #[must_use]
    pub const fn evidence_class(self) -> Option<EvidenceClass> {
        match self {
            Self::Screenshot | Self::Video => Some(EvidenceClass::Vision),
            Self::Auxiliary => None,
            Self::StdoutLog
            | Self::StderrLog
            | Self::RuntimeLog
            | Self::CompilerOutput
            | Self::TestReport
            | Self::AccessibilitySnapshot
            | Self::DomSnapshot
            | Self::ApiTranscript
            | Self::ProcessState
            | Self::Trace
            | Self::BuildProduct => Some(EvidenceClass::PrimaryMechanical),
        }
    }
}

/// Content-addressed artifact retained by the provenance store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub artifact_id: ArtifactId,
    pub attempt_id: AttemptId,
    pub kind: ArtifactKind,
    pub sha256: Sha256Digest,
    pub retained_bytes: u64,
    pub observed_bytes: Option<u64>,
    pub truncated: bool,
    pub media_type: String,
    pub storage_ref: TargetId,
}

/// Fixed trust class for a validation check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    PrimaryMechanical,
    Vision,
}

/// Check category. Its evidence class is fixed in code, not caller-controlled.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum CheckKind {
    Compiler,
    Test,
    Accessibility,
    DomState,
    ProcessState,
    ApiState,
    CliState,
    TuiState,
    DesktopState,
    DeviceState,
    LogAssertion,
    TraceAssertion,
    ArtifactIntegrity,
    Visual,
}

impl CheckKind {
    #[must_use]
    pub const fn evidence_class(self) -> EvidenceClass {
        match self {
            Self::Visual => EvidenceClass::Vision,
            Self::Compiler
            | Self::Test
            | Self::Accessibility
            | Self::DomState
            | Self::ProcessState
            | Self::ApiState
            | Self::CliState
            | Self::TuiState
            | Self::DesktopState
            | Self::DeviceState
            | Self::LogAssertion
            | Self::TraceAssertion
            | Self::ArtifactIntegrity => EvidenceClass::PrimaryMechanical,
        }
    }

    /// Closed mechanical compatibility matrix for typed artifact evidence.
    #[must_use]
    pub fn is_artifact_compatible(self, artifact: ArtifactKind) -> bool {
        match self {
            Self::Compiler => {
                matches!(
                    artifact,
                    ArtifactKind::CompilerOutput | ArtifactKind::BuildProduct
                )
            }
            Self::Test => matches!(artifact, ArtifactKind::TestReport),
            Self::Accessibility => matches!(artifact, ArtifactKind::AccessibilitySnapshot),
            Self::DomState => matches!(artifact, ArtifactKind::DomSnapshot),
            Self::ProcessState => matches!(artifact, ArtifactKind::ProcessState),
            Self::ApiState => matches!(artifact, ArtifactKind::ApiTranscript),
            Self::CliState | Self::TuiState => matches!(
                artifact,
                ArtifactKind::StdoutLog
                    | ArtifactKind::StderrLog
                    | ArtifactKind::RuntimeLog
                    | ArtifactKind::ProcessState
            ),
            Self::DesktopState | Self::DeviceState => matches!(
                artifact,
                ArtifactKind::RuntimeLog
                    | ArtifactKind::AccessibilitySnapshot
                    | ArtifactKind::ProcessState
            ),
            Self::LogAssertion => matches!(
                artifact,
                ArtifactKind::StdoutLog | ArtifactKind::StderrLog | ArtifactKind::RuntimeLog
            ),
            Self::TraceAssertion => matches!(artifact, ArtifactKind::Trace),
            Self::ArtifactIntegrity => {
                artifact.evidence_class() == Some(EvidenceClass::PrimaryMechanical)
            }
            Self::Visual => matches!(artifact, ArtifactKind::Screenshot | ArtifactKind::Video),
        }
    }

    /// Whether a process exit can mechanically contribute to this check kind.
    #[must_use]
    pub const fn is_exit_compatible(self) -> bool {
        matches!(
            self,
            Self::Compiler | Self::Test | Self::ProcessState | Self::CliState | Self::TuiState
        )
    }
}

/// Normalized check outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    Failed,
    Inconclusive,
}

/// Causal evidence referenced by a check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum CheckEvidence {
    Artifact { artifact_id: ArtifactId },
    AttemptExit { attempt_id: AttemptId },
}

/// One adapter-produced validation observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationCheck {
    pub check_id: CheckId,
    pub attempt_id: AttemptId,
    pub kind: CheckKind,
    pub outcome: CheckOutcome,
    pub evidence: Vec<CheckEvidence>,
}
