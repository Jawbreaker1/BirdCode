use crate::evidence::Sha256Digest;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

const MAX_IDENTIFIER_BYTES: usize = 256;

/// Structural failure for an opaque or externally supplied identity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds {maximum} UTF-8 bytes")]
    TooLong { field: &'static str, maximum: usize },
    #[error("{field} must be a non-nil UUID v{expected}; received UUID v{actual}")]
    WrongUuidVersion {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

macro_rules! text_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Preserves an exact provider-neutral identity.
            ///
            /// # Errors
            ///
            /// Returns a structural error for an empty or overlong identity.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                validate_text_id($field, &value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

fn validate_text_id(field: &'static str, value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentityError::TooLong {
            field,
            maximum: MAX_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

text_id!(AgentId, "agent_id");
text_id!(ProviderId, "provider_id");
text_id!(ModelId, "model_id");

macro_rules! opaque_v4_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a random, attribution-free UUID v4 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Imports an explicit UUID while preserving the v4 invariant.
            ///
            /// # Errors
            ///
            /// Rejects nil and non-v4 UUIDs.
            pub fn try_from_uuid(value: Uuid) -> Result<Self, IdentityError> {
                validate_uuid_version($field, value, 4)?;
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

fn validate_uuid_version(
    field: &'static str,
    value: Uuid,
    expected: usize,
) -> Result<(), IdentityError> {
    let actual = value.get_version_num();
    if value.is_nil() || actual != expected {
        return Err(IdentityError::WrongUuidVersion {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

opaque_v4_id!(CandidateId, "candidate_id");
opaque_v4_id!(EvaluationCaseId, "evaluation_case_id");

/// Declared provider/model selector retained locally, never sent as blind input.
///
/// This does not by itself prove backend, deployment, revision, weights, or
/// quantization; integrations must bind that richer manifest before claiming
/// exact model lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    provider_id: ProviderId,
    model_id: ModelId,
    configuration_sha256: Option<Sha256Digest>,
}

impl ModelIdentity {
    #[must_use]
    pub const fn new(
        provider_id: ProviderId,
        model_id: ModelId,
        configuration_sha256: Option<Sha256Digest>,
    ) -> Self {
        Self {
            provider_id,
            model_id,
            configuration_sha256,
        }
    }

    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        &self.model_id
    }

    #[must_use]
    pub const fn configuration_sha256(&self) -> Option<Sha256Digest> {
        self.configuration_sha256
    }
}

/// Explicit actor category retained for every attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ActorIdentity {
    /// A deterministic controller, adapter, or other non-model implementation.
    Deterministic {
        implementation_sha256: Sha256Digest,
        configuration_sha256: Sha256Digest,
    },
    /// An LLM-backed actor whose provider/model details stay in local provenance.
    Model { model: ModelIdentity },
}

/// Exact agent identity retained for a command attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    agent_id: AgentId,
    actor: ActorIdentity,
}

impl AgentIdentity {
    #[must_use]
    pub const fn new(agent_id: AgentId, actor: ActorIdentity) -> Self {
        Self { agent_id, actor }
    }

    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    #[must_use]
    pub const fn actor(&self) -> &ActorIdentity {
        &self.actor
    }

    #[must_use]
    pub const fn model(&self) -> Option<&ModelIdentity> {
        match &self.actor {
            ActorIdentity::Model { model } => Some(model),
            ActorIdentity::Deterministic { .. } => None,
        }
    }
}
