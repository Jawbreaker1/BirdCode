use crate::canonical;
use crate::compiler::{CompiledPrompt, PromptInvocation};
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

pub const MANIFEST_SCHEMA_JSON: &str = include_str!("../schemas/prompt-manifest.schema.json");
pub const TASK_ROUTER_MANIFEST_V1_0_0_JSON: &str =
    include_str!("../../../prompts/semantic-task-router/1.0.0/manifest.json");
pub const TASK_ROUTER_MANIFEST_V1_1_0_JSON: &str =
    include_str!("../../../prompts/semantic-task-router/1.1.0/manifest.json");
pub const TASK_ROUTER_MANIFEST_V1_1_1_JSON: &str =
    include_str!("../../../prompts/semantic-task-router/1.1.1/manifest.json");
pub const TASK_ROUTER_MANIFEST_V1_1_2_JSON: &str =
    include_str!("../../../prompts/semantic-task-router/1.1.2/manifest.json");
pub const TASK_ROUTER_MANIFEST_JSON: &str =
    include_str!("../../../prompts/semantic-task-router/1.1.3/manifest.json");
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("prompt JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{target} is not a valid JSON Schema: {message}")]
    SchemaCompilation { target: String, message: String },
    #[error("{target} failed JSON Schema validation: {errors:?}")]
    SchemaValidation { target: String, errors: Vec<String> },
    #[error("prompt identifier is invalid: {0}")]
    InvalidPromptId(String),
    #[error("prompt manifest field {0} must not be empty")]
    EmptyManifestField(&'static str),
    #[error("prompt {0} is already registered")]
    DuplicatePrompt(PromptKey),
    #[error("prompt {0} is not registered")]
    PromptNotFound(PromptKey),
    #[error("input section name is duplicated: {0}")]
    DuplicateSection(String),
    #[error("input section {section} violates its declared trust boundary")]
    TrustBoundary { section: String },
    #[error("compiled prompt does not match registered manifest {0}")]
    CompiledPromptMismatch(PromptKey),
    #[error("model output violates semantic-router invariants: {0:?}")]
    OutputInvariant(Vec<crate::router::RouterInvariantViolation>),
    #[error("generation schema contains an invalid dynamic directive: {0}")]
    GenerationSchemaDirective(String),
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PromptId(String);

impl PromptId {
    /// Creates a stable, machine-readable prompt identifier.
    ///
    /// # Errors
    ///
    /// Returns an error unless the identifier consists of lowercase ASCII
    /// segments separated by `.` or `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, PromptError> {
        let value = value.into();
        if valid_prompt_id(&value) {
            Ok(Self(value))
        } else {
            Err(PromptError::InvalidPromptId(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PromptId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PromptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn valid_prompt_id(value: &str) -> bool {
    let mut characters = value.bytes();
    let Some(first) = characters.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    let mut previous_was_separator = false;
    for character in characters {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            previous_was_separator = false;
        } else if matches!(character, b'.' | b'-') && !previous_was_separator {
            previous_was_separator = true;
        } else {
            return false;
        }
    }
    !previous_was_separator
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PromptKey {
    pub id: PromptId,
    pub version: Version,
}

impl PromptKey {
    #[must_use]
    pub const fn new(id: PromptId, version: Version) -> Self {
        Self { id, version }
    }
}

impl fmt::Display for PromptKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.id, self.version)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptRole {
    System,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptManifest {
    pub manifest_schema_version: u32,
    pub id: PromptId,
    pub version: Version,
    pub role: PromptRole,
    pub purpose: String,
    pub system_policy: String,
    pub input_schema: Value,
    /// Conservative schema supplied to provider grammar engines. The full
    /// output contract remains authoritative for local acceptance.
    pub generation_schema: Value,
    pub output_schema: Value,
}

impl PromptManifest {
    #[must_use]
    pub fn key(&self) -> PromptKey {
        PromptKey::new(self.id.clone(), self.version.clone())
    }

    /// Computes a stable digest of the typed manifest representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be serialized.
    pub fn content_sha256(&self) -> Result<String, PromptError> {
        let encoded = canonical::encode(&serde_json::to_value(self)?)?;
        let digest = Sha256::digest(encoded.as_bytes());
        let mut hash = String::with_capacity(64);
        for byte in digest {
            hash.push(char::from(HEX[usize::from(byte >> 4)]));
            hash.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(hash)
    }

    fn validate(&self) -> Result<(), PromptError> {
        let meta_schema = serde_json::from_str::<Value>(MANIFEST_SCHEMA_JSON)?;
        validate_value(
            &meta_schema,
            &serde_json::to_value(self)?,
            "prompt manifest",
        )?;
        if self.purpose.trim().is_empty() {
            return Err(PromptError::EmptyManifestField("purpose"));
        }
        if self.system_policy.trim().is_empty() {
            return Err(PromptError::EmptyManifestField("system_policy"));
        }
        ensure_object_contract(&self.input_schema, "input_schema")?;
        ensure_object_contract(&self.generation_schema, "generation_schema")?;
        ensure_object_contract(&self.output_schema, "output_schema")?;
        compile_schema(&self.input_schema, "input_schema")?;
        compile_schema(&self.generation_schema, "generation_schema")?;
        validate_generation_directives(&self.generation_schema)?;
        compile_schema(&self.output_schema, "output_schema")?;
        Ok(())
    }
}

/// Parses and validates one complete prompt manifest.
///
/// # Errors
///
/// Returns an error for invalid JSON, manifest shape, identifiers, semantic
/// versions, or embedded JSON Schemas.
pub fn parse_manifest(bytes: &[u8]) -> Result<PromptManifest, PromptError> {
    let value = serde_json::from_slice::<Value>(bytes)?;
    let meta_schema = serde_json::from_str::<Value>(MANIFEST_SCHEMA_JSON)?;
    validate_value(&meta_schema, &value, "prompt manifest")?;
    let manifest = serde_json::from_value::<PromptManifest>(value)?;
    manifest.validate()?;
    Ok(manifest)
}

/// Returns a registry containing every prompt embedded by this crate.
///
/// # Errors
///
/// Returns an error if a bundled manifest is invalid or duplicated.
pub fn builtin_registry() -> Result<PromptRegistry, PromptError> {
    PromptRegistry::new([
        parse_manifest(TASK_ROUTER_MANIFEST_V1_0_0_JSON.as_bytes())?,
        parse_manifest(TASK_ROUTER_MANIFEST_V1_1_0_JSON.as_bytes())?,
        parse_manifest(TASK_ROUTER_MANIFEST_V1_1_1_JSON.as_bytes())?,
        parse_manifest(TASK_ROUTER_MANIFEST_V1_1_2_JSON.as_bytes())?,
        parse_manifest(TASK_ROUTER_MANIFEST_JSON.as_bytes())?,
    ])
}

#[derive(Clone, Debug, Default)]
pub struct PromptRegistry {
    manifests: BTreeMap<PromptKey, PromptManifest>,
}

impl PromptRegistry {
    /// Builds a validated registry and rejects duplicate `(id, version)` keys.
    ///
    /// # Errors
    ///
    /// Returns an error when a manifest is invalid or a key is duplicated.
    pub fn new(manifests: impl IntoIterator<Item = PromptManifest>) -> Result<Self, PromptError> {
        let mut registry = Self::default();
        for manifest in manifests {
            registry.register(manifest)?;
        }
        Ok(registry)
    }

    /// Adds one manifest without replacing an existing version.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest is invalid or already registered.
    pub fn register(&mut self, manifest: PromptManifest) -> Result<(), PromptError> {
        manifest.validate()?;
        let key = manifest.key();
        if self.manifests.contains_key(&key) {
            return Err(PromptError::DuplicatePrompt(key));
        }
        self.manifests.insert(key, manifest);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, key: &PromptKey) -> Option<&PromptManifest> {
        self.manifests.get(key)
    }

    /// Compiles one invocation into provider-neutral messages.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown prompt, invalid trust boundaries, or an
    /// invocation that does not satisfy the manifest input schema.
    pub fn compile(
        &self,
        key: &PromptKey,
        invocation: &PromptInvocation,
    ) -> Result<CompiledPrompt, PromptError> {
        let manifest = self
            .get(key)
            .ok_or_else(|| PromptError::PromptNotFound(key.clone()))?;
        CompiledPrompt::compile(manifest, invocation)
    }

    /// Validates a JSON value against a prompt's declared output schema and an
    /// independently supplied authoritative invocation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown prompt or schema-invalid output.
    pub fn validate_output(
        &self,
        compiled: &CompiledPrompt,
        invocation: &PromptInvocation,
        value: &Value,
    ) -> Result<(), PromptError> {
        let key = &compiled.manifest.prompt;
        let manifest = self
            .get(key)
            .ok_or_else(|| PromptError::PromptNotFound(key.clone()))?;
        compiled.validate_against(manifest, invocation)?;
        validate_value(&manifest.output_schema, value, "model output")?;
        if crate::router::is_task_router_key(key) {
            crate::router::validate_router_output(value, invocation, &key.version)?;
        }
        Ok(())
    }

    /// Parses, schema-validates, and deserializes typed model output.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, an unknown prompt, schema-invalid
    /// output, or a mismatch with the requested Rust type.
    pub fn decode_output<T: DeserializeOwned>(
        &self,
        compiled: &CompiledPrompt,
        invocation: &PromptInvocation,
        bytes: &[u8],
    ) -> Result<T, PromptError> {
        let value = serde_json::from_slice::<Value>(bytes)?;
        self.validate_output(compiled, invocation, &value)?;
        serde_json::from_value(value).map_err(PromptError::from)
    }
}

pub(crate) fn validate_value(
    schema: &Value,
    value: &Value,
    target: &str,
) -> Result<(), PromptError> {
    let validator =
        jsonschema::validator_for(schema).map_err(|error| PromptError::SchemaCompilation {
            target: target.to_owned(),
            message: error.to_string(),
        })?;
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(PromptError::SchemaValidation {
            target: target.to_owned(),
            errors,
        })
    }
}

fn compile_schema(schema: &Value, target: &str) -> Result<(), PromptError> {
    jsonschema::validator_for(schema)
        .map(|_| ())
        .map_err(|error| PromptError::SchemaCompilation {
            target: target.to_owned(),
            message: error.to_string(),
        })
}

fn ensure_object_contract(schema: &Value, target: &str) -> Result<(), PromptError> {
    let valid = schema
        .as_object()
        .is_some_and(|object| object.get("type") == Some(&Value::String("object".to_owned())));
    if valid {
        Ok(())
    } else {
        Err(PromptError::SchemaCompilation {
            target: target.to_owned(),
            message: "top-level schema must declare type object".to_owned(),
        })
    }
}

fn validate_generation_directives(value: &Value) -> Result<(), PromptError> {
    match value {
        Value::Array(values) => {
            for value in values {
                validate_generation_directives(value)?;
            }
        }
        Value::Object(object) => {
            if let Some(directive) = object.get("x-birdcode-dynamic-enum")
                && (directive.as_str() != Some("input_section_names")
                    || object.get("type").and_then(Value::as_str) != Some("string")
                    || object.contains_key("enum"))
            {
                return Err(PromptError::GenerationSchemaDirective(
                    directive.to_string(),
                ));
            }
            for value in object.values() {
                validate_generation_directives(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
