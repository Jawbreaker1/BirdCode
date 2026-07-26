use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use url::Url;

const BACKEND_INSTANCE_IDENTITY_SCHEMA_VERSION: u32 = 1;
const BACKEND_INSTANCE_IDENTITY_DOMAIN: &str = "birdcode.backend-instance-identity.v1";
const DERIVED_DEPLOYMENT_ID_DOMAIN: &str = "birdcode.backend-origin-deployment.v1";
const MAX_BACKEND_DEPLOYMENT_ID_BYTES: usize = 512;
const MAX_BACKEND_ORIGIN_BYTES: usize = 2_048;

/// A boxed backend operation. Dropping the future cancels client-side work.
pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// A provider-neutral asynchronous model backend.
pub trait ModelBackend: Send + Sync {
    fn backend_id(&self) -> &BackendId;

    /// Returns the exact configured adapter instance used for every call.
    ///
    /// This is required rather than defaulted: an executor must be able to
    /// compare a prepared authority with the concrete backend before creating
    /// a provider future. The identity attests configured routing only. It
    /// does not attest model weights, a physical host, or review independence.
    fn instance_identity(&self) -> &BackendInstanceIdentity;

    fn discover_models(&self) -> BackendFuture<'_, ModelCatalog>;

    /// Performs one structured inference request.
    ///
    /// An `Ok` response must represent a complete provider generation. A
    /// backend that observes truncation or another incomplete finish condition
    /// must return [`BackendErrorKind::IncompleteResponse`] instead. The
    /// provider-specific `finish_reason` remains opaque to callers.
    fn infer_structured(
        &self,
        request: StructuredInferenceRequest,
    ) -> BackendFuture<'_, StructuredInferenceResponse>;
}

/// Identifies a backend provider/implementation (for example `lmstudio`).
///
/// It is not a unique configured endpoint instance; endpoint provenance is
/// carried separately in HTTP evidence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BackendId(String);

impl BackendId {
    /// Creates a non-empty backend identity without changing its spelling.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::EmptyIdentifier`] when `value` is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ContractError::EmptyIdentifier {
                field: "backend_id",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn known(value: &'static str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for BackendId {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<BackendId> for String {
    fn from(value: BackendId) -> Self {
        value.0
    }
}

/// Opaque configured deployment/instance identifier.
///
/// The identifier is adapter configuration, not a provider statement and not
/// evidence of distinct model weights or physical infrastructure.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct BackendDeploymentId(String);

impl BackendDeploymentId {
    /// Creates a bounded, non-empty configured deployment identifier without
    /// interpreting its contents.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an empty or overlong identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, BackendInstanceIdentityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(BackendInstanceIdentityError::EmptyDeploymentId);
        }
        if value.len() > MAX_BACKEND_DEPLOYMENT_ID_BYTES {
            return Err(BackendInstanceIdentityError::DeploymentIdTooLong {
                maximum: MAX_BACKEND_DEPLOYMENT_ID_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// Derives the default LM Studio deployment identifier from the exact
    /// configured provider and canonical transport origin.
    pub(crate) fn derived_for_origin(
        backend_id: &BackendId,
        origin: &BackendEndpointOrigin,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DERIVED_DEPLOYMENT_ID_DOMAIN.as_bytes());
        hasher.update([0]);
        hasher.update(backend_id.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(origin.as_str().as_bytes());
        Self(format!(
            "origin-sha256:{}",
            encode_sha256(hasher.finalize())
        ))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BackendDeploymentId {
    type Error = BackendInstanceIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<BackendDeploymentId> for String {
    fn from(value: BackendDeploymentId) -> Self {
        value.0
    }
}

/// Canonical HTTP(S) origin with credentials, path, query, and fragment
/// excluded by construction.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct BackendEndpointOrigin(String);

impl BackendEndpointOrigin {
    /// Derives the canonical origin from one HTTP(S) URL.
    ///
    /// # Errors
    ///
    /// Rejects unsupported/opaque URLs and URLs carrying user information.
    pub fn from_http_url(url: &Url) -> Result<Self, BackendInstanceIdentityError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(BackendInstanceIdentityError::UnsupportedOriginScheme);
        }
        if url.host_str().is_none() {
            return Err(BackendInstanceIdentityError::MissingOriginHost);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(BackendInstanceIdentityError::OriginContainsUserInfo);
        }
        let value = url.origin().ascii_serialization();
        if value == "null" || value.len() > MAX_BACKEND_ORIGIN_BYTES {
            return Err(BackendInstanceIdentityError::InvalidCanonicalOrigin);
        }
        Ok(Self(value))
    }

    /// Parses an already canonical origin and rejects alternate spellings.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical or unsafe origin strings.
    pub fn parse(value: impl Into<String>) -> Result<Self, BackendInstanceIdentityError> {
        let value = value.into();
        let url =
            Url::parse(&value).map_err(|_| BackendInstanceIdentityError::InvalidCanonicalOrigin)?;
        if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
            return Err(BackendInstanceIdentityError::InvalidCanonicalOrigin);
        }
        let canonical = Self::from_http_url(&url)?;
        if canonical.0 == value {
            Ok(canonical)
        } else {
            Err(BackendInstanceIdentityError::InvalidCanonicalOrigin)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Checks that response evidence came from this exact origin.
    #[must_use]
    pub fn matches_endpoint(&self, endpoint: &str) -> bool {
        Url::parse(endpoint).is_ok_and(|url| {
            url.username().is_empty()
                && url.password().is_none()
                && Self::from_http_url(&url).is_ok_and(|actual| actual == *self)
        })
    }
}

impl TryFrom<String> for BackendEndpointOrigin {
    type Error = BackendInstanceIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<BackendEndpointOrigin> for String {
    fn from(value: BackendEndpointOrigin) -> Self {
        value.0
    }
}

/// Typed provider-neutral transport scope for one configured backend.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum BackendTransportIdentity {
    HttpOrigin { origin: BackendEndpointOrigin },
}

/// Strict canonical SHA-256 digest for a backend instance identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct BackendInstanceDigest(String);

impl BackendInstanceDigest {
    fn of_bytes(bytes: &[u8]) -> Self {
        Self(encode_sha256(Sha256::digest(bytes)))
    }

    /// Parses one exact lowercase SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical digests.
    pub fn parse(value: impl Into<String>) -> Result<Self, BackendInstanceIdentityError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            Ok(Self(value))
        } else {
            Err(BackendInstanceIdentityError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BackendInstanceDigest {
    type Error = BackendInstanceIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<BackendInstanceDigest> for String {
    fn from(value: BackendInstanceDigest) -> Self {
        value.0
    }
}

#[derive(Serialize)]
struct BackendInstanceIdentityHashMaterial<'a> {
    domain: &'static str,
    schema_version: u32,
    backend_id: &'a BackendId,
    transport: &'a BackendTransportIdentity,
    configured_deployment_id: &'a BackendDeploymentId,
}

/// Backend-authored attestation of one exact configured dispatch target.
///
/// `identity_sha256` is a domain-separated digest over the provider class,
/// typed transport scope, and configured deployment ID. It proves request
/// routing equality only; it does not prove deployment independence or model
/// weight identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendInstanceIdentity {
    schema_version: u32,
    backend_id: BackendId,
    transport: BackendTransportIdentity,
    configured_deployment_id: BackendDeploymentId,
    identity_sha256: BackendInstanceDigest,
}

impl BackendInstanceIdentity {
    /// Constructs and hashes one backend identity from an already typed
    /// transport scope.
    ///
    /// # Errors
    ///
    /// Returns a typed error only when canonical encoding is impossible.
    pub fn new(
        backend_id: BackendId,
        transport: BackendTransportIdentity,
        configured_deployment_id: BackendDeploymentId,
    ) -> Result<Self, BackendInstanceIdentityError> {
        Self::build(backend_id, transport, configured_deployment_id)
    }

    /// Constructs and hashes one HTTP-origin-bound backend identity.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an unsafe origin or impossible canonical
    /// encoding.
    pub fn for_http_origin(
        backend_id: BackendId,
        configured_deployment_id: BackendDeploymentId,
        url: &Url,
    ) -> Result<Self, BackendInstanceIdentityError> {
        let transport = BackendTransportIdentity::HttpOrigin {
            origin: BackendEndpointOrigin::from_http_url(url)?,
        };
        Self::build(backend_id, transport, configured_deployment_id)
    }

    fn build(
        backend_id: BackendId,
        transport: BackendTransportIdentity,
        configured_deployment_id: BackendDeploymentId,
    ) -> Result<Self, BackendInstanceIdentityError> {
        let encoded = serde_json::to_vec(&BackendInstanceIdentityHashMaterial {
            domain: BACKEND_INSTANCE_IDENTITY_DOMAIN,
            schema_version: BACKEND_INSTANCE_IDENTITY_SCHEMA_VERSION,
            backend_id: &backend_id,
            transport: &transport,
            configured_deployment_id: &configured_deployment_id,
        })
        .map_err(|error| BackendInstanceIdentityError::Encoding(error.to_string()))?;
        Ok(Self {
            schema_version: BACKEND_INSTANCE_IDENTITY_SCHEMA_VERSION,
            backend_id,
            transport,
            configured_deployment_id,
            identity_sha256: BackendInstanceDigest::of_bytes(&encoded),
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub const fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    #[must_use]
    pub const fn transport(&self) -> &BackendTransportIdentity {
        &self.transport
    }

    #[must_use]
    pub const fn configured_deployment_id(&self) -> &BackendDeploymentId {
        &self.configured_deployment_id
    }

    #[must_use]
    pub const fn identity_sha256(&self) -> &BackendInstanceDigest {
        &self.identity_sha256
    }

    #[must_use]
    pub const fn endpoint_origin(&self) -> &BackendEndpointOrigin {
        match &self.transport {
            BackendTransportIdentity::HttpOrigin { origin } => origin,
        }
    }

    /// Recomputes the digest and exact internal relationships.
    ///
    /// # Errors
    ///
    /// Rejects schema or digest substitution.
    pub fn validate_integrity(&self) -> Result<(), BackendInstanceIdentityError> {
        if self.schema_version != BACKEND_INSTANCE_IDENTITY_SCHEMA_VERSION {
            return Err(BackendInstanceIdentityError::UnsupportedSchemaVersion {
                actual: self.schema_version,
            });
        }
        let expected = Self::build(
            self.backend_id.clone(),
            self.transport.clone(),
            self.configured_deployment_id.clone(),
        )?;
        if expected.identity_sha256 == self.identity_sha256 {
            Ok(())
        } else {
            Err(BackendInstanceIdentityError::DigestMismatch)
        }
    }

    /// Validates exact response identity plus same-origin endpoint evidence.
    #[must_use]
    pub fn matches_response_evidence(&self, evidence: &InferenceEvidence) -> bool {
        evidence.backend_id == self.backend_id
            && evidence.backend_instance.as_ref() == Some(self)
            && self.endpoint_origin().matches_endpoint(&evidence.endpoint)
    }
}

impl<'de> Deserialize<'de> for BackendInstanceIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Repr {
            schema_version: u32,
            backend_id: BackendId,
            transport: BackendTransportIdentity,
            configured_deployment_id: BackendDeploymentId,
            identity_sha256: BackendInstanceDigest,
        }

        let repr = Repr::deserialize(deserializer)?;
        if repr.schema_version != BACKEND_INSTANCE_IDENTITY_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(
                BackendInstanceIdentityError::UnsupportedSchemaVersion {
                    actual: repr.schema_version,
                },
            ));
        }
        let expected = Self::build(
            repr.backend_id,
            repr.transport,
            repr.configured_deployment_id,
        )
        .map_err(serde::de::Error::custom)?;
        if expected.identity_sha256 != repr.identity_sha256 {
            return Err(serde::de::Error::custom(
                BackendInstanceIdentityError::DigestMismatch,
            ));
        }
        Ok(expected)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BackendInstanceIdentityError {
    #[error("configured backend deployment ID must not be empty")]
    EmptyDeploymentId,
    #[error("configured backend deployment ID exceeds {maximum} bytes")]
    DeploymentIdTooLong { maximum: usize },
    #[error("backend endpoint origin scheme must be http or https")]
    UnsupportedOriginScheme,
    #[error("backend endpoint origin must contain a host")]
    MissingOriginHost,
    #[error("backend endpoint origin must not contain user information")]
    OriginContainsUserInfo,
    #[error("backend endpoint origin is not an exact canonical HTTP(S) origin")]
    InvalidCanonicalOrigin,
    #[error("backend instance digest must be exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("unsupported backend instance identity schema version {actual}")]
    UnsupportedSchemaVersion { actual: u32 },
    #[error("backend instance identity digest does not bind its exact content")]
    DigestMismatch,
    #[error("backend instance identity could not be encoded: {0}")]
    Encoding(String),
}

fn encode_sha256(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ModelId(String);

impl ModelId {
    /// Preserves an exact non-empty model identifier reported by a backend.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::EmptyIdentifier`] when `value` is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ContractError::EmptyIdentifier { field: "model_id" });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for ModelId {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ModelId> for String {
    fn from(value: ModelId) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    System,
    Developer,
    User,
    Assistant,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub content: String,
}

impl Message {
    #[must_use]
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StructuredOutputSpec {
    name: String,
    #[serde(alias = "schema")]
    validation_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation_schema: Option<Value>,
}

impl StructuredOutputSpec {
    /// Creates a named JSON Schema output contract.
    ///
    /// The name is a mechanical API identifier, not a semantic classifier.
    /// Schema validity and resource-safety checks are performed by the backend
    /// before an HTTP request is sent.
    ///
    /// # Errors
    ///
    /// Returns a typed contract error for an empty, overlong, or unsupported
    /// schema name.
    pub fn new(name: impl Into<String>, schema: Value) -> Result<Self, ContractError> {
        Self::build(name.into(), schema, None)
    }

    /// Creates an output contract with a distinct provider-facing generation
    /// schema and authoritative local validation schema.
    ///
    /// The generation schema is sent unchanged to the provider. The returned
    /// value is always validated against `validation_schema`; `BirdCode` never
    /// projects a response from one shape into the other.
    ///
    /// # Errors
    ///
    /// Returns a typed contract error for an empty, overlong, or unsupported
    /// schema name. Each schema is validated by the selected backend before
    /// inference.
    pub fn new_with_generation_schema(
        name: impl Into<String>,
        validation_schema: Value,
        generation_schema: Value,
    ) -> Result<Self, ContractError> {
        Self::build(name.into(), validation_schema, Some(generation_schema))
    }

    fn build(
        name: String,
        validation_schema: Value,
        generation_schema: Option<Value>,
    ) -> Result<Self, ContractError> {
        if name.is_empty() {
            return Err(ContractError::EmptyIdentifier {
                field: "output_schema_name",
            });
        }
        if name.len() > 64 {
            return Err(ContractError::IdentifierTooLong {
                field: "output_schema_name",
                maximum: 64,
            });
        }
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(ContractError::InvalidSchemaName);
        }
        Ok(Self {
            name,
            validation_schema,
            generation_schema,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn validation_schema(&self) -> &Value {
        &self.validation_schema
    }

    /// Returns the schema sent to the provider's constrained generation API.
    /// For contracts created with [`Self::new`], this is exactly the
    /// authoritative validation schema.
    #[must_use]
    pub fn generation_schema(&self) -> &Value {
        self.generation_schema
            .as_ref()
            .unwrap_or(&self.validation_schema)
    }

    /// Returns the authoritative local validation schema.
    ///
    /// Prefer [`Self::validation_schema`] in new code where the distinction
    /// from provider-facing generation constraints matters.
    #[must_use]
    pub const fn schema(&self) -> &Value {
        self.validation_schema()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningSetting {
    Off,
    On,
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StructuredInferenceRequest {
    model_id: ModelId,
    messages: Vec<Message>,
    output: StructuredOutputSpec,
    max_output_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reasoning: Option<ReasoningSetting>,
}

impl StructuredInferenceRequest {
    /// Creates a non-streamed structured inference request.
    ///
    /// # Errors
    ///
    /// Returns a contract error if there are no messages or the output token
    /// budget is zero.
    pub fn new(
        model_id: ModelId,
        messages: Vec<Message>,
        output: StructuredOutputSpec,
        max_output_tokens: u32,
    ) -> Result<Self, ContractError> {
        if messages.is_empty() {
            return Err(ContractError::NoMessages);
        }
        if max_output_tokens == 0 {
            return Err(ContractError::ZeroOutputTokens);
        }
        Ok(Self {
            model_id,
            messages,
            output,
            max_output_tokens,
            reasoning: None,
        })
    }

    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        &self.model_id
    }

    #[must_use]
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    #[must_use]
    pub const fn output(&self) -> &StructuredOutputSpec {
        &self.output
    }

    #[must_use]
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    /// Requests a provider reasoning setting. Backends that cannot represent
    /// the setting must reject it rather than silently rewrite it.
    #[must_use]
    pub fn with_reasoning(mut self, reasoning: ReasoningSetting) -> Self {
        self.reasoning = Some(reasoning);
        self
    }

    #[must_use]
    pub const fn reasoning(&self) -> Option<ReasoningSetting> {
        self.reasoning
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StructuredInferenceResponse {
    /// Exact model identity returned in the completion envelope. It must match
    /// the request's model identity byte-for-byte.
    pub model_id: ModelId,
    pub value: Value,
    /// Original assistant content before JSON decoding. Decoding it as JSON
    /// must produce exactly `value`.
    pub raw_text: String,
    /// Provider-specific, opaque completion metadata. Backends must reject an
    /// incomplete response instead of encoding completeness assumptions here.
    pub finish_reason: Option<String>,
    pub usage: Option<TokenUsage>,
    pub evidence: InferenceEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelCatalog {
    pub backend_id: BackendId,
    /// Exact configured instance that produced this catalog, suitable for
    /// typed policy configuration without reimplementing identity derivation.
    pub backend_instance: BackendInstanceIdentity,
    pub models: Vec<ModelDescriptor>,
    pub evidence: DiscoveryEvidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelDescriptor {
    /// Exact identifier returned by the OpenAI-compatible model endpoint.
    pub id: ModelId,
    pub kind: ModelKind,
    pub display_name: Option<String>,
    pub publisher: Option<String>,
    pub architecture: Option<String>,
    pub load_state: ModelLoadState,
    pub loaded_instances: Vec<LoadedInstance>,
    pub maximum_context_tokens: Option<u64>,
    pub quantization: Option<Quantization>,
    pub capabilities: ModelCapabilities,
    pub native_match: NativeMatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    Language,
    Embedding,
    Other(String),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLoadState {
    Loaded,
    NotLoaded,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoadedInstance {
    pub id: String,
    pub context_length: Option<u64>,
    /// Provider-reported simultaneous inference lanes for this exact loaded
    /// instance. `None` means discovery did not attest a capacity; callers
    /// must not substitute a model-name heuristic.
    #[serde(default)]
    pub parallel_capacity: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Quantization {
    pub name: Option<String>,
    pub bits_per_weight: Option<f64>,
    pub selected_variant: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelCapabilities {
    pub vision: CapabilityState,
    /// Whether LM Studio reports the model as trained for tool use. This does
    /// not assert that every tool call will be correct.
    pub trained_for_tool_use: CapabilityState,
    pub reasoning: Option<ReasoningCapabilities>,
}

impl ModelCapabilities {
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            vision: CapabilityState::Unknown,
            trained_for_tool_use: CapabilityState::Unknown,
            reasoning: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReasoningCapabilities {
    pub allowed_options: Vec<ReasoningOption>,
    pub default: ReasoningOption,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReasoningOption(pub String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMatch {
    None,
    Exact(NativeMatchKey),
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMatchKey {
    LoadedInstance,
    ModelKey,
    SelectedVariant,
    Variant,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryEvidence {
    pub openai: HttpEvidence,
    pub native: NativeDiscoveryEvidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NativeDiscoveryEvidence {
    Available { response: HttpEvidence },
    Unavailable { error: BackendError },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpEvidence {
    pub endpoint: String,
    pub status: u16,
    /// SHA-256 of the exact response body bytes received from the provider.
    pub response_body_sha256: String,
    pub body: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InferenceEvidence {
    pub backend_id: BackendId,
    /// Exact configured dispatch identity asserted by the concrete adapter.
    /// Callers must compare this with pre-dispatch authority and also verify
    /// that `endpoint` has the bound origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_instance: Option<BackendInstanceIdentity>,
    pub endpoint: String,
    pub status: u16,
    pub completion_id: Option<String>,
    /// SHA-256 of the exact response body bytes received from the provider.
    pub response_body_sha256: Option<String>,
    pub raw_response: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendOperation {
    Configure,
    DiscoverOpenAiModels,
    DiscoverNativeModels,
    StructuredInference,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendErrorKind {
    InvalidConfiguration,
    InvalidRequest,
    Unsupported,
    InvalidSchema,
    Transport,
    Timeout,
    RequestTooLarge,
    ResponseTooLarge,
    HttpStatus,
    MalformedResponse,
    ResponseContractViolation,
    SchemaViolation,
    IncompleteResponse,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendErrorEvidence {
    pub endpoint: Option<String>,
    pub status: Option<u16>,
    /// SHA-256 of the exact complete response body, when one was received.
    pub response_body_sha256: Option<String>,
    pub raw_response: Option<Value>,
    pub response_preview: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{backend_id} {operation:?} failed ({kind:?}): {message}")]
pub struct BackendError {
    pub backend_id: BackendId,
    /// Exact configured instance for errors returned by a constructed backend
    /// operation. Configuration-time failures legitimately have no instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_instance: Option<Box<BackendInstanceIdentity>>,
    pub operation: BackendOperation,
    pub kind: BackendErrorKind,
    pub message: String,
    pub evidence: Option<Box<BackendErrorEvidence>>,
}

impl BackendError {
    pub(crate) fn new(
        backend_id: &BackendId,
        operation: BackendOperation,
        kind: BackendErrorKind,
        message: impl Into<String>,
        evidence: Option<BackendErrorEvidence>,
    ) -> Self {
        Self {
            backend_id: backend_id.clone(),
            backend_instance: None,
            operation,
            kind,
            message: message.into(),
            evidence: evidence.map(Box::new),
        }
    }

    pub(crate) fn bind_instance(mut self, instance: &BackendInstanceIdentity) -> Self {
        debug_assert_eq!(&self.backend_id, instance.backend_id());
        self.backend_instance = Some(Box::new(instance.clone()));
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractError {
    #[error("{field} must not be empty")]
    EmptyIdentifier { field: &'static str },
    #[error("{field} exceeds its maximum length of {maximum} bytes")]
    IdentifierTooLong { field: &'static str, maximum: usize },
    #[error("output schema name may contain only ASCII letters, digits, '_' and '-'")]
    InvalidSchemaName,
    #[error("a structured inference request requires at least one message")]
    NoMessages,
    #[error("max_output_tokens must be greater than zero")]
    ZeroOutputTokens,
}
