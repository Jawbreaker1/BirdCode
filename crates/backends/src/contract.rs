use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// A boxed backend operation. Dropping the future cancels client-side work.
pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// A provider-neutral asynchronous model backend.
pub trait ModelBackend: Send + Sync {
    fn backend_id(&self) -> &BackendId;

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
            operation,
            kind,
            message: message.into(),
            evidence: evidence.map(Box::new),
        }
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
