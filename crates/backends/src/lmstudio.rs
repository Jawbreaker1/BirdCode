use crate::contract::{
    BackendError, BackendErrorEvidence, BackendErrorKind, BackendFuture, BackendId,
    BackendOperation, CapabilityState, DiscoveryEvidence, HttpEvidence, InferenceEvidence,
    LoadedInstance, Message, MessageRole, ModelBackend, ModelCapabilities, ModelCatalog,
    ModelDescriptor, ModelId, ModelKind, ModelLoadState, NativeDiscoveryEvidence, NativeMatch,
    NativeMatchKey, Quantization, ReasoningCapabilities, ReasoningOption, ReasoningSetting,
    StructuredInferenceRequest, StructuredInferenceResponse, TokenUsage,
};
use futures_util::StreamExt as _;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::ptr;
use std::time::Duration;
use url::Host;

const BACKEND_NAME: &str = "lmstudio";
const OPENAI_MODELS_PATH: &str = "/v1/models";
const NATIVE_MODELS_PATH: &str = "/api/v1/models";
const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const ERROR_PREVIEW_BYTES: usize = 2_048;
const MAX_SCHEMA_NODES: usize = 100_000;
const MAX_SCHEMA_DEPTH: usize = 128;
const REQUEST_ENVELOPE_LOWER_BOUND: usize = 128;
const MESSAGE_ENVELOPE_LOWER_BOUND: usize = 32;
const SERIALIZATION_INITIAL_CAPACITY: usize = 8 * 1024;

/// An API token whose debug representation never exposes its contents.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretToken(String);

impl SecretToken {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

/// Hard limits applied by the LM Studio HTTP adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpLimits {
    pub connect_timeout: Duration,
    /// Deadline for each discovery request, including optional enrichment.
    pub discovery_timeout: Duration,
    /// Deadline for one structured inference request.
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    /// Hard provider-side generation ceiling. Runtime budgets may lower it but
    /// can never raise it for this configured adapter.
    pub max_output_tokens: u32,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            discovery_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(120),
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 2 * 1024 * 1024,
            max_output_tokens: 32_768,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LmStudioConfig {
    pub base_url: Url,
    pub api_token: Option<SecretToken>,
    pub limits: HttpLimits,
}

impl LmStudioConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            api_token: None,
            limits: HttpLimits::default(),
        }
    }
}

#[derive(Clone)]
pub struct LmStudioBackend {
    backend_id: BackendId,
    base_url: Url,
    limits: HttpLimits,
    client: Client,
}

impl fmt::Debug for LmStudioBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LmStudioBackend")
            .field("backend_id", &self.backend_id)
            .field("base_url", &self.base_url)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl LmStudioBackend {
    /// Builds a read-only-discovery and inference adapter.
    ///
    /// Redirects and environment proxies are disabled so prompts and optional
    /// bearer credentials cannot be forwarded outside the configured origin.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error for unsafe URLs, invalid limits,
    /// invalid credentials, or HTTP client construction failures.
    pub fn new(config: LmStudioConfig) -> Result<Self, BackendError> {
        let backend_id = BackendId::known(BACKEND_NAME);
        validate_config(&backend_id, &config)?;

        let mut headers = HeaderMap::new();
        if let Some(token) = &config.api_token {
            let authorization = format!("Bearer {}", token.expose());
            let mut value = HeaderValue::from_str(&authorization).map_err(|_| {
                configuration_error(&backend_id, "API token cannot be encoded as an HTTP header")
            })?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }

        let client = Client::builder()
            .connect_timeout(config.limits.connect_timeout)
            .timeout(config.limits.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .default_headers(headers)
            .build()
            .map_err(|error| {
                configuration_error(
                    &backend_id,
                    format!("could not construct HTTP client: {error}"),
                )
            })?;

        Ok(Self {
            backend_id,
            base_url: config.base_url,
            limits: config.limits,
            client,
        })
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(path);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
    }

    async fn discover(&self) -> Result<ModelCatalog, BackendError> {
        let openai_endpoint = self.endpoint(OPENAI_MODELS_PATH);
        let openai_http = self
            .request_json(
                BackendOperation::DiscoverOpenAiModels,
                Method::GET,
                openai_endpoint,
                None,
            )
            .await?;
        let openai: OpenAiModelsResponse =
            self.decode_success(BackendOperation::DiscoverOpenAiModels, &openai_http)?;
        validate_openai_models(&self.backend_id, &openai_http, &openai)?;

        let native_endpoint = self.endpoint(NATIVE_MODELS_PATH);
        let native_result = self
            .request_json(
                BackendOperation::DiscoverNativeModels,
                Method::GET,
                native_endpoint,
                None,
            )
            .await
            .and_then(|http| {
                self.decode_success::<NativeModelsResponse>(
                    BackendOperation::DiscoverNativeModels,
                    &http,
                )
                .map(|native| (http, native))
            });

        let (models, native_evidence) = match native_result {
            Ok((native_http, native)) => (
                join_catalog(&openai, Some(&native)),
                NativeDiscoveryEvidence::Available {
                    response: native_http
                        .evidence(&self.backend_id, BackendOperation::DiscoverNativeModels)?,
                },
            ),
            Err(error) => (
                join_catalog(&openai, None),
                NativeDiscoveryEvidence::Unavailable { error },
            ),
        };

        Ok(ModelCatalog {
            backend_id: self.backend_id.clone(),
            models,
            evidence: DiscoveryEvidence {
                openai: openai_http
                    .evidence(&self.backend_id, BackendOperation::DiscoverOpenAiModels)?,
                native: native_evidence,
            },
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn infer(
        &self,
        request: StructuredInferenceRequest,
    ) -> Result<StructuredInferenceResponse, BackendError> {
        validate_request_contract(&self.backend_id, &self.limits, &request)?;
        preflight_request_structure(&self.backend_id, &self.limits, &request)?;
        let reasoning_effort = lmstudio_reasoning_effort(&self.backend_id, request.reasoning())?;
        let validator = compile_schema_validator(
            &self.backend_id,
            request.output().validation_schema(),
            "authoritative validation",
        )?;
        let _generation_validator = compile_schema_validator(
            &self.backend_id,
            request.output().generation_schema(),
            "provider generation",
        )?;
        let payload = ChatCompletionRequest {
            model: request.model_id().as_str(),
            messages: request.messages(),
            response_format: ResponseFormat {
                kind: "json_schema",
                json_schema: JsonSchemaFormat {
                    name: request.output().name(),
                    strict: true,
                    schema: request.output().generation_schema(),
                },
            },
            max_tokens: request.max_output_tokens(),
            reasoning_effort,
            stream: false,
        };
        let body =
            encode_request_capped(&self.backend_id, &payload, self.limits.max_request_bytes)?;

        let endpoint = self.endpoint(CHAT_COMPLETIONS_PATH);
        let http = self
            .request_json(
                BackendOperation::StructuredInference,
                Method::POST,
                endpoint,
                Some(body),
            )
            .await?;
        let raw_response =
            http.json_value(&self.backend_id, BackendOperation::StructuredInference)?;
        let completion: ChatCompletionResponse = serde_json::from_value(raw_response.clone())
            .map_err(|error| {
                malformed_error(
                    &self.backend_id,
                    BackendOperation::StructuredInference,
                    &http,
                    format!("chat completion envelope is invalid: {error}"),
                )
            })?;
        if completion.model != request.model_id().as_str() {
            return Err(BackendError::new(
                &self.backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::ResponseContractViolation,
                "completion model identity does not match the requested model",
                Some(BackendErrorEvidence {
                    endpoint: Some(http.endpoint.clone()),
                    status: Some(http.status),
                    response_body_sha256: Some(sha256_bytes(&http.body)),
                    raw_response: Some(raw_response.clone()),
                    response_preview: None,
                }),
            ));
        }
        let mut primary_choices = completion.choices.iter().filter(|choice| choice.index == 0);
        let choice = primary_choices.next().ok_or_else(|| {
            malformed_error(
                &self.backend_id,
                BackendOperation::StructuredInference,
                &http,
                "chat completion has no choice with index 0",
            )
        })?;
        if primary_choices.next().is_some() {
            return Err(malformed_error(
                &self.backend_id,
                BackendOperation::StructuredInference,
                &http,
                "chat completion contains duplicate choices with index 0",
            ));
        }
        if choice.message.role != "assistant" {
            return Err(malformed_error(
                &self.backend_id,
                BackendOperation::StructuredInference,
                &http,
                "choice 0 message role is not assistant",
            ));
        }
        if choice.finish_reason.as_deref() != Some("stop") {
            return Err(BackendError::new(
                &self.backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::IncompleteResponse,
                format!(
                    "structured completion did not finish normally (finish_reason={:?})",
                    choice.finish_reason
                ),
                Some(BackendErrorEvidence {
                    endpoint: Some(http.endpoint.clone()),
                    status: Some(http.status),
                    response_body_sha256: Some(sha256_bytes(&http.body)),
                    raw_response: Some(raw_response.clone()),
                    response_preview: None,
                }),
            ));
        }
        let raw_text = choice.message.content.clone().ok_or_else(|| {
            malformed_error(
                &self.backend_id,
                BackendOperation::StructuredInference,
                &http,
                "choice 0 has no string assistant content",
            )
        })?;
        let value: Value = serde_json::from_str(&raw_text).map_err(|error| {
            BackendError::new(
                &self.backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::MalformedResponse,
                format!("assistant content is not valid JSON: {error}"),
                Some(BackendErrorEvidence {
                    endpoint: Some(http.endpoint.clone()),
                    status: Some(http.status),
                    response_body_sha256: Some(sha256_bytes(&http.body)),
                    raw_response: Some(raw_response.clone()),
                    response_preview: None,
                }),
            )
        })?;
        if let Err(first_error) = validator.validate(&value) {
            let message = format!("assistant JSON violates the requested schema: {first_error}");
            return Err(BackendError::new(
                &self.backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::SchemaViolation,
                message,
                Some(BackendErrorEvidence {
                    endpoint: Some(http.endpoint.clone()),
                    status: Some(http.status),
                    response_body_sha256: Some(sha256_bytes(&http.body)),
                    raw_response: Some(raw_response.clone()),
                    response_preview: None,
                }),
            ));
        }
        let model_id = ModelId::new(completion.model).map_err(|error| {
            malformed_error(
                &self.backend_id,
                BackendOperation::StructuredInference,
                &http,
                format!("completion returned an invalid model identity: {error}"),
            )
        })?;

        Ok(StructuredInferenceResponse {
            model_id,
            value,
            raw_text,
            finish_reason: choice.finish_reason.clone(),
            usage: completion.usage.map(TokenUsage::from),
            evidence: InferenceEvidence {
                backend_id: self.backend_id.clone(),
                endpoint: http.endpoint,
                status: http.status,
                completion_id: completion.id,
                response_body_sha256: Some(sha256_bytes(&http.body)),
                raw_response,
            },
        })
    }

    async fn request_json(
        &self,
        operation: BackendOperation,
        method: Method,
        endpoint: Url,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, BackendError> {
        let endpoint_text = endpoint.to_string();
        let timeout = match &operation {
            BackendOperation::DiscoverOpenAiModels | BackendOperation::DiscoverNativeModels => {
                self.limits.discovery_timeout
            }
            BackendOperation::Configure | BackendOperation::StructuredInference => {
                self.limits.request_timeout
            }
        };
        let mut request = self
            .client
            .request(method, endpoint)
            .timeout(timeout)
            .header(ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request.send().await.map_err(|error| {
            transport_error(&self.backend_id, operation.clone(), &endpoint_text, &error)
        })?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > self.limits.max_response_bytes as u64)
        {
            return Err(BackendError::new(
                &self.backend_id,
                operation,
                BackendErrorKind::ResponseTooLarge,
                format!(
                    "response Content-Length exceeds configured maximum of {} bytes",
                    self.limits.max_response_bytes
                ),
                Some(BackendErrorEvidence {
                    endpoint: Some(endpoint_text),
                    status: Some(status.as_u16()),
                    response_body_sha256: None,
                    raw_response: None,
                    response_preview: None,
                }),
            ));
        }

        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                transport_error(&self.backend_id, operation.clone(), &endpoint_text, &error)
            })?;
            if bytes.len().saturating_add(chunk.len()) > self.limits.max_response_bytes {
                return Err(BackendError::new(
                    &self.backend_id,
                    operation,
                    BackendErrorKind::ResponseTooLarge,
                    format!(
                        "response body exceeds configured maximum of {} bytes",
                        self.limits.max_response_bytes
                    ),
                    Some(BackendErrorEvidence {
                        endpoint: Some(endpoint_text),
                        status: Some(status.as_u16()),
                        response_body_sha256: None,
                        raw_response: None,
                        response_preview: None,
                    }),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        let response = HttpResponse {
            endpoint: endpoint_text,
            status: status.as_u16(),
            body: bytes,
        };
        if !status.is_success() {
            return Err(http_status_error(&self.backend_id, operation, &response));
        }
        Ok(response)
    }

    fn decode_success<T>(
        &self,
        operation: BackendOperation,
        response: &HttpResponse,
    ) -> Result<T, BackendError>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_slice(&response.body).map_err(|error| {
            malformed_error(
                &self.backend_id,
                operation,
                response,
                format!("response body is not the expected JSON shape: {error}"),
            )
        })
    }
}

impl ModelBackend for LmStudioBackend {
    fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
        Box::pin(self.discover())
    }

    fn infer_structured(
        &self,
        request: StructuredInferenceRequest,
    ) -> BackendFuture<'_, StructuredInferenceResponse> {
        Box::pin(self.infer(request))
    }
}

#[derive(Debug)]
struct HttpResponse {
    endpoint: String,
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json_value(
        &self,
        backend_id: &BackendId,
        operation: BackendOperation,
    ) -> Result<Value, BackendError> {
        serde_json::from_slice(&self.body).map_err(|error| {
            malformed_error(
                backend_id,
                operation,
                self,
                format!("response body is not valid JSON: {error}"),
            )
        })
    }

    fn evidence(
        &self,
        backend_id: &BackendId,
        operation: BackendOperation,
    ) -> Result<HttpEvidence, BackendError> {
        let body = serde_json::from_slice(&self.body).map_err(|error| {
            BackendError::new(
                backend_id,
                operation,
                BackendErrorKind::MalformedResponse,
                format!("could not preserve discovery response as JSON evidence: {error}"),
                Some(self.error_evidence()),
            )
        })?;
        Ok(HttpEvidence {
            endpoint: self.endpoint.clone(),
            status: self.status,
            response_body_sha256: sha256_bytes(&self.body),
            body,
        })
    }

    fn error_evidence(&self) -> BackendErrorEvidence {
        let raw_response = serde_json::from_slice(&self.body).ok();
        let response_preview = raw_response
            .is_none()
            .then(|| bounded_preview(&self.body, ERROR_PREVIEW_BYTES));
        BackendErrorEvidence {
            endpoint: Some(self.endpoint.clone()),
            status: Some(self.status),
            response_body_sha256: Some(sha256_bytes(&self.body)),
            raw_response,
            response_preview,
        }
    }
}

fn validate_config(backend_id: &BackendId, config: &LmStudioConfig) -> Result<(), BackendError> {
    if !matches!(config.base_url.scheme(), "http" | "https") {
        return Err(configuration_error(
            backend_id,
            "base URL scheme must be http or https",
        ));
    }
    if config.base_url.host_str().is_none() {
        return Err(configuration_error(backend_id, "base URL must have a host"));
    }
    if !config.base_url.username().is_empty() || config.base_url.password().is_some() {
        return Err(configuration_error(
            backend_id,
            "base URL must not contain user information",
        ));
    }
    if config.base_url.query().is_some() || config.base_url.fragment().is_some() {
        return Err(configuration_error(
            backend_id,
            "base URL must not contain a query or fragment",
        ));
    }
    if !matches!(config.base_url.path(), "" | "/") {
        return Err(configuration_error(
            backend_id,
            "base URL path must be the server root",
        ));
    }
    if config.limits.connect_timeout.is_zero()
        || config.limits.discovery_timeout.is_zero()
        || config.limits.request_timeout.is_zero()
    {
        return Err(configuration_error(
            backend_id,
            "HTTP timeouts must be greater than zero",
        ));
    }
    if config.limits.max_request_bytes == 0 || config.limits.max_response_bytes == 0 {
        return Err(configuration_error(
            backend_id,
            "HTTP body limits must be greater than zero",
        ));
    }
    if config.limits.max_output_tokens == 0 {
        return Err(configuration_error(
            backend_id,
            "maximum output token limit must be greater than zero",
        ));
    }
    if config
        .api_token
        .as_ref()
        .is_some_and(|token| token.expose().is_empty())
    {
        return Err(configuration_error(
            backend_id,
            "configured API token must not be empty",
        ));
    }
    if config.base_url.scheme() == "http" && !is_loopback_host(&config.base_url) {
        return Err(configuration_error(
            backend_id,
            "plain HTTP is allowed only for loopback hosts because prompts and code are sensitive",
        ));
    }
    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain == "localhost",
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn configuration_error(backend_id: &BackendId, message: impl Into<String>) -> BackendError {
    BackendError::new(
        backend_id,
        BackendOperation::Configure,
        BackendErrorKind::InvalidConfiguration,
        message,
        None,
    )
}

fn transport_error(
    backend_id: &BackendId,
    operation: BackendOperation,
    endpoint: &str,
    error: &reqwest::Error,
) -> BackendError {
    let (kind, message) = if error.is_timeout() {
        (BackendErrorKind::Timeout, "HTTP operation timed out")
    } else {
        (BackendErrorKind::Transport, "HTTP transport failed")
    };
    BackendError::new(
        backend_id,
        operation,
        kind,
        message,
        Some(BackendErrorEvidence {
            endpoint: Some(endpoint.to_owned()),
            status: error.status().map(|status| status.as_u16()),
            response_body_sha256: None,
            raw_response: None,
            response_preview: None,
        }),
    )
}

fn http_status_error(
    backend_id: &BackendId,
    operation: BackendOperation,
    response: &HttpResponse,
) -> BackendError {
    BackendError::new(
        backend_id,
        operation,
        BackendErrorKind::HttpStatus,
        format!("server returned HTTP {}", response.status),
        Some(response.error_evidence()),
    )
}

fn malformed_error(
    backend_id: &BackendId,
    operation: BackendOperation,
    response: &HttpResponse,
    message: impl Into<String>,
) -> BackendError {
    BackendError::new(
        backend_id,
        operation,
        BackendErrorKind::MalformedResponse,
        message,
        Some(response.error_evidence()),
    )
}

fn bounded_preview(bytes: &[u8], maximum: usize) -> String {
    let end = bytes.len().min(maximum);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_request_contract(
    backend_id: &BackendId,
    limits: &HttpLimits,
    request: &StructuredInferenceRequest,
) -> Result<(), BackendError> {
    if request.messages().is_empty() {
        return Err(invalid_request(backend_id, "request has no messages"));
    }
    if request.max_output_tokens() == 0 {
        return Err(invalid_request(
            backend_id,
            "max_output_tokens must be greater than zero",
        ));
    }
    if request.max_output_tokens() > limits.max_output_tokens {
        return Err(invalid_request(
            backend_id,
            format!(
                "max_output_tokens {} exceeds configured hard ceiling {}",
                request.max_output_tokens(),
                limits.max_output_tokens
            ),
        ));
    }
    if !valid_schema_name(request.output().name()) {
        return Err(invalid_request(
            backend_id,
            "output schema name violates the provider contract",
        ));
    }
    Ok(())
}

/// Performs allocation-free, bounded structural inspection before either JSON
/// Schema compiler is allowed to process caller-controlled values.
///
/// The request-body budget is deliberately a lower bound: exact JSON escaping
/// is enforced later by [`CappedWriter`]. Each schema also receives its own
/// budget so a large authoritative-only schema cannot consume unbounded local
/// validator resources merely because it is absent from the provider payload.
fn preflight_request_structure(
    backend_id: &BackendId,
    limits: &HttpLimits,
    request: &StructuredInferenceRequest,
) -> Result<(), BackendError> {
    let maximum = limits.max_request_bytes;
    let mut wire_budget = StructuralBudget::new(maximum);
    wire_budget.consume(REQUEST_ENVELOPE_LOWER_BOUND, backend_id, "request envelope")?;
    wire_budget.consume(
        request.model_id().as_str().len(),
        backend_id,
        "model identifier",
    )?;
    wire_budget.consume(
        request.output().name().len(),
        backend_id,
        "output schema name",
    )?;

    for message in request.messages() {
        wire_budget.consume(
            MESSAGE_ENVELOPE_LOWER_BOUND,
            backend_id,
            "message envelopes",
        )?;
        wire_budget.consume(message.content.len(), backend_id, "message content")?;
        if message.role == MessageRole::Developer {
            return Err(BackendError::new(
                backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::Unsupported,
                "LM Studio chat completions do not document the developer message role",
                None,
            ));
        }
    }

    let validation_schema = request.output().validation_schema();
    let generation_schema = request.output().generation_schema();
    let validation_size = inspect_schema_bounded(
        backend_id,
        validation_schema,
        "authoritative validation",
        maximum,
    )?;
    let generation_size = if ptr::eq(validation_schema, generation_schema) {
        validation_size
    } else {
        inspect_schema_bounded(
            backend_id,
            generation_schema,
            "provider generation",
            maximum,
        )?
    };
    wire_budget.consume(generation_size, backend_id, "provider generation schema")?;
    Ok(())
}

#[derive(Debug)]
struct StructuralBudget {
    used: usize,
    maximum: usize,
}

impl StructuralBudget {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn consume(
        &mut self,
        amount: usize,
        backend_id: &BackendId,
        component: &'static str,
    ) -> Result<(), BackendError> {
        let Some(used) = self.used.checked_add(amount) else {
            return Err(request_too_large(backend_id, self.maximum, component));
        };
        if used > self.maximum {
            return Err(request_too_large(backend_id, self.maximum, component));
        }
        self.used = used;
        Ok(())
    }
}

fn request_too_large(
    backend_id: &BackendId,
    maximum: usize,
    component: &'static str,
) -> BackendError {
    BackendError::new(
        backend_id,
        BackendOperation::StructuredInference,
        BackendErrorKind::RequestTooLarge,
        format!(
            "structured inference {component} exceeds the configured maximum request size of {maximum} bytes"
        ),
        None,
    )
}

fn encode_request_capped<T>(
    backend_id: &BackendId,
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, BackendError>
where
    T: Serialize + ?Sized,
{
    let mut writer = CappedWriter::new(maximum);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        return match writer.failure {
            Some(CappedWriterFailure::Limit) => Err(request_too_large(
                backend_id,
                maximum,
                "encoded JSON request",
            )),
            Some(CappedWriterFailure::Allocation) => Err(BackendError::new(
                backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::InvalidRequest,
                "could not allocate the bounded structured inference request buffer",
                None,
            )),
            None => Err(BackendError::new(
                backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::InvalidRequest,
                format!("could not encode structured inference request: {error}"),
                None,
            )),
        };
    }
    Ok(writer.bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CappedWriterFailure {
    Limit,
    Allocation,
}

/// Collects a JSON body without ever extending its logical capacity beyond
/// the configured wire limit. Growth is geometric but clamped to `maximum`,
/// avoiding both an eager maximum-sized allocation and repeated tiny reserves.
#[derive(Debug)]
struct CappedWriter {
    bytes: Vec<u8>,
    maximum: usize,
    failure: Option<CappedWriterFailure>,
}

impl CappedWriter {
    const fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            failure: None,
        }
    }

    fn ensure_capacity(&mut self, required: usize) -> io::Result<()> {
        if required <= self.bytes.capacity() {
            return Ok(());
        }
        let geometric = self
            .bytes
            .capacity()
            .saturating_mul(2)
            .max(SERIALIZATION_INITIAL_CAPACITY);
        let target = required.max(geometric).min(self.maximum);
        let additional = target.saturating_sub(self.bytes.len());
        self.bytes.try_reserve_exact(additional).map_err(|_| {
            self.failure = Some(CappedWriterFailure::Allocation);
            io::Error::other("bounded JSON request allocation failed")
        })
    }
}

impl io::Write for CappedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(required) = self.bytes.len().checked_add(buffer.len()) else {
            self.failure = Some(CappedWriterFailure::Limit);
            return Err(io::Error::other("JSON request exceeds configured limit"));
        };
        if required > self.maximum {
            self.failure = Some(CappedWriterFailure::Limit);
            return Err(io::Error::other("JSON request exceeds configured limit"));
        }
        self.ensure_capacity(required)?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn valid_schema_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn invalid_request(backend_id: &BackendId, message: impl Into<String>) -> BackendError {
    BackendError::new(
        backend_id,
        BackendOperation::StructuredInference,
        BackendErrorKind::InvalidRequest,
        message,
        None,
    )
}

fn lmstudio_reasoning_effort(
    backend_id: &BackendId,
    reasoning: Option<ReasoningSetting>,
) -> Result<Option<LmStudioReasoningEffort>, BackendError> {
    match reasoning {
        None => Ok(None),
        Some(ReasoningSetting::Off) => Ok(Some(LmStudioReasoningEffort::Disabled)),
        Some(ReasoningSetting::Low) => Ok(Some(LmStudioReasoningEffort::Low)),
        Some(ReasoningSetting::Medium) => Ok(Some(LmStudioReasoningEffort::Medium)),
        Some(ReasoningSetting::High) => Ok(Some(LmStudioReasoningEffort::High)),
        Some(ReasoningSetting::On) => Err(BackendError::new(
            backend_id,
            BackendOperation::StructuredInference,
            BackendErrorKind::Unsupported,
            "LM Studio chat completions cannot faithfully represent provider-neutral reasoning On",
            None,
        )),
    }
}

fn compile_schema_validator(
    backend_id: &BackendId,
    schema: &Value,
    purpose: &'static str,
) -> Result<jsonschema::Validator, BackendError> {
    jsonschema::draft202012::options()
        .build(schema)
        .map_err(|error| {
            BackendError::new(
                backend_id,
                BackendOperation::StructuredInference,
                BackendErrorKind::InvalidSchema,
                format!("{purpose} JSON Schema is invalid: {error}"),
                None,
            )
        })
}

fn inspect_schema_bounded(
    backend_id: &BackendId,
    schema: &Value,
    purpose: &'static str,
    maximum_bytes: usize,
) -> Result<usize, BackendError> {
    let mut inspection = SchemaInspection {
        backend_id,
        purpose,
        nodes: 0,
        bytes: StructuralBudget::new(maximum_bytes),
    };
    inspection.visit(schema, 0)?;
    Ok(inspection.bytes.used)
}

struct SchemaInspection<'a> {
    backend_id: &'a BackendId,
    purpose: &'static str,
    nodes: usize,
    bytes: StructuralBudget,
}

impl SchemaInspection<'_> {
    fn visit(&mut self, value: &Value, depth: usize) -> Result<(), BackendError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_SCHEMA_NODES {
            return Err(invalid_schema(
                self.backend_id,
                format!(
                    "{} JSON Schema exceeds {MAX_SCHEMA_NODES} nodes",
                    self.purpose
                ),
            ));
        }
        if depth > MAX_SCHEMA_DEPTH {
            return Err(invalid_schema(
                self.backend_id,
                format!(
                    "{} JSON Schema exceeds depth {MAX_SCHEMA_DEPTH}",
                    self.purpose
                ),
            ));
        }

        match value {
            Value::Null | Value::Bool(true) => self.consume(4)?,
            Value::Bool(false) => self.consume(5)?,
            Value::Number(_) => self.consume(1)?,
            Value::String(value) => {
                self.consume(2)?;
                self.consume(value.len())?;
            }
            Value::Array(values) => {
                self.consume(2)?;
                self.consume(values.len().saturating_sub(1))?;
                for child in values {
                    self.visit(child, depth + 1)?;
                }
            }
            Value::Object(object) => {
                self.consume(2)?;
                self.consume(object.len().saturating_sub(1))?;
                if ["$ref", "$dynamicRef", "$recursiveRef"]
                    .iter()
                    .filter_map(|keyword| object.get(*keyword))
                    .filter_map(Value::as_str)
                    .any(|reference| !reference.starts_with('#'))
                {
                    return Err(invalid_schema(
                        self.backend_id,
                        format!(
                            "external references are not allowed in {} JSON Schema",
                            self.purpose
                        ),
                    ));
                }
                for (key, child) in object {
                    // Two quotes plus the colon. Escaping can only make the
                    // exact encoding larger, which the capped writer handles.
                    self.consume(3)?;
                    self.consume(key.len())?;
                    self.visit(child, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    fn consume(&mut self, amount: usize) -> Result<(), BackendError> {
        self.bytes
            .consume(amount, self.backend_id, "JSON Schema structure")
    }
}

fn invalid_schema(backend_id: &BackendId, message: impl Into<String>) -> BackendError {
    BackendError::new(
        backend_id,
        BackendOperation::StructuredInference,
        BackendErrorKind::InvalidSchema,
        message,
        None,
    )
}

#[derive(Debug, Deserialize)]
struct OpenAiModelsResponse {
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModel {
    id: String,
}

fn validate_openai_models(
    backend_id: &BackendId,
    response: &HttpResponse,
    models: &OpenAiModelsResponse,
) -> Result<(), BackendError> {
    let mut ids = BTreeSet::new();
    for model in &models.data {
        if model.id.is_empty() {
            return Err(malformed_error(
                backend_id,
                BackendOperation::DiscoverOpenAiModels,
                response,
                "model list contains an empty id",
            ));
        }
        if !ids.insert(&model.id) {
            return Err(malformed_error(
                backend_id,
                BackendOperation::DiscoverOpenAiModels,
                response,
                format!("model list contains duplicate id {:?}", model.id),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct NativeModelsResponse {
    models: Vec<NativeModel>,
}

#[derive(Debug, Deserialize)]
struct NativeModel {
    #[serde(rename = "type")]
    kind: Option<String>,
    key: String,
    display_name: Option<String>,
    publisher: Option<String>,
    architecture: Option<String>,
    quantization: Option<NativeQuantization>,
    #[serde(default)]
    loaded_instances: Vec<NativeLoadedInstance>,
    max_context_length: Option<u64>,
    capabilities: Option<NativeCapabilities>,
    #[serde(default)]
    variants: Vec<String>,
    selected_variant: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NativeQuantization {
    name: Option<String>,
    bits_per_weight: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct NativeLoadedInstance {
    id: String,
    config: NativeLoadedConfig,
}

#[derive(Debug, Deserialize)]
struct NativeLoadedConfig {
    context_length: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NativeCapabilities {
    vision: Option<bool>,
    trained_for_tool_use: Option<bool>,
    reasoning: Option<NativeReasoning>,
}

#[derive(Debug, Deserialize)]
struct NativeReasoning {
    #[serde(default)]
    allowed_options: Vec<String>,
    default: String,
}

fn join_catalog(
    openai: &OpenAiModelsResponse,
    native: Option<&NativeModelsResponse>,
) -> Vec<ModelDescriptor> {
    openai
        .data
        .iter()
        .map(|model| descriptor_for(model, native))
        .collect()
}

fn descriptor_for(openai: &OpenAiModel, native: Option<&NativeModelsResponse>) -> ModelDescriptor {
    let id = ModelId::new(openai.id.clone())
        .expect("OpenAI model identities were validated before catalog joining");
    let Some(native) = native else {
        return unknown_descriptor(id, NativeMatch::None);
    };
    let matches = exact_native_matches(&openai.id, &native.models);
    let Some((model, match_key)) = matches.first() else {
        return unknown_descriptor(id, NativeMatch::None);
    };
    if matches.len() > 1 {
        return unknown_descriptor(id, NativeMatch::Ambiguous);
    }

    let loaded_instances = model
        .loaded_instances
        .iter()
        .map(|instance| LoadedInstance {
            id: instance.id.clone(),
            context_length: instance.config.context_length,
        })
        .collect::<Vec<_>>();
    let load_state = if loaded_instances.is_empty() {
        ModelLoadState::NotLoaded
    } else if *match_key == NativeMatchKey::LoadedInstance {
        ModelLoadState::Loaded
    } else {
        // The native record proves that some instance of the underlying model
        // is loaded, but not that this exact OpenAI inference ID names it.
        ModelLoadState::Unknown
    };
    let capabilities =
        model
            .capabilities
            .as_ref()
            .map_or_else(ModelCapabilities::unknown, |capabilities| {
                ModelCapabilities {
                    vision: capability_state(capabilities.vision),
                    trained_for_tool_use: capability_state(capabilities.trained_for_tool_use),
                    reasoning: capabilities.reasoning.as_ref().map(|reasoning| {
                        ReasoningCapabilities {
                            allowed_options: reasoning
                                .allowed_options
                                .iter()
                                .cloned()
                                .map(ReasoningOption)
                                .collect(),
                            default: ReasoningOption(reasoning.default.clone()),
                        }
                    }),
                }
            });
    let quantization = match (&model.quantization, &model.selected_variant) {
        (None, None) => None,
        (quantization, selected_variant) => Some(Quantization {
            name: quantization.as_ref().and_then(|value| value.name.clone()),
            bits_per_weight: quantization
                .as_ref()
                .and_then(|value| value.bits_per_weight),
            selected_variant: selected_variant.clone(),
        }),
    };

    ModelDescriptor {
        id,
        kind: model_kind(model.kind.as_deref()),
        display_name: model.display_name.clone(),
        publisher: model.publisher.clone(),
        architecture: model.architecture.clone(),
        load_state,
        loaded_instances,
        maximum_context_tokens: model.max_context_length,
        quantization,
        capabilities,
        native_match: NativeMatch::Exact(match_key.clone()),
    }
}

fn unknown_descriptor(id: ModelId, native_match: NativeMatch) -> ModelDescriptor {
    ModelDescriptor {
        id,
        kind: ModelKind::Unknown,
        display_name: None,
        publisher: None,
        architecture: None,
        load_state: ModelLoadState::Unknown,
        loaded_instances: Vec::new(),
        maximum_context_tokens: None,
        quantization: None,
        capabilities: ModelCapabilities::unknown(),
        native_match,
    }
}

fn exact_native_matches<'a>(
    id: &str,
    models: &'a [NativeModel],
) -> Vec<(&'a NativeModel, NativeMatchKey)> {
    models
        .iter()
        .filter_map(|model| exact_match_key(id, model).map(|match_key| (model, match_key)))
        .collect()
}

fn exact_match_key(id: &str, model: &NativeModel) -> Option<NativeMatchKey> {
    if model
        .loaded_instances
        .iter()
        .any(|instance| instance.id == id)
    {
        Some(NativeMatchKey::LoadedInstance)
    } else if model.key == id {
        Some(NativeMatchKey::ModelKey)
    } else if model.selected_variant.as_deref() == Some(id) {
        Some(NativeMatchKey::SelectedVariant)
    } else if model.variants.iter().any(|variant| variant == id) {
        Some(NativeMatchKey::Variant)
    } else {
        None
    }
}

fn capability_state(reported: Option<bool>) -> CapabilityState {
    match reported {
        Some(true) => CapabilityState::Supported,
        Some(false) => CapabilityState::Unsupported,
        None => CapabilityState::Unknown,
    }
}

fn model_kind(reported: Option<&str>) -> ModelKind {
    match reported {
        Some("llm") => ModelKind::Language,
        Some("embedding") => ModelKind::Embedding,
        Some(other) => ModelKind::Other(other.to_owned()),
        None => ModelKind::Unknown,
    }
}

#[derive(Debug, Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: &'a [Message],
    response_format: ResponseFormat<'a>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<LmStudioReasoningEffort>,
    stream: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LmStudioReasoningEffort {
    #[serde(rename = "none")]
    Disabled,
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize)]
struct ResponseFormat<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    json_schema: JsonSchemaFormat<'a>,
}

#[derive(Debug, Serialize)]
struct JsonSchemaFormat<'a> {
    name: &'a str,
    strict: bool,
    schema: &'a Value,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    id: Option<String>,
    model: String,
    choices: Vec<ChatChoice>,
    usage: Option<ChatUsage>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    index: u32,
    message: ChatMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    role: String,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatUsage {
    #[serde(rename = "prompt_tokens")]
    prompt: Option<u64>,
    #[serde(rename = "completion_tokens")]
    completion: Option<u64>,
    #[serde(rename = "total_tokens")]
    total: Option<u64>,
}

impl From<ChatUsage> for TokenUsage {
    fn from(value: ChatUsage) -> Self {
        Self {
            input_tokens: value.prompt,
            output_tokens: value.completion,
            total_tokens: value.total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secret_token_debug_is_redacted() {
        let token = SecretToken::new("do-not-print-this");
        let debug = format!("{token:?}");
        assert_eq!(debug, "SecretToken([REDACTED])");
        assert!(!debug.contains("do-not-print-this"));
    }

    #[test]
    fn base_url_user_information_is_rejected_without_rendering_it() {
        let config = LmStudioConfig::new(
            Url::parse("http://runner:do-not-print@127.0.0.1:1234/").expect("test URL is valid"),
        );
        let error = LmStudioBackend::new(config).expect_err("URL user information must fail");
        assert_eq!(error.kind, BackendErrorKind::InvalidConfiguration);
        let rendered = error.to_string();
        assert!(rendered.contains("must not contain user information"));
        assert!(!rendered.contains("runner"));
        assert!(!rendered.contains("do-not-print"));
    }

    #[test]
    fn external_schema_references_are_rejected_without_resolution() {
        let backend_id = BackendId::new(BACKEND_NAME).expect("valid static ID");
        let error = inspect_schema_bounded(
            &backend_id,
            &json!({"$ref": "http://127.0.0.1/private-schema"}),
            "test",
            HttpLimits::default().max_request_bytes,
        )
        .expect_err("external references must be rejected");
        assert_eq!(error.kind, BackendErrorKind::InvalidSchema);
    }

    #[test]
    fn capped_writer_never_retains_bytes_past_its_limit() {
        let mut writer = CappedWriter::new(7);
        io::Write::write_all(&mut writer, b"1234567").expect("exact limit fits");
        let error = io::Write::write_all(&mut writer, b"8")
            .expect_err("one byte beyond the limit must fail");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(writer.bytes, b"1234567");
        assert_eq!(writer.failure, Some(CappedWriterFailure::Limit));
    }
}
