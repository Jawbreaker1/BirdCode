use birdcode_backends::{
    BackendErrorKind, CapabilityState, HttpLimits, LmStudioBackend, LmStudioConfig, Message,
    MessageRole, ModelBackend, ModelLoadState, NativeDiscoveryEvidence, NativeMatch,
    NativeMatchKey, ReasoningSetting, SecretToken, StructuredInferenceRequest,
    StructuredOutputSpec,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use url::Url;

#[derive(Clone, Debug)]
struct MockReply {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
    headers: Vec<(String, String)>,
}

impl MockReply {
    fn json(status: u16, body: impl serde::Serialize) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&body).expect("test JSON must encode"),
            delay: Duration::ZERO,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        }
    }

    fn raw(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }

    fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct MockServer {
    base_url: Url,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    task: JoinHandle<()>,
}

impl MockServer {
    async fn start(replies: Vec<MockReply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener must bind");
        let address = listener.local_addr().expect("mock listener has an address");
        let base_url = Url::parse(&format!("http://{address}/")).expect("mock URL is valid");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for reply in replies {
                let Ok((stream, _peer)) = listener.accept().await else {
                    break;
                };
                if let Ok(request) = read_request_and_reply(stream, reply).await {
                    captured.lock().await.push(request);
                }
            }
        });
        Self {
            base_url,
            requests,
            task,
        }
    }

    async fn captured(&self) -> Vec<CapturedRequest> {
        self.requests.lock().await.clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request_and_reply(
    mut stream: TcpStream,
    reply: MockReply,
) -> std::io::Result<CapturedRequest> {
    let mut received = Vec::new();
    let header_end = loop {
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if received.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mock request headers too large",
            ));
        }
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "mock client closed before headers",
            ));
        }
        received.extend_from_slice(&chunk[..count]);
    };
    let headers_text = std::str::from_utf8(&received[..header_end - 4])
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let mut lines = headers_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let path = request_parts.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .map_or(Ok(0_usize), |value| value.parse::<usize>())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    while received.len() - header_end < content_length {
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "mock client closed before request body",
            ));
        }
        received.extend_from_slice(&chunk[..count]);
    }
    let body = received[header_end..header_end + content_length].to_vec();

    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let reason = match reply.status {
        200 => "OK",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Mock Status",
    };
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reason,
        reply.body.len()
    );
    for (name, value) in reply.headers {
        response.push_str(&name);
        response.push_str(": ");
        response.push_str(&value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&reply.body).await?;
    stream.shutdown().await?;

    Ok(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn backend(server: &MockServer) -> LmStudioBackend {
    LmStudioBackend::new(LmStudioConfig::new(server.base_url.clone()))
        .expect("mock backend config is valid")
}

fn structured_request(messages: Vec<Message>) -> StructuredInferenceRequest {
    StructuredInferenceRequest::new(
        "google/gemma-4-26b-a4b"
            .to_owned()
            .try_into()
            .expect("model ID is valid"),
        messages,
        StructuredOutputSpec::new(
            "route_result",
            json!({
                "type": "object",
                "properties": {
                    "route": {"type": "string"},
                    "language": {"type": "string"}
                },
                "required": ["route", "language"],
                "additionalProperties": false
            }),
        )
        .expect("schema spec is valid"),
        128,
    )
    .expect("request is valid")
}

fn completion(content: impl serde::Serialize) -> Value {
    json!({
        "id": "chatcmpl-test",
        "model": "google/gemma-4-26b-a4b",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": serde_json::to_string(&content).expect("content encodes")
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 42,
            "completion_tokens": 9,
            "total_tokens": 51
        }
    })
}

#[tokio::test]
async fn discovery_joins_only_exact_ids_and_preserves_reported_metadata() {
    let openai = json!({
        "object": "list",
        "data": [
            {"id": "google/gemma-4-26b-a4b@q8_0", "object": "model"},
            {"id": "orphan/model", "object": "model"}
        ]
    });
    let native = json!({
        "models": [{
            "type": "llm",
            "publisher": "google",
            "key": "google/gemma-4-26b-a4b",
            "display_name": "Gemma 4 26B A4B",
            "architecture": "gemma4",
            "quantization": {"name": "Q8_0", "bits_per_weight": 8},
            "loaded_instances": [{
                "id": "google/gemma-4-26b-a4b@q8_0",
                "config": {"context_length": 121_088}
            }],
            "max_context_length": 262_144,
            "capabilities": {
                "vision": true,
                "trained_for_tool_use": true,
                "reasoning": {"allowed_options": ["off", "on"], "default": "on"}
            },
            "variants": ["google/gemma-4-26b-a4b@q8_0"],
            "selected_variant": "google/gemma-4-26b-a4b@q8_0"
        }]
    });
    let openai_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&openai).expect("OpenAI fixture encodes"))
    );
    let native_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&native).expect("native fixture encodes"))
    );
    let server = MockServer::start(vec![
        MockReply::json(200, openai.clone()),
        MockReply::json(200, native.clone()),
    ])
    .await;

    let catalog = backend(&server)
        .discover_models()
        .await
        .expect("discovery succeeds");

    assert_eq!(catalog.models.len(), 2);
    let gemma = &catalog.models[0];
    assert_eq!(gemma.id.as_str(), "google/gemma-4-26b-a4b@q8_0");
    assert_eq!(gemma.load_state, ModelLoadState::Loaded);
    assert_eq!(gemma.maximum_context_tokens, Some(262_144));
    assert_eq!(gemma.loaded_instances[0].context_length, Some(121_088));
    assert_eq!(gemma.capabilities.vision, CapabilityState::Supported);
    assert_eq!(
        gemma.capabilities.trained_for_tool_use,
        CapabilityState::Supported
    );
    assert_eq!(
        gemma.native_match,
        NativeMatch::Exact(NativeMatchKey::LoadedInstance)
    );
    assert_eq!(
        gemma
            .quantization
            .as_ref()
            .and_then(|quantization| quantization.name.as_deref()),
        Some("Q8_0")
    );
    assert_eq!(catalog.models[1].load_state, ModelLoadState::Unknown);
    assert_eq!(catalog.models[1].native_match, NativeMatch::None);
    assert_eq!(catalog.evidence.openai.body, openai);
    assert_eq!(catalog.evidence.openai.response_body_sha256, openai_sha256);
    match catalog.evidence.native {
        NativeDiscoveryEvidence::Available { response } => {
            assert_eq!(response.body, native);
            assert_eq!(response.response_body_sha256, native_sha256);
        }
        NativeDiscoveryEvidence::Unavailable { error } => {
            panic!("native discovery unexpectedly unavailable: {error}")
        }
    }

    let captured = server.captured().await;
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].method, "GET");
    assert_eq!(captured[0].path, "/v1/models");
    assert_eq!(captured[1].path, "/api/v1/models");
    assert!(!captured[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn native_endpoint_failure_has_conservative_unknown_fallback() {
    let server = MockServer::start(vec![
        MockReply::json(200, json!({"data": [{"id": "model-exact"}]})),
        MockReply::json(404, json!({"error": "native API unavailable"})),
    ])
    .await;

    let catalog = backend(&server)
        .discover_models()
        .await
        .expect("OpenAI-compatible discovery remains usable");

    assert_eq!(catalog.models[0].id.as_str(), "model-exact");
    assert_eq!(catalog.models[0].load_state, ModelLoadState::Unknown);
    assert_eq!(
        catalog.models[0].capabilities.vision,
        CapabilityState::Unknown
    );
    assert_eq!(catalog.models[0].native_match, NativeMatch::None);
    match catalog.evidence.native {
        NativeDiscoveryEvidence::Unavailable { error } => {
            assert_eq!(error.kind, BackendErrorKind::HttpStatus);
            assert_eq!(
                error.evidence.and_then(|evidence| evidence.status),
                Some(404)
            );
        }
        NativeDiscoveryEvidence::Available { .. } => panic!("native endpoint must be unavailable"),
    }
}

#[tokio::test]
async fn malformed_native_discovery_degrades_without_inventing_metadata() {
    let server = MockServer::start(vec![
        MockReply::json(200, json!({"data": [{"id": "model-exact"}]})),
        MockReply::raw(200, b"not-json".to_vec()),
    ])
    .await;

    let catalog = backend(&server)
        .discover_models()
        .await
        .expect("primary discovery remains usable");
    assert_eq!(catalog.models[0].load_state, ModelLoadState::Unknown);
    match catalog.evidence.native {
        NativeDiscoveryEvidence::Unavailable { error } => {
            assert_eq!(error.kind, BackendErrorKind::MalformedResponse);
        }
        NativeDiscoveryEvidence::Available { .. } => panic!("malformed native body is unavailable"),
    }
}

#[tokio::test]
async fn ambiguous_exact_native_join_is_conservatively_unknown() {
    let server = MockServer::start(vec![
        MockReply::json(200, json!({"data": [{"id": "duplicate-key"}]})),
        MockReply::json(
            200,
            json!({
                "models": [
                    {"type": "llm", "key": "duplicate-key", "loaded_instances": []},
                    {"type": "embedding", "key": "duplicate-key", "loaded_instances": []}
                ]
            }),
        ),
    ])
    .await;

    let catalog = backend(&server)
        .discover_models()
        .await
        .expect("discovery succeeds");
    assert_eq!(catalog.models[0].native_match, NativeMatch::Ambiguous);
    assert_eq!(catalog.models[0].load_state, ModelLoadState::Unknown);
    assert_eq!(
        catalog.models[0].capabilities.vision,
        CapabilityState::Unknown
    );
}

#[tokio::test]
async fn native_enrichment_uses_the_short_discovery_deadline() {
    let server = MockServer::start(vec![
        MockReply::json(200, json!({"data": [{"id": "model-exact"}]})),
        MockReply::json(200, json!({"models": []})).delayed(Duration::from_millis(150)),
    ])
    .await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.limits.discovery_timeout = Duration::from_millis(25);
    config.limits.request_timeout = Duration::from_secs(10);

    let catalog = LmStudioBackend::new(config)
        .expect("config is valid")
        .discover_models()
        .await
        .expect("primary model list survives native timeout");
    assert_eq!(catalog.models[0].load_state, ModelLoadState::Unknown);
    match catalog.evidence.native {
        NativeDiscoveryEvidence::Unavailable { error } => {
            assert_eq!(error.kind, BackendErrorKind::Timeout);
        }
        NativeDiscoveryEvidence::Available { .. } => panic!("native request must time out"),
    }
}

#[tokio::test]
async fn multilingual_structured_roundtrip_is_strict_and_preserves_utf8() {
    let provider_reply = MockReply::json(
        200,
        completion(json!({"route": "granska", "language": "sv"})),
    );
    let provider_body_sha256 = format!("{:x}", Sha256::digest(&provider_reply.body));
    let server = MockServer::start(vec![provider_reply]).await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.api_token = Some(SecretToken::new("local-test-token"));
    let backend = LmStudioBackend::new(config).expect("loopback token config is valid");
    let request = structured_request(vec![
        Message::new(MessageRole::System, "Klassificera utan att översätta."),
        Message::new(
            MessageRole::User,
            "Svenska: granska detta. 日本語: 確認してください。 العربية: راجع هذا.",
        ),
    ]);

    let response = backend
        .infer_structured(request)
        .await
        .expect("structured inference succeeds");

    assert_eq!(response.model_id.as_str(), "google/gemma-4-26b-a4b");
    assert_eq!(
        response.value,
        json!({"route": "granska", "language": "sv"})
    );
    assert_eq!(
        response.usage.as_ref().and_then(|usage| usage.total_tokens),
        Some(51)
    );
    assert_eq!(
        response.evidence.raw_response["id"],
        Value::String("chatcmpl-test".to_owned())
    );
    assert_eq!(
        response.evidence.response_body_sha256,
        Some(provider_body_sha256)
    );

    let captured = server.captured().await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].method, "POST");
    assert_eq!(captured[0].path, "/v1/chat/completions");
    assert_eq!(
        captured[0].headers.get("authorization").map(String::as_str),
        Some("Bearer local-test-token")
    );
    let body: Value = serde_json::from_slice(&captured[0].body).expect("request body is JSON");
    assert_eq!(body["stream"], false);
    assert_eq!(body["max_tokens"], 128);
    assert_eq!(body["response_format"]["type"], "json_schema");
    assert_eq!(body["response_format"]["json_schema"]["strict"], true);
    assert!(body.get("reasoning_effort").is_none());
    assert_eq!(
        body["messages"][1]["content"],
        "Svenska: granska detta. 日本語: 確認してください。 العربية: راجع هذا."
    );
}

#[tokio::test]
async fn successful_inference_hashes_exact_provider_bytes_not_only_json_semantics() {
    let value = completion(json!({"route": "granska", "language": "sv"}));
    let compact = serde_json::to_vec(&value).expect("compact provider JSON encodes");
    let pretty = serde_json::to_vec_pretty(&value).expect("pretty provider JSON encodes");
    assert_ne!(compact, pretty);

    let compact_server = MockServer::start(vec![
        MockReply::raw(200, compact.clone()).with_header("Content-Type", "application/json"),
    ])
    .await;
    let pretty_server = MockServer::start(vec![
        MockReply::raw(200, pretty.clone()).with_header("Content-Type", "application/json"),
    ])
    .await;

    let compact_response = backend(&compact_server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "granska",
        )]))
        .await
        .expect("compact response succeeds");
    let pretty_response = backend(&pretty_server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "granska",
        )]))
        .await
        .expect("pretty response succeeds");

    assert_eq!(
        compact_response.evidence.raw_response,
        pretty_response.evidence.raw_response
    );
    assert_eq!(
        compact_response.evidence.response_body_sha256,
        Some(format!("{:x}", Sha256::digest(compact)))
    );
    assert_eq!(
        pretty_response.evidence.response_body_sha256,
        Some(format!("{:x}", Sha256::digest(pretty)))
    );
    assert_ne!(
        compact_response.evidence.response_body_sha256,
        pretty_response.evidence.response_body_sha256
    );
}

#[tokio::test]
async fn completion_model_mismatch_is_typed_and_retains_bounded_raw_evidence() {
    let returned_model = "unexpected/returned-model";
    let raw_response = json!({
        "id": "chatcmpl-wrong-model",
        "model": returned_model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": serde_json::to_string(
                    &json!({"route": "granska", "language": "sv"})
                )
                .expect("content encodes")
            },
            "finish_reason": "stop"
        }]
    });
    let body = serde_json::to_vec(&raw_response).expect("response encodes");
    let expected_sha256 = format!("{:x}", Sha256::digest(&body));
    let server = MockServer::start(vec![MockReply::raw(200, body)]).await;

    let error = backend(&server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "Klassificera",
        )]))
        .await
        .expect_err("a backend must not relabel a response from another model");

    assert_eq!(error.kind, BackendErrorKind::ResponseContractViolation);
    assert!(!error.message.contains(returned_model));
    assert!(!error.message.contains("google/gemma-4-26b-a4b"));
    let evidence = error
        .evidence
        .expect("mismatch retains bounded HTTP evidence");
    assert_eq!(evidence.status, Some(200));
    assert_eq!(
        evidence.response_body_sha256.as_deref(),
        Some(expected_sha256.as_str())
    );
    assert_eq!(evidence.raw_response, Some(raw_response));
    assert!(evidence.response_preview.is_none());
}

#[tokio::test]
async fn generation_schema_is_sent_without_weakening_authoritative_validation() {
    let server = MockServer::start(vec![MockReply::json(
        200,
        completion(json!({"route": "other", "language": "sv"})),
    )])
    .await;
    let validation_schema = json!({
        "type": "object",
        "properties": {
            "route": {"const": "review"},
            "language": {"const": "sv"}
        },
        "required": ["route", "language"],
        "additionalProperties": false
    });
    let generation_schema = json!({
        "type": "object",
        "properties": {
            "route": {"type": "string"},
            "language": {"type": "string"}
        },
        "required": ["route", "language"],
        "additionalProperties": false
    });
    let output = StructuredOutputSpec::new_with_generation_schema(
        "route_result",
        validation_schema.clone(),
        generation_schema.clone(),
    )
    .expect("output contract is valid");
    let request = StructuredInferenceRequest::new(
        "google/gemma-4-26b-a4b"
            .to_owned()
            .try_into()
            .expect("model ID is valid"),
        vec![Message::new(MessageRole::User, "Klassificera")],
        output,
        128,
    )
    .expect("request is valid");

    let error = backend(&server)
        .infer_structured(request)
        .await
        .expect_err("weaker generation schema must not weaken local validation");
    assert_eq!(error.kind, BackendErrorKind::SchemaViolation);
    let captured = server.captured().await;
    let body: Value = serde_json::from_slice(&captured[0].body).expect("request body is JSON");
    assert_eq!(
        body["response_format"]["json_schema"]["schema"],
        generation_schema
    );
    assert_ne!(
        body["response_format"]["json_schema"]["schema"],
        validation_schema
    );
}

#[tokio::test]
async fn reasoning_setting_is_mapped_exactly_to_lm_studio_payload() {
    let server = MockServer::start(vec![MockReply::json(
        200,
        completion(json!({"route": "ok", "language": "sv"})),
    )])
    .await;
    let request = structured_request(vec![Message::new(MessageRole::User, "Klassificera")])
        .with_reasoning(ReasoningSetting::Off);

    backend(&server)
        .infer_structured(request)
        .await
        .expect("reasoning request succeeds");
    let captured = server.captured().await;
    let body: Value = serde_json::from_slice(&captured[0].body).expect("request body is JSON");
    assert_eq!(body["reasoning_effort"], "none");
}

#[tokio::test]
async fn unrepresentable_reasoning_on_is_rejected_before_http() {
    let server = MockServer::start(Vec::new()).await;
    let request = structured_request(vec![Message::new(MessageRole::User, "Klassificera")])
        .with_reasoning(ReasoningSetting::On);

    let error = backend(&server)
        .infer_structured(request)
        .await
        .expect_err("LM Studio cannot faithfully represent provider-neutral On");
    assert_eq!(error.kind, BackendErrorKind::Unsupported);
    assert!(server.captured().await.is_empty());
}

#[tokio::test]
async fn deserialized_generation_and_validation_schemas_are_both_checked_before_http() {
    let server = MockServer::start(Vec::new()).await;
    let outputs = [
        json!({
            "name": "route_result",
            "validation_schema": {"$ref": "https://example.invalid/authoritative"},
            "generation_schema": {"type": "object"}
        }),
        json!({
            "name": "route_result",
            "validation_schema": {"type": "object"},
            "generation_schema": {"$dynamicRef": "https://example.invalid/generation"}
        }),
    ];
    for output in outputs {
        let request: StructuredInferenceRequest = serde_json::from_value(json!({
            "model_id": "model",
            "messages": [{"role": "user", "content": "classify"}],
            "output": output,
            "max_output_tokens": 64
        }))
        .expect("adversarial request reaches backend validation");
        let error = backend(&server)
            .infer_structured(request)
            .await
            .expect_err("unsafe schema must fail before HTTP");
        assert_eq!(error.kind, BackendErrorKind::InvalidSchema);
    }
    assert!(server.captured().await.is_empty());
}

#[test]
fn output_schema_defaults_and_reasoning_values_have_explicit_wire_contracts() {
    let schema = json!({"type": "object"});
    let output = StructuredOutputSpec::new("result", schema.clone()).expect("valid output");
    assert_eq!(output.validation_schema(), &schema);
    assert_eq!(output.generation_schema(), &schema);

    let values = [
        (ReasoningSetting::Off, "off"),
        (ReasoningSetting::On, "on"),
        (ReasoningSetting::Low, "low"),
        (ReasoningSetting::Medium, "medium"),
        (ReasoningSetting::High, "high"),
    ];
    for (setting, expected) in values {
        assert_eq!(
            serde_json::to_value(setting).expect("setting serializes"),
            Value::String(expected.to_owned())
        );
    }

    let invalid_reasoning = json!({
        "model_id": "model",
        "messages": [{"role": "user", "content": "classify"}],
        "output": {"name": "result", "schema": {"type": "object"}},
        "max_output_tokens": 64,
        "reasoning": "extreme"
    });
    assert!(
        serde_json::from_value::<StructuredInferenceRequest>(invalid_reasoning).is_err(),
        "unknown reasoning strings must not enter the typed contract"
    );
}

#[tokio::test]
async fn schema_violation_returns_typed_error_with_raw_evidence() {
    let server = MockServer::start(vec![MockReply::json(
        200,
        completion(json!({"route": 7, "language": "sv"})),
    )])
    .await;
    let error = backend(&server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "Klassificera",
        )]))
        .await
        .expect_err("wrong field type violates schema");
    assert_eq!(error.kind, BackendErrorKind::SchemaViolation);
    assert!(
        error
            .evidence
            .and_then(|evidence| evidence.raw_response)
            .is_some()
    );
}

#[tokio::test]
async fn malformed_assistant_json_is_a_typed_error() {
    let server = MockServer::start(vec![MockReply::json(
        200,
        json!({
            "id": "chatcmpl-malformed",
            "model": "google/gemma-4-26b-a4b",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "{not-json"},
                "finish_reason": "stop"
            }]
        }),
    )])
    .await;
    let error = backend(&server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "Klassificera",
        )]))
        .await
        .expect_err("invalid assistant JSON must fail");
    assert_eq!(error.kind, BackendErrorKind::MalformedResponse);
}

#[tokio::test]
async fn non_success_status_is_typed_and_bounded() {
    let server = MockServer::start(vec![MockReply::json(
        429,
        json!({"error": {"message": "busy"}}),
    )])
    .await;
    let error = backend(&server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "Klassificera",
        )]))
        .await
        .expect_err("429 must fail");
    assert_eq!(error.kind, BackendErrorKind::HttpStatus);
    let evidence = error.evidence.expect("HTTP error has evidence");
    assert_eq!(evidence.status, Some(429));
    assert_eq!(
        evidence.raw_response,
        Some(json!({"error": {"message": "busy"}}))
    );
}

#[tokio::test]
async fn oversized_response_is_rejected_before_full_decode() {
    let server = MockServer::start(vec![MockReply::raw(200, vec![b'x'; 512])]).await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.limits.max_response_bytes = 128;
    let error = LmStudioBackend::new(config)
        .expect("config is valid")
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "Klassificera",
        )]))
        .await
        .expect_err("oversized body must fail");
    assert_eq!(error.kind, BackendErrorKind::ResponseTooLarge);
}

#[tokio::test]
async fn request_deadline_returns_typed_timeout() {
    let server = MockServer::start(vec![
        MockReply::json(200, completion(json!({"route": "ok", "language": "sv"})))
            .delayed(Duration::from_millis(150)),
    ])
    .await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.limits.request_timeout = Duration::from_millis(25);
    let error = LmStudioBackend::new(config)
        .expect("config is valid")
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "Klassificera",
        )]))
        .await
        .expect_err("delayed response must time out");
    assert_eq!(error.kind, BackendErrorKind::Timeout);
}

#[tokio::test]
async fn incomplete_finish_reason_is_never_reported_as_success() {
    let mut body = completion(json!({"route": "ok", "language": "sv"}));
    body["choices"][0]["finish_reason"] = Value::String("length".to_owned());
    let server = MockServer::start(vec![MockReply::json(200, body)]).await;
    let error = backend(&server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "Klassificera",
        )]))
        .await
        .expect_err("truncated response must fail even if JSON is valid");
    assert_eq!(error.kind, BackendErrorKind::IncompleteResponse);
}

#[tokio::test]
async fn unsupported_developer_role_is_not_silently_rewritten() {
    let server = MockServer::start(Vec::new()).await;
    let error = backend(&server)
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::Developer,
            "Policy",
        )]))
        .await
        .expect_err("undocumented role must fail before HTTP");
    assert_eq!(error.kind, BackendErrorKind::Unsupported);
    assert!(server.captured().await.is_empty());
}

#[tokio::test]
async fn serde_cannot_bypass_request_validation_before_http() {
    let server = MockServer::start(Vec::new()).await;
    let invalid: StructuredInferenceRequest = serde_json::from_value(json!({
        "model_id": "model",
        "messages": [],
        "output": {"name": "invalid name!", "schema": {}},
        "max_output_tokens": 0
    }))
    .expect("private fields can still be populated by serde");
    let error = backend(&server)
        .infer_structured(invalid)
        .await
        .expect_err("deserialized invalid request must not reach HTTP");
    assert_eq!(error.kind, BackendErrorKind::InvalidRequest);
    assert!(server.captured().await.is_empty());
}

#[tokio::test]
async fn request_body_limit_is_enforced_before_http() {
    let server = MockServer::start(Vec::new()).await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.limits.max_request_bytes = 64;
    let error = LmStudioBackend::new(config)
        .expect("config is valid")
        .infer_structured(structured_request(vec![Message::new(
            MessageRole::User,
            "ett innehåll som med säkerhet gör JSON-kroppen större än sextiofyra byte",
        )]))
        .await
        .expect_err("large request must fail before HTTP");
    assert_eq!(error.kind, BackendErrorKind::RequestTooLarge);
    assert!(server.captured().await.is_empty());
}

#[tokio::test]
async fn oversized_message_is_rejected_before_schema_compilation_and_http() {
    let server = MockServer::start(vec![MockReply::json(
        200,
        completion(json!({"unexpected": true})),
    )])
    .await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.limits.max_request_bytes = 512;
    let request = StructuredInferenceRequest::new(
        "model".to_owned().try_into().expect("model ID is valid"),
        vec![Message::new(MessageRole::User, "x".repeat(4_096))],
        // This schema is intentionally invalid. The structural request cap
        // must reject the message before the schema compiler sees it.
        StructuredOutputSpec::new("result", json!({"type": 7}))
            .expect("the provider-neutral contract preserves backend validation"),
        64,
    )
    .expect("request is valid at the provider-neutral layer");

    let error = LmStudioBackend::new(config)
        .expect("config is valid")
        .infer_structured(request)
        .await
        .expect_err("structurally oversized messages must fail before compilation");
    assert_eq!(error.kind, BackendErrorKind::RequestTooLarge);
    assert!(error.message.contains("message content"));
    assert!(server.captured().await.is_empty());
}

#[tokio::test]
async fn both_generation_and_authoritative_schemas_have_preflight_budgets() {
    let server = MockServer::start(vec![
        MockReply::json(200, completion(json!({"unexpected": true}))),
        MockReply::json(200, completion(json!({"unexpected": true}))),
    ])
    .await;
    let small = json!({"type": "object"});
    let large = json!({
        "type": "object",
        "description": "x".repeat(4_096)
    });
    let outputs = [
        StructuredOutputSpec::new_with_generation_schema("result", large.clone(), small.clone())
            .expect("output contract is valid"),
        StructuredOutputSpec::new_with_generation_schema("result", small, large)
            .expect("output contract is valid"),
    ];

    for output in outputs {
        let mut config = LmStudioConfig::new(server.base_url.clone());
        config.limits.max_request_bytes = 512;
        let request = StructuredInferenceRequest::new(
            "model".to_owned().try_into().expect("model ID is valid"),
            vec![Message::new(MessageRole::User, "bounded")],
            output,
            64,
        )
        .expect("request is valid at the provider-neutral layer");
        let error = LmStudioBackend::new(config)
            .expect("config is valid")
            .infer_structured(request)
            .await
            .expect_err("each schema must be independently bounded before compilation");
        assert_eq!(error.kind, BackendErrorKind::RequestTooLarge);
        assert!(error.message.contains("JSON Schema structure"));
    }
    assert!(server.captured().await.is_empty());
}

#[tokio::test]
async fn capped_json_writer_rejects_escape_expansion_before_http() {
    let server = MockServer::start(vec![MockReply::json(
        200,
        completion(json!({"unexpected": true})),
    )])
    .await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.limits.max_request_bytes = 512;
    let request = StructuredInferenceRequest::new(
        "m".to_owned().try_into().expect("model ID is valid"),
        vec![Message::new(MessageRole::User, "\0".repeat(128))],
        StructuredOutputSpec::new("result", json!({"type": "object"})).expect("schema is valid"),
        64,
    )
    .expect("request is valid at the provider-neutral layer");

    let error = LmStudioBackend::new(config)
        .expect("config is valid")
        .infer_structured(request)
        .await
        .expect_err("JSON escaping must not allocate beyond the request cap");
    assert_eq!(error.kind, BackendErrorKind::RequestTooLarge);
    assert!(error.message.contains("encoded JSON request"));
    assert!(server.captured().await.is_empty());
}

#[tokio::test]
async fn output_token_hard_ceiling_is_enforced_before_http() {
    let server = MockServer::start(Vec::new()).await;
    let mut config = LmStudioConfig::new(server.base_url.clone());
    config.limits.max_output_tokens = 256;
    let request = StructuredInferenceRequest::new(
        "model".to_owned().try_into().expect("model ID is valid"),
        vec![Message::new(MessageRole::User, "bounded")],
        StructuredOutputSpec::new(
            "bounded",
            json!({
                "type": "object",
                "properties": {"ok": {"type": "boolean"}},
                "required": ["ok"],
                "additionalProperties": false
            }),
        )
        .expect("schema is valid"),
        u32::MAX,
    )
    .expect("provider-neutral request permits runtime-selected budgets");

    let error = LmStudioBackend::new(config)
        .expect("config is valid")
        .infer_structured(request)
        .await
        .expect_err("provider ceiling must reject an excessive budget");
    assert_eq!(error.kind, BackendErrorKind::InvalidRequest);
    assert!(server.captured().await.is_empty());
}

#[test]
fn unsafe_base_urls_and_all_remote_plaintext_connections_are_rejected() {
    let cases = [
        "ftp://127.0.0.1:1234/",
        "http://user:pass@127.0.0.1:1234/",
        "http://127.0.0.1:1234/?debug=true",
        "http://127.0.0.1:1234/prefix/",
    ];
    for value in cases {
        let config = LmStudioConfig::new(Url::parse(value).expect("test URL parses"));
        let error = LmStudioBackend::new(config).expect_err("unsafe base URL must fail");
        assert_eq!(error.kind, BackendErrorKind::InvalidConfiguration);
    }

    for token in [None, Some(SecretToken::new("must-use-tls"))] {
        let mut remote =
            LmStudioConfig::new(Url::parse("http://192.0.2.10:1234/").expect("test URL parses"));
        remote.api_token = token;
        let error = LmStudioBackend::new(remote)
            .expect_err("remote HTTP must fail even when no credential is configured");
        assert_eq!(error.kind, BackendErrorKind::InvalidConfiguration);
    }

    let loopback =
        LmStudioConfig::new(Url::parse("http://127.0.0.1:1234/").expect("loopback URL parses"));
    assert!(LmStudioBackend::new(loopback).is_ok());

    let remote_tls =
        LmStudioConfig::new(Url::parse("https://192.0.2.10:1234/").expect("TLS URL parses"));
    assert!(LmStudioBackend::new(remote_tls).is_ok());

    let mut zero_token_limit =
        LmStudioConfig::new(Url::parse("http://127.0.0.1:1234/").expect("loopback URL parses"));
    zero_token_limit.limits.max_output_tokens = 0;
    assert!(matches!(
        LmStudioBackend::new(zero_token_limit),
        Err(error) if error.kind == BackendErrorKind::InvalidConfiguration
    ));
}

#[tokio::test]
async fn redirects_are_not_followed_with_discovery_credentials() {
    let target = MockServer::start(vec![MockReply::json(200, json!({"data": []}))]).await;
    let source = MockServer::start(vec![
        MockReply::raw(307, Vec::new()).with_header("Location", target.base_url.to_string()),
    ])
    .await;
    let mut config = LmStudioConfig::new(source.base_url.clone());
    config.api_token = Some(SecretToken::new("stay-on-origin"));

    let error = LmStudioBackend::new(config)
        .expect("loopback config is valid")
        .discover_models()
        .await
        .expect_err("redirect is surfaced rather than followed");
    assert_eq!(error.kind, BackendErrorKind::HttpStatus);
    assert!(target.captured().await.is_empty());
    let source_requests = source.captured().await;
    assert_eq!(source_requests.len(), 1);
    assert_eq!(
        source_requests[0]
            .headers
            .get("authorization")
            .map(String::as_str),
        Some("Bearer stay-on-origin")
    );
}

#[test]
fn backend_contract_is_object_safe_and_public_types_are_nameable() {
    let server_url = Url::parse("http://127.0.0.1:1234/").expect("static URL is valid");
    let concrete = LmStudioBackend::new(LmStudioConfig::new(server_url)).expect("config is valid");
    let backend: Box<dyn ModelBackend> = Box::new(concrete);
    assert_eq!(backend.backend_id().as_str(), "lmstudio");

    let limits = HttpLimits::default();
    assert!(limits.max_response_bytes > limits.max_request_bytes);
}
