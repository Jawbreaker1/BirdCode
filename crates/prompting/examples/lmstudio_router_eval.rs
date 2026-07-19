use birdcode_backends::{
    BackendError, DiscoveryEvidence, HttpEvidence, LmStudioBackend, LmStudioConfig,
    Message as BackendMessage, MessageRole as BackendMessageRole, ModelBackend, ModelDescriptor,
    ModelKind, ModelLoadState, NativeDiscoveryEvidence, NativeMatch, NativeMatchKey,
    ReasoningSetting, SecretToken, StructuredInferenceRequest, StructuredInferenceResponse,
    StructuredOutputSpec,
};
use birdcode_prompting::{
    CanonicalJson, CompiledMessage, CompiledPrompt, DataProvenance, DataSection, MessageContent,
    MessageRole, PromptInvocation, PromptLimits, PromptRegistry, RequiredAccess, RouteAction,
    RouteStrategy, SourceKind, TaskRouterOutput, TrustLevel, builtin_registry, task_router_key,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
#[cfg(not(unix))]
use std::io::Seek as _;
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};
use url::Url;

const DEFAULT_URL: &str = "http://127.0.0.1:1234/";
const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const ROUTER_MAX_CLARIFICATION_QUESTIONS: u32 = 3;
const EVAL_CATALOG: &str = include_str!("../../../evals/semantic-router/catalog.v2.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvalCatalog {
    catalog_version: u32,
    cases: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvalCase {
    id: String,
    version: u32,
    user_request: String,
    #[serde(default)]
    repository_context: Option<Value>,
    expected_action: RouteAction,
    expected_strategy: RouteStrategy,
    expected_required_access: RequiredAccess,
    required_evidence_sections: Vec<String>,
    #[serde(default)]
    forbidden_evidence_sections: Vec<String>,
    min_clarification_questions: u32,
    max_clarification_questions: u32,
    min_suggested_subtasks: u32,
    max_suggested_subtasks: u32,
    max_output_tokens: u32,
    #[serde(skip)]
    content_sha256: String,
}

#[derive(Debug)]
struct Options {
    base_url: Url,
    case_filter: Option<String>,
    output: PathBuf,
    source_revision: String,
    lm_studio_version: String,
    lm_studio_version_source: String,
}

#[derive(Clone, Debug, Serialize)]
struct EvalReport {
    report_schema_version: u32,
    status: &'static str,
    generated_at: chrono::DateTime<Utc>,
    completed_at: Option<chrono::DateTime<Utc>>,
    runner: RunnerReport,
    lm_studio: LmStudioReport,
    selected_model: Option<Value>,
    reasoning_setting: Option<ReasoningSetting>,
    catalog_content_sha256: String,
    results: Vec<Value>,
    failure: Option<FailureReport>,
}

#[derive(Clone, Debug, Serialize)]
struct RunnerReport {
    name: &'static str,
    version: &'static str,
    platform: &'static str,
    architecture: &'static str,
    source_revision: String,
}

#[derive(Clone, Debug, Serialize)]
struct LmStudioReport {
    application_version: String,
    application_version_source: String,
    api_version_evidence: &'static str,
    inference_endpoint_without_auth: String,
    discovery_evidence: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct FailureReport {
    stage: String,
    message: String,
    evidence: Option<Value>,
}

#[derive(Debug)]
struct EvalExecution {
    report: EvalReport,
    terminal_error: Option<String>,
}

#[derive(Debug)]
struct RetainedExecution {
    execution: EvalExecution,
    report_sha256: String,
}

#[derive(Debug)]
struct CaseExecution {
    report: Value,
    failed: bool,
}

#[derive(Debug)]
struct ReportReservation {
    path: PathBuf,
    _file: File,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let options = parse_explicit_inference_request()?;
    let registry = builtin_registry()?;
    let inference_endpoint = inference_endpoint_without_auth(&options.base_url)?;
    let cases = selected_cases(&options)?;
    let initial_report = initial_report(&options, inference_endpoint.clone());
    let mut config = LmStudioConfig::new(options.base_url.clone());
    config.api_token = optional_api_token()?;
    let backend = LmStudioBackend::new(config)?;
    let retained = run_and_retain(&options.output, initial_report, |report| async move {
        execute_eval(report, &backend, &registry, &cases, &inference_endpoint).await
    })
    .await?;
    let passed_cases = retained
        .execution
        .report
        .results
        .iter()
        .filter(|result| result["status"] == "passed")
        .count();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "report_path": options.output,
            "report_sha256": retained.report_sha256,
            "status": retained.execution.report.status,
            "passed_cases": passed_cases,
        }))?
    );
    if let Some(message) = retained.execution.terminal_error {
        return Err(io::Error::other(format!(
            "semantic-router eval failed after retaining its report: {message}"
        ))
        .into());
    }
    Ok(())
}

fn selected_cases(options: &Options) -> Result<Vec<EvalCase>, Box<dyn Error>> {
    let selected = load_cases()?
        .into_iter()
        .filter(|case| {
            options
                .case_filter
                .as_ref()
                .is_none_or(|filter| filter == &case.id)
        })
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(io::Error::other("requested semantic-router eval case was not found").into());
    }
    Ok(selected)
}

fn initial_report(options: &Options, inference_endpoint: String) -> EvalReport {
    EvalReport {
        report_schema_version: 2,
        status: "running",
        generated_at: Utc::now(),
        completed_at: None,
        runner: RunnerReport {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            source_revision: options.source_revision.clone(),
        },
        lm_studio: LmStudioReport {
            application_version: options.lm_studio_version.clone(),
            application_version_source: options.lm_studio_version_source.clone(),
            api_version_evidence: "Native model discovery used /api/v1/models; that endpoint does not itself report the LM Studio application version.",
            inference_endpoint_without_auth: inference_endpoint,
            discovery_evidence: None,
        },
        selected_model: None,
        reasoning_setting: None,
        catalog_content_sha256: sha256_bytes(EVAL_CATALOG.as_bytes()),
        results: Vec::new(),
        failure: None,
    }
}

async fn run_and_retain<F, Fut>(
    path: &Path,
    initial: EvalReport,
    operation: F,
) -> Result<RetainedExecution, Box<dyn Error>>
where
    F: FnOnce(EvalReport) -> Fut,
    Fut: Future<Output = EvalExecution>,
{
    let reservation = ReportReservation::create(path, &initial)?;
    let execution = operation(initial).await;
    let report_sha256 = reservation.finish(&execution.report)?;
    Ok(RetainedExecution {
        execution,
        report_sha256,
    })
}

async fn execute_eval(
    mut report: EvalReport,
    backend: &LmStudioBackend,
    registry: &PromptRegistry,
    cases: &[EvalCase],
    inference_endpoint: &str,
) -> EvalExecution {
    let catalog = match backend.discover_models().await {
        Ok(catalog) => catalog,
        Err(error) => {
            return failed_execution(
                report,
                "discovery",
                error.to_string(),
                Some(retained_backend_error(&error, false)),
            );
        }
    };
    report.lm_studio.discovery_evidence = Some(retained_discovery_summary(&catalog.evidence));
    let model = match exactly_one_loaded(catalog.models.clone()) {
        Ok(model) => model,
        Err(error) => {
            return failed_execution(report, "model_selection", error.to_string(), None);
        }
    };
    let discovery_evidence = match retained_discovery_evidence(&catalog.evidence, &model) {
        Ok(evidence) => evidence,
        Err(error) => {
            return failed_execution(report, "evidence_retention", error.to_string(), None);
        }
    };
    report.lm_studio.discovery_evidence = Some(discovery_evidence);
    report.selected_model = Some(retained_selected_model(&model));
    let reasoning = match reasoning_setting_for(&model) {
        Ok(reasoning) => reasoning,
        Err(error) => {
            return failed_execution(report, "reasoning_selection", error.to_string(), None);
        }
    };
    report.reasoning_setting = reasoning;

    let mut failed_cases = 0_usize;
    for case in cases {
        let execution = run_case(
            backend,
            &model,
            registry,
            case,
            reasoning,
            inference_endpoint,
        )
        .await;
        failed_cases += usize::from(execution.failed);
        report.results.push(execution.report);
    }
    report.completed_at = Some(Utc::now());
    if failed_cases == 0 {
        report.status = "passed";
        report.failure = None;
        EvalExecution {
            report,
            terminal_error: None,
        }
    } else {
        let message = format!("{failed_cases} of {} eval cases failed", cases.len());
        report.status = "failed";
        report.failure = Some(FailureReport {
            stage: "case_evaluation".to_owned(),
            message: message.clone(),
            evidence: None,
        });
        EvalExecution {
            report,
            terminal_error: Some(message),
        }
    }
}

fn failed_execution(
    mut report: EvalReport,
    stage: &str,
    message: String,
    evidence: Option<Value>,
) -> EvalExecution {
    report.status = "failed";
    report.completed_at = Some(Utc::now());
    report.failure = Some(FailureReport {
        stage: stage.to_owned(),
        message: message.clone(),
        evidence,
    });
    EvalExecution {
        report,
        terminal_error: Some(message),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "each retained failure stage is kept explicit so live evidence is never skipped"
)]
async fn run_case(
    backend: &LmStudioBackend,
    model: &ModelDescriptor,
    registry: &PromptRegistry,
    case: &EvalCase,
    reasoning: Option<ReasoningSetting>,
    inference_endpoint: &str,
) -> CaseExecution {
    let invocation = invocation_for(case);
    let compiled = match registry.compile(&task_router_key(), &invocation) {
        Ok(compiled) => compiled,
        Err(error) => {
            return failed_case(case, "prompt_compilation", error.to_string(), None, None);
        }
    };
    let provenance = match eval_provenance(&compiled, &invocation, case, inference_endpoint) {
        Ok(provenance) => provenance,
        Err(error) => return failed_case(case, "provenance", error.to_string(), None, None),
    };
    let messages = compiled
        .messages
        .iter()
        .map(to_backend_message)
        .collect::<Result<Vec<_>, _>>();
    let messages = match messages {
        Ok(messages) => messages,
        Err(error) => {
            return failed_case(
                case,
                "prompt_encoding",
                error.to_string(),
                Some(provenance),
                None,
            );
        }
    };
    let output_contract = match StructuredOutputSpec::new_with_generation_schema(
        "task_router_output",
        compiled.output_schema.clone(),
        compiled.generation_schema.clone(),
    ) {
        Ok(contract) => contract,
        Err(error) => {
            return failed_case(
                case,
                "request_contract",
                error.to_string(),
                Some(provenance),
                None,
            );
        }
    };
    let request = StructuredInferenceRequest::new(
        model.id.clone(),
        messages,
        output_contract,
        case.max_output_tokens,
    );
    let mut request = match request {
        Ok(request) => request,
        Err(error) => {
            return failed_case(
                case,
                "request_contract",
                error.to_string(),
                Some(provenance),
                None,
            );
        }
    };
    if let Some(reasoning) = reasoning {
        request = request.with_reasoning(reasoning);
    }

    let response = match backend.infer_structured(request).await {
        Ok(response) => response,
        Err(error) => {
            return failed_case(
                case,
                "inference",
                error.to_string(),
                Some(provenance),
                Some(retained_backend_error(&error, true)),
            );
        }
    };
    if let Err(error) = registry.validate_output(&compiled, &invocation, &response.value) {
        return failed_case_with_response(
            case,
            "output_validation",
            error.to_string(),
            provenance,
            &response,
            None,
        );
    }
    let output: TaskRouterOutput = match serde_json::from_value(response.value.clone()) {
        Ok(output) => output,
        Err(error) => {
            return failed_case_with_response(
                case,
                "output_decoding",
                error.to_string(),
                provenance,
                &response,
                None,
            );
        }
    };
    let mismatches = expectation_mismatches(case, &output);
    if !mismatches.is_empty() {
        return failed_case_with_response(
            case,
            "semantic_expectations",
            mismatches.join("; "),
            provenance,
            &response,
            Some(output),
        );
    }

    let mut report = case_report_base(case, "passed");
    report.insert("provenance".to_owned(), provenance);
    insert_response(&mut report, &response);
    report.insert(
        "validated_output".to_owned(),
        serde_json::to_value(output).expect("validated router output serializes"),
    );
    CaseExecution {
        report: Value::Object(report),
        failed: false,
    }
}

fn case_report_base(case: &EvalCase, status: &'static str) -> Map<String, Value> {
    let mut report = Map::new();
    report.insert(
        "eval".to_owned(),
        Value::String(format!("{}@{}", case.id, case.version)),
    );
    report.insert("status".to_owned(), Value::String(status.to_owned()));
    report.insert("expected".to_owned(), expected_case(case));
    report
}

fn expected_case(case: &EvalCase) -> Value {
    serde_json::json!({
        "action": case.expected_action,
        "strategy": case.expected_strategy,
        "required_access": case.expected_required_access,
        "required_evidence_sections": case.required_evidence_sections,
        "forbidden_evidence_sections": case.forbidden_evidence_sections,
        "clarification_questions": {
            "minimum": case.min_clarification_questions,
            "maximum": case.max_clarification_questions,
        },
        "suggested_subtasks": {
            "minimum": case.min_suggested_subtasks,
            "maximum": case.max_suggested_subtasks,
        },
    })
}

fn failed_case(
    case: &EvalCase,
    stage: &str,
    message: String,
    provenance: Option<Value>,
    evidence: Option<Value>,
) -> CaseExecution {
    let mut report = case_report_base(case, "failed");
    if let Some(provenance) = provenance {
        report.insert("provenance".to_owned(), provenance);
    }
    let mut failure = Map::new();
    failure.insert("stage".to_owned(), Value::String(stage.to_owned()));
    failure.insert("message".to_owned(), Value::String(message));
    failure.insert("evidence".to_owned(), evidence.unwrap_or(Value::Null));
    report.insert("failure".to_owned(), Value::Object(failure));
    CaseExecution {
        report: Value::Object(report),
        failed: true,
    }
}

fn failed_case_with_response(
    case: &EvalCase,
    stage: &str,
    message: String,
    provenance: Value,
    response: &StructuredInferenceResponse,
    candidate_output: Option<TaskRouterOutput>,
) -> CaseExecution {
    let mut execution = failed_case(case, stage, message, Some(provenance), None);
    let report = execution
        .report
        .as_object_mut()
        .expect("case reports are always objects");
    insert_response(report, response);
    report.insert(
        "candidate_output".to_owned(),
        candidate_output.map_or_else(
            || response.value.clone(),
            |output| serde_json::to_value(output).expect("router output serializes"),
        ),
    );
    execution
}

fn insert_response(report: &mut Map<String, Value>, response: &StructuredInferenceResponse) {
    report.insert(
        "model".to_owned(),
        serde_json::to_value(&response.model_id).expect("model ID serializes"),
    );
    report.insert(
        "finish_reason".to_owned(),
        serde_json::to_value(&response.finish_reason).expect("finish reason serializes"),
    );
    report.insert(
        "usage".to_owned(),
        serde_json::to_value(&response.usage).expect("usage serializes"),
    );
    report.insert(
        "raw_assistant_text".to_owned(),
        Value::String(response.raw_text.clone()),
    );
    report.insert(
        "inference_evidence".to_owned(),
        serde_json::to_value(&response.evidence).expect("inference evidence serializes"),
    );
}

fn expectation_mismatches(case: &EvalCase, output: &TaskRouterOutput) -> Vec<String> {
    let mut mismatches = Vec::new();
    if output.action != case.expected_action {
        mismatches.push(format!(
            "action expected {:?}, got {:?}",
            case.expected_action, output.action
        ));
    }
    if output.strategy != case.expected_strategy {
        mismatches.push(format!(
            "strategy expected {:?}, got {:?}",
            case.expected_strategy, output.strategy
        ));
    }
    if output.required_access != case.expected_required_access {
        mismatches.push(format!(
            "required_access expected {:?}, got {:?}",
            case.expected_required_access, output.required_access
        ));
    }
    let evidence_sections = output
        .evidence
        .iter()
        .map(|evidence| evidence.section.as_str())
        .collect::<BTreeSet<_>>();
    for required in &case.required_evidence_sections {
        if !evidence_sections.contains(required.as_str()) {
            mismatches.push(format!(
                "evidence did not cite required section {required:?}"
            ));
        }
    }
    for forbidden in &case.forbidden_evidence_sections {
        if evidence_sections.contains(forbidden.as_str()) {
            mismatches.push(format!("evidence cited forbidden section {forbidden:?}"));
        }
    }
    check_count(
        "clarification_questions",
        output.clarification_questions.len(),
        case.min_clarification_questions,
        case.max_clarification_questions,
        &mut mismatches,
    );
    check_count(
        "suggested_subtasks",
        output.suggested_subtasks.len(),
        case.min_suggested_subtasks,
        case.max_suggested_subtasks,
        &mut mismatches,
    );
    mismatches
}

fn check_count(
    name: &str,
    actual: usize,
    minimum: u32,
    maximum: u32,
    mismatches: &mut Vec<String>,
) {
    let actual = u32::try_from(actual).unwrap_or(u32::MAX);
    if actual < minimum || actual > maximum {
        mismatches.push(format!(
            "{name} expected {minimum}..={maximum} items, got {actual}"
        ));
    }
}

impl ReportReservation {
    fn create(path: &Path, initial: &EvalReport) -> Result<Self, Box<dyn Error>> {
        let bytes = report_bytes(initial)?;
        if let Some(parent) = report_parent(path) {
            fs::create_dir_all(parent)?;
        }
        let mut file = open_new_report_file(path)?;
        if let Err(error) = write_synced(&mut file, &bytes) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error.into());
        }
        sync_report_parent(path)?;
        Ok(Self {
            path: path.to_owned(),
            _file: file,
        })
    }

    #[cfg(unix)]
    fn finish(self, report: &EvalReport) -> Result<String, Box<dyn Error>> {
        let bytes = report_bytes(report)?;
        let (temporary_path, mut temporary_file) = create_final_report_file(&self.path)?;
        if let Err(error) = write_synced(&mut temporary_file, &bytes) {
            drop(temporary_file);
            let _ = fs::remove_file(&temporary_path);
            return Err(error.into());
        }
        drop(temporary_file);
        fs::rename(&temporary_path, &self.path)?;
        sync_report_parent(&self.path)?;
        Ok(sha256_bytes(&bytes))
    }

    #[cfg(not(unix))]
    fn finish(mut self, report: &EvalReport) -> Result<String, Box<dyn Error>> {
        let bytes = report_bytes(report)?;
        self._file.rewind()?;
        self._file.write_all(&bytes)?;
        self._file.set_len(u64::try_from(bytes.len())?)?;
        self._file.sync_all()?;
        sync_report_parent(&self.path)?;
        Ok(sha256_bytes(&bytes))
    }
}

fn open_new_report_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
fn create_final_report_file(path: &Path) -> io::Result<(PathBuf, File)> {
    let directory = report_directory(path);
    for attempt in 0_u8..100 {
        let name = format!(".birdcode-report-{}-{attempt}.tmp", std::process::id());
        let temporary_path = directory.join(name);
        match open_new_report_file(&temporary_path) {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not reserve a unique final report staging file",
    ))
}

fn report_bytes(report: &EvalReport) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_synced(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

fn report_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn report_directory(path: &Path) -> &Path {
    report_parent(path).unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_report_parent(path: &Path) -> io::Result<()> {
    File::open(report_directory(path))?.sync_all()
}

#[cfg(not(unix))]
fn sync_report_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn retained_discovery_summary(evidence: &DiscoveryEvidence) -> Value {
    serde_json::json!({
        "openai": retained_http_summary(&evidence.openai),
        "native": match &evidence.native {
            NativeDiscoveryEvidence::Available { response } => serde_json::json!({
                "status": "available",
                "response": retained_http_summary(response),
            }),
            NativeDiscoveryEvidence::Unavailable { error } => serde_json::json!({
                "status": "unavailable",
                "error": retained_backend_error(error, false),
            }),
        },
    })
}

fn retained_discovery_evidence(
    evidence: &DiscoveryEvidence,
    model: &ModelDescriptor,
) -> Result<Value, Box<dyn Error>> {
    let openai_entry = retained_openai_model_entry(&evidence.openai.body, model.id.as_str())?;
    let native = match &evidence.native {
        NativeDiscoveryEvidence::Available { response } => serde_json::json!({
            "status": "available",
            "response": retained_http_summary(response),
            "selected_match": retained_native_model_match(&response.body, model)?,
        }),
        NativeDiscoveryEvidence::Unavailable { error } => serde_json::json!({
            "status": "unavailable",
            "error": retained_backend_error(error, false),
        }),
    };
    Ok(serde_json::json!({
        "openai": {
            "response": retained_http_summary(&evidence.openai),
            "selected_model_entry": openai_entry,
        },
        "native": native,
    }))
}

fn retained_http_summary(evidence: &HttpEvidence) -> Value {
    serde_json::json!({
        "endpoint_without_auth": endpoint_without_auth(&evidence.endpoint),
        "status": evidence.status,
        "response_body_sha256": evidence.response_body_sha256,
    })
}

fn retained_openai_model_entry(body: &Value, model_id: &str) -> Result<Value, Box<dyn Error>> {
    let entries = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("OpenAI discovery evidence has no data array"))?;
    let mut matches = entries.iter().filter(|entry| entry["id"] == model_id);
    let entry = matches
        .next()
        .ok_or_else(|| io::Error::other("selected model is absent from OpenAI evidence"))?;
    if matches.next().is_some() {
        return Err(io::Error::other("selected model is duplicated in OpenAI evidence").into());
    }
    let object = entry
        .as_object()
        .ok_or_else(|| io::Error::other("selected OpenAI model entry is not an object"))?;
    let mut retained = Map::new();
    retained.insert("id".to_owned(), Value::String(model_id.to_owned()));
    if let Some(kind) = object.get("object").filter(|value| value.is_string()) {
        retained.insert("object".to_owned(), kind.clone());
    }
    if let Some(created) = object.get("created").filter(|value| value.is_number()) {
        retained.insert("created".to_owned(), created.clone());
    }
    Ok(Value::Object(retained))
}

fn retained_native_model_match(
    body: &Value,
    model: &ModelDescriptor,
) -> Result<Value, Box<dyn Error>> {
    let NativeMatch::Exact(match_key) = &model.native_match else {
        return Err(io::Error::other("selected model has no exact native match").into());
    };
    let entries = body
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("native discovery evidence has no models array"))?;
    let mut matches = entries
        .iter()
        .filter(|entry| native_entry_matches(entry, model.id.as_str(), match_key));
    let entry = matches
        .next()
        .ok_or_else(|| io::Error::other("selected model is absent from native evidence"))?;
    if matches.next().is_some() {
        return Err(io::Error::other("selected model is ambiguous in native evidence").into());
    }
    let object = entry
        .as_object()
        .ok_or_else(|| io::Error::other("selected native model entry is not an object"))?;
    let matching_loaded_instances = object
        .get("loaded_instances")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|instance| instance["id"] == model.id.as_str())
        .map(|instance| {
            serde_json::json!({
                "id": instance["id"],
                "context_length": instance["config"]["context_length"],
            })
        })
        .collect::<Vec<_>>();
    let quantization = object
        .get("quantization")
        .and_then(Value::as_object)
        .map(|value| {
            serde_json::json!({
                "name": value.get("name"),
                "bits_per_weight": value.get("bits_per_weight"),
            })
        });
    let selected_variant = object
        .get("selected_variant")
        .filter(|variant| *variant == model.id.as_str());
    Ok(serde_json::json!({
        "match_key": match_key,
        "key": object.get("key"),
        "selected_variant": selected_variant,
        "quantization": quantization,
        "matching_loaded_instances": matching_loaded_instances,
    }))
}

fn native_entry_matches(entry: &Value, model_id: &str, match_key: &NativeMatchKey) -> bool {
    match match_key {
        NativeMatchKey::LoadedInstance => entry["loaded_instances"]
            .as_array()
            .is_some_and(|instances| instances.iter().any(|instance| instance["id"] == model_id)),
        NativeMatchKey::ModelKey => entry["key"] == model_id,
        NativeMatchKey::SelectedVariant => entry["selected_variant"] == model_id,
        NativeMatchKey::Variant => entry["variants"]
            .as_array()
            .is_some_and(|variants| variants.iter().any(|variant| variant == model_id)),
    }
}

fn retained_selected_model(model: &ModelDescriptor) -> Value {
    let matching_loaded_instances = model
        .loaded_instances
        .iter()
        .filter(|instance| instance.id == model.id.as_str())
        .collect::<Vec<_>>();
    let quantization = model.quantization.as_ref().map(|quantization| {
        serde_json::json!({
            "name": quantization.name,
            "bits_per_weight": quantization.bits_per_weight,
            "selected_variant": quantization
                .selected_variant
                .as_deref()
                .filter(|variant| *variant == model.id.as_str()),
        })
    });
    serde_json::json!({
        "id": model.id,
        "kind": model.kind,
        "load_state": model.load_state,
        "matching_loaded_instances": matching_loaded_instances,
        "maximum_context_tokens": model.maximum_context_tokens,
        "quantization": quantization,
        "capabilities": model.capabilities,
        "native_match": model.native_match,
    })
}

fn retained_backend_error(error: &BackendError, include_raw_response: bool) -> Value {
    let evidence = error.evidence.as_deref().map(|evidence| {
        serde_json::json!({
            "endpoint_without_auth": evidence.endpoint.as_deref().map(endpoint_without_auth),
            "status": evidence.status,
            "response_body_sha256": evidence.response_body_sha256,
            "raw_response": include_raw_response.then(|| evidence.raw_response.clone()).flatten(),
            "response_preview": include_raw_response.then(|| evidence.response_preview.clone()).flatten(),
        })
    });
    serde_json::json!({
        "backend_id": error.backend_id,
        "operation": error.operation,
        "kind": error.kind,
        "message": error.message,
        "evidence": evidence,
    })
}

fn endpoint_without_auth(endpoint: &str) -> String {
    let Ok(mut endpoint) = Url::parse(endpoint) else {
        return "[invalid endpoint omitted]".to_owned();
    };
    if endpoint.set_username("").is_err() || endpoint.set_password(None).is_err() {
        return "[endpoint credentials omitted]".to_owned();
    }
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint.to_string()
}

fn optional_api_token() -> Result<Option<SecretToken>, io::Error> {
    match std::env::var("LM_STUDIO_API_TOKEN") {
        Ok(value) => Ok(Some(SecretToken::new(value))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LM_STUDIO_API_TOKEN is not valid Unicode",
        )),
    }
}

fn eval_provenance(
    compiled: &CompiledPrompt,
    invocation: &PromptInvocation,
    case: &EvalCase,
    inference_endpoint: &str,
) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::json!({
        "manifest_content_sha256": compiled.manifest.content_sha256.clone(),
        "generation_schema_sha256": canonical_json_sha256(&compiled.generation_schema)?,
        "inference_endpoint_without_auth": inference_endpoint,
        "case_content_sha256": case.content_sha256,
        "input_sha256": canonical_json_sha256(&serde_json::to_value(invocation)?)?,
    }))
}

fn canonical_json_sha256(value: &Value) -> Result<String, serde_json::Error> {
    let encoded = CanonicalJson::new(value.clone()).to_compact_string()?;
    Ok(sha256_bytes(encoded.as_bytes()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn inference_endpoint_without_auth(base_url: &Url) -> Result<String, io::Error> {
    let mut endpoint = base_url.clone();
    endpoint
        .set_username("")
        .map_err(|()| io::Error::other("LM Studio URL cannot remove username"))?;
    endpoint
        .set_password(None)
        .map_err(|()| io::Error::other("LM Studio URL cannot remove password"))?;
    endpoint.set_path(CHAT_COMPLETIONS_PATH);
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    Ok(endpoint.to_string())
}

fn load_cases() -> Result<Vec<EvalCase>, Box<dyn Error>> {
    let catalog: EvalCatalog = serde_json::from_str(EVAL_CATALOG)?;
    if catalog.catalog_version != 2 || catalog.cases.is_empty() {
        return Err(io::Error::other("unsupported or empty semantic-router eval catalog").into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../evals/semantic-router");
    catalog
        .cases
        .into_iter()
        .map(|filename| {
            validate_case_filename(&filename)?;
            let bytes = fs::read(root.join(&filename))?;
            let content_sha256 = sha256_bytes(&bytes);
            let mut case = serde_json::from_slice::<EvalCase>(&bytes)?;
            case.content_sha256 = content_sha256;
            validate_case_expectations(&case)?;
            Ok(case)
        })
        .collect()
}

fn validate_case_expectations(case: &EvalCase) -> Result<(), Box<dyn Error>> {
    let available_sections = if case.repository_context.is_some() {
        ["request", "repository"].as_slice()
    } else {
        ["request"].as_slice()
    };
    let required_evidence = case
        .required_evidence_sections
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let forbidden_evidence = case
        .forbidden_evidence_sections
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if case.required_evidence_sections.is_empty()
        || required_evidence.len() != case.required_evidence_sections.len()
        || forbidden_evidence.len() != case.forbidden_evidence_sections.len()
        || case
            .required_evidence_sections
            .iter()
            .any(|section| !available_sections.contains(&section.as_str()))
        || case
            .forbidden_evidence_sections
            .iter()
            .any(|section| !available_sections.contains(&section.as_str()))
        || !required_evidence.is_disjoint(&forbidden_evidence)
    {
        return Err(io::Error::other(format!(
            "eval {} has invalid evidence section expectations",
            case.id
        ))
        .into());
    }
    if case.min_clarification_questions > case.max_clarification_questions
        || case.max_clarification_questions > ROUTER_MAX_CLARIFICATION_QUESTIONS
        || case.min_suggested_subtasks > case.max_suggested_subtasks
        || case.max_suggested_subtasks > PromptLimits::DEFAULT.max_suggested_subtasks
    {
        return Err(
            io::Error::other(format!("eval {} has invalid expectation ranges", case.id)).into(),
        );
    }
    let clarification_range_matches_action = if case.expected_action == RouteAction::Clarify {
        case.min_clarification_questions > 0
    } else {
        case.max_clarification_questions == 0
    };
    let subtask_range_matches_strategy = if case.expected_strategy == RouteStrategy::Delegate {
        case.min_suggested_subtasks > 0
    } else {
        case.max_suggested_subtasks == 0
    };
    if !clarification_range_matches_action || !subtask_range_matches_strategy {
        return Err(io::Error::other(format!(
            "eval {} expectation ranges contradict its action or strategy",
            case.id
        ))
        .into());
    }
    Ok(())
}

fn validate_case_filename(filename: &str) -> Result<(), Box<dyn Error>> {
    let path = Path::new(filename);
    let mut components = path.components();
    let one_plain_component = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && path.extension().and_then(|extension| extension.to_str()) == Some("json");
    if !one_plain_component {
        return Err(io::Error::other(format!("unsafe eval case filename: {filename}")).into());
    }
    Ok(())
}

fn parse_explicit_inference_request() -> Result<Options, Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let Some(flag) = arguments.next() else {
        return Err(
            io::Error::other(
                "live inference is opt-in and retained; pass --infer-loaded --output REPORT.json --source-revision REVISION --lm-studio-version VERSION --lm-studio-version-source SOURCE [--url URL]",
            )
            .into(),
        );
    };
    if flag != "--infer-loaded" {
        return Err(io::Error::other("first argument must be --infer-loaded").into());
    }
    let mut base_url =
        std::env::var("BIRDCODE_LMSTUDIO_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned());
    let mut case_filter = None;
    let mut output = None;
    let mut source_revision = None;
    let mut lm_studio_version = None;
    let mut lm_studio_version_source = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--url" => {
                base_url = arguments
                    .next()
                    .ok_or_else(|| io::Error::other("--url requires a value"))?;
            }
            "--case" => {
                case_filter = Some(
                    arguments
                        .next()
                        .ok_or_else(|| io::Error::other("--case requires an eval ID"))?,
                );
            }
            "--output" => {
                output =
                    Some(PathBuf::from(arguments.next().ok_or_else(|| {
                        io::Error::other("--output requires a path")
                    })?));
            }
            "--source-revision" => {
                source_revision = Some(
                    arguments
                        .next()
                        .ok_or_else(|| io::Error::other("--source-revision requires a value"))?,
                );
            }
            "--lm-studio-version" => {
                lm_studio_version = Some(
                    arguments
                        .next()
                        .ok_or_else(|| io::Error::other("--lm-studio-version requires a value"))?,
                );
            }
            "--lm-studio-version-source" => {
                lm_studio_version_source = Some(arguments.next().ok_or_else(|| {
                    io::Error::other("--lm-studio-version-source requires a value")
                })?);
            }
            _ => {
                return Err(io::Error::other(format!("unknown argument: {argument}")).into());
            }
        }
    }
    Ok(Options {
        base_url: Url::parse(&base_url)?,
        case_filter,
        output: output.ok_or_else(|| {
            io::Error::other("--output REPORT.json is required so live evidence is retained")
        })?,
        source_revision: required_nonempty_option(source_revision, "--source-revision")?,
        lm_studio_version: required_nonempty_option(lm_studio_version, "--lm-studio-version")?,
        lm_studio_version_source: required_nonempty_option(
            lm_studio_version_source,
            "--lm-studio-version-source",
        )?,
    })
}

fn required_nonempty_option(value: Option<String>, flag: &str) -> Result<String, io::Error> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| io::Error::other(format!("{flag} requires a non-empty value")))
}

fn invocation_for(case: &EvalCase) -> PromptInvocation {
    let mut sections = vec![DataSection {
        name: "request".to_owned(),
        trust: TrustLevel::User,
        provenance: DataProvenance {
            source_kind: SourceKind::User,
            source_id: format!("eval:{}@{}:request", case.id, case.version),
            artifact_sha256: None,
            event_id: None,
        },
        payload: serde_json::json!({ "request": case.user_request }),
    }];
    if let Some(repository_context) = &case.repository_context {
        sections.push(DataSection {
            name: "repository".to_owned(),
            trust: TrustLevel::Repository,
            provenance: DataProvenance {
                source_kind: SourceKind::Repository,
                source_id: format!("eval:{}@{}:repository", case.id, case.version),
                artifact_sha256: None,
                event_id: None,
            },
            payload: repository_context.clone(),
        });
    }
    PromptInvocation::with_limits(sections, PromptLimits::new(case.max_suggested_subtasks))
}

fn reasoning_setting_for(
    model: &ModelDescriptor,
) -> Result<Option<ReasoningSetting>, Box<dyn Error>> {
    let Some(reasoning) = &model.capabilities.reasoning else {
        return Ok(None);
    };
    if reasoning
        .allowed_options
        .iter()
        .any(|option| option.0 == "off")
    {
        Ok(Some(ReasoningSetting::Off))
    } else {
        Err(
            io::Error::other("loaded reasoning model does not report a supported off setting")
                .into(),
        )
    }
}

fn exactly_one_loaded(models: Vec<ModelDescriptor>) -> Result<ModelDescriptor, Box<dyn Error>> {
    let mut loaded = models
        .into_iter()
        .filter(|model| is_loaded_language(&model.kind, &model.load_state));
    let model = loaded
        .next()
        .ok_or_else(|| io::Error::other("LM Studio reports no loaded language model"))?;
    if loaded.next().is_some() {
        return Err(io::Error::other(
            "LM Studio reports multiple loaded language models; choose explicitly in a future eval runner",
        )
        .into());
    }
    Ok(model)
}

fn is_loaded_language(kind: &ModelKind, load_state: &ModelLoadState) -> bool {
    matches!(kind, ModelKind::Language) && matches!(load_state, ModelLoadState::Loaded)
}

fn to_backend_message(message: &CompiledMessage) -> Result<BackendMessage, Box<dyn Error>> {
    let role = match message.role {
        MessageRole::System => BackendMessageRole::System,
        MessageRole::User => BackendMessageRole::User,
    };
    let content = match &message.content {
        MessageContent::Text(value) => value.clone(),
        MessageContent::Json(value) => value.to_compact_string()?,
    };
    Ok(BackendMessage::new(role, content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loaded_language_models_are_inference_candidates() {
        assert!(is_loaded_language(
            &ModelKind::Language,
            &ModelLoadState::Loaded
        ));
        assert!(!is_loaded_language(
            &ModelKind::Embedding,
            &ModelLoadState::Loaded
        ));
        assert!(!is_loaded_language(
            &ModelKind::Language,
            &ModelLoadState::NotLoaded
        ));
    }

    #[test]
    fn bundled_eval_catalog_and_comparison_use_all_route_axes() {
        let cases = load_cases().expect("bundled eval catalog should load");
        let routes = cases
            .iter()
            .map(|case| {
                (
                    case.id.as_str(),
                    case.expected_action,
                    case.expected_strategy,
                    case.expected_required_access,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            routes,
            vec![
                (
                    "semantic-router.multilingual-delegation",
                    RouteAction::Inspect,
                    RouteStrategy::Delegate,
                    RequiredAccess::ReadOnly,
                ),
                (
                    "semantic-router.clarification-abstention",
                    RouteAction::Clarify,
                    RouteStrategy::Direct,
                    RequiredAccess::None,
                ),
                (
                    "semantic-router.repository-injection-inspect",
                    RouteAction::Inspect,
                    RouteStrategy::Direct,
                    RequiredAccess::ReadOnly,
                ),
                (
                    "semantic-router.informational-answer",
                    RouteAction::Answer,
                    RouteStrategy::Direct,
                    RequiredAccess::None,
                ),
                (
                    "semantic-router.irrelevant-repository-answer",
                    RouteAction::Answer,
                    RouteStrategy::Direct,
                    RequiredAccess::None,
                ),
                (
                    "semantic-router.zero-delegation-read-only",
                    RouteAction::Inspect,
                    RouteStrategy::Direct,
                    RequiredAccess::ReadOnly,
                ),
                (
                    "semantic-router.english-change",
                    RouteAction::Change,
                    RouteStrategy::Direct,
                    RequiredAccess::WorkspaceWrite,
                ),
                (
                    "semantic-router.japanese-clarification",
                    RouteAction::Clarify,
                    RouteStrategy::Direct,
                    RequiredAccess::None,
                ),
                (
                    "semantic-router.arabic-delegation",
                    RouteAction::Inspect,
                    RouteStrategy::Delegate,
                    RequiredAccess::ReadOnly,
                ),
            ]
        );
        assert_eq!(
            cases
                .iter()
                .find(|case| case.id == "semantic-router.zero-delegation-read-only")
                .expect("zero-delegation case should exist")
                .max_suggested_subtasks,
            0
        );
    }

    #[test]
    fn semantic_expectations_compare_evidence_counts_and_all_route_axes() {
        let cases = load_cases().expect("bundled eval catalog should load");
        let mut output: TaskRouterOutput = serde_json::from_value(serde_json::json!({
            "action": "inspect",
            "strategy": "delegate",
            "required_access": "read_only",
            "confidence": 1.0,
            "evidence": [
                { "section": "request", "basis": "Independent read-only review." },
                { "section": "repository", "basis": "Three independent areas are supplied." }
            ],
            "clarification_questions": [],
            "suggested_subtasks": [
                {
                    "id": "review-store",
                    "objective": "Review one bounded area.",
                    "required_access": "read_only",
                    "acceptance_criteria": ["Findings are reported."],
                    "depends_on": []
                },
                {
                    "id": "review-backend",
                    "objective": "Review another bounded area.",
                    "required_access": "read_only",
                    "acceptance_criteria": ["Findings are reported."],
                    "depends_on": []
                }
            ]
        }))
        .expect("test output should decode");
        assert!(expectation_mismatches(&cases[0], &output).is_empty());
        output.required_access = RequiredAccess::WorkspaceWrite;
        assert!(!expectation_mismatches(&cases[0], &output).is_empty());
    }

    #[test]
    fn irrelevant_repository_case_rejects_cite_all_evidence() {
        let cases = load_cases().expect("bundled eval catalog should load");
        let case = cases
            .iter()
            .find(|case| case.id == "semantic-router.irrelevant-repository-answer")
            .expect("irrelevant repository case should exist");
        assert_eq!(case.required_evidence_sections, ["request"]);
        assert_eq!(case.forbidden_evidence_sections, ["repository"]);

        let mut output: TaskRouterOutput = serde_json::from_value(serde_json::json!({
            "action": "answer",
            "strategy": "direct",
            "required_access": "none",
            "confidence": 0.9,
            "evidence": [
                { "section": "request", "basis": "The request asks for a general explanation." }
            ],
            "clarification_questions": [],
            "suggested_subtasks": []
        }))
        .expect("test output should decode");
        assert!(expectation_mismatches(case, &output).is_empty());

        output.evidence.push(birdcode_prompting::RouteEvidence {
            section: "repository".to_owned(),
            basis: "Unrelated repository content.".to_owned(),
        });
        assert!(
            expectation_mismatches(case, &output)
                .iter()
                .any(|mismatch| mismatch.contains("forbidden section"))
        );
    }

    #[test]
    fn intent_bearing_japanese_and_arabic_cases_assert_semantic_payloads() {
        let cases = load_cases().expect("bundled eval catalog should load");
        let japanese = cases
            .iter()
            .find(|case| case.id == "semantic-router.japanese-clarification")
            .expect("Japanese clarification case should exist");
        assert_eq!(
            japanese.user_request,
            "このプロジェクトをもっと良くして、完成したら公開してください。"
        );
        assert_eq!(japanese.min_clarification_questions, 1);
        assert_eq!(japanese.max_suggested_subtasks, 0);
        assert_eq!(japanese.required_evidence_sections, ["request"]);

        let arabic = cases
            .iter()
            .find(|case| case.id == "semantic-router.arabic-delegation")
            .expect("Arabic delegation case should exist");
        assert_eq!(
            arabic.user_request,
            "افحص المستودع من دون تعديل أي ملف. وزّع مراجعة سجل الأحداث، وأمان LM Studio، وعزل الصلاحيات على وكلاء فرعيين مستقلين، ثم لخّص الأدلة."
        );
        assert!(arabic.min_suggested_subtasks >= 2);
        assert_eq!(arabic.required_evidence_sections, ["request", "repository"]);
        assert_eq!(arabic.max_clarification_questions, 0);
    }

    #[test]
    fn eval_provenance_is_reproducible_and_never_emits_url_auth() {
        let cases = load_cases().expect("bundled eval catalog should load");
        let case = cases
            .iter()
            .find(|case| case.id == "semantic-router.english-change")
            .expect("English change case should exist");
        let invocation = invocation_for(case);
        let registry = builtin_registry().expect("registry should load");
        let compiled = registry
            .compile(&task_router_key(), &invocation)
            .expect("case should compile");
        let endpoint = inference_endpoint_without_auth(
            &Url::parse("http://runner:secret@127.0.0.1:1234/base?token=hidden#fragment")
                .expect("test URL should parse"),
        )
        .expect("endpoint should sanitize");
        let provenance = eval_provenance(&compiled, &invocation, case, &endpoint)
            .expect("provenance should hash");

        assert_eq!(endpoint, "http://127.0.0.1:1234/v1/chat/completions");
        assert_eq!(
            provenance["manifest_content_sha256"],
            compiled.manifest.content_sha256
        );
        for field in [
            "manifest_content_sha256",
            "generation_schema_sha256",
            "case_content_sha256",
            "input_sha256",
        ] {
            assert_eq!(
                provenance[field]
                    .as_str()
                    .expect("digest should be text")
                    .len(),
                64
            );
        }
        let encoded = serde_json::to_string(&provenance).expect("provenance should encode");
        assert!(!encoded.contains("runner"));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("hidden"));
    }

    fn fixture_options() -> Options {
        Options {
            base_url: Url::parse("http://127.0.0.1:1234/").expect("fixture URL is valid"),
            case_filter: None,
            output: PathBuf::from("unused-report.json"),
            source_revision: "fixture-revision".to_owned(),
            lm_studio_version: "fixture-version".to_owned(),
            lm_studio_version_source: "fixture-source".to_owned(),
        }
    }

    fn fixture_report() -> EvalReport {
        initial_report(
            &fixture_options(),
            "http://127.0.0.1:1234/v1/chat/completions".to_owned(),
        )
    }

    #[test]
    fn retained_report_is_create_new_synced_json_with_an_exact_digest() {
        let directory = tempfile::tempdir().expect("temporary report directory should exist");
        let path = directory.path().join("nested/report.json");
        let initial = fixture_report();
        let reservation =
            ReportReservation::create(&path, &initial).expect("report path should reserve");
        let reserved: Value =
            serde_json::from_slice(&fs::read(&path).expect("initial report should be readable"))
                .expect("initial reservation must already be valid JSON");
        assert_eq!(reserved["status"], "running");

        let mut report = initial.clone();
        report.status = "passed";
        report.completed_at = Some(Utc::now());
        report.results = vec![serde_json::json!({"eval": "fixture@1", "status": "passed"})];
        let digest = reservation.finish(&report).expect("report should persist");
        let bytes = fs::read(&path).expect("report should be readable");
        assert_eq!(digest, sha256_bytes(&bytes));
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).expect("report should be valid JSON"),
            serde_json::to_value(&report).expect("report should encode")
        );
        assert!(ReportReservation::create(&path, &fixture_report()).is_err());
    }

    #[tokio::test]
    async fn an_existing_report_path_prevents_the_live_operation() {
        let directory = tempfile::tempdir().expect("temporary report directory should exist");
        let path = directory.path().join("report.json");
        let reservation = ReportReservation::create(&path, &fixture_report())
            .expect("first reservation should succeed");
        reservation
            .finish(&fixture_report())
            .expect("fixture report should finish");
        let called = std::cell::Cell::new(false);

        let result = run_and_retain(&path, fixture_report(), |report| async {
            called.set(true);
            EvalExecution {
                report,
                terminal_error: None,
            }
        })
        .await;

        assert!(result.is_err());
        assert!(!called.get(), "the operation stands in for all HTTP work");
    }

    #[tokio::test]
    async fn mismatch_and_discovery_errors_are_durable_before_nonzero_exit() {
        let directory = tempfile::tempdir().expect("temporary report directory should exist");
        let mismatch_path = directory.path().join("mismatch.json");
        let cases = load_cases().expect("bundled eval catalog should load");
        let case = cases
            .iter()
            .find(|case| case.id == "semantic-router.english-change")
            .expect("English change case should exist");
        let output: TaskRouterOutput = serde_json::from_value(serde_json::json!({
            "action": "inspect",
            "strategy": "direct",
            "required_access": "read_only",
            "confidence": 0.8,
            "evidence": [{"section": "request", "basis": "fixture"}],
            "clarification_questions": [],
            "suggested_subtasks": []
        }))
        .expect("fixture output should decode");
        let mismatches = expectation_mismatches(case, &output);
        assert!(!mismatches.is_empty());
        let case_report = failed_case(
            case,
            "semantic_expectations",
            mismatches.join("; "),
            None,
            None,
        )
        .report;
        let mismatch = run_and_retain(&mismatch_path, fixture_report(), |mut report| async move {
            report.results.push(case_report);
            failed_execution(
                report,
                "case_evaluation",
                "1 of 1 eval cases failed".to_owned(),
                None,
            )
        })
        .await
        .expect("failed eval should still retain a report");
        assert!(mismatch.execution.terminal_error.is_some());
        let mismatch_bytes = fs::read(&mismatch_path).expect("mismatch report should exist");
        assert_eq!(mismatch.report_sha256, sha256_bytes(&mismatch_bytes));
        let mismatch_json: Value =
            serde_json::from_slice(&mismatch_bytes).expect("mismatch report is valid JSON");
        assert_eq!(mismatch_json["status"], "failed");
        assert_eq!(
            mismatch_json["results"][0]["failure"]["stage"],
            "semantic_expectations"
        );

        let discovery_path = directory.path().join("discovery.json");
        let discovery = run_and_retain(&discovery_path, fixture_report(), |report| async move {
            failed_execution(
                report,
                "discovery",
                "fixture discovery failed".to_owned(),
                Some(serde_json::json!({"kind": "transport"})),
            )
        })
        .await
        .expect("discovery failure should retain a report");
        assert!(discovery.execution.terminal_error.is_some());
        let discovery_json: Value = serde_json::from_slice(
            &fs::read(&discovery_path).expect("discovery report should exist"),
        )
        .expect("discovery report is valid JSON");
        assert_eq!(discovery_json["status"], "failed");
        assert_eq!(discovery_json["failure"]["stage"], "discovery");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial whole-report fixture must carry unrelated inventory and path fields"
    )]
    fn whole_report_retains_only_selected_safe_discovery_evidence() {
        let selected_id = "google/gemma-4-26b-a4b@q8_0";
        let openai_body = serde_json::json!({
            "data": [
                {
                    "id": selected_id,
                    "object": "model",
                    "path": "/Users/private/models/selected.gguf",
                    "config": {"api_token": "selected-config-secret"}
                },
                {
                    "id": "private/other-model",
                    "path": "/Users/private/models/other.gguf"
                }
            ]
        });
        let native_body = serde_json::json!({
            "models": [
                {
                    "type": "llm",
                    "key": "google/gemma-4-26b-a4b",
                    "quantization": {"name": "Q8_0", "bits_per_weight": 8},
                    "loaded_instances": [
                        {
                            "id": selected_id,
                            "config": {
                                "context_length": 121_088,
                                "model_path": "/Users/private/selected.gguf"
                            }
                        },
                        {
                            "id": "private/other-instance",
                            "config": {"context_length": 4096, "secret": "other-config-secret"}
                        }
                    ],
                    "selected_variant": selected_id,
                    "variants": [selected_id, "private/other-instance"],
                    "path": "/Users/private/native-record"
                },
                {
                    "type": "llm",
                    "key": "private/other-model",
                    "config": {"secret": "other-native-secret"}
                }
            ]
        });
        let evidence: DiscoveryEvidence = serde_json::from_value(serde_json::json!({
            "openai": {
                "endpoint": "http://credential-user:credential-password@127.0.0.1:1234/v1/models?token=query-secret#fragment-secret",
                "status": 200,
                "response_body_sha256": sha256_bytes(b"exact-openai-body"),
                "body": openai_body
            },
            "native": {
                "status": "available",
                "response": {
                    "endpoint": "http://credential-user:credential-password@127.0.0.1:1234/api/v1/models?token=query-secret#fragment-secret",
                    "status": 200,
                    "response_body_sha256": sha256_bytes(b"exact-native-body"),
                    "body": native_body
                }
            }
        }))
        .expect("fixture discovery evidence should decode");
        let model: ModelDescriptor = serde_json::from_value(serde_json::json!({
            "id": selected_id,
            "kind": "language",
            "display_name": "Gemma",
            "publisher": "Google",
            "architecture": "gemma4",
            "load_state": "loaded",
            "loaded_instances": [
                {"id": selected_id, "context_length": 121_088},
                {"id": "private/other-instance", "context_length": 4096}
            ],
            "maximum_context_tokens": 262_144,
            "quantization": {
                "name": "Q8_0",
                "bits_per_weight": 8,
                "selected_variant": selected_id
            },
            "capabilities": {
                "vision": "supported",
                "trained_for_tool_use": "supported",
                "reasoning": null
            },
            "native_match": {"exact": "loaded_instance"}
        }))
        .expect("fixture model should decode");
        let mut report = fixture_report();
        report.status = "passed";
        report.completed_at = Some(Utc::now());
        report.selected_model = Some(retained_selected_model(&model));
        report.lm_studio.discovery_evidence = Some(
            retained_discovery_evidence(&evidence, &model)
                .expect("selected evidence should retain safely"),
        );
        let encoded = serde_json::to_string(&report).expect("whole report should encode");

        assert!(encoded.contains(selected_id));
        assert!(encoded.contains("Q8_0"));
        assert!(encoded.contains("response_body_sha256"));
        for forbidden in [
            "/Users/private",
            "private/other-model",
            "private/other-instance",
            "selected-config-secret",
            "other-config-secret",
            "other-native-secret",
            "model_path",
            "credential-user",
            "credential-password",
            "query-secret",
            "fragment-secret",
        ] {
            assert!(!encoded.contains(forbidden), "report leaked {forbidden}");
        }
    }
}
