use birdcode_backends::{
    LmStudioBackend, LmStudioConfig, Message, MessageRole, ModelBackend, ModelCatalog, ModelId,
    ReasoningSetting, SecretToken, StructuredInferenceRequest, StructuredOutputSpec,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

const DEFAULT_URL: &str = "http://127.0.0.1:1234/";
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 600;
const MAX_REPAIR_INPUT_BYTES: u64 = 1024 * 1024;
const GENERATION_PROMPT: &str =
    include_str!("../../../prompts/codegen-calibration-literal-stream/1.0.0/manifest.json");
const REPAIR_PROMPT: &str =
    include_str!("../../../prompts/codegen-calibration-literal-stream-repair/1.0.0/manifest.json");
const TASK: &str = include_str!("../../../evals/codegen/literal-stream-v1/task.md");

#[derive(Debug)]
struct Options {
    base_url: Url,
    model_id: ModelId,
    reasoning: ReasoningSetting,
    candidate_path: PathBuf,
    evidence_path: PathBuf,
    request_timeout: Duration,
    repair_from: Option<PathBuf>,
    failure_report: Option<PathBuf>,
}

struct CompiledCalibration {
    request: StructuredInferenceRequest,
    prompt_manifest: &'static str,
    input_evidence: Value,
}

struct ReservedOutput {
    path: PathBuf,
    file: fs::File,
}

impl ReservedOutput {
    fn reserve(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        Ok(Self {
            path: path.to_owned(),
            file,
        })
    }

    fn write_all_and_sync(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)?;
        self.file.sync_all()
    }

    fn discard_empty(self) -> io::Result<()> {
        drop(self.file);
        fs::remove_file(self.path)
    }
}

struct ReservedOutputs {
    candidate: ReservedOutput,
    evidence: ReservedOutput,
}

fn reserve_outputs(candidate_path: &Path, evidence_path: &Path) -> io::Result<ReservedOutputs> {
    if candidate_path == evidence_path {
        return Err(io::Error::other(
            "candidate and evidence paths must be different",
        ));
    }
    let candidate = ReservedOutput::reserve(candidate_path)?;
    let evidence = match ReservedOutput::reserve(evidence_path) {
        Ok(evidence) => evidence,
        Err(error) => {
            candidate.discard_empty().map_err(|cleanup_error| {
                io::Error::other(format!(
                    "could not reserve evidence output ({error}); candidate reservation cleanup also failed: {cleanup_error}"
                ))
            })?;
            return Err(error);
        }
    };
    Ok(ReservedOutputs {
        candidate,
        evidence,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(options) = parse_options()? else {
        return Ok(());
    };
    let mut config = LmStudioConfig::new(options.base_url);
    config.limits.request_timeout = options.request_timeout;
    config.api_token = std::env::var("LM_STUDIO_API_TOKEN")
        .ok()
        .map(SecretToken::new);
    let backend = LmStudioBackend::new(config)?;
    let catalog = backend.discover_models().await?;
    require_discovered_model(&catalog, &options.model_id)?;

    let compiled = calibration_request(
        options.model_id.clone(),
        options.reasoning,
        options.repair_from.as_deref(),
        options.failure_report.as_deref(),
    )?;
    // Reserve both create-new outputs before the model inference. A stale or
    // colliding evidence path must not allow an unjournalable generation.
    let mut outputs = reserve_outputs(&options.candidate_path, &options.evidence_path)?;
    let request = compiled.request;
    let request_json = serde_json::to_vec(&request)?;
    let request_evidence = request.clone();
    let response = match backend.infer_structured(request).await {
        Ok(response) => response,
        Err(error) => {
            let evidence = json!({
                "schema_version": 1,
                "fixture_id": "literal-stream-v1",
                "generator": "birdcode-backends/lmstudio_codegen_calibration",
                "prompt_manifest_sha256": sha256(compiled.prompt_manifest.as_bytes()),
                "task_sha256": sha256(TASK.as_bytes()),
                "calibration_input": compiled.input_evidence,
                "request_sha256": sha256(&request_json),
                "request_timeout_ms": options.request_timeout.as_millis(),
                "request": request_evidence,
                "catalog": catalog,
                "outcome": {
                    "status": "backend_error",
                    "error": error
                }
            });
            let mut evidence_bytes = serde_json::to_vec_pretty(&evidence)?;
            evidence_bytes.push(b'\n');
            let ReservedOutputs {
                candidate,
                mut evidence,
            } = outputs;
            candidate.discard_empty()?;
            evidence.write_all_and_sync(&evidence_bytes)?;
            println!(
                "{}",
                json!({
                    "status": "backend_error",
                    "evidence_sha256": sha256(&evidence_bytes)
                })
            );
            return Err(error.into());
        }
    };
    let candidate_bytes = response.raw_text.as_bytes();
    outputs.candidate.write_all_and_sync(candidate_bytes)?;

    let evidence = json!({
        "schema_version": 1,
        "fixture_id": "literal-stream-v1",
        "generator": "birdcode-backends/lmstudio_codegen_calibration",
        "prompt_manifest_sha256": sha256(compiled.prompt_manifest.as_bytes()),
        "task_sha256": sha256(TASK.as_bytes()),
        "calibration_input": compiled.input_evidence,
        "request_sha256": sha256(&request_json),
        "request_timeout_ms": options.request_timeout.as_millis(),
        "candidate_sha256": sha256(candidate_bytes),
        "request": request_evidence,
        "catalog": catalog,
        "outcome": {
            "status": "response",
            "response": response
        },
        "output": {
            "candidate_path": options.candidate_path,
            "candidate_created_new": true
        }
    });
    let mut evidence_bytes = serde_json::to_vec_pretty(&evidence)?;
    evidence_bytes.push(b'\n');
    outputs.evidence.write_all_and_sync(&evidence_bytes)?;
    println!(
        "{}",
        json!({
            "status": "generated",
            "candidate_sha256": sha256(candidate_bytes),
            "evidence_sha256": sha256(&evidence_bytes)
        })
    );
    Ok(())
}

fn parse_options() -> Result<Option<Options>, Box<dyn Error>> {
    let mut base_url = Url::parse(
        &std::env::var("BIRDCODE_LMSTUDIO_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned()),
    )?;
    let mut model = None;
    let mut reasoning = ReasoningSetting::Off;
    let mut candidate_path = None;
    let mut evidence_path = None;
    let mut repair_from = None;
    let mut failure_report = None;
    let mut request_timeout = Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS);
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--url" => {
                base_url = Url::parse(&required_value(&mut arguments, "--url")?)?;
            }
            "--model" => model = Some(required_value(&mut arguments, "--model")?),
            "--reasoning" => {
                reasoning = parse_reasoning(&required_value(&mut arguments, "--reasoning")?)?;
            }
            "--candidate" => {
                candidate_path = Some(PathBuf::from(required_value(
                    &mut arguments,
                    "--candidate",
                )?));
            }
            "--evidence" => {
                evidence_path = Some(PathBuf::from(required_value(&mut arguments, "--evidence")?));
            }
            "--repair-from" => {
                repair_from = Some(PathBuf::from(required_value(
                    &mut arguments,
                    "--repair-from",
                )?));
            }
            "--failure-report" => {
                failure_report = Some(PathBuf::from(required_value(
                    &mut arguments,
                    "--failure-report",
                )?));
            }
            "--timeout-seconds" => {
                let value = required_value(&mut arguments, "--timeout-seconds")?;
                let seconds = value.parse::<u64>().map_err(|_| {
                    io::Error::other("--timeout-seconds must be an integer from 1 to 1800")
                })?;
                if !(1..=1_800).contains(&seconds) {
                    return Err(io::Error::other(
                        "--timeout-seconds must be an integer from 1 to 1800",
                    )
                    .into());
                }
                request_timeout = Duration::from_secs(seconds);
            }
            "--help" | "-h" => {
                println!(
                    "Usage: cargo run -p birdcode-backends --example \
                     lmstudio_codegen_calibration -- --model MODEL --candidate FILE \
                     --evidence FILE [--url URL] [--timeout-seconds N] \
                     [--reasoning off|on|low|medium|high] \
                     [--repair-from CANDIDATE --failure-report REPORT]"
                );
                return Ok(None);
            }
            unknown => return Err(io::Error::other(format!("unknown argument: {unknown}")).into()),
        }
    }

    if repair_from.is_some() != failure_report.is_some() {
        return Err(io::Error::other(
            "--repair-from and --failure-report must be supplied together",
        )
        .into());
    }

    Ok(Some(Options {
        base_url,
        model_id: ModelId::new(model.ok_or_else(|| io::Error::other("missing --model"))?)?,
        reasoning,
        candidate_path: candidate_path.ok_or_else(|| io::Error::other("missing --candidate"))?,
        evidence_path: evidence_path.ok_or_else(|| io::Error::other("missing --evidence"))?,
        request_timeout,
        repair_from,
        failure_report,
    }))
}

fn required_value(
    arguments: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, io::Error> {
    arguments
        .next()
        .ok_or_else(|| io::Error::other(format!("{flag} requires a value")))
}

fn parse_reasoning(value: &str) -> Result<ReasoningSetting, io::Error> {
    match value {
        "off" => Ok(ReasoningSetting::Off),
        "on" => Ok(ReasoningSetting::On),
        "low" => Ok(ReasoningSetting::Low),
        "medium" => Ok(ReasoningSetting::Medium),
        "high" => Ok(ReasoningSetting::High),
        _ => Err(io::Error::other(
            "--reasoning must be one of off, on, low, medium, or high",
        )),
    }
}

fn require_discovered_model(catalog: &ModelCatalog, model_id: &ModelId) -> io::Result<()> {
    if catalog.models.iter().any(|model| &model.id == model_id) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "requested model is not in the discovered catalog: {model_id}"
        )))
    }
}

fn calibration_request(
    model_id: ModelId,
    reasoning: ReasoningSetting,
    repair_from: Option<&Path>,
    failure_report: Option<&Path>,
) -> Result<CompiledCalibration, Box<dyn Error>> {
    let (prompt_manifest, input_evidence) = match (repair_from, failure_report) {
        (None, None) => (
            GENERATION_PROMPT,
            json!({
                "mode": "generation",
                "fixture_id": "literal-stream-v1",
                "task_sha256": sha256(TASK.as_bytes())
            }),
        ),
        (Some(candidate_path), Some(report_path)) => {
            let candidate_bytes = read_bounded(candidate_path, "repair candidate")?;
            let report_bytes = read_bounded(report_path, "failure report")?;
            let previous_candidate: Value = serde_json::from_slice(&candidate_bytes)?;
            let mechanical_report: Value = serde_json::from_slice(&report_bytes)?;
            (
                REPAIR_PROMPT,
                json!({
                    "mode": "repair",
                    "fixture_id": "literal-stream-v1",
                    "task_sha256": sha256(TASK.as_bytes()),
                    "previous_candidate_sha256": sha256(&candidate_bytes),
                    "mechanical_report_sha256": sha256(&report_bytes),
                    "previous_candidate": previous_candidate,
                    "mechanical_report": mechanical_report
                }),
            )
        }
        _ => {
            return Err(io::Error::other(
                "repair candidate and failure report must be supplied together",
            )
            .into());
        }
    };
    let prompt: Value = serde_json::from_str(prompt_manifest)?;
    let mut messages: Vec<Message> = serde_json::from_value(prompt["messages"].clone())?;
    let runtime_input = match repair_from {
        None => format!("The exact task follows. Implement every requirement.\n\n{TASK}"),
        Some(_) => serde_json::to_string(&json!({
            "fixture_id": "literal-stream-v1",
            "task": TASK,
            "repair_evidence": input_evidence
        }))?,
    };
    messages.push(Message::new(MessageRole::User, runtime_input));
    let output = StructuredOutputSpec::new_with_generation_schema(
        required_string(&prompt["output"]["name"], "output.name")?,
        prompt["output"]["schema"].clone(),
        prompt["generation_schema"].clone(),
    )?;
    let max_output_tokens = prompt["max_output_tokens"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| io::Error::other("prompt max_output_tokens is not a u32"))?;
    Ok(CompiledCalibration {
        request: StructuredInferenceRequest::new(model_id, messages, output, max_output_tokens)?
            .with_reasoning(reasoning),
        prompt_manifest,
        input_evidence,
    })
}

fn read_bounded(path: &Path, field: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_REPAIR_INPUT_BYTES {
        return Err(io::Error::other(format!(
            "{field} must contain 1..={MAX_REPAIR_INPUT_BYTES} bytes"
        ))
        .into());
    }
    Ok(fs::read(path)?)
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other(format!("prompt {field} is missing")).into())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{ReasoningSetting, ReservedOutputs, parse_reasoning, reserve_outputs};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(test_name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "birdcode-lmstudio-calibration-{test_name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique test directory is created");
        path
    }

    #[test]
    fn occupied_evidence_path_blocks_generation_and_cleans_candidate_reservation() {
        let directory = temporary_directory("occupied-evidence");
        let candidate = directory.join("candidate.json");
        let evidence = directory.join("evidence.json");
        fs::write(&evidence, b"keep exact existing evidence")
            .expect("occupied evidence fixture is written");

        let error = reserve_outputs(&candidate, &evidence)
            .err()
            .expect("occupied evidence path must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!candidate.exists());
        assert_eq!(
            fs::read(&evidence).expect("existing evidence remains readable"),
            b"keep exact existing evidence"
        );

        fs::remove_file(evidence).expect("fixture evidence is removed");
        fs::remove_dir(directory).expect("empty test directory is removed");
    }

    #[test]
    fn reservations_are_create_new_and_write_only_to_their_exact_paths() {
        let directory = temporary_directory("write-reservations");
        let candidate_path = directory.join("candidate.json");
        let evidence_path = directory.join("evidence.json");
        let ReservedOutputs {
            mut candidate,
            mut evidence,
        } = reserve_outputs(&candidate_path, &evidence_path).expect("outputs are reserved");

        candidate
            .write_all_and_sync(b"candidate")
            .expect("candidate reservation is finalized");
        evidence
            .write_all_and_sync(b"evidence")
            .expect("evidence reservation is finalized");
        drop(candidate);
        drop(evidence);
        assert_eq!(fs::read(&candidate_path).unwrap(), b"candidate");
        assert_eq!(fs::read(&evidence_path).unwrap(), b"evidence");
        assert!(reserve_outputs(&candidate_path, &evidence_path).is_err());

        fs::remove_file(candidate_path).expect("candidate fixture is removed");
        fs::remove_file(evidence_path).expect("evidence fixture is removed");
        fs::remove_dir(directory).expect("empty test directory is removed");
    }

    #[test]
    fn reasoning_mode_is_an_explicit_closed_cli_value() {
        assert_eq!(parse_reasoning("off").unwrap(), ReasoningSetting::Off);
        assert_eq!(parse_reasoning("on").unwrap(), ReasoningSetting::On);
        assert_eq!(parse_reasoning("low").unwrap(), ReasoningSetting::Low);
        assert_eq!(parse_reasoning("medium").unwrap(), ReasoningSetting::Medium);
        assert_eq!(parse_reasoning("high").unwrap(), ReasoningSetting::High);
        assert!(parse_reasoning("auto").is_err());
        assert!(parse_reasoning("ON").is_err());
    }
}
