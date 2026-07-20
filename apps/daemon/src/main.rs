use birdcode_backends::{LmStudioBackend, LmStudioConfig, ModelBackend, SecretToken};
use birdcode_daemon::model_policy::{ModelPolicyError, compile_root_planning_policy_json};
use birdcode_daemon::{
    HELP, ParseOutcome, RunSupervisor, RunSupervisorConfig, parse, serve_with_supervisor,
};
use birdcode_protocol::RootPlanningExecutionPolicy;
use birdcode_runtime::{LocalRuntime, RuntimePaths};
use birdcode_store::Store;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use url::Url;

const DEFAULT_LMSTUDIO_URL: &str = "http://127.0.0.1:1234/";
const MAX_MODEL_POLICY_BYTES: u64 = 64 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("birdcode-daemon: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1);
    let options = match parse(arguments)? {
        ParseOutcome::Help => {
            println!("{HELP}");
            return Ok(());
        }
        ParseOutcome::Run(options) => options,
    };

    let root_planning_policy = options
        .model_policy
        .as_deref()
        .map(load_model_policy)
        .transpose()?;
    let paths = RuntimePaths::new(options.data_dir);
    paths.prepare()?;
    let store = Store::open(paths.database(), paths.artifacts())?;
    let mut runtime = LocalRuntime::new(store);
    let endpoint = options
        .lmstudio_url
        .or_else(|| std::env::var("BIRDCODE_LMSTUDIO_URL").ok())
        .unwrap_or_else(|| DEFAULT_LMSTUDIO_URL.to_owned());
    let mut backend_config = LmStudioConfig::new(Url::parse(&endpoint)?);
    backend_config.api_token = std::env::var("LM_STUDIO_API_TOKEN")
        .ok()
        .map(SecretToken::new);
    let backend: Arc<dyn ModelBackend> = Arc::new(LmStudioBackend::new(backend_config)?);
    let supervisor_config = RunSupervisorConfig {
        root_planning_policy,
        ..RunSupervisorConfig::default()
    };
    let supervisor = RunSupervisor::start(paths, backend, supervisor_config)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let served = serve_with_supervisor(
        &mut runtime,
        &supervisor,
        BufReader::new(stdin.lock()),
        stdout.lock(),
    );
    let stopped = supervisor.shutdown();
    served?;
    stopped?;
    Ok(())
}

#[derive(Debug)]
enum ModelPolicyLoadError {
    Open {
        path: PathBuf,
        source: io::Error,
    },
    Read {
        path: PathBuf,
        source: io::Error,
    },
    TooLarge {
        path: PathBuf,
        maximum_bytes: u64,
    },
    Invalid {
        path: PathBuf,
        source: ModelPolicyError,
    },
}

impl fmt::Display for ModelPolicyLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "cannot open model policy {}: {source}",
                    path.display()
                )
            }
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "cannot read model policy {}: {source}",
                    path.display()
                )
            }
            Self::TooLarge {
                path,
                maximum_bytes,
            } => write!(
                formatter,
                "model policy {} exceeds the {maximum_bytes}-byte limit",
                path.display()
            ),
            Self::Invalid { path, source } => {
                write!(
                    formatter,
                    "invalid model policy {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for ModelPolicyLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Read { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
            Self::TooLarge { .. } => None,
        }
    }
}

fn load_model_policy(path: &Path) -> Result<RootPlanningExecutionPolicy, ModelPolicyLoadError> {
    let file = File::open(path).map_err(|source| ModelPolicyLoadError::Open {
        path: path.to_owned(),
        source,
    })?;
    let mut bounded = file.take(MAX_MODEL_POLICY_BYTES + 1);
    let mut bytes = Vec::new();
    bounded
        .read_to_end(&mut bytes)
        .map_err(|source| ModelPolicyLoadError::Read {
            path: path.to_owned(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MODEL_POLICY_BYTES {
        return Err(ModelPolicyLoadError::TooLarge {
            path: path.to_owned(),
            maximum_bytes: MAX_MODEL_POLICY_BYTES,
        });
    }
    compile_root_planning_policy_json(&bytes).map_err(|source| ModelPolicyLoadError::Invalid {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use birdcode_daemon::model_policy::{
        ROOT_PLANNING_MAX_MODEL_CALLS, ROOT_PLANNING_MAX_REPAIRS, ROOT_PLANNING_MAX_REVIEW_ROUNDS,
        ROOT_PLANNING_POLICY_SCHEMA_VERSION, TrustedRootPlanningPolicyConfig,
    };
    use birdcode_protocol::{ModelLineage, RootPlanningStageBudgets};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn valid_policy_json() -> Vec<u8> {
        let config = TrustedRootPlanningPolicyConfig {
            schema_version: ROOT_PLANNING_POLICY_SCHEMA_VERSION,
            producer: ModelLineage {
                backend_id: "lmstudio".to_owned(),
                model_id: "producer-model".to_owned(),
                deployment_id: "producer-deployment".to_owned(),
                independence_domain_id: "producer-domain".to_owned(),
            },
            critic: ModelLineage {
                backend_id: "lmstudio".to_owned(),
                model_id: "critic-model".to_owned(),
                deployment_id: "critic-deployment".to_owned(),
                independence_domain_id: "critic-domain".to_owned(),
            },
            max_model_calls: ROOT_PLANNING_MAX_MODEL_CALLS,
            max_repairs: ROOT_PLANNING_MAX_REPAIRS,
            max_review_rounds: ROOT_PLANNING_MAX_REVIEW_ROUNDS,
            stage_budgets: RootPlanningStageBudgets {
                initial_plan_output_tokens: 4_096,
                initial_review_output_tokens: 2_048,
                repair_output_tokens: 4_096,
                final_review_output_tokens: 2_048,
            },
        };
        serde_json::to_vec(&config).expect("test policy should serialize")
    }

    #[test]
    fn loads_and_compiles_an_explicit_policy_file() {
        let mut file = NamedTempFile::new().expect("temporary policy should open");
        file.write_all(&valid_policy_json())
            .expect("test policy should write");

        let policy = load_model_policy(file.path()).expect("valid policy should compile");

        assert_eq!(policy.producer.model_id, "producer-model");
        assert_eq!(policy.critic.model_id, "critic-model");
    }

    #[test]
    fn rejects_policy_files_above_the_fixed_input_bound() {
        let mut file = NamedTempFile::new().expect("temporary policy should open");
        let oversized = vec![b' '; usize::try_from(MAX_MODEL_POLICY_BYTES + 1).unwrap()];
        file.write_all(&oversized)
            .expect("oversized test policy should write");

        assert!(matches!(
            load_model_policy(file.path()),
            Err(ModelPolicyLoadError::TooLarge {
                maximum_bytes: MAX_MODEL_POLICY_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn reports_invalid_policy_with_the_source_path() {
        let mut file = NamedTempFile::new().expect("temporary policy should open");
        file.write_all(br#"{"schema_version":1}"#)
            .expect("invalid test policy should write");

        let error = load_model_policy(file.path()).expect_err("invalid policy must fail");

        assert!(
            error
                .to_string()
                .contains(&file.path().display().to_string())
        );
        assert!(matches!(error, ModelPolicyLoadError::Invalid { .. }));
    }
}
