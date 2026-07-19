use birdcode_backends::{LmStudioBackend, LmStudioConfig, ModelBackend, SecretToken};
use birdcode_daemon::{
    ParseOutcome, RunSupervisor, RunSupervisorConfig, parse, serve_with_supervisor,
};
use birdcode_runtime::{LocalRuntime, RuntimePaths};
use birdcode_store::Store;
use std::error::Error;
use std::io::{self, BufReader};
use std::sync::Arc;
use url::Url;

const DEFAULT_LMSTUDIO_URL: &str = "http://127.0.0.1:1234/";

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
            println!(
                "Usage: birdcode-daemon [--data-dir PATH] [--lmstudio-url URL]\n\
                 BIRDCODE_LMSTUDIO_URL and LM_STUDIO_API_TOKEN provide endpoint defaults."
            );
            return Ok(());
        }
        ParseOutcome::Run(options) => options,
    };

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
    let supervisor = RunSupervisor::start(paths, backend, RunSupervisorConfig::default())?;
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
