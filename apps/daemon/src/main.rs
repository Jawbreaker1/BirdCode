use birdcode_daemon::{ParseOutcome, parse, serve};
use birdcode_runtime::{LocalRuntime, RuntimePaths};
use birdcode_store::Store;
use std::error::Error;
use std::io::{self, BufReader};

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
            println!("Usage: birdcode-daemon [--data-dir PATH]");
            return Ok(());
        }
        ParseOutcome::Run(options) => options,
    };

    let paths = RuntimePaths::new(options.data_dir);
    paths.prepare()?;
    let store = Store::open(paths.database(), paths.artifacts())?;
    let mut runtime = LocalRuntime::new(store);
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve(&mut runtime, BufReader::new(stdin.lock()), stdout.lock())?;
    Ok(())
}
