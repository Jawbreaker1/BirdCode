mod args;

use args::{Command, Options};
use birdcode_client::{DaemonClient, resolve_daemon_path};
use birdcode_protocol::{ClientCommand, CreateSessionRequest, HealthStatus, ServerResult};
use std::error::Error;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("birdcode: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let options = args::parse(std::env::args_os().skip(1))?;
    if options.command == Command::Help {
        print_help();
        return Ok(());
    }

    let daemon = daemon_path(&options)?;
    let data_dir = data_dir(&options)?;
    let mut client = DaemonClient::spawn(&daemon, &data_dir)?;
    let initialized = client.initialize("birdcode-cli", env!("CARGO_PKG_VERSION"))?;

    match options.command {
        Command::Doctor => {
            let health = client.health()?;
            if health.status != HealthStatus::Ready {
                return Err("daemon reports degraded local storage".into());
            }
            println!(
                "BirdCode daemon {} is ready (protocol {}, {}/{})",
                initialized.server.version,
                initialized.protocol_version,
                health.platform,
                health.architecture
            );
        }
        Command::SessionSmoke => {
            let workspace_root = std::env::current_dir()?;
            let result = client.call(ClientCommand::CreateSession(CreateSessionRequest {
                workspace_root: workspace_root.into(),
                title: Some("BirdCode CLI smoke – svenska / 日本語".to_owned()),
            }))?;
            let ServerResult::Session(created) = result else {
                return Err("daemon returned the wrong result for create_session".into());
            };
            let result = client.call(ClientCommand::GetSession {
                session_id: created.id,
            })?;
            let ServerResult::Session(loaded) = result else {
                return Err("daemon returned the wrong result for get_session".into());
            };
            if loaded != created {
                return Err("reloaded session differs from the created session".into());
            }
            println!("Session {} persisted and reloaded successfully", loaded.id);
        }
        Command::Help => unreachable!("help returns before starting the daemon"),
    }
    Ok(())
}

fn daemon_path(options: &Options) -> Result<std::path::PathBuf, Box<dyn Error>> {
    Ok(resolve_daemon_path(options.daemon.as_deref())?)
}

fn data_dir(options: &Options) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = &options.data_dir {
        return Ok(path.clone());
    }
    if let Some(path) = std::env::var_os("BIRDCODE_DATA_DIR") {
        return Ok(path.into());
    }
    Ok(std::env::current_dir()?.join(".birdcode"))
}

fn print_help() {
    println!(
        "BirdCode CLI\n\n\
         Usage:\n  \
         birdcode doctor [--daemon PATH] [--data-dir PATH]\n  \
         birdcode session-smoke [--daemon PATH] [--data-dir PATH]\n\n\
         BIRDCODE_DAEMON and BIRDCODE_DATA_DIR provide equivalent defaults."
    );
}
