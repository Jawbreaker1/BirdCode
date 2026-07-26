use birdcode_protocol::{
    RepositoryCommandArgumentV1, RepositoryMacOsDiskImageOperationV1, RuntimeClockReading,
    RuntimeInstanceId, WorkspacePath,
};
use chrono::Utc;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use thiserror::Error;

const HDIUTIL_PATH: &str = "/usr/bin/hdiutil";
const MAX_COMMAND_STREAM_BYTES: u64 = 4 * 1_024 * 1_024;

/// Closed, no-shell macOS command prepared by the workspace manager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMacOsCommand {
    operation: RepositoryMacOsDiskImageOperationV1,
    executable: PathBuf,
    native_argv: Vec<OsString>,
    protocol_argv: Vec<RepositoryCommandArgumentV1>,
}

/// Closed, no-shell command used only to observe the current disk-image
/// topology during restart recovery. It is deliberately a different type from
/// [`PreparedMacOsCommand`]: observing an indeterminate effect must never be
/// confused with authorization to repeat that effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMacOsRecoveryInspection {
    executable: PathBuf,
    native_argv: Vec<OsString>,
    protocol_argv: Vec<RepositoryCommandArgumentV1>,
}

impl PreparedMacOsRecoveryInspection {
    pub(crate) fn hdiutil_info() -> Self {
        Self {
            executable: PathBuf::from(HDIUTIL_PATH),
            native_argv: vec![OsString::from("info"), OsString::from("-plist")],
            protocol_argv: vec![
                RepositoryCommandArgumentV1::Literal {
                    value: "info".to_owned(),
                },
                RepositoryCommandArgumentV1::Literal {
                    value: "-plist".to_owned(),
                },
            ],
        }
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn native_argv(&self) -> &[OsString] {
        &self.native_argv
    }

    #[must_use]
    pub fn protocol_argv(&self) -> &[RepositoryCommandArgumentV1] {
        &self.protocol_argv
    }
}

impl PreparedMacOsCommand {
    pub(crate) fn hdiutil(
        operation: RepositoryMacOsDiskImageOperationV1,
        native_argv: Vec<OsString>,
        protocol_argv: Vec<RepositoryCommandArgumentV1>,
    ) -> Self {
        Self {
            operation,
            executable: PathBuf::from(HDIUTIL_PATH),
            native_argv,
            protocol_argv,
        }
    }

    #[must_use]
    pub const fn operation(&self) -> RepositoryMacOsDiskImageOperationV1 {
        self.operation
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn native_argv(&self) -> &[OsString] {
        &self.native_argv
    }

    #[must_use]
    pub fn protocol_argv(&self) -> &[RepositoryCommandArgumentV1] {
        &self.protocol_argv
    }

    pub(crate) fn executable_wire(&self) -> WorkspacePath {
        self.executable.clone().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawCommandOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandBoundaryErrorKind {
    NotStarted,
    OutcomeUnknown,
    TerminatedWithoutExitCode,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("macOS command boundary failed ({kind:?}, os error {raw_os_error:?})")]
pub struct CommandBoundaryError {
    pub kind: CommandBoundaryErrorKind,
    pub raw_os_error: Option<i32>,
}

/// Injectable external-command boundary. Implementations must execute exactly
/// the provided executable and argv without a shell.
pub trait CommandBoundary: Send + Sync {
    /// Executes one previously prepared command.
    ///
    /// # Errors
    ///
    /// Distinguishes a command known not to have started from an indeterminate
    /// effect boundary.
    fn run(&self, command: &PreparedMacOsCommand)
    -> Result<RawCommandOutput, CommandBoundaryError>;

    /// Executes the closed read-only topology inspection used by recovery.
    ///
    /// The default fails before starting so existing injected boundaries do
    /// not silently acquire a new external-command capability.
    ///
    /// # Errors
    ///
    /// Uses the same explicit start/outcome distinction as [`Self::run`].
    fn inspect_recovery(
        &self,
        _command: &PreparedMacOsRecoveryInspection,
    ) -> Result<RawCommandOutput, CommandBoundaryError> {
        Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandBoundary;

impl CommandBoundary for SystemCommandBoundary {
    fn run(
        &self,
        command: &PreparedMacOsCommand,
    ) -> Result<RawCommandOutput, CommandBoundaryError> {
        run_exact(command.executable(), command.native_argv())
    }

    fn inspect_recovery(
        &self,
        command: &PreparedMacOsRecoveryInspection,
    ) -> Result<RawCommandOutput, CommandBoundaryError> {
        run_exact(command.executable(), command.native_argv())
    }
}

fn run_exact(
    executable: &Path,
    native_argv: &[OsString],
) -> Result<RawCommandOutput, CommandBoundaryError> {
    let mut child = Command::new(executable)
        .args(native_argv)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CommandBoundaryError {
            kind: CommandBoundaryErrorKind::NotStarted,
            raw_os_error: error.raw_os_error(),
        })?;

    let stdout = child.stdout.take().ok_or(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::OutcomeUnknown,
        raw_os_error: None,
    })?;
    let stderr = child.stderr.take().ok_or(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::OutcomeUnknown,
        raw_os_error: None,
    })?;
    let stdout_reader = spawn_reader(stdout)?;
    let stderr_reader = spawn_reader(stderr)?;
    let status = child.wait().map_err(|error| CommandBoundaryError {
        kind: CommandBoundaryErrorKind::OutcomeUnknown,
        raw_os_error: error.raw_os_error(),
    })?;
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    let Some(exit_code) = status.code() else {
        return Err(CommandBoundaryError {
            kind: CommandBoundaryErrorKind::TerminatedWithoutExitCode,
            raw_os_error: None,
        });
    };
    Ok(RawCommandOutput {
        exit_code,
        stdout,
        stderr,
    })
}

fn spawn_reader<R>(
    mut reader: R,
) -> Result<std::thread::JoinHandle<std::io::Result<Vec<u8>>>, CommandBoundaryError>
where
    R: Read + Send + 'static,
{
    std::thread::Builder::new()
        .name("birdcode-workspace-command-output".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            reader
                .by_ref()
                .take(MAX_COMMAND_STREAM_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_COMMAND_STREAM_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bounded hdiutil output exceeded",
                ));
            }
            Ok(bytes)
        })
        .map_err(|error| CommandBoundaryError {
            kind: CommandBoundaryErrorKind::OutcomeUnknown,
            raw_os_error: error.raw_os_error(),
        })
}

fn join_reader(
    handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, CommandBoundaryError> {
    handle
        .join()
        .map_err(|_| CommandBoundaryError {
            kind: CommandBoundaryErrorKind::OutcomeUnknown,
            raw_os_error: None,
        })?
        .map_err(|error| CommandBoundaryError {
            kind: CommandBoundaryErrorKind::OutcomeUnknown,
            raw_os_error: error.raw_os_error(),
        })
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("clock boundary returned no observation")]
pub struct ClockBoundaryError;

pub trait ClockBoundary: Send + Sync {
    /// Observes wall and monotonic time in the caller-authorized runtime domain.
    ///
    /// # Errors
    ///
    /// Fails if the injected clock cannot return a reading.
    fn now(
        &self,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<RuntimeClockReading, ClockBoundaryError>;
}

#[derive(Debug)]
pub struct SystemClock {
    started: Instant,
}

impl SystemClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockBoundary for SystemClock {
    fn now(
        &self,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<RuntimeClockReading, ClockBoundaryError> {
        let elapsed = self.started.elapsed().as_nanos();
        Ok(RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos: u64::try_from(elapsed).unwrap_or(u64::MAX),
            observed_at: Utc::now(),
        })
    }
}
