//! Shared stdio transport for `BirdCode` daemon clients.

use birdcode_protocol::{
    ArtifactChunk, ArtifactReadContractError, ArtifactRef, BackendCatalog, CancellationReceipt,
    ClientCommand, ClientIdentity, ClientRequest, CreateRunRequest, ErrorCode, EventPage,
    GetArtifactRequest, Health, InitializeRequest, InitializeResult, PROTOCOL_VERSION,
    ResponseOutcome, Run, RunId, ServerResponse, ServerResult, SessionId,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The daemon's current maximum incoming JSON-lines frame size.
pub const DAEMON_REQUEST_FRAME_BYTES: usize = 1024 * 1024;
/// The client allows response-envelope headroom beyond the largest request.
pub const MAX_RESPONSE_FRAME_BYTES: usize = 2 * 1024 * 1024;
const _: () = assert!(MAX_RESPONSE_FRAME_BYTES > DAEMON_REQUEST_FRAME_BYTES);
pub const DAEMON_BINARY_NAME: &str = "birdcode-daemon";
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for daemon initialization, including durable-store migrations.
///
/// Startup deliberately has a much larger budget than an ordinary RPC. The
/// bound still guarantees that a stalled child is terminated instead of
/// hanging a CLI or desktop process forever.
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Compatibility name for the deadline that now covers the complete request.
pub const DEFAULT_RESPONSE_TIMEOUT: Duration = DEFAULT_REQUEST_TIMEOUT;
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_millis(100);
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug)]
pub enum ClientError {
    CurrentExecutable(io::Error),
    Spawn {
        executable: PathBuf,
        source: io::Error,
    },
    MissingPipe(&'static str),
    Io(io::Error),
    Encode(serde_json::Error),
    Decode(serde_json::Error),
    Ended,
    RequestTooLarge,
    ResponseTooLarge,
    ResponseTimeout(Duration),
    StartupTimeout(Duration),
    ResponseIdMismatch,
    RunIdentityMismatch {
        expected: RunId,
        actual: RunId,
    },
    RunSpecificationMismatch {
        run_id: RunId,
    },
    ReconnectBeforeInitialize,
    NegotiatedProtocolMismatch {
        expected: u32,
        actual: u32,
    },
    WriterThread(io::Error),
    ReaderThread(io::Error),
    Rejected {
        code: ErrorCode,
        retryable: bool,
        message: String,
    },
    UnexpectedResult {
        expected: &'static str,
        actual: &'static str,
    },
    InvalidArtifactRequest(ArtifactReadContractError),
    ArtifactReferenceMismatch,
    ArtifactOffsetMismatch {
        expected: u64,
        actual: u64,
    },
    ArtifactChunkExceedsRequest {
        requested: u32,
        actual: usize,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentExecutable(error) => {
                write!(
                    formatter,
                    "could not locate the current executable: {error}"
                )
            }
            Self::Spawn { executable, source } => {
                write!(
                    formatter,
                    "could not start daemon at {}: {source}",
                    executable.display()
                )
            }
            Self::MissingPipe(pipe) => write!(formatter, "daemon {pipe} pipe was unavailable"),
            Self::Io(error) => write!(formatter, "daemon transport failed: {error}"),
            Self::Encode(error) => write!(formatter, "could not encode daemon request: {error}"),
            Self::Decode(error) => write!(formatter, "could not decode daemon response: {error}"),
            Self::Ended => formatter.write_str("daemon ended before sending a response"),
            Self::RequestTooLarge => formatter.write_str("daemon request exceeded 1 MiB"),
            Self::ResponseTooLarge => formatter.write_str("daemon response exceeded 2 MiB"),
            Self::ResponseTimeout(timeout) => {
                write!(
                    formatter,
                    "daemon request did not complete within {timeout:?}"
                )
            }
            Self::StartupTimeout(timeout) => write!(
                formatter,
                "daemon startup did not complete within {timeout:?}; the process was terminated"
            ),
            Self::ResponseIdMismatch => {
                formatter.write_str("daemon response id did not match the request id")
            }
            Self::RunIdentityMismatch { expected, actual } => write!(
                formatter,
                "daemon returned run {actual} for requested run {expected}"
            ),
            Self::RunSpecificationMismatch { run_id } => write!(
                formatter,
                "daemon returned a different specification for requested run {run_id}"
            ),
            Self::ReconnectBeforeInitialize => formatter.write_str(
                "daemon connection cannot be reconciled before successful initialization",
            ),
            Self::NegotiatedProtocolMismatch { expected, actual } => write!(
                formatter,
                "daemon reported protocol version {actual}, but the client requires {expected}"
            ),
            Self::ReaderThread(error) => {
                write!(formatter, "could not start daemon response reader: {error}")
            }
            Self::WriterThread(error) => {
                write!(formatter, "could not start daemon request writer: {error}")
            }
            Self::Rejected {
                code,
                retryable,
                message,
            } => write!(
                formatter,
                "daemon rejected request ({code:?}, retryable={retryable}): {message}"
            ),
            Self::UnexpectedResult { expected, actual } => write!(
                formatter,
                "daemon returned {actual} when {expected} was expected"
            ),
            Self::InvalidArtifactRequest(error) => {
                write!(formatter, "invalid artifact read request: {error}")
            }
            Self::ArtifactReferenceMismatch => formatter
                .write_str("daemon returned an artifact chunk for a different artifact reference"),
            Self::ArtifactOffsetMismatch { expected, actual } => write!(
                formatter,
                "daemon returned artifact offset {actual}; expected {expected}"
            ),
            Self::ArtifactChunkExceedsRequest { requested, actual } => write!(
                formatter,
                "daemon returned {actual} artifact bytes; request allowed {requested}"
            ),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CurrentExecutable(error)
            | Self::Spawn { source: error, .. }
            | Self::Io(error)
            | Self::WriterThread(error)
            | Self::ReaderThread(error) => Some(error),
            Self::Encode(error) | Self::Decode(error) => Some(error),
            Self::InvalidArtifactRequest(error) => Some(error),
            Self::MissingPipe(_)
            | Self::Ended
            | Self::RequestTooLarge
            | Self::ResponseTooLarge
            | Self::ResponseTimeout(_)
            | Self::StartupTimeout(_)
            | Self::ResponseIdMismatch
            | Self::RunIdentityMismatch { .. }
            | Self::RunSpecificationMismatch { .. }
            | Self::ReconnectBeforeInitialize
            | Self::NegotiatedProtocolMismatch { .. }
            | Self::Rejected { .. }
            | Self::UnexpectedResult { .. }
            | Self::ArtifactReferenceMismatch
            | Self::ArtifactOffsetMismatch { .. }
            | Self::ArtifactChunkExceedsRequest { .. } => None,
        }
    }
}

/// A client-identified run whose submission may have executed, but whose
/// exact result could not be established after one bounded reconnect/replay.
///
/// The request is intentionally retained as one indivisible value so callers
/// cannot accidentally reconcile a new id or a modified specification.
#[derive(Debug)]
pub struct PendingCreateRun {
    request: Box<CreateRunRequest>,
    last_error: Box<ClientError>,
}

impl PendingCreateRun {
    /// Returns the stable idempotency identity that must be reconciled.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.request.run_id
    }

    /// Returns the exact request retained for reconciliation.
    #[must_use]
    pub fn request(&self) -> &CreateRunRequest {
        self.request.as_ref()
    }

    /// Returns the most recent failure that left the result ambiguous.
    #[must_use]
    pub fn last_error(&self) -> &ClientError {
        self.last_error.as_ref()
    }
}

/// Exact failure classification for a client-identified `CreateRun` action.
#[derive(Debug)]
pub enum CreateRunFailure {
    /// No `CreateRun` frame in the action can have reached the daemon.
    NotSubmitted {
        request: Box<CreateRunRequest>,
        source: Box<ClientError>,
    },
    /// The daemon returned an authoritative protocol rejection.
    Rejected {
        request: Box<CreateRunRequest>,
        source: Box<ClientError>,
    },
    /// The stable request remains pending after bounded reconciliation.
    ReconciliationRequired(PendingCreateRun),
}

impl CreateRunFailure {
    /// Returns the stable run id associated with every failure class.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        match self {
            Self::NotSubmitted { request, .. } | Self::Rejected { request, .. } => request.run_id,
            Self::ReconciliationRequired(pending) => pending.run_id(),
        }
    }

    /// Returns the unchanged request associated with this failure.
    #[must_use]
    pub fn request(&self) -> &CreateRunRequest {
        match self {
            Self::NotSubmitted { request, .. } | Self::Rejected { request, .. } => request.as_ref(),
            Self::ReconciliationRequired(pending) => pending.request(),
        }
    }
}

impl fmt::Display for CreateRunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSubmitted { request, source } => write!(
                formatter,
                "run {} was definitely not submitted: {source}",
                request.run_id
            ),
            Self::Rejected { request, source } => {
                write!(formatter, "run {} was rejected: {source}", request.run_id)
            }
            Self::ReconciliationRequired(pending) => write!(
                formatter,
                "run {} may have been created and requires exact reconciliation: {}",
                pending.run_id(),
                pending.last_error()
            ),
        }
    }
}

impl std::error::Error for CreateRunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotSubmitted { source, .. } | Self::Rejected { source, .. } => {
                Some(source.as_ref())
            }
            Self::ReconciliationRequired(pending) => Some(pending.last_error()),
        }
    }
}

/// Resolves the daemon executable using an explicit path, the environment,
/// or a sibling of the current client executable, in that order.
///
/// # Errors
///
/// Returns an error when the current executable cannot be resolved and neither
/// an explicit path nor `BIRDCODE_DAEMON` was supplied.
pub fn resolve_daemon_path(explicit: Option<&Path>) -> Result<PathBuf, ClientError> {
    if let Some(path) = explicit {
        return Ok(path.to_owned());
    }
    if let Some(path) = std::env::var_os("BIRDCODE_DAEMON") {
        return Ok(path.into());
    }
    let executable = std::env::current_exe().map_err(ClientError::CurrentExecutable)?;
    Ok(sibling_daemon_path(&executable))
}

#[must_use]
pub fn sibling_daemon_path(client_executable: &Path) -> PathBuf {
    client_executable.with_file_name(format!(
        "{DAEMON_BINARY_NAME}{}",
        std::env::consts::EXE_SUFFIX
    ))
}

type ResponseReceiver = Receiver<Result<Vec<u8>, ResponseReadError>>;

/// Independent deadlines for daemon initialization and steady-state RPCs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientTimeouts {
    pub request: Duration,
    pub startup: Duration,
}

impl ClientTimeouts {
    #[must_use]
    pub const fn new(request: Duration, startup: Duration) -> Self {
        Self { request, startup }
    }
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self::new(DEFAULT_REQUEST_TIMEOUT, DEFAULT_STARTUP_TIMEOUT)
    }
}

/// Explicit process-level configuration passed to the local daemon.
///
/// Reviewer lineage is never inferred by the client. A planning policy is
/// enabled only when its exact file path is supplied by the caller.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaemonLaunchOptions {
    pub model_policy: Option<PathBuf>,
}

#[derive(Clone, Copy)]
enum RequestPhase {
    Startup,
    SteadyState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestProgress {
    NotSubmitted,
    MayHaveExecuted,
}

#[derive(Debug)]
enum CallFailure {
    Request {
        progress: RequestProgress,
        error: ClientError,
    },
    Rejected(ClientError),
}

impl CallFailure {
    fn into_client_error(self) -> ClientError {
        match self {
            Self::Request { error, .. } | Self::Rejected(error) => error,
        }
    }
}

#[derive(Debug)]
enum CreateRunAttemptFailure {
    NotSubmitted(ClientError),
    Rejected(ClientError),
    MayHaveExecuted(ClientError),
}

impl RequestPhase {
    const fn timeout_error(self, timeout: Duration) -> ClientError {
        match self {
            Self::Startup => ClientError::StartupTimeout(timeout),
            Self::SteadyState => ClientError::ResponseTimeout(timeout),
        }
    }
}

pub struct DaemonClient {
    child: Child,
    write_requests: Option<Sender<WriteRequest>>,
    writer_thread: Option<JoinHandle<()>>,
    responses: Option<ResponseReceiver>,
    reader_thread: Option<JoinHandle<()>>,
    request_timeout: Duration,
    startup_timeout: Duration,
    executable: PathBuf,
    data_dir: PathBuf,
    launch_options: DaemonLaunchOptions,
    initialized_client: Option<ClientIdentity>,
}

fn daemon_command(
    executable: &Path,
    data_dir: &Path,
    launch_options: &DaemonLaunchOptions,
) -> Command {
    let mut command = Command::new(executable);
    command.arg("--data-dir").arg(data_dir);
    if let Some(model_policy) = &launch_options.model_policy {
        command.arg("--model-policy").arg(model_policy);
    }
    command
}

impl DaemonClient {
    /// Starts one daemon process connected over newline-delimited JSON on stdio.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon cannot be started or its stdio pipes
    /// cannot be acquired.
    pub fn spawn(executable: &Path, data_dir: &Path) -> Result<Self, ClientError> {
        Self::spawn_with_timeouts(executable, data_dir, ClientTimeouts::default())
    }

    /// Starts one daemon with explicit process-level launch configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon cannot be started or its stdio pipes
    /// cannot be acquired.
    pub fn spawn_with_launch_options(
        executable: &Path,
        data_dir: &Path,
        launch_options: DaemonLaunchOptions,
    ) -> Result<Self, ClientError> {
        Self::spawn_with_launch_options_and_timeouts(
            executable,
            data_dir,
            launch_options,
            ClientTimeouts::default(),
        )
    }

    /// Starts a daemon with an explicit deadline for each complete request,
    /// including both request writing and ordered response reading.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon or its response-reader thread cannot be
    /// started, or if the daemon's stdio pipes cannot be acquired.
    pub fn spawn_with_timeout(
        executable: &Path,
        data_dir: &Path,
        request_timeout: Duration,
    ) -> Result<Self, ClientError> {
        Self::spawn_with_timeouts(
            executable,
            data_dir,
            ClientTimeouts::new(request_timeout, request_timeout),
        )
    }

    /// Starts a daemon with independent initialization and steady-state RPC
    /// deadlines.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon or its transport threads cannot be
    /// started, or if the daemon's stdio pipes cannot be acquired.
    pub fn spawn_with_timeouts(
        executable: &Path,
        data_dir: &Path,
        timeouts: ClientTimeouts,
    ) -> Result<Self, ClientError> {
        Self::spawn_with_launch_options_and_timeouts(
            executable,
            data_dir,
            DaemonLaunchOptions::default(),
            timeouts,
        )
    }

    /// Starts a daemon with explicit launch configuration and independent
    /// initialization and steady-state RPC deadlines.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon or its transport threads cannot be
    /// started, or if the daemon's stdio pipes cannot be acquired.
    pub fn spawn_with_launch_options_and_timeouts(
        executable: &Path,
        data_dir: &Path,
        launch_options: DaemonLaunchOptions,
        timeouts: ClientTimeouts,
    ) -> Result<Self, ClientError> {
        let mut child = daemon_command(executable, data_dir, &launch_options)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|source| ClientError::Spawn {
                executable: executable.to_owned(),
                source,
            })?;
        let input = child
            .stdin
            .take()
            .ok_or(ClientError::MissingPipe("stdin"))?;
        let output = child
            .stdout
            .take()
            .ok_or(ClientError::MissingPipe("stdout"))?;
        let (write_requests, writer_thread) = match start_request_writer(input) {
            Ok(writer) => writer,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let (responses, reader_thread) = match start_response_reader(output) {
            Ok(reader) => reader,
            Err(error) => {
                drop(write_requests);
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer_thread.join();
                return Err(error);
            }
        };

        Ok(Self {
            child,
            write_requests: Some(write_requests),
            writer_thread: Some(writer_thread),
            responses: Some(responses),
            reader_thread: Some(reader_thread),
            request_timeout: timeouts.request,
            startup_timeout: timeouts.startup,
            executable: executable.to_owned(),
            data_dir: data_dir.to_owned(),
            launch_options,
            initialized_client: None,
        })
    }

    /// Changes the deadline applied to subsequent complete requests.
    pub const fn set_request_timeout(&mut self, request_timeout: Duration) {
        self.request_timeout = request_timeout;
    }

    /// Changes the deadline used only while negotiating initialization.
    pub const fn set_startup_timeout(&mut self, startup_timeout: Duration) {
        self.startup_timeout = startup_timeout;
    }

    /// Compatibility alias for [`Self::set_request_timeout`].
    pub const fn set_response_timeout(&mut self, response_timeout: Duration) {
        self.set_request_timeout(response_timeout);
    }

    /// Sends one raw JSON-lines request and decodes one ordered response.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, framing, size, or JSON failures.
    pub fn request<Request, Response>(&mut self, request: &Request) -> Result<Response, ClientError>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        self.request_with_phase(request, RequestPhase::SteadyState)
    }

    fn request_with_phase<Request, Response>(
        &mut self,
        request: &Request,
        phase: RequestPhase,
    ) -> Result<Response, ClientError>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        self.request_with_progress(request, phase)
            .map_err(CallFailure::into_client_error)
    }

    fn request_with_progress<Request, Response>(
        &mut self,
        request: &Request,
        phase: RequestPhase,
    ) -> Result<Response, CallFailure>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        let frame = encode_request(request).map_err(|error| CallFailure::Request {
            progress: RequestProgress::NotSubmitted,
            error,
        })?;
        let timeout = match phase {
            RequestPhase::Startup => self.startup_timeout,
            RequestPhase::SteadyState => self.request_timeout,
        };
        let started = Instant::now();
        let (completion_sender, completion_receiver) = mpsc::sync_channel(1);
        let write_request = WriteRequest {
            frame,
            completion: completion_sender,
        };
        let Some(writer) = self.write_requests.as_ref() else {
            return Err(CallFailure::Request {
                progress: RequestProgress::NotSubmitted,
                error: ClientError::MissingPipe("stdin"),
            });
        };
        if writer.send(write_request).is_err() {
            self.terminate_now();
            return Err(CallFailure::Request {
                progress: RequestProgress::NotSubmitted,
                error: ClientError::Ended,
            });
        }
        match completion_receiver.recv_timeout(remaining_timeout(started, timeout)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.terminate_now();
                return Err(CallFailure::Request {
                    progress: RequestProgress::MayHaveExecuted,
                    error: ClientError::Io(error),
                });
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.terminate_now();
                return Err(CallFailure::Request {
                    progress: RequestProgress::MayHaveExecuted,
                    error: ClientError::Ended,
                });
            }
            Err(RecvTimeoutError::Timeout) => {
                self.terminate_now();
                return Err(CallFailure::Request {
                    progress: RequestProgress::MayHaveExecuted,
                    error: phase.timeout_error(timeout),
                });
            }
        }

        let Some(responses) = self.responses.as_ref() else {
            return Err(CallFailure::Request {
                progress: RequestProgress::MayHaveExecuted,
                error: ClientError::MissingPipe("stdout"),
            });
        };
        let response = match responses.recv_timeout(remaining_timeout(started, timeout)) {
            Ok(Ok(frame)) => frame,
            Ok(Err(ResponseReadError::TooLarge)) => {
                return Err(CallFailure::Request {
                    progress: RequestProgress::MayHaveExecuted,
                    error: ClientError::ResponseTooLarge,
                });
            }
            Ok(Err(ResponseReadError::Io(error))) => {
                self.terminate_now();
                return Err(CallFailure::Request {
                    progress: RequestProgress::MayHaveExecuted,
                    error: ClientError::Io(error),
                });
            }
            Ok(Err(ResponseReadError::Ended)) | Err(RecvTimeoutError::Disconnected) => {
                self.terminate_now();
                return Err(CallFailure::Request {
                    progress: RequestProgress::MayHaveExecuted,
                    error: ClientError::Ended,
                });
            }
            Err(RecvTimeoutError::Timeout) => {
                self.terminate_now();
                return Err(CallFailure::Request {
                    progress: RequestProgress::MayHaveExecuted,
                    error: phase.timeout_error(timeout),
                });
            }
        };
        serde_json::from_slice(&response).map_err(|error| CallFailure::Request {
            progress: RequestProgress::MayHaveExecuted,
            error: ClientError::Decode(error),
        })
    }

    /// Performs one typed protocol call and validates response correlation.
    ///
    /// # Errors
    ///
    /// Returns transport failures, rejected protocol responses, and response-id
    /// mismatches as typed client errors.
    pub fn call(&mut self, command: ClientCommand) -> Result<ServerResult, ClientError> {
        self.call_with_phase(command, RequestPhase::SteadyState)
    }

    fn call_with_phase(
        &mut self,
        command: ClientCommand,
        phase: RequestPhase,
    ) -> Result<ServerResult, ClientError> {
        self.call_with_progress(command, phase)
            .map_err(CallFailure::into_client_error)
    }

    fn call_with_progress(
        &mut self,
        command: ClientCommand,
        phase: RequestPhase,
    ) -> Result<ServerResult, CallFailure> {
        let request = ClientRequest::new(command);
        let request_id = request.id;
        let response: ServerResponse = self.request_with_progress(&request, phase)?;
        if response.request_id != request_id {
            return Err(CallFailure::Request {
                progress: RequestProgress::MayHaveExecuted,
                error: ClientError::ResponseIdMismatch,
            });
        }
        match response.outcome {
            ResponseOutcome::Success { result } => Ok(result),
            ResponseOutcome::Error { error } => Err(CallFailure::Rejected(ClientError::Rejected {
                code: error.code,
                retryable: error.retryable,
                message: error.message,
            })),
        }
    }

    /// Negotiates the canonical protocol version for a named client.
    ///
    /// # Errors
    ///
    /// Returns transport and protocol errors, or an unexpected-result error if
    /// the daemon violates the initialize contract.
    pub fn initialize(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<InitializeResult, ClientError> {
        let identity = ClientIdentity {
            name: name.into(),
            version: version.into(),
        };
        let result = self.call_with_phase(
            ClientCommand::Initialize(InitializeRequest {
                protocol_version: PROTOCOL_VERSION,
                client: identity.clone(),
            }),
            RequestPhase::Startup,
        )?;
        match result {
            ServerResult::Initialized(initialized) => {
                ensure_protocol_version(initialized.protocol_version)?;
                self.initialized_client = Some(identity);
                Ok(initialized)
            }
            other => Err(ClientError::UnexpectedResult {
                expected: "initialized",
                actual: result_name(&other),
            }),
        }
    }

    /// Fetches runtime health after successful initialization.
    ///
    /// # Errors
    ///
    /// Returns transport and protocol errors, or an unexpected-result error if
    /// the daemon violates the health contract.
    pub fn health(&mut self) -> Result<Health, ClientError> {
        let result = self.call(ClientCommand::Health)?;
        match result {
            ServerResult::Health(health) => {
                ensure_protocol_version(health.protocol_version)?;
                Ok(health)
            }
            other => Err(ClientError::UnexpectedResult {
                expected: "health",
                actual: result_name(&other),
            }),
        }
    }

    /// Discovers configured local models without granting them runtime access.
    ///
    /// # Errors
    ///
    /// Returns transport or protocol errors, including an unexpected result
    /// when the daemon violates the command contract.
    pub fn discover_models(&mut self) -> Result<BackendCatalog, ClientError> {
        match self.call(ClientCommand::DiscoverModels)? {
            ServerResult::BackendCatalog(catalog) => Ok(catalog),
            other => Err(ClientError::UnexpectedResult {
                expected: "backend_catalog",
                actual: result_name(&other),
            }),
        }
    }

    /// Creates one client-identified run with one bounded recovery attempt.
    ///
    /// When the first submission is not known to have been rejected, this
    /// method reconnects once and replays the identical request once. It never
    /// retries any preceding command, including `CreateSession`.
    ///
    /// # Errors
    ///
    /// Returns an exact failure class. An ambiguous result always retains the
    /// original run id and specification in [`PendingCreateRun`].
    pub fn create_run(&mut self, request: &CreateRunRequest) -> Result<Run, CreateRunFailure> {
        let first_progress = match self.create_run_once(request) {
            Ok(run) => return Ok(run),
            Err(CreateRunAttemptFailure::Rejected(source)) => {
                return Err(CreateRunFailure::Rejected {
                    request: Box::new(request.clone()),
                    source: Box::new(source),
                });
            }
            Err(CreateRunAttemptFailure::NotSubmitted(_)) => RequestProgress::NotSubmitted,
            Err(CreateRunAttemptFailure::MayHaveExecuted(_)) => RequestProgress::MayHaveExecuted,
        };

        if let Err(source) = self.reconnect_initialized() {
            return Err(create_run_recovery_failure(
                request.clone(),
                first_progress,
                source,
            ));
        }

        match self.create_run_once(request) {
            Ok(run) => Ok(run),
            Err(CreateRunAttemptFailure::Rejected(source)) => Err(CreateRunFailure::Rejected {
                request: Box::new(request.clone()),
                source: Box::new(source),
            }),
            Err(CreateRunAttemptFailure::NotSubmitted(source)) => Err(create_run_recovery_failure(
                request.clone(),
                first_progress,
                source,
            )),
            Err(CreateRunAttemptFailure::MayHaveExecuted(source)) => {
                Err(CreateRunFailure::ReconciliationRequired(PendingCreateRun {
                    request: Box::new(request.clone()),
                    last_error: Box::new(source),
                }))
            }
        }
    }

    /// Reconciles one previously ambiguous run using exactly one reconnect and
    /// one replay of the retained request.
    ///
    /// # Errors
    ///
    /// Returns a definitive rejection, or returns the same stable request as a
    /// pending reconciliation when the result remains ambiguous.
    pub fn reconcile_create_run(
        &mut self,
        pending: PendingCreateRun,
    ) -> Result<Run, CreateRunFailure> {
        let request = *pending.request;
        if let Err(last_error) = self.reconnect_initialized() {
            return Err(CreateRunFailure::ReconciliationRequired(PendingCreateRun {
                request: Box::new(request),
                last_error: Box::new(last_error),
            }));
        }
        match self.create_run_once(&request) {
            Ok(run) => Ok(run),
            Err(CreateRunAttemptFailure::Rejected(source)) => Err(CreateRunFailure::Rejected {
                request: Box::new(request),
                source: Box::new(source),
            }),
            Err(
                CreateRunAttemptFailure::NotSubmitted(last_error)
                | CreateRunAttemptFailure::MayHaveExecuted(last_error),
            ) => Err(CreateRunFailure::ReconciliationRequired(PendingCreateRun {
                request: Box::new(request),
                last_error: Box::new(last_error),
            })),
        }
    }

    /// Reads current materialized run state.
    ///
    /// # Errors
    ///
    /// Returns transport, protocol, or not-found errors.
    pub fn get_run(&mut self, run_id: RunId) -> Result<Run, ClientError> {
        match self.call(ClientCommand::GetRun { run_id })? {
            ServerResult::Run(run) if run.id == run_id => Ok(run),
            ServerResult::Run(run) => Err(ClientError::RunIdentityMismatch {
                expected: run_id,
                actual: run.id,
            }),
            other => Err(ClientError::UnexpectedResult {
                expected: "run",
                actual: result_name(&other),
            }),
        }
    }

    /// Reads one bounded replay page after an authoritative sequence cursor.
    ///
    /// # Errors
    ///
    /// Returns transport, protocol, or not-found errors.
    pub fn get_events(
        &mut self,
        session_id: SessionId,
        after_sequence: u64,
    ) -> Result<EventPage, ClientError> {
        match self.call(ClientCommand::GetEvents {
            session_id,
            after_sequence,
        })? {
            ServerResult::EventPage(page) => Ok(page),
            other => Err(ClientError::UnexpectedResult {
                expected: "event_page",
                actual: result_name(&other),
            }),
        }
    }

    /// Durably requests cancellation of one run.
    ///
    /// # Errors
    ///
    /// Returns transport, protocol, or not-found errors.
    pub fn cancel_run(&mut self, run_id: RunId) -> Result<CancellationReceipt, ClientError> {
        match self.call(ClientCommand::CancelRun { run_id })? {
            ServerResult::CancellationReceipt(receipt) => Ok(receipt),
            other => Err(ClientError::UnexpectedResult {
                expected: "cancellation_receipt",
                actual: result_name(&other),
            }),
        }
    }

    /// Reads one bounded page from an exact content-addressed artifact.
    ///
    /// The helper validates the request locally, then verifies that the daemon
    /// bound its response to the identical artifact reference and offset and
    /// did not exceed the requested raw-byte limit. Filesystem paths are never
    /// accepted by this API.
    ///
    /// # Errors
    ///
    /// Returns request-contract, transport, protocol, or response-binding
    /// errors. Callers continue with [`ArtifactChunk::next_offset`] until
    /// [`ArtifactChunk::eof`] is true.
    pub fn get_artifact(
        &mut self,
        artifact: ArtifactRef,
        offset: u64,
        max_bytes: u32,
    ) -> Result<ArtifactChunk, ClientError> {
        let request = GetArtifactRequest::new(artifact, offset, max_bytes)
            .map_err(ClientError::InvalidArtifactRequest)?;
        let result = self.call(ClientCommand::GetArtifact(request.clone()))?;
        let chunk = match result {
            ServerResult::ArtifactChunk(chunk) => chunk,
            other => {
                return Err(ClientError::UnexpectedResult {
                    expected: "artifact_chunk",
                    actual: result_name(&other),
                });
            }
        };
        validate_artifact_response(&request, &chunk)?;
        Ok(chunk)
    }

    fn create_run_once(
        &mut self,
        request: &CreateRunRequest,
    ) -> Result<Run, CreateRunAttemptFailure> {
        let result = self.call_with_progress(
            ClientCommand::CreateRun(request.clone()),
            RequestPhase::SteadyState,
        );
        let run = match result {
            Ok(ServerResult::Run(run)) => run,
            Ok(other) => {
                self.terminate_now();
                return Err(CreateRunAttemptFailure::MayHaveExecuted(
                    ClientError::UnexpectedResult {
                        expected: "run",
                        actual: result_name(&other),
                    },
                ));
            }
            Err(CallFailure::Rejected(error)) => {
                return Err(classify_create_run_rejection(error));
            }
            Err(CallFailure::Request { progress, error }) => {
                if progress == RequestProgress::MayHaveExecuted {
                    self.terminate_now();
                    return Err(CreateRunAttemptFailure::MayHaveExecuted(error));
                }
                return Err(CreateRunAttemptFailure::NotSubmitted(error));
            }
        };
        if run.id != request.run_id {
            let error = ClientError::RunIdentityMismatch {
                expected: request.run_id,
                actual: run.id,
            };
            self.terminate_now();
            return Err(CreateRunAttemptFailure::MayHaveExecuted(error));
        }
        if run.spec != request.spec {
            let error = ClientError::RunSpecificationMismatch {
                run_id: request.run_id,
            };
            self.terminate_now();
            return Err(CreateRunAttemptFailure::MayHaveExecuted(error));
        }
        Ok(run)
    }

    fn reconnect_initialized(&mut self) -> Result<InitializeResult, ClientError> {
        let identity = self
            .initialized_client
            .clone()
            .ok_or(ClientError::ReconnectBeforeInitialize)?;
        let mut replacement = Self::spawn_with_launch_options_and_timeouts(
            &self.executable,
            &self.data_dir,
            self.launch_options.clone(),
            ClientTimeouts::new(self.request_timeout, self.startup_timeout),
        )?;
        let initialized = replacement.initialize(identity.name, identity.version)?;
        std::mem::swap(self, &mut replacement);
        drop(replacement);
        Ok(initialized)
    }
}

fn classify_create_run_rejection(error: ClientError) -> CreateRunAttemptFailure {
    let is_definitive = matches!(
        &error,
        ClientError::Rejected {
            code: ErrorCode::InvalidRequest | ErrorCode::NotFound | ErrorCode::Conflict,
            retryable: false,
            ..
        }
    );
    if is_definitive {
        CreateRunAttemptFailure::Rejected(error)
    } else {
        // A generic/internal server failure proves that the daemon decoded the
        // request, but not that every durable side effect rolled back before
        // the response was produced. Preserve the stable identity until an
        // exact replay returns the run or a pre-commit rejection class above.
        CreateRunAttemptFailure::MayHaveExecuted(error)
    }
}

fn create_run_recovery_failure(
    request: CreateRunRequest,
    first_progress: RequestProgress,
    source: ClientError,
) -> CreateRunFailure {
    if first_progress == RequestProgress::NotSubmitted {
        CreateRunFailure::NotSubmitted {
            request: Box::new(request),
            source: Box::new(source),
        }
    } else {
        CreateRunFailure::ReconciliationRequired(PendingCreateRun {
            request: Box::new(request),
            last_error: Box::new(source),
        })
    }
}

impl Drop for DaemonClient {
    fn drop(&mut self) {
        self.write_requests.take();
        self.wait_then_terminate(SHUTDOWN_GRACE_PERIOD);
        self.responses.take();
        self.join_transport_threads();
    }
}

impl DaemonClient {
    fn terminate_now(&mut self) {
        self.write_requests.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        self.responses.take();
        self.join_transport_threads();
    }

    fn wait_then_terminate(&mut self, grace_period: Duration) {
        let deadline = Instant::now().checked_add(grace_period);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(_) => break,
            }
            if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
                break;
            }
            thread::sleep(SHUTDOWN_POLL_INTERVAL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn join_transport_threads(&mut self) {
        if let Some(writer) = self.writer_thread.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader_thread.take() {
            let _ = reader.join();
        }
    }
}

fn remaining_timeout(started: Instant, timeout: Duration) -> Duration {
    timeout.saturating_sub(started.elapsed())
}

const fn result_name(result: &ServerResult) -> &'static str {
    match result {
        ServerResult::Initialized(_) => "initialized",
        ServerResult::Health(_) => "health",
        ServerResult::BackendCatalog(_) => "backend_catalog",
        ServerResult::Session(_) => "session",
        ServerResult::Run(_) => "run",
        ServerResult::EventPage(_) => "event_page",
        ServerResult::CancellationReceipt(_) => "cancellation_receipt",
        ServerResult::ArtifactChunk(_) => "artifact_chunk",
    }
}

fn validate_artifact_response(
    request: &GetArtifactRequest,
    chunk: &ArtifactChunk,
) -> Result<(), ClientError> {
    if chunk.artifact() != request.artifact() {
        return Err(ClientError::ArtifactReferenceMismatch);
    }
    if chunk.offset() != request.offset() {
        return Err(ClientError::ArtifactOffsetMismatch {
            expected: request.offset(),
            actual: chunk.offset(),
        });
    }
    if chunk.data().len() > request.max_bytes() as usize {
        return Err(ClientError::ArtifactChunkExceedsRequest {
            requested: request.max_bytes(),
            actual: chunk.data().len(),
        });
    }
    Ok(())
}

fn ensure_protocol_version(actual: u32) -> Result<(), ClientError> {
    if actual == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ClientError::NegotiatedProtocolMismatch {
            expected: PROTOCOL_VERSION,
            actual,
        })
    }
}

fn encode_request<Request>(request: &Request) -> Result<Vec<u8>, ClientError>
where
    Request: Serialize,
{
    let mut frame = CappedRequestFrame::new(DAEMON_REQUEST_FRAME_BYTES.saturating_sub(1));
    let encoded = serde_json::to_writer(&mut frame, request);
    if frame.overflowed {
        return Err(ClientError::RequestTooLarge);
    }
    encoded.map_err(ClientError::Encode)?;
    frame.bytes.push(b'\n');
    Ok(frame.bytes)
}

struct CappedRequestFrame {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl CappedRequestFrame {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }
}

impl Write for CappedRequestFrame {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > self.limit {
            self.overflowed = true;
            return Err(io::Error::other(
                "serialized daemon request exceeded its frame limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum ResponseReadError {
    Io(io::Error),
    Ended,
    TooLarge,
}

impl From<ResponseReadError> for ClientError {
    fn from(error: ResponseReadError) -> Self {
        match error {
            ResponseReadError::Io(error) => Self::Io(error),
            ResponseReadError::Ended => Self::Ended,
            ResponseReadError::TooLarge => Self::ResponseTooLarge,
        }
    }
}

struct WriteRequest {
    frame: Vec<u8>,
    completion: SyncSender<io::Result<()>>,
}

fn start_request_writer(
    input: ChildStdin,
) -> Result<(Sender<WriteRequest>, JoinHandle<()>), ClientError> {
    let (sender, receiver) = mpsc::channel();
    let writer = thread::Builder::new()
        .name("birdcode-daemon-requests".to_owned())
        .spawn(move || request_writer(input, &receiver))
        .map_err(ClientError::WriterThread)?;
    Ok((sender, writer))
}

fn request_writer(mut input: ChildStdin, receiver: &Receiver<WriteRequest>) {
    while let Ok(request) = receiver.recv() {
        let result = input.write_all(&request.frame).and_then(|()| input.flush());
        let should_end = result.is_err();
        if request.completion.send(result).is_err() || should_end {
            return;
        }
    }
}

fn start_response_reader(
    output: ChildStdout,
) -> Result<(ResponseReceiver, JoinHandle<()>), ClientError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::Builder::new()
        .name("birdcode-daemon-responses".to_owned())
        .spawn(move || response_reader(output, &sender))
        .map_err(ClientError::ReaderThread)?;
    Ok((receiver, reader))
}

fn response_reader(output: ChildStdout, sender: &SyncSender<Result<Vec<u8>, ResponseReadError>>) {
    let mut output = BufReader::new(output);
    loop {
        let result = read_response_frame(&mut output);
        let should_end = matches!(
            result,
            Err(ResponseReadError::Io(_) | ResponseReadError::Ended)
        );
        if sender.send(result).is_err() || should_end {
            return;
        }
    }
}

fn read_response_frame(output: &mut impl BufRead) -> Result<Vec<u8>, ResponseReadError> {
    let mut response = Vec::new();
    let read_limit = u64::try_from(MAX_RESPONSE_FRAME_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let bytes_read = output
        .by_ref()
        .take(read_limit)
        .read_until(b'\n', &mut response)
        .map_err(ResponseReadError::Io)?;
    if bytes_read == 0 {
        return Err(ResponseReadError::Ended);
    }
    if response.len() > MAX_RESPONSE_FRAME_BYTES {
        if !response.ends_with(b"\n") {
            drain_line(output).map_err(ResponseReadError::Io)?;
        }
        return Err(ResponseReadError::TooLarge);
    }

    Ok(response)
}

fn drain_line(input: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |position| position + 1);
        input.consume(consumed);
        if newline.is_some() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientError, ClientTimeouts, CreateRunFailure, DAEMON_BINARY_NAME,
        DAEMON_REQUEST_FRAME_BYTES, DEFAULT_REQUEST_TIMEOUT, DEFAULT_STARTUP_TIMEOUT, DaemonClient,
        DaemonLaunchOptions, MAX_RESPONSE_FRAME_BYTES, ResponseReadError, daemon_command,
        encode_request, ensure_protocol_version, read_response_frame, result_name,
        sibling_daemon_path, validate_artifact_response,
    };
    use birdcode_protocol::{
        ArtifactChunk, ArtifactRef, BackendKind, BackendSelection, ClientCommand, CreateRunRequest,
        CreateSessionRequest, ErrorCode, GetArtifactRequest, InputItem, PlanAcceptanceContract,
        RunId, RunLimits, RunPurpose, RunSpec, ServerResult, SessionId, Sha256Digest,
    };
    use serde::ser::SerializeSeq;
    use serde::{Serialize, Serializer};
    use std::cell::Cell;
    use std::io::{BufReader, Cursor};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    struct CountedLargeSequence {
        chunk: String,
        elements: usize,
        serialized: Cell<usize>,
    }

    fn artifact(byte: char, size_bytes: u64) -> ArtifactRef {
        ArtifactRef {
            sha256: byte.to_string().repeat(Sha256Digest::HEX_LENGTH),
            size_bytes,
            media_type: "application/octet-stream".to_owned(),
        }
    }

    impl Serialize for CountedLargeSequence {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(self.elements))?;
            for index in 0..self.elements {
                self.serialized.set(index + 1);
                sequence.serialize_element(&self.chunk)?;
            }
            sequence.end()
        }
    }

    #[cfg(unix)]
    fn executable_daemon(directory: &Path, name: &str, source: &str) -> PathBuf {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let daemon = directory.join(name);
        fs::write(&daemon, source).expect("test daemon should be written");
        let mut permissions = fs::metadata(&daemon)
            .expect("test daemon metadata should exist")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&daemon, permissions).expect("test daemon should be executable");
        daemon
    }

    #[cfg(unix)]
    fn non_reading_daemon(directory: &Path) -> PathBuf {
        executable_daemon(
            directory,
            "non-reading-daemon",
            "#!/bin/sh\nwhile :; do :; done\n",
        )
    }

    #[cfg(unix)]
    fn slow_initializing_daemon(directory: &Path) -> PathBuf {
        let source = r#"#!/bin/sh
IFS= read -r request
request_id=${request#*\"id\":\"}
request_id=${request_id%%\"*}
sleep 1
printf '%s\n' "{\"request_id\":\"$request_id\",\"status\":\"success\",\"result\":{\"type\":\"initialized\",\"data\":{\"protocol_version\":__PROTOCOL_VERSION__,\"server\":{\"name\":\"slow-test-daemon\",\"version\":\"test\"},\"capabilities\":{\"supported\":[]}}}}"
while IFS= read -r ignored; do :; done
"#
        .replace("__PROTOCOL_VERSION__", &birdcode_protocol::PROTOCOL_VERSION.to_string());
        executable_daemon(directory, "slow-initializing-daemon", &source)
    }

    #[cfg(unix)]
    fn reconciliation_daemon(directory: &Path) -> PathBuf {
        let source = r#"#!/usr/bin/env python3
import json
import pathlib
import sys

data_dir = pathlib.Path(sys.argv[sys.argv.index("--data-dir") + 1])
mode = (data_dir / "mode").read_text().strip()

def bump(name):
    path = data_dir / (name + ".count")
    value = int(path.read_text()) + 1 if path.exists() else 1
    path.write_text(str(value))
    return value

def send(request_id, result=None, error=None):
    if error is None:
        response = {"request_id": request_id, "status": "success", "result": result}
    else:
        response = {"request_id": request_id, "status": "error", "error": error}
    print(json.dumps(response, separators=(",", ":")), flush=True)

for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    params = request.get("params")
    if method == "initialize":
        bump("initialize")
        identity_path = data_dir / "initialize.json"
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"))
        if identity_path.exists() and identity_path.read_text() != canonical:
            sys.exit(41)
        identity_path.write_text(canonical)
        send(request["id"], {
            "type": "initialized",
            "data": {
                "protocol_version": __PROTOCOL_VERSION__,
                "server": {"name": "reconciliation-test", "version": "test"},
                "capabilities": {"supported": []}
            }
        })
    elif method == "create_session":
        bump("create_session")
        send(request["id"], {
            "type": "session",
            "data": {
                "id": "019b0000-0000-7000-8000-000000000001",
                "workspace_root": params["workspace_root"],
                "title": params.get("title"),
                "created_at": "2026-07-19T12:00:00Z"
            }
        })
    elif method == "create_run":
        attempt = bump("create_run")
        request_path = data_dir / "create_run.json"
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"))
        if request_path.exists() and request_path.read_text() != canonical:
            send(request["id"], error={
                "code": "conflict",
                "message": "replay changed the retained request",
                "retryable": False
            })
            continue
        request_path.write_text(canonical)
        if attempt == 1 and mode in ("commit_drop", "conflict", "commit_internal"):
            sys.exit(0)
        if mode == "commit_internal":
            send(request["id"], error={
                "code": "internal",
                "message": "store outcome is unavailable",
                "retryable": True
            })
            continue
        if mode == "conflict":
            send(request["id"], error={
                "code": "conflict",
                "message": "stored run conflicts with retained specification",
                "retryable": False
            })
            continue
        run_id = params["run_id"]
        if mode == "wrong_run":
            run_id = "019b0000-0000-7000-8000-000000000099"
        send(request["id"], {
            "type": "run",
            "data": {
                "id": run_id,
                "spec": params["spec"],
                "state": "queued",
                "created_at": "2026-07-19T12:00:00Z"
            }
        })
    else:
        send(request["id"], error={
            "code": "invalid_request",
            "message": "unsupported test command",
            "retryable": False
        })
"#
        .replace(
            "__PROTOCOL_VERSION__",
            &birdcode_protocol::PROTOCOL_VERSION.to_string(),
        );
        executable_daemon(directory, "reconciliation-daemon", &source)
    }

    fn plan_request() -> CreateRunRequest {
        CreateRunRequest {
            run_id: RunId::new(),
            spec: RunSpec {
                session_id: SessionId::new(),
                purpose: RunPurpose::PlanOnly,
                plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
                backend: BackendSelection {
                    backend_id: "lmstudio".to_owned(),
                    kind: BackendKind::Model,
                    model: Some("exact-model".to_owned()),
                    reasoning_effort: None,
                },
                input: vec![InputItem::Text {
                    text: "Planera exakt på svenska".to_owned(),
                }],
                limits: RunLimits {
                    max_output_tokens: Some(4096),
                    max_wall_time_seconds: Some(60),
                    max_subagents: 0,
                },
            },
        }
    }

    #[cfg(unix)]
    fn read_count(directory: &Path, name: &str) -> u32 {
        std::fs::read_to_string(directory.join(format!("{name}.count")))
            .expect("counter should exist")
            .parse()
            .expect("counter should be numeric")
    }

    #[test]
    fn resolves_daemon_next_to_client_executable() {
        let expected = if cfg!(windows) {
            PathBuf::from(r"C:\BirdCode\birdcode-daemon.exe")
        } else {
            PathBuf::from("/Applications/BirdCode/birdcode-daemon")
        };
        let client = if cfg!(windows) {
            Path::new(r"C:\BirdCode\birdcode.exe")
        } else {
            Path::new("/Applications/BirdCode/birdcode")
        };

        assert_eq!(sibling_daemon_path(client), expected);
        assert_eq!(DAEMON_BINARY_NAME, "birdcode-daemon");
    }

    #[test]
    fn launch_arguments_forward_only_an_explicit_model_policy_path() {
        let default = daemon_command(
            Path::new("/Applications/BirdCode/birdcode-daemon"),
            Path::new("/tmp/BirdCode data"),
            &DaemonLaunchOptions::default(),
        );
        assert_eq!(
            default.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("--data-dir"),
                std::ffi::OsStr::new("/tmp/BirdCode data")
            ]
        );

        let explicit = daemon_command(
            Path::new("/Applications/BirdCode/birdcode-daemon"),
            Path::new("/tmp/BirdCode data"),
            &DaemonLaunchOptions {
                model_policy: Some(PathBuf::from("/tmp/policies/critic policy.json")),
            },
        );
        assert_eq!(
            explicit.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("--data-dir"),
                std::ffi::OsStr::new("/tmp/BirdCode data"),
                std::ffi::OsStr::new("--model-policy"),
                std::ffi::OsStr::new("/tmp/policies/critic policy.json"),
            ]
        );
    }

    #[test]
    fn default_startup_budget_is_bounded_and_independent_from_rpc_budget() {
        assert_eq!(DEFAULT_REQUEST_TIMEOUT, Duration::from_secs(10));
        assert_eq!(DEFAULT_STARTUP_TIMEOUT, Duration::from_secs(15 * 60));
        assert_eq!(
            ClientTimeouts::default(),
            ClientTimeouts::new(DEFAULT_REQUEST_TIMEOUT, DEFAULT_STARTUP_TIMEOUT)
        );
    }

    #[test]
    fn accepts_a_response_larger_than_the_daemon_request_limit() {
        let value = "x".repeat(DAEMON_REQUEST_FRAME_BYTES);
        let frame = serde_json::to_vec(&value).expect("test response should encode");
        let mut framed = frame;
        framed.push(b'\n');
        let mut reader = BufReader::new(Cursor::new(framed));

        let response = read_response_frame(&mut reader)
            .expect("response envelope headroom should be accepted");
        let decoded: String = serde_json::from_slice(&response).expect("response should decode");

        assert_eq!(decoded, value);
    }

    #[test]
    fn request_frame_is_encoded_atomically_and_bounded() {
        let largest_value = "x".repeat(DAEMON_REQUEST_FRAME_BYTES - 3);
        let frame = encode_request(&largest_value).expect("frame at the limit should encode");
        assert_eq!(frame.len(), DAEMON_REQUEST_FRAME_BYTES);
        assert!(frame.ends_with(b"\n"));

        let oversized_value = format!("{largest_value}x");
        assert!(matches!(
            encode_request(&oversized_value),
            Err(ClientError::RequestTooLarge)
        ));
    }

    #[test]
    fn oversized_request_serialization_stops_when_the_frame_cap_is_reached() {
        let request = CountedLargeSequence {
            chunk: "x".repeat(4 * 1024),
            elements: 4 * 1024,
            serialized: Cell::new(0),
        };

        assert!(matches!(
            encode_request(&request),
            Err(ClientError::RequestTooLarge)
        ));
        assert!(request.serialized.get() < request.elements);
    }

    #[test]
    fn rejects_a_success_response_with_a_different_protocol_version() {
        assert!(ensure_protocol_version(birdcode_protocol::PROTOCOL_VERSION).is_ok());
        assert!(matches!(
            ensure_protocol_version(birdcode_protocol::PROTOCOL_VERSION + 1),
            Err(ClientError::NegotiatedProtocolMismatch {
                expected: birdcode_protocol::PROTOCOL_VERSION,
                actual
            }) if actual == birdcode_protocol::PROTOCOL_VERSION + 1
        ));
    }

    #[test]
    fn artifact_result_name_and_response_binding_are_exact() {
        let exact_artifact = artifact('a', 8);
        let request = GetArtifactRequest::new(exact_artifact.clone(), 0, 4)
            .expect("artifact request should be valid");
        let chunk = ArtifactChunk::new(exact_artifact.clone(), 0, vec![1, 2, 3, 4], false)
            .expect("artifact chunk should be valid");

        assert_eq!(
            result_name(&ServerResult::ArtifactChunk(chunk.clone())),
            "artifact_chunk"
        );
        validate_artifact_response(&request, &chunk)
            .expect("exact artifact response should be accepted");

        let wrong_artifact_chunk = ArtifactChunk::new(artifact('b', 8), 0, vec![1, 2, 3, 4], false)
            .expect("alternate chunk should be structurally valid");
        assert!(matches!(
            validate_artifact_response(&request, &wrong_artifact_chunk),
            Err(ClientError::ArtifactReferenceMismatch)
        ));

        let wrong_offset_chunk = ArtifactChunk::new(exact_artifact, 1, vec![1, 2, 3, 4], false)
            .expect("offset chunk should be structurally valid");
        assert!(matches!(
            validate_artifact_response(&request, &wrong_offset_chunk),
            Err(ClientError::ArtifactOffsetMismatch {
                expected: 0,
                actual: 1
            })
        ));
    }

    #[test]
    fn artifact_response_cannot_exceed_the_requested_page_size() {
        let artifact = artifact('c', 8);
        let request = GetArtifactRequest::new(artifact.clone(), 0, 2)
            .expect("artifact request should be valid");
        let chunk = ArtifactChunk::new(artifact, 0, vec![1, 2, 3, 4], false)
            .expect("chunk remains below the protocol-wide bound");

        assert!(matches!(
            validate_artifact_response(&request, &chunk),
            Err(ClientError::ArtifactChunkExceedsRequest {
                requested: 2,
                actual: 4
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn committed_run_with_dropped_response_replays_exactly_without_replaying_session() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        std::fs::write(directory.path().join("mode"), "commit_drop")
            .expect("test mode should be written");
        let daemon = reconciliation_daemon(directory.path());
        let mut client = DaemonClient::spawn_with_timeouts(
            &daemon,
            directory.path(),
            ClientTimeouts::new(Duration::from_secs(2), Duration::from_secs(2)),
        )
        .expect("test daemon should start");
        client
            .initialize("reconciliation-client", "test")
            .expect("initialization should succeed");
        let session_result = client
            .call(ClientCommand::CreateSession(CreateSessionRequest {
                workspace_root: directory.path().to_owned().into(),
                title: Some("one session only".to_owned()),
            }))
            .expect("session creation should succeed");
        assert!(matches!(session_result, ServerResult::Session(_)));
        let request = plan_request();

        let run = client
            .create_run(&request)
            .expect("exact replay should recover the committed run");

        assert_eq!(run.id, request.run_id);
        assert_eq!(run.spec, request.spec);
        assert_eq!(read_count(directory.path(), "initialize"), 2);
        assert_eq!(read_count(directory.path(), "create_run"), 2);
        assert_eq!(read_count(directory.path(), "create_session"), 1);
    }

    #[cfg(unix)]
    #[test]
    fn wrong_returned_run_remains_bound_to_the_original_pending_identity() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        std::fs::write(directory.path().join("mode"), "wrong_run")
            .expect("test mode should be written");
        let daemon = reconciliation_daemon(directory.path());
        let mut client = DaemonClient::spawn_with_timeouts(
            &daemon,
            directory.path(),
            ClientTimeouts::new(Duration::from_secs(2), Duration::from_secs(2)),
        )
        .expect("test daemon should start");
        client
            .initialize("reconciliation-client", "test")
            .expect("initialization should succeed");
        let request = plan_request();

        let failure = client
            .create_run(&request)
            .expect_err("a response for another run must fail closed");
        let CreateRunFailure::ReconciliationRequired(pending) = failure else {
            panic!("wrong identities are ambiguous, not safe rejections");
        };

        assert_eq!(pending.run_id(), request.run_id);
        assert_eq!(pending.request(), &request);
        assert!(matches!(
            pending.last_error(),
            ClientError::RunIdentityMismatch { expected, .. } if *expected == request.run_id
        ));
        let repeated = client
            .reconcile_create_run(pending)
            .expect_err("an explicit action remains bounded to one exact replay");
        let CreateRunFailure::ReconciliationRequired(pending) = repeated else {
            panic!("a repeated wrong identity must remain pending");
        };
        assert_eq!(pending.run_id(), request.run_id);
        assert_eq!(pending.request(), &request);
        assert_eq!(read_count(directory.path(), "initialize"), 3);
        assert_eq!(read_count(directory.path(), "create_run"), 3);
    }

    #[cfg(unix)]
    #[test]
    fn conflict_after_ambiguous_commit_is_authoritative_and_never_changes_identity() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        std::fs::write(directory.path().join("mode"), "conflict")
            .expect("test mode should be written");
        let daemon = reconciliation_daemon(directory.path());
        let mut client = DaemonClient::spawn_with_timeouts(
            &daemon,
            directory.path(),
            ClientTimeouts::new(Duration::from_secs(2), Duration::from_secs(2)),
        )
        .expect("test daemon should start");
        client
            .initialize("reconciliation-client", "test")
            .expect("initialization should succeed");
        let request = plan_request();

        let failure = client
            .create_run(&request)
            .expect_err("conflict must stop bounded reconciliation");
        let CreateRunFailure::Rejected {
            request: rejected,
            source,
        } = failure
        else {
            panic!("conflict should remain a typed authoritative rejection");
        };
        let ClientError::Rejected {
            code, retryable, ..
        } = *source
        else {
            panic!("conflict must retain its protocol error");
        };

        assert_eq!(*rejected, request);
        assert_eq!(code, ErrorCode::Conflict);
        assert!(!retryable);
        assert_eq!(read_count(directory.path(), "initialize"), 2);
        assert_eq!(read_count(directory.path(), "create_run"), 2);
    }

    #[cfg(unix)]
    #[test]
    fn internal_error_after_ambiguous_commit_retains_exact_reconciliation_identity() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        std::fs::write(directory.path().join("mode"), "commit_internal")
            .expect("test mode should be written");
        let daemon = reconciliation_daemon(directory.path());
        let mut client = DaemonClient::spawn_with_timeouts(
            &daemon,
            directory.path(),
            ClientTimeouts::new(Duration::from_secs(2), Duration::from_secs(2)),
        )
        .expect("test daemon should start");
        client
            .initialize("reconciliation-client", "test")
            .expect("initialization should succeed");
        let request = plan_request();

        let failure = client
            .create_run(&request)
            .expect_err("an internal replay result cannot prove rollback");
        let CreateRunFailure::ReconciliationRequired(pending) = failure else {
            panic!("an internal result after a possible commit must remain pending");
        };
        assert_eq!(pending.run_id(), request.run_id);
        assert_eq!(pending.request(), &request);
        assert!(matches!(
            pending.last_error(),
            ClientError::Rejected {
                code: ErrorCode::Internal,
                retryable: true,
                ..
            }
        ));

        let repeated = client
            .reconcile_create_run(pending)
            .expect_err("another internal result must retain the same request");
        let CreateRunFailure::ReconciliationRequired(pending) = repeated else {
            panic!("repeated internal results must remain pending");
        };
        assert_eq!(pending.run_id(), request.run_id);
        assert_eq!(pending.request(), &request);
        assert_eq!(read_count(directory.path(), "initialize"), 3);
        assert_eq!(read_count(directory.path(), "create_run"), 3);
    }

    #[cfg(unix)]
    #[test]
    fn oversized_create_run_is_definitely_not_submitted_on_either_connection() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        std::fs::write(directory.path().join("mode"), "commit_drop")
            .expect("test mode should be written");
        let daemon = reconciliation_daemon(directory.path());
        let mut client = DaemonClient::spawn_with_timeouts(
            &daemon,
            directory.path(),
            ClientTimeouts::new(Duration::from_secs(2), Duration::from_secs(2)),
        )
        .expect("test daemon should start");
        client
            .initialize("reconciliation-client", "test")
            .expect("initialization should succeed");
        let mut request = plan_request();
        request.spec.input = vec![InputItem::Text {
            text: "x".repeat(DAEMON_REQUEST_FRAME_BYTES),
        }];

        let failure = client
            .create_run(&request)
            .expect_err("oversized request must fail before submission");
        let CreateRunFailure::NotSubmitted {
            request: retained,
            source,
        } = failure
        else {
            panic!("local framing rejection must be definitely-not-submitted");
        };

        assert!(matches!(*source, ClientError::RequestTooLarge));
        assert_eq!(retained.run_id, request.run_id);
        assert_eq!(read_count(directory.path(), "initialize"), 2);
        assert!(!directory.path().join("create_run.count").exists());
    }

    #[test]
    fn oversized_response_is_drained_before_the_next_frame() {
        let mut framed = vec![b'x'; MAX_RESPONSE_FRAME_BYTES + 1];
        framed.extend_from_slice(b"\n{}\n");
        let mut reader = BufReader::new(Cursor::new(framed));

        assert!(matches!(
            read_response_frame(&mut reader),
            Err(ResponseReadError::TooLarge)
        ));
        assert_eq!(
            read_response_frame(&mut reader).expect("next frame should remain aligned"),
            b"{}\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unresponsive_daemon_is_terminated_after_bounded_timeout() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let daemon = non_reading_daemon(directory.path());
        let timeout = Duration::from_millis(30);
        let mut client = DaemonClient::spawn_with_timeout(&daemon, directory.path(), timeout)
            .expect("test daemon should start");
        let started = Instant::now();

        let result: Result<serde_json::Value, ClientError> =
            client.request(&serde_json::json!({ "ping": true }));

        assert!(matches!(result, Err(ClientError::ResponseTimeout(value)) if value == timeout));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn non_reading_daemon_cannot_block_a_large_stdin_write_past_the_deadline() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let daemon = non_reading_daemon(directory.path());
        let timeout = Duration::from_millis(50);
        let mut client = DaemonClient::spawn_with_timeout(&daemon, directory.path(), timeout)
            .expect("test daemon should start");
        let payload = "x".repeat(DAEMON_REQUEST_FRAME_BYTES - 3);
        let started = Instant::now();

        let result: Result<serde_json::Value, ClientError> = client.request(&payload);

        assert!(matches!(result, Err(ClientError::ResponseTimeout(value)) if value == timeout));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(client.write_requests.is_none());
        assert!(client.writer_thread.is_none());
        assert!(client.responses.is_none());
        assert!(client.reader_thread.is_none());
        assert!(
            client
                .child
                .try_wait()
                .expect("child status should be readable")
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn slow_initialization_can_outlive_the_steady_state_rpc_deadline() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let daemon = slow_initializing_daemon(directory.path());
        let rpc_timeout = Duration::from_millis(40);
        let startup_timeout = Duration::from_secs(3);
        let mut client = DaemonClient::spawn_with_timeouts(
            &daemon,
            directory.path(),
            ClientTimeouts::new(rpc_timeout, startup_timeout),
        )
        .expect("test daemon should start");
        let started = Instant::now();

        let initialized = client
            .initialize("startup-budget-test", "test")
            .expect("a bounded slow startup should complete");

        assert_eq!(
            initialized.protocol_version,
            birdcode_protocol::PROTOCOL_VERSION
        );
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert!(started.elapsed() < startup_timeout);

        let health = client.health();
        assert!(matches!(
            health,
            Err(ClientError::ResponseTimeout(value)) if value == rpc_timeout
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stalled_initialization_is_terminated_at_the_startup_deadline() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let daemon = non_reading_daemon(directory.path());
        let startup_timeout = Duration::from_millis(50);
        let mut client = DaemonClient::spawn_with_timeouts(
            &daemon,
            directory.path(),
            ClientTimeouts::new(Duration::from_secs(1), startup_timeout),
        )
        .expect("test daemon should start");
        let started = Instant::now();

        let result = client.initialize("stalled-startup-test", "test");

        assert!(matches!(
            result,
            Err(ClientError::StartupTimeout(value)) if value == startup_timeout
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(client.write_requests.is_none());
        assert!(client.writer_thread.is_none());
        assert!(client.responses.is_none());
        assert!(client.reader_thread.is_none());
        assert!(
            client
                .child
                .try_wait()
                .expect("child status should be readable")
                .is_some()
        );
    }
}
