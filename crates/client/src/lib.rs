//! Shared stdio transport for `BirdCode` daemon clients.

use birdcode_protocol::{
    ClientCommand, ClientIdentity, ClientRequest, ErrorCode, Health, InitializeRequest,
    InitializeResult, PROTOCOL_VERSION, ResponseOutcome, ServerResponse, ServerResult,
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
            Self::MissingPipe(_)
            | Self::Ended
            | Self::RequestTooLarge
            | Self::ResponseTooLarge
            | Self::ResponseTimeout(_)
            | Self::StartupTimeout(_)
            | Self::ResponseIdMismatch
            | Self::NegotiatedProtocolMismatch { .. }
            | Self::Rejected { .. }
            | Self::UnexpectedResult { .. } => None,
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

#[derive(Clone, Copy)]
enum RequestPhase {
    Startup,
    SteadyState,
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
        let mut child = Command::new(executable)
            .arg("--data-dir")
            .arg(data_dir)
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
        let frame = encode_request(request)?;
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
            return Err(ClientError::MissingPipe("stdin"));
        };
        if writer.send(write_request).is_err() {
            self.terminate_now();
            return Err(ClientError::Ended);
        }
        match completion_receiver.recv_timeout(remaining_timeout(started, timeout)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.terminate_now();
                return Err(ClientError::Io(error));
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.terminate_now();
                return Err(ClientError::Ended);
            }
            Err(RecvTimeoutError::Timeout) => {
                self.terminate_now();
                return Err(phase.timeout_error(timeout));
            }
        }

        let Some(responses) = self.responses.as_ref() else {
            return Err(ClientError::MissingPipe("stdout"));
        };
        let response = match responses.recv_timeout(remaining_timeout(started, timeout)) {
            Ok(Ok(frame)) => frame,
            Ok(Err(ResponseReadError::TooLarge)) => return Err(ClientError::ResponseTooLarge),
            Ok(Err(ResponseReadError::Io(error))) => {
                self.terminate_now();
                return Err(ClientError::Io(error));
            }
            Ok(Err(ResponseReadError::Ended)) | Err(RecvTimeoutError::Disconnected) => {
                self.terminate_now();
                return Err(ClientError::Ended);
            }
            Err(RecvTimeoutError::Timeout) => {
                self.terminate_now();
                return Err(phase.timeout_error(timeout));
            }
        };
        serde_json::from_slice(&response).map_err(ClientError::Decode)
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
        let request = ClientRequest::new(command);
        let request_id = request.id;
        let response: ServerResponse = self.request_with_phase(&request, phase)?;
        if response.request_id != request_id {
            return Err(ClientError::ResponseIdMismatch);
        }
        match response.outcome {
            ResponseOutcome::Success { result } => Ok(result),
            ResponseOutcome::Error { error } => Err(ClientError::Rejected {
                code: error.code,
                retryable: error.retryable,
                message: error.message,
            }),
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
        let result = self.call_with_phase(
            ClientCommand::Initialize(InitializeRequest {
                protocol_version: PROTOCOL_VERSION,
                client: ClientIdentity {
                    name: name.into(),
                    version: version.into(),
                },
            }),
            RequestPhase::Startup,
        )?;
        match result {
            ServerResult::Initialized(initialized) => {
                ensure_protocol_version(initialized.protocol_version)?;
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
        ServerResult::Session(_) => "session",
        ServerResult::Run(_) => "run",
    }
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
        ClientError, ClientTimeouts, DAEMON_BINARY_NAME, DAEMON_REQUEST_FRAME_BYTES,
        DEFAULT_REQUEST_TIMEOUT, DEFAULT_STARTUP_TIMEOUT, DaemonClient, MAX_RESPONSE_FRAME_BYTES,
        ResponseReadError, encode_request, ensure_protocol_version, read_response_frame,
        sibling_daemon_path,
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
