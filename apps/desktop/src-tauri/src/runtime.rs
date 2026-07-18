use birdcode_client::{ClientError, ClientTimeouts, DaemonClient, resolve_daemon_path};
use birdcode_protocol::{Health, HealthStatus, InitializeResult};
use serde::Serialize;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Manager;

const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(250);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(8);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeHealth {
    state: RuntimeState,
    transport: Transport,
    protocol_version: Option<String>,
    daemon_version: Option<String>,
    message: String,
    backends: Vec<BackendHealth>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeState {
    Ready,
    Unavailable,
    Error,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Transport {
    Stdio,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendHealth {
    id: String,
    display_name: String,
    state: String,
    model_identity: Option<String>,
}

#[derive(Clone)]
pub struct RuntimeManager {
    inner: Arc<ConnectionManager<DaemonClient>>,
}

impl Default for RuntimeManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(ConnectionManager::default()),
        }
    }
}

impl RuntimeManager {
    /// Clears the current connection, retry backoff, and permanent failure latch.
    ///
    /// This is the typed recovery hook for a future explicit desktop action. It
    /// deliberately is not exposed as a command until the shell has a real
    /// user-initiated reset control.
    ///
    /// # Errors
    ///
    /// Returns an error when another thread poisoned the connection state.
    pub fn reset_connection(&self) -> Result<(), RuntimeResetError> {
        self.inner.reset()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeResetError;

impl fmt::Display for RuntimeResetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime connection state is unavailable")
    }
}

impl std::error::Error for RuntimeResetError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectionKey {
    daemon: PathBuf,
    data_dir: PathBuf,
}

struct ManagedConnection<C> {
    key: ConnectionKey,
    client: C,
    initialized: InitializeResult,
}

struct ConnectionManager<C> {
    state: Mutex<ConnectionState<C>>,
}

struct ConnectionState<C> {
    connection: Option<ManagedConnection<C>>,
    // UI health polling must not repeatedly kill and restart the same long
    // migration, nor retry a known-incompatible protocol. A new runtime key,
    // an explicit reset, or a new application process clears this latch.
    permanent_failure: Option<PermanentFailure>,
    retry: Option<RetryState>,
}

struct PermanentFailure {
    key: ConnectionKey,
    health: RuntimeHealth,
}

struct RetryState {
    key: ConnectionKey,
    health: RuntimeHealth,
    attempted_at: Instant,
    failures: u32,
}

impl<C> Default for ConnectionManager<C> {
    fn default() -> Self {
        Self {
            state: Mutex::new(ConnectionState {
                connection: None,
                permanent_failure: None,
                retry: None,
            }),
        }
    }
}

trait RuntimeConnection {
    fn initialize_for_desktop(&mut self) -> Result<InitializeResult, ClientError>;
    fn health(&mut self) -> Result<Health, ClientError>;
}

impl RuntimeConnection for DaemonClient {
    fn initialize_for_desktop(&mut self) -> Result<InitializeResult, ClientError> {
        self.initialize("birdcode-desktop", env!("CARGO_PKG_VERSION"))
    }

    fn health(&mut self) -> Result<Health, ClientError> {
        DaemonClient::health(self)
    }
}

impl<C> ConnectionManager<C>
where
    C: RuntimeConnection,
{
    fn health<Connector>(&self, key: &ConnectionKey, connector: &Connector) -> RuntimeHealth
    where
        Connector: Fn(&Path, &Path) -> Result<C, ClientError>,
    {
        self.health_at(key, connector, Instant::now())
    }

    fn health_at<Connector>(
        &self,
        key: &ConnectionKey,
        connector: &Connector,
        now: Instant,
    ) -> RuntimeHealth
    where
        Connector: Fn(&Path, &Path) -> Result<C, ClientError>,
    {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                return failure(
                    RuntimeState::Error,
                    format!("Runtime connection state is unavailable: {error}"),
                );
            }
        };
        if state
            .permanent_failure
            .as_ref()
            .is_some_and(|blocked| &blocked.key != key)
        {
            state.permanent_failure.take();
        }
        if let Some(blocked) = state
            .permanent_failure
            .as_ref()
            .filter(|blocked| &blocked.key == key)
        {
            return blocked.health.clone();
        }
        if state.retry.as_ref().is_some_and(|retry| &retry.key != key) {
            state.retry.take();
        }
        if state
            .connection
            .as_ref()
            .is_some_and(|managed| &managed.key != key)
        {
            state.connection.take();
        }
        if let Some(retry) = state.retry.as_ref().filter(|retry| &retry.key == key) {
            let delay = retry_backoff(retry.failures);
            if now.saturating_duration_since(retry.attempted_at) < delay {
                return retry.health.clone();
            }
        }

        if state.connection.is_none() {
            match connect(key, connector) {
                Ok(connected) => state.connection = Some(connected),
                Err(ConnectError::Spawn(error) | ConnectError::Initialize(error)) => {
                    return record_client_failure(&mut state, key, &error, now);
                }
            }
        }

        let result = check_health(
            state
                .connection
                .as_mut()
                .expect("connection is populated immediately above"),
        );
        match result {
            Ok(health) if health.state == RuntimeState::Ready => {
                state.retry.take();
                health
            }
            Ok(health) => record_runtime_failure(&mut state, key, health, now),
            Err(error) => record_client_failure(&mut state, key, &error, now),
        }
    }

    fn reset(&self) -> Result<(), RuntimeResetError> {
        let connection = {
            let mut state = self.state.lock().map_err(|_| RuntimeResetError)?;
            state.permanent_failure.take();
            state.retry.take();
            state.connection.take()
        };
        drop(connection);
        Ok(())
    }
}

#[tauri::command]
pub async fn runtime_health(
    app: tauri::AppHandle,
    manager: tauri::State<'_, RuntimeManager>,
) -> Result<RuntimeHealth, String> {
    let daemon = match resolve_daemon_path(None) {
        Ok(path) => path,
        Err(error) => return Ok(client_failure(&error)),
    };
    let data_dir = match resolve_data_dir(std::env::var_os("BIRDCODE_DATA_DIR"), || {
        app.path().app_local_data_dir()
    }) {
        Ok(path) => path,
        Err(error) => {
            return Ok(failure(
                RuntimeState::Error,
                format!("Could not resolve BirdCode's local data directory: {error}"),
            ));
        }
    };
    let manager = Arc::clone(&manager.inner);
    let key = ConnectionKey { daemon, data_dir };

    Ok(
        match tauri::async_runtime::spawn_blocking(move || {
            manager.health(&key, &|daemon, data_dir| {
                DaemonClient::spawn_with_timeouts(daemon, data_dir, ClientTimeouts::default())
            })
        })
        .await
        {
            Ok(health) => health,
            Err(error) => failure(
                RuntimeState::Error,
                format!("Runtime health task failed: {error}"),
            ),
        },
    )
}

#[tauri::command]
pub async fn runtime_reset(manager: tauri::State<'_, RuntimeManager>) -> Result<(), String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.reset_connection())
        .await
        .map_err(|error| format!("Runtime reset task failed: {error}"))?
        .map_err(|error| error.to_string())
}

fn resolve_data_dir<Error>(
    configured: Option<OsString>,
    platform_default: impl FnOnce() -> Result<PathBuf, Error>,
) -> Result<PathBuf, Error> {
    configured.map_or_else(platform_default, |path| Ok(PathBuf::from(path)))
}

fn connect<C, Connector>(
    key: &ConnectionKey,
    connector: &Connector,
) -> Result<ManagedConnection<C>, ConnectError>
where
    C: RuntimeConnection,
    Connector: Fn(&Path, &Path) -> Result<C, ClientError>,
{
    let mut client = connector(&key.daemon, &key.data_dir).map_err(ConnectError::Spawn)?;
    let initialized = client
        .initialize_for_desktop()
        .map_err(ConnectError::Initialize)?;
    Ok(ManagedConnection {
        key: key.clone(),
        client,
        initialized,
    })
}

enum ConnectError {
    Spawn(ClientError),
    Initialize(ClientError),
}

fn check_health<C>(connection: &mut ManagedConnection<C>) -> Result<RuntimeHealth, ClientError>
where
    C: RuntimeConnection,
{
    let health = connection.client.health()?;
    Ok(project_health(&connection.initialized, &health))
}

fn project_health(initialized: &InitializeResult, health: &Health) -> RuntimeHealth {
    let protocol_version = Some(initialized.protocol_version.to_string());
    let daemon_version = Some(initialized.server.version.clone());
    if health.status != HealthStatus::Ready {
        return RuntimeHealth {
            state: RuntimeState::Error,
            transport: Transport::Stdio,
            protocol_version,
            daemon_version,
            message: "The daemon reports degraded local storage.".to_owned(),
            backends: Vec::new(),
        };
    }

    RuntimeHealth {
        state: RuntimeState::Ready,
        transport: Transport::Stdio,
        protocol_version,
        daemon_version,
        message: format!(
            "Local runtime is ready on {}/{}.",
            health.platform, health.architecture
        ),
        backends: Vec::new(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePolicy {
    Latch,
    RetryConnection,
    RetryRequest,
}

const fn failure_policy(error: &ClientError) -> FailurePolicy {
    match error {
        ClientError::StartupTimeout(_) | ClientError::NegotiatedProtocolMismatch { .. } => {
            FailurePolicy::Latch
        }
        ClientError::Rejected {
            code: birdcode_protocol::ErrorCode::IncompatibleProtocol,
            ..
        } => FailurePolicy::Latch,
        ClientError::Encode(_) | ClientError::RequestTooLarge | ClientError::Rejected { .. } => {
            FailurePolicy::RetryRequest
        }
        ClientError::CurrentExecutable(_)
        | ClientError::Spawn { .. }
        | ClientError::MissingPipe(_)
        | ClientError::Io(_)
        | ClientError::Decode(_)
        | ClientError::Ended
        | ClientError::ResponseTooLarge
        | ClientError::ResponseTimeout(_)
        | ClientError::ResponseIdMismatch
        | ClientError::WriterThread(_)
        | ClientError::ReaderThread(_)
        | ClientError::UnexpectedResult { .. } => FailurePolicy::RetryConnection,
    }
}

fn record_client_failure<C>(
    state: &mut ConnectionState<C>,
    key: &ConnectionKey,
    error: &ClientError,
    now: Instant,
) -> RuntimeHealth {
    let health = client_failure(error);
    match failure_policy(error) {
        FailurePolicy::Latch => {
            state.connection.take();
            state.retry.take();
            state.permanent_failure = Some(PermanentFailure {
                key: key.clone(),
                health: health.clone(),
            });
        }
        FailurePolicy::RetryConnection => {
            state.connection.take();
            record_retry(state, key, health.clone(), now);
        }
        FailurePolicy::RetryRequest => record_retry(state, key, health.clone(), now),
    }
    health
}

fn record_runtime_failure<C>(
    state: &mut ConnectionState<C>,
    key: &ConnectionKey,
    health: RuntimeHealth,
    now: Instant,
) -> RuntimeHealth {
    record_retry(state, key, health.clone(), now);
    health
}

fn record_retry<C>(
    state: &mut ConnectionState<C>,
    key: &ConnectionKey,
    health: RuntimeHealth,
    now: Instant,
) {
    let failures = state
        .retry
        .as_ref()
        .filter(|retry| &retry.key == key)
        .map_or(1, |retry| retry.failures.saturating_add(1));
    state.retry = Some(RetryState {
        key: key.clone(),
        health,
        attempted_at: now,
        failures,
    });
}

fn retry_backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(31);
    INITIAL_RETRY_BACKOFF
        .saturating_mul(1_u32 << exponent)
        .min(MAX_RETRY_BACKOFF)
}

fn client_failure(error: &ClientError) -> RuntimeHealth {
    failure(
        if matches!(error, ClientError::Spawn { .. }) {
            RuntimeState::Unavailable
        } else {
            RuntimeState::Error
        },
        error.to_string(),
    )
}

fn failure(state: RuntimeState, message: String) -> RuntimeHealth {
    RuntimeHealth {
        state,
        transport: Transport::Stdio,
        protocol_version: None,
        daemon_version: None,
        message,
        backends: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionKey, ConnectionManager, FailurePolicy, INITIAL_RETRY_BACKOFF, MAX_RETRY_BACKOFF,
        RuntimeConnection, RuntimeManager, RuntimeState, client_failure, failure_policy,
        resolve_data_dir, retry_backoff,
    };
    use birdcode_client::{ClientError, DaemonClient};
    use birdcode_protocol::{
        ErrorCode, Health, HealthStatus, InitializeResult, PROTOCOL_VERSION, RuntimeCapabilities,
        ServerIdentity,
    };
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug)]
    enum FakeError {
        StartupTimeout,
        NegotiatedProtocolMismatch,
        IncompatibleProtocol,
        InternalRejection { retryable: bool },
        Ended,
    }

    struct FakeConnection {
        initialize_error: Option<FakeError>,
        health_error: Option<FakeError>,
        health_failures: usize,
        degraded_failures: usize,
        health_calls: Arc<AtomicUsize>,
    }

    impl FakeError {
        fn into_client_error(self) -> ClientError {
            match self {
                Self::StartupTimeout => ClientError::StartupTimeout(Duration::from_secs(1)),
                Self::NegotiatedProtocolMismatch => ClientError::NegotiatedProtocolMismatch {
                    expected: PROTOCOL_VERSION,
                    actual: PROTOCOL_VERSION + 1,
                },
                Self::IncompatibleProtocol => ClientError::Rejected {
                    code: ErrorCode::IncompatibleProtocol,
                    retryable: false,
                    message: "test protocol incompatibility".to_owned(),
                },
                Self::InternalRejection { retryable } => ClientError::Rejected {
                    code: ErrorCode::Internal,
                    retryable,
                    message: "test internal rejection".to_owned(),
                },
                Self::Ended => ClientError::Ended,
            }
        }
    }

    impl RuntimeConnection for FakeConnection {
        fn initialize_for_desktop(&mut self) -> Result<InitializeResult, ClientError> {
            match self.initialize_error {
                Some(error) => Err(error.into_client_error()),
                None => Ok(initialize_result()),
            }
        }

        fn health(&mut self) -> Result<Health, ClientError> {
            let call = self.health_calls.fetch_add(1, Ordering::SeqCst);
            if call < self.health_failures {
                return Err(self
                    .health_error
                    .expect("a configured health failure needs an error")
                    .into_client_error());
            }
            Ok(Health {
                protocol_version: PROTOCOL_VERSION,
                status: if call < self.degraded_failures {
                    HealthStatus::Degraded
                } else {
                    HealthStatus::Ready
                },
                platform: "test".to_owned(),
                architecture: "test".to_owned(),
            })
        }
    }

    #[test]
    fn reuses_one_daemon_connection_across_health_calls() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            connects.fetch_add(1, Ordering::SeqCst);
            Ok(ready_connection(Arc::clone(&health_calls)))
        };

        let now = Instant::now();
        let first = manager.health_at(&key(), &connector, now);
        let second = manager.health_at(&key(), &connector, now);

        assert_eq!(first.state, RuntimeState::Ready);
        assert_eq!(second.state, RuntimeState::Ready);
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert_eq!(health_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn child_exit_reconnects_after_backoff_without_a_tight_restart_loop() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            connects.fetch_add(1, Ordering::SeqCst);
            Ok(FakeConnection {
                initialize_error: None,
                health_error: Some(FakeError::Ended),
                health_failures: 1,
                degraded_failures: 0,
                health_calls: Arc::clone(&health_calls),
            })
        };

        let now = Instant::now();
        let first = manager.health_at(&key(), &connector, now);
        let suppressed = manager.health_at(&key(), &connector, now + Duration::from_millis(249));
        let recovered = manager.health_at(&key(), &connector, now + INITIAL_RETRY_BACKOFF);

        assert_eq!(first.state, RuntimeState::Error);
        assert_eq!(suppressed.message, first.message);
        assert_eq!(recovered.state, RuntimeState::Ready);
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        assert_eq!(health_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retryable_initialization_rejection_recovers_after_backoff() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            let attempt = connects.fetch_add(1, Ordering::SeqCst);
            let mut connection = ready_connection(Arc::clone(&health_calls));
            if attempt == 0 {
                connection.initialize_error =
                    Some(FakeError::InternalRejection { retryable: true });
            }
            Ok(connection)
        };

        let now = Instant::now();
        let first = manager.health_at(&key(), &connector, now);
        let suppressed = manager.health_at(&key(), &connector, now + Duration::from_millis(100));
        let recovered = manager.health_at(&key(), &connector, now + INITIAL_RETRY_BACKOFF);

        assert_eq!(first.state, RuntimeState::Error);
        assert_eq!(suppressed.message, first.message);
        assert_eq!(recovered.state, RuntimeState::Ready);
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        assert_eq!(health_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_retryable_internal_initialization_rejection_is_not_permanently_latched() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            let attempt = connects.fetch_add(1, Ordering::SeqCst);
            let mut connection = ready_connection(Arc::clone(&health_calls));
            if attempt == 0 {
                connection.initialize_error =
                    Some(FakeError::InternalRejection { retryable: false });
            }
            Ok(connection)
        };
        let now = Instant::now();

        assert_eq!(
            manager.health_at(&key(), &connector, now).state,
            RuntimeState::Error
        );
        assert_eq!(
            manager
                .health_at(&key(), &connector, now + INITIAL_RETRY_BACKOFF)
                .state,
            RuntimeState::Ready
        );
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn only_startup_timeout_and_protocol_incompatibility_are_latched() {
        for error in [
            FakeError::StartupTimeout,
            FakeError::NegotiatedProtocolMismatch,
            FakeError::IncompatibleProtocol,
        ] {
            let manager = ConnectionManager::default();
            let connects = Arc::new(AtomicUsize::new(0));
            let health_calls = Arc::new(AtomicUsize::new(0));
            let connector = |_: &Path, _: &Path| {
                connects.fetch_add(1, Ordering::SeqCst);
                let mut connection = ready_connection(Arc::clone(&health_calls));
                connection.initialize_error = Some(error);
                Ok(connection)
            };
            let now = Instant::now();

            let first = manager.health_at(&key(), &connector, now);
            let much_later = manager.health_at(&key(), &connector, now + Duration::from_secs(3600));

            assert_eq!(first.state, RuntimeState::Error, "{error:?}");
            assert_eq!(first.message, much_later.message, "{error:?}");
            assert_eq!(connects.load(Ordering::SeqCst), 1, "{error:?}");
            assert_eq!(health_calls.load(Ordering::SeqCst), 0, "{error:?}");
        }
    }

    #[test]
    fn startup_timeout_latch_requires_an_explicit_reset_or_new_key() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            let attempt = connects.fetch_add(1, Ordering::SeqCst);
            let mut connection = ready_connection(Arc::clone(&health_calls));
            if attempt == 0 {
                connection.initialize_error = Some(FakeError::StartupTimeout);
            }
            Ok(connection)
        };
        let now = Instant::now();

        let timed_out = manager.health_at(&key(), &connector, now);
        let still_latched = manager.health_at(&key(), &connector, now + Duration::from_secs(3600));
        assert!(timed_out.message.contains("startup did not complete"));
        assert_eq!(still_latched.message, timed_out.message);
        assert_eq!(connects.load(Ordering::SeqCst), 1);

        manager.reset().expect("manual reset should succeed");
        assert_eq!(
            manager.health_at(&key(), &connector, now).state,
            RuntimeState::Ready
        );
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn changing_runtime_key_clears_a_permanent_latch() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            let attempt = connects.fetch_add(1, Ordering::SeqCst);
            let mut connection = ready_connection(Arc::clone(&health_calls));
            if attempt == 0 {
                connection.initialize_error = Some(FakeError::NegotiatedProtocolMismatch);
            }
            Ok(connection)
        };
        let now = Instant::now();
        let alternate_key = ConnectionKey {
            daemon: PathBuf::from("/birdcode-test/alternate/birdcode-daemon"),
            data_dir: PathBuf::from("/birdcode-test/alternate/data"),
        };

        assert_eq!(
            manager.health_at(&key(), &connector, now).state,
            RuntimeState::Error
        );
        assert_eq!(
            manager.health_at(&alternate_key, &connector, now).state,
            RuntimeState::Ready
        );
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn request_rejection_retries_the_existing_responsive_connection() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            connects.fetch_add(1, Ordering::SeqCst);
            Ok(FakeConnection {
                initialize_error: None,
                health_error: Some(FakeError::InternalRejection { retryable: true }),
                health_failures: 1,
                degraded_failures: 0,
                health_calls: Arc::clone(&health_calls),
            })
        };
        let now = Instant::now();

        assert_eq!(
            manager.health_at(&key(), &connector, now).state,
            RuntimeState::Error
        );
        assert_eq!(
            manager
                .health_at(&key(), &connector, now + INITIAL_RETRY_BACKOFF)
                .state,
            RuntimeState::Ready
        );
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert_eq!(health_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn degraded_storage_health_uses_the_same_bounded_backoff() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            connects.fetch_add(1, Ordering::SeqCst);
            Ok(FakeConnection {
                initialize_error: None,
                health_error: None,
                health_failures: 0,
                degraded_failures: 1,
                health_calls: Arc::clone(&health_calls),
            })
        };
        let now = Instant::now();

        let degraded = manager.health_at(&key(), &connector, now);
        let suppressed = manager.health_at(&key(), &connector, now + Duration::from_millis(100));
        let recovered = manager.health_at(&key(), &connector, now + INITIAL_RETRY_BACKOFF);

        assert_eq!(degraded.state, RuntimeState::Error);
        assert_eq!(suppressed.message, degraded.message);
        assert_eq!(recovered.state, RuntimeState::Ready);
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert_eq!(health_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn repeated_failures_exponentially_back_off_and_cap() {
        assert_eq!(retry_backoff(0), INITIAL_RETRY_BACKOFF);
        assert_eq!(retry_backoff(1), INITIAL_RETRY_BACKOFF);
        assert_eq!(retry_backoff(2), Duration::from_millis(500));
        assert_eq!(retry_backoff(3), Duration::from_secs(1));
        assert_eq!(retry_backoff(6), MAX_RETRY_BACKOFF);
        assert_eq!(retry_backoff(u32::MAX), MAX_RETRY_BACKOFF);

        let manager = ConnectionManager::default();
        let attempts = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<FakeConnection, _>(ClientError::Ended)
        };
        let now = Instant::now();

        manager.health_at(&key(), &connector, now);
        manager.health_at(&key(), &connector, now + Duration::from_millis(249));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        manager.health_at(&key(), &connector, now + Duration::from_millis(250));
        manager.health_at(&key(), &connector, now + Duration::from_millis(749));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        manager.health_at(&key(), &connector, now + Duration::from_millis(750));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn explicit_reset_clears_an_active_retry_delay() {
        let manager = ConnectionManager::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let health_calls = Arc::new(AtomicUsize::new(0));
        let connector = |_: &Path, _: &Path| {
            connects.fetch_add(1, Ordering::SeqCst);
            Ok(FakeConnection {
                initialize_error: None,
                health_error: Some(FakeError::Ended),
                health_failures: 1,
                degraded_failures: 0,
                health_calls: Arc::clone(&health_calls),
            })
        };
        let now = Instant::now();

        assert_eq!(
            manager.health_at(&key(), &connector, now).state,
            RuntimeState::Error
        );
        manager.reset().expect("manual reset should succeed");
        assert_eq!(
            manager.health_at(&key(), &connector, now).state,
            RuntimeState::Ready
        );
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn public_runtime_manager_exposes_a_typed_manual_reset_hook() {
        RuntimeManager::default()
            .reset_connection()
            .expect("unused manager state should reset");
    }

    #[test]
    fn failure_policy_is_explicit_for_permanent_and_transient_errors() {
        assert_eq!(
            failure_policy(&FakeError::StartupTimeout.into_client_error()),
            FailurePolicy::Latch
        );
        assert_eq!(
            failure_policy(&FakeError::NegotiatedProtocolMismatch.into_client_error()),
            FailurePolicy::Latch
        );
        assert_eq!(
            failure_policy(&FakeError::IncompatibleProtocol.into_client_error()),
            FailurePolicy::Latch
        );
        assert_eq!(
            failure_policy(&ClientError::Ended),
            FailurePolicy::RetryConnection
        );
        assert_eq!(
            failure_policy(&ClientError::Io(io::Error::other("test I/O failure"))),
            FailurePolicy::RetryConnection
        );
        assert_eq!(
            failure_policy(&FakeError::InternalRejection { retryable: true }.into_client_error()),
            FailurePolicy::RetryRequest
        );
        assert_eq!(
            failure_policy(&FakeError::InternalRejection { retryable: false }.into_client_error()),
            FailurePolicy::RetryRequest
        );
    }

    #[test]
    fn missing_daemon_is_reported_as_unavailable() {
        let manager = ConnectionManager::default();
        let health = manager.health(&key(), &|daemon, data_dir| {
            DaemonClient::spawn(daemon, data_dir)
        });

        assert_eq!(health.state, RuntimeState::Unavailable);
        assert!(health.message.contains("could not start daemon"));
        assert!(health.protocol_version.is_none());
        assert!(health.daemon_version.is_none());
    }

    #[test]
    fn configured_data_directory_short_circuits_the_platform_default() {
        let configured = PathBuf::from("/birdcode-test/configured-data");
        let selected = resolve_data_dir(Some(configured.clone().into_os_string()), || {
            Err::<PathBuf, _>("platform default should not be resolved")
        })
        .expect("configured data directory should resolve without the platform default");

        assert_eq!(selected, configured);
    }

    #[test]
    fn platform_data_directory_is_used_without_an_override() {
        let platform = PathBuf::from("/birdcode-test/platform-data");
        let selected = resolve_data_dir(None, || Ok::<PathBuf, &'static str>(platform.clone()))
            .expect("platform data directory should resolve");

        assert_eq!(selected, platform);
    }

    fn key() -> ConnectionKey {
        ConnectionKey {
            daemon: PathBuf::from("/birdcode-test/nonexistent/birdcode-daemon"),
            data_dir: PathBuf::from("/birdcode-test/nonexistent/data"),
        }
    }

    fn initialize_result() -> InitializeResult {
        InitializeResult {
            protocol_version: PROTOCOL_VERSION,
            server: ServerIdentity {
                name: "fake-daemon".to_owned(),
                version: "test".to_owned(),
            },
            capabilities: RuntimeCapabilities::new([]),
        }
    }

    fn ready_connection(health_calls: Arc<AtomicUsize>) -> FakeConnection {
        FakeConnection {
            initialize_error: None,
            health_error: None,
            health_failures: 0,
            degraded_failures: 0,
            health_calls,
        }
    }

    #[test]
    fn spawn_error_projection_remains_truthful() {
        let error = DaemonClient::spawn(
            Path::new("/birdcode-test/nonexistent/second-daemon"),
            Path::new("/birdcode-test/nonexistent/data"),
        )
        .err()
        .expect("missing daemon should fail");

        assert_eq!(client_failure(&error).state, RuntimeState::Unavailable);
    }
}
