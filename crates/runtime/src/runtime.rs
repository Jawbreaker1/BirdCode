use birdcode_protocol::{
    ActorId, CreateRunRequest, CreateSessionRequest, ErrorCode, EventPayload, Health, HealthStatus,
    InitializeRequest, InitializeResult, NewEvent, PROTOCOL_VERSION, ProtocolError, Provenance,
    Run, RunId, RuntimeCapabilities, RuntimeCapability, ServerIdentity, Session, SessionId,
};
use birdcode_store::{Store, StoreError};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryErrorKind {
    InvalidRequest,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryError {
    kind: RepositoryErrorKind,
    message: String,
}

impl RepositoryError {
    #[must_use]
    pub fn new(kind: RepositoryErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> RepositoryErrorKind {
        self.kind
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RepositoryError {}

/// Minimal durable catalog required by the first runtime slice.
///
/// The interface is deliberately mechanical. Backend selection, intent, and
/// delegation remain structured data; the repository never guesses semantics.
pub trait Repository {
    /// # Errors
    ///
    /// Returns an unavailable error when the repository cannot answer a probe.
    fn health(&self) -> Result<(), RepositoryError>;

    /// # Errors
    ///
    /// Returns a conflict or unavailable error when insertion fails.
    fn insert_session(&mut self, session: &Session, event: NewEvent)
    -> Result<(), RepositoryError>;

    /// # Errors
    ///
    /// Returns an unavailable error when the lookup cannot complete.
    fn get_session(&self, id: SessionId) -> Result<Option<Session>, RepositoryError>;

    /// # Errors
    ///
    /// Returns a conflict or unavailable error when insertion fails.
    fn insert_run(&mut self, run: &Run, event: NewEvent) -> Result<(), RepositoryError>;

    /// # Errors
    ///
    /// Returns an unavailable error when the lookup cannot complete.
    fn get_run(&self, id: RunId) -> Result<Option<Run>, RepositoryError>;
}

impl Repository for Store {
    fn health(&self) -> Result<(), RepositoryError> {
        Store::health_probe(self).map_err(|error| repository_error(&error))
    }

    fn insert_session(
        &mut self,
        session: &Session,
        event: NewEvent,
    ) -> Result<(), RepositoryError> {
        Store::create_session(self, session, event)
            .map(|_| ())
            .map_err(|error| repository_error(&error))
    }

    fn get_session(&self, id: SessionId) -> Result<Option<Session>, RepositoryError> {
        Store::get_session(self, id).map_err(|error| repository_error(&error))
    }

    fn insert_run(&mut self, run: &Run, event: NewEvent) -> Result<(), RepositoryError> {
        Store::create_run(self, run, event)
            .map(|_| ())
            .map_err(|error| repository_error(&error))
    }

    fn get_run(&self, id: RunId) -> Result<Option<Run>, RepositoryError> {
        Store::get_run(self, id).map_err(|error| repository_error(&error))
    }
}

fn repository_error(error: &StoreError) -> RepositoryError {
    RepositoryError::new(
        if matches!(
            error,
            StoreError::EventTooLarge | StoreError::ArtifactReferenceBudget
        ) {
            RepositoryErrorKind::InvalidRequest
        } else if error.is_retryable() {
            RepositoryErrorKind::Unavailable
        } else {
            RepositoryErrorKind::Internal
        },
        error.to_string(),
    )
}

#[derive(Debug)]
pub enum RuntimeError {
    IncompatibleProtocol { requested: u32, supported: u32 },
    SessionNotFound(SessionId),
    RunNotFound(RunId),
    Repository(RepositoryError),
}

impl RuntimeError {
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        match self {
            Self::IncompatibleProtocol {
                requested,
                supported,
            } => ProtocolError {
                code: ErrorCode::IncompatibleProtocol,
                message: format!(
                    "protocol version {requested} is unsupported; this daemon supports {supported}"
                ),
                retryable: false,
            },
            Self::SessionNotFound(id) => ProtocolError {
                code: ErrorCode::NotFound,
                message: format!("session {id} was not found"),
                retryable: false,
            },
            Self::RunNotFound(id) => ProtocolError {
                code: ErrorCode::NotFound,
                message: format!("run {id} was not found"),
                retryable: false,
            },
            Self::Repository(error) => ProtocolError {
                code: match error.kind() {
                    RepositoryErrorKind::InvalidRequest => ErrorCode::InvalidRequest,
                    RepositoryErrorKind::NotFound => ErrorCode::NotFound,
                    RepositoryErrorKind::Conflict => ErrorCode::Conflict,
                    RepositoryErrorKind::Unavailable | RepositoryErrorKind::Internal => {
                        ErrorCode::Internal
                    }
                },
                message: "local runtime state operation failed".to_owned(),
                retryable: error.kind() == RepositoryErrorKind::Unavailable,
            },
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleProtocol {
                requested,
                supported,
            } => write!(
                formatter,
                "protocol version {requested} is unsupported (supported: {supported})"
            ),
            Self::SessionNotFound(id) => write!(formatter, "session {id} was not found"),
            Self::RunNotFound(id) => write!(formatter, "run {id} was not found"),
            Self::Repository(error) => write!(formatter, "repository operation failed: {error}"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repository(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RepositoryError> for RuntimeError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

pub struct LocalRuntime<R> {
    repository: R,
    actor_id: ActorId,
}

impl<R> LocalRuntime<R>
where
    R: Repository,
{
    #[must_use]
    pub fn new(repository: R) -> Self {
        Self {
            repository,
            actor_id: ActorId::new(),
        }
    }

    /// Negotiates the canonical protocol and reports runtime capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::IncompatibleProtocol`] when the requested
    /// version does not exactly match the daemon's supported version.
    pub fn initialize(
        &self,
        request: &InitializeRequest,
    ) -> Result<InitializeResult, RuntimeError> {
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(RuntimeError::IncompatibleProtocol {
                requested: request.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }

        Ok(InitializeResult {
            protocol_version: PROTOCOL_VERSION,
            server: ServerIdentity {
                name: "birdcode-daemon".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            capabilities: RuntimeCapabilities::new([RuntimeCapability::DurableSessions]),
        })
    }

    #[must_use]
    pub fn health(&self) -> Health {
        let status = if self.repository.health().is_ok() {
            HealthStatus::Ready
        } else {
            HealthStatus::Degraded
        };
        Health {
            protocol_version: PROTOCOL_VERSION,
            status,
            platform: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
        }
    }

    /// Persists immutable session metadata.
    ///
    /// # Errors
    ///
    /// Returns a repository error when local persistence fails.
    pub fn create_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> Result<Session, RuntimeError> {
        let session = Session::new(request);
        self.repository.insert_session(
            &session,
            NewEvent {
                session_id: session.id,
                run_id: None,
                actor_id: self.actor_id,
                causal_parent: None,
                provenance: runtime_provenance(),
                payload: EventPayload::SessionCreated {
                    session: session.clone(),
                },
            },
        )?;
        Ok(session)
    }

    /// Retrieves a previously persisted session.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::SessionNotFound`] when no session exists, or a
    /// repository error when local persistence is unavailable.
    pub fn get_session(&self, id: SessionId) -> Result<Session, RuntimeError> {
        self.repository
            .get_session(id)?
            .ok_or(RuntimeError::SessionNotFound(id))
    }

    /// Validates the parent session and persists a queued run specification.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::SessionNotFound`] when the parent does not
    /// exist, or a repository error when local persistence fails.
    pub fn create_run(&mut self, request: CreateRunRequest) -> Result<Run, RuntimeError> {
        if self
            .repository
            .get_session(request.spec.session_id)?
            .is_none()
        {
            return Err(RuntimeError::SessionNotFound(request.spec.session_id));
        }
        let run = Run::new(request.spec);
        self.repository.insert_run(
            &run,
            NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id: self.actor_id,
                causal_parent: None,
                provenance: runtime_provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            },
        )?;
        Ok(run)
    }

    /// Retrieves a previously persisted run.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::RunNotFound`] when no run exists, or a
    /// repository error when local persistence is unavailable.
    pub fn get_run(&self, id: RunId) -> Result<Run, RuntimeError> {
        self.repository
            .get_run(id)?
            .ok_or(RuntimeError::RunNotFound(id))
    }
}

fn runtime_provenance() -> Provenance {
    Provenance {
        producer: format!("birdcode-runtime/{}", env!("CARGO_PKG_VERSION")),
        backend: None,
        raw_artifact: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LocalRuntime, Repository, RepositoryError, RepositoryErrorKind, RuntimeError,
        repository_error,
    };
    use birdcode_protocol::{
        BackendKind, BackendSelection, ClientIdentity, CreateRunRequest, CreateSessionRequest,
        EventPayload, InitializeRequest, InputItem, NewEvent, PROTOCOL_VERSION, Run, RunId,
        RunLimits, RunSpec, Session, SessionId,
    };
    use birdcode_store::{Store, StoreError};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tempfile::TempDir;

    #[derive(Default)]
    struct MemoryRepository {
        sessions: Mutex<HashMap<SessionId, Session>>,
        runs: Mutex<HashMap<RunId, Run>>,
        events: Mutex<Vec<NewEvent>>,
    }

    impl Repository for MemoryRepository {
        fn health(&self) -> Result<(), RepositoryError> {
            Ok(())
        }

        fn insert_session(
            &mut self,
            session: &Session,
            event: NewEvent,
        ) -> Result<(), RepositoryError> {
            self.sessions
                .lock()
                .expect("session lock should be available")
                .insert(session.id, session.clone());
            self.events
                .lock()
                .expect("event lock should be available")
                .push(event);
            Ok(())
        }

        fn get_session(&self, id: SessionId) -> Result<Option<Session>, RepositoryError> {
            Ok(self
                .sessions
                .lock()
                .expect("session lock should be available")
                .get(&id)
                .cloned())
        }

        fn insert_run(&mut self, run: &Run, event: NewEvent) -> Result<(), RepositoryError> {
            self.runs
                .lock()
                .expect("run lock should be available")
                .insert(run.id, run.clone());
            self.events
                .lock()
                .expect("event lock should be available")
                .push(event);
            Ok(())
        }

        fn get_run(&self, id: RunId) -> Result<Option<Run>, RepositoryError> {
            Ok(self
                .runs
                .lock()
                .expect("run lock should be available")
                .get(&id)
                .cloned())
        }
    }

    #[test]
    fn rejects_incompatible_protocol_versions() {
        let runtime = LocalRuntime::new(MemoryRepository::default());
        let error = runtime
            .initialize(&InitializeRequest {
                protocol_version: PROTOCOL_VERSION + 1,
                client: ClientIdentity {
                    name: "test".to_owned(),
                    version: "0".to_owned(),
                },
            })
            .expect_err("incompatible versions should fail");

        assert!(matches!(error, RuntimeError::IncompatibleProtocol { .. }));
    }

    #[test]
    fn creates_and_reads_session_and_run_without_synthesizing_output() {
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/多言語 projekt").into(),
                title: Some("Fortsätt utan att tappa kontext".to_owned()),
            })
            .expect("session should be created");
        let run = runtime
            .create_run(CreateRunRequest {
                spec: RunSpec {
                    session_id: session.id,
                    backend: BackendSelection {
                        backend_id: "not-connected".to_owned(),
                        kind: BackendKind::Model,
                        model: None,
                        reasoning_effort: None,
                    },
                    input: Vec::new(),
                    limits: RunLimits::default(),
                },
            })
            .expect("run should be created");

        assert_eq!(runtime.get_session(session.id).unwrap(), session);
        assert_eq!(runtime.get_run(run.id).unwrap(), run);
        assert!(run.spec.input.is_empty());
    }

    #[test]
    fn refuses_run_for_unknown_session() {
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let missing = SessionId::new();
        let error = runtime
            .create_run(CreateRunRequest {
                spec: RunSpec {
                    session_id: missing,
                    backend: BackendSelection {
                        backend_id: "not-connected".to_owned(),
                        kind: BackendKind::Agent,
                        model: None,
                        reasoning_effort: None,
                    },
                    input: Vec::new(),
                    limits: RunLimits::default(),
                },
            })
            .expect_err("unknown parent session must fail");

        assert!(matches!(error, RuntimeError::SessionNotFound(id) if id == missing));
    }

    #[test]
    fn permanent_store_errors_are_not_marked_retryable() {
        let repository = repository_error(&StoreError::InvalidStateEvent);
        assert_eq!(repository.kind(), RepositoryErrorKind::Internal);

        let protocol = RuntimeError::Repository(repository).to_protocol_error();
        assert_eq!(protocol.code, birdcode_protocol::ErrorCode::Internal);
        assert!(!protocol.retryable);

        let artifact_budget = repository_error(&StoreError::ArtifactReferenceBudget);
        assert_eq!(artifact_budget.kind(), RepositoryErrorKind::InvalidRequest);
        let protocol = RuntimeError::Repository(artifact_budget).to_protocol_error();
        assert_eq!(protocol.code, birdcode_protocol::ErrorCode::InvalidRequest);
        assert!(!protocol.retryable);
    }

    #[test]
    fn oversized_but_transport_valid_session_is_an_invalid_request() {
        let directory = TempDir::new().expect("temporary directory should be created");
        let store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("store should open");
        let mut runtime = LocalRuntime::new(store);

        let error = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/large-request").into(),
                title: Some("x".repeat(300_000)),
            })
            .expect_err("oversized inline session event must be rejected");
        let protocol = error.to_protocol_error();
        assert_eq!(protocol.code, birdcode_protocol::ErrorCode::InvalidRequest);
        assert!(!protocol.retryable);
        assert_eq!(protocol.message, "local runtime state operation failed");
    }

    #[test]
    fn reopens_durable_session_and_run_from_sqlite() {
        let directory = TempDir::new().expect("temporary directory should be created");
        let database = directory.path().join("state.sqlite3");
        let artifacts = directory.path().join("artifacts");
        let (session, run) = {
            let store = Store::open(&database, &artifacts).expect("store should open");
            let mut runtime = LocalRuntime::new(store);
            let session = runtime
                .create_session(CreateSessionRequest {
                    workspace_root: PathBuf::from("/tmp/projekt").into(),
                    title: Some("Långlivad session".to_owned()),
                })
                .expect("session should persist");
            let run = runtime
                .create_run(CreateRunRequest {
                    spec: RunSpec {
                        session_id: session.id,
                        backend: BackendSelection {
                            backend_id: "local-test-backend".to_owned(),
                            kind: BackendKind::Model,
                            model: Some("test-only".to_owned()),
                            reasoning_effort: None,
                        },
                        input: vec![InputItem::Text {
                            text: "Bevara svenska och 日本語 exakt".to_owned(),
                        }],
                        limits: RunLimits::default(),
                    },
                })
                .expect("run should persist");
            (session, run)
        };

        let event_store = Store::open(&database, &artifacts).expect("event store should reopen");
        let events = event_store
            .events_after(session.id, 0)
            .expect("authoritative events should be readable");
        assert_eq!(events.events.len(), 2);
        assert!(matches!(
            &events.events[0].payload,
            EventPayload::SessionCreated { session: recorded } if recorded == &session
        ));
        assert!(matches!(
            &events.events[1].payload,
            EventPayload::RunCreated { run: recorded } if recorded == &run
        ));

        let reopened = LocalRuntime::new(
            Store::open(database, artifacts).expect("store should reopen after runtime shutdown"),
        );
        assert_eq!(reopened.get_session(session.id).unwrap(), session);
        assert_eq!(reopened.get_run(run.id).unwrap(), run);
    }
}
