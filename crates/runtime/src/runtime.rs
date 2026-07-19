use birdcode_protocol::{
    ActorId, ArtifactChunk, ArtifactRef, BackendKind, CancellationDisposition, CancellationReceipt,
    CancellationRequestId, CancellationRequested, CreateRunRequest, CreateSessionRequest,
    ErrorCode, EventEnvelope, EventPage as ProtocolEventPage, EventPayload, GetArtifactRequest,
    Health, HealthStatus, InitializeRequest, InitializeResult, InputItem, NewEvent,
    PROTOCOL_VERSION, ProtocolError, Provenance, Run, RunId, RunPurpose, RunState,
    RuntimeCapabilities, RuntimeCapability, ServerIdentity, Session, SessionId,
};
use birdcode_store::{Store, StoreError};
use std::fmt;

const MAX_CANCELLATION_APPEND_ATTEMPTS: usize = 8;

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

    /// # Errors
    ///
    /// Returns a conflict or unavailable error when the append fails.
    fn append_event(&mut self, event: NewEvent) -> Result<EventEnvelope, RepositoryError>;

    /// # Errors
    ///
    /// Returns an unavailable error when replay cannot be read.
    fn events_after(
        &self,
        session_id: SessionId,
        sequence: u64,
    ) -> Result<ProtocolEventPage, RepositoryError>;

    /// Replays one bounded page scoped to a single run. Long-lived sessions
    /// must not be scanned in full merely to cancel one active run.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when replay cannot be read.
    fn events_for_run_after(
        &self,
        run_id: RunId,
        sequence: u64,
    ) -> Result<ProtocolEventPage, RepositoryError>;

    /// Loads and verifies the complete bytes named by an exact artifact
    /// reference. The runtime slices the verified value into bounded wire
    /// chunks; repository paths never cross this boundary.
    ///
    /// # Errors
    ///
    /// Returns not-found, integrity, or availability errors.
    fn read_artifact(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, RepositoryError>;
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

    fn append_event(&mut self, event: NewEvent) -> Result<EventEnvelope, RepositoryError> {
        Store::append_event(self, event).map_err(|error| repository_error(&error))
    }

    fn events_after(
        &self,
        session_id: SessionId,
        sequence: u64,
    ) -> Result<ProtocolEventPage, RepositoryError> {
        Store::events_after(self, session_id, sequence)
            .map(|page| ProtocolEventPage {
                events: page.events,
                next_sequence: page.next_sequence,
                has_more: page.has_more,
            })
            .map_err(|error| repository_error(&error))
    }

    fn events_for_run_after(
        &self,
        run_id: RunId,
        sequence: u64,
    ) -> Result<ProtocolEventPage, RepositoryError> {
        Store::events_for_run_after(self, run_id, sequence)
            .map(|page| ProtocolEventPage {
                events: page.events,
                next_sequence: page.next_sequence,
                has_more: page.has_more,
            })
            .map_err(|error| repository_error(&error))
    }

    fn read_artifact(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, RepositoryError> {
        Store::get_artifact(self, artifact).map_err(|error| repository_error(&error))
    }
}

fn repository_error(error: &StoreError) -> RepositoryError {
    RepositoryError::new(
        if error.is_conflict() {
            RepositoryErrorKind::Conflict
        } else if matches!(error, StoreError::Io(source) if source.kind() == std::io::ErrorKind::NotFound)
        {
            RepositoryErrorKind::NotFound
        } else if matches!(
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
    UnsupportedRunPurpose(RunPurpose),
    InvalidRunSpec(&'static str),
    SessionNotFound(SessionId),
    RunNotFound(RunId),
    RunConflict(RunId),
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
            Self::UnsupportedRunPurpose(purpose) => ProtocolError {
                code: ErrorCode::InvalidRequest,
                message: format!("run purpose {purpose:?} is not implemented by this runtime"),
                retryable: false,
            },
            Self::InvalidRunSpec(reason) => ProtocolError {
                code: ErrorCode::InvalidRequest,
                message: (*reason).to_owned(),
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
            Self::RunConflict(id) => ProtocolError {
                code: ErrorCode::Conflict,
                message: format!("run {id} already exists with a different specification"),
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
            Self::UnsupportedRunPurpose(purpose) => {
                write!(formatter, "run purpose {purpose:?} is not implemented")
            }
            Self::InvalidRunSpec(reason) => {
                write!(formatter, "invalid run specification: {reason}")
            }
            Self::SessionNotFound(id) => write!(formatter, "session {id} was not found"),
            Self::RunNotFound(id) => write!(formatter, "run {id} was not found"),
            Self::RunConflict(id) => {
                write!(
                    formatter,
                    "run {id} already exists with a different specification"
                )
            }
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
            capabilities: RuntimeCapabilities::new([
                RuntimeCapability::DurableSessions,
                RuntimeCapability::EventReplay,
                RuntimeCapability::Cancellation,
            ]),
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
        if request.spec.purpose != RunPurpose::PlanOnly {
            return Err(RuntimeError::UnsupportedRunPurpose(request.spec.purpose));
        }
        if self
            .repository
            .get_session(request.spec.session_id)?
            .is_none()
        {
            return Err(RuntimeError::SessionNotFound(request.spec.session_id));
        }
        validate_plan_only_spec(&request)?;
        if let Some(existing) = self.repository.get_run(request.run_id)? {
            return if existing.spec == request.spec {
                Ok(existing)
            } else {
                Err(RuntimeError::RunConflict(request.run_id))
            };
        }
        let run = Run::with_id(request.run_id, request.spec);
        let insertion = self.repository.insert_run(
            &run,
            NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id: self.actor_id,
                causal_parent: None,
                provenance: runtime_provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            },
        );
        match insertion {
            Ok(()) => Ok(run),
            Err(error) if error.kind() == RepositoryErrorKind::Conflict => {
                match self.repository.get_run(run.id)? {
                    Some(existing) if existing.spec == run.spec => Ok(existing),
                    Some(_) => Err(RuntimeError::RunConflict(run.id)),
                    None => Err(RuntimeError::Repository(error)),
                }
            }
            Err(error) => Err(RuntimeError::Repository(error)),
        }
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

    /// Replays one bounded page of authoritative session events.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::SessionNotFound`] for an unknown session or a
    /// repository error when replay is unavailable.
    pub fn get_events(
        &self,
        session_id: SessionId,
        after_sequence: u64,
    ) -> Result<ProtocolEventPage, RuntimeError> {
        if self.repository.get_session(session_id)?.is_none() {
            return Err(RuntimeError::SessionNotFound(session_id));
        }
        self.repository
            .events_after(session_id, after_sequence)
            .map_err(RuntimeError::from)
    }

    /// Reads one bounded chunk from an exact content-addressed artifact.
    ///
    /// The repository verifies the complete artifact against its reference
    /// before any bytes are returned. This method then applies only mechanical
    /// cursor arithmetic; it never accepts or exposes a filesystem path.
    ///
    /// # Errors
    ///
    /// Returns a repository error for missing, corrupt, or unavailable bytes.
    pub fn get_artifact(
        &self,
        request: &GetArtifactRequest,
    ) -> Result<ArtifactChunk, RuntimeError> {
        let bytes = self.repository.read_artifact(request.artifact())?;
        let offset = usize::try_from(request.offset()).map_err(|_| {
            RuntimeError::Repository(RepositoryError::new(
                RepositoryErrorKind::Internal,
                "artifact offset cannot be represented on this platform",
            ))
        })?;
        let requested = request.max_bytes() as usize;
        let end = offset.saturating_add(requested).min(bytes.len());
        let chunk = bytes[offset..end].to_vec();
        let eof = end == bytes.len();
        ArtifactChunk::new(request.artifact().clone(), request.offset(), chunk, eof).map_err(
            |error| {
                RuntimeError::Repository(RepositoryError::new(
                    RepositoryErrorKind::Internal,
                    format!("verified artifact violated its wire contract: {error}"),
                ))
            },
        )
    }

    /// Durably records cancellation before changing any local run state.
    ///
    /// Queued and waiting runs have no active provider future, so their state
    /// is transitioned immediately after the cancellation record. A running
    /// run remains running until its supervisor observes the durable request,
    /// stops external work, and records the terminal transition.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::RunNotFound`] for an unknown run or a repository
    /// error when the request cannot be retained.
    pub fn cancel_run(&mut self, run_id: RunId) -> Result<CancellationReceipt, RuntimeError> {
        let cancellation_request_id = CancellationRequestId::new();
        let cancellation_generation = 1;

        // Claim heartbeats and cancellation both extend the same causal run
        // history. Re-read and retry a bounded number of times when a heartbeat
        // wins between replay and append; cancellation itself remains a single,
        // stable idempotent request.
        for attempt in 0..MAX_CANCELLATION_APPEND_ATTEMPTS {
            let run = self.get_run(run_id)?;
            let events = self.run_events(&run)?;
            let previous = latest_cancellation(&events);
            if is_terminal(run.state) {
                return Ok(previous.map_or_else(
                    || CancellationReceipt {
                        run_id,
                        cancellation_request_id,
                        cancellation_generation: 0,
                        disposition: CancellationDisposition::RunAlreadyTerminal,
                    },
                    |(_event, cancellation)| CancellationReceipt {
                        run_id,
                        cancellation_request_id: cancellation.cancellation_request_id,
                        cancellation_generation: cancellation.cancellation_generation,
                        disposition: CancellationDisposition::RunAlreadyTerminal,
                    },
                ));
            }
            if let Some((event, cancellation)) = previous {
                self.finish_inactive_cancellation(&run, event.id)?;
                return Ok(CancellationReceipt {
                    run_id,
                    cancellation_request_id: cancellation.cancellation_request_id,
                    cancellation_generation: cancellation.cancellation_generation,
                    disposition: CancellationDisposition::AlreadyRequested,
                });
            }

            let appended = self.repository.append_event(NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id: self.actor_id,
                causal_parent: events.last().map(|event| event.id),
                provenance: runtime_provenance(),
                payload: EventPayload::CancellationRequested(CancellationRequested {
                    cancellation_request_id,
                    cancellation_generation,
                }),
            });
            match appended {
                Ok(cancellation_event) => {
                    self.finish_inactive_cancellation(&run, cancellation_event.id)?;
                    return Ok(CancellationReceipt {
                        run_id,
                        cancellation_request_id,
                        cancellation_generation,
                        disposition: CancellationDisposition::Recorded,
                    });
                }
                Err(error) if attempt + 1 < MAX_CANCELLATION_APPEND_ATTEMPTS => {
                    // The next iteration replays authoritative state. This may
                    // reveal another caller's cancellation or a newer claim.
                    let _ = error;
                }
                Err(error) => return Err(RuntimeError::Repository(error)),
            }
        }
        unreachable!("bounded cancellation loop always returns on its final attempt")
    }

    fn finish_inactive_cancellation(
        &mut self,
        original: &Run,
        cancellation_event_id: birdcode_protocol::EventId,
    ) -> Result<(), RuntimeError> {
        let current = self.get_run(original.id)?;
        if !matches!(current.state, RunState::Queued | RunState::Waiting) {
            return Ok(());
        }
        let transition = self.repository.append_event(NewEvent {
            session_id: current.spec.session_id,
            run_id: Some(current.id),
            actor_id: self.actor_id,
            causal_parent: Some(cancellation_event_id),
            provenance: runtime_provenance(),
            payload: EventPayload::RunStateChanged {
                from: current.state,
                to: RunState::Cancelled,
            },
        });
        match transition {
            Ok(_) => Ok(()),
            Err(error) => {
                let refreshed = self.get_run(current.id)?;
                if refreshed.state == RunState::Cancelled {
                    Ok(())
                } else {
                    Err(RuntimeError::Repository(error))
                }
            }
        }
    }

    fn run_events(&self, run: &Run) -> Result<Vec<EventEnvelope>, RuntimeError> {
        let mut cursor = 0;
        let mut events = Vec::new();
        loop {
            let page = self.repository.events_for_run_after(run.id, cursor)?;
            events.extend(page.events);
            if !page.has_more {
                return Ok(events);
            }
            if page.next_sequence <= cursor {
                return Err(RuntimeError::Repository(RepositoryError::new(
                    RepositoryErrorKind::Internal,
                    "event replay cursor did not advance",
                )));
            }
            cursor = page.next_sequence;
        }
    }
}

fn validate_plan_only_spec(request: &CreateRunRequest) -> Result<(), RuntimeError> {
    if request.spec.backend.kind != BackendKind::Model {
        return Err(RuntimeError::InvalidRunSpec(
            "plan-only runs require a model backend",
        ));
    }
    if request.spec.backend.backend_id.trim().is_empty() {
        return Err(RuntimeError::InvalidRunSpec("backend_id must not be blank"));
    }
    if request
        .spec
        .backend
        .model
        .as_deref()
        .is_none_or(|model| model.trim().is_empty())
    {
        return Err(RuntimeError::InvalidRunSpec(
            "plan-only runs require an explicit model",
        ));
    }
    if request.spec.input.is_empty() {
        return Err(RuntimeError::InvalidRunSpec(
            "plan-only runs require at least one text input",
        ));
    }
    for item in &request.spec.input {
        match item {
            InputItem::Text { text } if !text.trim().is_empty() => {}
            InputItem::Text { .. } => {
                return Err(RuntimeError::InvalidRunSpec(
                    "plan-only text input must not be blank",
                ));
            }
            InputItem::Artifact { .. } => {
                return Err(RuntimeError::InvalidRunSpec(
                    "artifact input is not implemented for plan-only runs",
                ));
            }
        }
    }
    if request.spec.limits.max_output_tokens == Some(0) {
        return Err(RuntimeError::InvalidRunSpec(
            "max_output_tokens must be greater than zero",
        ));
    }
    if request
        .spec
        .limits
        .max_output_tokens
        .is_some_and(|limit| limit > u64::from(crate::planning::MAX_ROOT_PLANNER_OUTPUT_TOKENS))
    {
        return Err(RuntimeError::InvalidRunSpec(
            "max_output_tokens exceeds the PlanOnly hard limit",
        ));
    }
    if request.spec.limits.max_wall_time_seconds == Some(0) {
        return Err(RuntimeError::InvalidRunSpec(
            "max_wall_time_seconds must be greater than zero",
        ));
    }
    if request.spec.limits.max_subagents != 0 {
        return Err(RuntimeError::InvalidRunSpec(
            "the read-only plan slice does not authorize subagents",
        ));
    }
    Ok(())
}

fn latest_cancellation(
    events: &[EventEnvelope],
) -> Option<(&EventEnvelope, &CancellationRequested)> {
    events.iter().rev().find_map(|event| match &event.payload {
        EventPayload::CancellationRequested(cancellation) => Some((event, cancellation)),
        _ => None,
    })
}

const fn is_terminal(state: RunState) -> bool {
    matches!(
        state,
        RunState::Completed | RunState::Failed | RunState::Cancelled
    )
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
        repository_error, runtime_provenance,
    };
    use birdcode_protocol::{
        BackendKind, BackendSelection, CancellationDisposition, ClientIdentity, CreateRunRequest,
        CreateSessionRequest, EventEnvelope, EventPage as ProtocolEventPage, EventPayload,
        GetArtifactRequest, InitializeRequest, InputItem, NewEvent, PROTOCOL_VERSION, Run, RunId,
        RunLimits, RunPurpose, RunSpec, RunState, Session, SessionId,
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

        fn append_event(&mut self, _event: NewEvent) -> Result<EventEnvelope, RepositoryError> {
            Err(RepositoryError::new(
                RepositoryErrorKind::Internal,
                "memory fixture does not implement generic append",
            ))
        }

        fn events_after(
            &self,
            _session_id: SessionId,
            sequence: u64,
        ) -> Result<ProtocolEventPage, RepositoryError> {
            Ok(ProtocolEventPage {
                events: Vec::new(),
                next_sequence: sequence,
                has_more: false,
            })
        }

        fn events_for_run_after(
            &self,
            _run_id: RunId,
            sequence: u64,
        ) -> Result<ProtocolEventPage, RepositoryError> {
            Ok(ProtocolEventPage {
                events: Vec::new(),
                next_sequence: sequence,
                has_more: false,
            })
        }

        fn read_artifact(
            &self,
            _artifact: &birdcode_protocol::ArtifactRef,
        ) -> Result<Vec<u8>, RepositoryError> {
            Err(RepositoryError::new(
                RepositoryErrorKind::NotFound,
                "memory fixture has no artifacts",
            ))
        }
    }

    fn plan_limits() -> RunLimits {
        RunLimits {
            max_subagents: 0,
            ..RunLimits::default()
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
    fn advertises_only_runtime_capabilities_with_end_to_end_handlers() {
        let runtime = LocalRuntime::new(MemoryRepository::default());
        let initialized = runtime
            .initialize(&InitializeRequest {
                protocol_version: PROTOCOL_VERSION,
                client: ClientIdentity {
                    name: "capability-test".to_owned(),
                    version: "0".to_owned(),
                },
            })
            .expect("matching protocol should initialize");

        assert!(
            initialized
                .capabilities
                .supports(birdcode_protocol::RuntimeCapability::DurableSessions)
        );
        assert!(
            initialized
                .capabilities
                .supports(birdcode_protocol::RuntimeCapability::EventReplay)
        );
        assert!(
            initialized
                .capabilities
                .supports(birdcode_protocol::RuntimeCapability::Cancellation)
        );
        assert!(
            !initialized
                .capabilities
                .supports(birdcode_protocol::RuntimeCapability::DurableRootPlanning)
        );
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
                run_id: RunId::new(),
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "not-connected".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("model-id".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Planera detta utan att fabricera resultat 日本語".to_owned(),
                    }],
                    limits: plan_limits(),
                },
            })
            .expect("run should be created");

        assert_eq!(runtime.get_session(session.id).unwrap(), session);
        assert_eq!(runtime.get_run(run.id).unwrap(), run);
        assert_eq!(run.state, RunState::Queued);
    }

    #[test]
    fn client_run_identity_is_idempotent_and_conflicting_specs_fail_closed() {
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/idempotent-plan").into(),
                title: None,
            })
            .expect("session should be created");
        let run_id = RunId::new();
        let request = CreateRunRequest {
            run_id,
            spec: RunSpec {
                session_id: session.id,
                purpose: RunPurpose::PlanOnly,
                backend: BackendSelection {
                    backend_id: "lmstudio".to_owned(),
                    kind: BackendKind::Model,
                    model: Some("local-model".to_owned()),
                    reasoning_effort: None,
                },
                input: vec![InputItem::Text {
                    text: "Planera detta utan att skriva filer。".to_owned(),
                }],
                limits: plan_limits(),
            },
        };

        let first = runtime
            .create_run(request.clone())
            .expect("first submission should persist");
        let replay = runtime
            .create_run(request.clone())
            .expect("identical submission should be idempotent");
        assert_eq!(replay, first);

        let mut conflicting = request;
        conflicting.spec.input = vec![InputItem::Text {
            text: "Ett annat mål".to_owned(),
        }];
        assert!(matches!(
            runtime.create_run(conflicting),
            Err(RuntimeError::RunConflict(id)) if id == run_id
        ));
    }

    #[test]
    fn refuses_run_for_unknown_session() {
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let missing = SessionId::new();
        let error = runtime
            .create_run(CreateRunRequest {
                run_id: RunId::new(),
                spec: RunSpec {
                    session_id: missing,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "not-connected".to_owned(),
                        kind: BackendKind::Agent,
                        model: None,
                        reasoning_effort: None,
                    },
                    input: Vec::new(),
                    limits: plan_limits(),
                },
            })
            .expect_err("unknown parent session must fail");

        assert!(matches!(error, RuntimeError::SessionNotFound(id) if id == missing));
    }

    #[test]
    fn rejects_reserved_execute_purpose_before_persisting_a_run() {
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/plan-only-runtime").into(),
                title: None,
            })
            .expect("session should be created");
        let run_id = RunId::new();

        let error = runtime
            .create_run(CreateRunRequest {
                run_id,
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::Execute,
                    backend: BackendSelection {
                        backend_id: "lmstudio".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("local-model".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Implement this".to_owned(),
                    }],
                    limits: plan_limits(),
                },
            })
            .expect_err("execute is reserved but not implemented");

        assert!(matches!(
            error,
            RuntimeError::UnsupportedRunPurpose(RunPurpose::Execute)
        ));
        assert!(runtime.get_run(run_id).is_err());
    }

    #[test]
    fn plan_only_run_cannot_smuggle_subagent_authority() {
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/plan-without-delegation").into(),
                title: None,
            })
            .expect("session should be created");
        let run_id = RunId::new();

        let error = runtime
            .create_run(CreateRunRequest {
                run_id,
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "lmstudio".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("local-model".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Skapa en plan men delegera ännu inte.".to_owned(),
                    }],
                    limits: RunLimits {
                        max_subagents: 1,
                        ..RunLimits::default()
                    },
                },
            })
            .expect_err("plan-only must not imply child-agent authority");

        assert!(matches!(error, RuntimeError::InvalidRunSpec(_)));
        assert!(runtime.get_run(run_id).is_err());
    }

    #[test]
    fn plan_only_run_rejects_output_budget_above_the_compiler_ceiling() {
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/plan-output-ceiling").into(),
                title: None,
            })
            .expect("session should be created");
        let run_id = RunId::new();

        let error = runtime
            .create_run(CreateRunRequest {
                run_id,
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "lmstudio".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("local-model".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Plan this within the declared compiler limit.".to_owned(),
                    }],
                    limits: RunLimits {
                        max_output_tokens: Some(
                            u64::from(crate::planning::MAX_ROOT_PLANNER_OUTPUT_TOKENS) + 1,
                        ),
                        ..RunLimits::default()
                    },
                },
            })
            .expect_err("the runtime must reject an unrepresentable PlanOnly budget");

        assert!(matches!(error, RuntimeError::InvalidRunSpec(_)));
        assert!(runtime.get_run(run_id).is_err());
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
    fn artifact_reads_are_exact_verified_and_wire_bounded() {
        let directory = TempDir::new().expect("temporary directory should be created");
        let store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("store should open");
        let bytes = "BirdCode håller 日本語 och العربية byte-exakt".as_bytes();
        let artifact = store
            .put_artifact(bytes, "application/json")
            .expect("artifact should persist");
        let runtime = LocalRuntime::new(store);

        let first = runtime
            .get_artifact(
                &GetArtifactRequest::new(artifact.clone(), 0, 11)
                    .expect("first read should be valid"),
            )
            .expect("first chunk should be returned");
        assert_eq!(first.data(), &bytes[..11]);
        assert_eq!(first.next_offset(), 11);
        assert!(!first.eof());

        let remainder = runtime
            .get_artifact(
                &GetArtifactRequest::new(artifact.clone(), first.next_offset(), 256)
                    .expect("remainder read should be valid"),
            )
            .expect("remainder should be returned");
        assert_eq!(remainder.data(), &bytes[11..]);
        assert_eq!(remainder.next_offset(), artifact.size_bytes);
        assert!(remainder.eof());

        let mut forged = artifact;
        forged.size_bytes += 1;
        let error = runtime
            .get_artifact(
                &GetArtifactRequest::new(forged, 0, 16).expect("the wire shape itself is valid"),
            )
            .expect_err("metadata forgery must fail against stored content");
        assert!(matches!(error, RuntimeError::Repository(_)));
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
                    run_id: RunId::new(),
                    spec: RunSpec {
                        session_id: session.id,
                        purpose: RunPurpose::PlanOnly,
                        backend: BackendSelection {
                            backend_id: "local-test-backend".to_owned(),
                            kind: BackendKind::Model,
                            model: Some("test-only".to_owned()),
                            reasoning_effort: None,
                        },
                        input: vec![InputItem::Text {
                            text: "Bevara svenska och 日本語 exakt".to_owned(),
                        }],
                        limits: plan_limits(),
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

    #[test]
    fn queued_cancellation_is_durable_before_terminal_state_and_replayable() {
        let directory = TempDir::new().expect("temporary directory should be created");
        let database = directory.path().join("state.sqlite3");
        let artifacts = directory.path().join("artifacts");
        let store = Store::open(&database, &artifacts).expect("store should open");
        let mut runtime = LocalRuntime::new(store);
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/cancel-plan").into(),
                title: Some("Cancellation provenance".to_owned()),
            })
            .expect("session should persist");
        let run_id = RunId::new();
        runtime
            .create_run(CreateRunRequest {
                run_id,
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "lmstudio".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("local-model".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Planera robust。".to_owned(),
                    }],
                    limits: plan_limits(),
                },
            })
            .expect("run should persist");

        let receipt = runtime
            .cancel_run(run_id)
            .expect("cancellation should persist");
        assert_eq!(receipt.disposition, CancellationDisposition::Recorded);
        assert_eq!(receipt.cancellation_generation, 1);
        assert_eq!(runtime.get_run(run_id).unwrap().state, RunState::Cancelled);

        let replay = runtime
            .get_events(session.id, 0)
            .expect("events should replay");
        assert_eq!(replay.events.len(), 4);
        let cancellation = &replay.events[2];
        let terminal = &replay.events[3];
        assert!(matches!(
            cancellation.payload,
            EventPayload::CancellationRequested(_)
        ));
        assert_eq!(cancellation.causal_parent, Some(replay.events[1].id));
        assert!(matches!(
            terminal.payload,
            EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Cancelled
            }
        ));
        assert_eq!(terminal.causal_parent, Some(cancellation.id));

        let repeated = runtime
            .cancel_run(run_id)
            .expect("terminal cancellation should be idempotent");
        assert_eq!(
            repeated.disposition,
            CancellationDisposition::RunAlreadyTerminal
        );
        assert_eq!(
            repeated.cancellation_request_id,
            receipt.cancellation_request_id
        );
        assert_eq!(
            runtime.get_events(session.id, 0).unwrap().events.len(),
            replay.events.len()
        );

        drop(runtime);
        let reopened = LocalRuntime::new(
            Store::open(database, artifacts).expect("store should reopen after cancellation"),
        );
        assert_eq!(reopened.get_run(run_id).unwrap().state, RunState::Cancelled);
        assert_eq!(
            reopened.get_events(session.id, 0).unwrap().events,
            replay.events
        );
    }

    #[test]
    fn replacement_runtime_finishes_a_durable_inactive_cancellation() {
        let directory = TempDir::new().expect("temporary directory should be created");
        let database = directory.path().join("state.sqlite3");
        let artifacts = directory.path().join("artifacts");
        let store = Store::open(&database, &artifacts).expect("store should open");
        let mut runtime = LocalRuntime::new(store);
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/restart-cancel-plan").into(),
                title: Some("Crash-safe cancellation".to_owned()),
            })
            .expect("session should persist");
        let run_id = RunId::new();
        runtime
            .create_run(CreateRunRequest {
                run_id,
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "lmstudio".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("local-model".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Avbryt hållbart före omstart。".to_owned(),
                    }],
                    limits: plan_limits(),
                },
            })
            .expect("run should persist");
        drop(runtime);

        let cancellation_request_id = birdcode_protocol::CancellationRequestId::new();
        let cancellation_actor = birdcode_protocol::ActorId::new();
        let mut interrupted_store =
            Store::open(&database, &artifacts).expect("store should reopen at crash boundary");
        let run_created = interrupted_store
            .events_for_run_after(run_id, 0)
            .expect("run history should load")
            .events
            .pop()
            .expect("run-created event should exist");
        let cancellation = interrupted_store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run_id),
                actor_id: cancellation_actor,
                causal_parent: Some(run_created.id),
                provenance: runtime_provenance(),
                payload: EventPayload::CancellationRequested(
                    birdcode_protocol::CancellationRequested {
                        cancellation_request_id,
                        cancellation_generation: 1,
                    },
                ),
            })
            .expect("durable cancellation should survive the simulated crash");
        drop(interrupted_store);

        let mut replacement = LocalRuntime::new(
            Store::open(&database, &artifacts).expect("replacement runtime should reopen store"),
        );
        let receipt = replacement
            .cancel_run(run_id)
            .expect("replacement runtime should finish existing cancellation");
        assert_eq!(
            receipt.disposition,
            CancellationDisposition::AlreadyRequested
        );
        assert_eq!(receipt.cancellation_request_id, cancellation_request_id);
        assert_eq!(
            replacement.get_run(run_id).unwrap().state,
            RunState::Cancelled
        );

        let replay = replacement
            .get_events(session.id, 0)
            .expect("terminal history should replay");
        let terminal = replay
            .events
            .last()
            .expect("terminal transition should exist");
        assert_eq!(terminal.causal_parent, Some(cancellation.id));
        assert_ne!(terminal.actor_id, cancellation_actor);
        assert!(matches!(
            terminal.payload,
            EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Cancelled
            }
        ));
    }
}
