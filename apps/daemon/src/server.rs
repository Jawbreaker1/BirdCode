use crate::{
    FrameError, JsonLines, RunSupervisor, SupervisorDiscoveryError, SupervisorSubmitError,
};
use birdcode_protocol::{
    ClientCommand, ClientRequest, ErrorCode, ProtocolError, RunState, RuntimeCapability,
    ServerResponse, ServerResult,
};
use birdcode_runtime::{LocalRuntime, Repository, RuntimeError};
use std::io::{BufRead, Write};

/// Serves one ordered daemon connection until its input reaches EOF.
///
/// # Errors
///
/// Returns a framing error if stdin cannot be read or a typed response cannot
/// be written. Runtime errors are returned to the client as protocol values.
pub fn serve<R, Reader, Writer>(
    runtime: &mut LocalRuntime<R>,
    reader: Reader,
    writer: Writer,
) -> Result<(), FrameError>
where
    R: Repository,
    Reader: BufRead,
    Writer: Write,
{
    serve_inner(runtime, None, reader, writer)
}

/// Serves one daemon connection backed by the durable root-plan supervisor.
/// Model inference stays on the supervisor's background runtime, so ordered
/// health, event, cancellation, and artifact RPCs remain responsive.
///
/// # Errors
///
/// Returns a framing error if the transport cannot read or write a frame.
pub fn serve_with_supervisor<R, Reader, Writer>(
    runtime: &mut LocalRuntime<R>,
    supervisor: &RunSupervisor,
    reader: Reader,
    writer: Writer,
) -> Result<(), FrameError>
where
    R: Repository,
    Reader: BufRead,
    Writer: Write,
{
    serve_inner(runtime, Some(supervisor), reader, writer)
}

fn serve_inner<R, Reader, Writer>(
    runtime: &mut LocalRuntime<R>,
    supervisor: Option<&RunSupervisor>,
    reader: Reader,
    writer: Writer,
) -> Result<(), FrameError>
where
    R: Repository,
    Reader: BufRead,
    Writer: Write,
{
    let mut connection = JsonLines::new(reader, writer);
    let mut initialized = false;

    loop {
        let Some(request) = connection.read::<ClientRequest>()? else {
            return Ok(());
        };
        let request_id = request.id;
        let response = match request.command {
            ClientCommand::Initialize(parameters) => match runtime.initialize(&parameters) {
                Ok(mut result) => {
                    if supervisor.is_some() {
                        result
                            .capabilities
                            .supported
                            .insert(RuntimeCapability::DurableRootPlanning);
                    }
                    initialized = true;
                    ServerResponse::success(request_id, ServerResult::Initialized(result))
                }
                Err(error) => runtime_error_response(request_id, &error),
            },
            command if !initialized => ServerResponse::error(
                request_id,
                ProtocolError {
                    code: ErrorCode::InvalidRequest,
                    message: format!("initialize must succeed before {}", command_name(&command)),
                    retryable: false,
                },
            ),
            ClientCommand::Health => {
                ServerResponse::success(request_id, ServerResult::Health(runtime.health()))
            }
            ClientCommand::DiscoverModels => discover_models_response(request_id, supervisor),
            ClientCommand::CreateSession(parameters) => {
                runtime.create_session(parameters).map_or_else(
                    |error| runtime_error_response(request_id, &error),
                    |session| ServerResponse::success(request_id, ServerResult::Session(session)),
                )
            }
            ClientCommand::GetSession { session_id } => {
                runtime.get_session(session_id).map_or_else(
                    |error| runtime_error_response(request_id, &error),
                    |session| ServerResponse::success(request_id, ServerResult::Session(session)),
                )
            }
            ClientCommand::CreateRun(parameters) => {
                create_run_response(runtime, supervisor, request_id, parameters)
            }
            ClientCommand::GetRun { run_id } => runtime.get_run(run_id).map_or_else(
                |error| runtime_error_response(request_id, &error),
                |run| ServerResponse::success(request_id, ServerResult::Run(run)),
            ),
            ClientCommand::GetEvents {
                session_id,
                after_sequence,
            } => runtime.get_events(session_id, after_sequence).map_or_else(
                |error| runtime_error_response(request_id, &error),
                |page| ServerResponse::success(request_id, ServerResult::EventPage(page)),
            ),
            ClientCommand::CancelRun { run_id } => runtime.cancel_run(run_id).map_or_else(
                |error| runtime_error_response(request_id, &error),
                |receipt| {
                    if let Some(supervisor) = supervisor {
                        let _ = supervisor.cancel(run_id);
                    }
                    ServerResponse::success(request_id, ServerResult::CancellationReceipt(receipt))
                },
            ),
            ClientCommand::GetArtifact(parameters) => {
                runtime.get_artifact(&parameters).map_or_else(
                    |error| runtime_error_response(request_id, &error),
                    |chunk| ServerResponse::success(request_id, ServerResult::ArtifactChunk(chunk)),
                )
            }
        };
        connection.write(&response)?;
    }
}

fn discover_models_response(
    request_id: birdcode_protocol::RequestId,
    supervisor: Option<&RunSupervisor>,
) -> ServerResponse {
    supervisor.map_or_else(
        || {
            ServerResponse::error(
                request_id,
                ProtocolError {
                    code: ErrorCode::InvalidRequest,
                    message: "model discovery is not configured for this daemon".to_owned(),
                    retryable: false,
                },
            )
        },
        |supervisor| {
            supervisor.discover_models().map_or_else(
                |error| supervisor_discovery_error_response(request_id, &error),
                |catalog| {
                    ServerResponse::success(request_id, ServerResult::BackendCatalog(catalog))
                },
            )
        },
    )
}

fn create_run_response<R: Repository>(
    runtime: &mut LocalRuntime<R>,
    supervisor: Option<&RunSupervisor>,
    request_id: birdcode_protocol::RequestId,
    parameters: birdcode_protocol::CreateRunRequest,
) -> ServerResponse {
    create_run_response_with_submit(runtime, request_id, parameters, |run_id| {
        supervisor.map(|supervisor| supervisor.submit(run_id).map(|_| ()))
    })
}

fn create_run_response_with_submit<R, Submit>(
    runtime: &mut LocalRuntime<R>,
    request_id: birdcode_protocol::RequestId,
    parameters: birdcode_protocol::CreateRunRequest,
    submit: Submit,
) -> ServerResponse
where
    R: Repository,
    Submit: FnOnce(birdcode_protocol::RunId) -> Option<Result<(), SupervisorSubmitError>>,
{
    match runtime.create_run(parameters) {
        Err(error) => runtime_error_response(request_id, &error),
        Ok(run) => {
            // `create_run` has already crossed the durable commit boundary.
            // Direct submission is only an eager wake-up: the SQLite-backed
            // dispatcher, or a subsequent daemon startup, owns recovery of
            // every nonterminal run. A closed in-memory supervisor therefore
            // cannot retroactively turn the committed mutation into a
            // rejection that would make a client discard its stable run id.
            if matches!(
                run.state,
                RunState::Queued | RunState::Running | RunState::Waiting
            ) {
                let _ = submit(run.id);
            }
            ServerResponse::success(request_id, ServerResult::Run(run))
        }
    }
}

fn supervisor_discovery_error_response(
    request_id: birdcode_protocol::RequestId,
    error: &SupervisorDiscoveryError,
) -> ServerResponse {
    let retryable = !matches!(error, SupervisorDiscoveryError::CatalogTooLarge { .. });
    ServerResponse::error(
        request_id,
        ProtocolError {
            code: ErrorCode::Internal,
            message: error.to_string(),
            retryable,
        },
    )
}

fn runtime_error_response(
    request_id: birdcode_protocol::RequestId,
    error: &RuntimeError,
) -> ServerResponse {
    if matches!(error, RuntimeError::Repository(_)) {
        eprintln!("birdcode-daemon: {error}");
    }
    ServerResponse::error(request_id, error.to_protocol_error())
}

const fn command_name(command: &ClientCommand) -> &'static str {
    match command {
        ClientCommand::Initialize(_) => "initialize",
        ClientCommand::Health => "health",
        ClientCommand::DiscoverModels => "discover_models",
        ClientCommand::CreateSession(_) => "create_session",
        ClientCommand::GetSession { .. } => "get_session",
        ClientCommand::CreateRun(_) => "create_run",
        ClientCommand::GetRun { .. } => "get_run",
        ClientCommand::GetEvents { .. } => "get_events",
        ClientCommand::CancelRun { .. } => "cancel_run",
        ClientCommand::GetArtifact(_) => "get_artifact",
    }
}

#[cfg(test)]
mod tests {
    use super::{create_run_response_with_submit, serve};
    use crate::SupervisorSubmitError;
    use birdcode_protocol::{
        BackendKind, BackendSelection, CancellationDisposition, ClientCommand, ClientIdentity,
        ClientRequest, CreateRunRequest, CreateSessionRequest, ErrorCode, EventEnvelope, EventPage,
        EventPayload, GetArtifactRequest, InitializeRequest, InputItem, NewEvent, PROTOCOL_VERSION,
        RequestId, ResponseOutcome, Run, RunId, RunLimits, RunPurpose, RunSpec, RunState,
        ServerResponse, ServerResult, Session, SessionId,
    };
    use birdcode_runtime::{LocalRuntime, Repository, RepositoryError};
    use birdcode_store::Store;
    use std::collections::HashMap;
    use std::io::{BufReader, Cursor};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tempfile::TempDir;

    #[derive(Default)]
    struct MemoryRepository {
        sessions: Mutex<HashMap<SessionId, Session>>,
        runs: Mutex<HashMap<RunId, Run>>,
    }

    impl Repository for MemoryRepository {
        fn health(&self) -> Result<(), RepositoryError> {
            Ok(())
        }

        fn insert_session(
            &mut self,
            session: &Session,
            _event: NewEvent,
        ) -> Result<(), RepositoryError> {
            self.sessions
                .lock()
                .unwrap()
                .insert(session.id, session.clone());
            Ok(())
        }

        fn get_session(&self, id: SessionId) -> Result<Option<Session>, RepositoryError> {
            Ok(self.sessions.lock().unwrap().get(&id).cloned())
        }

        fn insert_run(&mut self, run: &Run, _event: NewEvent) -> Result<(), RepositoryError> {
            self.runs.lock().unwrap().insert(run.id, run.clone());
            Ok(())
        }

        fn get_run(&self, id: RunId) -> Result<Option<Run>, RepositoryError> {
            Ok(self.runs.lock().unwrap().get(&id).cloned())
        }

        fn append_event(&mut self, _event: NewEvent) -> Result<EventEnvelope, RepositoryError> {
            Err(RepositoryError::new(
                birdcode_runtime::RepositoryErrorKind::Internal,
                "memory fixture does not implement generic append",
            ))
        }

        fn events_after(
            &self,
            _session_id: SessionId,
            sequence: u64,
        ) -> Result<EventPage, RepositoryError> {
            Ok(EventPage {
                events: Vec::new(),
                next_sequence: sequence,
                has_more: false,
            })
        }

        fn events_for_run_after(
            &self,
            _run_id: RunId,
            sequence: u64,
        ) -> Result<EventPage, RepositoryError> {
            Ok(EventPage {
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
                birdcode_runtime::RepositoryErrorKind::NotFound,
                "memory fixture has no artifacts",
            ))
        }
    }

    fn protocol_v4_requests(session_id: SessionId, run_id: RunId) -> [ClientRequest; 6] {
        [
            ClientRequest::new(ClientCommand::Initialize(InitializeRequest {
                protocol_version: PROTOCOL_VERSION,
                client: ClientIdentity {
                    name: "daemon-v3-test".to_owned(),
                    version: "0".to_owned(),
                },
            })),
            ClientRequest::new(ClientCommand::CreateRun(CreateRunRequest {
                run_id,
                spec: RunSpec {
                    session_id,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "lmstudio".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("local-model".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Planera säkert på svenska och 日本語。".to_owned(),
                    }],
                    limits: RunLimits {
                        max_subagents: 0,
                        ..RunLimits::default()
                    },
                },
            })),
            ClientRequest::new(ClientCommand::GetEvents {
                session_id,
                after_sequence: 0,
            }),
            ClientRequest::new(ClientCommand::CancelRun { run_id }),
            ClientRequest::new(ClientCommand::GetRun { run_id }),
            ClientRequest::new(ClientCommand::GetEvents {
                session_id,
                after_sequence: 0,
            }),
        ]
    }

    #[test]
    fn closed_supervisor_cannot_reject_or_reidentify_a_committed_run() {
        let directory = TempDir::new().expect("temporary state should be created");
        let store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("store should open");
        let mut runtime = LocalRuntime::new(store);
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/closed-supervisor-plan").into(),
                title: Some("Durable closed-supervisor boundary".to_owned()),
            })
            .expect("session should persist");
        let request = CreateRunRequest {
            run_id: RunId::new(),
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
                    text: "Behåll samma körningsidentitet efter durable commit.".to_owned(),
                }],
                limits: RunLimits {
                    max_subagents: 0,
                    ..RunLimits::default()
                },
            },
        };
        let mut submit_calls = 0_u8;

        let first_response = create_run_response_with_submit(
            &mut runtime,
            RequestId::new(),
            request.clone(),
            |_| {
                submit_calls += 1;
                Some(Err(SupervisorSubmitError::Closed))
            },
        );
        let ResponseOutcome::Success {
            result: ServerResult::Run(first),
        } = first_response.outcome
        else {
            panic!("a post-commit supervisor closure must still acknowledge the durable run");
        };
        assert_eq!(first.id, request.run_id);
        assert_eq!(first.spec, request.spec);
        assert_eq!(
            runtime
                .get_run(request.run_id)
                .expect("committed run should remain readable"),
            first
        );

        let replay_response = create_run_response_with_submit(
            &mut runtime,
            RequestId::new(),
            request.clone(),
            |_| {
                submit_calls += 1;
                Some(Err(SupervisorSubmitError::Closed))
            },
        );
        let ResponseOutcome::Success {
            result: ServerResult::Run(replayed),
        } = replay_response.outcome
        else {
            panic!("an exact replay must not become a false rejection");
        };
        assert_eq!(replayed, first);
        assert_eq!(replayed.id, request.run_id);
        assert_eq!(submit_calls, 2);

        let events = runtime
            .get_events(session.id, 0)
            .expect("durable session events should replay");
        assert_eq!(
            events
                .events
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::RunCreated { .. }))
                .count(),
            1,
            "an exact retry must not create a second durable run identity"
        );
    }

    #[test]
    fn requires_initialize_then_reports_typed_health() {
        let health_before = ClientRequest::new(ClientCommand::Health);
        let initialize = ClientRequest::new(ClientCommand::Initialize(InitializeRequest {
            protocol_version: PROTOCOL_VERSION,
            client: ClientIdentity {
                name: "daemon-test".to_owned(),
                version: "0".to_owned(),
            },
        }));
        let health_after = ClientRequest::new(ClientCommand::Health);
        let input = [health_before, initialize, health_after]
            .into_iter()
            .map(|request| serde_json::to_string(&request).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut runtime = LocalRuntime::new(MemoryRepository::default());
        let mut output = Vec::new();

        serve(
            &mut runtime,
            BufReader::new(Cursor::new(input.into_bytes())),
            &mut output,
        )
        .expect("connection should complete");

        let responses: Vec<ServerResponse> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 3);
        assert!(matches!(
            &responses[0].outcome,
            ResponseOutcome::Error { error } if error.code == ErrorCode::InvalidRequest
        ));
        assert!(matches!(
            &responses[1].outcome,
            ResponseOutcome::Success {
                result: ServerResult::Initialized(_)
            }
        ));
        assert!(matches!(
            &responses[2].outcome,
            ResponseOutcome::Success {
                result: ServerResult::Health(_)
            }
        ));
    }

    #[test]
    fn protocol_v4_replays_events_and_records_cancellation_before_terminal_state() {
        let directory = TempDir::new().expect("temporary state should be created");
        let store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("store should open");
        let mut runtime = LocalRuntime::new(store);
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/daemon-plan").into(),
                title: Some("Plan-only daemon test".to_owned()),
            })
            .expect("session should persist");
        let run_id = RunId::new();
        let requests = protocol_v4_requests(session.id, run_id);
        let input = requests
            .iter()
            .map(|request| serde_json::to_string(request).expect("request should encode"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();

        serve(
            &mut runtime,
            BufReader::new(Cursor::new(input.into_bytes())),
            &mut output,
        )
        .expect("connection should complete");

        let responses = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<ServerResponse>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), requests.len());
        let result = |index: usize| match &responses[index].outcome {
            ResponseOutcome::Success { result } => result,
            ResponseOutcome::Error { error } => panic!("unexpected protocol error: {error:?}"),
        };
        assert!(matches!(result(1), ServerResult::Run(run) if run.id == run_id));
        assert!(matches!(
            result(2),
            ServerResult::EventPage(page) if page.events.len() == 2
        ));
        assert!(matches!(
            result(3),
            ServerResult::CancellationReceipt(receipt)
                if receipt.disposition == CancellationDisposition::Recorded
        ));
        assert!(matches!(
            result(4),
            ServerResult::Run(run) if run.state == RunState::Cancelled
        ));
        let ServerResult::EventPage(page) = result(5) else {
            panic!("expected final event page");
        };
        assert_eq!(page.events.len(), 4);
        assert!(matches!(
            page.events[2].payload,
            EventPayload::CancellationRequested(_)
        ));
        assert!(matches!(
            page.events[3].payload,
            EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Cancelled
            }
        ));
        assert_eq!(page.events[3].causal_parent, Some(page.events[2].id));
    }

    #[test]
    fn artifact_rpc_returns_only_a_bounded_chunk_bound_to_the_exact_reference() {
        let directory = TempDir::new().expect("temporary state should be created");
        let store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("store should open");
        let bytes = b"0123456789abcdef";
        let artifact = store
            .put_artifact(bytes, "application/octet-stream")
            .expect("artifact should persist");
        let mut runtime = LocalRuntime::new(store);
        let requests = [
            ClientRequest::new(ClientCommand::Initialize(InitializeRequest {
                protocol_version: PROTOCOL_VERSION,
                client: ClientIdentity {
                    name: "daemon-artifact-test".to_owned(),
                    version: "0".to_owned(),
                },
            })),
            ClientRequest::new(ClientCommand::GetArtifact(
                GetArtifactRequest::new(artifact.clone(), 4, 5)
                    .expect("bounded request should be valid"),
            )),
        ];
        let input = requests
            .iter()
            .map(|request| serde_json::to_string(request).expect("request should encode"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();

        serve(
            &mut runtime,
            BufReader::new(Cursor::new(input.into_bytes())),
            &mut output,
        )
        .expect("connection should complete");

        let responses = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<ServerResponse>(line).unwrap())
            .collect::<Vec<_>>();
        let ResponseOutcome::Success {
            result: ServerResult::ArtifactChunk(chunk),
        } = &responses[1].outcome
        else {
            panic!("expected a successful artifact chunk");
        };
        assert_eq!(chunk.artifact(), &artifact);
        assert_eq!(chunk.offset(), 4);
        assert_eq!(chunk.next_offset(), 9);
        assert_eq!(chunk.data(), b"45678");
        assert!(!chunk.eof());
    }
}
