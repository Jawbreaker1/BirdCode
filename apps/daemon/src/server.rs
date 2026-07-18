use crate::{FrameError, JsonLines};
use birdcode_protocol::{
    ClientCommand, ClientRequest, ErrorCode, ProtocolError, ServerResponse, ServerResult,
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
    let mut connection = JsonLines::new(reader, writer);
    let mut initialized = false;

    loop {
        let Some(request) = connection.read::<ClientRequest>()? else {
            return Ok(());
        };
        let request_id = request.id;
        let response = match request.command {
            ClientCommand::Initialize(parameters) => match runtime.initialize(&parameters) {
                Ok(result) => {
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
            ClientCommand::CreateRun(parameters) => runtime.create_run(parameters).map_or_else(
                |error| runtime_error_response(request_id, &error),
                |run| ServerResponse::success(request_id, ServerResult::Run(run)),
            ),
            ClientCommand::GetRun { run_id } => runtime.get_run(run_id).map_or_else(
                |error| runtime_error_response(request_id, &error),
                |run| ServerResponse::success(request_id, ServerResult::Run(run)),
            ),
        };
        connection.write(&response)?;
    }
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
        ClientCommand::CreateSession(_) => "create_session",
        ClientCommand::GetSession { .. } => "get_session",
        ClientCommand::CreateRun(_) => "create_run",
        ClientCommand::GetRun { .. } => "get_run",
    }
}

#[cfg(test)]
mod tests {
    use super::serve;
    use birdcode_protocol::{
        ClientCommand, ClientIdentity, ClientRequest, ErrorCode, InitializeRequest, NewEvent,
        PROTOCOL_VERSION, ResponseOutcome, Run, RunId, ServerResponse, ServerResult, Session,
        SessionId,
    };
    use birdcode_runtime::{LocalRuntime, Repository, RepositoryError};
    use std::collections::HashMap;
    use std::io::{BufReader, Cursor};
    use std::sync::Mutex;

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
}
