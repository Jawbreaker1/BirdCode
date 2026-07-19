use birdcode_client::{
    ClientError, ClientTimeouts, CreateRunFailure, DAEMON_REQUEST_FRAME_BYTES, DaemonClient,
    PendingCreateRun, resolve_daemon_path,
};
use birdcode_prompting::{RootPlannerDirective, RootPlannerOutput, VerificationKind};
use birdcode_protocol::{
    ArtifactChunk, ArtifactRef, BackendCatalog, BackendKind, BackendSelection, CancellationReceipt,
    ClientCommand, CreateRunRequest, CreateSessionRequest, EventEnvelope, EventPayload, Health,
    HealthStatus, InitializeResult, InputItem, MAX_ARTIFACT_CHUNK_BYTES, PlanProposalAccepted,
    PlannerInferenceObservation, RunId, RunLimits, RunPurpose, RunSpec, RunState,
    RuntimeCapability, ServerResult, SessionId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Manager;

const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(250);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(8);
const LM_STUDIO_BACKEND_ID: &str = "lmstudio";
const ACCEPTED_PLAN_MEDIA_TYPE: &str = "application/vnd.birdcode.accepted-plan+json";
const MAX_DESKTOP_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVENT_PAGES_PER_POLL: usize = 32;
const MAX_ROOT_PLANNER_OUTPUT_TOKENS: u64 = 16_384;
// Leave substantial room in the daemon's one-MiB request frame for the
// protocol envelope, run metadata, and future additive fields.
const MAX_DESKTOP_GOAL_BYTES: usize = DAEMON_REQUEST_FRAME_BYTES / 2;
const MAX_DESKTOP_START_REQUEST_BYTES: usize = DAEMON_REQUEST_FRAME_BYTES * 3 / 4;
const _: () = assert!(MAX_DESKTOP_GOAL_BYTES < MAX_DESKTOP_START_REQUEST_BYTES);
const _: () = assert!(MAX_DESKTOP_START_REQUEST_BYTES < DAEMON_REQUEST_FRAME_BYTES);

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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannerModel {
    backend_id: String,
    model_id: String,
    display_name: String,
    context_window_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReasoningEffort {
    Off,
    Low,
    Medium,
    High,
}

impl PlannerReasoningEffort {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartPlanRequest {
    workspace_root: String,
    goal: String,
    backend_id: String,
    model_id: String,
    max_output_tokens: u64,
    max_wall_time_seconds: u64,
    reasoning_effort: Option<PlannerReasoningEffort>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartedPlan {
    session_id: SessionId,
    run_id: RunId,
    state: RunState,
    workspace_root: String,
    model_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationRequiredPlan {
    session_id: SessionId,
    run_id: RunId,
    workspace_root: String,
    model_id: String,
    may_have_executed: bool,
    message: String,
}

#[derive(Serialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum StartPlanOutcome {
    Started(StartedPlan),
    ReconciliationRequired(ReconciliationRequiredPlan),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcilePlanStartRequest {
    run_id: RunId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollPlanRequest {
    session_id: SessionId,
    run_id: RunId,
    after_sequence: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelPlanRequest {
    run_id: RunId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancellationReceiptView {
    run_id: RunId,
    cancellation_request_id: birdcode_protocol::CancellationRequestId,
    cancellation_generation: u64,
    disposition: birdcode_protocol::CancellationDisposition,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanPoll {
    run_id: RunId,
    state: RunState,
    next_sequence: u64,
    events: Vec<PlanEventView>,
    accepted_plan: Option<AcceptedPlanView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanEventView {
    sequence: u64,
    occurred_at: String,
    kind: &'static str,
    tone: &'static str,
    title: &'static str,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedPlanView {
    revision: u64,
    digest: String,
    directive: &'static str,
    rationale: String,
    decision_evidence: Vec<DecisionEvidenceView>,
    work_orders: Vec<WorkOrderView>,
    clarifications: Vec<String>,
    escalations: Vec<EscalationView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionEvidenceView {
    section: String,
    basis: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkOrderView {
    id: String,
    objective: String,
    obligation_ids: Vec<String>,
    dependencies: Vec<String>,
    verification_targets: Vec<VerificationTargetView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationTargetView {
    kind: &'static str,
    selector: String,
    question: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EscalationView {
    reason: String,
    blocked_obligation_ids: Vec<String>,
    requested_decision: String,
}

#[derive(Clone)]
pub struct RuntimeManager {
    inner: Arc<ConnectionManager<DaemonClient>>,
    plan_start: Arc<Mutex<PlanStartLifecycle>>,
}

impl Default for RuntimeManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(ConnectionManager::default()),
            plan_start: Arc::new(Mutex::new(PlanStartLifecycle::Idle)),
        }
    }
}

enum PlanStartLifecycle {
    Idle,
    Starting,
    Pending(PendingPlanStart),
    Reconciling(ReconciliationRequiredPlan),
}

enum BeginPlanStart {
    Reserved(PlanStartReservation),
    ReconciliationRequired(ReconciliationRequiredPlan),
    InProgress(PlanStartOperation),
}

#[derive(Clone, Copy)]
enum PlanStartOperation {
    Starting,
    Reconciling(RunId),
}

enum BeginPlanReconciliation {
    Reserved(Box<PlanReconciliationReservation>),
    InProgress(PlanStartOperation),
    NotPending,
    RunMismatch { requested: RunId, retained: RunId },
}

struct PlanStartReservation {
    lifecycle: Arc<Mutex<PlanStartLifecycle>>,
    active: bool,
}

struct PlanReconciliationReservation {
    lifecycle: Arc<Mutex<PlanStartLifecycle>>,
    pending: Option<PendingPlanStart>,
}

struct PendingPlanStart {
    submission: PendingPlanSubmission,
    session_id: SessionId,
    workspace_root: String,
    model_id: String,
}

enum PendingPlanSubmission {
    NotSubmitted(CreateRunRequest),
    Ambiguous(PendingCreateRun),
}

impl PendingPlanSubmission {
    const fn run_id(&self) -> RunId {
        match self {
            Self::NotSubmitted(request) => request.run_id,
            Self::Ambiguous(pending) => pending.run_id(),
        }
    }
}

impl PendingPlanStart {
    const fn run_id(&self) -> RunId {
        self.submission.run_id()
    }

    fn view(&self, message: impl Into<String>) -> ReconciliationRequiredPlan {
        ReconciliationRequiredPlan {
            session_id: self.session_id,
            run_id: self.run_id(),
            workspace_root: self.workspace_root.clone(),
            model_id: self.model_id.clone(),
            may_have_executed: matches!(self.submission, PendingPlanSubmission::Ambiguous(_)),
            message: message.into(),
        }
    }
}

enum PlanStartAttempt {
    Started(StartedPlan),
    Pending {
        retained: PendingPlanStart,
        message: String,
    },
}

impl fmt::Display for PlanStartOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => formatter.write_str("another desktop plan start is in progress"),
            Self::Reconciling(run_id) => {
                write!(formatter, "run {run_id} reconciliation is in progress")
            }
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

    fn begin_plan_start(&self) -> BeginPlanStart {
        let mut lifecycle = lock_plan_start(&self.plan_start);
        match &*lifecycle {
            PlanStartLifecycle::Idle => {
                *lifecycle = PlanStartLifecycle::Starting;
                BeginPlanStart::Reserved(PlanStartReservation {
                    lifecycle: Arc::clone(&self.plan_start),
                    active: true,
                })
            }
            PlanStartLifecycle::Starting => {
                BeginPlanStart::InProgress(PlanStartOperation::Starting)
            }
            PlanStartLifecycle::Pending(pending) => {
                BeginPlanStart::ReconciliationRequired(pending.view(format!(
                    "Run {} must be reconciled before another plan can start",
                    pending.run_id()
                )))
            }
            PlanStartLifecycle::Reconciling(view) => {
                BeginPlanStart::InProgress(PlanStartOperation::Reconciling(view.run_id))
            }
        }
    }

    fn begin_plan_reconciliation(&self, run_id: RunId) -> BeginPlanReconciliation {
        let mut lifecycle = lock_plan_start(&self.plan_start);
        match std::mem::replace(&mut *lifecycle, PlanStartLifecycle::Idle) {
            PlanStartLifecycle::Pending(pending) if pending.run_id() == run_id => {
                let view = pending.view(format!("Run {run_id} reconciliation is in progress"));
                *lifecycle = PlanStartLifecycle::Reconciling(view);
                BeginPlanReconciliation::Reserved(Box::new(PlanReconciliationReservation {
                    lifecycle: Arc::clone(&self.plan_start),
                    pending: Some(pending),
                }))
            }
            PlanStartLifecycle::Pending(pending) => {
                let retained = pending.run_id();
                *lifecycle = PlanStartLifecycle::Pending(pending);
                BeginPlanReconciliation::RunMismatch {
                    requested: run_id,
                    retained,
                }
            }
            PlanStartLifecycle::Idle => BeginPlanReconciliation::NotPending,
            PlanStartLifecycle::Starting => {
                *lifecycle = PlanStartLifecycle::Starting;
                BeginPlanReconciliation::InProgress(PlanStartOperation::Starting)
            }
            PlanStartLifecycle::Reconciling(view) => {
                let retained = view.run_id;
                *lifecycle = PlanStartLifecycle::Reconciling(view);
                BeginPlanReconciliation::InProgress(PlanStartOperation::Reconciling(retained))
            }
        }
    }
}

fn lock_plan_start(
    lifecycle: &Mutex<PlanStartLifecycle>,
) -> std::sync::MutexGuard<'_, PlanStartLifecycle> {
    lifecycle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl PlanStartReservation {
    fn complete(mut self, next: PlanStartLifecycle) -> Result<(), String> {
        let mut lifecycle = lock_plan_start(&self.lifecycle);
        if !matches!(*lifecycle, PlanStartLifecycle::Starting) {
            return Err("Desktop plan start reservation lost its Starting state".to_owned());
        }
        *lifecycle = next;
        self.active = false;
        Ok(())
    }
}

impl Drop for PlanStartReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut lifecycle = lock_plan_start(&self.lifecycle);
        if matches!(*lifecycle, PlanStartLifecycle::Starting) {
            *lifecycle = PlanStartLifecycle::Idle;
        }
    }
}

impl PlanReconciliationReservation {
    fn take_pending(&mut self) -> PendingPlanStart {
        self.pending
            .take()
            .expect("a reconciliation reservation owns exactly one pending start")
    }

    fn complete(mut self, next: PlanStartLifecycle) -> Result<(), String> {
        let mut lifecycle = lock_plan_start(&self.lifecycle);
        if !matches!(*lifecycle, PlanStartLifecycle::Reconciling(_)) {
            return Err("Desktop plan reconciliation reservation lost its state".to_owned());
        }
        *lifecycle = next;
        self.pending = None;
        Ok(())
    }
}

impl Drop for PlanReconciliationReservation {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let mut lifecycle = lock_plan_start(&self.lifecycle);
        if matches!(*lifecycle, PlanStartLifecycle::Reconciling(_)) {
            *lifecycle = PlanStartLifecycle::Pending(pending);
        }
    }
}

#[derive(Debug)]
enum DesktopOperationError {
    Client(ClientError),
    Contract(String),
}

impl From<ClientError> for DesktopOperationError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

impl ConnectionManager<DaemonClient> {
    fn run_operation<ResultValue>(
        &self,
        key: &ConnectionKey,
        operation: impl FnOnce(
            &InitializeResult,
            &mut DaemonClient,
        ) -> Result<ResultValue, DesktopOperationError>,
    ) -> Result<ResultValue, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| format!("Runtime connection state is unavailable: {error}"))?;

        if state
            .permanent_failure
            .as_ref()
            .is_some_and(|blocked| &blocked.key != key)
        {
            state.permanent_failure.take();
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
        if let Some(blocked) = state
            .permanent_failure
            .as_ref()
            .filter(|blocked| &blocked.key == key)
        {
            return Err(blocked.health.message.clone());
        }
        if state.connection.is_none() {
            let connected = connect(key, &|daemon, data_dir| {
                DaemonClient::spawn_with_timeouts(daemon, data_dir, ClientTimeouts::default())
            })
            .map_err(|error| match error {
                ConnectError::Spawn(error) | ConnectError::Initialize(error) => error.to_string(),
            })?;
            state.connection = Some(connected);
        }

        let result = {
            let connection = state
                .connection
                .as_mut()
                .expect("connection is populated immediately above");
            operation(&connection.initialized, &mut connection.client)
        };
        match result {
            Ok(value) => Ok(value),
            Err(DesktopOperationError::Contract(message)) => Err(message),
            Err(DesktopOperationError::Client(error)) => {
                let message = error.to_string();
                let _ = record_client_failure(&mut state, key, &error, Instant::now());
                Err(message)
            }
        }
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

#[tauri::command]
pub async fn runtime_discover_models(
    app: tauri::AppHandle,
    manager: tauri::State<'_, RuntimeManager>,
) -> Result<Vec<PlannerModel>, String> {
    let key = resolve_connection_key(&app)?;
    let manager = Arc::clone(&manager.inner);
    tauri::async_runtime::spawn_blocking(move || {
        manager.run_operation(&key, |initialized, client| {
            require_planning_capability(initialized)?;
            let catalog = client.discover_models()?;
            project_planner_models(&catalog)
        })
    })
    .await
    .map_err(|error| format!("Model discovery task failed: {error}"))?
}

fn create_plan_start_attempt(
    initialized: &InitializeResult,
    client: &mut DaemonClient,
    request: &StartPlanRequest,
    workspace: &Path,
) -> Result<PlanStartAttempt, DesktopOperationError> {
    require_planning_capability(initialized)?;
    let catalog = client.discover_models()?;
    let model = resolve_exact_model(&catalog, &request.backend_id, &request.model_id)?;
    let ServerResult::Session(session) =
        client.call(ClientCommand::CreateSession(CreateSessionRequest {
            workspace_root: workspace.to_owned().into(),
            title: Some("BirdCode desktop root plan".to_owned()),
        }))?
    else {
        return Err(DesktopOperationError::Contract(
            "Daemon returned the wrong result for create_session".to_owned(),
        ));
    };
    let spec = RunSpec {
        session_id: session.id,
        purpose: RunPurpose::PlanOnly,
        backend: BackendSelection {
            backend_id: model.backend_id,
            kind: model.kind,
            model: Some(model.model_id.clone()),
            reasoning_effort: request
                .reasoning_effort
                .map(|effort| effort.as_str().to_owned()),
        },
        input: vec![InputItem::Text {
            text: request.goal.clone(),
        }],
        limits: RunLimits {
            max_output_tokens: Some(request.max_output_tokens),
            max_wall_time_seconds: Some(request.max_wall_time_seconds),
            max_subagents: 0,
        },
    };
    let run_id = RunId::new();
    let run_request = CreateRunRequest {
        run_id,
        spec: spec.clone(),
    };
    let workspace_root = workspace.to_string_lossy().into_owned();
    match client.create_run(&run_request) {
        Ok(run) => Ok(PlanStartAttempt::Started(StartedPlan {
            session_id: session.id,
            run_id,
            state: run.state,
            workspace_root,
            model_id: model.model_id,
        })),
        Err(CreateRunFailure::NotSubmitted { request, source }) => Ok(PlanStartAttempt::Pending {
            retained: PendingPlanStart {
                submission: PendingPlanSubmission::NotSubmitted(*request),
                session_id: session.id,
                workspace_root,
                model_id: model.model_id,
            },
            message: format!(
                "Run {run_id} was not submitted and is retained for exact retry without recreating session {}: {source}",
                session.id
            ),
        }),
        Err(CreateRunFailure::ReconciliationRequired(pending)) => Ok(PlanStartAttempt::Pending {
            retained: PendingPlanStart {
                submission: PendingPlanSubmission::Ambiguous(pending),
                session_id: session.id,
                workspace_root,
                model_id: model.model_id,
            },
            message: format!(
                "Run {run_id} may already exist and is retained for exact reconciliation without recreating session {}",
                session.id
            ),
        }),
        Err(CreateRunFailure::Rejected { source, .. }) => Err(DesktopOperationError::Contract(
            format!("Run {run_id} was authoritatively rejected: {source}"),
        )),
    }
}

#[tauri::command]
pub async fn runtime_start_plan(
    app: tauri::AppHandle,
    manager: tauri::State<'_, RuntimeManager>,
    request: StartPlanRequest,
) -> Result<StartPlanOutcome, String> {
    let key = resolve_connection_key(&app)?;
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        with_validated_start_request(&request, |workspace| {
            let reservation = match manager.begin_plan_start() {
                BeginPlanStart::Reserved(reservation) => reservation,
                BeginPlanStart::ReconciliationRequired(pending) => {
                    return Ok(StartPlanOutcome::ReconciliationRequired(pending));
                }
                BeginPlanStart::InProgress(operation) => {
                    return Err(format!("Cannot start a new plan while {operation}"));
                }
            };
            let result = manager.inner.run_operation(&key, |initialized, client| {
                create_plan_start_attempt(initialized, client, &request, &workspace)
            });
            match result {
                Ok(PlanStartAttempt::Started(started)) => {
                    reservation.complete(PlanStartLifecycle::Idle)?;
                    Ok(StartPlanOutcome::Started(started))
                }
                Ok(PlanStartAttempt::Pending { retained, message }) => {
                    let view = retained.view(message);
                    reservation.complete(PlanStartLifecycle::Pending(retained))?;
                    Ok(StartPlanOutcome::ReconciliationRequired(view))
                }
                Err(error) => {
                    reservation.complete(PlanStartLifecycle::Idle)?;
                    Err(error)
                }
            }
        })
    })
    .await
    .map_err(|error| format!("Plan start task failed: {error}"))?
}

/// Retries only the exact `CreateRun` identity retained by a failed plan start.
/// It never repeats model discovery or `CreateSession`.
#[tauri::command]
pub async fn runtime_reconcile_plan_start(
    app: tauri::AppHandle,
    manager: tauri::State<'_, RuntimeManager>,
    request: ReconcilePlanStartRequest,
) -> Result<StartPlanOutcome, String> {
    let key = resolve_connection_key(&app)?;
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let reservation = match manager.begin_plan_reconciliation(request.run_id) {
            BeginPlanReconciliation::Reserved(reservation) => reservation,
            BeginPlanReconciliation::InProgress(operation) => {
                return Err(format!("Cannot reconcile while {operation}"));
            }
            BeginPlanReconciliation::NotPending => {
                return Err(format!(
                    "Run {} has no pending desktop plan start to reconcile",
                    request.run_id
                ));
            }
            BeginPlanReconciliation::RunMismatch {
                requested,
                retained,
            } => {
                return Err(format!(
                    "Run {retained} requires reconciliation; refusing mismatched run {requested}"
                ));
            }
        };
        let mut reservation = Some(reservation);
        manager.inner.run_operation(&key, |initialized, client| {
            require_planning_capability(initialized)?;
            let reservation = reservation
                .take()
                .expect("a reconciliation reservation is consumed by at most one operation");
            reconcile_pending_plan_start(client, *reservation)
        })
    })
    .await
    .map_err(|error| format!("Plan start reconciliation task failed: {error}"))?
}

fn reconcile_pending_plan_start(
    client: &mut DaemonClient,
    mut reservation: PlanReconciliationReservation,
) -> Result<StartPlanOutcome, DesktopOperationError> {
    let mut retained = reservation.take_pending();
    let run_id = retained.run_id();
    let session_id = retained.session_id;
    let workspace_root = retained.workspace_root.clone();
    let model_id = retained.model_id.clone();
    let result = match retained.submission {
        PendingPlanSubmission::NotSubmitted(ref request) => client.create_run(request),
        PendingPlanSubmission::Ambiguous(pending) => client.reconcile_create_run(pending),
    };
    match result {
        Ok(run) => {
            reservation
                .complete(PlanStartLifecycle::Idle)
                .map_err(DesktopOperationError::Contract)?;
            Ok(StartPlanOutcome::Started(StartedPlan {
                session_id,
                run_id,
                state: run.state,
                workspace_root,
                model_id,
            }))
        }
        Err(CreateRunFailure::NotSubmitted { request, source }) => {
            retained.submission = PendingPlanSubmission::NotSubmitted(*request);
            let view = retained.view(format!(
                "Run {run_id} remains retained for exact retry: {source}"
            ));
            reservation
                .complete(PlanStartLifecycle::Pending(retained))
                .map_err(DesktopOperationError::Contract)?;
            Ok(StartPlanOutcome::ReconciliationRequired(view))
        }
        Err(CreateRunFailure::ReconciliationRequired(pending)) => {
            retained.submission = PendingPlanSubmission::Ambiguous(pending);
            let view = retained.view(format!(
                "Run {run_id} still has an ambiguous result and remains retained for exact reconciliation"
            ));
            reservation
                .complete(PlanStartLifecycle::Pending(retained))
                .map_err(DesktopOperationError::Contract)?;
            Ok(StartPlanOutcome::ReconciliationRequired(view))
        }
        Err(CreateRunFailure::Rejected { source, .. }) => {
            reservation
                .complete(PlanStartLifecycle::Idle)
                .map_err(DesktopOperationError::Contract)?;
            Err(DesktopOperationError::Contract(format!(
                "Run {run_id} was authoritatively rejected during reconciliation: {source}"
            )))
        }
    }
}

#[tauri::command]
pub async fn runtime_poll_plan(
    app: tauri::AppHandle,
    manager: tauri::State<'_, RuntimeManager>,
    request: PollPlanRequest,
) -> Result<PlanPoll, String> {
    let key = resolve_connection_key(&app)?;
    let manager = Arc::clone(&manager.inner);
    tauri::async_runtime::spawn_blocking(move || {
        manager.run_operation(&key, |initialized, client| {
            require_planning_capability(initialized)?;
            poll_plan(client, &request)
        })
    })
    .await
    .map_err(|error| format!("Plan polling task failed: {error}"))?
}

#[tauri::command]
pub async fn runtime_cancel_plan(
    app: tauri::AppHandle,
    manager: tauri::State<'_, RuntimeManager>,
    request: CancelPlanRequest,
) -> Result<CancellationReceiptView, String> {
    let key = resolve_connection_key(&app)?;
    let manager = Arc::clone(&manager.inner);
    tauri::async_runtime::spawn_blocking(move || {
        manager.run_operation(&key, |_initialized, client| {
            let receipt = client.cancel_run(request.run_id)?;
            if receipt.run_id != request.run_id {
                return Err(DesktopOperationError::Contract(
                    "Daemon returned a cancellation receipt for a different run".to_owned(),
                ));
            }
            Ok(project_cancellation_receipt(&receipt))
        })
    })
    .await
    .map_err(|error| format!("Plan cancellation task failed: {error}"))?
}

fn project_cancellation_receipt(receipt: &CancellationReceipt) -> CancellationReceiptView {
    CancellationReceiptView {
        run_id: receipt.run_id,
        cancellation_request_id: receipt.cancellation_request_id,
        cancellation_generation: receipt.cancellation_generation,
        disposition: receipt.disposition,
    }
}

fn resolve_connection_key(app: &tauri::AppHandle) -> Result<ConnectionKey, String> {
    let daemon = resolve_daemon_path(None).map_err(|error| error.to_string())?;
    let data_dir = resolve_data_dir(std::env::var_os("BIRDCODE_DATA_DIR"), || {
        app.path().app_local_data_dir()
    })
    .map_err(|error| error.to_string())?;
    Ok(ConnectionKey { daemon, data_dir })
}

fn require_planning_capability(
    initialized: &InitializeResult,
) -> Result<(), DesktopOperationError> {
    if initialized
        .capabilities
        .supports(RuntimeCapability::DurableRootPlanning)
    {
        Ok(())
    } else {
        Err(DesktopOperationError::Contract(
            "Daemon does not advertise durable root planning".to_owned(),
        ))
    }
}

fn validate_start_request(request: &StartPlanRequest) -> Result<PathBuf, String> {
    if request.workspace_root.is_empty() {
        return Err("Workspace path must not be empty".to_owned());
    }
    if request.goal.trim().is_empty() {
        return Err("Planning goal must contain text".to_owned());
    }
    if request.goal.len() > MAX_DESKTOP_GOAL_BYTES {
        return Err(format!(
            "Planning goal exceeds the desktop limit of {MAX_DESKTOP_GOAL_BYTES} UTF-8 bytes"
        ));
    }
    let encoded_request = serde_json::to_vec(request)
        .map_err(|error| format!("Could not encode the desktop plan request: {error}"))?;
    if encoded_request.len() > MAX_DESKTOP_START_REQUEST_BYTES {
        return Err(format!(
            "Plan request exceeds the desktop limit of {MAX_DESKTOP_START_REQUEST_BYTES} bytes"
        ));
    }
    if request.backend_id != LM_STUDIO_BACKEND_ID {
        return Err(format!(
            "Desktop planning currently supports the exact backend id {LM_STUDIO_BACKEND_ID:?}"
        ));
    }
    if request.model_id.is_empty() {
        return Err("Model id must not be empty".to_owned());
    }
    if request.max_output_tokens == 0 {
        return Err("Maximum output tokens must be greater than zero".to_owned());
    }
    if request.max_output_tokens > MAX_ROOT_PLANNER_OUTPUT_TOKENS {
        return Err(format!(
            "Maximum output tokens must not exceed {MAX_ROOT_PLANNER_OUTPUT_TOKENS}"
        ));
    }
    if request.max_wall_time_seconds == 0 {
        return Err("Maximum wall time must be greater than zero".to_owned());
    }
    let workspace = fs::canonicalize(PathBuf::from(&request.workspace_root))
        .map_err(|error| format!("Could not resolve workspace: {error}"))?;
    let metadata = fs::metadata(&workspace)
        .map_err(|error| format!("Could not inspect workspace: {error}"))?;
    if !metadata.is_dir() {
        return Err("Workspace must be an existing directory".to_owned());
    }
    Ok(workspace)
}

fn with_validated_start_request<ResultValue>(
    request: &StartPlanRequest,
    start: impl FnOnce(PathBuf) -> Result<ResultValue, String>,
) -> Result<ResultValue, String> {
    let workspace = validate_start_request(request)?;
    start(workspace)
}

fn project_planner_models(
    catalog: &BackendCatalog,
) -> Result<Vec<PlannerModel>, DesktopOperationError> {
    let mut identities = BTreeSet::new();
    let mut models = Vec::new();
    for discovered in &catalog.models {
        if discovered.identity.backend_id != LM_STUDIO_BACKEND_ID
            || discovered.identity.kind != BackendKind::Model
        {
            continue;
        }
        let identity = (
            discovered.identity.backend_id.clone(),
            discovered.identity.model_id.clone(),
        );
        if discovered.identity.model_id.is_empty() {
            return Err(DesktopOperationError::Contract(
                "LM Studio reported an empty model id".to_owned(),
            ));
        }
        if !identities.insert(identity) {
            return Err(DesktopOperationError::Contract(format!(
                "LM Studio reported duplicate model id {:?}",
                discovered.identity.model_id
            )));
        }
        models.push(PlannerModel {
            backend_id: discovered.identity.backend_id.clone(),
            model_id: discovered.identity.model_id.clone(),
            display_name: discovered
                .display_name
                .clone()
                .unwrap_or_else(|| discovered.identity.model_id.clone()),
            context_window_tokens: discovered.context_window_tokens,
            max_output_tokens: discovered.max_output_tokens,
        });
    }
    models.sort_by(|left, right| left.model_id.as_bytes().cmp(right.model_id.as_bytes()));
    Ok(models)
}

fn resolve_exact_model(
    catalog: &BackendCatalog,
    backend_id: &str,
    model_id: &str,
) -> Result<birdcode_protocol::BackendModelIdentity, DesktopOperationError> {
    let mut matching = catalog.models.iter().filter(|model| {
        model.identity.backend_id.as_bytes() == backend_id.as_bytes()
            && model.identity.kind == BackendKind::Model
            && model.identity.model_id.as_bytes() == model_id.as_bytes()
    });
    let selected = matching.next().ok_or_else(|| {
        DesktopOperationError::Contract(format!(
            "LM Studio did not report an exact model id match for {model_id:?}"
        ))
    })?;
    if matching.next().is_some() {
        return Err(DesktopOperationError::Contract(format!(
            "LM Studio reported ambiguous duplicate entries for model id {model_id:?}"
        )));
    }
    Ok(selected.identity.clone())
}

fn poll_plan(
    client: &mut DaemonClient,
    request: &PollPlanRequest,
) -> Result<PlanPoll, DesktopOperationError> {
    let mut cursor = request.after_sequence;
    let mut event_views = Vec::new();
    let mut accepted: Option<PlanProposalAccepted> = None;
    let mut exhausted = false;

    for _ in 0..MAX_EVENT_PAGES_PER_POLL {
        let page = client.get_events(request.session_id, cursor)?;
        if page.has_more && page.events.is_empty() {
            return Err(DesktopOperationError::Contract(
                "Event replay returned an empty non-terminal page".to_owned(),
            ));
        }
        let mut previous = cursor;
        for event in &page.events {
            if event.session_id != request.session_id {
                return Err(DesktopOperationError::Contract(
                    "Event replay crossed the requested session boundary".to_owned(),
                ));
            }
            if event.sequence <= previous {
                return Err(DesktopOperationError::Contract(
                    "Event replay sequence did not increase strictly".to_owned(),
                ));
            }
            previous = event.sequence;
            if event.run_id == Some(request.run_id) {
                if let EventPayload::PlanProposalAccepted(decision) = &event.payload
                    && accepted.replace(decision.clone()).is_some()
                {
                    return Err(DesktopOperationError::Contract(
                        "Run contains more than one accepted plan decision".to_owned(),
                    ));
                }
                event_views.push(project_event(event));
            }
        }
        if page.next_sequence != previous {
            return Err(DesktopOperationError::Contract(
                "Event replay cursor does not equal its last sequence".to_owned(),
            ));
        }
        if page.has_more && page.next_sequence <= cursor {
            return Err(DesktopOperationError::Contract(
                "Event replay claimed more data without advancing".to_owned(),
            ));
        }
        cursor = page.next_sequence;
        if !page.has_more {
            exhausted = true;
            break;
        }
    }
    if !exhausted {
        return Err(DesktopOperationError::Contract(format!(
            "Event replay exceeded the desktop limit of {MAX_EVENT_PAGES_PER_POLL} pages"
        )));
    }

    let run = client.get_run(request.run_id)?;
    if run.id != request.run_id || run.spec.session_id != request.session_id {
        return Err(DesktopOperationError::Contract(
            "Daemon returned a run outside the requested plan identity".to_owned(),
        ));
    }
    let accepted_plan = if accepted_plan_is_visible(run.state) {
        accepted
            .as_ref()
            .map(|decision| fetch_accepted_plan(client, decision))
            .transpose()?
    } else {
        None
    };
    if request.after_sequence == 0 && run.state == RunState::Completed && accepted_plan.is_none() {
        return Err(DesktopOperationError::Contract(
            "Completed plan run has no accepted plan event in full replay".to_owned(),
        ));
    }
    Ok(PlanPoll {
        run_id: request.run_id,
        state: run.state,
        next_sequence: cursor,
        events: event_views,
        accepted_plan,
    })
}

const fn accepted_plan_is_visible(state: RunState) -> bool {
    matches!(state, RunState::Completed)
}

// Keeping this exhaustive match in one place makes every protocol event's UI
// projection auditable; splitting it would require catch-all branches that
// could silently hide a newly added typed event.
#[allow(clippy::too_many_lines)]
fn project_event(event: &EventEnvelope) -> PlanEventView {
    let (kind, tone, title, detail) = match &event.payload {
        EventPayload::SessionCreated { .. } => (
            "session_created",
            "neutral",
            "Session created",
            "Durable planning session recorded".to_owned(),
        ),
        EventPayload::UserInput { items } => (
            "user_input",
            "neutral",
            "Goal recorded",
            format!("{} typed input item(s) persisted", items.len()),
        ),
        EventPayload::RunCreated { run } => (
            "run_created",
            "neutral",
            "Plan run queued",
            format!("Client run id {}", run.id),
        ),
        EventPayload::RunStateChanged { from, to } => (
            "run_state_changed",
            state_tone(*to),
            "Run state changed",
            format!("{} → {}", state_name(*from), state_name(*to)),
        ),
        EventPayload::RunClaimed(claim) => (
            "run_claimed",
            "active",
            "Planner claimed",
            format!(
                "Claim generation {} · cancellation generation {}",
                claim.claim_generation, claim.cancellation_generation
            ),
        ),
        EventPayload::CancellationRequested(cancellation) => (
            "cancellation_requested",
            "warning",
            "Cancellation recorded",
            format!(
                "Durable cancellation generation {}",
                cancellation.cancellation_generation
            ),
        ),
        EventPayload::RootPlanningFailed(failure) => (
            "root_planning_failed",
            "danger",
            "Planning failed before inference",
            format!(
                "Typed phase {:?} · reason {:?}",
                failure.phase, failure.reason
            ),
        ),
        EventPayload::PlannerInferencePrepared(prepared) => (
            "planner_inference_prepared",
            "active",
            "Inference prepared",
            format!(
                "{} · revision {} · {} output tokens reserved",
                prepared.backend_model.model_id,
                prepared.plan_revision,
                prepared.token_reservation.max_output_tokens
            ),
        ),
        EventPayload::PlannerInferenceObserved(observed) => match &observed.outcome {
            PlannerInferenceObservation::Succeeded { token_usage, .. } => (
                "planner_inference_observed",
                "active",
                "Inference observed",
                format!(
                    "Complete response retained · {} total tokens",
                    token_usage.total_tokens
                ),
            ),
            PlannerInferenceObservation::Failed { error } => (
                "planner_inference_observed",
                "danger",
                "Inference failed",
                format!("Typed failure: {:?} · retry {:?}", error.kind, error.retry),
            ),
        },
        EventPayload::PlannerInferenceOutcomeUnknown(unknown) => (
            "planner_inference_outcome_unknown",
            "danger",
            "Inference outcome unknown",
            format!("Fail-closed reconciliation: {:?}", unknown.reason),
        ),
        EventPayload::ReadOperationPrepared(read) => (
            "read_operation_prepared",
            "active",
            "Read prepared",
            format!("Read-only operation {:?}", read.operation),
        ),
        EventPayload::ReadOperationObserved(read) => (
            "read_operation_observed",
            "active",
            "Read observed",
            format!("Typed read outcome {:?}", read.outcome),
        ),
        EventPayload::PlanProposalRejected(rejected) => (
            "plan_proposal_rejected",
            "danger",
            "Plan rejected",
            format!("Typed validation reason: {:?}", rejected.reason),
        ),
        EventPayload::PlanProposalAccepted(accepted) => (
            "plan_proposal_accepted",
            "success",
            "Plan accepted",
            format!(
                "Revision {} · {}",
                accepted.accepted_plan_revision,
                accepted.accepted_plan_digest.as_str()
            ),
        ),
        EventPayload::BackendEvent { event_type, .. } => (
            "backend_event",
            "neutral",
            "Backend telemetry",
            event_type.clone(),
        ),
        EventPayload::ArtifactStored { artifact } => (
            "artifact_stored",
            "neutral",
            "Artifact stored",
            format!("{} · {} bytes", artifact.media_type, artifact.size_bytes),
        ),
    };
    PlanEventView {
        sequence: event.sequence,
        occurred_at: event.occurred_at.to_rfc3339(),
        kind,
        tone,
        title,
        detail,
    }
}

const fn state_name(state: RunState) -> &'static str {
    match state {
        RunState::Queued => "queued",
        RunState::Running => "running",
        RunState::Waiting => "waiting",
        RunState::Completed => "completed",
        RunState::Failed => "failed",
        RunState::Cancelled => "cancelled",
    }
}

const fn state_tone(state: RunState) -> &'static str {
    match state {
        RunState::Queued | RunState::Waiting => "neutral",
        RunState::Running => "active",
        RunState::Completed => "success",
        RunState::Failed => "danger",
        RunState::Cancelled => "warning",
    }
}

fn fetch_accepted_plan(
    client: &mut DaemonClient,
    accepted: &PlanProposalAccepted,
) -> Result<AcceptedPlanView, DesktopOperationError> {
    let artifact = &accepted.accepted_plan_artifact;
    if artifact.media_type != ACCEPTED_PLAN_MEDIA_TYPE {
        return Err(DesktopOperationError::Contract(format!(
            "Accepted plan has media type {:?}; expected {ACCEPTED_PLAN_MEDIA_TYPE:?}",
            artifact.media_type
        )));
    }
    if accepted.accepted_plan_digest.as_str().as_bytes() != artifact.sha256.as_bytes() {
        return Err(DesktopOperationError::Contract(
            "Accepted plan event digest differs from its artifact reference".to_owned(),
        ));
    }
    let bytes = fetch_verified_artifact(client, artifact)?;
    let output = serde_json::from_slice::<RootPlannerOutput>(&bytes).map_err(|error| {
        DesktopOperationError::Contract(format!(
            "Accepted plan artifact is not valid typed planner JSON: {error}"
        ))
    })?;
    Ok(project_accepted_plan(accepted, output))
}

fn fetch_verified_artifact(
    client: &mut DaemonClient,
    artifact: &ArtifactRef,
) -> Result<Vec<u8>, DesktopOperationError> {
    if artifact.size_bytes > MAX_DESKTOP_ARTIFACT_BYTES {
        return Err(DesktopOperationError::Contract(format!(
            "Artifact {} declares {} bytes; desktop limit is {MAX_DESKTOP_ARTIFACT_BYTES}",
            artifact.sha256, artifact.size_bytes
        )));
    }
    let capacity = usize::try_from(artifact.size_bytes).map_err(|_| {
        DesktopOperationError::Contract("Artifact size does not fit this platform".to_owned())
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut offset = 0_u64;
    loop {
        let chunk = client.get_artifact(artifact.clone(), offset, MAX_ARTIFACT_CHUNK_BYTES)?;
        validate_artifact_chunk(artifact, offset, &chunk)?;
        let next_offset = chunk.next_offset();
        let eof = chunk.eof();
        bytes.extend_from_slice(chunk.data());
        if eof {
            if next_offset != artifact.size_bytes {
                return Err(DesktopOperationError::Contract(
                    "Artifact reached EOF at the wrong declared size".to_owned(),
                ));
            }
            break;
        }
        if next_offset <= offset {
            return Err(DesktopOperationError::Contract(
                "Artifact pagination did not advance".to_owned(),
            ));
        }
        offset = next_offset;
    }
    if u64::try_from(bytes.len()).ok() != Some(artifact.size_bytes) {
        return Err(DesktopOperationError::Contract(
            "Assembled artifact length differs from its reference".to_owned(),
        ));
    }
    let actual_sha256 = sha256_hex(&bytes);
    if actual_sha256.as_bytes() != artifact.sha256.as_bytes() {
        return Err(DesktopOperationError::Contract(format!(
            "Assembled artifact SHA-256 {actual_sha256} differs from reference {}",
            artifact.sha256
        )));
    }
    Ok(bytes)
}

fn validate_artifact_chunk(
    artifact: &ArtifactRef,
    offset: u64,
    chunk: &ArtifactChunk,
) -> Result<(), DesktopOperationError> {
    if chunk.artifact() != artifact || chunk.offset() != offset {
        return Err(DesktopOperationError::Contract(
            "Artifact page is not bound to the requested reference and cursor".to_owned(),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn project_accepted_plan(
    accepted: &PlanProposalAccepted,
    output: RootPlannerOutput,
) -> AcceptedPlanView {
    AcceptedPlanView {
        revision: accepted.accepted_plan_revision,
        digest: accepted.accepted_plan_digest.as_str().to_owned(),
        directive: directive_name(output.directive),
        rationale: output.rationale,
        decision_evidence: output
            .decision_evidence
            .into_iter()
            .map(|evidence| DecisionEvidenceView {
                section: evidence.section,
                basis: evidence.basis,
            })
            .collect(),
        work_orders: output
            .work_orders
            .into_iter()
            .map(|work| WorkOrderView {
                id: work.local_id,
                objective: work.objective,
                obligation_ids: work
                    .obligation_refs
                    .into_iter()
                    .map(|obligation| obligation.obligation_id)
                    .collect(),
                dependencies: work.depends_on,
                verification_targets: work
                    .proposed_verification_targets
                    .into_iter()
                    .map(|target| VerificationTargetView {
                        kind: verification_kind_name(target.kind),
                        selector: target.selector,
                        question: target.question,
                    })
                    .collect(),
            })
            .collect(),
        clarifications: output.clarification_questions,
        escalations: output
            .escalation_requests
            .into_iter()
            .map(|escalation| EscalationView {
                reason: escalation.reason,
                blocked_obligation_ids: escalation
                    .blocked_obligation_refs
                    .into_iter()
                    .map(|obligation| obligation.obligation_id)
                    .collect(),
                requested_decision: escalation.requested_decision,
            })
            .collect(),
    }
}

const fn directive_name(directive: RootPlannerDirective) -> &'static str {
    match directive {
        RootPlannerDirective::Plan => "plan",
        RootPlannerDirective::Clarify => "clarify",
        RootPlannerDirective::Escalate => "escalate",
    }
}

const fn verification_kind_name(kind: VerificationKind) -> &'static str {
    match kind {
        VerificationKind::RepositoryTree => "repository_tree",
        VerificationKind::RepositoryFile => "repository_file",
        VerificationKind::RepositorySearch => "repository_search",
        VerificationKind::ExistingEvidence => "existing_evidence",
    }
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
        ClientError::Encode(_)
        | ClientError::RequestTooLarge
        | ClientError::Rejected { .. }
        | ClientError::InvalidArtifactRequest(_) => FailurePolicy::RetryRequest,
        ClientError::CurrentExecutable(_)
        | ClientError::Spawn { .. }
        | ClientError::MissingPipe(_)
        | ClientError::Io(_)
        | ClientError::Decode(_)
        | ClientError::Ended
        | ClientError::ResponseTooLarge
        | ClientError::ResponseTimeout(_)
        | ClientError::ResponseIdMismatch
        | ClientError::RunIdentityMismatch { .. }
        | ClientError::RunSpecificationMismatch { .. }
        | ClientError::ReconnectBeforeInitialize
        | ClientError::WriterThread(_)
        | ClientError::ReaderThread(_)
        | ClientError::UnexpectedResult { .. }
        | ClientError::ArtifactReferenceMismatch
        | ClientError::ArtifactOffsetMismatch { .. }
        | ClientError::ArtifactChunkExceedsRequest { .. } => FailurePolicy::RetryConnection,
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
        BeginPlanReconciliation, BeginPlanStart, ConnectionKey, ConnectionManager, FailurePolicy,
        INITIAL_RETRY_BACKOFF, MAX_DESKTOP_GOAL_BYTES, MAX_DESKTOP_START_REQUEST_BYTES,
        MAX_RETRY_BACKOFF, MAX_ROOT_PLANNER_OUTPUT_TOKENS, PendingPlanStart, PendingPlanSubmission,
        PlanStartLifecycle, PlanStartOperation, ReconciliationRequiredPlan, RuntimeConnection,
        RuntimeManager, RuntimeState, StartPlanOutcome, StartPlanRequest, accepted_plan_is_visible,
        client_failure, failure_policy, project_cancellation_receipt, project_planner_models,
        resolve_data_dir, retry_backoff, sha256_hex, validate_artifact_chunk,
        with_validated_start_request,
    };
    use birdcode_client::{ClientError, DaemonClient};
    use birdcode_protocol::{
        ArtifactChunk, ArtifactRef, BackendCatalog, BackendKind, BackendSelection,
        CancellationReceipt, CreateRunRequest, ErrorCode, Health, HealthStatus, InitializeResult,
        InputItem, PROTOCOL_VERSION, RunId, RunLimits, RunPurpose, RunSpec, RuntimeCapabilities,
        ServerIdentity, SessionId,
    };
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug)]
    enum FakeError {
        StartupTimeout,
        NegotiatedProtocolMismatch,
        IncompatibleProtocol,
        InternalRejection { retryable: bool },
        Ended,
    }

    #[test]
    fn desktop_contract_rejects_unrepresentable_reasoning_on() {
        let request = serde_json::json!({
            "workspaceRoot": "/tmp/project",
            "goal": "Plan the requested outcome",
            "backendId": "lmstudio",
            "modelId": "exact-model",
            "maxOutputTokens": 4096,
            "maxWallTimeSeconds": 180,
            "reasoningEffort": "on"
        });

        assert!(
            serde_json::from_value::<StartPlanRequest>(request).is_err(),
            "the desktop boundary must reject a provider-neutral value that LM Studio cannot encode"
        );
    }

    #[test]
    fn invalid_native_limits_never_dispatch_a_session_or_start() {
        let calls = AtomicUsize::new(0);
        let request = start_plan_request(
            "Plan the requested outcome".to_owned(),
            "exact-model".to_owned(),
            MAX_ROOT_PLANNER_OUTPUT_TOKENS + 1,
        );

        let result = with_validated_start_request(&request, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn oversized_native_goal_and_request_never_dispatch_a_session_or_start() {
        for request in [
            start_plan_request(
                "x".repeat(MAX_DESKTOP_GOAL_BYTES + 1),
                "exact-model".to_owned(),
                4096,
            ),
            start_plan_request(
                "Plan safely".to_owned(),
                "m".repeat(MAX_DESKTOP_START_REQUEST_BYTES),
                4096,
            ),
        ] {
            let calls = AtomicUsize::new(0);
            let result = with_validated_start_request(&request, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn concurrent_plan_starts_share_one_atomic_starting_reservation() {
        let manager = RuntimeManager::default();
        let BeginPlanStart::Reserved(first) = manager.begin_plan_start() else {
            panic!("the first start must reserve the idle lifecycle");
        };
        let barrier = Arc::new(Barrier::new(2));
        let contender_manager = manager.clone();
        let contender_barrier = Arc::clone(&barrier);
        let contender = std::thread::spawn(move || {
            contender_barrier.wait();
            matches!(
                contender_manager.begin_plan_start(),
                BeginPlanStart::InProgress(PlanStartOperation::Starting)
            )
        });

        barrier.wait();
        assert!(contender.join().expect("start contender should finish"));
        first
            .complete(PlanStartLifecycle::Idle)
            .expect("the sole reservation should complete");
        assert!(matches!(
            manager.begin_plan_start(),
            BeginPlanStart::Reserved(_)
        ));
    }

    #[test]
    fn reconciliation_atomically_blocks_start_and_restores_pending_on_drop() {
        let manager = RuntimeManager::default();
        let pending = pending_plan_start();
        let run_id = pending.run_id();
        let BeginPlanStart::Reserved(start) = manager.begin_plan_start() else {
            panic!("idle lifecycle should reserve a start");
        };
        start
            .complete(PlanStartLifecycle::Pending(pending))
            .expect("pending identity should become durable desktop state");
        let BeginPlanReconciliation::Reserved(reconciliation) =
            manager.begin_plan_reconciliation(run_id)
        else {
            panic!("the exact retained run should reserve reconciliation");
        };
        let barrier = Arc::new(Barrier::new(2));
        let contender_manager = manager.clone();
        let contender_barrier = Arc::clone(&barrier);
        let contender = std::thread::spawn(move || {
            contender_barrier.wait();
            matches!(
                contender_manager.begin_plan_start(),
                BeginPlanStart::InProgress(PlanStartOperation::Reconciling(actual)) if actual == run_id
            )
        });

        barrier.wait();
        assert!(contender.join().expect("start contender should finish"));
        assert!(matches!(
            manager.begin_plan_reconciliation(run_id),
            BeginPlanReconciliation::InProgress(PlanStartOperation::Reconciling(actual)) if actual == run_id
        ));

        drop(reconciliation);
        assert!(matches!(
            manager.begin_plan_start(),
            BeginPlanStart::ReconciliationRequired(view) if view.run_id == run_id
        ));
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

    fn start_plan_request(
        goal: String,
        model_id: String,
        max_output_tokens: u64,
    ) -> StartPlanRequest {
        StartPlanRequest {
            workspace_root: "/path/that/must/not/be-read-before-local-validation".to_owned(),
            goal,
            backend_id: "lmstudio".to_owned(),
            model_id,
            max_output_tokens,
            max_wall_time_seconds: 180,
            reasoning_effort: None,
        }
    }

    fn pending_plan_start() -> PendingPlanStart {
        let session_id = SessionId::new();
        PendingPlanStart {
            submission: PendingPlanSubmission::NotSubmitted(CreateRunRequest {
                run_id: RunId::new(),
                spec: RunSpec {
                    session_id,
                    purpose: RunPurpose::PlanOnly,
                    backend: BackendSelection {
                        backend_id: "lmstudio".to_owned(),
                        kind: BackendKind::Model,
                        model: Some("exact-model".to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: "Plan exactly once".to_owned(),
                    }],
                    limits: RunLimits {
                        max_output_tokens: Some(4096),
                        max_wall_time_seconds: Some(180),
                        max_subagents: 0,
                    },
                },
            }),
            session_id,
            workspace_root: "/tmp/BirdCode".to_owned(),
            model_id: "exact-model".to_owned(),
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

    #[test]
    fn model_projection_rejects_ambiguous_exact_identities() {
        let catalog: BackendCatalog = serde_json::from_value(serde_json::json!({
            "discovered_at": "2026-07-19T16:00:00Z",
            "models": [
                {
                    "identity": {
                        "backend_id": "lmstudio",
                        "kind": "model",
                        "model_id": "exact-model"
                    },
                    "display_name": "First",
                    "context_window_tokens": 32000,
                    "max_output_tokens": null
                },
                {
                    "identity": {
                        "backend_id": "lmstudio",
                        "kind": "model",
                        "model_id": "exact-model"
                    },
                    "display_name": "Duplicate",
                    "context_window_tokens": 32000,
                    "max_output_tokens": null
                }
            ]
        }))
        .expect("catalog fixture should decode");

        let error = project_planner_models(&catalog)
            .err()
            .expect("duplicate exact identities must fail closed");
        assert!(
            matches!(error, super::DesktopOperationError::Contract(message) if message.contains("duplicate model id"))
        );
    }

    #[test]
    fn artifact_page_must_match_the_full_reference_and_cursor() {
        let artifact = ArtifactRef {
            sha256: "a".repeat(64),
            size_bytes: 3,
            media_type: "application/json".to_owned(),
        };
        let chunk = ArtifactChunk::new(artifact.clone(), 0, b"abc".to_vec(), true)
            .expect("valid artifact page");
        validate_artifact_chunk(&artifact, 0, &chunk).expect("matching page should validate");

        let mut mismatched = artifact.clone();
        mismatched.media_type = "text/plain".to_owned();
        assert!(validate_artifact_chunk(&mismatched, 0, &chunk).is_err());
        assert!(validate_artifact_chunk(&artifact, 1, &chunk).is_err());
    }

    #[test]
    fn sha256_projection_is_canonical_lowercase() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn cancellation_receipt_uses_the_desktop_camel_case_boundary() {
        let receipt: CancellationReceipt = serde_json::from_value(serde_json::json!({
            "run_id": "019b0000-0000-7000-8000-000000000001",
            "cancellation_request_id": "019b0000-0000-7000-8000-000000000002",
            "cancellation_generation": 1,
            "disposition": "recorded"
        }))
        .expect("protocol receipt fixture should decode");
        let wire = serde_json::to_value(project_cancellation_receipt(&receipt))
            .expect("desktop receipt should encode");

        assert!(wire.get("runId").is_some());
        assert!(wire.get("cancellationRequestId").is_some());
        assert!(wire.get("cancellationGeneration").is_some());
        assert!(wire.get("run_id").is_none());
    }

    #[test]
    fn cancelled_run_never_exposes_or_fetches_an_earlier_accepted_plan() {
        assert!(accepted_plan_is_visible(
            birdcode_protocol::RunState::Completed
        ));
        assert!(!accepted_plan_is_visible(
            birdcode_protocol::RunState::Cancelled
        ));
    }

    #[test]
    fn pending_plan_start_is_a_typed_boundary_and_never_requires_string_parsing() {
        let session_id = SessionId::new();
        let run_id = RunId::new();
        let outcome = StartPlanOutcome::ReconciliationRequired(ReconciliationRequiredPlan {
            session_id,
            run_id,
            workspace_root: "/tmp/Bird Code".to_owned(),
            model_id: "exact-model".to_owned(),
            may_have_executed: true,
            message: "exact reconciliation required".to_owned(),
        });

        let wire = serde_json::to_value(outcome).expect("outcome should encode");

        assert_eq!(wire["status"], "reconciliation_required");
        assert_eq!(wire["data"]["sessionId"], session_id.to_string());
        assert_eq!(wire["data"]["runId"], run_id.to_string());
        assert_eq!(wire["data"]["mayHaveExecuted"], true);
        assert!(wire["data"].get("message").is_some());
        assert!(wire.get("error").is_none());
    }
}
