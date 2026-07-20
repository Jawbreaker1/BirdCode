//! Durable background supervision for one root-planning model turn.
//!
//! The supervisor deliberately owns no `SQLite` connection. Every durable phase
//! opens and drops a separate [`Store`] before the next asynchronous boundary,
//! so provider waits can never retain a database transaction or connection.

use birdcode_backends::{
    BackendError, BackendErrorKind, BackendId, ModelBackend, ModelCatalog, ModelId, ModelLoadState,
    ReasoningSetting, StructuredInferenceRequest, StructuredInferenceResponse,
};
use birdcode_prompting::{
    CompiledPrompt, PlanCriticOutput, PlanCriticPolicy, PlanCriticVerdict, PromptError,
    PromptInvocation, RootPlannerOutput, RootPlannerPolicy, RootPlannerRejectionClass,
    builtin_registry, classify_root_planner_rejection,
};
use birdcode_protocol::{
    ActorId, ArtifactRef, BackendCatalog, BackendKind, BackendModelIdentity, BackendSelection,
    CancellationRequestId, DiscoveredModel, EventEnvelope, EventId, EventPayload,
    InferenceAttemptId, ModelLineage, NewEvent, PlanAcceptanceContract, PlanCandidateBinding,
    PlanProposalAccepted, PlanProposalId, PlanProposalRejected, PlanProposalRejectionReason,
    PlanSemanticReviewAccepted, PlanSemanticReviewId, PlanSemanticReviewRejected,
    PlanSemanticReviewRejectionDisposition, PlanSemanticReviewValidatedVerdict,
    PlanSemanticReviewValidationReceipt, PlannerInferenceError, PlannerInferenceErrorKind,
    PlannerInferenceObservation, PlannerInferenceObserved, PlannerInferenceOutcomeUnknown,
    PlannerInferencePrepared, PlannerStageContext, Provenance,
    ROOT_PLANNING_EXECUTION_POLICY_MEDIA_TYPE, RetryDisposition, RootPlanningExecutionPolicy,
    RootPlanningFailed, RootPlanningFailurePhase, RootPlanningFailureReason, RootPlanningModelRole,
    RootPlanningModelSubject, RootPlanningStage, RootPlanningStageFailed,
    RootPlanningStageFailureId, RootPlanningStageFailureReason, Run, RunClaimId, RunClaimed, RunId,
    RunState, RuntimeInstanceId, Session, Sha256Digest, TokenReservation, TokenReservationId,
    TokenUsage, UnknownInferenceBoundary, UnknownInferenceOutcomeReason,
};
use birdcode_runtime::{
    MAX_ROOT_PLANNER_OUTPUT_TOKENS, RuntimePaths, compile_plan_critic_request,
    compile_plan_repair_request, compile_root_plan_request,
};
use birdcode_store::{DeadlineAppendOutcome, RunRecoveryPage, Store, StoreError};
use chrono::{Duration as ChronoDuration, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const SUPERVISOR_PRODUCER: &str = "birdcode-daemon-root-supervisor/1";
const PROMPT_MEDIA_TYPE: &str = "application/vnd.birdcode.root-prompt+json";
const REQUEST_MEDIA_TYPE: &str = "application/vnd.birdcode.inference-request+json";
const INFERENCE_MEDIA_TYPE: &str = "application/vnd.birdcode.inference-evidence+json";
const PROPOSAL_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-proposal+json";
const VALIDATION_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-validation+json";
const PLAN_MEDIA_TYPE: &str = "application/vnd.birdcode.accepted-plan+json";
const CANCELLATION_MEDIA_TYPE: &str = "application/vnd.birdcode.cancellation-boundary+json";
const ROOT_PLANNING_FAILURE_MEDIA_TYPE: &str =
    "application/vnd.birdcode.root-planning-failure+json";
const CRITIC_POLICY_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-critic-policy+json";
const CRITIQUE_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-critique+json";
const SEMANTIC_REVIEW_RECEIPT_MEDIA_TYPE: &str =
    "application/vnd.birdcode.plan-semantic-review-receipt+json";
const ROOT_PLANNING_STAGE_FAILURE_MEDIA_TYPE: &str =
    "application/vnd.birdcode.root-planning-stage-failure+json";
const MAX_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(8);
const MIN_CLAIM_LEASE: Duration = Duration::from_millis(30);
const MAX_TRANSITION_APPEND_ATTEMPTS: usize = 8;
const MIN_DURABLE_DISPATCH_BACKOFF: Duration = Duration::from_millis(50);
const MAX_DURABLE_DISPATCH_BACKOFF: Duration = Duration::from_secs(1);

/// Bounded policy for one background supervisor instance.
#[derive(Clone, Debug)]
pub struct RunSupervisorConfig {
    /// Stable across an intentional daemon restart when immediate claim
    /// recovery is desired. A new identity must wait for an old live lease.
    pub runtime_instance_id: RuntimeInstanceId,
    /// Stable actor paired with `runtime_instance_id` in durable claims.
    pub actor_id: ActorId,
    pub command_capacity: usize,
    pub worker_threads: usize,
    /// Hard limit on simultaneously supervised runs and therefore on model
    /// inference futures owned by this instance.
    pub max_concurrent_runs: usize,
    pub discovery_timeout: Duration,
    pub claim_lease: Duration,
    pub max_recovery_events: usize,
    /// Maximum durable run identifiers examined between cooperative yields.
    /// This is a scan quantum, not a ceiling on recoverable runs.
    pub max_startup_runs: usize,
    pub max_discovered_models: usize,
    pub default_max_output_tokens: u32,
    /// Trusted daemon-owned producer/reviewer identities and closed stage
    /// budgets. `None` can replay protocol-v4 legacy history but cannot start
    /// a new independently reviewed planning run.
    pub root_planning_policy: Option<RootPlanningExecutionPolicy>,
}

impl Default for RunSupervisorConfig {
    fn default() -> Self {
        Self {
            runtime_instance_id: RuntimeInstanceId::new(),
            actor_id: ActorId::new(),
            command_capacity: 128,
            worker_threads: 2,
            max_concurrent_runs: 2,
            discovery_timeout: Duration::from_secs(5),
            claim_lease: Duration::from_secs(60),
            max_recovery_events: 16_384,
            max_startup_runs: 4_096,
            max_discovered_models: 4_096,
            default_max_output_tokens: 4_096,
            root_planning_policy: None,
        }
    }
}

impl RunSupervisorConfig {
    fn validate(&self) -> Result<(), SupervisorStartError> {
        if self.command_capacity == 0 {
            return Err(SupervisorStartError::InvalidConfig("command_capacity"));
        }
        if self.worker_threads == 0 {
            return Err(SupervisorStartError::InvalidConfig("worker_threads"));
        }
        if self.max_concurrent_runs == 0 {
            return Err(SupervisorStartError::InvalidConfig("max_concurrent_runs"));
        }
        if self.discovery_timeout.is_zero() || self.discovery_timeout > MAX_DISCOVERY_TIMEOUT {
            return Err(SupervisorStartError::InvalidConfig("discovery_timeout"));
        }
        if self.claim_lease < MIN_CLAIM_LEASE {
            return Err(SupervisorStartError::InvalidConfig("claim_lease"));
        }
        if self.max_recovery_events == 0 {
            return Err(SupervisorStartError::InvalidConfig("max_recovery_events"));
        }
        if self.max_startup_runs == 0 {
            return Err(SupervisorStartError::InvalidConfig("max_startup_runs"));
        }
        if self.max_discovered_models == 0 {
            return Err(SupervisorStartError::InvalidConfig("max_discovered_models"));
        }
        if self.default_max_output_tokens == 0
            || self.default_max_output_tokens > MAX_ROOT_PLANNER_OUTPUT_TOKENS
        {
            return Err(SupervisorStartError::InvalidConfig(
                "default_max_output_tokens",
            ));
        }
        if let Some(policy) = &self.root_planning_policy {
            let trusted = crate::model_policy::TrustedRootPlanningPolicyConfig {
                schema_version: policy.schema_version,
                producer: policy.producer.clone(),
                critic: policy.critic.clone(),
                max_model_calls: policy.max_model_calls,
                max_repairs: policy.max_repairs,
                max_review_rounds: policy.max_review_rounds,
                stage_budgets: policy.stage_budgets.clone(),
            };
            if trusted.compile().ok().as_ref() != Some(policy) {
                return Err(SupervisorStartError::InvalidConfig("root_planning_policy"));
            }
        }
        ChronoDuration::from_std(self.claim_lease)
            .map_err(|_| SupervisorStartError::InvalidConfig("claim_lease"))?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum SupervisorStartError {
    InvalidConfig(&'static str),
    Io(io::Error),
}

impl fmt::Display for SupervisorStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(field) => write!(formatter, "invalid supervisor {field}"),
            Self::Io(error) => write!(formatter, "could not start supervisor: {error}"),
        }
    }
}

impl std::error::Error for SupervisorStartError {}

impl From<io::Error> for SupervisorStartError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorSubmitError {
    QueueFull,
    Closed,
    AlreadyActive,
}

impl fmt::Display for SupervisorSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => formatter.write_str("supervisor command queue is full"),
            Self::Closed => formatter.write_str("supervisor is shut down"),
            Self::AlreadyActive => formatter.write_str("run is already active in this supervisor"),
        }
    }
}

impl std::error::Error for SupervisorSubmitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorCancelDisposition {
    Signalled,
    AlreadySignalled,
    NotActive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisorDiscoveryError {
    QueueFull,
    Closed,
    TimedOut,
    Backend(String),
    CatalogTooLarge { maximum: usize, actual: usize },
}

impl fmt::Display for SupervisorDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => formatter.write_str("supervisor command queue is full"),
            Self::Closed => formatter.write_str("supervisor is shut down"),
            Self::TimedOut => formatter.write_str("bounded model discovery timed out"),
            Self::Backend(message) => write!(formatter, "model discovery failed: {message}"),
            Self::CatalogTooLarge { maximum, actual } => write!(
                formatter,
                "model catalog contains {actual} entries; maximum is {maximum}"
            ),
        }
    }
}

impl std::error::Error for SupervisorDiscoveryError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorShutdownError {
    BackgroundThreadPanicked,
}

impl fmt::Display for SupervisorShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("supervisor background thread panicked")
    }
}

impl std::error::Error for SupervisorShutdownError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunCompletion {
    Completed,
    Failed,
    Cancelled,
    Paused,
    AlreadyTerminal(RunState),
    Contended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunSupervisorEvent {
    Started {
        run_id: RunId,
    },
    Finished {
        run_id: RunId,
        completion: RunCompletion,
    },
    Failed {
        run_id: RunId,
        message: String,
    },
    BackgroundFailure {
        message: String,
    },
}

/// A direct, nonblocking cancellation signal for one submitted run.
#[derive(Clone, Debug)]
pub struct RunSubmission {
    run_id: RunId,
    cancellation: CancellationToken,
}

impl RunSubmission {
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

struct SubmitCommand {
    run_id: RunId,
    cancellation: CancellationToken,
}

struct DiscoveryCommand {
    reply: std::sync::mpsc::SyncSender<Result<BackendCatalog, SupervisorDiscoveryError>>,
}

/// Owns a dedicated Tokio runtime and schedules durable run work without
/// blocking the daemon's ordered protocol loop.
pub struct RunSupervisor {
    commands: mpsc::Sender<SubmitCommand>,
    discoveries: mpsc::Sender<DiscoveryCommand>,
    shutdown: CancellationToken,
    backend_id: BackendId,
    discovery_timeout: Duration,
    active_cancellations: Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    dispatch_wake: Arc<Notify>,
    events: Mutex<std::sync::mpsc::Receiver<RunSupervisorEvent>>,
    thread: Option<JoinHandle<()>>,
}

impl RunSupervisor {
    /// Starts the background runtime and returns only after the thread and
    /// bounded command queue have been constructed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, runtime path preparation, Tokio
    /// runtime construction, or OS thread creation.
    pub fn start(
        paths: RuntimePaths,
        backend: Arc<dyn ModelBackend>,
        config: RunSupervisorConfig,
    ) -> Result<Self, SupervisorStartError> {
        config.validate()?;
        paths.prepare()?;
        let runtime = RuntimeBuilder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .enable_all()
            .build()?;
        let (commands, receiver) = mpsc::channel(config.command_capacity);
        let (discoveries, discovery_receiver) = mpsc::channel(config.command_capacity);
        let notification_capacity = config.command_capacity.saturating_mul(2).max(1);
        let (event_sender, events) = std::sync::mpsc::sync_channel(notification_capacity);
        let shutdown = CancellationToken::new();
        let active_cancellations = Arc::new(Mutex::new(BTreeMap::new()));
        let dispatch_wake = Arc::new(Notify::new());
        let background_shutdown = shutdown.clone();
        let background_cancellations = Arc::clone(&active_cancellations);
        let background_commands = commands.clone();
        let background_dispatch_wake = Arc::clone(&dispatch_wake);
        let backend_id = backend.backend_id().clone();
        let discovery_timeout = config.discovery_timeout;
        let thread = std::thread::Builder::new()
            .name("birdcode-run-supervisor".to_owned())
            .spawn(move || {
                runtime.block_on(supervisor_loop(
                    paths,
                    backend,
                    config,
                    background_commands,
                    receiver,
                    discovery_receiver,
                    event_sender,
                    background_shutdown,
                    background_cancellations,
                    background_dispatch_wake,
                ));
            })?;
        Ok(Self {
            commands,
            discoveries,
            shutdown,
            backend_id,
            discovery_timeout,
            active_cancellations,
            dispatch_wake,
            events: Mutex::new(events),
            thread: Some(thread),
        })
    }

    /// Enqueues a run without waiting for discovery, storage, or inference.
    ///
    /// # Errors
    ///
    /// Fails immediately when the bounded queue is full or closed.
    pub fn submit(&self, run_id: RunId) -> Result<RunSubmission, SupervisorSubmitError> {
        let cancellation = CancellationToken::new();
        {
            let mut active = self
                .active_cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if active.contains_key(&run_id) {
                return Err(SupervisorSubmitError::AlreadyActive);
            }
            active.insert(run_id, cancellation.clone());
        }
        if let Err(error) = self.commands.try_send(SubmitCommand {
            run_id,
            cancellation: cancellation.clone(),
        }) {
            self.active_cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&run_id);
            let error = match error {
                mpsc::error::TrySendError::Full(_) => SupervisorSubmitError::QueueFull,
                mpsc::error::TrySendError::Closed(_) => SupervisorSubmitError::Closed,
            };
            if error == SupervisorSubmitError::QueueFull {
                self.dispatch_wake.notify_one();
            }
            return Err(error);
        }
        Ok(RunSubmission {
            run_id,
            cancellation,
        })
    }

    #[must_use]
    pub const fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    /// Performs provider discovery on the background runtime and waits only
    /// for the configured bounded deadline. It never creates an inference
    /// request or model-generation future.
    ///
    /// # Errors
    ///
    /// Returns immediately for queue pressure/closure and otherwise no later
    /// than the configured discovery timeout plus command handoff allowance.
    pub fn discover_models(&self) -> Result<BackendCatalog, SupervisorDiscoveryError> {
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        self.discoveries
            .try_send(DiscoveryCommand { reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SupervisorDiscoveryError::QueueFull,
                mpsc::error::TrySendError::Closed(_) => SupervisorDiscoveryError::Closed,
            })?;
        let handoff = self
            .discovery_timeout
            .checked_add(Duration::from_millis(500))
            .unwrap_or(self.discovery_timeout);
        result.recv_timeout(handoff).map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => SupervisorDiscoveryError::TimedOut,
            std::sync::mpsc::RecvTimeoutError::Disconnected => SupervisorDiscoveryError::Closed,
        })?
    }

    /// Signals an active run without requiring the caller to retain its
    /// [`RunSubmission`]. Repeated calls are idempotent.
    #[must_use]
    pub fn cancel(&self, run_id: RunId) -> SupervisorCancelDisposition {
        let token = self
            .active_cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&run_id)
            .cloned();
        let Some(token) = token else {
            return SupervisorCancelDisposition::NotActive;
        };
        if token.is_cancelled() {
            SupervisorCancelDisposition::AlreadySignalled
        } else {
            token.cancel();
            SupervisorCancelDisposition::Signalled
        }
    }

    /// Returns the next lifecycle notification without blocking.
    #[must_use]
    pub fn try_next_event(&self) -> Option<RunSupervisorEvent> {
        self.events.lock().ok()?.try_recv().ok()
    }

    /// Cancels active futures, lets tasks retain their ambiguity boundaries,
    /// and joins the background runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the background thread panicked.
    pub fn shutdown(mut self) -> Result<(), SupervisorShutdownError> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> Result<(), SupervisorShutdownError> {
        self.shutdown.cancel();
        if self
            .thread
            .take()
            .is_some_and(|thread| thread.join().is_err())
        {
            return Err(SupervisorShutdownError::BackgroundThreadPanicked);
        }
        Ok(())
    }
}

impl Drop for RunSupervisor {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn supervisor_loop(
    paths: RuntimePaths,
    backend: Arc<dyn ModelBackend>,
    config: RunSupervisorConfig,
    durable_commands: mpsc::Sender<SubmitCommand>,
    mut commands: mpsc::Receiver<SubmitCommand>,
    mut discoveries: mpsc::Receiver<DiscoveryCommand>,
    events: std::sync::mpsc::SyncSender<RunSupervisorEvent>,
    shutdown: CancellationToken,
    active_cancellations: Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    dispatch_wake: Arc<Notify>,
) {
    let mut tasks = JoinSet::new();
    let mut task_runs = HashMap::new();
    let mut pending = VecDeque::new();
    let mut dispatcher = tokio::spawn(durable_dispatch_loop(
        paths.clone(),
        durable_commands,
        Arc::clone(&active_cancellations),
        Arc::clone(&dispatch_wake),
        shutdown.clone(),
        config.max_startup_runs,
        events.clone(),
    ));
    let mut dispatcher_finished = false;
    let mut commands_open = true;
    let mut discoveries_open = true;
    loop {
        while tasks.len() < config.max_concurrent_runs {
            let Some(command) = pending.pop_front() else {
                break;
            };
            spawn_run_task(
                &mut tasks,
                &mut task_runs,
                &events,
                &paths,
                &backend,
                &config,
                &shutdown,
                command,
            );
        }
        if !commands_open && !discoveries_open && pending.is_empty() && tasks.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                if let Some(run_id) = publish_joined(&events, &mut task_runs, joined) {
                    active_cancellations
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&run_id);
                    dispatch_wake.notify_one();
                }
            }
            dispatcher_result = &mut dispatcher, if !dispatcher_finished => {
                dispatcher_finished = true;
                let message = match dispatcher_result {
                    Ok(DurableDispatcherExit::Shutdown) => {
                        "durable dispatcher stopped before supervisor shutdown".to_owned()
                    }
                    Ok(DurableDispatcherExit::CommandChannelClosed) => {
                        "durable dispatcher command channel closed unexpectedly".to_owned()
                    }
                    Err(error) => format!("durable dispatcher task failed: {error}"),
                };
                let _ = events.try_send(RunSupervisorEvent::BackgroundFailure { message });
                shutdown.cancel();
                break;
            }
            command = commands.recv(), if commands_open && pending.len() < config.command_capacity => {
                match command {
                    Some(command) => pending.push_back(command),
                    None => commands_open = false,
                }
            }
            discovery = discoveries.recv(), if discoveries_open => {
                match discovery {
                    Some(discovery) => {
                        let result = discover_for_protocol(&*backend, &config).await;
                        let _ = discovery.reply.send(result);
                    }
                    None => discoveries_open = false,
                }
            }
        }
    }
    shutdown.cancel();
    if !dispatcher_finished {
        let _ = dispatcher.await;
    }
    commands.close();
    discoveries.close();
    for command in pending {
        active_cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&command.run_id);
    }
    while let Ok(command) = commands.try_recv() {
        active_cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&command.run_id);
    }
    while let Some(joined) = tasks.join_next_with_id().await {
        if let Some(run_id) = publish_joined(&events, &mut task_runs, Some(joined)) {
            active_cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&run_id);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableDispatcherExit {
    Shutdown,
    CommandChannelClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableAdmission {
    Enqueued,
    AlreadyActive,
    Shutdown,
    CommandChannelClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableDispatchWait {
    Shutdown,
    Notified,
    Elapsed,
}

#[allow(clippy::too_many_arguments)]
async fn durable_dispatch_loop(
    paths: RuntimePaths,
    commands: mpsc::Sender<SubmitCommand>,
    active_cancellations: Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    wake: Arc<Notify>,
    shutdown: CancellationToken,
    scan_quantum: usize,
    events: std::sync::mpsc::SyncSender<RunSupervisorEvent>,
) -> DurableDispatcherExit {
    let mut cursor = None;
    let mut scanned_since_yield = 0_usize;
    let mut backoff = MIN_DURABLE_DISPATCH_BACKOFF;
    loop {
        let page = tokio::select! {
            biased;
            () = shutdown.cancelled() => return DurableDispatcherExit::Shutdown,
            page = load_nonterminal_page(paths.clone(), cursor) => page,
        };
        let page = match page {
            Ok(page) => page,
            Err(error) => {
                let _ = events.try_send(RunSupervisorEvent::BackgroundFailure {
                    message: format!("durable dispatch scan failed: {error}"),
                });
                match wait_for_durable_dispatch(&wake, &shutdown, backoff).await {
                    DurableDispatchWait::Shutdown => return DurableDispatcherExit::Shutdown,
                    DurableDispatchWait::Notified => backoff = MIN_DURABLE_DISPATCH_BACKOFF,
                    DurableDispatchWait::Elapsed => {
                        backoff = next_durable_dispatch_backoff(backoff);
                    }
                }
                continue;
            }
        };

        if page.runs.is_empty() {
            if page.has_more {
                let _ = events.try_send(RunSupervisorEvent::BackgroundFailure {
                    message: "durable dispatch page was empty but claimed more results".to_owned(),
                });
            } else {
                cursor = None;
            }
            match wait_for_durable_dispatch(&wake, &shutdown, backoff).await {
                DurableDispatchWait::Shutdown => return DurableDispatcherExit::Shutdown,
                DurableDispatchWait::Notified => backoff = MIN_DURABLE_DISPATCH_BACKOFF,
                DurableDispatchWait::Elapsed => {
                    backoff = next_durable_dispatch_backoff(backoff);
                }
            }
            continue;
        }

        let has_more = page.has_more;
        for run in page.runs {
            match enqueue_durable_run(&commands, &active_cancellations, &shutdown, run.id).await {
                DurableAdmission::Enqueued | DurableAdmission::AlreadyActive => {
                    cursor = Some(run.id);
                }
                DurableAdmission::Shutdown => return DurableDispatcherExit::Shutdown,
                DurableAdmission::CommandChannelClosed => {
                    return DurableDispatcherExit::CommandChannelClosed;
                }
            }
            scanned_since_yield += 1;
            if scanned_since_yield == scan_quantum {
                scanned_since_yield = 0;
                tokio::task::yield_now().await;
            }
        }

        if has_more {
            continue;
        }
        cursor = None;
        match wait_for_durable_dispatch(&wake, &shutdown, backoff).await {
            DurableDispatchWait::Shutdown => return DurableDispatcherExit::Shutdown,
            DurableDispatchWait::Notified => backoff = MIN_DURABLE_DISPATCH_BACKOFF,
            DurableDispatchWait::Elapsed => {
                backoff = next_durable_dispatch_backoff(backoff);
            }
        }
    }
}

async fn load_nonterminal_page(
    paths: RuntimePaths,
    cursor: Option<RunId>,
) -> Result<RunRecoveryPage, SupervisorRunError> {
    store_phase(paths, move |store| {
        store.nonterminal_runs(cursor).map_err(Into::into)
    })
    .await
}

async fn enqueue_durable_run(
    commands: &mpsc::Sender<SubmitCommand>,
    active_cancellations: &Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    shutdown: &CancellationToken,
    run_id: RunId,
) -> DurableAdmission {
    if active_cancellations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains_key(&run_id)
    {
        return DurableAdmission::AlreadyActive;
    }

    let permit = tokio::select! {
        biased;
        () = shutdown.cancelled() => return DurableAdmission::Shutdown,
        permit = commands.reserve() => match permit {
            Ok(permit) => permit,
            Err(_) => return DurableAdmission::CommandChannelClosed,
        },
    };
    if shutdown.is_cancelled() {
        return DurableAdmission::Shutdown;
    }

    let cancellation = CancellationToken::new();
    let mut active = active_cancellations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let std::collections::btree_map::Entry::Vacant(entry) = active.entry(run_id) else {
        return DurableAdmission::AlreadyActive;
    };
    entry.insert(cancellation.clone());
    permit.send(SubmitCommand {
        run_id,
        cancellation,
    });
    DurableAdmission::Enqueued
}

async fn wait_for_durable_dispatch(
    wake: &Notify,
    shutdown: &CancellationToken,
    delay: Duration,
) -> DurableDispatchWait {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => DurableDispatchWait::Shutdown,
        () = wake.notified() => DurableDispatchWait::Notified,
        () = tokio::time::sleep(delay) => DurableDispatchWait::Elapsed,
    }
}

fn next_durable_dispatch_backoff(current: Duration) -> Duration {
    current
        .checked_mul(2)
        .unwrap_or(MAX_DURABLE_DISPATCH_BACKOFF)
        .min(MAX_DURABLE_DISPATCH_BACKOFF)
}

type RunTaskOutput = (RunId, Result<RunCompletion, SupervisorRunError>);
type JoinedRunTask = Result<(tokio::task::Id, RunTaskOutput), tokio::task::JoinError>;

#[allow(clippy::too_many_arguments)]
fn spawn_run_task(
    tasks: &mut JoinSet<RunTaskOutput>,
    task_runs: &mut HashMap<tokio::task::Id, RunId>,
    events: &std::sync::mpsc::SyncSender<RunSupervisorEvent>,
    paths: &RuntimePaths,
    backend: &Arc<dyn ModelBackend>,
    config: &RunSupervisorConfig,
    shutdown: &CancellationToken,
    command: SubmitCommand,
) {
    let _ = events.try_send(RunSupervisorEvent::Started {
        run_id: command.run_id,
    });
    let run_paths = paths.clone();
    let run_backend = Arc::clone(backend);
    let run_config = config.clone();
    let run_shutdown = shutdown.clone();
    let run_id = command.run_id;
    let abort_handle = tasks.spawn(async move {
        let result = Box::pin(supervise_run(
            run_paths,
            run_backend,
            run_config,
            command.run_id,
            command.cancellation,
            run_shutdown,
        ))
        .await;
        (command.run_id, result)
    });
    task_runs.insert(abort_handle.id(), run_id);
}

fn publish_joined(
    events: &std::sync::mpsc::SyncSender<RunSupervisorEvent>,
    task_runs: &mut HashMap<tokio::task::Id, RunId>,
    joined: Option<JoinedRunTask>,
) -> Option<RunId> {
    let joined = joined?;
    let (run_id, event) = match joined {
        Ok((task_id, (run_id, Ok(completion)))) => {
            task_runs.remove(&task_id);
            (
                Some(run_id),
                RunSupervisorEvent::Finished { run_id, completion },
            )
        }
        Ok((task_id, (run_id, Err(error)))) => {
            task_runs.remove(&task_id);
            (
                Some(run_id),
                RunSupervisorEvent::Failed {
                    run_id,
                    message: error.to_string(),
                },
            )
        }
        Err(error) => {
            let run_id = task_runs.remove(&error.id());
            (
                run_id,
                RunSupervisorEvent::BackgroundFailure {
                    message: format!("supervisor task join failed: {error}"),
                },
            )
        }
    };
    let _ = events.try_send(event);
    run_id
}

async fn discover_for_protocol(
    backend: &dyn ModelBackend,
    config: &RunSupervisorConfig,
) -> Result<BackendCatalog, SupervisorDiscoveryError> {
    let catalog = tokio::time::timeout(config.discovery_timeout, backend.discover_models())
        .await
        .map_err(|_| SupervisorDiscoveryError::TimedOut)?
        .map_err(|error| SupervisorDiscoveryError::Backend(error.to_string()))?;
    if &catalog.backend_id != backend.backend_id() {
        return Err(SupervisorDiscoveryError::Backend(
            "discovery returned another backend identity".to_owned(),
        ));
    }
    if catalog.models.len() > config.max_discovered_models {
        return Err(SupervisorDiscoveryError::CatalogTooLarge {
            maximum: config.max_discovered_models,
            actual: catalog.models.len(),
        });
    }
    let backend_id = catalog.backend_id.as_str().to_owned();
    Ok(BackendCatalog {
        discovered_at: Utc::now(),
        models: catalog
            .models
            .into_iter()
            .filter(|model| model.load_state == ModelLoadState::Loaded)
            .map(|model| DiscoveredModel {
                identity: BackendModelIdentity {
                    backend_id: backend_id.clone(),
                    kind: BackendKind::Model,
                    model_id: model.id.as_str().to_owned(),
                },
                display_name: model.display_name,
                context_window_tokens: model.maximum_context_tokens,
                // The provider-neutral backend contract does not currently
                // expose a distinct maximum-generation field.
                max_output_tokens: None,
            })
            .collect(),
    })
}

#[derive(Debug)]
enum SupervisorRunError {
    Store(StoreError),
    ArtifactPersistence(StoreError),
    Io(io::Error),
    InvalidState(String),
    CommittedArtifact(String),
    Contract(String),
    Background(String),
}

impl fmt::Display for SupervisorRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::ArtifactPersistence(error) => {
                write!(
                    formatter,
                    "could not persist a new runtime artifact: {error}"
                )
            }
            Self::Io(error) => error.fmt(formatter),
            Self::InvalidState(message) => {
                write!(formatter, "invalid durable run state: {message}")
            }
            Self::CommittedArtifact(message) => {
                write!(formatter, "invalid committed inference artifact: {message}")
            }
            Self::Contract(message) => write!(formatter, "planner contract failed: {message}"),
            Self::Background(message) => {
                write!(formatter, "background operation failed: {message}")
            }
        }
    }
}

impl std::error::Error for SupervisorRunError {}

impl From<StoreError> for SupervisorRunError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<io::Error> for SupervisorRunError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn persist_new_artifact(
    store: &Store,
    bytes: &[u8],
    media_type: &str,
) -> Result<ArtifactRef, SupervisorRunError> {
    store
        .put_artifact(bytes, media_type)
        .map_err(SupervisorRunError::ArtifactPersistence)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedPrompt {
    prompt_invocation: PromptInvocation,
    compiled_prompt: CompiledPrompt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedRequest {
    request: StructuredInferenceRequest,
    request_sha256: Sha256Digest,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum RetainedInferenceEvidence {
    Response {
        response: StructuredInferenceResponse,
    },
    Error {
        error: BackendError,
    },
    CancelledBeforeCall,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedValidation {
    status: &'static str,
    violations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedCancellationBoundary {
    reason: UnknownInferenceBoundary,
    prepared_event_id: EventId,
    cancellation_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedRootPlanningFailure {
    schema_version: u32,
    run_id: RunId,
    claim_event_id: EventId,
    claim_id: RunClaimId,
    phase: RootPlanningFailurePhase,
    reason: RootPlanningFailureReason,
    model_subject: Option<RootPlanningModelSubject>,
    detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedRootPlanningStageFailure {
    schema_version: u32,
    run_id: RunId,
    failed_stage: RootPlanningStage,
    predecessor_event_id: EventId,
    execution_policy_sha256: Sha256Digest,
    reason: RootPlanningStageFailureReason,
    model_subject: RootPlanningModelSubject,
    detail: String,
}

#[derive(Clone, Debug)]
struct PreInferenceFailure {
    phase: RootPlanningFailurePhase,
    reason: RootPlanningFailureReason,
    model_subject: Option<Box<RootPlanningModelSubject>>,
    detail: String,
}

impl PreInferenceFailure {
    fn new(
        phase: RootPlanningFailurePhase,
        reason: RootPlanningFailureReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            reason,
            model_subject: None,
            detail: detail.into(),
        }
    }

    fn for_model(
        phase: RootPlanningFailurePhase,
        reason: RootPlanningFailureReason,
        role: RootPlanningModelRole,
        lineage: &ModelLineage,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            reason,
            model_subject: Some(Box::new(RootPlanningModelSubject {
                role,
                lineage: lineage.clone(),
            })),
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug)]
struct AttemptReplay {
    prepared: EventEnvelope,
    observed: Option<EventEnvelope>,
    unknown: Option<EventEnvelope>,
    decision: Option<EventEnvelope>,
}

#[derive(Clone, Debug)]
struct RunHistory {
    last_event_id: Option<EventId>,
    latest_claim: Option<(EventEnvelope, RunClaimed)>,
    cancellation_generation: u64,
    root_planning_failure: Option<EventEnvelope>,
    root_planning_stage_failure: Option<EventEnvelope>,
    attempts: BTreeMap<InferenceAttemptId, AttemptReplay>,
}

impl RunHistory {
    fn uses_independent_semantic_review(&self) -> bool {
        self.attempts.values().any(|attempt| {
            matches!(
                &attempt.prepared.payload,
                EventPayload::PlannerInferencePrepared(prepared)
                    if prepared.stage_context.is_some()
            )
        })
    }

    fn attempt_for_stage(&self, stage: RootPlanningStage) -> Option<&AttemptReplay> {
        self.attempts.values().find(|attempt| {
            let EventPayload::PlannerInferencePrepared(prepared) = &attempt.prepared.payload else {
                return false;
            };
            matches!(
                (&prepared.stage_context, stage),
                (
                    Some(PlannerStageContext::InitialPlan { .. }),
                    RootPlanningStage::InitialPlan
                ) | (
                    Some(PlannerStageContext::InitialReview { .. }),
                    RootPlanningStage::InitialReview
                ) | (
                    Some(PlannerStageContext::Repair { .. }),
                    RootPlanningStage::Repair
                ) | (
                    Some(PlannerStageContext::FinalReview { .. }),
                    RootPlanningStage::FinalReview
                )
            )
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed replay state machine is kept contiguous for auditability"
    )]
    fn recovery_action(&self) -> Result<RecoveryAction, SupervisorRunError> {
        if self.root_planning_failure.is_some() {
            if !self.attempts.is_empty() {
                return Err(SupervisorRunError::InvalidState(
                    "pre-inference failure follows a prepared attempt".to_owned(),
                ));
            }
            return Ok(RecoveryAction::Terminal(RunState::Failed));
        }
        if self.root_planning_stage_failure.is_some() {
            return Ok(RecoveryAction::Terminal(RunState::Failed));
        }
        let mut attempts = self.attempts.values().collect::<Vec<_>>();
        attempts.sort_by_key(|attempt| attempt.prepared.sequence);
        let mut unresolved = Vec::new();
        for attempt in &attempts {
            if attempt.unknown.is_none() && attempt.observed.is_none() {
                unresolved.push(RecoveryAction::Prepared(attempt.prepared.clone()));
            } else if attempt.unknown.is_none()
                && attempt.observed.is_some()
                && attempt.decision.is_none()
            {
                unresolved.push(RecoveryAction::Observed {
                    prepared: attempt.prepared.clone(),
                    observed: attempt.observed.clone().ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "observed recovery lost its observation".to_owned(),
                        )
                    })?,
                });
            }
        }
        if unresolved.len() > 1 {
            return Err(SupervisorRunError::InvalidState(
                "more than one inference attempt is unresolved".to_owned(),
            ));
        }
        if let Some(action) = unresolved.pop() {
            return Ok(action);
        }

        let latest = attempts
            .iter()
            .filter_map(|attempt| {
                attempt
                    .decision
                    .as_ref()
                    .or(attempt.unknown.as_ref())
                    .map(|event| (event.sequence, &event.payload))
            })
            .max_by_key(|(sequence, _)| *sequence);
        let enhanced = attempts.first().is_some_and(|attempt| {
            matches!(
                &attempt.prepared.payload,
                EventPayload::PlannerInferencePrepared(prepared)
                    if prepared.stage_context.is_some()
            )
        });
        Ok(match latest {
            Some((_, EventPayload::PlanProposalAccepted(accepted))) if enhanced => {
                let attempt = self
                    .attempts
                    .get(&accepted.inference_attempt_id)
                    .ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "accepted candidate has no prepared stage".to_owned(),
                        )
                    })?;
                let EventPayload::PlannerInferencePrepared(prepared) = &attempt.prepared.payload
                else {
                    return Err(SupervisorRunError::InvalidState(
                        "accepted candidate preparation has wrong event type".to_owned(),
                    ));
                };
                match prepared.stage_context.as_ref() {
                    Some(birdcode_protocol::PlannerStageContext::InitialPlan { .. }) => {
                        RecoveryAction::NextStage(RootPlanningStage::InitialReview)
                    }
                    Some(birdcode_protocol::PlannerStageContext::Repair { .. }) => {
                        RecoveryAction::NextStage(RootPlanningStage::FinalReview)
                    }
                    _ => {
                        return Err(SupervisorRunError::InvalidState(
                            "review stage produced a plan proposal".to_owned(),
                        ));
                    }
                }
            }
            Some((_, EventPayload::PlanProposalAccepted(_))) => {
                RecoveryAction::Terminal(RunState::Completed)
            }
            Some((_, EventPayload::PlanSemanticReviewAccepted(_))) if enhanced => {
                RecoveryAction::Terminal(RunState::Completed)
            }
            Some((_, EventPayload::PlanSemanticReviewRejected(rejected))) if enhanced => {
                if rejected.disposition
                    == birdcode_protocol::PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
                {
                    RecoveryAction::NextStage(RootPlanningStage::Repair)
                } else {
                    RecoveryAction::Terminal(RunState::Failed)
                }
            }
            Some((
                _,
                EventPayload::PlanProposalRejected(_)
                | EventPayload::PlannerInferenceOutcomeUnknown(_)
                | EventPayload::RootPlanningStageFailed(_),
            )) => RecoveryAction::Terminal(RunState::Failed),
            Some(_) => {
                return Err(SupervisorRunError::InvalidState(
                    "attempt terminal has the wrong event type".to_owned(),
                ));
            }
            None => RecoveryAction::Fresh,
        })
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum RecoveryAction {
    Fresh,
    NextStage(RootPlanningStage),
    Prepared(EventEnvelope),
    Observed {
        prepared: EventEnvelope,
        observed: EventEnvelope,
    },
    Terminal(RunState),
}

#[allow(clippy::large_enum_variant)]
enum BeginRun {
    Ready {
        session: Session,
        run: Run,
        history: RunHistory,
    },
    AlreadyTerminal(RunState),
    LeaseBlocked {
        expires_at: chrono::DateTime<Utc>,
        deadline: Option<chrono::DateTime<Utc>>,
    },
}

async fn store_phase<T, Operation>(
    paths: RuntimePaths,
    operation: Operation,
) -> Result<T, SupervisorRunError>
where
    T: Send + 'static,
    Operation: FnOnce(&mut Store) -> Result<T, SupervisorRunError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open(paths.database(), paths.artifacts())?;
        operation(&mut store)
    })
    .await
    .map_err(|error| SupervisorRunError::Background(error.to_string()))?
}

async fn acquire_run_lock(
    paths: RuntimePaths,
    run_id: RunId,
) -> Result<Option<File>, SupervisorRunError> {
    tokio::task::spawn_blocking(move || acquire_run_lock_sync(&paths, run_id))
        .await
        .map_err(|error| SupervisorRunError::Background(error.to_string()))?
}

fn acquire_run_lock_sync(
    paths: &RuntimePaths,
    run_id: RunId,
) -> Result<Option<File>, SupervisorRunError> {
    let directory = paths.root().join("run-locks");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{run_id}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[allow(clippy::too_many_lines)]
fn load_run_history(
    store: &Store,
    run_id: RunId,
    maximum: usize,
) -> Result<RunHistory, SupervisorRunError> {
    let mut cursor = 0;
    let mut count = 0_usize;
    let mut last_event_id = None;
    let mut latest_claim = None;
    let mut cancellation_generation = 0_u64;
    let mut root_planning_failure = None;
    let mut root_planning_stage_failure = None;
    let mut attempts = BTreeMap::<InferenceAttemptId, AttemptReplay>::new();
    loop {
        let page = store.events_for_run_after(run_id, cursor)?;
        count = count
            .checked_add(page.events.len())
            .ok_or_else(|| SupervisorRunError::InvalidState("event count overflow".to_owned()))?;
        if count > maximum {
            return Err(SupervisorRunError::InvalidState(format!(
                "run recovery exceeds {maximum} events"
            )));
        }
        for event in page.events {
            last_event_id = Some(event.id);
            match &event.payload {
                EventPayload::RunClaimed(claim) => {
                    latest_claim = Some((event.clone(), claim.clone()));
                }
                EventPayload::CancellationRequested(cancellation) => {
                    cancellation_generation =
                        cancellation_generation.max(cancellation.cancellation_generation);
                }
                EventPayload::RootPlanningFailed(_) => {
                    if root_planning_failure.replace(event.clone()).is_some() {
                        return Err(SupervisorRunError::InvalidState(
                            "duplicate pre-inference failure".to_owned(),
                        ));
                    }
                }
                EventPayload::RootPlanningStageFailed(_) => {
                    if root_planning_stage_failure.replace(event.clone()).is_some() {
                        return Err(SupervisorRunError::InvalidState(
                            "duplicate planning stage failure".to_owned(),
                        ));
                    }
                }
                EventPayload::PlannerInferencePrepared(prepared) => {
                    if attempts
                        .insert(
                            prepared.attempt_id,
                            AttemptReplay {
                                prepared: event.clone(),
                                observed: None,
                                unknown: None,
                                decision: None,
                            },
                        )
                        .is_some()
                    {
                        return Err(SupervisorRunError::InvalidState(
                            "duplicate prepared inference".to_owned(),
                        ));
                    }
                }
                EventPayload::PlannerInferenceObserved(observed) => {
                    let attempt = attempts.get_mut(&observed.attempt_id).ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "observation precedes preparation".to_owned(),
                        )
                    })?;
                    if attempt.observed.replace(event.clone()).is_some()
                        || attempt.unknown.is_some()
                    {
                        return Err(SupervisorRunError::InvalidState(
                            "duplicate inference terminal".to_owned(),
                        ));
                    }
                }
                EventPayload::PlannerInferenceOutcomeUnknown(unknown) => {
                    let attempt = attempts.get_mut(&unknown.attempt_id).ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "unknown outcome precedes preparation".to_owned(),
                        )
                    })?;
                    if attempt.unknown.replace(event.clone()).is_some()
                        || attempt.observed.is_some()
                    {
                        return Err(SupervisorRunError::InvalidState(
                            "duplicate inference terminal".to_owned(),
                        ));
                    }
                }
                EventPayload::PlanProposalAccepted(accepted) => {
                    attach_decision(&mut attempts, accepted.inference_attempt_id, event.clone())?;
                }
                EventPayload::PlanProposalRejected(rejected) => {
                    attach_decision(&mut attempts, rejected.inference_attempt_id, event.clone())?;
                }
                EventPayload::PlanSemanticReviewAccepted(accepted) => {
                    attach_decision(&mut attempts, accepted.inference_attempt_id, event.clone())?;
                }
                EventPayload::PlanSemanticReviewRejected(rejected) => {
                    attach_decision(&mut attempts, rejected.inference_attempt_id, event.clone())?;
                }
                _ => {}
            }
        }
        cursor = page.next_sequence;
        if !page.has_more {
            break;
        }
    }
    Ok(RunHistory {
        last_event_id,
        latest_claim,
        cancellation_generation,
        root_planning_failure,
        root_planning_stage_failure,
        attempts,
    })
}

fn attach_decision(
    attempts: &mut BTreeMap<InferenceAttemptId, AttemptReplay>,
    attempt_id: InferenceAttemptId,
    event: EventEnvelope,
) -> Result<(), SupervisorRunError> {
    let attempt = attempts.get_mut(&attempt_id).ok_or_else(|| {
        SupervisorRunError::InvalidState("decision precedes preparation".to_owned())
    })?;
    if attempt.observed.is_none() || attempt.decision.replace(event).is_some() {
        return Err(SupervisorRunError::InvalidState(
            "decision is duplicated or lacks observation".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn supervise_run(
    paths: RuntimePaths,
    backend: Arc<dyn ModelBackend>,
    config: RunSupervisorConfig,
    run_id: RunId,
    cancellation: CancellationToken,
    shutdown: CancellationToken,
) -> Result<RunCompletion, SupervisorRunError> {
    let Some(_lock) = acquire_run_lock(paths.clone(), run_id).await? else {
        return Ok(RunCompletion::Contended);
    };

    let mut deadline_elapsed_while_waiting = false;
    let (_session, run, history) = loop {
        match begin_run(paths.clone(), run_id, config.clone()).await? {
            BeginRun::Ready {
                session,
                run,
                history,
            } => break (session, run, history),
            BeginRun::AlreadyTerminal(state) => {
                return Ok(RunCompletion::AlreadyTerminal(state));
            }
            BeginRun::LeaseBlocked {
                expires_at,
                deadline,
            } => {
                let wait = (expires_at - Utc::now()).to_std().unwrap_or(Duration::ZERO);
                if deadline_elapsed_while_waiting || deadline_elapsed(deadline) {
                    deadline_elapsed_while_waiting = true;
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => return Ok(RunCompletion::Contended),
                        () = tokio::time::sleep(wait) => {}
                    }
                } else {
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => return Ok(RunCompletion::Contended),
                        () = tokio::time::sleep(wait) => {}
                        () = wait_for_deadline(deadline) => {
                            // A foreign claim remains authoritative until its
                            // lease expires. Remember the stable deadline and
                            // acquire ownership only to durably fail the run.
                            deadline_elapsed_while_waiting = true;
                        }
                    }
                }
            }
        }
    };

    let recovery = history.recovery_action()?;
    if run.spec.plan_acceptance == PlanAcceptanceContract::IndependentSemanticReviewV1 {
        return Box::pin(supervise_semantic_run(
            paths,
            backend,
            config,
            run,
            history,
            cancellation,
            shutdown,
        ))
        .await;
    }
    if run.spec.plan_acceptance != PlanAcceptanceContract::LegacyMechanicalOnlyV4
        || history.uses_independent_semantic_review()
    {
        return Err(SupervisorRunError::InvalidState(
            "plan run acceptance contract does not match its durable planner history".to_owned(),
        ));
    }
    if history.cancellation_generation > 0 && !matches!(&recovery, RecoveryAction::Prepared(_)) {
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Cancelled,
        )
        .await?;
        return Ok(completion_for_state(actual));
    }

    match recovery {
        RecoveryAction::Prepared(prepared) => {
            let cancelled = history.cancellation_generation > 0 || cancellation.is_cancelled();
            if cancellation.is_cancelled() && history.cancellation_generation == 0 {
                ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
                renew_claim(paths.clone(), run_id, config.clone()).await?;
            }
            append_unknown(
                paths.clone(),
                run_id,
                config.actor_id,
                config.max_recovery_events,
                prepared,
                UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
                if cancelled {
                    UnknownInferenceBoundary::Cancelled
                } else {
                    UnknownInferenceBoundary::Restart
                },
            )
            .await?;
            let state = if cancelled {
                RunState::Cancelled
            } else {
                RunState::Failed
            };
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                state,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        RecoveryAction::Observed { prepared, observed } => {
            return resume_observed(paths, run_id, config, prepared, observed).await;
        }
        RecoveryAction::Terminal(state) => {
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                state,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        RecoveryAction::NextStage(stage) => {
            return Err(SupervisorRunError::InvalidState(format!(
                "enhanced planning stage {stage:?} is durable but its executor is not configured"
            )));
        }
        RecoveryAction::Fresh => {}
    }

    let deadline = match run_deadline(&run) {
        Ok(deadline) => deadline,
        Err(error) => {
            let actual = fail_before_inference(
                paths.clone(),
                run_id,
                config.clone(),
                &cancellation,
                PreInferenceFailure::new(
                    RootPlanningFailurePhase::Preflight,
                    RootPlanningFailureReason::InvalidWallDeadline,
                    error.to_string(),
                ),
            )
            .await?;
            if actual == RunState::Cancelled {
                return Ok(RunCompletion::Cancelled);
            }
            return Err(error);
        }
    };

    if cancellation.is_cancelled() {
        ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
        renew_claim(paths.clone(), run_id, config.clone()).await?;
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Cancelled,
        )
        .await?;
        return Ok(completion_for_state(actual));
    }
    if shutdown.is_cancelled() {
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Waiting,
        )
        .await?;
        return Ok(completion_for_state(actual));
    }
    if deadline_elapsed(deadline) {
        let actual = fail_before_inference(
            paths,
            run_id,
            config,
            &cancellation,
            PreInferenceFailure::new(
                RootPlanningFailurePhase::Preflight,
                RootPlanningFailureReason::WallDeadlineExceeded,
                "run wall deadline elapsed before model discovery",
            ),
        )
        .await?;
        return Ok(completion_for_state(actual));
    }

    let resolved = match discover_model(
        Arc::clone(&backend),
        &run,
        &config,
        &cancellation,
        &shutdown,
        deadline,
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(DiscoveryEnd::Cancelled) => {
            ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
            renew_claim(paths.clone(), run_id, config.clone()).await?;
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                RunState::Cancelled,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        Err(DiscoveryEnd::Shutdown) => {
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                RunState::Waiting,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        Err(DiscoveryEnd::Deadline) => {
            let actual = fail_before_inference(
                paths,
                run_id,
                config,
                &cancellation,
                PreInferenceFailure::new(
                    RootPlanningFailurePhase::ModelDiscovery,
                    RootPlanningFailureReason::WallDeadlineExceeded,
                    "run wall deadline elapsed during model discovery",
                ),
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        Err(DiscoveryEnd::Failed(failure)) => {
            let message = failure.detail.clone();
            let actual =
                fail_before_inference(paths, run_id, config, &cancellation, failure).await?;
            if actual == RunState::Cancelled {
                return Ok(RunCompletion::Cancelled);
            }
            return Err(SupervisorRunError::Contract(message));
        }
    };

    let prepare_phase = match compile_and_prepare(
        paths.clone(),
        run_id,
        config.clone(),
        resolved,
        deadline,
    )
    .await
    {
        Ok(phase) => phase,
        Err(error) => {
            let failure_reason = match &error {
                SupervisorRunError::Store(_)
                | SupervisorRunError::Io(_)
                | SupervisorRunError::Background(_) => None,
                SupervisorRunError::ArtifactPersistence(error) if error.is_retryable() => None,
                SupervisorRunError::ArtifactPersistence(_) => {
                    Some(RootPlanningFailureReason::ArtifactPersistenceFailed)
                }
                SupervisorRunError::InvalidState(_) | SupervisorRunError::CommittedArtifact(_) => {
                    Some(RootPlanningFailureReason::DurableStateConflict)
                }
                SupervisorRunError::Contract(_) => {
                    Some(RootPlanningFailureReason::PromptCompilationFailed)
                }
            };
            let actual = if let Some(reason) = failure_reason {
                fail_before_inference(
                    paths,
                    run_id,
                    config,
                    &cancellation,
                    PreInferenceFailure::new(
                        RootPlanningFailurePhase::PromptPreparation,
                        reason,
                        error.to_string(),
                    ),
                )
                .await
            } else {
                transition_run(
                    paths,
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    RunState::Waiting,
                )
                .await
            }
            .map_err(|transition_error| {
                SupervisorRunError::Background(format!(
                    "prepare failed ({error}); recovery transition failed ({transition_error})"
                ))
            })?;
            if actual == RunState::Cancelled {
                return Ok(RunCompletion::Cancelled);
            }
            return Err(error);
        }
    };
    let prepared = match prepare_phase {
        PreparePhase::Prepared(prepared) => prepared,
        PreparePhase::Cancelled => {
            renew_claim(paths.clone(), run_id, config.clone()).await?;
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                RunState::Cancelled,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        PreparePhase::Deadline => {
            let actual = fail_before_inference(
                paths,
                run_id,
                config,
                &cancellation,
                PreInferenceFailure::new(
                    RootPlanningFailurePhase::PromptPreparation,
                    RootPlanningFailureReason::WallDeadlineExceeded,
                    "run wall deadline elapsed before Prepared was durable",
                ),
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
    };

    if cancellation.is_cancelled() {
        ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
        renew_claim(paths.clone(), run_id, config.clone()).await?;
        append_cancelled_before_call(paths.clone(), run_id, config.actor_id, &prepared).await?;
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Cancelled,
        )
        .await?;
        return Ok(completion_for_state(actual));
    }

    // This method call may create provider work. It is intentionally after the
    // Prepared event has been acknowledged by a separate Store connection.
    let inference = backend.infer_structured(prepared.request.clone());
    tokio::pin!(inference);
    let heartbeat_interval = (config.claim_lease / 3).max(Duration::from_millis(10));
    let inference_end = loop {
        let heartbeat = tokio::time::sleep(heartbeat_interval);
        tokio::pin!(heartbeat);
        let boundary = tokio::select! {
            biased;
            result = &mut inference => Some(InferenceEnd::Observed(result)),
            () = cancellation.cancelled() => Some(InferenceEnd::Cancelled),
            () = shutdown.cancelled() => Some(InferenceEnd::Shutdown),
            () = wait_for_deadline(deadline) => Some(InferenceEnd::Deadline),
            () = &mut heartbeat => None,
        };
        if let Some(boundary) = boundary {
            break boundary;
        }
        if let Err(error) = renew_claim(paths.clone(), run_id, config.clone()).await {
            break InferenceEnd::RenewalFailed(error);
        }
        if durable_cancellation_generation(paths.clone(), run_id, config.max_recovery_events)
            .await?
            > 0
        {
            break InferenceEnd::Cancelled;
        }
    };
    // A provider future and the wall timer can become ready in the same
    // scheduler turn. The result branch is intentionally polled first to
    // retain deterministic cancellation ordering, so wall time is rechecked
    // explicitly before any response evidence can be committed.
    let inference_end = match inference_end {
        InferenceEnd::Observed(_) if deadline_elapsed(deadline) => InferenceEnd::Deadline,
        other => other,
    };
    let backend_result = match inference_end {
        InferenceEnd::Observed(result) => result,
        boundary => {
            let user_cancelled = matches!(&boundary, InferenceEnd::Cancelled);
            let renewal_failed = matches!(&boundary, InferenceEnd::RenewalFailed(_));
            let mut claim_recovery_needed = false;
            if user_cancelled {
                ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
                claim_recovery_needed = renew_claim(paths.clone(), run_id, config.clone())
                    .await
                    .is_err();
            }
            let (reason, boundary_name) = match &boundary {
                InferenceEnd::RenewalFailed(_) => (
                    UnknownInferenceOutcomeReason::ClaimExpiredBeforeObservation,
                    UnknownInferenceBoundary::ClaimRenewalFailed,
                ),
                InferenceEnd::Shutdown => (
                    UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
                    UnknownInferenceBoundary::Shutdown,
                ),
                InferenceEnd::Deadline => (
                    UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate,
                    UnknownInferenceBoundary::Deadline,
                ),
                InferenceEnd::Cancelled => (
                    UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate,
                    UnknownInferenceBoundary::Cancelled,
                ),
                InferenceEnd::Observed(_) => {
                    return Err(SupervisorRunError::InvalidState(
                        "observed inference escaped its result branch".to_owned(),
                    ));
                }
            };
            let first_unknown = append_unknown(
                paths.clone(),
                run_id,
                config.actor_id,
                config.max_recovery_events,
                prepared.event.clone(),
                reason,
                boundary_name,
            )
            .await;
            if let Err(first_error) = first_unknown {
                if !renewal_failed && !claim_recovery_needed {
                    return Err(first_error);
                }
                if let Some(actual) =
                    reclaim_claim_after_boundary(paths.clone(), run_id, config.clone(), &shutdown)
                        .await?
                {
                    return Ok(completion_for_state(actual));
                }
                append_unknown(
                    paths.clone(),
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    prepared.event,
                    reason,
                    boundary_name,
                )
                .await
                .map_err(|second_error| {
                    SupervisorRunError::Background(format!(
                        "could not retain unknown outcome before ({first_error}) or after safe claim recovery ({second_error})"
                    ))
                })?;
            }
            let state = if user_cancelled {
                RunState::Cancelled
            } else {
                RunState::Failed
            };
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                state,
            )
            .await?;
            if let InferenceEnd::RenewalFailed(error) = boundary
                && actual != RunState::Cancelled
            {
                return Err(error);
            }
            return Ok(completion_for_state(actual));
        }
    };

    let observed = append_observation(
        paths.clone(),
        run_id,
        config.actor_id,
        prepared.event,
        backend_result,
    )
    .await?;
    resume_observed(paths, run_id, config, observed.prepared, observed.observed).await
}

enum SemanticPreparedExecution {
    Observed(Box<ObservedPair>),
    Terminal(RunCompletion),
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn execute_semantic_prepared(
    paths: RuntimePaths,
    backend: Arc<dyn ModelBackend>,
    config: RunSupervisorConfig,
    run_id: RunId,
    prepared: PreparedCall,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<SemanticPreparedExecution, SupervisorRunError> {
    if cancellation.is_cancelled() {
        ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
        renew_claim(paths.clone(), run_id, config.clone()).await?;
        append_cancelled_before_call(paths.clone(), run_id, config.actor_id, &prepared).await?;
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Cancelled,
        )
        .await?;
        return Ok(SemanticPreparedExecution::Terminal(completion_for_state(
            actual,
        )));
    }

    let inference = backend.infer_structured(prepared.request.clone());
    tokio::pin!(inference);
    let heartbeat_interval = (config.claim_lease / 3).max(Duration::from_millis(10));
    let inference_end = loop {
        let heartbeat = tokio::time::sleep(heartbeat_interval);
        tokio::pin!(heartbeat);
        let boundary = tokio::select! {
            biased;
            result = &mut inference => Some(InferenceEnd::Observed(result)),
            () = cancellation.cancelled() => Some(InferenceEnd::Cancelled),
            () = shutdown.cancelled() => Some(InferenceEnd::Shutdown),
            () = wait_for_deadline(deadline) => Some(InferenceEnd::Deadline),
            () = &mut heartbeat => None,
        };
        if let Some(boundary) = boundary {
            break boundary;
        }
        if let Err(error) = renew_claim(paths.clone(), run_id, config.clone()).await {
            break InferenceEnd::RenewalFailed(error);
        }
        if durable_cancellation_generation(paths.clone(), run_id, config.max_recovery_events)
            .await?
            > 0
        {
            break InferenceEnd::Cancelled;
        }
    };
    // See the legacy path above: an already-ready result cannot outrun the
    // absolute deadline merely because it won the biased select branch.
    let inference_end = match inference_end {
        InferenceEnd::Observed(_) if deadline_elapsed(deadline) => InferenceEnd::Deadline,
        other => other,
    };
    let backend_result = match inference_end {
        InferenceEnd::Observed(result) => result,
        boundary => {
            let user_cancelled = matches!(&boundary, InferenceEnd::Cancelled);
            let renewal_failed = matches!(&boundary, InferenceEnd::RenewalFailed(_));
            let mut claim_recovery_needed = false;
            if user_cancelled {
                ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
                claim_recovery_needed = renew_claim(paths.clone(), run_id, config.clone())
                    .await
                    .is_err();
            }
            let (reason, boundary_name) = match &boundary {
                InferenceEnd::RenewalFailed(_) => (
                    UnknownInferenceOutcomeReason::ClaimExpiredBeforeObservation,
                    UnknownInferenceBoundary::ClaimRenewalFailed,
                ),
                InferenceEnd::Shutdown => (
                    UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
                    UnknownInferenceBoundary::Shutdown,
                ),
                InferenceEnd::Deadline => (
                    UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate,
                    UnknownInferenceBoundary::Deadline,
                ),
                InferenceEnd::Cancelled => (
                    UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate,
                    UnknownInferenceBoundary::Cancelled,
                ),
                InferenceEnd::Observed(_) => {
                    return Err(SupervisorRunError::InvalidState(
                        "observed semantic inference escaped its result branch".to_owned(),
                    ));
                }
            };
            let first_unknown = append_unknown(
                paths.clone(),
                run_id,
                config.actor_id,
                config.max_recovery_events,
                prepared.event.clone(),
                reason,
                boundary_name,
            )
            .await;
            if let Err(first_error) = first_unknown {
                if !renewal_failed && !claim_recovery_needed {
                    return Err(first_error);
                }
                if let Some(actual) =
                    reclaim_claim_after_boundary(paths.clone(), run_id, config.clone(), shutdown)
                        .await?
                {
                    return Ok(SemanticPreparedExecution::Terminal(completion_for_state(
                        actual,
                    )));
                }
                append_unknown(
                    paths.clone(),
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    prepared.event,
                    reason,
                    boundary_name,
                )
                .await
                .map_err(|second_error| {
                    SupervisorRunError::Background(format!(
                        "could not retain semantic unknown outcome before ({first_error}) or after safe claim recovery ({second_error})"
                    ))
                })?;
            }
            let state = if user_cancelled {
                RunState::Cancelled
            } else {
                RunState::Failed
            };
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                state,
            )
            .await?;
            if let InferenceEnd::RenewalFailed(error) = boundary
                && actual != RunState::Cancelled
            {
                return Err(error);
            }
            return Ok(SemanticPreparedExecution::Terminal(completion_for_state(
                actual,
            )));
        }
    };
    let observed = append_observation(
        paths,
        run_id,
        config.actor_id,
        prepared.event,
        backend_result,
    )
    .await?;
    Ok(SemanticPreparedExecution::Observed(Box::new(observed)))
}

async fn reload_run_and_history(
    paths: RuntimePaths,
    run_id: RunId,
    maximum_events: usize,
) -> Result<(Run, RunHistory), SupervisorRunError> {
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let history = load_run_history(store, run_id, maximum_events)?;
        Ok((run, history))
    })
    .await
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DurablePolicyCheck {
    Matches,
    ConfigurationDrift,
    InvalidCommittedArtifact(String),
}

async fn check_durable_policy(
    paths: RuntimePaths,
    run_id: RunId,
    maximum_events: usize,
    expected: RootPlanningExecutionPolicy,
) -> Result<DurablePolicyCheck, SupervisorRunError> {
    store_phase(paths, move |store| {
        let history = load_run_history(store, run_id, maximum_events)?;
        let Some(initial) = history.attempt_for_stage(RootPlanningStage::InitialPlan) else {
            return Ok(DurablePolicyCheck::ConfigurationDrift);
        };
        let prepared = prepared_payload(initial)?;
        let Some(PlannerStageContext::InitialPlan {
            execution_policy_artifact,
            ..
        }) = &prepared.stage_context
        else {
            return Ok(DurablePolicyCheck::ConfigurationDrift);
        };
        let bytes = match store.get_artifact(execution_policy_artifact) {
            Ok(bytes) => bytes,
            Err(error) if error.is_retryable() => return Err(error.into()),
            Err(error) => {
                return Ok(DurablePolicyCheck::InvalidCommittedArtifact(
                    error.to_string(),
                ));
            }
        };
        let persisted = match serde_json::from_slice::<RootPlanningExecutionPolicy>(&bytes) {
            Ok(policy) => policy,
            Err(error) => {
                return Ok(DurablePolicyCheck::InvalidCommittedArtifact(format!(
                    "durable execution policy cannot be decoded: {error}"
                )));
            }
        };
        let canonical = serde_json::to_vec(&persisted)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        if canonical != bytes {
            return Ok(DurablePolicyCheck::InvalidCommittedArtifact(
                "durable execution policy is not canonically encoded".to_owned(),
            ));
        }
        if persisted != expected {
            return Ok(DurablePolicyCheck::ConfigurationDrift);
        }
        Ok(DurablePolicyCheck::Matches)
    })
    .await
}

async fn fail_semantic_stage(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    stage: RootPlanningStage,
    reason: RootPlanningStageFailureReason,
    detail: String,
) -> Result<RunCompletion, SupervisorRunError> {
    fail_semantic_stage_for_subject(paths, run_id, config, stage, reason, None, detail).await
}

async fn fail_semantic_stage_for_subject(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    stage: RootPlanningStage,
    reason: RootPlanningStageFailureReason,
    model_subject: Option<RootPlanningModelSubject>,
    detail: String,
) -> Result<RunCompletion, SupervisorRunError> {
    let appended = append_root_planning_stage_failure(
        paths.clone(),
        run_id,
        config.clone(),
        stage,
        reason,
        model_subject,
        detail,
    )
    .await?;
    let target = if appended == RootPlanningStageFailureAppend::Cancelled {
        RunState::Cancelled
    } else {
        RunState::Failed
    };
    let actual = transition_run(
        paths,
        run_id,
        config.actor_id,
        config.max_recovery_events,
        target,
    )
    .await?;
    Ok(completion_for_state(actual))
}

fn later_discovery_failure_reason(failure: &PreInferenceFailure) -> RootPlanningStageFailureReason {
    match (
        failure.reason,
        failure.model_subject.as_ref().map(|subject| subject.role),
    ) {
        (
            RootPlanningFailureReason::SelectedModelUnavailable,
            Some(RootPlanningModelRole::IndependentCritic),
        ) => RootPlanningStageFailureReason::IndependentReviewerUnavailable,
        (
            RootPlanningFailureReason::SelectedModelUnavailable,
            Some(RootPlanningModelRole::Producer),
        ) => RootPlanningStageFailureReason::SelectedModelUnavailable,
        _ => RootPlanningStageFailureReason::ConfigurationDrift,
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn supervise_semantic_run(
    paths: RuntimePaths,
    backend: Arc<dyn ModelBackend>,
    config: RunSupervisorConfig,
    mut run: Run,
    mut history: RunHistory,
    cancellation: CancellationToken,
    shutdown: CancellationToken,
) -> Result<RunCompletion, SupervisorRunError> {
    let run_id = run.id;
    let deadline = match run_deadline(&run) {
        Ok(deadline) => deadline,
        Err(error) => {
            if history.attempts.is_empty() {
                let actual = fail_before_inference(
                    paths,
                    run_id,
                    config,
                    &cancellation,
                    PreInferenceFailure::new(
                        RootPlanningFailurePhase::Preflight,
                        RootPlanningFailureReason::InvalidWallDeadline,
                        error.to_string(),
                    ),
                )
                .await?;
                return Ok(completion_for_state(actual));
            }
            let RecoveryAction::NextStage(stage) = history.recovery_action()? else {
                return Err(error);
            };
            return fail_semantic_stage(
                paths,
                run_id,
                config,
                stage,
                RootPlanningStageFailureReason::ConfigurationDrift,
                error.to_string(),
            )
            .await;
        }
    };
    let mut resolved_models = None;

    loop {
        let recovery = history.recovery_action()?;
        if history.cancellation_generation > 0 && !matches!(&recovery, RecoveryAction::Prepared(_))
        {
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                RunState::Cancelled,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        match recovery {
            RecoveryAction::Prepared(prepared) => {
                let cancelled = history.cancellation_generation > 0 || cancellation.is_cancelled();
                if cancellation.is_cancelled() && history.cancellation_generation == 0 {
                    ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
                    renew_claim(paths.clone(), run_id, config.clone()).await?;
                }
                append_unknown(
                    paths.clone(),
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    prepared,
                    UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
                    if cancelled {
                        UnknownInferenceBoundary::Cancelled
                    } else {
                        UnknownInferenceBoundary::Restart
                    },
                )
                .await?;
                let state = if cancelled {
                    RunState::Cancelled
                } else {
                    RunState::Failed
                };
                let actual = transition_run(
                    paths,
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    state,
                )
                .await?;
                return Ok(completion_for_state(actual));
            }
            RecoveryAction::Observed { prepared, observed } => {
                let EventPayload::PlannerInferenceObserved(observation) = &observed.payload else {
                    return Err(SupervisorRunError::InvalidState(
                        "semantic replay target is not Observed".to_owned(),
                    ));
                };
                if matches!(
                    observation.outcome,
                    PlannerInferenceObservation::Failed { .. }
                ) {
                    let actual = transition_run(
                        paths,
                        run_id,
                        config.actor_id,
                        config.max_recovery_events,
                        RunState::Failed,
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                let decision = match decide_or_fail_semantic_observed(
                    paths.clone(),
                    run_id,
                    config.clone(),
                    prepared,
                    observed,
                    deadline,
                )
                .await?
                {
                    SemanticObservedDecision::Decided(decision) => decision,
                    SemanticObservedDecision::Terminal(completion) => return Ok(completion),
                };
                if decision == DecisionOutcome::Cancelled {
                    let actual = transition_run(
                        paths,
                        run_id,
                        config.actor_id,
                        config.max_recovery_events,
                        RunState::Cancelled,
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                (run, history) =
                    reload_run_and_history(paths.clone(), run_id, config.max_recovery_events)
                        .await?;
                continue;
            }
            RecoveryAction::Terminal(state) => {
                let actual = transition_run(
                    paths,
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    state,
                )
                .await?;
                return Ok(completion_for_state(actual));
            }
            RecoveryAction::Fresh | RecoveryAction::NextStage(_) => {}
        }

        let stage = match history.recovery_action()? {
            RecoveryAction::Fresh => RootPlanningStage::InitialPlan,
            RecoveryAction::NextStage(stage) => stage,
            _ => {
                return Err(SupervisorRunError::InvalidState(
                    "semantic stage selection changed during replay".to_owned(),
                ));
            }
        };
        if cancellation.is_cancelled() {
            ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
            renew_claim(paths.clone(), run_id, config.clone()).await?;
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                RunState::Cancelled,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        if shutdown.is_cancelled() {
            let actual = transition_run(
                paths,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                RunState::Waiting,
            )
            .await?;
            return Ok(completion_for_state(actual));
        }
        if deadline_elapsed(deadline) {
            if stage == RootPlanningStage::InitialPlan {
                let actual = fail_before_inference(
                    paths,
                    run_id,
                    config,
                    &cancellation,
                    PreInferenceFailure::new(
                        RootPlanningFailurePhase::Preflight,
                        RootPlanningFailureReason::WallDeadlineExceeded,
                        "run wall deadline elapsed before semantic model discovery",
                    ),
                )
                .await?;
                return Ok(completion_for_state(actual));
            }
            return fail_semantic_stage(
                paths,
                run_id,
                config,
                stage,
                RootPlanningStageFailureReason::WallDeadlineExceeded,
                "run wall deadline elapsed before the next semantic stage".to_owned(),
            )
            .await;
        }
        let Some(policy) = config.root_planning_policy.clone() else {
            if stage == RootPlanningStage::InitialPlan {
                let actual = fail_before_inference(
                    paths,
                    run_id,
                    config,
                    &cancellation,
                    PreInferenceFailure::new(
                        RootPlanningFailurePhase::Preflight,
                        RootPlanningFailureReason::InvalidRunConfiguration,
                        "independently reviewed planning requires an explicit trusted model policy",
                    ),
                )
                .await?;
                return Ok(completion_for_state(actual));
            }
            return fail_semantic_stage(
                paths,
                run_id,
                config,
                stage,
                RootPlanningStageFailureReason::ConfigurationDrift,
                "trusted semantic model policy is unavailable after restart".to_owned(),
            )
            .await;
        };
        if stage != RootPlanningStage::InitialPlan {
            match check_durable_policy(
                paths.clone(),
                run_id,
                config.max_recovery_events,
                policy.clone(),
            )
            .await?
            {
                DurablePolicyCheck::Matches => {}
                DurablePolicyCheck::ConfigurationDrift => {
                    return fail_semantic_stage(
                        paths,
                        run_id,
                        config,
                        stage,
                        RootPlanningStageFailureReason::ConfigurationDrift,
                        "configured semantic model policy differs from the durable initial policy"
                            .to_owned(),
                    )
                    .await;
                }
                DurablePolicyCheck::InvalidCommittedArtifact(detail) => {
                    if cancellation.is_cancelled() {
                        ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
                        renew_claim(paths.clone(), run_id, config.clone()).await?;
                        let actual = transition_run(
                            paths,
                            run_id,
                            config.actor_id,
                            config.max_recovery_events,
                            RunState::Cancelled,
                        )
                        .await?;
                        return Ok(completion_for_state(actual));
                    }
                    return fail_semantic_stage(
                        paths,
                        run_id,
                        config,
                        stage,
                        RootPlanningStageFailureReason::InvalidCommittedArtifact,
                        format!(
                            "durable execution policy is unavailable before {stage:?} Prepared: {detail}"
                        ),
                    )
                    .await;
                }
            }
        }
        if resolved_models.is_none() {
            resolved_models = match discover_semantic_models(
                Arc::clone(&backend),
                &run,
                &policy,
                &config,
                &cancellation,
                &shutdown,
                deadline,
            )
            .await
            {
                Ok(models) => Some(models),
                Err(DiscoveryEnd::Cancelled) => {
                    ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
                    renew_claim(paths.clone(), run_id, config.clone()).await?;
                    let actual = transition_run(
                        paths,
                        run_id,
                        config.actor_id,
                        config.max_recovery_events,
                        RunState::Cancelled,
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                Err(DiscoveryEnd::Shutdown) => {
                    let actual = transition_run(
                        paths,
                        run_id,
                        config.actor_id,
                        config.max_recovery_events,
                        RunState::Waiting,
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                Err(DiscoveryEnd::Deadline) => {
                    if stage == RootPlanningStage::InitialPlan {
                        let actual = fail_before_inference(
                            paths,
                            run_id,
                            config,
                            &cancellation,
                            PreInferenceFailure::new(
                                RootPlanningFailurePhase::ModelDiscovery,
                                RootPlanningFailureReason::WallDeadlineExceeded,
                                "run wall deadline elapsed during semantic model discovery",
                            ),
                        )
                        .await?;
                        return Ok(completion_for_state(actual));
                    }
                    return fail_semantic_stage(
                        paths,
                        run_id,
                        config,
                        stage,
                        RootPlanningStageFailureReason::WallDeadlineExceeded,
                        "run wall deadline elapsed during semantic model discovery".to_owned(),
                    )
                    .await;
                }
                Err(DiscoveryEnd::Failed(failure)) => {
                    if stage == RootPlanningStage::InitialPlan {
                        let actual =
                            fail_before_inference(paths, run_id, config, &cancellation, failure)
                                .await?;
                        return Ok(completion_for_state(actual));
                    }
                    let reason = later_discovery_failure_reason(&failure);
                    return fail_semantic_stage_for_subject(
                        paths,
                        run_id,
                        config,
                        stage,
                        reason,
                        failure.model_subject.map(|subject| *subject),
                        failure.detail,
                    )
                    .await;
                }
            };
        }
        let prepare = compile_and_prepare_semantic(
            paths.clone(),
            run_id,
            config.clone(),
            policy,
            resolved_models.clone().ok_or_else(|| {
                SupervisorRunError::InvalidState(
                    "semantic model discovery completed without resolved models".to_owned(),
                )
            })?,
            stage,
            deadline,
        )
        .await;
        let prepared = match prepare {
            Ok(PreparePhase::Prepared(prepared)) => prepared,
            Ok(PreparePhase::Cancelled) => {
                let actual = transition_run(
                    paths,
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    RunState::Cancelled,
                )
                .await?;
                return Ok(completion_for_state(actual));
            }
            Ok(PreparePhase::Deadline) => {
                if stage == RootPlanningStage::InitialPlan {
                    let actual = fail_before_inference(
                        paths,
                        run_id,
                        config,
                        &cancellation,
                        PreInferenceFailure::new(
                            RootPlanningFailurePhase::PromptPreparation,
                            RootPlanningFailureReason::WallDeadlineExceeded,
                            "run wall deadline elapsed before InitialPlan Prepared",
                        ),
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                return fail_semantic_stage(
                    paths,
                    run_id,
                    config,
                    stage,
                    RootPlanningStageFailureReason::WallDeadlineExceeded,
                    "run wall deadline elapsed before semantic Prepared".to_owned(),
                )
                .await;
            }
            Err(error) => {
                let typed_reason = match &error {
                    SupervisorRunError::Contract(_) => {
                        Some(RootPlanningStageFailureReason::PromptCompilationFailed)
                    }
                    SupervisorRunError::CommittedArtifact(_) => {
                        Some(RootPlanningStageFailureReason::InvalidCommittedArtifact)
                    }
                    SupervisorRunError::ArtifactPersistence(error) if error.is_retryable() => None,
                    SupervisorRunError::ArtifactPersistence(_) => {
                        Some(RootPlanningStageFailureReason::ArtifactPersistenceFailed)
                    }
                    SupervisorRunError::Store(error) if error.is_retryable() => None,
                    SupervisorRunError::Store(
                        StoreError::Io(_)
                        | StoreError::InvalidArtifactHash
                        | StoreError::ArtifactTooLarge
                        | StoreError::ArtifactIntegrity,
                    ) => Some(RootPlanningStageFailureReason::InvalidCommittedArtifact),
                    SupervisorRunError::InvalidState(_) | SupervisorRunError::Store(_) => {
                        Some(RootPlanningStageFailureReason::DurableStateConflict)
                    }
                    SupervisorRunError::Io(_) | SupervisorRunError::Background(_) => None,
                };
                if stage == RootPlanningStage::InitialPlan {
                    let reason = match &error {
                        SupervisorRunError::Contract(_) => {
                            Some(RootPlanningFailureReason::PromptCompilationFailed)
                        }
                        SupervisorRunError::ArtifactPersistence(error) if error.is_retryable() => {
                            None
                        }
                        SupervisorRunError::ArtifactPersistence(_) => {
                            Some(RootPlanningFailureReason::ArtifactPersistenceFailed)
                        }
                        SupervisorRunError::Store(error) if error.is_retryable() => None,
                        SupervisorRunError::InvalidState(_)
                        | SupervisorRunError::CommittedArtifact(_)
                        | SupervisorRunError::Store(_) => {
                            Some(RootPlanningFailureReason::DurableStateConflict)
                        }
                        SupervisorRunError::Io(_) | SupervisorRunError::Background(_) => None,
                    };
                    if let Some(reason) = reason {
                        let actual = fail_before_inference(
                            paths,
                            run_id,
                            config,
                            &cancellation,
                            PreInferenceFailure::new(
                                RootPlanningFailurePhase::PromptPreparation,
                                reason,
                                error.to_string(),
                            ),
                        )
                        .await?;
                        return Ok(completion_for_state(actual));
                    }
                    let actual = transition_run(
                        paths,
                        run_id,
                        config.actor_id,
                        config.max_recovery_events,
                        RunState::Waiting,
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                if let Some(reason) = typed_reason {
                    return fail_semantic_stage(
                        paths,
                        run_id,
                        config,
                        stage,
                        reason,
                        error.to_string(),
                    )
                    .await;
                }
                let actual = transition_run(
                    paths,
                    run_id,
                    config.actor_id,
                    config.max_recovery_events,
                    RunState::Waiting,
                )
                .await?;
                return Ok(completion_for_state(actual));
            }
        };
        match execute_semantic_prepared(
            paths.clone(),
            Arc::clone(&backend),
            config.clone(),
            run_id,
            prepared,
            &cancellation,
            &shutdown,
            deadline,
        )
        .await?
        {
            SemanticPreparedExecution::Terminal(completion) => return Ok(completion),
            SemanticPreparedExecution::Observed(observed) => {
                let EventPayload::PlannerInferenceObserved(observation) =
                    &observed.observed.payload
                else {
                    return Err(SupervisorRunError::InvalidState(
                        "semantic call returned a non-Observed event".to_owned(),
                    ));
                };
                if matches!(
                    observation.outcome,
                    PlannerInferenceObservation::Failed { .. }
                ) {
                    let actual = transition_run(
                        paths,
                        run_id,
                        config.actor_id,
                        config.max_recovery_events,
                        RunState::Failed,
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                let decision = match decide_or_fail_semantic_observed(
                    paths.clone(),
                    run_id,
                    config.clone(),
                    observed.prepared,
                    observed.observed,
                    deadline,
                )
                .await?
                {
                    SemanticObservedDecision::Decided(decision) => decision,
                    SemanticObservedDecision::Terminal(completion) => return Ok(completion),
                };
                if decision == DecisionOutcome::Cancelled {
                    let actual = transition_run(
                        paths,
                        run_id,
                        config.actor_id,
                        config.max_recovery_events,
                        RunState::Cancelled,
                    )
                    .await?;
                    return Ok(completion_for_state(actual));
                }
                (run, history) =
                    reload_run_and_history(paths.clone(), run_id, config.max_recovery_events)
                        .await?;
            }
        }
    }
}

fn completion_for_state(state: RunState) -> RunCompletion {
    match state {
        RunState::Completed => RunCompletion::Completed,
        RunState::Cancelled => RunCompletion::Cancelled,
        RunState::Failed => RunCompletion::Failed,
        RunState::Waiting => RunCompletion::Paused,
        RunState::Queued | RunState::Running => RunCompletion::AlreadyTerminal(state),
    }
}

async fn begin_run(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
) -> Result<BeginRun, SupervisorRunError> {
    store_phase(paths, move |store| {
        let mut run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        if is_terminal(run.state) {
            return Ok(BeginRun::AlreadyTerminal(run.state));
        }
        let session = store.get_session(run.spec.session_id)?.ok_or_else(|| {
            SupervisorRunError::InvalidState(format!("session {} not found", run.spec.session_id))
        })?;
        let history = load_run_history(store, run_id, config.max_recovery_events)?;
        if matches!(run.state, RunState::Queued | RunState::Waiting)
            && history.cancellation_generation > 0
        {
            store.append_event(NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id: config.actor_id,
                causal_parent: history.last_event_id,
                provenance: supervisor_provenance(None),
                payload: EventPayload::RunStateChanged {
                    from: run.state,
                    to: RunState::Cancelled,
                },
            })?;
            return Ok(BeginRun::AlreadyTerminal(RunState::Cancelled));
        }
        if let Some((claim_event, claim)) = &history.latest_claim
            && claim.lease_expires_at > Utc::now()
            && (claim.runtime_instance_id != config.runtime_instance_id
                || claim_event.actor_id != config.actor_id)
        {
            return Ok(BeginRun::LeaseBlocked {
                expires_at: claim.lease_expires_at,
                deadline: run_deadline(&run)?,
            });
        }
        let claim_generation = history
            .latest_claim
            .as_ref()
            .map_or(1, |(_, claim)| claim.claim_generation.saturating_add(1));
        let lease = ChronoDuration::from_std(config.claim_lease)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let claim_event = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: history.last_event_id,
            provenance: supervisor_provenance(None),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id: config.runtime_instance_id,
                claim_generation,
                cancellation_generation: history.cancellation_generation,
                lease_expires_at: Utc::now() + lease,
            }),
        })?;
        if matches!(run.state, RunState::Queued | RunState::Waiting) {
            store.append_event(NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id: config.actor_id,
                causal_parent: Some(claim_event.id),
                provenance: supervisor_provenance(None),
                payload: EventPayload::RunStateChanged {
                    from: run.state,
                    to: RunState::Running,
                },
            })?;
            run.state = RunState::Running;
        }
        Ok(BeginRun::Ready {
            session,
            run,
            history,
        })
    })
    .await
}

async fn renew_claim(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
) -> Result<(), SupervisorRunError> {
    match begin_run(paths, run_id, config).await? {
        BeginRun::Ready { .. } | BeginRun::AlreadyTerminal(_) => Ok(()),
        BeginRun::LeaseBlocked { expires_at, .. } => Err(SupervisorRunError::InvalidState(
            format!("claim is held until {expires_at}"),
        )),
    }
}

/// Re-establishes durable ownership after an inference future has been
/// dropped at an ambiguous boundary. A foreign live lease is never stolen;
/// the retained Prepared event remains the startup-recovery marker if daemon
/// shutdown interrupts this wait.
async fn reclaim_claim_after_boundary(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    shutdown: &CancellationToken,
) -> Result<Option<RunState>, SupervisorRunError> {
    loop {
        match begin_run(paths.clone(), run_id, config.clone()).await? {
            BeginRun::Ready { .. } => return Ok(None),
            BeginRun::AlreadyTerminal(state) => return Ok(Some(state)),
            BeginRun::LeaseBlocked { expires_at, .. } => {
                let wait = (expires_at - Utc::now()).to_std().unwrap_or(Duration::ZERO);
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => {
                        return Err(SupervisorRunError::Background(
                            "claim recovery interrupted; durable Prepared evidence is retained for startup recovery"
                                .to_owned(),
                        ));
                    }
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
    }
}

const fn is_terminal(state: RunState) -> bool {
    matches!(
        state,
        RunState::Completed | RunState::Failed | RunState::Cancelled
    )
}

fn supervisor_provenance(backend: Option<birdcode_protocol::BackendSelection>) -> Provenance {
    Provenance {
        producer: SUPERVISOR_PRODUCER.to_owned(),
        backend,
        raw_artifact: None,
    }
}

#[derive(Clone, Debug)]
struct ResolvedModel {
    model_id: ModelId,
    max_output_tokens: u32,
    total_token_budget: u64,
    reasoning: Option<ReasoningSetting>,
}

#[derive(Clone, Debug)]
struct ResolvedSemanticModel {
    model_id: ModelId,
    total_token_budget: u64,
    reasoning: Option<ReasoningSetting>,
}

#[derive(Clone, Debug)]
struct ResolvedSemanticModels {
    producer: ResolvedSemanticModel,
    critic: ResolvedSemanticModel,
}

enum DiscoveryEnd {
    Cancelled,
    Shutdown,
    Deadline,
    Failed(PreInferenceFailure),
}

async fn discover_model(
    backend: Arc<dyn ModelBackend>,
    run: &Run,
    config: &RunSupervisorConfig,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<ResolvedModel, DiscoveryEnd> {
    if run.spec.backend.kind != BackendKind::Model {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "root planning requires a model backend",
        )));
    }
    if run.spec.backend.backend_id.as_bytes() != backend.backend_id().as_str().as_bytes() {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            format!(
                "selected backend {:?} does not match configured backend {:?}",
                run.spec.backend.backend_id,
                backend.backend_id().as_str()
            ),
        )));
    }
    let discovery = tokio::time::timeout(config.discovery_timeout, backend.discover_models());
    let catalog = tokio::select! {
        biased;
        result = discovery => match result {
            Ok(Ok(catalog)) => catalog,
            Ok(Err(error)) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::BackendDiscoveryFailed,
                error.to_string(),
            ))),
            Err(_) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::DiscoveryTimedOut,
                "model discovery timed out",
            ))),
        },
        () = cancellation.cancelled() => return Err(DiscoveryEnd::Cancelled),
        () = shutdown.cancelled() => return Err(DiscoveryEnd::Shutdown),
        () = wait_for_deadline(deadline) => return Err(DiscoveryEnd::Deadline),
    };
    if catalog.backend_id != *backend.backend_id() {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            "model discovery returned another backend identity",
        )));
    }
    resolve_catalog(&catalog, run, config)
}

async fn discover_semantic_models(
    backend: Arc<dyn ModelBackend>,
    run: &Run,
    policy: &RootPlanningExecutionPolicy,
    config: &RunSupervisorConfig,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<ResolvedSemanticModels, DiscoveryEnd> {
    validate_semantic_selection(run, policy, backend.backend_id())?;
    let discovery = tokio::time::timeout(config.discovery_timeout, backend.discover_models());
    let catalog = tokio::select! {
        biased;
        result = discovery => match result {
            Ok(Ok(catalog)) => catalog,
            Ok(Err(error)) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::BackendDiscoveryFailed,
                error.to_string(),
            ))),
            Err(_) => return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::DiscoveryTimedOut,
                "model discovery timed out",
            ))),
        },
        () = cancellation.cancelled() => return Err(DiscoveryEnd::Cancelled),
        () = shutdown.cancelled() => return Err(DiscoveryEnd::Shutdown),
        () = wait_for_deadline(deadline) => return Err(DiscoveryEnd::Deadline),
    };
    if catalog.backend_id != *backend.backend_id()
        || catalog.models.len() > config.max_discovered_models
    {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            "semantic planning discovery returned an invalid bounded catalog",
        )));
    }
    let budgets = &policy.stage_budgets;
    let producer_required = budgets
        .initial_plan_output_tokens
        .max(budgets.repair_output_tokens);
    let critic_required = budgets
        .initial_review_output_tokens
        .max(budgets.final_review_output_tokens);
    let reasoning = parse_reasoning(run.spec.backend.reasoning_effort.as_deref())?;
    let producer = resolve_semantic_lineage_model(
        &catalog,
        &policy.producer,
        producer_required,
        reasoning,
        RootPlanningModelRole::Producer,
    )?;
    let critic = resolve_semantic_lineage_model(
        &catalog,
        &policy.critic,
        critic_required,
        reasoning,
        RootPlanningModelRole::IndependentCritic,
    )?;
    Ok(ResolvedSemanticModels { producer, critic })
}

fn validate_semantic_selection(
    run: &Run,
    policy: &RootPlanningExecutionPolicy,
    backend_id: &BackendId,
) -> Result<(), DiscoveryEnd> {
    let budgets = &policy.stage_budgets;
    let aggregate = [
        budgets.initial_plan_output_tokens,
        budgets.initial_review_output_tokens,
        budgets.repair_output_tokens,
        budgets.final_review_output_tokens,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
    .ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "semantic planning stage budget overflow",
        ))
    })?;
    let run_model = run.spec.backend.model.as_deref();
    if run.spec.backend.kind != BackendKind::Model
        || run.spec.backend.backend_id != policy.producer.backend_id
        || run_model != Some(policy.producer.model_id.as_str())
        || policy.producer.backend_id != backend_id.as_str()
        || policy.critic.backend_id != backend_id.as_str()
        || policy.producer.model_id == policy.critic.model_id
        || policy.producer.deployment_id == policy.critic.deployment_id
        || policy.producer.independence_domain_id == policy.critic.independence_domain_id
        || run
            .spec
            .limits
            .max_output_tokens
            .is_some_and(|limit| limit < aggregate)
    {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "run selection, independent lineage, backend, or aggregate output budget does not match the trusted semantic-planning policy",
        )));
    }
    Ok(())
}

fn resolve_semantic_lineage_model(
    catalog: &ModelCatalog,
    lineage: &ModelLineage,
    required_output_tokens: u64,
    reasoning: Option<ReasoningSetting>,
    role: RootPlanningModelRole,
) -> Result<ResolvedSemanticModel, DiscoveryEnd> {
    let role_name = match role {
        RootPlanningModelRole::Producer => "producer",
        RootPlanningModelRole::IndependentCritic => "independent critic",
    };
    let mut matches = catalog.models.iter().filter(|model| {
        model.load_state == ModelLoadState::Loaded
            && model.id.as_str().as_bytes() == lineage.model_id.as_bytes()
    });
    let descriptor = matches.next().ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::for_model(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::SelectedModelUnavailable,
            role,
            lineage,
            format!(
                "configured {role_name} model {:?} is not loaded",
                lineage.model_id
            ),
        ))
    })?;
    if matches.next().is_some() {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::for_model(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            role,
            lineage,
            format!(
                "configured {role_name} model {:?} is ambiguous",
                lineage.model_id
            ),
        )));
    }
    let total_token_budget = resolved_total_token_budget(descriptor, &lineage.model_id)
        .ok_or_else(|| {
            DiscoveryEnd::Failed(PreInferenceFailure::for_model(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidRunConfiguration,
                role,
                lineage,
                format!("configured {role_name} model has no bounded context-window metadata"),
            ))
        })?;
    if total_token_budget < required_output_tokens {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::for_model(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            role,
            lineage,
            format!(
                "configured {role_name} context budget {total_token_budget} is below its stage output ceiling {required_output_tokens}"
            ),
        )));
    }
    Ok(ResolvedSemanticModel {
        model_id: descriptor.id.clone(),
        total_token_budget,
        reasoning,
    })
}

fn resolve_catalog(
    catalog: &ModelCatalog,
    run: &Run,
    config: &RunSupervisorConfig,
) -> Result<ResolvedModel, DiscoveryEnd> {
    if catalog.models.len() > config.max_discovered_models {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            format!(
                "model catalog exceeds {} entries",
                config.max_discovered_models
            ),
        )));
    }
    let selected = run.spec.backend.model.as_deref().ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "run has no selected model",
        ))
    })?;
    let mut matches = catalog.models.iter().filter(|model| {
        model.load_state == ModelLoadState::Loaded
            && model.id.as_str().as_bytes() == selected.as_bytes()
    });
    let descriptor = matches.next().ok_or_else(|| {
        DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::SelectedModelUnavailable,
            format!("selected model {selected:?} not found"),
        ))
    })?;
    if matches.next().is_some() {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidDiscoveryCatalog,
            format!("selected model {selected:?} is ambiguous"),
        )));
    }
    let max_output_tokens = run.spec.limits.max_output_tokens.map_or_else(
        || config.default_max_output_tokens,
        |limit| u32::try_from(limit).unwrap_or(u32::MAX),
    );
    if max_output_tokens == 0 {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            "resolved output token ceiling is zero",
        )));
    }
    let total_token_budget =
        resolved_total_token_budget(descriptor, selected).ok_or_else(|| {
            DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidRunConfiguration,
                format!("selected model {selected:?} has no bounded context-window metadata"),
            ))
        })?;
    if total_token_budget < u64::from(max_output_tokens) {
        return Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration,
            format!(
                "selected model {selected:?} has context budget {total_token_budget}, below the requested output ceiling {max_output_tokens}"
            ),
        )));
    }
    let reasoning = parse_reasoning(run.spec.backend.reasoning_effort.as_deref())?;
    Ok(ResolvedModel {
        model_id: descriptor.id.clone(),
        max_output_tokens,
        total_token_budget,
        reasoning,
    })
}

/// Resolves the tightest provider-reported upper bound for total input and
/// output usage. An exact loaded-instance bound is authoritative; otherwise a
/// single loaded instance, the largest explicitly configured loaded instance,
/// or finally the model-level maximum provides a conservative finite ceiling.
fn resolved_total_token_budget(
    descriptor: &birdcode_backends::ModelDescriptor,
    selected_model_id: &str,
) -> Option<u64> {
    let exact_instance = descriptor
        .loaded_instances
        .iter()
        .find(|instance| instance.id.as_bytes() == selected_model_id.as_bytes())
        .and_then(|instance| instance.context_length)
        .filter(|context| *context > 0);
    let loaded_instance_bound = exact_instance.or_else(|| {
        if descriptor.loaded_instances.len() == 1 {
            descriptor.loaded_instances[0].context_length
        } else {
            descriptor
                .loaded_instances
                .iter()
                .filter_map(|instance| instance.context_length)
                .max()
        }
        .filter(|context| *context > 0)
    });
    let model_bound = descriptor
        .maximum_context_tokens
        .filter(|context| *context > 0);
    match (loaded_instance_bound, model_bound) {
        (Some(instance), Some(model)) => Some(instance.min(model)),
        (Some(instance), None) => Some(instance),
        (None, Some(model)) => Some(model),
        (None, None) => None,
    }
}

fn parse_reasoning(value: Option<&str>) -> Result<Option<ReasoningSetting>, DiscoveryEnd> {
    value
        .map(|value| match value {
            "off" => Ok(ReasoningSetting::Off),
            "on" => Ok(ReasoningSetting::On),
            "low" => Ok(ReasoningSetting::Low),
            "medium" => Ok(ReasoningSetting::Medium),
            "high" => Ok(ReasoningSetting::High),
            _ => Err(DiscoveryEnd::Failed(PreInferenceFailure::new(
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::InvalidRunConfiguration,
                format!("unsupported reasoning setting {value:?}"),
            ))),
        })
        .transpose()
}

fn run_deadline(run: &Run) -> Result<Option<chrono::DateTime<Utc>>, SupervisorRunError> {
    let Some(seconds) = run.spec.limits.max_wall_time_seconds else {
        return Ok(None);
    };
    if seconds == 0 {
        return Err(SupervisorRunError::Contract(
            "max_wall_time_seconds must be greater than zero".to_owned(),
        ));
    }
    let seconds = i64::try_from(seconds).map_err(|_| {
        SupervisorRunError::Contract("max_wall_time_seconds is out of range".to_owned())
    })?;
    let duration = ChronoDuration::try_seconds(seconds).ok_or_else(|| {
        SupervisorRunError::Contract("max_wall_time_seconds is out of range".to_owned())
    })?;
    run.created_at
        .checked_add_signed(duration)
        .map(Some)
        .ok_or_else(|| SupervisorRunError::Contract("run wall deadline overflowed".to_owned()))
}

fn deadline_elapsed(deadline: Option<chrono::DateTime<Utc>>) -> bool {
    deadline.is_some_and(|deadline| deadline <= Utc::now())
}

async fn wait_for_deadline(deadline: Option<chrono::DateTime<Utc>>) {
    let Some(deadline) = deadline else {
        std::future::pending::<()>().await;
        return;
    };
    let remaining = (deadline - Utc::now()).to_std().unwrap_or(Duration::ZERO);
    tokio::time::sleep(remaining).await;
}

struct PreparedCall {
    event: EventEnvelope,
    request: StructuredInferenceRequest,
}

#[allow(clippy::large_enum_variant)]
enum InferenceEnd {
    Observed(Result<StructuredInferenceResponse, BackendError>),
    Cancelled,
    Shutdown,
    Deadline,
    RenewalFailed(SupervisorRunError),
}

#[allow(clippy::large_enum_variant)]
enum PreparePhase {
    Prepared(PreparedCall),
    Cancelled,
    Deadline,
}

struct PrepareInputs {
    session: Session,
    run: Run,
}

#[derive(Clone)]
#[allow(
    clippy::struct_field_names,
    reason = "the digest suffix distinguishes these protocol-bound identities from source values"
)]
struct RootStageBindings {
    obligation_snapshot_digest: Sha256Digest,
    acceptance_policy_digest: Sha256Digest,
    context_manifest_digest: Sha256Digest,
    planner_policy_digest: Sha256Digest,
}

#[derive(Clone)]
struct CommittedCandidate {
    binding: PlanCandidateBinding,
    output: RootPlannerOutput,
}

#[derive(Clone)]
struct CommittedRootContext {
    policy_artifact: ArtifactRef,
    root_policy: RootPlannerPolicy,
    bindings: RootStageBindings,
}

#[allow(clippy::large_enum_variant)]
enum SemanticCompileSource {
    InitialPlan {
        session: Session,
        run: Run,
    },
    InitialReview {
        session: Session,
        run: Run,
        root: CommittedRootContext,
        parent_attempt_id: InferenceAttemptId,
        candidate: CommittedCandidate,
    },
    Repair {
        session: Session,
        run: Run,
        root: CommittedRootContext,
        parent_attempt_id: InferenceAttemptId,
        candidate: CommittedCandidate,
        critic_policy: PlanCriticPolicy,
        critique: PlanCriticOutput,
        critique_sha256: Sha256Digest,
        triggering_review_event_id: EventId,
        required_finding_ids: Vec<String>,
    },
    FinalReview {
        session: Session,
        run: Run,
        root: CommittedRootContext,
        parent_attempt_id: InferenceAttemptId,
        candidate: CommittedCandidate,
    },
}

#[allow(clippy::large_enum_variant)]
enum CompiledSemanticPayload {
    InitialPlan,
    InitialReview {
        candidate: PlanCandidateBinding,
        critic_policy: PlanCriticPolicy,
    },
    Repair {
        candidate: PlanCandidateBinding,
        triggering_review_event_id: EventId,
        required_finding_ids: Vec<String>,
    },
    FinalReview {
        candidate: PlanCandidateBinding,
        critic_policy: PlanCriticPolicy,
    },
}

struct CompiledSemanticStage {
    retained_prompt: RetainedPrompt,
    inference_request: StructuredInferenceRequest,
    request_sha256: Sha256Digest,
    prompt_manifest_sha256: Sha256Digest,
    root_bindings: RootStageBindings,
    parent_attempt_id: Option<InferenceAttemptId>,
    plan_revision: u64,
    plan_digest: Sha256Digest,
    payload: CompiledSemanticPayload,
}

fn prepared_payload(
    attempt: &AttemptReplay,
) -> Result<&PlannerInferencePrepared, SupervisorRunError> {
    let EventPayload::PlannerInferencePrepared(prepared) = &attempt.prepared.payload else {
        return Err(SupervisorRunError::InvalidState(
            "attempt does not contain PlannerInferencePrepared".to_owned(),
        ));
    };
    Ok(prepared)
}

fn load_committed_root_context(
    store: &Store,
    history: &RunHistory,
    expected_execution_policy: &RootPlanningExecutionPolicy,
) -> Result<CommittedRootContext, SupervisorRunError> {
    let initial = history
        .attempt_for_stage(RootPlanningStage::InitialPlan)
        .ok_or_else(|| {
            SupervisorRunError::InvalidState("initial plan stage is missing".to_owned())
        })?;
    let prepared = prepared_payload(initial)?;
    let Some(PlannerStageContext::InitialPlan {
        execution_policy_artifact,
        ..
    }) = &prepared.stage_context
    else {
        return Err(SupervisorRunError::InvalidState(
            "initial plan stage context is invalid".to_owned(),
        ));
    };
    let execution_policy_bytes = store.get_artifact(execution_policy_artifact)?;
    let persisted_execution_policy =
        serde_json::from_slice::<RootPlanningExecutionPolicy>(&execution_policy_bytes)
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
    if serde_json::to_vec(&persisted_execution_policy)
        .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?
        != execution_policy_bytes
        || &persisted_execution_policy != expected_execution_policy
    {
        return Err(SupervisorRunError::InvalidState(
            "configured semantic planning policy differs from the durable initial policy"
                .to_owned(),
        ));
    }
    let prompt_bytes = store.get_artifact(&prepared.prompt_artifact)?;
    let retained_prompt = serde_json::from_slice::<RetainedPrompt>(&prompt_bytes)
        .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
    let [constraint] = retained_prompt
        .prompt_invocation
        .runtime_constraints
        .as_slice()
    else {
        return Err(SupervisorRunError::InvalidState(
            "initial prompt does not contain exactly one root policy".to_owned(),
        ));
    };
    if constraint.name != "planner_policy" {
        return Err(SupervisorRunError::InvalidState(
            "initial prompt root policy has the wrong identity".to_owned(),
        ));
    }
    let root_policy = serde_json::from_value::<RootPlannerPolicy>(constraint.payload.clone())
        .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
    root_policy
        .validate_integrity()
        .map_err(|violations| SupervisorRunError::CommittedArtifact(format!("{violations:?}")))?;
    if root_policy.root_snapshot_sha256 != prepared.plan_digest.as_str()
        || root_policy.planner_policy_sha256 != prepared.planner_policy_digest.as_str()
        || root_policy.context_manifest_sha256 != prepared.context_manifest_digest.as_str()
    {
        return Err(SupervisorRunError::InvalidState(
            "durable root policy does not match the initial Prepared bindings".to_owned(),
        ));
    }
    Ok(CommittedRootContext {
        policy_artifact: execution_policy_artifact.clone(),
        root_policy,
        bindings: RootStageBindings {
            obligation_snapshot_digest: prepared.obligation_snapshot_digest.clone(),
            acceptance_policy_digest: prepared.acceptance_policy_digest.clone(),
            context_manifest_digest: prepared.context_manifest_digest.clone(),
            planner_policy_digest: prepared.planner_policy_digest.clone(),
        },
    })
}

fn load_committed_candidate(
    store: &Store,
    attempt: &AttemptReplay,
) -> Result<CommittedCandidate, SupervisorRunError> {
    let decision = attempt.decision.as_ref().ok_or_else(|| {
        SupervisorRunError::InvalidState("candidate stage has no durable decision".to_owned())
    })?;
    let EventPayload::PlanProposalAccepted(accepted) = &decision.payload else {
        return Err(SupervisorRunError::InvalidState(
            "candidate stage was not accepted".to_owned(),
        ));
    };
    let bytes = store.get_artifact(&accepted.accepted_plan_artifact)?;
    let output = serde_json::from_slice::<RootPlannerOutput>(&bytes)
        .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
    if serde_json::to_vec(&output)
        .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?
        != bytes
        || accepted.accepted_plan_digest.as_str() != accepted.accepted_plan_artifact.sha256
    {
        return Err(SupervisorRunError::InvalidState(
            "accepted candidate artifact is not canonical or digest-bound".to_owned(),
        ));
    }
    Ok(CommittedCandidate {
        binding: PlanCandidateBinding {
            proposal_event_id: decision.id,
            plan_revision: accepted.accepted_plan_revision,
            plan_digest: accepted.accepted_plan_digest.clone(),
            plan_artifact: accepted.accepted_plan_artifact.clone(),
        },
        output,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "all four closed semantic stage sources are validated in one exhaustive match"
)]
fn semantic_compile_source(
    store: &Store,
    session: Session,
    run: Run,
    history: &RunHistory,
    stage: RootPlanningStage,
    policy: &RootPlanningExecutionPolicy,
) -> Result<SemanticCompileSource, SupervisorRunError> {
    match stage {
        RootPlanningStage::InitialPlan => Ok(SemanticCompileSource::InitialPlan { session, run }),
        RootPlanningStage::InitialReview => {
            let initial = history
                .attempt_for_stage(RootPlanningStage::InitialPlan)
                .ok_or_else(|| {
                    SupervisorRunError::InvalidState("initial plan stage is missing".to_owned())
                })?;
            let parent_attempt_id = prepared_payload(initial)?.attempt_id;
            Ok(SemanticCompileSource::InitialReview {
                session,
                run,
                root: load_committed_root_context(store, history, policy)?,
                parent_attempt_id,
                candidate: load_committed_candidate(store, initial)?,
            })
        }
        RootPlanningStage::Repair => {
            let review = history
                .attempt_for_stage(RootPlanningStage::InitialReview)
                .ok_or_else(|| {
                    SupervisorRunError::InvalidState("initial review stage is missing".to_owned())
                })?;
            let review_prepared = prepared_payload(review)?;
            let Some(PlannerStageContext::InitialReview {
                critic_policy_artifact,
                candidate,
                ..
            }) = &review_prepared.stage_context
            else {
                return Err(SupervisorRunError::InvalidState(
                    "initial review context is invalid".to_owned(),
                ));
            };
            let review_event = review.decision.as_ref().ok_or_else(|| {
                SupervisorRunError::InvalidState("initial review has no decision".to_owned())
            })?;
            let EventPayload::PlanSemanticReviewRejected(rejected) = &review_event.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "repair lacks a rejecting semantic review".to_owned(),
                ));
            };
            if rejected.disposition != PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
            {
                return Err(SupervisorRunError::InvalidState(
                    "semantic review did not authorize repair".to_owned(),
                ));
            }
            let critic_policy_bytes = store.get_artifact(critic_policy_artifact)?;
            let critic_policy = serde_json::from_slice::<PlanCriticPolicy>(&critic_policy_bytes)
                .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
            let critique_bytes = store.get_artifact(&rejected.critique_artifact)?;
            let critique = serde_json::from_slice::<PlanCriticOutput>(&critique_bytes)
                .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
            if serde_json::to_vec(&critic_policy)
                .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?
                != critic_policy_bytes
                || serde_json::to_vec(&critique)
                    .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?
                    != critique_bytes
            {
                return Err(SupervisorRunError::InvalidState(
                    "repair inputs are not canonical committed artifacts".to_owned(),
                ));
            }
            let initial = history
                .attempt_for_stage(RootPlanningStage::InitialPlan)
                .ok_or_else(|| {
                    SupervisorRunError::InvalidState("initial plan stage is missing".to_owned())
                })?;
            let committed_candidate = load_committed_candidate(store, initial)?;
            if committed_candidate.binding != *candidate
                || rejected.candidate != committed_candidate.binding
            {
                return Err(SupervisorRunError::InvalidState(
                    "repair candidate differs from committed review subject".to_owned(),
                ));
            }
            Ok(SemanticCompileSource::Repair {
                session,
                run,
                root: load_committed_root_context(store, history, policy)?,
                parent_attempt_id: review_prepared.attempt_id,
                candidate: committed_candidate,
                critic_policy,
                critique,
                critique_sha256: Sha256Digest::parse(rejected.critique_artifact.sha256.clone())
                    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?,
                triggering_review_event_id: review_event.id,
                required_finding_ids: rejected.required_finding_ids.clone(),
            })
        }
        RootPlanningStage::FinalReview => {
            let repair = history
                .attempt_for_stage(RootPlanningStage::Repair)
                .ok_or_else(|| {
                    SupervisorRunError::InvalidState("repair stage is missing".to_owned())
                })?;
            Ok(SemanticCompileSource::FinalReview {
                session,
                run,
                root: load_committed_root_context(store, history, policy)?,
                parent_attempt_id: prepared_payload(repair)?.attempt_id,
                candidate: load_committed_candidate(store, repair)?,
            })
        }
    }
}

fn stage_output_tokens(
    policy: &RootPlanningExecutionPolicy,
    stage: RootPlanningStage,
) -> Result<u32, SupervisorRunError> {
    let tokens = match stage {
        RootPlanningStage::InitialPlan => policy.stage_budgets.initial_plan_output_tokens,
        RootPlanningStage::InitialReview => policy.stage_budgets.initial_review_output_tokens,
        RootPlanningStage::Repair => policy.stage_budgets.repair_output_tokens,
        RootPlanningStage::FinalReview => policy.stage_budgets.final_review_output_tokens,
    };
    u32::try_from(tokens).map_err(|_| {
        SupervisorRunError::Contract(format!(
            "semantic planning stage {stage:?} output ceiling exceeds u32"
        ))
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "all four typed prompt compilers remain visibly exhaustive in one function"
)]
fn compile_semantic_stage(
    source: SemanticCompileSource,
    models: &ResolvedSemanticModels,
    policy: &RootPlanningExecutionPolicy,
) -> Result<CompiledSemanticStage, SupervisorRunError> {
    match source {
        SemanticCompileSource::InitialPlan { session, run } => {
            let compiled = compile_root_plan_request(
                &session,
                &run,
                models.producer.model_id.clone(),
                stage_output_tokens(policy, RootPlanningStage::InitialPlan)?,
                models.producer.reasoning,
            )
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            Ok(CompiledSemanticStage {
                retained_prompt: RetainedPrompt {
                    prompt_invocation: compiled.prompt_invocation,
                    compiled_prompt: compiled.compiled_prompt,
                },
                inference_request: compiled.inference_request,
                request_sha256: compiled.request_sha256,
                prompt_manifest_sha256: compiled.prompt_manifest_sha256,
                root_bindings: RootStageBindings {
                    obligation_snapshot_digest: compiled.obligation_snapshot_sha256,
                    acceptance_policy_digest: compiled.acceptance_policy_sha256,
                    context_manifest_digest: compiled.context_manifest_sha256,
                    planner_policy_digest: compiled.planner_policy_sha256,
                },
                parent_attempt_id: None,
                plan_revision: 0,
                plan_digest: compiled.root_snapshot_sha256,
                payload: CompiledSemanticPayload::InitialPlan,
            })
        }
        SemanticCompileSource::InitialReview {
            session,
            run,
            root,
            parent_attempt_id,
            candidate,
        } => {
            let compiled = compile_plan_critic_request(
                &session,
                &run,
                &root.root_policy,
                &candidate.output,
                &candidate.binding.plan_digest,
                models.critic.model_id.clone(),
                stage_output_tokens(policy, RootPlanningStage::InitialReview)?,
                models.critic.reasoning,
            )
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            if root.policy_artifact.sha256.is_empty() {
                return Err(SupervisorRunError::InvalidState(
                    "durable execution policy artifact is empty".to_owned(),
                ));
            }
            Ok(CompiledSemanticStage {
                retained_prompt: RetainedPrompt {
                    prompt_invocation: compiled.prompt_invocation,
                    compiled_prompt: compiled.compiled_prompt,
                },
                inference_request: compiled.inference_request,
                request_sha256: compiled.request_sha256,
                prompt_manifest_sha256: compiled.prompt_manifest_sha256,
                root_bindings: root.bindings,
                parent_attempt_id: Some(parent_attempt_id),
                plan_revision: candidate.binding.plan_revision,
                plan_digest: candidate.binding.plan_digest.clone(),
                payload: CompiledSemanticPayload::InitialReview {
                    candidate: candidate.binding,
                    critic_policy: compiled.critic_policy,
                },
            })
        }
        SemanticCompileSource::Repair {
            session,
            run,
            root,
            parent_attempt_id,
            candidate,
            critic_policy,
            critique,
            critique_sha256,
            triggering_review_event_id,
            required_finding_ids,
        } => {
            let compiled = compile_plan_repair_request(
                &session,
                &run,
                &root.root_policy,
                &candidate.output,
                &candidate.binding.plan_digest,
                &critic_policy,
                &critique,
                &critique_sha256,
                triggering_review_event_id,
                &required_finding_ids,
                models.producer.model_id.clone(),
                stage_output_tokens(policy, RootPlanningStage::Repair)?,
                models.producer.reasoning,
            )
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            Ok(CompiledSemanticStage {
                retained_prompt: RetainedPrompt {
                    prompt_invocation: compiled.prompt_invocation,
                    compiled_prompt: compiled.compiled_prompt,
                },
                inference_request: compiled.inference_request,
                request_sha256: compiled.request_sha256,
                prompt_manifest_sha256: compiled.prompt_manifest_sha256,
                root_bindings: root.bindings,
                parent_attempt_id: Some(parent_attempt_id),
                plan_revision: candidate.binding.plan_revision,
                plan_digest: candidate.binding.plan_digest.clone(),
                payload: CompiledSemanticPayload::Repair {
                    candidate: candidate.binding,
                    triggering_review_event_id,
                    required_finding_ids,
                },
            })
        }
        SemanticCompileSource::FinalReview {
            session,
            run,
            root,
            parent_attempt_id,
            candidate,
        } => {
            let compiled = compile_plan_critic_request(
                &session,
                &run,
                &root.root_policy,
                &candidate.output,
                &candidate.binding.plan_digest,
                models.critic.model_id.clone(),
                stage_output_tokens(policy, RootPlanningStage::FinalReview)?,
                models.critic.reasoning,
            )
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            Ok(CompiledSemanticStage {
                retained_prompt: RetainedPrompt {
                    prompt_invocation: compiled.prompt_invocation,
                    compiled_prompt: compiled.compiled_prompt,
                },
                inference_request: compiled.inference_request,
                request_sha256: compiled.request_sha256,
                prompt_manifest_sha256: compiled.prompt_manifest_sha256,
                root_bindings: root.bindings,
                parent_attempt_id: Some(parent_attempt_id),
                plan_revision: candidate.binding.plan_revision,
                plan_digest: candidate.binding.plan_digest.clone(),
                payload: CompiledSemanticPayload::FinalReview {
                    candidate: candidate.binding,
                    critic_policy: compiled.critic_policy,
                },
            })
        }
    }
}

fn backend_selection_for_lineage(
    lineage: &ModelLineage,
    reasoning_effort: Option<&str>,
) -> BackendSelection {
    BackendSelection {
        backend_id: lineage.backend_id.clone(),
        kind: BackendKind::Model,
        model: Some(lineage.model_id.clone()),
        reasoning_effort: reasoning_effort.map(str::to_owned),
    }
}

fn backend_selection_for_prepared(
    prepared: &PlannerInferencePrepared,
    reasoning_effort: Option<&str>,
) -> BackendSelection {
    BackendSelection {
        backend_id: prepared.backend_model.backend_id.clone(),
        kind: prepared.backend_model.kind,
        model: Some(prepared.backend_model.model_id.clone()),
        reasoning_effort: reasoning_effort.map(str::to_owned),
    }
}

fn recovery_expects_stage(recovery: &RecoveryAction, stage: RootPlanningStage) -> bool {
    matches!(
        (recovery, stage),
        (RecoveryAction::Fresh, RootPlanningStage::InitialPlan)
            | (
                RecoveryAction::NextStage(RootPlanningStage::InitialReview),
                RootPlanningStage::InitialReview
            )
            | (
                RecoveryAction::NextStage(RootPlanningStage::Repair),
                RootPlanningStage::Repair
            )
            | (
                RecoveryAction::NextStage(RootPlanningStage::FinalReview),
                RootPlanningStage::FinalReview
            )
    )
}

fn predecessor_for_next_stage(
    history: &RunHistory,
    stage: RootPlanningStage,
) -> Result<EventId, SupervisorRunError> {
    let preceding_stage = match stage {
        RootPlanningStage::InitialPlan => {
            return Err(SupervisorRunError::InvalidState(
                "InitialPlan has no preceding semantic decision".to_owned(),
            ));
        }
        RootPlanningStage::InitialReview => RootPlanningStage::InitialPlan,
        RootPlanningStage::Repair => RootPlanningStage::InitialReview,
        RootPlanningStage::FinalReview => RootPlanningStage::Repair,
    };
    history
        .attempt_for_stage(preceding_stage)
        .and_then(|attempt| attempt.decision.as_ref())
        .map(|event| event.id)
        .ok_or_else(|| {
            SupervisorRunError::InvalidState(format!(
                "semantic stage {stage:?} has no exact durable predecessor decision"
            ))
        })
}

fn semantic_stage_identity(
    stage: &PlannerStageContext,
) -> (RootPlanningStage, RootPlanningModelSubject, &ArtifactRef) {
    match stage {
        PlannerStageContext::InitialPlan {
            model_lineage,
            execution_policy_artifact,
            ..
        } => (
            RootPlanningStage::InitialPlan,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::Producer,
                lineage: model_lineage.clone(),
            },
            execution_policy_artifact,
        ),
        PlannerStageContext::InitialReview {
            model_lineage,
            execution_policy_artifact,
            ..
        } => (
            RootPlanningStage::InitialReview,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::IndependentCritic,
                lineage: model_lineage.clone(),
            },
            execution_policy_artifact,
        ),
        PlannerStageContext::Repair {
            model_lineage,
            execution_policy_artifact,
            ..
        } => (
            RootPlanningStage::Repair,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::Producer,
                lineage: model_lineage.clone(),
            },
            execution_policy_artifact,
        ),
        PlannerStageContext::FinalReview {
            model_lineage,
            execution_policy_artifact,
            ..
        } => (
            RootPlanningStage::FinalReview,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::IndependentCritic,
                lineage: model_lineage.clone(),
            },
            execution_policy_artifact,
        ),
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the durable prepare transaction cross-binds every closed semantic stage invariant"
)]
async fn compile_and_prepare_semantic(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    policy: RootPlanningExecutionPolicy,
    models: ResolvedSemanticModels,
    stage: RootPlanningStage,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<PreparePhase, SupervisorRunError> {
    let source_policy = policy.clone();
    let source_config = config.clone();
    let source = store_phase(paths.clone(), move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let session = store.get_session(run.spec.session_id)?.ok_or_else(|| {
            SupervisorRunError::InvalidState(format!("session {} not found", run.spec.session_id))
        })?;
        let history = load_run_history(store, run_id, source_config.max_recovery_events)?;
        if history.cancellation_generation > 0 || run.state == RunState::Cancelled {
            return Ok(Err(PreparePhase::Cancelled));
        }
        if run_deadline(&run)? != deadline || deadline_elapsed(deadline) {
            return Ok(Err(PreparePhase::Deadline));
        }
        if run.state != RunState::Running
            || !recovery_expects_stage(&history.recovery_action()?, stage)
        {
            return Err(SupervisorRunError::InvalidState(format!(
                "durable history is not ready for semantic stage {stage:?}"
            )));
        }
        semantic_compile_source(store, session, run, &history, stage, &source_policy).map(Ok)
    })
    .await?;
    let source = match source {
        Ok(source) => source,
        Err(boundary) => return Ok(boundary),
    };
    let compile_models = models.clone();
    let compile_policy = policy.clone();
    let compiled = tokio::task::spawn_blocking(move || {
        compile_semantic_stage(source, &compile_models, &compile_policy)
    })
    .await
    .map_err(|error| SupervisorRunError::Background(error.to_string()))??;

    renew_claim(paths.clone(), run_id, config.clone()).await?;
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let history = load_run_history(store, run_id, config.max_recovery_events)?;
        if history.cancellation_generation > 0 || run.state == RunState::Cancelled {
            return Ok(PreparePhase::Cancelled);
        }
        if run_deadline(&run)? != deadline || deadline_elapsed(deadline) {
            return Ok(PreparePhase::Deadline);
        }
        if run.state != RunState::Running
            || !recovery_expects_stage(&history.recovery_action()?, stage)
        {
            return Err(SupervisorRunError::InvalidState(format!(
                "semantic stage {stage:?} changed while its prompt was compiled"
            )));
        }

        let policy_bytes =
            serde_json::to_vec(&config.root_planning_policy.as_ref().ok_or_else(|| {
                SupervisorRunError::InvalidState("semantic planning policy disappeared".to_owned())
            })?)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let execution_policy_artifact = persist_new_artifact(
            store,
            &policy_bytes,
            ROOT_PLANNING_EXECUTION_POLICY_MEDIA_TYPE,
        )?;
        let prompt_bytes = serde_json::to_vec(&compiled.retained_prompt)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let prompt_artifact = persist_new_artifact(store, &prompt_bytes, PROMPT_MEDIA_TYPE)?;
        let retained_request = RetainedRequest {
            request: compiled.inference_request.clone(),
            request_sha256: compiled.request_sha256.clone(),
        };
        let request_bytes = serde_json::to_vec(&retained_request)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let request_artifact = persist_new_artifact(store, &request_bytes, REQUEST_MEDIA_TYPE)?;
        let model_actor_id = ActorId::new();
        let (lineage, total_token_budget, stage_context) = match &compiled.payload {
            CompiledSemanticPayload::InitialPlan => (
                &config
                    .root_planning_policy
                    .as_ref()
                    .ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "semantic planning policy disappeared".to_owned(),
                        )
                    })?
                    .producer,
                models.producer.total_token_budget,
                PlannerStageContext::InitialPlan {
                    model_actor_id,
                    model_lineage: config
                        .root_planning_policy
                        .as_ref()
                        .ok_or_else(|| {
                            SupervisorRunError::InvalidState(
                                "semantic planning policy disappeared".to_owned(),
                            )
                        })?
                        .producer
                        .clone(),
                    critic_lineage: config
                        .root_planning_policy
                        .as_ref()
                        .ok_or_else(|| {
                            SupervisorRunError::InvalidState(
                                "semantic planning policy disappeared".to_owned(),
                            )
                        })?
                        .critic
                        .clone(),
                    execution_policy_artifact: execution_policy_artifact.clone(),
                },
            ),
            CompiledSemanticPayload::InitialReview {
                candidate,
                critic_policy,
            } => {
                let critic_policy_bytes = serde_json::to_vec(critic_policy)
                    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
                let critic_policy_artifact =
                    persist_new_artifact(store, &critic_policy_bytes, CRITIC_POLICY_MEDIA_TYPE)?;
                (
                    &config
                        .root_planning_policy
                        .as_ref()
                        .ok_or_else(|| {
                            SupervisorRunError::InvalidState(
                                "semantic planning policy disappeared".to_owned(),
                            )
                        })?
                        .critic,
                    models.critic.total_token_budget,
                    PlannerStageContext::InitialReview {
                        model_actor_id,
                        model_lineage: config
                            .root_planning_policy
                            .as_ref()
                            .ok_or_else(|| {
                                SupervisorRunError::InvalidState(
                                    "semantic planning policy disappeared".to_owned(),
                                )
                            })?
                            .critic
                            .clone(),
                        execution_policy_artifact: execution_policy_artifact.clone(),
                        critic_policy_artifact,
                        review_round: 1,
                        candidate: candidate.clone(),
                    },
                )
            }
            CompiledSemanticPayload::Repair {
                candidate,
                triggering_review_event_id,
                required_finding_ids,
            } => (
                &config
                    .root_planning_policy
                    .as_ref()
                    .ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "semantic planning policy disappeared".to_owned(),
                        )
                    })?
                    .producer,
                models.producer.total_token_budget,
                PlannerStageContext::Repair {
                    model_actor_id,
                    model_lineage: config
                        .root_planning_policy
                        .as_ref()
                        .ok_or_else(|| {
                            SupervisorRunError::InvalidState(
                                "semantic planning policy disappeared".to_owned(),
                            )
                        })?
                        .producer
                        .clone(),
                    execution_policy_artifact: execution_policy_artifact.clone(),
                    repair_ordinal: 1,
                    candidate: candidate.clone(),
                    triggering_review_event_id: *triggering_review_event_id,
                    required_finding_ids: required_finding_ids.clone(),
                },
            ),
            CompiledSemanticPayload::FinalReview {
                candidate,
                critic_policy,
            } => {
                let critic_policy_bytes = serde_json::to_vec(critic_policy)
                    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
                let critic_policy_artifact =
                    persist_new_artifact(store, &critic_policy_bytes, CRITIC_POLICY_MEDIA_TYPE)?;
                (
                    &config
                        .root_planning_policy
                        .as_ref()
                        .ok_or_else(|| {
                            SupervisorRunError::InvalidState(
                                "semantic planning policy disappeared".to_owned(),
                            )
                        })?
                        .critic,
                    models.critic.total_token_budget,
                    PlannerStageContext::FinalReview {
                        model_actor_id,
                        model_lineage: config
                            .root_planning_policy
                            .as_ref()
                            .ok_or_else(|| {
                                SupervisorRunError::InvalidState(
                                    "semantic planning policy disappeared".to_owned(),
                                )
                            })?
                            .critic
                            .clone(),
                        execution_policy_artifact: execution_policy_artifact.clone(),
                        critic_policy_artifact,
                        review_round: 2,
                        repair_ordinal: 1,
                        candidate: candidate.clone(),
                    },
                )
            }
        };
        let prepared = PlannerInferencePrepared {
            attempt_id: InferenceAttemptId::new(),
            parent_attempt_id: compiled.parent_attempt_id,
            backend_model: BackendModelIdentity {
                backend_id: lineage.backend_id.clone(),
                kind: BackendKind::Model,
                model_id: lineage.model_id.clone(),
            },
            prompt_artifact,
            prompt_manifest_digest: compiled.prompt_manifest_sha256,
            request_artifact,
            token_reservation: TokenReservation {
                id: TokenReservationId::new(),
                reserved_tokens: total_token_budget,
                max_output_tokens: u64::from(compiled.inference_request.max_output_tokens()),
            },
            plan_revision: compiled.plan_revision,
            plan_digest: compiled.plan_digest,
            obligation_snapshot_digest: compiled.root_bindings.obligation_snapshot_digest,
            acceptance_policy_digest: compiled.root_bindings.acceptance_policy_digest,
            context_manifest_digest: compiled.root_bindings.context_manifest_digest,
            planner_policy_digest: compiled.root_bindings.planner_policy_digest,
            cancellation_generation: history.cancellation_generation,
            stage_context: Some(stage_context),
        };
        let event = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: history.last_event_id,
            provenance: supervisor_provenance(Some(backend_selection_for_lineage(
                lineage,
                run.spec.backend.reasoning_effort.as_deref(),
            ))),
            payload: EventPayload::PlannerInferencePrepared(prepared),
        })?;
        Ok(PreparePhase::Prepared(PreparedCall {
            event,
            request: compiled.inference_request,
        }))
    })
    .await
}

#[allow(clippy::too_many_lines)]
async fn compile_and_prepare(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    resolved: ResolvedModel,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<PreparePhase, SupervisorRunError> {
    let preflight_config = config.clone();
    let inputs = store_phase(paths.clone(), move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let session = store.get_session(run.spec.session_id)?.ok_or_else(|| {
            SupervisorRunError::InvalidState(format!("session {} not found", run.spec.session_id))
        })?;
        let history = load_run_history(store, run_id, preflight_config.max_recovery_events)?;
        if history.cancellation_generation > 0 || run.state == RunState::Cancelled {
            return Ok(Err(PreparePhase::Cancelled));
        }
        if run_deadline(&run)? != deadline || deadline_elapsed(deadline) {
            return Ok(Err(PreparePhase::Deadline));
        }
        if run.state != RunState::Running {
            return Err(SupervisorRunError::InvalidState(format!(
                "cannot prepare inference while run is {:?}",
                run.state
            )));
        }
        if !matches!(history.recovery_action()?, RecoveryAction::Fresh) {
            return Err(SupervisorRunError::InvalidState(
                "a planner attempt appeared during discovery".to_owned(),
            ));
        }
        Ok(Ok(PrepareInputs { session, run }))
    })
    .await?;
    let inputs = match inputs {
        Ok(inputs) => inputs,
        Err(boundary) => return Ok(boundary),
    };

    // Prompt/schema compilation can be CPU-heavy. It runs without a Store
    // connection, then ownership is renewed before the Prepared CAS.
    let ResolvedModel {
        model_id,
        max_output_tokens,
        total_token_budget,
        reasoning,
    } = resolved;
    let compiled = tokio::task::spawn_blocking(move || {
        compile_root_plan_request(
            &inputs.session,
            &inputs.run,
            model_id,
            max_output_tokens,
            reasoning,
        )
    })
    .await
    .map_err(|error| SupervisorRunError::Background(error.to_string()))?
    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;

    renew_claim(paths.clone(), run_id, config.clone()).await?;
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let history = load_run_history(store, run_id, config.max_recovery_events)?;
        if history.cancellation_generation > 0 || run.state == RunState::Cancelled {
            return Ok(PreparePhase::Cancelled);
        }
        if run_deadline(&run)? != deadline || deadline_elapsed(deadline) {
            return Ok(PreparePhase::Deadline);
        }
        if run.state != RunState::Running {
            return Err(SupervisorRunError::InvalidState(format!(
                "cannot persist Prepared while run is {:?}",
                run.state
            )));
        }
        if !matches!(history.recovery_action()?, RecoveryAction::Fresh) {
            return Err(SupervisorRunError::InvalidState(
                "a planner attempt appeared while compiling the prompt".to_owned(),
            ));
        }
        let retained_prompt = RetainedPrompt {
            prompt_invocation: compiled.prompt_invocation.clone(),
            compiled_prompt: compiled.compiled_prompt.clone(),
        };
        let prompt_bytes = serde_json::to_vec(&retained_prompt)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let prompt_artifact = persist_new_artifact(store, &prompt_bytes, PROMPT_MEDIA_TYPE)?;
        let retained_request = RetainedRequest {
            request: compiled.inference_request.clone(),
            request_sha256: compiled.request_sha256.clone(),
        };
        let request_bytes = serde_json::to_vec(&retained_request)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let request_artifact = persist_new_artifact(store, &request_bytes, REQUEST_MEDIA_TYPE)?;
        let (plan_revision, plan_digest) =
            current_plan_base(&history).unwrap_or((0, compiled.root_snapshot_sha256.clone()));
        let prepared = PlannerInferencePrepared {
            attempt_id: InferenceAttemptId::new(),
            parent_attempt_id: None,
            backend_model: BackendModelIdentity {
                backend_id: run.spec.backend.backend_id.clone(),
                kind: BackendKind::Model,
                model_id: compiled.inference_request.model_id().as_str().to_owned(),
            },
            prompt_artifact,
            prompt_manifest_digest: compiled.prompt_manifest_sha256,
            request_artifact,
            token_reservation: TokenReservation {
                id: TokenReservationId::new(),
                reserved_tokens: total_token_budget,
                max_output_tokens: u64::from(compiled.inference_request.max_output_tokens()),
            },
            plan_revision,
            plan_digest,
            obligation_snapshot_digest: compiled.obligation_snapshot_sha256,
            acceptance_policy_digest: compiled.acceptance_policy_sha256,
            context_manifest_digest: compiled.context_manifest_sha256,
            planner_policy_digest: compiled.planner_policy_sha256,
            cancellation_generation: history.cancellation_generation,
            stage_context: None,
        };
        let event = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: history.last_event_id,
            provenance: supervisor_provenance(Some(run.spec.backend.clone())),
            payload: EventPayload::PlannerInferencePrepared(prepared),
        })?;
        Ok(PreparePhase::Prepared(PreparedCall {
            event,
            request: compiled.inference_request,
        }))
    })
    .await
}

fn current_plan_base(history: &RunHistory) -> Option<(u64, Sha256Digest)> {
    history
        .attempts
        .values()
        .filter_map(|attempt| attempt.decision.as_ref())
        .filter_map(|event| match &event.payload {
            EventPayload::PlanProposalAccepted(accepted) => Some((
                event.sequence,
                accepted.accepted_plan_revision,
                accepted.accepted_plan_digest.clone(),
            )),
            _ => None,
        })
        .max_by_key(|(sequence, _, _)| *sequence)
        .map(|(_, revision, digest)| (revision, digest))
}

async fn ensure_durable_cancellation(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
) -> Result<u64, SupervisorRunError> {
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let history = load_run_history(store, run_id, config.max_recovery_events)?;
        if history.cancellation_generation > 0 {
            return Ok(history.cancellation_generation);
        }
        if is_terminal(run.state) {
            return Ok(0);
        }
        let appended = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: history.last_event_id,
            provenance: supervisor_provenance(None),
            payload: EventPayload::CancellationRequested(
                birdcode_protocol::CancellationRequested {
                    cancellation_request_id: CancellationRequestId::new(),
                    cancellation_generation: 1,
                },
            ),
        });
        match appended {
            Ok(_) => Ok(1),
            Err(error) => {
                let refreshed = load_run_history(store, run_id, config.max_recovery_events)?;
                if refreshed.cancellation_generation > 0 {
                    Ok(refreshed.cancellation_generation)
                } else {
                    Err(error.into())
                }
            }
        }
    })
    .await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootPlanningFailureAppend {
    Recorded,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootPlanningStageFailureAppend {
    Recorded,
    Cancelled,
}

async fn fail_before_inference(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    cancellation: &CancellationToken,
    failure: PreInferenceFailure,
) -> Result<RunState, SupervisorRunError> {
    if cancellation.is_cancelled() {
        ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
        renew_claim(paths.clone(), run_id, config.clone()).await?;
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Cancelled,
        )
        .await?;
        return Ok(actual);
    }

    renew_claim(paths.clone(), run_id, config.clone()).await?;
    let appended = append_root_planning_failure(
        paths.clone(),
        run_id,
        config.actor_id,
        config.max_recovery_events,
        failure,
    )
    .await?;
    if cancellation.is_cancelled() {
        ensure_durable_cancellation(paths.clone(), run_id, config.clone()).await?;
    }
    let target = if appended == RootPlanningFailureAppend::Cancelled || cancellation.is_cancelled()
    {
        RunState::Cancelled
    } else {
        RunState::Failed
    };
    renew_claim(paths.clone(), run_id, config.clone()).await?;
    transition_run(
        paths,
        run_id,
        config.actor_id,
        config.max_recovery_events,
        target,
    )
    .await
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed durable failure append binds typed cause, model subject, evidence, provenance, and terminal CAS"
)]
async fn append_root_planning_failure(
    paths: RuntimePaths,
    run_id: RunId,
    actor_id: ActorId,
    maximum_events: usize,
    failure: PreInferenceFailure,
) -> Result<RootPlanningFailureAppend, SupervisorRunError> {
    store_phase(paths, move |store| {
        let expected_phase = failure.phase;
        let expected_reason = failure.reason;
        let expected_subject = failure.model_subject.as_deref().cloned();
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let history = load_run_history(store, run_id, maximum_events)?;
        if history.cancellation_generation > 0 || run.state == RunState::Cancelled {
            return Ok(RootPlanningFailureAppend::Cancelled);
        }
        if let Some(existing) = &history.root_planning_failure {
            let EventPayload::RootPlanningFailed(existing) = &existing.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "replayed root failure has the wrong event type".to_owned(),
                ));
            };
            if existing.phase == expected_phase
                && existing.reason == expected_reason
                && existing.model_subject == expected_subject
            {
                return Ok(RootPlanningFailureAppend::Recorded);
            }
            return Err(SupervisorRunError::InvalidState(
                "a different pre-inference failure is already durable".to_owned(),
            ));
        }
        if run.state != RunState::Running
            || !matches!(history.recovery_action()?, RecoveryAction::Fresh)
        {
            return Err(SupervisorRunError::InvalidState(
                "pre-inference failure requires a fresh running planner".to_owned(),
            ));
        }
        let (claim_event, claim) = history.latest_claim.as_ref().ok_or_else(|| {
            SupervisorRunError::InvalidState("pre-inference failure has no live claim".to_owned())
        })?;
        let retained = RetainedRootPlanningFailure {
            schema_version: 1,
            run_id,
            claim_event_id: claim_event.id,
            claim_id: claim.claim_id,
            phase: expected_phase,
            reason: expected_reason,
            model_subject: expected_subject.clone(),
            detail: failure.detail,
        };
        let bytes = serde_json::to_vec(&retained)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let artifact = persist_new_artifact(store, &bytes, ROOT_PLANNING_FAILURE_MEDIA_TYPE)?;
        let appended = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: history.last_event_id,
            provenance: Provenance {
                producer: SUPERVISOR_PRODUCER.to_owned(),
                backend: Some(expected_subject.as_ref().map_or_else(
                    || run.spec.backend.clone(),
                    |subject| {
                        backend_selection_for_lineage(
                            &subject.lineage,
                            run.spec.backend.reasoning_effort.as_deref(),
                        )
                    },
                )),
                raw_artifact: Some(artifact.clone()),
            },
            payload: EventPayload::RootPlanningFailed(RootPlanningFailed {
                claim_event_id: claim_event.id,
                claim_id: claim.claim_id,
                cancellation_generation: history.cancellation_generation,
                phase: expected_phase,
                reason: expected_reason,
                model_subject: expected_subject.clone(),
                evidence_artifact: artifact,
            }),
        });
        match appended {
            Ok(_) => Ok(RootPlanningFailureAppend::Recorded),
            Err(error) => {
                let refreshed = load_run_history(store, run_id, maximum_events)?;
                if refreshed.cancellation_generation > 0 {
                    return Ok(RootPlanningFailureAppend::Cancelled);
                }
                if let Some(existing) = refreshed.root_planning_failure {
                    let EventPayload::RootPlanningFailed(existing) = existing.payload else {
                        return Err(SupervisorRunError::InvalidState(
                            "replayed root failure has the wrong event type".to_owned(),
                        ));
                    };
                    if existing.phase == expected_phase
                        && existing.reason == expected_reason
                        && existing.model_subject == expected_subject
                    {
                        return Ok(RootPlanningFailureAppend::Recorded);
                    }
                }
                Err(error.into())
            }
        }
    })
    .await
}

#[allow(
    clippy::too_many_lines,
    reason = "the failure append keeps validation, evidence, CAS, and idempotent replay together"
)]
async fn append_root_planning_stage_failure(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    stage: RootPlanningStage,
    reason: RootPlanningStageFailureReason,
    model_subject: Option<RootPlanningModelSubject>,
    detail: String,
) -> Result<RootPlanningStageFailureAppend, SupervisorRunError> {
    renew_claim(paths.clone(), run_id, config.clone()).await?;
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let history = load_run_history(store, run_id, config.max_recovery_events)?;
        if history.cancellation_generation > 0 || run.state == RunState::Cancelled {
            return Ok(RootPlanningStageFailureAppend::Cancelled);
        }
        if run.state != RunState::Running
            || !recovery_expects_stage(&history.recovery_action()?, stage)
        {
            return Err(SupervisorRunError::InvalidState(format!(
                "cannot fail semantic stage {stage:?} from the durable predecessor"
            )));
        }
        let initial = history
            .attempt_for_stage(RootPlanningStage::InitialPlan)
            .ok_or_else(|| {
                SupervisorRunError::InvalidState(
                    "later semantic stage failure lacks InitialPlan".to_owned(),
                )
            })?;
        let initial_prepared = prepared_payload(initial)?;
        let Some(PlannerStageContext::InitialPlan {
            model_lineage: producer_lineage,
            critic_lineage,
            execution_policy_artifact,
            ..
        }) = &initial_prepared.stage_context
        else {
            return Err(SupervisorRunError::InvalidState(
                "later semantic stage failure lacks a policy artifact".to_owned(),
            ));
        };
        let default_subject = match stage {
            RootPlanningStage::InitialPlan | RootPlanningStage::Repair => {
                RootPlanningModelSubject {
                    role: RootPlanningModelRole::Producer,
                    lineage: producer_lineage.clone(),
                }
            }
            RootPlanningStage::InitialReview | RootPlanningStage::FinalReview => {
                RootPlanningModelSubject {
                    role: RootPlanningModelRole::IndependentCritic,
                    lineage: critic_lineage.clone(),
                }
            }
        };
        let model_subject = model_subject.unwrap_or(default_subject);
        let predecessor_event_id = predecessor_for_next_stage(&history, stage)?;
        let retained = RetainedRootPlanningStageFailure {
            schema_version: 1,
            run_id,
            failed_stage: stage,
            predecessor_event_id,
            execution_policy_sha256: Sha256Digest::parse(execution_policy_artifact.sha256.clone())
                .map_err(|error| SupervisorRunError::Contract(error.to_string()))?,
            reason,
            model_subject: model_subject.clone(),
            detail,
        };
        let bytes = serde_json::to_vec(&retained)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let evidence_artifact =
            persist_new_artifact(store, &bytes, ROOT_PLANNING_STAGE_FAILURE_MEDIA_TYPE)?;
        let appended = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: history.last_event_id,
            provenance: Provenance {
                producer: SUPERVISOR_PRODUCER.to_owned(),
                backend: Some(backend_selection_for_lineage(
                    &model_subject.lineage,
                    run.spec.backend.reasoning_effort.as_deref(),
                )),
                raw_artifact: Some(evidence_artifact.clone()),
            },
            payload: EventPayload::RootPlanningStageFailed(RootPlanningStageFailed {
                failure_id: RootPlanningStageFailureId::new(),
                failed_stage: stage,
                predecessor_event_id,
                execution_policy_artifact: execution_policy_artifact.clone(),
                cancellation_generation: history.cancellation_generation,
                reason,
                model_subject: model_subject.clone(),
                evidence_artifact,
            }),
        });
        match appended {
            Ok(_) => Ok(RootPlanningStageFailureAppend::Recorded),
            Err(error) => {
                let refreshed = load_run_history(store, run_id, config.max_recovery_events)?;
                if refreshed.cancellation_generation > 0 {
                    return Ok(RootPlanningStageFailureAppend::Cancelled);
                }
                if let Some(existing) = refreshed.root_planning_stage_failure {
                    let EventPayload::RootPlanningStageFailed(existing) = existing.payload else {
                        return Err(SupervisorRunError::InvalidState(
                            "replayed stage failure has the wrong event type".to_owned(),
                        ));
                    };
                    if existing.failed_stage == stage
                        && existing.predecessor_event_id == predecessor_event_id
                        && existing.execution_policy_artifact == *execution_policy_artifact
                        && existing.reason == reason
                        && existing.model_subject == model_subject
                    {
                        return Ok(RootPlanningStageFailureAppend::Recorded);
                    }
                }
                Err(error.into())
            }
        }
    })
    .await
}

#[allow(
    clippy::too_many_lines,
    reason = "the observed failure boundary keeps exact binding and cancellation dominance together"
)]
async fn fail_observed_semantic_stage(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    prepared_event: EventEnvelope,
    observed_event: EventEnvelope,
    reason: RootPlanningStageFailureReason,
    detail: String,
) -> Result<RunCompletion, SupervisorRunError> {
    renew_claim(paths.clone(), run_id, config.clone()).await?;
    let appended = store_phase(paths.clone(), {
        let config = config.clone();
        move |store| {
            let run = store.get_run(run_id)?.ok_or_else(|| {
                SupervisorRunError::InvalidState(format!("run {run_id} not found"))
            })?;
            let history = load_run_history(store, run_id, config.max_recovery_events)?;
            if history.cancellation_generation > 0 || run.state == RunState::Cancelled {
                return Ok(RootPlanningStageFailureAppend::Cancelled);
            }
            if run.state != RunState::Running {
                return Err(SupervisorRunError::InvalidState(format!(
                    "cannot fail an observed semantic stage while run is {:?}",
                    run.state
                )));
            }
            let RecoveryAction::Observed { prepared, observed } = history.recovery_action()? else {
                return Err(SupervisorRunError::InvalidState(
                    "committed-artifact failure requires one unresolved Observed".to_owned(),
                ));
            };
            if prepared.id != prepared_event.id || observed.id != observed_event.id {
                return Err(SupervisorRunError::InvalidState(
                    "committed-artifact failure does not match the unresolved attempt".to_owned(),
                ));
            }
            let EventPayload::PlannerInferencePrepared(prepared_payload) = &prepared.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "committed-artifact failure lacks Prepared".to_owned(),
                ));
            };
            let EventPayload::PlannerInferenceObserved(observed_payload) = &observed.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "committed-artifact failure lacks Observed".to_owned(),
                ));
            };
            if !matches!(
                observed_payload.outcome,
                PlannerInferenceObservation::Succeeded { .. }
            ) {
                return Err(SupervisorRunError::InvalidState(
                    "only a successful unresolved observation can fail deterministic replay"
                        .to_owned(),
                ));
            }
            let stage_context = prepared_payload.stage_context.as_ref().ok_or_else(|| {
                SupervisorRunError::InvalidState(
                    "committed-artifact failure requires semantic stage context".to_owned(),
                )
            })?;
            let (stage, model_subject, execution_policy_artifact) =
                semantic_stage_identity(stage_context);
            let retained = RetainedRootPlanningStageFailure {
                schema_version: 1,
                run_id,
                failed_stage: stage,
                predecessor_event_id: observed.id,
                execution_policy_sha256: Sha256Digest::parse(
                    execution_policy_artifact.sha256.clone(),
                )
                .map_err(|error| SupervisorRunError::Contract(error.to_string()))?,
                reason,
                model_subject: model_subject.clone(),
                detail,
            };
            let bytes = serde_json::to_vec(&retained)
                .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            let evidence_artifact =
                persist_new_artifact(store, &bytes, ROOT_PLANNING_STAGE_FAILURE_MEDIA_TYPE)?;
            let predecessor_event_id = observed.id;
            let execution_policy_artifact = execution_policy_artifact.clone();
            let appended = store.append_event(NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id: config.actor_id,
                causal_parent: history.last_event_id,
                provenance: Provenance {
                    producer: SUPERVISOR_PRODUCER.to_owned(),
                    backend: Some(backend_selection_for_lineage(
                        &model_subject.lineage,
                        run.spec.backend.reasoning_effort.as_deref(),
                    )),
                    raw_artifact: Some(evidence_artifact.clone()),
                },
                payload: EventPayload::RootPlanningStageFailed(RootPlanningStageFailed {
                    failure_id: RootPlanningStageFailureId::new(),
                    failed_stage: stage,
                    predecessor_event_id,
                    execution_policy_artifact: execution_policy_artifact.clone(),
                    cancellation_generation: history.cancellation_generation,
                    reason,
                    model_subject: model_subject.clone(),
                    evidence_artifact,
                }),
            });
            match appended {
                Ok(_) => Ok(RootPlanningStageFailureAppend::Recorded),
                Err(error) => {
                    let refreshed = load_run_history(store, run_id, config.max_recovery_events)?;
                    if refreshed.cancellation_generation > 0 {
                        return Ok(RootPlanningStageFailureAppend::Cancelled);
                    }
                    if let Some(existing) = refreshed.root_planning_stage_failure {
                        let EventPayload::RootPlanningStageFailed(existing) = existing.payload
                        else {
                            return Err(SupervisorRunError::InvalidState(
                                "replayed observed-stage failure has the wrong event type"
                                    .to_owned(),
                            ));
                        };
                        if existing.failed_stage == stage
                            && existing.predecessor_event_id == predecessor_event_id
                            && existing.execution_policy_artifact == execution_policy_artifact
                            && existing.reason == reason
                            && existing.model_subject == model_subject
                        {
                            return Ok(RootPlanningStageFailureAppend::Recorded);
                        }
                    }
                    Err(error.into())
                }
            }
        }
    })
    .await?;
    let target = if appended == RootPlanningStageFailureAppend::Cancelled {
        RunState::Cancelled
    } else {
        RunState::Failed
    };
    renew_claim(paths.clone(), run_id, config.clone()).await?;
    let actual = transition_run(
        paths,
        run_id,
        config.actor_id,
        config.max_recovery_events,
        target,
    )
    .await?;
    Ok(completion_for_state(actual))
}

enum SemanticObservedDecision {
    Decided(DecisionOutcome),
    Terminal(RunCompletion),
}

async fn decide_or_fail_semantic_observed(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    prepared: EventEnvelope,
    observed: EventEnvelope,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<SemanticObservedDecision, SupervisorRunError> {
    let decision = decide_observed(
        paths.clone(),
        run_id,
        config.actor_id,
        config.max_recovery_events,
        prepared.clone(),
        observed.clone(),
        deadline,
    )
    .await;
    match decision {
        Ok(DecisionOutcome::Deadline) => fail_observed_semantic_stage(
            paths,
            run_id,
            config,
            prepared,
            observed,
            RootPlanningStageFailureReason::WallDeadlineExceeded,
            "run wall deadline elapsed before the committed observation could be accepted"
                .to_owned(),
        )
        .await
        .map(SemanticObservedDecision::Terminal),
        Err(error) => {
            let Some(reason) = committed_replay_failure_reason(&error) else {
                return Err(error);
            };
            fail_observed_semantic_stage(
                paths,
                run_id,
                config,
                prepared,
                observed,
                reason,
                error.to_string(),
            )
            .await
            .map(SemanticObservedDecision::Terminal)
        }
        Ok(decision) => Ok(SemanticObservedDecision::Decided(decision)),
    }
}

fn committed_replay_failure_reason(
    error: &SupervisorRunError,
) -> Option<RootPlanningStageFailureReason> {
    match error {
        SupervisorRunError::ArtifactPersistence(error) if error.is_retryable() => None,
        SupervisorRunError::ArtifactPersistence(_) => {
            Some(RootPlanningStageFailureReason::ArtifactPersistenceFailed)
        }
        SupervisorRunError::CommittedArtifact(_) => {
            Some(RootPlanningStageFailureReason::InvalidCommittedArtifact)
        }
        SupervisorRunError::Contract(_) | SupervisorRunError::InvalidState(_) => {
            Some(RootPlanningStageFailureReason::DurableStateConflict)
        }
        SupervisorRunError::Store(error) if error.is_retryable() => None,
        SupervisorRunError::Store(
            StoreError::Io(_)
            | StoreError::InvalidArtifactHash
            | StoreError::ArtifactTooLarge
            | StoreError::ArtifactIntegrity,
        ) => Some(RootPlanningStageFailureReason::InvalidCommittedArtifact),
        SupervisorRunError::Store(_) => Some(RootPlanningStageFailureReason::DurableStateConflict),
        SupervisorRunError::Io(_) | SupervisorRunError::Background(_) => None,
    }
}

async fn append_unknown(
    paths: RuntimePaths,
    run_id: RunId,
    actor_id: ActorId,
    maximum_events: usize,
    prepared_event: EventEnvelope,
    reason: UnknownInferenceOutcomeReason,
    boundary_reason: UnknownInferenceBoundary,
) -> Result<EventEnvelope, SupervisorRunError> {
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let history = load_run_history(store, run_id, maximum_events)?;
        let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
            return Err(SupervisorRunError::InvalidState(
                "unknown outcome is not bound to Prepared".to_owned(),
            ));
        };
        let boundary = RetainedCancellationBoundary {
            reason: boundary_reason,
            prepared_event_id: prepared_event.id,
            cancellation_generation: history.cancellation_generation,
        };
        let bytes = serde_json::to_vec(&boundary)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let artifact = persist_new_artifact(store, &bytes, CANCELLATION_MEDIA_TYPE)?;
        store
            .append_event(NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(prepared_event.id),
                provenance: Provenance {
                    producer: SUPERVISOR_PRODUCER.to_owned(),
                    backend: Some(backend_selection_for_prepared(
                        prepared,
                        run.spec.backend.reasoning_effort.as_deref(),
                    )),
                    raw_artifact: Some(artifact),
                },
                payload: EventPayload::PlannerInferenceOutcomeUnknown(
                    PlannerInferenceOutcomeUnknown {
                        attempt_id: prepared.attempt_id,
                        token_reservation_id: prepared.token_reservation.id,
                        prepared_event_id: prepared_event.id,
                        reason,
                        cancellation_generation: history.cancellation_generation,
                    },
                ),
            })
            .map_err(Into::into)
    })
    .await
}

async fn append_cancelled_before_call(
    paths: RuntimePaths,
    run_id: RunId,
    actor_id: ActorId,
    prepared_call: &PreparedCall,
) -> Result<EventEnvelope, SupervisorRunError> {
    let prepared_event = prepared_call.event.clone();
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
            return Err(SupervisorRunError::InvalidState(
                "cancelled call is not bound to Prepared".to_owned(),
            ));
        };
        let bytes = serde_json::to_vec(&RetainedInferenceEvidence::CancelledBeforeCall)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let artifact = persist_new_artifact(store, &bytes, INFERENCE_MEDIA_TYPE)?;
        store
            .append_event(NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(prepared_event.id),
                provenance: Provenance {
                    producer: SUPERVISOR_PRODUCER.to_owned(),
                    backend: Some(backend_selection_for_prepared(
                        prepared,
                        run.spec.backend.reasoning_effort.as_deref(),
                    )),
                    raw_artifact: Some(artifact.clone()),
                },
                payload: EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                    attempt_id: prepared.attempt_id,
                    token_reservation_id: prepared.token_reservation.id,
                    prepared_event_id: prepared_event.id,
                    normalized_complete_evidence_artifact: artifact,
                    outcome: PlannerInferenceObservation::Failed {
                        error: PlannerInferenceError {
                            kind: PlannerInferenceErrorKind::Cancelled,
                            retry: RetryDisposition::Never,
                        },
                    },
                }),
            })
            .map_err(Into::into)
    })
    .await
}

struct ObservedPair {
    prepared: EventEnvelope,
    observed: EventEnvelope,
}

async fn append_observation(
    paths: RuntimePaths,
    run_id: RunId,
    actor_id: ActorId,
    prepared_event: EventEnvelope,
    result: Result<StructuredInferenceResponse, BackendError>,
) -> Result<ObservedPair, SupervisorRunError> {
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
            return Err(SupervisorRunError::InvalidState(
                "observation is not bound to Prepared".to_owned(),
            ));
        };
        let (retained, outcome) = normalize_observation(prepared, result);
        let bytes = serde_json::to_vec(&retained)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let artifact = persist_new_artifact(store, &bytes, INFERENCE_MEDIA_TYPE)?;
        let observed = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(prepared_event.id),
            provenance: Provenance {
                producer: SUPERVISOR_PRODUCER.to_owned(),
                backend: Some(backend_selection_for_prepared(
                    prepared,
                    run.spec.backend.reasoning_effort.as_deref(),
                )),
                raw_artifact: Some(artifact.clone()),
            },
            payload: EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                attempt_id: prepared.attempt_id,
                token_reservation_id: prepared.token_reservation.id,
                prepared_event_id: prepared_event.id,
                normalized_complete_evidence_artifact: artifact,
                outcome,
            }),
        })?;
        Ok(ObservedPair {
            prepared: prepared_event,
            observed,
        })
    })
    .await
}

fn normalize_observation(
    prepared: &PlannerInferencePrepared,
    result: Result<StructuredInferenceResponse, BackendError>,
) -> (RetainedInferenceEvidence, PlannerInferenceObservation) {
    match result {
        Ok(response) => {
            let violations = response_contract_violations(prepared, &response);
            let outcome = if violations.is_empty()
                && let Some(token_usage) = normalized_token_usage(&response)
            {
                PlannerInferenceObservation::Succeeded {
                    reported_backend_model: prepared.backend_model.clone(),
                    token_usage,
                }
            } else {
                PlannerInferenceObservation::Failed {
                    error: PlannerInferenceError {
                        kind: PlannerInferenceErrorKind::ProtocolViolation,
                        retry: RetryDisposition::Never,
                    },
                }
            };
            (RetainedInferenceEvidence::Response { response }, outcome)
        }
        Err(error) => {
            let outcome = PlannerInferenceObservation::Failed {
                error: PlannerInferenceError {
                    kind: protocol_error_kind(&error.kind),
                    retry: retry_disposition(&error.kind),
                },
            };
            (RetainedInferenceEvidence::Error { error }, outcome)
        }
    }
}

fn response_contract_violations(
    prepared: &PlannerInferencePrepared,
    response: &StructuredInferenceResponse,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if response.model_id.as_str().as_bytes() != prepared.backend_model.model_id.as_bytes() {
        violations.push("model_identity_mismatch");
    }
    if response.evidence.backend_id.as_str().as_bytes()
        != prepared.backend_model.backend_id.as_bytes()
    {
        violations.push("backend_identity_mismatch");
    }
    match serde_json::from_str::<serde_json::Value>(&response.raw_text) {
        Ok(value) if value != response.value => violations.push("raw_json_value_mismatch"),
        Err(_) => violations.push("raw_text_is_not_json"),
        Ok(_) => {}
    }
    let Some(usage) = &response.usage else {
        violations.push("missing_token_usage");
        return violations;
    };
    let (Some(input), Some(output), Some(total)) =
        (usage.input_tokens, usage.output_tokens, usage.total_tokens)
    else {
        violations.push("incomplete_token_usage");
        return violations;
    };
    if output > prepared.token_reservation.max_output_tokens {
        violations.push("output_token_ceiling_exceeded");
    }
    if total > prepared.token_reservation.reserved_tokens {
        violations.push("total_token_reservation_exceeded");
    }
    if input.checked_add(output) != Some(total) {
        violations.push("token_total_mismatch");
    }
    violations
}

const fn protocol_error_kind(kind: &BackendErrorKind) -> PlannerInferenceErrorKind {
    match kind {
        BackendErrorKind::Transport => PlannerInferenceErrorKind::Transport,
        BackendErrorKind::Timeout => PlannerInferenceErrorKind::Timeout,
        BackendErrorKind::HttpStatus => PlannerInferenceErrorKind::ProviderRejected,
        BackendErrorKind::MalformedResponse
        | BackendErrorKind::ResponseContractViolation
        | BackendErrorKind::SchemaViolation
        | BackendErrorKind::IncompleteResponse => {
            PlannerInferenceErrorKind::InvalidStructuredResponse
        }
        BackendErrorKind::InvalidConfiguration
        | BackendErrorKind::InvalidRequest
        | BackendErrorKind::Unsupported
        | BackendErrorKind::InvalidSchema
        | BackendErrorKind::RequestTooLarge
        | BackendErrorKind::ResponseTooLarge => PlannerInferenceErrorKind::ProtocolViolation,
    }
}

const fn retry_disposition(kind: &BackendErrorKind) -> RetryDisposition {
    match kind {
        BackendErrorKind::Transport | BackendErrorKind::Timeout => {
            RetryDisposition::RequiresNewAttempt
        }
        _ => RetryDisposition::Never,
    }
}

async fn resume_observed(
    paths: RuntimePaths,
    run_id: RunId,
    config: RunSupervisorConfig,
    prepared: EventEnvelope,
    observed: EventEnvelope,
) -> Result<RunCompletion, SupervisorRunError> {
    let EventPayload::PlannerInferenceObserved(observation) = &observed.payload else {
        return Err(SupervisorRunError::InvalidState(
            "replay target is not an Observed event".to_owned(),
        ));
    };
    if durable_cancellation_generation(paths.clone(), run_id, config.max_recovery_events).await? > 0
    {
        renew_claim(paths.clone(), run_id, config.clone()).await?;
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Cancelled,
        )
        .await?;
        return Ok(completion_for_state(actual));
    }
    if matches!(
        observation.outcome,
        PlannerInferenceObservation::Failed { .. }
    ) {
        let actual = transition_run(
            paths,
            run_id,
            config.actor_id,
            config.max_recovery_events,
            RunState::Failed,
        )
        .await?;
        return Ok(completion_for_state(actual));
    }
    let decision = decide_observed(
        paths.clone(),
        run_id,
        config.actor_id,
        config.max_recovery_events,
        prepared,
        observed,
        None,
    )
    .await?;
    let state = match decision {
        DecisionOutcome::Accepted => RunState::Completed,
        DecisionOutcome::Rejected => RunState::Failed,
        DecisionOutcome::Cancelled => {
            renew_claim(paths.clone(), run_id, config.clone()).await?;
            RunState::Cancelled
        }
        DecisionOutcome::Deadline => {
            return Err(SupervisorRunError::InvalidState(
                "legacy decision unexpectedly received a semantic deadline boundary".to_owned(),
            ));
        }
    };
    let actual = transition_run(
        paths,
        run_id,
        config.actor_id,
        config.max_recovery_events,
        state,
    )
    .await?;
    Ok(completion_for_state(actual))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecisionOutcome {
    Accepted,
    Rejected,
    Cancelled,
    Deadline,
}

#[allow(clippy::too_many_lines)]
async fn decide_observed(
    paths: RuntimePaths,
    run_id: RunId,
    actor_id: ActorId,
    maximum_events: usize,
    prepared_event: EventEnvelope,
    observed_event: EventEnvelope,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<DecisionOutcome, SupervisorRunError> {
    store_phase(paths, move |store| {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
            return Err(SupervisorRunError::InvalidState(
                "decision is not bound to Prepared".to_owned(),
            ));
        };
        let EventPayload::PlannerInferenceObserved(observed) = &observed_event.payload else {
            return Err(SupervisorRunError::InvalidState(
                "decision is not bound to Observed".to_owned(),
            ));
        };
        let PlannerInferenceObservation::Succeeded { token_usage, .. } = &observed.outcome else {
            return Err(SupervisorRunError::InvalidState(
                "failed observation cannot produce a plan decision".to_owned(),
            ));
        };
        let decision_history = load_run_history(store, run_id, maximum_events)?;
        if decision_history.cancellation_generation > 0 {
            return Ok(DecisionOutcome::Cancelled);
        }
        if deadline_elapsed(deadline) {
            return Ok(DecisionOutcome::Deadline);
        }
        let prompt_bytes = store.get_artifact(&prepared.prompt_artifact)?;
        let retained_prompt = serde_json::from_slice::<RetainedPrompt>(&prompt_bytes)
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
        if retained_prompt
            .compiled_prompt
            .manifest
            .content_sha256
            .as_bytes()
            != prepared.prompt_manifest_digest.as_str().as_bytes()
        {
            return Err(SupervisorRunError::CommittedArtifact(
                "retained prompt manifest digest mismatch".to_owned(),
            ));
        }
        let request_bytes = store.get_artifact(&prepared.request_artifact)?;
        let retained_request = serde_json::from_slice::<RetainedRequest>(&request_bytes)
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
        if retained_request.request.model_id().as_str().as_bytes()
            != prepared.backend_model.model_id.as_bytes()
            || u64::from(retained_request.request.max_output_tokens())
                != prepared.token_reservation.max_output_tokens
            || canonical_sha256(&retained_request.request)? != retained_request.request_sha256
        {
            return Err(SupervisorRunError::CommittedArtifact(
                "retained inference request does not match Prepared".to_owned(),
            ));
        }
        let evidence_bytes = store.get_artifact(&observed.normalized_complete_evidence_artifact)?;
        let retained_evidence =
            serde_json::from_slice::<RetainedInferenceEvidence>(&evidence_bytes)
                .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
        let RetainedInferenceEvidence::Response { response } = retained_evidence else {
            return Err(SupervisorRunError::CommittedArtifact(
                "successful observation lacks a retained complete response".to_owned(),
            ));
        };
        if !response_contract_violations(prepared, &response).is_empty() {
            return Err(SupervisorRunError::CommittedArtifact(
                "successful observation contains a response contract violation".to_owned(),
            ));
        }
        let normalized_usage = normalized_token_usage(&response).ok_or_else(|| {
            SupervisorRunError::CommittedArtifact("successful response lost token usage".to_owned())
        })?;
        if &normalized_usage != token_usage {
            return Err(SupervisorRunError::CommittedArtifact(
                "Observed token usage differs from retained response".to_owned(),
            ));
        }
        let parsed = serde_json::from_str::<serde_json::Value>(&response.raw_text)
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
        if parsed != response.value {
            return Err(SupervisorRunError::CommittedArtifact(
                "raw response differs from retained model value".to_owned(),
            ));
        }
        if matches!(
            &prepared.stage_context,
            Some(
                PlannerStageContext::InitialReview { .. } | PlannerStageContext::FinalReview { .. }
            )
        ) {
            return decide_semantic_review_in_store(
                store,
                &run,
                maximum_events,
                actor_id,
                prepared,
                &observed_event,
                &retained_prompt,
                &response,
                deadline,
            );
        }
        let proposal_artifact =
            persist_new_artifact(store, response.raw_text.as_bytes(), PROPOSAL_MEDIA_TYPE)?;
        let registry =
            builtin_registry().map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
        let decoded = registry.decode_output::<RootPlannerOutput>(
            &retained_prompt.compiled_prompt,
            &retained_prompt.prompt_invocation,
            response.raw_text.as_bytes(),
        );
        let proposal_id = PlanProposalId::new();
        match decoded {
            Ok(output) => {
                let validation = RetainedValidation {
                    status: "accepted",
                    violations: Vec::new(),
                };
                let validation_bytes = serde_json::to_vec(&validation)
                    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
                let validation_artifact =
                    persist_new_artifact(store, &validation_bytes, VALIDATION_MEDIA_TYPE)?;
                let accepted_bytes = serde_json::to_vec(&output)
                    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
                let accepted_plan_artifact =
                    persist_new_artifact(store, &accepted_bytes, PLAN_MEDIA_TYPE)?;
                let accepted_plan_digest =
                    Sha256Digest::parse(accepted_plan_artifact.sha256.clone())
                        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
                let accepted_plan_revision =
                    prepared.plan_revision.checked_add(1).ok_or_else(|| {
                        SupervisorRunError::InvalidState("plan revision overflow".to_owned())
                    })?;
                let event = NewEvent {
                    session_id: run.spec.session_id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(observed_event.id),
                    provenance: supervisor_provenance(Some(backend_selection_for_prepared(
                        prepared,
                        run.spec.backend.reasoning_effort.as_deref(),
                    ))),
                    payload: EventPayload::PlanProposalAccepted(PlanProposalAccepted {
                        proposal_id,
                        inference_attempt_id: prepared.attempt_id,
                        observed_event_id: observed_event.id,
                        proposal_artifact,
                        previous_plan_revision: prepared.plan_revision,
                        previous_plan_digest: prepared.plan_digest.clone(),
                        accepted_plan_revision,
                        accepted_plan_digest,
                        accepted_plan_artifact,
                        validation_evidence_artifact: validation_artifact,
                    }),
                };
                append_decision_or_cancel(
                    store,
                    run_id,
                    maximum_events,
                    event,
                    DecisionOutcome::Accepted,
                    deadline,
                )
            }
            Err(error) => {
                let reason = rejection_reason(&error);
                let validation = RetainedValidation {
                    status: "rejected",
                    violations: vec![error.to_string()],
                };
                let validation_bytes = serde_json::to_vec(&validation)
                    .map_err(|encode| SupervisorRunError::Contract(encode.to_string()))?;
                let validation_artifact =
                    persist_new_artifact(store, &validation_bytes, VALIDATION_MEDIA_TYPE)?;
                let event = NewEvent {
                    session_id: run.spec.session_id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(observed_event.id),
                    provenance: supervisor_provenance(Some(backend_selection_for_prepared(
                        prepared,
                        run.spec.backend.reasoning_effort.as_deref(),
                    ))),
                    payload: EventPayload::PlanProposalRejected(PlanProposalRejected {
                        proposal_id,
                        inference_attempt_id: prepared.attempt_id,
                        observed_event_id: observed_event.id,
                        proposal_artifact,
                        base_plan_revision: prepared.plan_revision,
                        base_plan_digest: prepared.plan_digest.clone(),
                        reason,
                        validation_evidence_artifact: validation_artifact,
                    }),
                };
                append_decision_or_cancel(
                    store,
                    run_id,
                    maximum_events,
                    event,
                    DecisionOutcome::Rejected,
                    deadline,
                )
            }
        }
    })
    .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the semantic receipt and decision are built from one exact observed response"
)]
fn decide_semantic_review_in_store(
    store: &mut Store,
    run: &Run,
    maximum_events: usize,
    actor_id: ActorId,
    prepared: &PlannerInferencePrepared,
    observed_event: &EventEnvelope,
    retained_prompt: &RetainedPrompt,
    response: &StructuredInferenceResponse,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<DecisionOutcome, SupervisorRunError> {
    let stage = prepared.stage_context.as_ref().ok_or_else(|| {
        SupervisorRunError::InvalidState("semantic review has no stage context".to_owned())
    })?;
    let (candidate, critic_policy_artifact, initial_review) = match stage {
        PlannerStageContext::InitialReview {
            candidate,
            critic_policy_artifact,
            ..
        } => (candidate.clone(), critic_policy_artifact, true),
        PlannerStageContext::FinalReview {
            candidate,
            critic_policy_artifact,
            ..
        } => (candidate.clone(), critic_policy_artifact, false),
        PlannerStageContext::InitialPlan { .. } | PlannerStageContext::Repair { .. } => {
            return Err(SupervisorRunError::InvalidState(
                "plan-producing stage reached semantic review decision".to_owned(),
            ));
        }
    };
    let critic_policy_bytes = store.get_artifact(critic_policy_artifact)?;
    let critic_policy = serde_json::from_slice::<PlanCriticPolicy>(&critic_policy_bytes)
        .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?;
    let registry =
        builtin_registry().map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let decoded = registry.decode_output::<PlanCriticOutput>(
        &retained_prompt.compiled_prompt,
        &retained_prompt.prompt_invocation,
        response.raw_text.as_bytes(),
    );
    let (critique_artifact, verdict, finding_ids) = match decoded {
        Ok(output) => {
            let bytes = serde_json::to_vec(&output)
                .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            let artifact = persist_new_artifact(store, &bytes, CRITIQUE_MEDIA_TYPE)?;
            let verdict = match output.verdict {
                PlanCriticVerdict::Accept => PlanSemanticReviewValidatedVerdict::Accept,
                PlanCriticVerdict::Revise => PlanSemanticReviewValidatedVerdict::Revise,
                PlanCriticVerdict::Clarify => PlanSemanticReviewValidatedVerdict::Clarify,
                PlanCriticVerdict::Escalate => PlanSemanticReviewValidatedVerdict::Escalate,
            };
            let finding_ids = output
                .findings
                .iter()
                .map(|finding| finding.finding_id.clone())
                .collect();
            (artifact, verdict, finding_ids)
        }
        Err(_) => (
            persist_new_artifact(store, response.raw_text.as_bytes(), CRITIQUE_MEDIA_TYPE)?,
            PlanSemanticReviewValidatedVerdict::ContractInvalid,
            Vec::new(),
        ),
    };
    let EventPayload::PlannerInferenceObserved(observed) = &observed_event.payload else {
        return Err(SupervisorRunError::InvalidState(
            "semantic review decision lacks Observed".to_owned(),
        ));
    };
    let receipt = PlanSemanticReviewValidationReceipt {
        schema_version: 1,
        inference_attempt_id: prepared.attempt_id,
        observed_event_id: observed_event.id,
        candidate: candidate.clone(),
        prompt_manifest_sha256: prepared.prompt_manifest_digest.clone(),
        prompt_artifact_sha256: Sha256Digest::parse(prepared.prompt_artifact.sha256.clone())
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?,
        request_artifact_sha256: Sha256Digest::parse(prepared.request_artifact.sha256.clone())
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?,
        normalized_evidence_sha256: Sha256Digest::parse(
            observed
                .normalized_complete_evidence_artifact
                .sha256
                .clone(),
        )
        .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?,
        critic_policy_sha256: Sha256Digest::parse(critic_policy.critic_policy_sha256.clone())
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?,
        critique_sha256: Sha256Digest::parse(critique_artifact.sha256.clone())
            .map_err(|error| SupervisorRunError::CommittedArtifact(error.to_string()))?,
        verdict,
        finding_ids: finding_ids.clone(),
    };
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let receipt_artifact =
        persist_new_artifact(store, &receipt_bytes, SEMANTIC_REVIEW_RECEIPT_MEDIA_TYPE)?;
    let review_id = PlanSemanticReviewId::new();
    let payload = match verdict {
        PlanSemanticReviewValidatedVerdict::Accept => {
            EventPayload::PlanSemanticReviewAccepted(PlanSemanticReviewAccepted {
                review_id,
                inference_attempt_id: prepared.attempt_id,
                observed_event_id: observed_event.id,
                candidate,
                critique_artifact,
                validation_evidence_artifact: receipt_artifact,
            })
        }
        PlanSemanticReviewValidatedVerdict::Revise if initial_review => {
            EventPayload::PlanSemanticReviewRejected(PlanSemanticReviewRejected {
                review_id,
                inference_attempt_id: prepared.attempt_id,
                observed_event_id: observed_event.id,
                candidate,
                critique_artifact,
                validation_evidence_artifact: receipt_artifact,
                disposition: PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized,
                required_finding_ids: finding_ids,
            })
        }
        PlanSemanticReviewValidatedVerdict::ContractInvalid => {
            EventPayload::PlanSemanticReviewRejected(PlanSemanticReviewRejected {
                review_id,
                inference_attempt_id: prepared.attempt_id,
                observed_event_id: observed_event.id,
                candidate,
                critique_artifact,
                validation_evidence_artifact: receipt_artifact,
                disposition: PlanSemanticReviewRejectionDisposition::ReviewContractInvalid,
                required_finding_ids: Vec::new(),
            })
        }
        PlanSemanticReviewValidatedVerdict::Revise
        | PlanSemanticReviewValidatedVerdict::Clarify
        | PlanSemanticReviewValidatedVerdict::Escalate => {
            EventPayload::PlanSemanticReviewRejected(PlanSemanticReviewRejected {
                review_id,
                inference_attempt_id: prepared.attempt_id,
                observed_event_id: observed_event.id,
                candidate,
                critique_artifact,
                validation_evidence_artifact: receipt_artifact,
                disposition: PlanSemanticReviewRejectionDisposition::TerminalReject,
                required_finding_ids: Vec::new(),
            })
        }
    };
    let outcome = if matches!(&payload, EventPayload::PlanSemanticReviewAccepted(_)) {
        DecisionOutcome::Accepted
    } else {
        DecisionOutcome::Rejected
    };
    append_decision_or_cancel(
        store,
        run.id,
        maximum_events,
        NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(observed_event.id),
            provenance: supervisor_provenance(Some(backend_selection_for_prepared(
                prepared,
                run.spec.backend.reasoning_effort.as_deref(),
            ))),
            payload,
        },
        outcome,
        deadline,
    )
}

fn append_decision_or_cancel(
    store: &mut Store,
    run_id: RunId,
    maximum_events: usize,
    event: NewEvent,
    success: DecisionOutcome,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<DecisionOutcome, SupervisorRunError> {
    if deadline_elapsed(deadline) {
        let history = load_run_history(store, run_id, maximum_events)?;
        return Ok(if history.cancellation_generation > 0 {
            DecisionOutcome::Cancelled
        } else {
            DecisionOutcome::Deadline
        });
    }
    let appended = match deadline {
        Some(deadline) => store.append_event_before_deadline(event, deadline),
        None => store
            .append_event(event)
            .map(|_| DeadlineAppendOutcome::Appended),
    };
    match appended {
        Ok(DeadlineAppendOutcome::Appended) => Ok(success),
        Ok(DeadlineAppendOutcome::DeadlineElapsed) => {
            let history = load_run_history(store, run_id, maximum_events)?;
            if history.cancellation_generation > 0 {
                Ok(DecisionOutcome::Cancelled)
            } else {
                Ok(DecisionOutcome::Deadline)
            }
        }
        Err(error) => {
            let history = load_run_history(store, run_id, maximum_events)?;
            if history.cancellation_generation > 0 {
                Ok(DecisionOutcome::Cancelled)
            } else {
                Err(error.into())
            }
        }
    }
}

async fn durable_cancellation_generation(
    paths: RuntimePaths,
    run_id: RunId,
    maximum_events: usize,
) -> Result<u64, SupervisorRunError> {
    store_phase(paths, move |store| {
        Ok(load_run_history(store, run_id, maximum_events)?.cancellation_generation)
    })
    .await
}

fn normalized_token_usage(response: &StructuredInferenceResponse) -> Option<TokenUsage> {
    let usage = response.usage.as_ref()?;
    Some(TokenUsage {
        input_tokens: usage.input_tokens?,
        output_tokens: usage.output_tokens?,
        total_tokens: usage.total_tokens?,
        cached_input_tokens: None,
    })
}

fn rejection_reason(error: &PromptError) -> PlanProposalRejectionReason {
    match classify_root_planner_rejection(error) {
        RootPlannerRejectionClass::InvalidSchema => PlanProposalRejectionReason::InvalidSchema,
        RootPlannerRejectionClass::ProtectedAuthorityMutation => {
            PlanProposalRejectionReason::ProtectedAuthorityMutation
        }
        RootPlannerRejectionClass::ObligationCoverageIncomplete => {
            PlanProposalRejectionReason::ObligationCoverageIncomplete
        }
        RootPlannerRejectionClass::DependencyCycle => PlanProposalRejectionReason::DependencyCycle,
        RootPlannerRejectionClass::PolicyLimitExceeded => {
            PlanProposalRejectionReason::PolicyLimitExceeded
        }
    }
}

async fn transition_run(
    paths: RuntimePaths,
    run_id: RunId,
    actor_id: ActorId,
    maximum_events: usize,
    target: RunState,
) -> Result<RunState, SupervisorRunError> {
    store_phase(paths, move |store| {
        transition_run_in_store(store, run_id, actor_id, maximum_events, target, || {})
    })
    .await
}

fn transition_run_in_store<BeforeFirstAppend>(
    store: &mut Store,
    run_id: RunId,
    actor_id: ActorId,
    maximum_events: usize,
    requested_target: RunState,
    before_first_append: BeforeFirstAppend,
) -> Result<RunState, SupervisorRunError>
where
    BeforeFirstAppend: FnOnce(),
{
    let mut before_first_append = Some(before_first_append);
    for attempt in 0..MAX_TRANSITION_APPEND_ATTEMPTS {
        let run = store
            .get_run(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState(format!("run {run_id} not found")))?;
        if is_terminal(run.state) {
            return Ok(run.state);
        }
        let history = load_run_history(store, run_id, maximum_events)?;
        let target = if history.cancellation_generation > 0 {
            RunState::Cancelled
        } else {
            requested_target
        };
        if run.state == target {
            return Ok(run.state);
        }
        if let Some(before_append) = before_first_append.take() {
            before_append();
        }
        let appended = store.append_event(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: history.last_event_id,
            provenance: supervisor_provenance(None),
            payload: EventPayload::RunStateChanged {
                from: run.state,
                to: target,
            },
        });
        match appended {
            Ok(_) => return Ok(target),
            Err(error) => {
                let refreshed = store.get_run(run_id)?.ok_or_else(|| {
                    SupervisorRunError::InvalidState(format!("run {run_id} disappeared"))
                })?;
                if is_terminal(refreshed.state) {
                    return Ok(refreshed.state);
                }
                let refreshed_history = load_run_history(store, run_id, maximum_events)?;
                let run_history_advanced = refreshed_history.last_event_id != history.last_event_id;
                if attempt + 1 < MAX_TRANSITION_APPEND_ATTEMPTS && run_history_advanced {
                    continue;
                }
                return Err(error.into());
            }
        }
    }
    Err(SupervisorRunError::Background(format!(
        "run {run_id} transition exhausted {MAX_TRANSITION_APPEND_ATTEMPTS} CAS attempts"
    )))
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<Sha256Digest, SupervisorRunError> {
    let value = serde_json::to_value(value)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let mut encoded = String::new();
    encode_canonical_json(&value, &mut encoded)?;
    let bytes = Sha256::digest(encoded.as_bytes());
    let mut hash = String::with_capacity(Sha256Digest::HEX_LENGTH);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut hash, "{byte:02x}")
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    }
    Sha256Digest::parse(hash).map_err(|error| SupervisorRunError::Contract(error.to_string()))
}

fn encode_canonical_json(
    value: &serde_json::Value,
    output: &mut String,
) -> Result<(), SupervisorRunError> {
    match value {
        serde_json::Value::Null => output.push_str("null"),
        serde_json::Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        serde_json::Value::Number(value) => output.push_str(&value.to_string()),
        serde_json::Value::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|error| SupervisorRunError::Contract(error.to_string()))?,
        ),
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                encode_canonical_json(value, output)?;
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            output.push('{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?,
                );
                output.push(':');
                encode_canonical_json(&values[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use birdcode_backends::{
        BackendFuture, BackendOperation, CapabilityState, DiscoveryEvidence, HttpEvidence,
        InferenceEvidence, LoadedInstance, ModelCapabilities, ModelDescriptor, ModelKind,
        NativeDiscoveryEvidence, NativeMatch,
    };
    use birdcode_prompting::{
        ObligationAssessment, ObligationAssessmentStatus, PlanCriticFinding,
        PlanCriticFindingCategory, PlanCriticFindingSeverity, PlanCriticOutput, PlanCriticPolicy,
        PlanCriticVerdict, ProposedVerificationTarget, RootPlannerDecisionEvidence,
        RootPlannerDirective, RootPlannerWorkOrder, VerificationKind,
    };
    use birdcode_protocol::{
        BackendSelection, CreateRunRequest, CreateSessionRequest, InputItem, ModelLineage,
        RootPlanningStageBudgets, RunLimits, RunPurpose, RunSpec,
    };
    use birdcode_runtime::LocalRuntime;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;
    use tempfile::TempDir;

    const BACKEND: &str = "test-model-backend";
    const MODEL: &str = "model/多言語-exact";
    const CRITIC_MODEL: &str = "model/independent-critic-exact";

    #[derive(Clone, Copy)]
    enum SemanticCriticMode {
        Accept,
        ReviseThenAccept,
        InvalidContract,
    }

    struct TestBackend {
        id: BackendId,
        model: ModelId,
        response: StructuredInferenceResponse,
        discovery_error: Option<BackendError>,
        inference_delay: Duration,
        discovery_delay: Duration,
        discovery_calls: AtomicUsize,
        inference_calls: AtomicUsize,
        critic_calls: AtomicUsize,
        semantic_critic: Option<SemanticCriticMode>,
        prepared_at_call: AtomicBool,
        prepared_probe: Option<(RuntimePaths, RunId)>,
    }

    impl TestBackend {
        fn new(response: StructuredInferenceResponse) -> Self {
            Self {
                id: BackendId::new(BACKEND).expect("test backend id is valid"),
                model: ModelId::new(MODEL).expect("test model id is valid"),
                response,
                discovery_error: None,
                inference_delay: Duration::ZERO,
                discovery_delay: Duration::ZERO,
                discovery_calls: AtomicUsize::new(0),
                inference_calls: AtomicUsize::new(0),
                critic_calls: AtomicUsize::new(0),
                semantic_critic: None,
                prepared_at_call: AtomicBool::new(false),
                prepared_probe: None,
            }
        }

        fn with_inference_delay(mut self, delay: Duration) -> Self {
            self.inference_delay = delay;
            self
        }

        fn with_discovery_delay(mut self, delay: Duration) -> Self {
            self.discovery_delay = delay;
            self
        }

        fn with_catalog_model(mut self, model: &str) -> Self {
            self.model = ModelId::new(model).expect("test catalog model id is valid");
            self
        }

        fn with_discovery_error(mut self) -> Self {
            self.discovery_error = Some(BackendError {
                backend_id: self.id.clone(),
                operation: BackendOperation::DiscoverOpenAiModels,
                kind: BackendErrorKind::Transport,
                message: "typed test discovery transport failure".to_owned(),
                evidence: None,
            });
            self
        }

        fn with_semantic_critic(mut self, mode: SemanticCriticMode) -> Self {
            self.semantic_critic = Some(mode);
            self
        }

        fn probe_prepared(mut self, paths: RuntimePaths, run_id: RunId) -> Self {
            self.prepared_probe = Some((paths, run_id));
            self
        }

        fn catalog(&self) -> ModelCatalog {
            let evidence = HttpEvidence {
                endpoint: "test://models".to_owned(),
                status: 200,
                response_body_sha256: "0".repeat(64),
                body: json!({"data": [{"id": MODEL}]}),
            };
            let descriptor = |id: ModelId, display_name: &str, instance_id: &str| ModelDescriptor {
                id,
                kind: ModelKind::Language,
                display_name: Some(display_name.to_owned()),
                publisher: None,
                architecture: None,
                load_state: ModelLoadState::Loaded,
                loaded_instances: vec![LoadedInstance {
                    id: instance_id.to_owned(),
                    context_length: Some(32_768),
                }],
                maximum_context_tokens: Some(32_768),
                quantization: None,
                capabilities: ModelCapabilities {
                    vision: CapabilityState::Unknown,
                    trained_for_tool_use: CapabilityState::Unknown,
                    reasoning: None,
                },
                native_match: NativeMatch::None,
            };
            let mut models = vec![descriptor(
                self.model.clone(),
                "Multilingual test model",
                "loaded-test-instance",
            )];
            if self.semantic_critic.is_some() {
                models.push(descriptor(
                    ModelId::new(CRITIC_MODEL).expect("critic model id is valid"),
                    "Independent critic test model",
                    "loaded-independent-critic",
                ));
            }
            ModelCatalog {
                backend_id: self.id.clone(),
                models,
                evidence: DiscoveryEvidence {
                    openai: evidence.clone(),
                    native: NativeDiscoveryEvidence::Available { response: evidence },
                },
            }
        }
    }

    impl ModelBackend for TestBackend {
        fn backend_id(&self) -> &BackendId {
            &self.id
        }

        fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
            self.discovery_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                tokio::time::sleep(self.discovery_delay).await;
                if let Some(error) = &self.discovery_error {
                    return Err(error.clone());
                }
                Ok(self.catalog())
            })
        }

        fn infer_structured(
            &self,
            request: StructuredInferenceRequest,
        ) -> BackendFuture<'_, StructuredInferenceResponse> {
            self.inference_calls.fetch_add(1, Ordering::SeqCst);
            if let Some((paths, run_id)) = &self.prepared_probe {
                let prepared = all_events(paths, *run_id).iter().any(|event| {
                    matches!(event.payload, EventPayload::PlannerInferencePrepared(_))
                });
                self.prepared_at_call.store(prepared, Ordering::SeqCst);
            }
            let response = if request.model_id().as_str() == CRITIC_MODEL {
                let call = self.critic_calls.fetch_add(1, Ordering::SeqCst);
                match self.semantic_critic {
                    Some(SemanticCriticMode::ReviseThenAccept) if call == 0 => {
                        semantic_critic_response(&request, PlanCriticVerdict::Revise)
                    }
                    Some(SemanticCriticMode::Accept | SemanticCriticMode::ReviseThenAccept) => {
                        semantic_critic_response(&request, PlanCriticVerdict::Accept)
                    }
                    Some(SemanticCriticMode::InvalidContract) => response_for_value(
                        json!({"schema_version": 1, "verdict": "accept"}),
                        CRITIC_MODEL,
                    ),
                    None => {
                        return Box::pin(async {
                            panic!("critic inference was invoked without a configured test critic")
                        });
                    }
                }
            } else {
                self.response.clone()
            };
            Box::pin(async move {
                tokio::time::sleep(self.inference_delay).await;
                Ok(response)
            })
        }
    }

    struct Fixture {
        _directory: TempDir,
        paths: RuntimePaths,
        run: Run,
    }

    fn fixture(input: &str, max_wall_time_seconds: Option<u64>) -> Fixture {
        fixture_with_max_output(input, max_wall_time_seconds, 512)
    }

    fn fixture_with_max_output(
        input: &str,
        max_wall_time_seconds: Option<u64>,
        max_output_tokens: u64,
    ) -> Fixture {
        let directory = TempDir::new().expect("test directory is created");
        let paths = RuntimePaths::new(directory.path());
        paths.prepare().expect("runtime paths are prepared");
        let store = Store::open(paths.database(), paths.artifacts()).expect("store opens");
        let mut runtime = LocalRuntime::new(store);
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/BirdCode flerspråkig 日本語").into(),
                title: Some("Agentisk planering".to_owned()),
            })
            .expect("session persists");
        let run = runtime
            .create_run(CreateRunRequest {
                run_id: RunId::new(),
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::PlanOnly,
                    plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
                    backend: BackendSelection {
                        backend_id: BACKEND.to_owned(),
                        kind: BackendKind::Model,
                        model: Some(MODEL.to_owned()),
                        reasoning_effort: None,
                    },
                    input: vec![InputItem::Text {
                        text: input.to_owned(),
                    }],
                    limits: RunLimits {
                        max_output_tokens: Some(max_output_tokens),
                        max_wall_time_seconds,
                        max_subagents: 0,
                    },
                },
            })
            .expect("run persists");
        drop(runtime);
        migrate_test_runs_through_protocol_v4(&paths);
        let run = Store::open(paths.database(), paths.artifacts())
            .expect("migrated test store opens")
            .get_run(run.id)
            .expect("migrated test run reads")
            .expect("migrated test run exists");
        Fixture {
            _directory: directory,
            paths,
            run,
        }
    }

    fn semantic_fixture(input: &str) -> Fixture {
        semantic_fixture_with_reasoning(input, None)
    }

    fn semantic_fixture_with_reasoning(input: &str, reasoning_effort: Option<&str>) -> Fixture {
        let directory = TempDir::new().expect("test directory is created");
        let paths = RuntimePaths::new(directory.path());
        paths.prepare().expect("runtime paths are prepared");
        let store = Store::open(paths.database(), paths.artifacts()).expect("store opens");
        let mut runtime = LocalRuntime::new(store);
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/BirdCode semantic review 日本語").into(),
                title: Some("Oberoende semantisk planering".to_owned()),
            })
            .expect("session persists");
        let policy = semantic_test_policy();
        let aggregate = [
            policy.stage_budgets.initial_plan_output_tokens,
            policy.stage_budgets.initial_review_output_tokens,
            policy.stage_budgets.repair_output_tokens,
            policy.stage_budgets.final_review_output_tokens,
        ]
        .into_iter()
        .sum();
        let run = runtime
            .create_run(CreateRunRequest {
                run_id: RunId::new(),
                spec: RunSpec {
                    session_id: session.id,
                    purpose: RunPurpose::PlanOnly,
                    plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
                    backend: BackendSelection {
                        backend_id: BACKEND.to_owned(),
                        kind: BackendKind::Model,
                        model: Some(MODEL.to_owned()),
                        reasoning_effort: reasoning_effort.map(str::to_owned),
                    },
                    input: vec![InputItem::Text {
                        text: input.to_owned(),
                    }],
                    limits: RunLimits {
                        max_output_tokens: Some(aggregate),
                        max_wall_time_seconds: None,
                        max_subagents: 0,
                    },
                },
            })
            .expect("semantic run persists");
        Fixture {
            _directory: directory,
            paths,
            run,
        }
    }

    fn persist_plan_runs(paths: &RuntimePaths, count: usize) -> Vec<Run> {
        let store = Store::open(paths.database(), paths.artifacts()).expect("store opens");
        let mut runtime = LocalRuntime::new(store);
        let session = runtime
            .create_session(CreateSessionRequest {
                workspace_root: PathBuf::from("/tmp/BirdCode durable dispatch").into(),
                title: Some("Durable dispatch regression".to_owned()),
            })
            .expect("session persists");
        let runs = (0..count)
            .map(|index| {
                runtime
                    .create_run(CreateRunRequest {
                        run_id: RunId::new(),
                        spec: RunSpec {
                            session_id: session.id,
                            purpose: RunPurpose::PlanOnly,
                            plan_acceptance:
                                PlanAcceptanceContract::IndependentSemanticReviewV1,
                            backend: BackendSelection {
                                backend_id: BACKEND.to_owned(),
                                kind: BackendKind::Model,
                                model: Some(MODEL.to_owned()),
                                reasoning_effort: None,
                            },
                            input: vec![InputItem::Text {
                                text: format!(
                                    "Planera durable dispatch-arbetsorder {index} på svenska och 日本語。"
                                ),
                            }],
                            limits: RunLimits {
                                max_output_tokens: Some(512),
                                max_wall_time_seconds: None,
                                max_subagents: 0,
                            },
                        },
                    })
                    .expect("run persists")
            })
            .collect::<Vec<_>>();
        drop(runtime);
        migrate_test_runs_through_protocol_v4(paths);
        let store = Store::open(paths.database(), paths.artifacts()).expect("migrated store opens");
        runs.into_iter()
            .map(|run| {
                store
                    .get_run(run.id)
                    .expect("migrated run reads")
                    .expect("migrated run exists")
            })
            .collect()
    }

    /// Existing single-turn supervisor tests intentionally exercise replay of
    /// historical protocol-v4 runs. They must cross the real v7→v8 store
    /// boundary instead of constructing the forbidden legacy contract through
    /// a current create API.
    fn migrate_test_runs_through_protocol_v4(paths: &RuntimePaths) {
        let connection =
            rusqlite::Connection::open(paths.database()).expect("protocol-v4 test database opens");
        connection
            .execute_batch(
                "DROP TRIGGER events_are_immutable_on_update;
                 DROP TRIGGER events_are_immutable_on_delete;
                 UPDATE runs
                    SET value_json = json_remove(value_json, '$.spec.plan_acceptance');
                 UPDATE events
                    SET value_json = json_remove(
                        value_json,
                        '$.payload.data.run.spec.plan_acceptance'
                    );
                 CREATE TRIGGER events_are_immutable_on_update
                 BEFORE UPDATE ON events BEGIN
                     SELECT RAISE(ABORT, 'events are immutable');
                 END;
                 CREATE TRIGGER events_are_immutable_on_delete
                 BEFORE DELETE ON events BEGIN
                     SELECT RAISE(ABORT, 'events are immutable');
                 END;",
            )
            .expect("test history loses the post-v4 field and restores immutability");
        connection
            .pragma_update(None, "user_version", 7_i64)
            .expect("test database is marked as schema v7");
        drop(connection);
        drop(
            Store::open(paths.database(), paths.artifacts())
                .expect("protocol-v4 test history migrates through schema v8"),
        );
    }

    fn valid_response(paths: &RuntimePaths, run_id: RunId) -> StructuredInferenceResponse {
        valid_response_with_usage(paths, run_id, 512, 40, 60)
    }

    fn valid_response_with_usage(
        paths: &RuntimePaths,
        run_id: RunId,
        max_output_tokens: u32,
        input_tokens: u64,
        output_tokens: u64,
    ) -> StructuredInferenceResponse {
        let store = Store::open(paths.database(), paths.artifacts()).expect("store opens");
        let run = store
            .get_run(run_id)
            .expect("run read succeeds")
            .expect("run exists");
        let session = store
            .get_session(run.spec.session_id)
            .expect("session read succeeds")
            .expect("session exists");
        let Ok(reasoning) = parse_reasoning(run.spec.backend.reasoning_effort.as_deref()) else {
            panic!("fixture reasoning should be a supported typed setting")
        };
        let compiled = compile_root_plan_request(
            &session,
            &run,
            ModelId::new(MODEL).expect("model id is valid"),
            max_output_tokens,
            reasoning,
        )
        .expect("root request compiles");
        let obligation_refs = compiled
            .root_planner_policy
            .obligations
            .iter()
            .filter(|obligation| obligation.mandatory)
            .map(birdcode_prompting::ProtectedObligation::reference)
            .collect::<Vec<_>>();
        let output = RootPlannerOutput {
            schema_version: 1,
            root_snapshot_sha256: compiled.root_planner_policy.root_snapshot_sha256.clone(),
            planner_policy_sha256: compiled.root_planner_policy.planner_policy_sha256.clone(),
            context_manifest_sha256: compiled.root_planner_policy.context_manifest_sha256.clone(),
            directive: RootPlannerDirective::Plan,
            rationale: "Dela upp målet i en verifierbar arbetsorder utan språkheuristik。"
                .to_owned(),
            decision_evidence: vec![RootPlannerDecisionEvidence {
                section: "run_input".to_owned(),
                basis: "Det fullständiga skyddade användarmålet styr planen。".to_owned(),
            }],
            work_orders: vec![RootPlannerWorkOrder {
                local_id: "implement-agent-kernel".to_owned(),
                objective: "Bygg den agentiska kärnan och verifiera dess faktiska beteende。"
                    .to_owned(),
                obligation_refs: obligation_refs.clone(),
                depends_on: Vec::new(),
                proposed_verification_targets: vec![ProposedVerificationTarget {
                    kind: VerificationKind::RepositoryFile,
                    selector: "Cargo.toml".to_owned(),
                    question: "Bygger den deklarerade arbetsytan och uppfylls målet?".to_owned(),
                    obligation_refs,
                }],
            }],
            clarification_questions: Vec::new(),
            escalation_requests: Vec::new(),
        };
        let value = serde_json::to_value(output).expect("output serializes");
        builtin_registry()
            .expect("builtin registry loads")
            .validate_output(
                &compiled.compiled_prompt,
                &compiled.prompt_invocation,
                &value,
            )
            .expect("test planner output satisfies the retained contract");
        response_for_value_with_usage(value, MODEL, input_tokens, output_tokens)
    }

    fn response_for_value(value: serde_json::Value, model: &str) -> StructuredInferenceResponse {
        response_for_value_with_usage(value, model, 40, 60)
    }

    fn response_for_value_with_usage(
        value: serde_json::Value,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> StructuredInferenceResponse {
        StructuredInferenceResponse {
            model_id: ModelId::new(model).expect("model id is valid"),
            raw_text: serde_json::to_string(&value).expect("response serializes"),
            value,
            finish_reason: Some("stop".to_owned()),
            usage: Some(birdcode_backends::TokenUsage {
                input_tokens: Some(input_tokens),
                output_tokens: Some(output_tokens),
                total_tokens: Some(
                    input_tokens
                        .checked_add(output_tokens)
                        .expect("test token usage fits u64"),
                ),
            }),
            evidence: InferenceEvidence {
                backend_id: BackendId::new(BACKEND).expect("backend id is valid"),
                endpoint: "test://inference".to_owned(),
                status: 200,
                completion_id: Some("completion-test".to_owned()),
                response_body_sha256: Some("0".repeat(Sha256Digest::HEX_LENGTH)),
                raw_response: json!({"complete": true}),
            },
        }
    }

    fn semantic_critic_response(
        request: &StructuredInferenceRequest,
        verdict: PlanCriticVerdict,
    ) -> StructuredInferenceResponse {
        assert_eq!(request.output().name(), "birdcode_plan_semantic_critic_v1");
        let policy = request
            .messages()
            .iter()
            .filter_map(|message| serde_json::from_str::<serde_json::Value>(&message.content).ok())
            .find_map(|value| value.pointer("/constraints/0/payload").cloned())
            .and_then(|value| serde_json::from_value::<PlanCriticPolicy>(value).ok())
            .expect("critic request contains the typed runtime policy");
        let work_order_id = policy
            .candidate_work_order_ids
            .first()
            .expect("semantic candidate contains a work order")
            .clone();
        let obligation_assessments = policy
            .obligations
            .iter()
            .map(|obligation| ObligationAssessment {
                obligation_ref: obligation.reference(),
                status: if verdict == PlanCriticVerdict::Accept {
                    ObligationAssessmentStatus::Addressed
                } else {
                    ObligationAssessmentStatus::Partial
                },
                basis: "Den exakta kandidaten granskades mot den skyddade förpliktelsen。"
                    .to_owned(),
                affected_work_order_ids: vec![work_order_id.clone()],
            })
            .collect();
        let findings = if verdict == PlanCriticVerdict::Revise {
            vec![PlanCriticFinding {
                finding_id: "finding-independent-review".to_owned(),
                severity: PlanCriticFindingSeverity::Major,
                category: PlanCriticFindingCategory::IndependentReview,
                statement: "Kandidaten behöver en verifierbar ersättningsplan。".to_owned(),
                source_sections: vec!["run_input".to_owned(), "candidate_plan".to_owned()],
                affected_work_order_ids: vec![work_order_id],
                required_change: "Leverera en komplett ersättningsplan för ny oberoende review。"
                    .to_owned(),
            }]
        } else {
            Vec::new()
        };
        let output = PlanCriticOutput {
            schema_version: 1,
            bindings: policy.bindings(),
            verdict,
            summary: "Oberoende, typad semantisk granskning är slutförd。".to_owned(),
            obligation_assessments,
            findings,
            clarification_questions: Vec::new(),
            escalation_requests: Vec::new(),
            decision_evidence: vec![RootPlannerDecisionEvidence {
                section: "run_input".to_owned(),
                basis: "Hela den skyddade flerspråkiga inmatningen användes som grund。".to_owned(),
            }],
        };
        response_for_value_with_usage(
            serde_json::to_value(output).expect("critic output serializes"),
            CRITIC_MODEL,
            40,
            60,
        )
    }

    fn semantic_test_policy() -> RootPlanningExecutionPolicy {
        crate::model_policy::TrustedRootPlanningPolicyConfig {
            schema_version: crate::model_policy::ROOT_PLANNING_POLICY_SCHEMA_VERSION,
            producer: ModelLineage {
                backend_id: BACKEND.to_owned(),
                model_id: MODEL.to_owned(),
                deployment_id: "producer-deployment-test".to_owned(),
                independence_domain_id: "producer-domain-test".to_owned(),
            },
            critic: ModelLineage {
                backend_id: BACKEND.to_owned(),
                model_id: CRITIC_MODEL.to_owned(),
                deployment_id: "critic-deployment-test".to_owned(),
                independence_domain_id: "critic-domain-test".to_owned(),
            },
            max_model_calls: crate::model_policy::ROOT_PLANNING_MAX_MODEL_CALLS,
            max_repairs: crate::model_policy::ROOT_PLANNING_MAX_REPAIRS,
            max_review_rounds: crate::model_policy::ROOT_PLANNING_MAX_REVIEW_ROUNDS,
            stage_budgets: RootPlanningStageBudgets {
                initial_plan_output_tokens: 512,
                initial_review_output_tokens: 256,
                repair_output_tokens: 512,
                final_review_output_tokens: 256,
            },
        }
        .compile()
        .expect("semantic test policy compiles")
    }

    fn semantic_test_models() -> ResolvedSemanticModels {
        ResolvedSemanticModels {
            producer: ResolvedSemanticModel {
                model_id: ModelId::new(MODEL).expect("producer model id is valid"),
                total_token_budget: 32_768,
                reasoning: None,
            },
            critic: ResolvedSemanticModel {
                model_id: ModelId::new(CRITIC_MODEL).expect("critic model id is valid"),
                total_token_budget: 32_768,
                reasoning: None,
            },
        }
    }

    fn test_config() -> RunSupervisorConfig {
        RunSupervisorConfig {
            claim_lease: Duration::from_secs(2),
            discovery_timeout: Duration::from_millis(250),
            ..RunSupervisorConfig::default()
        }
    }

    fn semantic_test_config() -> RunSupervisorConfig {
        RunSupervisorConfig {
            root_planning_policy: Some(semantic_test_policy()),
            ..test_config()
        }
    }

    fn all_events(paths: &RuntimePaths, run_id: RunId) -> Vec<EventEnvelope> {
        let store = Store::open(paths.database(), paths.artifacts()).expect("store opens");
        let mut events = Vec::new();
        let mut cursor = 0;
        loop {
            let page = store
                .events_for_run_after(run_id, cursor)
                .expect("events replay");
            events.extend(page.events);
            cursor = page.next_sequence;
            if !page.has_more {
                return events;
            }
        }
    }

    fn artifact_disk_path(paths: &RuntimePaths, artifact: &ArtifactRef) -> PathBuf {
        paths
            .artifacts()
            .join(&artifact.sha256[..2])
            .join(&artifact.sha256)
    }

    fn assert_overreported_observation(
        paths: &RuntimePaths,
        run_id: RunId,
        expected_response: &StructuredInferenceResponse,
    ) {
        let events = all_events(paths, run_id);
        let (prepared_event_id, prepared) = events
            .iter()
            .find_map(|event| match &event.payload {
                EventPayload::PlannerInferencePrepared(prepared) => Some((event.id, prepared)),
                _ => None,
            })
            .expect("Prepared is durable before the provider call");
        let (observed_event, observed) = events
            .iter()
            .find_map(|event| match &event.payload {
                EventPayload::PlannerInferenceObserved(observed) => Some((event, observed)),
                _ => None,
            })
            .expect("the provider result is durably observed");
        assert_eq!(observed.prepared_event_id, prepared_event_id);
        assert_eq!(observed.attempt_id, prepared.attempt_id);
        assert_eq!(observed.token_reservation_id, prepared.token_reservation.id);
        assert!(matches!(
            observed.outcome,
            PlannerInferenceObservation::Failed {
                error: PlannerInferenceError {
                    kind: PlannerInferenceErrorKind::ProtocolViolation,
                    retry: RetryDisposition::Never,
                },
            }
        ));
        assert_eq!(
            observed_event.provenance.raw_artifact.as_ref(),
            Some(&observed.normalized_complete_evidence_artifact)
        );
        assert!(!events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlannerInferenceOutcomeUnknown(_)
        )));

        let store = Store::open(paths.database(), paths.artifacts()).expect("store reopens");
        let evidence = store
            .get_artifact(&observed.normalized_complete_evidence_artifact)
            .expect("content-addressed response evidence verifies");
        let retained: RetainedInferenceEvidence =
            serde_json::from_slice(&evidence).expect("typed response evidence decodes");
        let RetainedInferenceEvidence::Response { response } = retained else {
            panic!("protocol violation must retain the exact provider response");
        };
        assert_eq!(&response, expected_response);
        assert_eq!(
            response.usage.as_ref().and_then(|usage| usage.total_tokens),
            Some(32_769)
        );
        assert_eq!(
            response.evidence.response_body_sha256,
            Some("0".repeat(Sha256Digest::HEX_LENGTH))
        );
        assert_eq!(response.evidence.raw_response, json!({"complete": true}));
        assert!(
            response
                .usage
                .as_ref()
                .and_then(|usage| usage.total_tokens)
                .is_some_and(|total| total > prepared.token_reservation.reserved_tokens)
        );
    }

    fn wait_for_completion(
        supervisor: &RunSupervisor,
        run_id: RunId,
        timeout: Duration,
    ) -> RunCompletion {
        let started = Instant::now();
        loop {
            if let Some(RunSupervisorEvent::Finished {
                run_id: finished_run_id,
                completion,
            }) = supervisor.try_next_event()
                && finished_run_id == run_id
            {
                return completion;
            }
            assert!(
                started.elapsed() < timeout,
                "restart did not replay the terminal observation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_root_failure_evidence(
        paths: &RuntimePaths,
        run_id: RunId,
        expected_phase: RootPlanningFailurePhase,
        expected_reason: RootPlanningFailureReason,
    ) {
        let events = all_events(paths, run_id);
        let failure_event = events
            .iter()
            .find(|event| matches!(event.payload, EventPayload::RootPlanningFailed(_)))
            .expect("typed root-planning failure should be durable");
        let EventPayload::RootPlanningFailed(failure) = &failure_event.payload else {
            panic!("failure event should retain its typed payload")
        };
        assert_eq!(failure.phase, expected_phase);
        assert_eq!(failure.reason, expected_reason);
        assert_eq!(
            failure_event.provenance.raw_artifact.as_ref(),
            Some(&failure.evidence_artifact)
        );
        let failed_transition = events
            .iter()
            .find(|event| {
                matches!(
                    event.payload,
                    EventPayload::RunStateChanged {
                        to: RunState::Failed,
                        ..
                    }
                )
            })
            .expect("Failed transition should follow typed failure provenance");
        assert!(failure_event.sequence < failed_transition.sequence);

        let store = Store::open(paths.database(), paths.artifacts()).expect("store opens");
        let bytes = store
            .get_artifact(&failure.evidence_artifact)
            .expect("failure evidence should pass content-address verification");
        let digest = Sha256::digest(&bytes);
        let mut actual_hash = String::with_capacity(Sha256Digest::HEX_LENGTH);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut actual_hash, "{byte:02x}").expect("writing to a String cannot fail");
        }
        assert_eq!(actual_hash, failure.evidence_artifact.sha256);
        let retained: RetainedRootPlanningFailure =
            serde_json::from_slice(&bytes).expect("typed failure evidence should decode");
        assert_eq!(retained.run_id, run_id);
        assert_eq!(retained.claim_event_id, failure.claim_event_id);
        assert_eq!(retained.claim_id, failure.claim_id);
        assert_eq!(retained.phase, expected_phase);
        assert_eq!(retained.reason, expected_reason);
        assert_eq!(retained.model_subject, failure.model_subject);
        let expected_backend = failure.model_subject.as_ref().map_or_else(
            || {
                store
                    .get_run(run_id)
                    .expect("run reads")
                    .expect("run exists")
                    .spec
                    .backend
            },
            |subject| backend_selection_for_lineage(&subject.lineage, None),
        );
        assert_eq!(failure_event.provenance.backend, Some(expected_backend));
    }

    fn wait_for_state(paths: &RuntimePaths, run_id: RunId, expected: RunState, timeout: Duration) {
        let started = Instant::now();
        loop {
            let store = Store::open(paths.database(), paths.artifacts()).expect("store opens");
            let state = store
                .get_run(run_id)
                .expect("run read succeeds")
                .expect("run exists")
                .state;
            if state == expected {
                return;
            }
            assert!(
                started.elapsed() < timeout,
                "run did not reach {expected:?}; current state is {state:?}; events: {:#?}",
                all_events(paths, run_id)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn persist_plan_decision(
        fixture: &Fixture,
        config: &RunSupervisorConfig,
        response: StructuredInferenceResponse,
    ) -> DecisionOutcome {
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                ResolvedModel {
                    model_id: ModelId::new(MODEL).expect("model id is valid"),
                    max_output_tokens: 512,
                    total_token_budget: 32_768,
                    reasoning: None,
                },
                None,
            )
            .await
            .expect("prepare succeeds") else {
                panic!("expected a prepared phase");
            };
            let observed = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response),
            )
            .await
            .expect("observation persists");
            decide_observed(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                config.max_recovery_events,
                observed.prepared,
                observed.observed,
                None,
            )
            .await
            .expect("plan decision persists")
        })
    }

    fn persist_semantic_initial_candidate(
        fixture: &Fixture,
        config: &RunSupervisorConfig,
        response: StructuredInferenceResponse,
    ) -> ObservedPair {
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("semantic claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialPlan,
                None,
            )
            .await
            .expect("semantic initial plan prepares") else {
                panic!("expected a prepared semantic producer call");
            };
            let observed = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response),
            )
            .await
            .expect("semantic producer observation persists");
            assert_eq!(
                decide_observed(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.actor_id,
                    config.max_recovery_events,
                    observed.prepared.clone(),
                    observed.observed.clone(),
                    None,
                )
                .await
                .expect("semantic producer decision persists"),
                DecisionOutcome::Accepted
            );
            observed
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture persists each closed semantic stage explicitly for recovery tests"
    )]
    fn persist_semantic_prefix_before(
        fixture: &Fixture,
        config: &RunSupervisorConfig,
        next_stage: RootPlanningStage,
    ) -> ArtifactRef {
        assert!(matches!(
            next_stage,
            RootPlanningStage::InitialReview
                | RootPlanningStage::Repair
                | RootPlanningStage::FinalReview
        ));
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let initial = persist_semantic_initial_candidate(fixture, config, plan.clone());
        let EventPayload::PlannerInferencePrepared(PlannerInferencePrepared {
            stage_context:
                Some(PlannerStageContext::InitialPlan {
                    execution_policy_artifact,
                    ..
                }),
            ..
        }) = &initial.prepared.payload
        else {
            panic!("semantic prefix must begin with InitialPlan Prepared");
        };
        let execution_policy_artifact = execution_policy_artifact.clone();
        if next_stage == RootPlanningStage::InitialReview {
            return execution_policy_artifact;
        }

        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            let PreparePhase::Prepared(review) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialReview,
                None,
            )
            .await
            .expect("initial review prepares") else {
                panic!("expected InitialReview Prepared");
            };
            let review_response =
                semantic_critic_response(&review.request, PlanCriticVerdict::Revise);
            let review_observed = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                review.event,
                Ok(review_response),
            )
            .await
            .expect("initial review observation persists");
            assert_eq!(
                decide_observed(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.actor_id,
                    config.max_recovery_events,
                    review_observed.prepared,
                    review_observed.observed,
                    None,
                )
                .await
                .expect("initial review decision persists"),
                DecisionOutcome::Rejected
            );
            if next_stage == RootPlanningStage::Repair {
                return;
            }

            let PreparePhase::Prepared(repair) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::Repair,
                None,
            )
            .await
            .expect("repair prepares") else {
                panic!("expected Repair Prepared");
            };
            let repair_observed = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                repair.event,
                Ok(plan),
            )
            .await
            .expect("repair observation persists");
            assert_eq!(
                decide_observed(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.actor_id,
                    config.max_recovery_events,
                    repair_observed.prepared,
                    repair_observed.observed,
                    None,
                )
                .await
                .expect("repair decision persists"),
                DecisionOutcome::Accepted
            );
        });
        execution_policy_artifact
    }

    #[test]
    fn semantic_plan_requires_explicit_trusted_policy_before_any_provider_access() {
        let fixture = semantic_fixture(
            "Planera på svenska och 日本語 utan att härleda reviewer-identitet från text.",
        );
        let backend = Arc::new(TestBackend::new(valid_response_with_usage(
            &fixture.paths,
            fixture.run.id,
            512,
            40,
            60,
        )));
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
                .expect("supervisor starts without inventing a policy");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        assert_root_failure_evidence(
            &fixture.paths,
            fixture.run.id,
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidRunConfiguration,
        );
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn unavailable_independent_critic_fails_before_the_producer_is_called() {
        let fixture = semantic_fixture(
            "Kräv en verkligt oberoende review innan producenten får generera planen.",
        );
        let backend = Arc::new(TestBackend::new(valid_response_with_usage(
            &fixture.paths,
            fixture.run.id,
            512,
            40,
            60,
        )));
        let supervisor = RunSupervisor::start(
            fixture.paths.clone(),
            backend.clone(),
            semantic_test_config(),
        )
        .expect("supervisor starts with a trusted policy");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        assert!(
            !all_events(&fixture.paths, fixture.run.id)
                .iter()
                .any(|event| matches!(event.payload, EventPayload::PlannerInferencePrepared(_)))
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let failure_event = events
            .iter()
            .find(|event| matches!(event.payload, EventPayload::RootPlanningFailed(_)))
            .expect("typed critic discovery failure persists");
        let EventPayload::RootPlanningFailed(failure) = &failure_event.payload else {
            panic!("expected a typed root planning failure");
        };
        assert_eq!(
            failure.model_subject,
            Some(RootPlanningModelSubject {
                role: RootPlanningModelRole::IndependentCritic,
                lineage: semantic_test_policy().critic,
            })
        );
        assert_eq!(
            failure_event.provenance.backend,
            Some(backend_selection_for_lineage(
                &failure
                    .model_subject
                    .as_ref()
                    .expect("critic subject is explicit")
                    .lineage,
                None,
            ))
        );
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn later_discovery_names_a_missing_producer_without_guessing_from_review_stage() {
        let fixture = semantic_fixture(
            "Behåll producentens exakta lineage när reviewstadiet återupptas efter restart.",
        );
        let config = semantic_test_config();
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        persist_semantic_initial_candidate(&fixture, &config, plan.clone());
        let backend = Arc::new(
            TestBackend::new(plan)
                .with_catalog_model("model/other-loaded-producer")
                .with_semantic_critic(SemanticCriticMode::Accept),
        );
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("replacement semantic supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(3),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let failure_event = events
            .iter()
            .find(|event| matches!(event.payload, EventPayload::RootPlanningStageFailed(_)))
            .expect("later producer discovery failure persists");
        let EventPayload::RootPlanningStageFailed(failure) = &failure_event.payload else {
            panic!("expected a typed stage failure");
        };
        assert_eq!(failure.failed_stage, RootPlanningStage::InitialReview);
        assert_eq!(
            failure.reason,
            RootPlanningStageFailureReason::SelectedModelUnavailable
        );
        assert_eq!(
            failure.model_subject,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::Producer,
                lineage: semantic_test_policy().producer,
            }
        );
        assert_eq!(
            failure_event.provenance.backend,
            Some(backend_selection_for_lineage(
                &failure.model_subject.lineage,
                None,
            ))
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("semantic supervisor joins");
    }

    #[test]
    fn later_discovery_names_a_missing_critic_without_guessing_from_review_stage() {
        let fixture = semantic_fixture(
            "Behåll kritikerns exakta lineage när reviewstadiet återupptas efter restart.",
        );
        let config = semantic_test_config();
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        persist_semantic_initial_candidate(&fixture, &config, plan.clone());
        let backend = Arc::new(TestBackend::new(plan));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("replacement semantic supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(3),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let failure_event = events
            .iter()
            .find(|event| matches!(event.payload, EventPayload::RootPlanningStageFailed(_)))
            .expect("later critic discovery failure persists");
        let EventPayload::RootPlanningStageFailed(failure) = &failure_event.payload else {
            panic!("expected a typed stage failure");
        };
        assert_eq!(failure.failed_stage, RootPlanningStage::InitialReview);
        assert_eq!(
            failure.reason,
            RootPlanningStageFailureReason::IndependentReviewerUnavailable
        );
        assert_eq!(
            failure.model_subject,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::IndependentCritic,
                lineage: semantic_test_policy().critic,
            }
        );
        assert_eq!(
            failure_event.provenance.backend,
            Some(backend_selection_for_lineage(
                &failure.model_subject.lineage,
                None,
            ))
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("semantic supervisor joins");
    }

    #[test]
    fn semantic_direct_accept_uses_two_bound_independent_calls() {
        let fixture = semantic_fixture(
            "Skapa en robust plan och låt en separat modell bedöma hela innebörden.",
        );
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let backend =
            Arc::new(TestBackend::new(plan).with_semantic_critic(SemanticCriticMode::Accept));
        let supervisor = RunSupervisor::start(
            fixture.paths.clone(),
            backend.clone(),
            semantic_test_config(),
        )
        .expect("semantic supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Completed,
            Duration::from_secs(3),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let stages = events
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::PlannerInferencePrepared(prepared) => prepared.stage_context.as_ref(),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(stages.len(), 2);
        assert!(matches!(
            stages[0],
            PlannerStageContext::InitialPlan {
                critic_lineage,
                ..
            } if critic_lineage == &semantic_test_policy().critic
        ));
        assert!(matches!(
            stages[1],
            PlannerStageContext::InitialReview { .. }
        ));
        assert!(
            events
                .iter()
                .any(|event| matches!(event.payload, EventPayload::PlanSemanticReviewAccepted(_)))
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 2);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn semantic_high_reasoning_is_bound_to_every_inference_and_decision_event() {
        let fixture = semantic_fixture_with_reasoning(
            "Bind high reasoning exakt genom producent, oberoende kritiker och beslut.",
            Some("high"),
        );
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let backend =
            Arc::new(TestBackend::new(plan).with_semantic_critic(SemanticCriticMode::Accept));
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend, semantic_test_config())
                .expect("high-reasoning semantic supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Completed,
            Duration::from_secs(3),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let store = Store::open(fixture.paths.database(), fixture.paths.artifacts())
            .expect("high-reasoning store reopens");
        let mut prepared_count = 0;
        let mut observed_count = 0;
        let mut decision_count = 0;
        for event in &events {
            match &event.payload {
                EventPayload::PlannerInferencePrepared(prepared) => {
                    prepared_count += 1;
                    assert_eq!(
                        event.provenance.backend,
                        Some(BackendSelection {
                            backend_id: prepared.backend_model.backend_id.clone(),
                            kind: prepared.backend_model.kind,
                            model: Some(prepared.backend_model.model_id.clone()),
                            reasoning_effort: Some("high".to_owned()),
                        })
                    );
                    assert!(event.provenance.raw_artifact.is_none());
                    let request_bytes = store
                        .get_artifact(&prepared.request_artifact)
                        .expect("retained high-reasoning request verifies");
                    let retained = serde_json::from_slice::<RetainedRequest>(&request_bytes)
                        .expect("retained high-reasoning request decodes");
                    assert_eq!(retained.request.reasoning(), Some(ReasoningSetting::High));
                }
                EventPayload::PlannerInferenceObserved(observed) => {
                    observed_count += 1;
                    let prepared_event = events
                        .iter()
                        .find(|candidate| candidate.id == observed.prepared_event_id)
                        .expect("Observed binds its exact Prepared");
                    assert_eq!(event.provenance.backend, prepared_event.provenance.backend);
                    assert_eq!(
                        event.provenance.raw_artifact.as_ref(),
                        Some(&observed.normalized_complete_evidence_artifact)
                    );
                }
                EventPayload::PlanProposalAccepted(decision) => {
                    decision_count += 1;
                    let observed_event = events
                        .iter()
                        .find(|candidate| candidate.id == decision.observed_event_id)
                        .expect("producer decision binds its exact Observed");
                    assert_eq!(event.provenance.backend, observed_event.provenance.backend);
                    assert!(event.provenance.raw_artifact.is_none());
                }
                EventPayload::PlanSemanticReviewAccepted(decision) => {
                    decision_count += 1;
                    let observed_event = events
                        .iter()
                        .find(|candidate| candidate.id == decision.observed_event_id)
                        .expect("review decision binds its exact Observed");
                    assert_eq!(event.provenance.backend, observed_event.provenance.backend);
                    assert!(event.provenance.raw_artifact.is_none());
                }
                _ => {}
            }
        }
        assert_eq!(prepared_count, 2);
        assert_eq!(observed_count, 2);
        assert_eq!(decision_count, 2);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn semantic_revise_executes_one_repair_and_one_final_review() {
        let fixture = semantic_fixture(
            "Reparera en semantiskt underkänd plan exakt en gång och granska ersättningen blint.",
        );
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let backend = Arc::new(
            TestBackend::new(plan).with_semantic_critic(SemanticCriticMode::ReviseThenAccept),
        );
        let supervisor = RunSupervisor::start(
            fixture.paths.clone(),
            backend.clone(),
            semantic_test_config(),
        )
        .expect("semantic supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Completed,
            Duration::from_secs(3),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let stage_names = events
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::PlannerInferencePrepared(prepared) => prepared.stage_context.as_ref(),
                _ => None,
            })
            .map(|stage| match stage {
                PlannerStageContext::InitialPlan { .. } => RootPlanningStage::InitialPlan,
                PlannerStageContext::InitialReview { .. } => RootPlanningStage::InitialReview,
                PlannerStageContext::Repair { .. } => RootPlanningStage::Repair,
                PlannerStageContext::FinalReview { .. } => RootPlanningStage::FinalReview,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            stage_names,
            [
                RootPlanningStage::InitialPlan,
                RootPlanningStage::InitialReview,
                RootPlanningStage::Repair,
                RootPlanningStage::FinalReview,
            ]
        );
        assert!(events.iter().any(|event| matches!(
            &event.payload,
            EventPayload::PlanSemanticReviewRejected(rejected)
                if rejected.disposition
                    == PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
        )));
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 4);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn semantic_invalid_critic_contract_is_terminal_without_repair() {
        let fixture = semantic_fixture(
            "Ett trasigt granskningsformat får aldrig tolkas som ett semantiskt godkännande.",
        );
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let backend = Arc::new(
            TestBackend::new(plan).with_semantic_critic(SemanticCriticMode::InvalidContract),
        );
        let supervisor = RunSupervisor::start(
            fixture.paths.clone(),
            backend.clone(),
            semantic_test_config(),
        )
        .expect("semantic supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(3),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        assert!(events.iter().any(|event| matches!(
            &event.payload,
            EventPayload::PlanSemanticReviewRejected(rejected)
                if rejected.disposition
                    == PlanSemanticReviewRejectionDisposition::ReviewContractInvalid
        )));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::PlannerInferencePrepared(_)))
                .count(),
            2
        );
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 2);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn semantic_prepared_crash_recovery_never_reissues_the_ambiguous_call() {
        let fixture = semantic_fixture(
            "Efter en krasch vid Prepared ska den tvetydiga modellkörningen aldrig göras om.",
        );
        let config = semantic_test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            assert!(matches!(
                compile_and_prepare_semantic(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.clone(),
                    semantic_test_policy(),
                    semantic_test_models(),
                    RootPlanningStage::InitialPlan,
                    None,
                )
                .await
                .expect("semantic prepare succeeds"),
                PreparePhase::Prepared(_)
            ));
        });
        let backend = Arc::new(
            TestBackend::new(response_for_value(json!({}), MODEL))
                .with_semantic_critic(SemanticCriticMode::Accept),
        );
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("semantic supervisor restarts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        let events = all_events(&fixture.paths, fixture.run.id);
        let (unknown_event, unknown) = events
            .iter()
            .find_map(|event| match &event.payload {
                EventPayload::PlannerInferenceOutcomeUnknown(unknown) => Some((event, unknown)),
                _ => None,
            })
            .expect("restart records one exact Unknown boundary");
        let prepared_event = events
            .iter()
            .find(|event| event.id == unknown.prepared_event_id)
            .expect("Unknown binds its exact Prepared");
        assert_eq!(
            unknown_event.provenance.backend,
            prepared_event.provenance.backend
        );
        let boundary_artifact = unknown_event
            .provenance
            .raw_artifact
            .as_ref()
            .expect("Unknown retains its typed mechanical boundary");
        let store = Store::open(fixture.paths.database(), fixture.paths.artifacts())
            .expect("restart store reopens");
        let boundary = serde_json::from_slice::<RetainedCancellationBoundary>(
            &store
                .get_artifact(boundary_artifact)
                .expect("Unknown boundary evidence verifies"),
        )
        .expect("Unknown boundary evidence decodes");
        assert_eq!(boundary.reason, UnknownInferenceBoundary::Restart);
        assert_eq!(boundary.prepared_event_id, prepared_event.id);
        assert_eq!(
            boundary.cancellation_generation,
            unknown.cancellation_generation
        );
        supervisor.shutdown().expect("semantic supervisor joins");
    }

    #[test]
    fn semantic_observed_crash_replays_the_plan_decision_then_calls_only_the_critic() {
        let fixture = semantic_fixture(
            "Efter durabel observation ska producentbeslutet replayas och bara kritikern köras.",
        );
        let response = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let config = semantic_test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialPlan,
                None,
            )
            .await
            .expect("semantic prepare succeeds") else {
                panic!("expected a prepared semantic producer call");
            };
            append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response.clone()),
            )
            .await
            .expect("producer observation persists before crash");
        });
        let backend =
            Arc::new(TestBackend::new(response).with_semantic_critic(SemanticCriticMode::Accept));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("semantic supervisor restarts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Completed,
            Duration::from_secs(3),
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.critic_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            all_events(&fixture.paths, fixture.run.id)
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::PlannerInferencePrepared(_)))
                .count(),
            2
        );
        supervisor.shutdown().expect("semantic supervisor joins");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the crash/restart regression asserts the complete no-redispatch history"
    )]
    fn corrupt_committed_observation_terminalizes_once_without_redispatch_or_inference() {
        let fixture = semantic_fixture(
            "Ett korrupt durabelt svar ska terminaliseras utan att samma modell anropas igen.",
        );
        let response = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let config = semantic_test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        let evidence = runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialPlan,
                None,
            )
            .await
            .expect("semantic prepare succeeds") else {
                panic!("expected a prepared semantic producer call");
            };
            let observed = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response.clone()),
            )
            .await
            .expect("producer observation persists before corruption");
            let EventPayload::PlannerInferenceObserved(observed) = observed.observed.payload else {
                panic!("expected Observed evidence");
            };
            observed.normalized_complete_evidence_artifact
        });
        fs::write(artifact_disk_path(&fixture.paths, &evidence), b"corrupt")
            .expect("test corrupts the exact committed evidence file");

        let backend =
            Arc::new(TestBackend::new(response).with_semantic_critic(SemanticCriticMode::Accept));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("semantic supervisor restarts");
        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(3),
        );
        std::thread::sleep(Duration::from_millis(200));
        let events = all_events(&fixture.paths, fixture.run.id);
        let failures = events
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::RootPlanningStageFailed(failure) => Some(failure),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].failed_stage, RootPlanningStage::InitialPlan);
        assert_eq!(
            failures[0].reason,
            RootPlanningStageFailureReason::InvalidCommittedArtifact
        );
        assert_eq!(
            failures[0].model_subject,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::Producer,
                lineage: semantic_test_policy().producer,
            }
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::PlannerInferenceObserved(_)))
                .count(),
            1
        );
        assert!(!events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlanProposalAccepted(_)
                | EventPayload::PlanProposalRejected(_)
                | EventPayload::PlannerInferenceOutcomeUnknown(_)
        )));
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("semantic supervisor joins");

        let replacement_backend = Arc::new(
            TestBackend::new(response_for_value(json!({}), MODEL))
                .with_semantic_critic(SemanticCriticMode::Accept),
        );
        let replacement = RunSupervisor::start(
            fixture.paths.clone(),
            replacement_backend.clone(),
            semantic_test_config(),
        )
        .expect("second replacement supervisor starts");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            replacement_backend.discovery_calls.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            replacement_backend.inference_calls.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            all_events(&fixture.paths, fixture.run.id)
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::RootPlanningStageFailed(_)))
                .count(),
            1
        );
        replacement
            .shutdown()
            .expect("replacement semantic supervisor joins");
    }

    #[test]
    fn committed_replay_failure_classification_uses_typed_error_provenance() {
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::ArtifactPersistence(
                StoreError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture new artifact write",
                )),
            )),
            Some(RootPlanningStageFailureReason::ArtifactPersistenceFailed)
        );
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::ArtifactPersistence(
                StoreError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "fixture transient artifact write",
                )),
            )),
            None
        );
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::CommittedArtifact(
                "fixture artifact binding".to_owned(),
            )),
            Some(RootPlanningStageFailureReason::InvalidCommittedArtifact)
        );
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::InvalidState(
                "fixture causal contradiction".to_owned(),
            )),
            Some(RootPlanningStageFailureReason::DurableStateConflict)
        );
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::Contract(
                "fixture bundled registry invariant".to_owned(),
            )),
            Some(RootPlanningStageFailureReason::DurableStateConflict)
        );
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::Store(StoreError::Io(
                io::Error::new(io::ErrorKind::WouldBlock, "fixture transient artifact read"),
            ))),
            None
        );
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::Store(
                StoreError::ArtifactIntegrity,
            )),
            Some(RootPlanningStageFailureReason::InvalidCommittedArtifact)
        );
        assert_eq!(
            committed_replay_failure_reason(&SupervisorRunError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "fixture transient supervisor I/O",
            ))),
            None
        );
    }

    #[test]
    fn corrupt_committed_policy_can_still_record_an_exact_observed_stage_failure() {
        let fixture = semantic_fixture(
            "En korrupt policyref får inte blockera terminal provenance för ett observerat review-svar.",
        );
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let config = semantic_test_config();
        persist_semantic_initial_candidate(&fixture, &config, plan.clone());
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        let (policy_artifact, observed_pair) = runtime.block_on(async {
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialReview,
                None,
            )
            .await
            .expect("initial review prepares") else {
                panic!("expected a prepared critic call");
            };
            let policy_artifact = match &prepared.event.payload {
                EventPayload::PlannerInferencePrepared(PlannerInferencePrepared {
                    stage_context:
                        Some(PlannerStageContext::InitialReview {
                            execution_policy_artifact,
                            ..
                        }),
                    ..
                }) => execution_policy_artifact.clone(),
                _ => panic!("critic Prepared retains the exact policy ref"),
            };
            let response = semantic_critic_response(&prepared.request, PlanCriticVerdict::Accept);
            let observed_pair = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response),
            )
            .await
            .expect("critic observation persists before corruption");
            (policy_artifact, observed_pair)
        });
        fs::write(
            artifact_disk_path(&fixture.paths, &policy_artifact),
            b"corrupt execution policy",
        )
        .expect("test corrupts the exact committed execution-policy file");

        let completion = runtime.block_on(fail_observed_semantic_stage(
            fixture.paths.clone(),
            fixture.run.id,
            config,
            observed_pair.prepared,
            observed_pair.observed,
            RootPlanningStageFailureReason::InvalidCommittedArtifact,
            "the exact committed execution-policy artifact failed integrity verification"
                .to_owned(),
        ));
        assert_eq!(
            completion.expect("corrupt policy boundary persists"),
            RunCompletion::Failed
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let failure = events
            .iter()
            .find_map(|event| match &event.payload {
                EventPayload::RootPlanningStageFailed(failure) => Some(failure),
                _ => None,
            })
            .expect("policy corruption has a typed durable terminal cause");
        assert_eq!(failure.failed_stage, RootPlanningStage::InitialReview);
        assert_eq!(
            failure.reason,
            RootPlanningStageFailureReason::InvalidCommittedArtifact
        );
        assert_eq!(failure.execution_policy_artifact, policy_artifact);
        assert_eq!(
            failure.model_subject,
            RootPlanningModelSubject {
                role: RootPlanningModelRole::IndependentCritic,
                lineage: semantic_test_policy().critic,
            }
        );
        assert!(!events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlanSemanticReviewAccepted(_)
                | EventPayload::PlanSemanticReviewRejected(_)
        )));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression proves both the decision-time integrity gate and restart idempotence"
    )]
    fn policy_corruption_after_review_observation_is_detected_by_the_decision_gate() {
        let fixture = semantic_fixture(
            "En policy som försvinner efter review-observation får aldrig kringgå beslutsgaten.",
        );
        let config = semantic_test_config();
        let plan = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        persist_semantic_initial_candidate(&fixture, &config, plan);
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        let (policy_artifact, observed_pair) = runtime.block_on(async {
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialReview,
                None,
            )
            .await
            .expect("initial review prepares") else {
                panic!("expected InitialReview Prepared");
            };
            let policy_artifact = match &prepared.event.payload {
                EventPayload::PlannerInferencePrepared(PlannerInferencePrepared {
                    stage_context:
                        Some(PlannerStageContext::InitialReview {
                            execution_policy_artifact,
                            ..
                        }),
                    ..
                }) => execution_policy_artifact.clone(),
                _ => panic!("review Prepared must retain its execution policy"),
            };
            let response = semantic_critic_response(&prepared.request, PlanCriticVerdict::Accept);
            let observed_pair = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response),
            )
            .await
            .expect("review observation persists before policy corruption");
            (policy_artifact, observed_pair)
        });
        fs::write(
            artifact_disk_path(&fixture.paths, &policy_artifact),
            b"corrupt after review observation",
        )
        .expect("test corrupts the exact execution-policy artifact");

        let outcome = runtime
            .block_on(decide_or_fail_semantic_observed(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                observed_pair.prepared,
                observed_pair.observed,
                None,
            ))
            .expect("decision gate terminalizes corrupt policy");
        assert!(matches!(
            outcome,
            SemanticObservedDecision::Terminal(RunCompletion::Failed)
        ));
        let events = all_events(&fixture.paths, fixture.run.id);
        let failures = events
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::RootPlanningStageFailed(failure) => Some(failure),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].failed_stage, RootPlanningStage::InitialReview);
        assert_eq!(
            failures[0].reason,
            RootPlanningStageFailureReason::InvalidCommittedArtifact
        );
        assert_eq!(failures[0].execution_policy_artifact, policy_artifact);
        assert!(!events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlanSemanticReviewAccepted(_)
                | EventPayload::PlanSemanticReviewRejected(_)
        )));

        let backend = Arc::new(
            TestBackend::new(response_for_value(json!({}), MODEL))
                .with_semantic_critic(SemanticCriticMode::Accept),
        );
        let replacement = RunSupervisor::start(
            fixture.paths.clone(),
            backend.clone(),
            semantic_test_config(),
        )
        .expect("replacement semantic supervisor starts");
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            all_events(&fixture.paths, fixture.run.id)
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::RootPlanningStageFailed(_)))
                .count(),
            1
        );
        replacement
            .shutdown()
            .expect("replacement semantic supervisor joins");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the table regression audits three exact stage identities and restart boundaries"
    )]
    fn missing_or_corrupt_policy_before_each_later_stage_terminalizes_once_without_inference() {
        for stage in [
            RootPlanningStage::InitialReview,
            RootPlanningStage::Repair,
            RootPlanningStage::FinalReview,
        ] {
            let fixture = semantic_fixture(&format!(
                "Policyartefakten får inte blockera en durabel terminalgräns före {stage:?}."
            ));
            let config = semantic_test_config();
            let policy_artifact = persist_semantic_prefix_before(&fixture, &config, stage);
            let fallback = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
            let policy_path = artifact_disk_path(&fixture.paths, &policy_artifact);
            if stage == RootPlanningStage::Repair {
                fs::remove_file(&policy_path)
                    .expect("test removes the exact committed execution-policy file");
            } else {
                fs::write(&policy_path, b"corrupt execution policy")
                    .expect("test corrupts the exact committed execution-policy file");
            }

            let backend = Arc::new(
                TestBackend::new(fallback).with_semantic_critic(SemanticCriticMode::Accept),
            );
            let supervisor =
                RunSupervisor::start(fixture.paths.clone(), backend.clone(), config.clone())
                    .expect("replacement semantic supervisor starts");
            wait_for_state(
                &fixture.paths,
                fixture.run.id,
                RunState::Failed,
                Duration::from_secs(3),
            );
            std::thread::sleep(Duration::from_millis(100));

            let events = all_events(&fixture.paths, fixture.run.id);
            let failures = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::RootPlanningStageFailed(failure) => Some((event, failure)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(failures.len(), 1, "stage {stage:?}");
            let (failure_event, failure) = failures[0];
            assert_eq!(failure.failed_stage, stage);
            assert_eq!(
                failure.reason,
                RootPlanningStageFailureReason::InvalidCommittedArtifact
            );
            assert_eq!(failure.execution_policy_artifact, policy_artifact);
            let expected_subject = match stage {
                RootPlanningStage::InitialReview | RootPlanningStage::FinalReview => {
                    RootPlanningModelSubject {
                        role: RootPlanningModelRole::IndependentCritic,
                        lineage: semantic_test_policy().critic,
                    }
                }
                RootPlanningStage::Repair => RootPlanningModelSubject {
                    role: RootPlanningModelRole::Producer,
                    lineage: semantic_test_policy().producer,
                },
                RootPlanningStage::InitialPlan => unreachable!("loop excludes InitialPlan"),
            };
            assert_eq!(failure.model_subject, expected_subject);
            assert_eq!(
                failure_event.provenance.backend,
                Some(backend_selection_for_lineage(
                    &failure.model_subject.lineage,
                    None,
                ))
            );
            assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
            assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
            supervisor.shutdown().expect("semantic supervisor joins");

            let replacement_backend = Arc::new(
                TestBackend::new(response_for_value(json!({}), MODEL))
                    .with_semantic_critic(SemanticCriticMode::Accept),
            );
            let replacement = RunSupervisor::start(
                fixture.paths.clone(),
                replacement_backend.clone(),
                semantic_test_config(),
            )
            .expect("second replacement supervisor starts");
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(
                replacement_backend.discovery_calls.load(Ordering::SeqCst),
                0
            );
            assert_eq!(
                replacement_backend.inference_calls.load(Ordering::SeqCst),
                0
            );
            assert_eq!(
                all_events(&fixture.paths, fixture.run.id)
                    .iter()
                    .filter(|event| matches!(
                        event.payload,
                        EventPayload::RootPlanningStageFailed(_)
                    ))
                    .count(),
                1
            );
            replacement
                .shutdown()
                .expect("replacement semantic supervisor joins");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the table verifies three distinct committed semantic inputs plus restart idempotence"
    )]
    fn missing_or_corrupt_committed_stage_inputs_terminalize_once_without_inference() {
        #[derive(Clone, Copy, Debug)]
        enum Tamper {
            InitialCandidate,
            RepairCriticPolicy,
            RepairCritique,
        }

        for tamper in [
            Tamper::InitialCandidate,
            Tamper::RepairCriticPolicy,
            Tamper::RepairCritique,
        ] {
            let (next_stage, fixture) = match tamper {
                Tamper::InitialCandidate => (
                    RootPlanningStage::InitialReview,
                    semantic_fixture("En saknad planartefakt får inte återdispatchas för evigt."),
                ),
                Tamper::RepairCriticPolicy => (
                    RootPlanningStage::Repair,
                    semantic_fixture("En korrupt kritikerpolicy måste terminaliseras före repair."),
                ),
                Tamper::RepairCritique => (
                    RootPlanningStage::Repair,
                    semantic_fixture("En saknad kritikartefakt måste terminaliseras före repair."),
                ),
            };
            let config = semantic_test_config();
            persist_semantic_prefix_before(&fixture, &config, next_stage);
            let events = all_events(&fixture.paths, fixture.run.id);
            let artifact = match tamper {
                Tamper::InitialCandidate => events
                    .iter()
                    .find_map(|event| match &event.payload {
                        EventPayload::PlanProposalAccepted(accepted) => {
                            Some(accepted.accepted_plan_artifact.clone())
                        }
                        _ => None,
                    })
                    .expect("initial candidate should be committed"),
                Tamper::RepairCriticPolicy => events
                    .iter()
                    .find_map(|event| match &event.payload {
                        EventPayload::PlannerInferencePrepared(PlannerInferencePrepared {
                            stage_context:
                                Some(PlannerStageContext::InitialReview {
                                    critic_policy_artifact,
                                    ..
                                }),
                            ..
                        }) => Some(critic_policy_artifact.clone()),
                        _ => None,
                    })
                    .expect("initial review should commit its critic policy"),
                Tamper::RepairCritique => events
                    .iter()
                    .find_map(|event| match &event.payload {
                        EventPayload::PlanSemanticReviewRejected(rejected)
                            if rejected.disposition
                                == PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized =>
                        {
                            Some(rejected.critique_artifact.clone())
                        }
                        _ => None,
                    })
                    .expect("repair-authorizing review should commit its critique"),
            };
            let artifact_path = artifact_disk_path(&fixture.paths, &artifact);
            match tamper {
                Tamper::RepairCritique => {
                    fs::remove_file(&artifact_path)
                        .expect("test removes the committed critique artifact");
                }
                Tamper::InitialCandidate | Tamper::RepairCriticPolicy => {
                    fs::write(&artifact_path, b"corrupt committed stage input")
                        .expect("test corrupts the committed stage artifact");
                }
            }

            let fallback = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
            let backend = Arc::new(
                TestBackend::new(fallback).with_semantic_critic(SemanticCriticMode::Accept),
            );
            let supervisor =
                RunSupervisor::start(fixture.paths.clone(), backend.clone(), config.clone())
                    .expect("replacement semantic supervisor starts");
            wait_for_state(
                &fixture.paths,
                fixture.run.id,
                RunState::Failed,
                Duration::from_secs(3),
            );
            std::thread::sleep(Duration::from_millis(100));

            let events = all_events(&fixture.paths, fixture.run.id);
            let failures = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::RootPlanningStageFailed(failure) => Some(failure),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(failures.len(), 1, "tamper {tamper:?}");
            assert_eq!(failures[0].failed_stage, next_stage, "tamper {tamper:?}");
            assert_eq!(
                failures[0].reason,
                RootPlanningStageFailureReason::InvalidCommittedArtifact,
                "tamper {tamper:?}"
            );
            assert_eq!(
                backend.inference_calls.load(Ordering::SeqCst),
                0,
                "tamper {tamper:?}"
            );
            supervisor.shutdown().expect("semantic supervisor joins");

            let replacement_backend = Arc::new(
                TestBackend::new(response_for_value(json!({}), MODEL))
                    .with_semantic_critic(SemanticCriticMode::Accept),
            );
            let replacement = RunSupervisor::start(
                fixture.paths.clone(),
                replacement_backend.clone(),
                semantic_test_config(),
            )
            .expect("second replacement semantic supervisor starts");
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(
                replacement_backend.discovery_calls.load(Ordering::SeqCst),
                0
            );
            assert_eq!(
                replacement_backend.inference_calls.load(Ordering::SeqCst),
                0
            );
            assert_eq!(
                all_events(&fixture.paths, fixture.run.id)
                    .iter()
                    .filter(|event| matches!(
                        event.payload,
                        EventPayload::RootPlanningStageFailed(_)
                    ))
                    .count(),
                1,
                "tamper {tamper:?}"
            );
            replacement
                .shutdown()
                .expect("replacement semantic supervisor joins");
        }
    }

    #[test]
    fn durable_cancellation_dominates_corrupt_policy_before_next_stage() {
        let fixture = semantic_fixture(
            "En durabel cancellation måste vinna över en samtidigt korrupt policyartefakt.",
        );
        let config = semantic_test_config();
        let policy_artifact =
            persist_semantic_prefix_before(&fixture, &config, RootPlanningStage::InitialReview);
        let fallback = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        fs::write(
            artifact_disk_path(&fixture.paths, &policy_artifact),
            b"corrupt execution policy",
        )
        .expect("test corrupts the exact committed execution-policy file");
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime
            .block_on(ensure_durable_cancellation(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
            ))
            .expect("cancellation becomes durable before restart");

        let backend =
            Arc::new(TestBackend::new(fallback).with_semantic_critic(SemanticCriticMode::Accept));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("replacement semantic supervisor starts");
        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Cancelled,
            Duration::from_secs(3),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.payload, EventPayload::RootPlanningStageFailed(_)))
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("semantic supervisor joins");
    }

    #[test]
    fn simultaneous_ready_result_cannot_outrun_the_hard_deadline() {
        let fixture = semantic_fixture(
            "Ett samtidigt modellresultat får aldrig vinna över den absoluta deadlinen.",
        );
        let response = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let config = semantic_test_config();
        let backend =
            Arc::new(TestBackend::new(response).with_semantic_critic(SemanticCriticMode::Accept));
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        let completion = runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialPlan,
                None,
            )
            .await
            .expect("semantic prepare succeeds") else {
                panic!("expected a prepared semantic producer call");
            };
            execute_semantic_prepared(
                fixture.paths.clone(),
                backend.clone(),
                config.clone(),
                fixture.run.id,
                prepared,
                &CancellationToken::new(),
                &CancellationToken::new(),
                Some(Utc::now() - ChronoDuration::milliseconds(1)),
            )
            .await
            .expect("deadline boundary persists")
        });
        assert!(matches!(
            completion,
            SemanticPreparedExecution::Terminal(RunCompletion::Failed)
        ));
        let events = all_events(&fixture.paths, fixture.run.id);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        assert!(events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlannerInferenceOutcomeUnknown(_)
        )));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.payload, EventPayload::PlannerInferenceObserved(_)))
        );
    }

    #[test]
    fn expired_observed_result_fails_before_any_plan_decision_is_committed() {
        let fixture = semantic_fixture(
            "En redan observerad respons får inte accepteras efter den hårda deadlinen.",
        );
        let response = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let config = semantic_test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialPlan,
                None,
            )
            .await
            .expect("semantic prepare succeeds") else {
                panic!("expected a prepared semantic producer call");
            };
            let observed = append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response),
            )
            .await
            .expect("observation persists before deadline check");
            assert!(matches!(
                decide_or_fail_semantic_observed(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.clone(),
                    observed.prepared,
                    observed.observed,
                    Some(Utc::now() - ChronoDuration::milliseconds(1)),
                )
                .await
                .expect("deadline terminalizes the observed attempt"),
                SemanticObservedDecision::Terminal(RunCompletion::Failed)
            ));
        });
        let events = all_events(&fixture.paths, fixture.run.id);
        assert!(events.iter().any(|event| matches!(
            &event.payload,
            EventPayload::RootPlanningStageFailed(failure)
                if failure.reason == RootPlanningStageFailureReason::WallDeadlineExceeded
                    && failure.failed_stage == RootPlanningStage::InitialPlan
        )));
        assert!(!events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlanProposalAccepted(_) | EventPayload::PlanProposalRejected(_)
        )));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression constructs both valid decision variants at the exact commit boundary"
    )]
    fn sqlite_writer_wait_cannot_commit_a_supervisor_decision_after_its_deadline() {
        for accept in [true, false] {
            let fixture = fixture(
                "Ett SQLite-writerlås får aldrig flytta ett planbeslut över hard deadline.",
                None,
            );
            let config = test_config();
            let response = if accept {
                valid_response(&fixture.paths, fixture.run.id)
            } else {
                response_for_value(json!({}), MODEL)
            };
            let runtime = RuntimeBuilder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime builds");
            let observed = runtime.block_on(async {
                assert!(matches!(
                    begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                        .await
                        .expect("claim succeeds"),
                    BeginRun::Ready { .. }
                ));
                let PreparePhase::Prepared(prepared) = compile_and_prepare(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.clone(),
                    ResolvedModel {
                        model_id: ModelId::new(MODEL).expect("model id is valid"),
                        max_output_tokens: 512,
                        total_token_budget: 32_768,
                        reasoning: None,
                    },
                    None,
                )
                .await
                .expect("prepare succeeds") else {
                    panic!("expected Prepared");
                };
                append_observation(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.actor_id,
                    prepared.event,
                    Ok(response.clone()),
                )
                .await
                .expect("observation persists")
            });
            let EventPayload::PlannerInferencePrepared(prepared) = &observed.prepared.payload
            else {
                panic!("test decision requires Prepared");
            };
            let mut store = Store::open(fixture.paths.database(), fixture.paths.artifacts())
                .expect("decision store opens before the competing writer");
            let proposal_artifact = store
                .put_artifact(response.raw_text.as_bytes(), PROPOSAL_MEDIA_TYPE)
                .expect("proposal artifact persists");
            let validation = RetainedValidation {
                status: if accept { "accepted" } else { "rejected" },
                violations: if accept {
                    Vec::new()
                } else {
                    vec!["typed invalid-schema fixture".to_owned()]
                },
            };
            let validation_artifact = store
                .put_artifact(
                    &serde_json::to_vec(&validation).expect("validation serializes"),
                    VALIDATION_MEDIA_TYPE,
                )
                .expect("validation artifact persists");
            let proposal_id = PlanProposalId::new();
            let payload = if accept {
                let output = serde_json::from_value::<RootPlannerOutput>(response.value.clone())
                    .expect("accepted fixture decodes");
                let accepted_plan_artifact = store
                    .put_artifact(
                        &serde_json::to_vec(&output).expect("accepted plan serializes"),
                        PLAN_MEDIA_TYPE,
                    )
                    .expect("accepted plan artifact persists");
                EventPayload::PlanProposalAccepted(PlanProposalAccepted {
                    proposal_id,
                    inference_attempt_id: prepared.attempt_id,
                    observed_event_id: observed.observed.id,
                    proposal_artifact,
                    previous_plan_revision: prepared.plan_revision,
                    previous_plan_digest: prepared.plan_digest.clone(),
                    accepted_plan_revision: prepared.plan_revision + 1,
                    accepted_plan_digest: Sha256Digest::parse(
                        accepted_plan_artifact.sha256.clone(),
                    )
                    .expect("accepted plan digest is canonical"),
                    accepted_plan_artifact,
                    validation_evidence_artifact: validation_artifact,
                })
            } else {
                EventPayload::PlanProposalRejected(PlanProposalRejected {
                    proposal_id,
                    inference_attempt_id: prepared.attempt_id,
                    observed_event_id: observed.observed.id,
                    proposal_artifact,
                    base_plan_revision: prepared.plan_revision,
                    base_plan_digest: prepared.plan_digest.clone(),
                    reason: PlanProposalRejectionReason::InvalidSchema,
                    validation_evidence_artifact: validation_artifact,
                })
            };
            let event = NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: Some(fixture.run.id),
                actor_id: config.actor_id,
                causal_parent: Some(observed.observed.id),
                provenance: supervisor_provenance(Some(backend_selection_for_prepared(
                    prepared,
                    fixture.run.spec.backend.reasoning_effort.as_deref(),
                ))),
                payload,
            };

            let database = fixture.paths.database();
            let (locked_sender, locked_receiver) = std::sync::mpsc::sync_channel(0);
            let writer = std::thread::spawn(move || {
                let mut connection =
                    rusqlite::Connection::open(database).expect("competing writer opens");
                connection
                    .busy_timeout(Duration::from_secs(2))
                    .expect("competing writer timeout configures");
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .expect("competing writer acquires BEGIN IMMEDIATE");
                locked_sender
                    .send(())
                    .expect("test observes the held writer lock");
                std::thread::sleep(Duration::from_millis(500));
                transaction
                    .rollback()
                    .expect("competing writer releases its lock");
            });
            locked_receiver
                .recv()
                .expect("competing writer signals its lock");
            let deadline = Utc::now() + ChronoDuration::milliseconds(150);
            assert!(!deadline_elapsed(Some(deadline)));

            assert_eq!(
                append_decision_or_cancel(
                    &mut store,
                    fixture.run.id,
                    config.max_recovery_events,
                    event,
                    if accept {
                        DecisionOutcome::Accepted
                    } else {
                        DecisionOutcome::Rejected
                    },
                    Some(deadline),
                )
                .expect("deadline-aware supervisor append resolves"),
                DecisionOutcome::Deadline
            );
            writer.join().expect("competing writer joins");
            assert!(deadline_elapsed(Some(deadline)));
            assert!(
                all_events(&fixture.paths, fixture.run.id)
                    .iter()
                    .all(|event| {
                        !matches!(
                            event.payload,
                            EventPayload::PlanProposalAccepted(_)
                                | EventPayload::PlanProposalRejected(_)
                        )
                    })
            );
        }
    }

    #[test]
    fn durable_cancellation_suppresses_an_observed_stage_failure() {
        let fixture = semantic_fixture(
            "Durabel cancellation ska vinna över terminalisering av ett observerat replayfel.",
        );
        let response = valid_response_with_usage(&fixture.paths, fixture.run.id, 512, 40, 60);
        let config = semantic_test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        let observed = runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare_semantic(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                semantic_test_policy(),
                semantic_test_models(),
                RootPlanningStage::InitialPlan,
                None,
            )
            .await
            .expect("semantic prepare succeeds") else {
                panic!("expected a prepared semantic producer call");
            };
            append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response),
            )
            .await
            .expect("observation persists")
        });
        let store = Store::open(fixture.paths.database(), fixture.paths.artifacts())
            .expect("cancellation store opens");
        LocalRuntime::new(store)
            .cancel_run(fixture.run.id)
            .expect("cancellation is durable before replay failure handling");
        let completion = runtime.block_on(fail_observed_semantic_stage(
            fixture.paths.clone(),
            fixture.run.id,
            config,
            observed.prepared,
            observed.observed,
            RootPlanningStageFailureReason::InvalidCommittedArtifact,
            "this failure must be suppressed by cancellation".to_owned(),
        ));
        assert_eq!(
            completion.expect("cancellation terminalizes"),
            RunCompletion::Cancelled
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.payload, EventPayload::RootPlanningStageFailed(_)))
        );
        assert!(events.iter().any(|event| matches!(
            event.payload,
            EventPayload::RunStateChanged {
                to: RunState::Cancelled,
                ..
            }
        )));
    }

    #[test]
    fn invalid_wall_deadline_is_typed_before_failed_without_provider_access() {
        let fixture = fixture(
            "Avvisa en ogiltig wall-deadline med exakt provenance.",
            Some(u64::MAX),
        );
        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
                .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_root_failure_evidence(
            &fixture.paths,
            fixture.run.id,
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidWallDeadline,
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn unavailable_discovered_model_is_typed_before_failed_without_inference() {
        let fixture = fixture("Klassificera ett katalogfel utan strängheuristik.", None);
        let backend = Arc::new(
            TestBackend::new(response_for_value(json!({}), MODEL))
                .with_catalog_model("different-loaded-model"),
        );
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
                .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_root_failure_evidence(
            &fixture.paths,
            fixture.run.id,
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::SelectedModelUnavailable,
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn backend_discovery_failure_is_classified_without_parsing_its_message() {
        let fixture = fixture("Behåll den råa discovery-diagnostiken som evidens.", None);
        let backend =
            Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)).with_discovery_error());
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
                .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_root_failure_evidence(
            &fixture.paths,
            fixture.run.id,
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::BackendDiscoveryFailed,
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn wall_deadline_during_discovery_is_typed_before_prepared() {
        let fixture = fixture("Stoppa före Prepared när wall-deadline löper ut.", Some(1));
        let backend = Arc::new(
            TestBackend::new(response_for_value(json!({}), MODEL))
                .with_discovery_delay(Duration::from_secs(2)),
        );
        let supervisor = RunSupervisor::start(
            fixture.paths.clone(),
            backend.clone(),
            RunSupervisorConfig {
                discovery_timeout: Duration::from_secs(2),
                ..test_config()
            },
        )
        .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_root_failure_evidence(
            &fixture.paths,
            fixture.run.id,
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::WallDeadlineExceeded,
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        assert!(
            !all_events(&fixture.paths, fixture.run.id)
                .iter()
                .any(|event| matches!(event.payload, EventPayload::PlannerInferencePrepared(_)))
        );
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn restart_replays_exact_pre_inference_failure_without_provider_access() {
        for (phase, reason) in [
            (
                RootPlanningFailurePhase::Preflight,
                RootPlanningFailureReason::InvalidRunConfiguration,
            ),
            (
                RootPlanningFailurePhase::ModelDiscovery,
                RootPlanningFailureReason::BackendDiscoveryFailed,
            ),
            (
                RootPlanningFailurePhase::PromptPreparation,
                RootPlanningFailureReason::WallDeadlineExceeded,
            ),
        ] {
            let fixture = fixture("Återspela den exakta typade felorsaken.", None);
            let config = test_config();
            let runtime = RuntimeBuilder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime builds");
            runtime.block_on(async {
                assert!(matches!(
                    begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                        .await
                        .expect("claim succeeds"),
                    BeginRun::Ready { .. }
                ));
                assert_eq!(
                    append_root_planning_failure(
                        fixture.paths.clone(),
                        fixture.run.id,
                        config.actor_id,
                        config.max_recovery_events,
                        PreInferenceFailure::new(phase, reason, "exact retained test evidence"),
                    )
                    .await
                    .expect("failure event persists before the simulated restart"),
                    RootPlanningFailureAppend::Recorded
                );
            });
            assert_eq!(
                Store::open(fixture.paths.database(), fixture.paths.artifacts())
                    .expect("store opens")
                    .get_run(fixture.run.id)
                    .expect("run read succeeds")
                    .expect("run exists")
                    .state,
                RunState::Running
            );

            let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
            let supervisor =
                RunSupervisor::start(fixture.paths.clone(), backend.clone(), config.clone())
                    .expect("restarted supervisor starts");
            wait_for_state(
                &fixture.paths,
                fixture.run.id,
                RunState::Failed,
                Duration::from_secs(2),
            );
            assert_root_failure_evidence(&fixture.paths, fixture.run.id, phase, reason);
            assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
            assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
            supervisor.shutdown().expect("supervisor joins");
        }
    }

    #[test]
    fn durable_cancellation_after_root_failure_dominates_restart_replay() {
        let fixture = fixture("Cancellation ska dominera ett redan loggat rotfel.", None);
        let config = test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            append_root_planning_failure(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                config.max_recovery_events,
                PreInferenceFailure::new(
                    RootPlanningFailurePhase::ModelDiscovery,
                    RootPlanningFailureReason::BackendDiscoveryFailed,
                    "failure races with durable cancellation",
                ),
            )
            .await
            .expect("failure event persists");
        });
        let store =
            Store::open(fixture.paths.database(), fixture.paths.artifacts()).expect("store opens");
        LocalRuntime::new(store)
            .cancel_run(fixture.run.id)
            .expect("cancellation persists after the failure event");

        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("restarted supervisor starts");
        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Cancelled,
            Duration::from_secs(2),
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn startup_recovery_exceeding_scan_quantum_schedules_every_run() {
        let directory = TempDir::new().expect("test directory is created");
        let paths = RuntimePaths::new(directory.path());
        paths.prepare().expect("runtime paths are prepared");
        let runs = persist_plan_runs(&paths, 3);
        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(
            paths.clone(),
            backend.clone(),
            RunSupervisorConfig {
                command_capacity: 1,
                max_concurrent_runs: 1,
                max_startup_runs: 1,
                ..test_config()
            },
        )
        .expect("supervisor starts");

        for run in &runs {
            wait_for_state(&paths, run.id, RunState::Failed, Duration::from_secs(5));
        }
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), runs.len());
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn persisted_run_without_submit_is_eventually_dispatched() {
        let directory = TempDir::new().expect("test directory is created");
        let paths = RuntimePaths::new(directory.path());
        paths.prepare().expect("runtime paths are prepared");
        drop(Store::open(paths.database(), paths.artifacts()).expect("store initializes"));
        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(paths.clone(), backend.clone(), test_config())
            .expect("supervisor starts");

        let run = persist_plan_runs(&paths, 1)
            .pop()
            .expect("one run is persisted after supervisor startup");
        wait_for_state(&paths, run.id, RunState::Failed, Duration::from_secs(5));

        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn direct_submit_racing_durable_scan_invokes_model_once() {
        let directory = TempDir::new().expect("test directory is created");
        let paths = RuntimePaths::new(directory.path());
        paths.prepare().expect("runtime paths are prepared");
        drop(Store::open(paths.database(), paths.artifacts()).expect("store initializes"));
        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(
            paths.clone(),
            backend.clone(),
            RunSupervisorConfig {
                command_capacity: 1,
                max_concurrent_runs: 1,
                max_startup_runs: 1,
                ..test_config()
            },
        )
        .expect("supervisor starts");

        let run = persist_plan_runs(&paths, 1)
            .pop()
            .expect("one run is persisted");
        assert!(matches!(
            supervisor.submit(run.id),
            Ok(_) | Err(SupervisorSubmitError::AlreadyActive | SupervisorSubmitError::QueueFull)
        ));
        wait_for_state(&paths, run.id, RunState::Failed, Duration::from_secs(5));

        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            all_events(&paths, run.id)
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::PlannerInferencePrepared(_)))
                .count(),
            1
        );
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn prepared_is_durable_before_call_and_heartbeats_preserve_a_long_multilingual_turn() {
        let fixture = fixture(
            "Planera parallella specialistagenter på svenska, 日本語 och العربية.",
            None,
        );
        let backend = Arc::new(
            TestBackend::new(valid_response(&fixture.paths, fixture.run.id))
                .with_inference_delay(Duration::from_millis(1_100))
                .probe_prepared(fixture.paths.clone(), fixture.run.id),
        );
        let supervisor = RunSupervisor::start(
            fixture.paths.clone(),
            backend.clone(),
            RunSupervisorConfig {
                claim_lease: Duration::from_millis(300),
                ..test_config()
            },
        )
        .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Completed,
            Duration::from_secs(5),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let claims = events
            .iter()
            .filter(|event| matches!(event.payload, EventPayload::RunClaimed(_)))
            .count();
        assert!(backend.prepared_at_call.load(Ordering::SeqCst));
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        assert!(claims >= 3, "long inference should renew its durable claim");
        assert!(events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                outcome: PlannerInferenceObservation::Succeeded { .. },
                ..
            })
        )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event.payload, EventPayload::PlanProposalAccepted(_)))
        );
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn provider_context_reservation_accepts_valid_total_usage_above_the_output_ceiling() {
        let fixture =
            fixture_with_max_output("Planera med en separat total tokenbudget.", None, 4_096);
        let response =
            valid_response_with_usage(&fixture.paths, fixture.run.id, 4_096, 3_000, 2_000);
        let backend = Arc::new(TestBackend::new(response));
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
                .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Completed,
            Duration::from_secs(2),
        );
        let events = all_events(&fixture.paths, fixture.run.id);
        let reservation = events.iter().find_map(|event| match &event.payload {
            EventPayload::PlannerInferencePrepared(prepared) => Some(&prepared.token_reservation),
            _ => None,
        });
        let reservation = reservation.expect("Prepared retains its token reservation");
        assert_eq!(reservation.max_output_tokens, 4_096);
        assert_eq!(reservation.reserved_tokens, 32_768);
        assert!(events.iter().any(|event| matches!(
            &event.payload,
            EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                outcome: PlannerInferenceObservation::Succeeded { token_usage, .. },
                ..
            }) if token_usage.input_tokens == 3_000
                && token_usage.output_tokens == 2_000
                && token_usage.total_tokens == 5_000
        )));
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn overreported_total_usage_is_a_durable_protocol_violation_across_restart() {
        let fixture = fixture_with_max_output(
            "Avvisa tokenanvändning som överskrider den reserverade kontextbudgeten.",
            None,
            4_096,
        );
        let response = valid_response_with_usage(&fixture.paths, fixture.run.id, 4_096, 32_768, 1);
        let retained_response = response.clone();
        let backend = Arc::new(TestBackend::new(response));
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
                .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        supervisor.shutdown().expect("supervisor joins");

        assert_overreported_observation(&fixture.paths, fixture.run.id, &retained_response);

        let restarted = RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
            .expect("supervisor restarts");
        restarted
            .submit(fixture.run.id)
            .expect("terminal run can be replayed explicitly");
        let completion = wait_for_completion(&restarted, fixture.run.id, Duration::from_secs(2));
        assert_eq!(completion, RunCompletion::AlreadyTerminal(RunState::Failed));
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 1);
        restarted.shutdown().expect("restarted supervisor joins");

        let replayed_events = all_events(&fixture.paths, fixture.run.id);
        assert_eq!(
            replayed_events
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::PlannerInferenceObserved(_)))
                .count(),
            1
        );
        assert!(!replayed_events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlannerInferenceOutcomeUnknown(_)
        )));
    }

    #[test]
    fn explicit_output_limit_above_the_default_is_preserved() {
        let fixture = fixture_with_max_output(
            "Behåll den uttryckliga outputbudgeten i provenance.",
            None,
            8_192,
        );
        let backend = TestBackend::new(response_for_value(json!({}), MODEL));
        let Ok(resolved) = resolve_catalog(&backend.catalog(), &fixture.run, &test_config()) else {
            panic!("the exact loaded model resolves");
        };

        assert_eq!(resolved.max_output_tokens, 8_192);
        assert_eq!(resolved.total_token_budget, 32_768);
    }

    #[test]
    fn durable_fresh_cancellation_terminalizes_before_discovery() {
        let fixture = fixture("Avbryt före all modellåtkomst.", None);
        let config = test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
        });
        let store =
            Store::open(fixture.paths.database(), fixture.paths.artifacts()).expect("store opens");
        let mut local_runtime = LocalRuntime::new(store);
        let receipt = local_runtime
            .cancel_run(fixture.run.id)
            .expect("cancellation persists");
        assert_eq!(receipt.cancellation_generation, 1);
        assert_eq!(
            local_runtime
                .get_run(fixture.run.id)
                .expect("run remains readable")
                .state,
            RunState::Running
        );

        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("supervisor starts");
        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Cancelled,
            Duration::from_secs(2),
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn startup_recovery_terminalizes_inactive_durable_cancellation_before_claiming() {
        let fixture = fixture("Avbryt mellan durabel request och terminal state.", None);
        let config = test_config();
        let requesting_actor = ActorId::new();
        assert_ne!(requesting_actor, config.actor_id);
        let mut store =
            Store::open(fixture.paths.database(), fixture.paths.artifacts()).expect("store opens");
        let run_created = all_events(&fixture.paths, fixture.run.id)
            .pop()
            .expect("run-created event exists");
        let cancellation = store
            .append_event(NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: Some(fixture.run.id),
                actor_id: requesting_actor,
                causal_parent: Some(run_created.id),
                provenance: supervisor_provenance(None),
                payload: EventPayload::CancellationRequested(
                    birdcode_protocol::CancellationRequested {
                        cancellation_request_id: birdcode_protocol::CancellationRequestId::new(),
                        cancellation_generation: 1,
                    },
                ),
            })
            .expect("cancellation request persists at the crash boundary");
        drop(store);

        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("replacement supervisor starts");
        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Cancelled,
            Duration::from_secs(2),
        );

        let events = all_events(&fixture.paths, fixture.run.id);
        let terminal = events.last().expect("terminal transition persists");
        assert_eq!(terminal.causal_parent, Some(cancellation.id));
        assert!(matches!(
            terminal.payload,
            EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Cancelled
            }
        ));
        assert!(
            events
                .iter()
                .all(|event| !matches!(event.payload, EventPayload::RunClaimed(_))),
            "replacement recovery must terminalize before manufacturing a claim"
        );
        assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn cancellation_cas_wins_after_accepted_and_rejected_decisions() {
        for accept in [true, false] {
            let fixture = fixture(
                "Låt durabel cancellation vinna terminaliseringsracet.",
                None,
            );
            let config = test_config();
            let response = if accept {
                valid_response(&fixture.paths, fixture.run.id)
            } else {
                response_for_value(json!({}), MODEL)
            };
            let decision = persist_plan_decision(&fixture, &config, response);
            assert_eq!(
                decision,
                if accept {
                    DecisionOutcome::Accepted
                } else {
                    DecisionOutcome::Rejected
                }
            );

            let cancellation_paths = fixture.paths.clone();
            let run_id = fixture.run.id;
            let mut store = Store::open(fixture.paths.database(), fixture.paths.artifacts())
                .expect("store opens");
            let actual = transition_run_in_store(
                &mut store,
                run_id,
                config.actor_id,
                config.max_recovery_events,
                if accept {
                    RunState::Completed
                } else {
                    RunState::Failed
                },
                move || {
                    let cancellation_store = Store::open(
                        cancellation_paths.database(),
                        cancellation_paths.artifacts(),
                    )
                    .expect("cancellation store opens");
                    LocalRuntime::new(cancellation_store)
                        .cancel_run(run_id)
                        .expect("cancellation wins between transition read and CAS");
                },
            )
            .expect("transition retries against the new cancellation parent");
            assert_eq!(actual, RunState::Cancelled);
            assert_eq!(
                store
                    .get_run(run_id)
                    .expect("run read succeeds")
                    .expect("run exists")
                    .state,
                RunState::Cancelled
            );
        }
    }

    #[test]
    fn durable_cancellation_dominates_terminal_decision_recovery() {
        for accept in [true, false] {
            let fixture = fixture("Återställ cancellation före terminalt planbeslut.", None);
            let config = test_config();
            let response = if accept {
                valid_response(&fixture.paths, fixture.run.id)
            } else {
                response_for_value(json!({}), MODEL)
            };
            persist_plan_decision(&fixture, &config, response);

            let store = Store::open(fixture.paths.database(), fixture.paths.artifacts())
                .expect("store opens");
            LocalRuntime::new(store)
                .cancel_run(fixture.run.id)
                .expect("cancellation persists after the decision");
            let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
            let supervisor =
                RunSupervisor::start(fixture.paths.clone(), backend.clone(), config.clone())
                    .expect("supervisor starts");

            wait_for_state(
                &fixture.paths,
                fixture.run.id,
                RunState::Cancelled,
                Duration::from_secs(2),
            );
            assert_eq!(backend.discovery_calls.load(Ordering::SeqCst), 0);
            assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
            supervisor.shutdown().expect("supervisor joins");
        }
    }

    #[test]
    fn prepared_crash_recovery_records_unknown_without_a_second_model_call() {
        let fixture = fixture("Planera en crash-säker körning.", None);
        let config = test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            assert!(matches!(
                compile_and_prepare(
                    fixture.paths.clone(),
                    fixture.run.id,
                    config.clone(),
                    ResolvedModel {
                        model_id: ModelId::new(MODEL).expect("model id is valid"),
                        max_output_tokens: 512,
                        total_token_budget: 32_768,
                        reasoning: None,
                    },
                    None,
                )
                .await
                .expect("prepare succeeds"),
                PreparePhase::Prepared(_)
            ));
        });
        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        assert!(
            all_events(&fixture.paths, fixture.run.id)
                .iter()
                .any(|event| {
                    matches!(
                        event.payload,
                        EventPayload::PlannerInferenceOutcomeUnknown(_)
                    )
                })
        );
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn observed_crash_recovery_replays_the_decision_without_model_inference() {
        let fixture = fixture("Fortsätt deterministiskt efter observation。", None);
        let response = valid_response(&fixture.paths, fixture.run.id);
        let config = test_config();
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            assert!(matches!(
                begin_run(fixture.paths.clone(), fixture.run.id, config.clone())
                    .await
                    .expect("claim succeeds"),
                BeginRun::Ready { .. }
            ));
            let PreparePhase::Prepared(prepared) = compile_and_prepare(
                fixture.paths.clone(),
                fixture.run.id,
                config.clone(),
                ResolvedModel {
                    model_id: ModelId::new(MODEL).expect("model id is valid"),
                    max_output_tokens: 512,
                    total_token_budget: 32_768,
                    reasoning: None,
                },
                None,
            )
            .await
            .expect("prepare succeeds") else {
                panic!("expected a prepared phase");
            };
            append_observation(
                fixture.paths.clone(),
                fixture.run.id,
                config.actor_id,
                prepared.event,
                Ok(response),
            )
            .await
            .expect("observation persists");
        });
        let backend = Arc::new(TestBackend::new(response_for_value(json!({}), MODEL)));
        let supervisor = RunSupervisor::start(fixture.paths.clone(), backend.clone(), config)
            .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Completed,
            Duration::from_secs(2),
        );
        assert_eq!(backend.inference_calls.load(Ordering::SeqCst), 0);
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn wall_deadline_drops_inference_and_retains_unknown_evidence() {
        let fixture = fixture("Respektera en stabil wall-time-gräns.", Some(1));
        let backend = Arc::new(
            TestBackend::new(response_for_value(json!({}), MODEL))
                .with_inference_delay(Duration::from_secs(3)),
        );
        let started = Instant::now();
        let supervisor =
            RunSupervisor::start(fixture.paths.clone(), backend.clone(), test_config())
                .expect("supervisor starts");

        wait_for_state(
            &fixture.paths,
            fixture.run.id,
            RunState::Failed,
            Duration::from_secs(2),
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        let events = all_events(&fixture.paths, fixture.run.id);
        assert!(events.iter().any(|event| matches!(
            event.payload,
            EventPayload::PlannerInferenceOutcomeUnknown(_)
        )));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.payload, EventPayload::PlannerInferenceObserved(_)))
        );
        supervisor.shutdown().expect("supervisor joins");
    }

    #[test]
    fn public_discovery_has_a_bounded_timeout_below_the_client_deadline() {
        let directory = TempDir::new().expect("test directory is created");
        let paths = RuntimePaths::new(directory.path());
        let backend = Arc::new(
            TestBackend::new(response_for_value(json!({}), MODEL))
                .with_discovery_delay(Duration::from_secs(2)),
        );
        let supervisor = RunSupervisor::start(
            paths,
            backend,
            RunSupervisorConfig {
                discovery_timeout: Duration::from_millis(80),
                ..test_config()
            },
        )
        .expect("supervisor starts");
        let started = Instant::now();

        assert_eq!(
            supervisor.discover_models(),
            Err(SupervisorDiscoveryError::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        supervisor.shutdown().expect("supervisor joins");
    }
}
