//! Durable run discovery, admission, scheduling, and task publication.

use super::run_execution::{purpose_has_executable_supervisor, supervise_run_with_registry};
use super::{
    BackendRegistry, DiscoveryCommand, ModelBackend, ModelCallScheduler, RunCompletion, RunId,
    RunSupervisorConfig, RunSupervisorEvent, RuntimePaths, SubmitCommand, SupervisorRunError,
    discover_for_protocol, store_phase,
};
use birdcode_store::RunRecoveryPage;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const MIN_DURABLE_DISPATCH_BACKOFF: Duration = Duration::from_millis(50);
const MAX_DURABLE_DISPATCH_BACKOFF: Duration = Duration::from_secs(1);

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(super) async fn supervisor_loop(
    paths: RuntimePaths,
    backend_registry: BackendRegistry,
    backend: Arc<dyn ModelBackend>,
    model_calls: ModelCallScheduler,
    config: RunSupervisorConfig,
    durable_commands: mpsc::Sender<SubmitCommand>,
    mut commands: mpsc::Receiver<SubmitCommand>,
    mut discoveries: mpsc::Receiver<DiscoveryCommand>,
    events: std::sync::mpsc::SyncSender<RunSupervisorEvent>,
    shutdown: CancellationToken,
    active_cancellations: Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    dispatch_wake: Arc<Notify>,
    parallel_reconnaissance_available: bool,
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
        parallel_reconnaissance_available,
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
                &backend_registry,
                &backend,
                &model_calls,
                &config,
                &shutdown,
                parallel_reconnaissance_available,
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
    parallel_reconnaissance_available: bool,
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
            // Protocol admission is intentionally broader than this daemon's
            // executable capability set. Leave unavailable purposes durable
            // and quiescent instead of repeatedly claiming or failing them.
            if !purpose_has_executable_supervisor(
                run.spec.purpose,
                parallel_reconnaissance_available,
            ) {
                cursor = Some(run.id);
                scanned_since_yield += 1;
                if scanned_since_yield == scan_quantum {
                    scanned_since_yield = 0;
                    tokio::task::yield_now().await;
                }
                continue;
            }
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
    backend_registry: &BackendRegistry,
    backend: &Arc<dyn ModelBackend>,
    model_calls: &ModelCallScheduler,
    config: &RunSupervisorConfig,
    shutdown: &CancellationToken,
    parallel_reconnaissance_available: bool,
    command: SubmitCommand,
) {
    let _ = events.try_send(RunSupervisorEvent::Started {
        run_id: command.run_id,
    });
    let run_paths = paths.clone();
    let run_backend_registry = backend_registry.clone();
    let run_backend = Arc::clone(backend);
    let run_model_calls = model_calls.clone();
    let run_config = config.clone();
    let run_shutdown = shutdown.clone();
    let run_id = command.run_id;
    let abort_handle = tasks.spawn(async move {
        let result = Box::pin(supervise_run_with_registry(
            run_paths,
            run_backend_registry,
            run_backend,
            run_model_calls,
            run_config,
            command.run_id,
            command.cancellation,
            run_shutdown,
            parallel_reconnaissance_available,
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
