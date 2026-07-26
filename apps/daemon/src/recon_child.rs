//! Narrow runtime boundary for one repository-explorer child.
//!
//! The root owns only durable identities and lifecycle handles. The child
//! engine must rederive the immutable work-order document, repository policy,
//! snapshot/root authority and execution binding from Store; none of those
//! semantic or capability-bearing values are accepted from its caller.

use crate::{
    model_call_scheduler::ModelCallScheduler,
    recon::{ReconModelProfile, ReconRuntimeClock},
    supervisor::{RunSupervisorConfig, SupervisorRunError},
};
use birdcode_backends::ModelBackend;
use birdcode_protocol::{
    ChildExecutionId, ChildWorkOrderId, EventEnvelope, EventId, EventPayload, RunId,
};
use birdcode_runtime::RuntimePaths;
use chrono::{DateTime, Utc};
use std::{
    fmt,
    future::{Future, pending},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

/// Bounded outcome of the exact-two child rendezvous. A peer that fails before
/// release must explicitly break the gate so its sibling cannot deadlock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildStartGateEnd {
    Released,
    Cancelled,
    RuntimeShutdown,
    DeadlineElapsed,
    PeerFailed,
}

/// Opaque proof that the exact Started envelope returned by Store binds this
/// run and work order.  The model never receives, chooses, or can mint this
/// value; the rendezvous therefore cannot be satisfied by passing arbitrary
/// lifecycle UUIDs.
pub(crate) struct CommittedChildStart {
    work_order_id: ChildWorkOrderId,
    started_event_id: EventId,
}

impl CommittedChildStart {
    pub(crate) fn from_store_event(
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        event: &EventEnvelope,
    ) -> Result<Self, SupervisorRunError> {
        let EventPayload::ChildExecutionStarted(started) = &event.payload else {
            return Err(SupervisorRunError::InvalidState(
                "child start proof does not contain a Started event".to_owned(),
            ));
        };
        if event.run_id != Some(run_id) || started.binding.work_order_id != work_order_id {
            return Err(SupervisorRunError::InvalidState(
                "child start proof does not bind the exact run and work order".to_owned(),
            ));
        }
        Ok(Self {
            work_order_id,
            started_event_id: event.id,
        })
    }

    #[cfg(test)]
    fn test(work_order_id: ChildWorkOrderId) -> Self {
        Self {
            work_order_id,
            started_event_id: EventId::new(),
        }
    }
}

/// Cancel-safe start rendezvous supplied by the root. Implementations must
/// release only after exactly two distinct authorized work orders arrive and
/// must make `break_for_peer_failure` wake every waiter idempotently.
pub(crate) trait ChildStartGate: Send + Sync {
    fn arrive_after_committed_start<'a>(
        &'a self,
        committed: &'a CommittedChildStart,
        cancellation: &'a CancellationToken,
        shutdown: &'a CancellationToken,
        deadline: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = ChildStartGateEnd> + Send + 'a>>;

    fn break_for_peer_failure(&self, work_order_id: ChildWorkOrderId);
}

/// Construction error for an exact-two rendezvous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExactTwoChildStartGateError {
    DuplicateAuthorizedWorkOrder,
}

impl fmt::Display for ExactTwoChildStartGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAuthorizedWorkOrder => {
                formatter.write_str("the exact-two start gate requires distinct work orders")
            }
        }
    }
}

impl std::error::Error for ExactTwoChildStartGateError {}

#[derive(Debug)]
struct ExactTwoChildStartGateState {
    arrived: [bool; 2],
    started_event_ids: [Option<EventId>; 2],
    terminal: Option<ChildStartGateEnd>,
}

/// One-shot, exact-two rendezvous for the two root-authorized explorer work
/// orders. Its first terminal outcome is durable in memory for every current
/// and future waiter, so no notification can be missed.
#[derive(Debug)]
pub(crate) struct ExactTwoChildStartGate {
    authorized: [ChildWorkOrderId; 2],
    state: Mutex<ExactTwoChildStartGateState>,
    terminal_sender: watch::Sender<Option<ChildStartGateEnd>>,
}

impl ExactTwoChildStartGate {
    pub(crate) fn new(
        authorized: [ChildWorkOrderId; 2],
    ) -> Result<Self, ExactTwoChildStartGateError> {
        if authorized[0] == authorized[1] {
            return Err(ExactTwoChildStartGateError::DuplicateAuthorizedWorkOrder);
        }
        let (terminal_sender, _) = watch::channel(None);
        Ok(Self {
            authorized,
            state: Mutex::new(ExactTwoChildStartGateState {
                arrived: [false; 2],
                started_event_ids: [None, None],
                terminal: None,
            }),
            terminal_sender,
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, ExactTwoChildStartGateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn publish_terminal(&self, end: ChildStartGateEnd) {
        self.terminal_sender.send_replace(Some(end));
    }

    fn end_if_open(&self, requested: ChildStartGateEnd) -> ChildStartGateEnd {
        let (end, publish) = {
            let mut state = self.lock_state();
            if let Some(existing) = state.terminal {
                (existing, false)
            } else {
                state.terminal = Some(requested);
                (requested, true)
            }
        };
        if publish {
            self.publish_terminal(end);
        }
        end
    }

    fn register_arrival(&self, committed: &CommittedChildStart) -> Option<ChildStartGateEnd> {
        let (terminal, publish) = {
            let mut state = self.lock_state();
            if let Some(existing) = state.terminal {
                return Some(existing);
            }

            let Some(index) = self
                .authorized
                .iter()
                .position(|authorized| *authorized == committed.work_order_id)
            else {
                // A foreign identity is an internal authorization violation.
                // Fail closed and wake the real peers rather than allowing an
                // impossible rendezvous to strand either child.
                state.terminal = Some(ChildStartGateEnd::PeerFailed);
                return {
                    drop(state);
                    self.publish_terminal(ChildStartGateEnd::PeerFailed);
                    Some(ChildStartGateEnd::PeerFailed)
                };
            };

            if state.started_event_ids[index]
                .is_some_and(|existing| existing != committed.started_event_id)
                || state
                    .started_event_ids
                    .iter()
                    .enumerate()
                    .any(|(other, existing)| {
                        other != index && *existing == Some(committed.started_event_id)
                    })
            {
                state.terminal = Some(ChildStartGateEnd::PeerFailed);
                return {
                    drop(state);
                    self.publish_terminal(ChildStartGateEnd::PeerFailed);
                    Some(ChildStartGateEnd::PeerFailed)
                };
            }

            state.arrived[index] = true;
            state.started_event_ids[index] = Some(committed.started_event_id);
            if state.arrived == [true, true] {
                state.terminal = Some(ChildStartGateEnd::Released);
                (Some(ChildStartGateEnd::Released), true)
            } else {
                (None, false)
            }
        };
        if publish {
            self.publish_terminal(ChildStartGateEnd::Released);
        }
        terminal
    }

    #[cfg(test)]
    fn distinct_arrival_count(&self) -> usize {
        self.lock_state()
            .arrived
            .iter()
            .filter(|arrived| **arrived)
            .count()
    }
}

impl ChildStartGate for ExactTwoChildStartGate {
    fn arrive_after_committed_start<'a>(
        &'a self,
        committed: &'a CommittedChildStart,
        cancellation: &'a CancellationToken,
        shutdown: &'a CancellationToken,
        deadline: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = ChildStartGateEnd> + Send + 'a>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return self.end_if_open(ChildStartGateEnd::Cancelled);
            }
            if shutdown.is_cancelled() {
                return self.end_if_open(ChildStartGateEnd::RuntimeShutdown);
            }
            if deadline.is_some_and(|deadline| deadline <= Utc::now()) {
                return self.end_if_open(ChildStartGateEnd::DeadlineElapsed);
            }

            let mut terminal_receiver = self.terminal_sender.subscribe();
            if let Some(end) = self.register_arrival(committed) {
                return end;
            }

            let deadline_wait = async move {
                match deadline {
                    Some(deadline) => {
                        let remaining = deadline.signed_duration_since(Utc::now());
                        if let Ok(duration) = remaining.to_std() {
                            sleep(duration).await;
                        }
                    }
                    None => pending::<()>().await,
                }
            };
            tokio::pin!(deadline_wait);

            loop {
                if let Some(end) = *terminal_receiver.borrow_and_update() {
                    return end;
                }
                let requested_end = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => ChildStartGateEnd::Cancelled,
                    () = shutdown.cancelled() => ChildStartGateEnd::RuntimeShutdown,
                    () = &mut deadline_wait => ChildStartGateEnd::DeadlineElapsed,
                    changed = terminal_receiver.changed() => {
                        if changed.is_err() {
                            ChildStartGateEnd::PeerFailed
                        } else {
                            continue;
                        }
                    }
                };
                return self.end_if_open(requested_end);
            }
        })
    }

    fn break_for_peer_failure(&self, _work_order_id: ChildWorkOrderId) {
        self.end_if_open(ChildStartGateEnd::PeerFailed);
    }
}

/// Caller-owned mechanical handles for one child engine. The authorization
/// event and work-order identity are lookup keys, not trusted copies of their
/// Store-owned content.
pub(crate) struct ChildEngineInput {
    pub paths: RuntimePaths,
    pub run_id: RunId,
    pub authorization_event_id: EventId,
    pub work_order_id: ChildWorkOrderId,
    pub backend: Arc<dyn ModelBackend>,
    pub model_profile: ReconModelProfile,
    pub scheduler: ModelCallScheduler,
    pub config: RunSupervisorConfig,
    pub cancellation: CancellationToken,
    pub shutdown: CancellationToken,
    pub deadline: Option<DateTime<Utc>>,
    pub clock: Arc<ReconRuntimeClock>,
    pub start_gate: Arc<dyn ChildStartGate>,
}

/// Store-committed terminal identity returned by one child task. A successful
/// execution has an exact handoff envelope; failed/cancelled executions do
/// not invent one. The root waits for both terminals before integration.
pub(crate) struct ChildEngineTerminal {
    pub work_order_id: ChildWorkOrderId,
    pub execution_id: ChildExecutionId,
    pub started_event: EventEnvelope,
    pub terminal_event: EventEnvelope,
    pub handoff_event: Option<EventEnvelope>,
}

/// One-child Store-total model→action→broker→handoff engine.
///
/// The implementation lives in this module so it cannot accidentally accept
/// root-supplied semantic documents. It must be provided before the product
/// capability flag can be enabled.
pub(crate) async fn run_child_repository_explorer(
    _input: ChildEngineInput,
) -> Result<ChildEngineTerminal, SupervisorRunError> {
    Err(SupervisorRunError::InvalidState(
        "repository-explorer child engine is not implemented".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use tokio::time::{Duration, timeout};

    fn distinct_work_orders() -> [ChildWorkOrderId; 2] {
        [ChildWorkOrderId::new(), ChildWorkOrderId::new()]
    }

    fn committed(work_order_id: ChildWorkOrderId) -> CommittedChildStart {
        CommittedChildStart::test(work_order_id)
    }

    async fn yield_after_polling_two<F, G>(first: &mut Pin<Box<F>>, second: &mut Pin<Box<G>>)
    where
        F: Future<Output = ChildStartGateEnd> + ?Sized,
        G: Future<Output = ChildStartGateEnd> + ?Sized,
    {
        tokio::select! {
            biased;
            result = first => panic!("first waiter unexpectedly completed with {result:?}"),
            result = second => panic!("second waiter unexpectedly completed with {result:?}"),
            () = tokio::task::yield_now() => {}
        }
    }

    #[test]
    fn construction_rejects_duplicate_authorized_identity() {
        let work_order_id = ChildWorkOrderId::new();
        assert_eq!(
            ExactTwoChildStartGate::new([work_order_id, work_order_id])
                .expect_err("duplicate authorization must be rejected"),
            ExactTwoChildStartGateError::DuplicateAuthorizedWorkOrder
        );
    }

    #[tokio::test]
    async fn duplicate_arrivals_do_not_release_without_the_second_authorized_identity() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let first_start = committed(work_orders[0]);
        let duplicate_start = CommittedChildStart {
            work_order_id: work_orders[0],
            started_event_id: first_start.started_event_id,
        };
        let mut first =
            gate.arrive_after_committed_start(&first_start, &cancellation, &shutdown, None);
        let mut duplicate =
            gate.arrive_after_committed_start(&duplicate_start, &cancellation, &shutdown, None);

        yield_after_polling_two(&mut first, &mut duplicate).await;
        assert_eq!(gate.distinct_arrival_count(), 1);

        let second_start = committed(work_orders[1]);
        let second_identity =
            gate.arrive_after_committed_start(&second_start, &cancellation, &shutdown, None);
        let (first_end, duplicate_end, second_end) = timeout(Duration::from_secs(1), async {
            tokio::join!(first, duplicate, second_identity)
        })
        .await
        .expect("the exact pair must release every waiter");
        assert_eq!(
            [first_end, duplicate_end, second_end],
            [ChildStartGateEnd::Released; 3]
        );
        assert_eq!(gate.distinct_arrival_count(), 2);
    }

    #[tokio::test]
    async fn conflicting_started_event_for_one_work_order_fails_closed() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let first_start = committed(work_orders[0]);
        let conflicting_start = committed(work_orders[0]);
        let first = gate.arrive_after_committed_start(&first_start, &cancellation, &shutdown, None);
        tokio::pin!(first);
        tokio::select! {
            result = &mut first => panic!("first waiter unexpectedly completed with {result:?}"),
            () = tokio::task::yield_now() => {}
        }

        let conflicting =
            gate.arrive_after_committed_start(&conflicting_start, &cancellation, &shutdown, None);
        let (first_end, conflicting_end) = timeout(Duration::from_secs(1), async {
            tokio::join!(first, conflicting)
        })
        .await
        .expect("conflicting Started proof must wake the legitimate waiter");
        assert_eq!(first_end, ChildStartGateEnd::PeerFailed);
        assert_eq!(conflicting_end, ChildStartGateEnd::PeerFailed);
    }

    #[tokio::test]
    async fn cancellation_terminates_the_gate_and_wakes_every_waiter() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let sibling_cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let cancelled_start = committed(work_orders[0]);
        let sibling_start = CommittedChildStart {
            work_order_id: work_orders[0],
            started_event_id: cancelled_start.started_event_id,
        };
        let mut cancelled_waiter =
            gate.arrive_after_committed_start(&cancelled_start, &cancellation, &shutdown, None);
        let mut sibling_waiter = gate.arrive_after_committed_start(
            &sibling_start,
            &sibling_cancellation,
            &shutdown,
            None,
        );
        yield_after_polling_two(&mut cancelled_waiter, &mut sibling_waiter).await;

        cancellation.cancel();
        let (cancelled_end, sibling_end) = timeout(Duration::from_secs(1), async {
            tokio::join!(cancelled_waiter, sibling_waiter)
        })
        .await
        .expect("cancellation must wake both waiters");
        assert_eq!(cancelled_end, ChildStartGateEnd::Cancelled);
        assert_eq!(sibling_end, ChildStartGateEnd::Cancelled);

        let late_start = committed(work_orders[1]);
        assert_eq!(
            gate.arrive_after_committed_start(&late_start, &sibling_cancellation, &shutdown, None,)
                .await,
            ChildStartGateEnd::Cancelled
        );
    }

    #[tokio::test]
    async fn shutdown_terminates_a_waiting_gate_and_is_sticky() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let first_start = committed(work_orders[0]);
        let waiter =
            gate.arrive_after_committed_start(&first_start, &cancellation, &shutdown, None);
        tokio::pin!(waiter);
        tokio::select! {
            result = &mut waiter => panic!("waiter unexpectedly completed with {result:?}"),
            () = tokio::task::yield_now() => {}
        }

        shutdown.cancel();
        assert_eq!(
            timeout(Duration::from_secs(1), waiter)
                .await
                .expect("shutdown must wake the waiter"),
            ChildStartGateEnd::RuntimeShutdown
        );
        let late_start = committed(work_orders[1]);
        assert_eq!(
            gate.arrive_after_committed_start(
                &late_start,
                &cancellation,
                &CancellationToken::new(),
                None,
            )
            .await,
            ChildStartGateEnd::RuntimeShutdown
        );
    }

    #[tokio::test]
    async fn deadline_terminates_a_waiting_gate_and_is_sticky() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let deadline = Utc::now() + ChronoDuration::milliseconds(10);
        let first_start = committed(work_orders[0]);

        assert_eq!(
            timeout(
                Duration::from_secs(1),
                gate.arrive_after_committed_start(
                    &first_start,
                    &cancellation,
                    &shutdown,
                    Some(deadline),
                ),
            )
            .await
            .expect("deadline must wake the waiter"),
            ChildStartGateEnd::DeadlineElapsed
        );
        let late_start = committed(work_orders[1]);
        assert_eq!(
            gate.arrive_after_committed_start(&late_start, &cancellation, &shutdown, None,)
                .await,
            ChildStartGateEnd::DeadlineElapsed
        );
    }

    #[tokio::test]
    async fn peer_failure_break_is_idempotent_and_wakes_every_waiter() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let first_start = committed(work_orders[0]);
        let duplicate_start = CommittedChildStart {
            work_order_id: work_orders[0],
            started_event_id: first_start.started_event_id,
        };
        let mut first =
            gate.arrive_after_committed_start(&first_start, &cancellation, &shutdown, None);
        let mut duplicate =
            gate.arrive_after_committed_start(&duplicate_start, &cancellation, &shutdown, None);
        yield_after_polling_two(&mut first, &mut duplicate).await;

        gate.break_for_peer_failure(work_orders[0]);
        gate.break_for_peer_failure(work_orders[0]);
        let (first_end, duplicate_end) = timeout(Duration::from_secs(1), async {
            tokio::join!(first, duplicate)
        })
        .await
        .expect("peer failure must wake all waiters");
        assert_eq!(first_end, ChildStartGateEnd::PeerFailed);
        assert_eq!(duplicate_end, ChildStartGateEnd::PeerFailed);
        let late_start = committed(work_orders[1]);
        assert_eq!(
            gate.arrive_after_committed_start(&late_start, &cancellation, &shutdown, None,)
                .await,
            ChildStartGateEnd::PeerFailed
        );
    }

    #[tokio::test]
    async fn release_cannot_be_overwritten_by_a_late_break() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let first_start = committed(work_orders[0]);
        let second_start = committed(work_orders[1]);
        let first = gate.arrive_after_committed_start(&first_start, &cancellation, &shutdown, None);
        let second =
            gate.arrive_after_committed_start(&second_start, &cancellation, &shutdown, None);
        assert_eq!(
            tokio::join!(first, second),
            (ChildStartGateEnd::Released, ChildStartGateEnd::Released)
        );

        gate.break_for_peer_failure(work_orders[0]);
        let late_start = CommittedChildStart {
            work_order_id: work_orders[0],
            started_event_id: first_start.started_event_id,
        };
        assert_eq!(
            gate.arrive_after_committed_start(&late_start, &cancellation, &shutdown, None,)
                .await,
            ChildStartGateEnd::Released
        );
    }

    #[tokio::test]
    async fn foreign_identity_fails_closed_and_wakes_an_authorized_waiter() {
        let work_orders = distinct_work_orders();
        let gate = ExactTwoChildStartGate::new(work_orders).expect("distinct authorization");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let authorized_start = committed(work_orders[0]);
        let authorized =
            gate.arrive_after_committed_start(&authorized_start, &cancellation, &shutdown, None);
        tokio::pin!(authorized);
        tokio::select! {
            result = &mut authorized => {
                panic!("authorized waiter unexpectedly completed with {result:?}");
            }
            () = tokio::task::yield_now() => {}
        }

        let foreign_start = committed(ChildWorkOrderId::new());
        let foreign =
            gate.arrive_after_committed_start(&foreign_start, &cancellation, &shutdown, None);
        let (authorized_end, foreign_end) = timeout(Duration::from_secs(1), async {
            tokio::join!(authorized, foreign)
        })
        .await
        .expect("authorization failure must wake the legitimate peer");
        assert_eq!(authorized_end, ChildStartGateEnd::PeerFailed);
        assert_eq!(foreign_end, ChildStartGateEnd::PeerFailed);
    }
}
