//! Provider-neutral backpressure for model-generation effects.
//!
//! This limit is deliberately independent from both run admission and each
//! run's subagent budget. A single scheduler is shared by every supervised
//! run, planner, and child that targets the configured backend.

use std::fmt;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub(crate) struct ModelCallScheduler {
    permits: Arc<Semaphore>,
    maximum_parallel_calls: usize,
}

impl ModelCallScheduler {
    pub(crate) fn new(maximum_parallel_calls: usize) -> Result<Self, ModelCallSchedulerError> {
        if maximum_parallel_calls == 0 {
            return Err(ModelCallSchedulerError::ZeroCapacity);
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(maximum_parallel_calls)),
            maximum_parallel_calls,
        })
    }

    #[must_use]
    pub(crate) const fn maximum_parallel_calls(&self) -> usize {
        self.maximum_parallel_calls
    }

    /// Waits in Tokio's FIFO semaphore queue. The returned permit must remain
    /// alive for the entire provider future. Dropping either this future while
    /// queued or the resulting permit never leaks capacity.
    pub(crate) async fn acquire(
        &self,
        cancellation: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<ModelCallPermit, ModelCallQueueExit> {
        if cancellation.is_cancelled() {
            return Err(ModelCallQueueExit::Cancelled);
        }
        if shutdown.is_cancelled() {
            return Err(ModelCallQueueExit::Shutdown);
        }

        let permit = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(ModelCallQueueExit::Cancelled),
            () = shutdown.cancelled() => return Err(ModelCallQueueExit::Shutdown),
            permit = Arc::clone(&self.permits).acquire_owned() => {
                permit.map_err(|_| ModelCallQueueExit::Closed)?
            }
        };

        // Cancellation may have become observable in the scheduler turn that
        // granted capacity. Give it precedence before the caller can construct
        // a backend future; dropping `permit` returns the lane immediately.
        if cancellation.is_cancelled() {
            return Err(ModelCallQueueExit::Cancelled);
        }
        if shutdown.is_cancelled() {
            return Err(ModelCallQueueExit::Shutdown);
        }
        Ok(ModelCallPermit { _permit: permit })
    }
}

#[derive(Debug)]
pub(crate) struct ModelCallPermit {
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ModelCallQueueExit {
    Cancelled,
    Shutdown,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ModelCallSchedulerError {
    ZeroCapacity,
}

impl fmt::Display for ModelCallSchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => {
                formatter.write_str("model-call capacity must be greater than zero")
            }
        }
    }
}

impl std::error::Error for ModelCallSchedulerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{Barrier, Semaphore as ReleaseSemaphore, mpsc};
    use tokio::task::JoinSet;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn four_backend_calls_run_while_the_fifth_waits_and_capacity_is_reused() {
        let scheduler = ModelCallScheduler::new(4).expect("four lanes are valid");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let active_backend_calls = Arc::new(AtomicUsize::new(0));
        let peak_backend_calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(ReleaseSemaphore::new(0));
        let first_four_ready = Arc::new(Barrier::new(5));
        let (started_sender, mut started_receiver) = mpsc::unbounded_channel();
        let mut calls = JoinSet::new();

        for call_index in 0..4 {
            let scheduler = scheduler.clone();
            let cancellation = cancellation.clone();
            let shutdown = shutdown.clone();
            let active_backend_calls = Arc::clone(&active_backend_calls);
            let peak_backend_calls = Arc::clone(&peak_backend_calls);
            let release = Arc::clone(&release);
            let first_four_ready = Arc::clone(&first_four_ready);
            let started_sender = started_sender.clone();
            calls.spawn(async move {
                let _permit = scheduler
                    .acquire(&cancellation, &shutdown)
                    .await
                    .expect("call acquires a lane");
                let active = active_backend_calls.fetch_add(1, Ordering::SeqCst) + 1;
                peak_backend_calls.fetch_max(active, Ordering::SeqCst);
                started_sender
                    .send(call_index)
                    .expect("observer remains open");
                first_four_ready.wait().await;
                release
                    .acquire()
                    .await
                    .expect("release gate remains open")
                    .forget();
                active_backend_calls.fetch_sub(1, Ordering::SeqCst);
            });
        }

        first_four_ready.wait().await;
        let mut initial = Vec::new();
        for _ in 0..4 {
            initial.push(started_receiver.recv().await.expect("four calls started"));
        }
        initial.sort_unstable();
        assert_eq!(initial, vec![0, 1, 2, 3]);

        {
            let scheduler = scheduler.clone();
            let cancellation = cancellation.clone();
            let shutdown = shutdown.clone();
            let active_backend_calls = Arc::clone(&active_backend_calls);
            let peak_backend_calls = Arc::clone(&peak_backend_calls);
            let release = Arc::clone(&release);
            let started_sender = started_sender.clone();
            calls.spawn(async move {
                let _permit = scheduler
                    .acquire(&cancellation, &shutdown)
                    .await
                    .expect("fifth call eventually acquires a lane");
                let active = active_backend_calls.fetch_add(1, Ordering::SeqCst) + 1;
                peak_backend_calls.fetch_max(active, Ordering::SeqCst);
                started_sender.send(4).expect("observer remains open");
                release
                    .acquire()
                    .await
                    .expect("release gate remains open")
                    .forget();
                active_backend_calls.fetch_sub(1, Ordering::SeqCst);
            });
        }
        drop(started_sender);
        assert!(
            timeout(Duration::from_millis(25), started_receiver.recv())
                .await
                .is_err(),
            "the fifth call must remain queued while all four lanes are held"
        );

        release.add_permits(1);
        assert_eq!(
            timeout(Duration::from_secs(1), started_receiver.recv())
                .await
                .expect("the fifth call starts after capacity returns"),
            Some(4)
        );
        release.add_permits(4);
        while let Some(result) = calls.join_next().await {
            result.expect("simulated model call joins");
        }
        assert_eq!(peak_backend_calls.load(Ordering::SeqCst), 4);
        assert_eq!(active_backend_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_while_queued_never_reaches_the_provider_boundary() {
        let scheduler = ModelCallScheduler::new(1).expect("one lane is valid");
        let holder_cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let holder = scheduler
            .acquire(&holder_cancellation, &shutdown)
            .await
            .expect("holder acquires the only lane");
        let queued_cancellation = CancellationToken::new();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let queued = {
            let scheduler = scheduler.clone();
            let queued_cancellation = queued_cancellation.clone();
            let shutdown = shutdown.clone();
            let provider_calls = Arc::clone(&provider_calls);
            tokio::spawn(async move {
                let _permit = scheduler.acquire(&queued_cancellation, &shutdown).await?;
                provider_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ModelCallQueueExit>(())
            })
        };
        tokio::task::yield_now().await;
        queued_cancellation.cancel();
        assert_eq!(
            queued.await.expect("queued task joins"),
            Err(ModelCallQueueExit::Cancelled)
        );
        drop(holder);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        scheduler
            .acquire(&CancellationToken::new(), &shutdown)
            .await
            .expect("cancelled waiter did not leak the returned lane");
    }

    #[tokio::test]
    async fn shutdown_while_queued_never_reaches_the_provider_boundary() {
        let scheduler = ModelCallScheduler::new(1).expect("one lane is valid");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let holder = scheduler
            .acquire(&cancellation, &shutdown)
            .await
            .expect("holder acquires the only lane");
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let queued = {
            let scheduler = scheduler.clone();
            let cancellation = cancellation.clone();
            let shutdown = shutdown.clone();
            let provider_calls = Arc::clone(&provider_calls);
            tokio::spawn(async move {
                let _permit = scheduler.acquire(&cancellation, &shutdown).await?;
                provider_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ModelCallQueueExit>(())
            })
        };
        tokio::task::yield_now().await;
        shutdown.cancel();
        assert_eq!(
            queued.await.expect("queued task joins"),
            Err(ModelCallQueueExit::Shutdown)
        );
        drop(holder);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn permit_is_returned_when_a_provider_call_errors_or_is_cancelled() {
        let scheduler = ModelCallScheduler::new(1).expect("one lane is valid");
        let cancellation = CancellationToken::new();
        let shutdown = CancellationToken::new();

        let simulated_error: Result<(), &'static str> = async {
            let _permit = scheduler
                .acquire(&cancellation, &shutdown)
                .await
                .expect("erroring call acquires the lane");
            Err::<(), &'static str>("provider error")
        }
        .await;
        assert_eq!(simulated_error, Err("provider error"));

        let acquired = Arc::new(Barrier::new(2));
        let in_flight = {
            let scheduler = scheduler.clone();
            let cancellation = cancellation.clone();
            let shutdown = shutdown.clone();
            let acquired = Arc::clone(&acquired);
            tokio::spawn(async move {
                let _permit = scheduler
                    .acquire(&cancellation, &shutdown)
                    .await
                    .expect("call acquires the lane");
                acquired.wait().await;
                cancellation.cancelled().await;
            })
        };
        acquired.wait().await;
        cancellation.cancel();
        in_flight.await.expect("cancelled call drops its permit");

        scheduler
            .acquire(&CancellationToken::new(), &shutdown)
            .await
            .expect("error and cancellation both returned the lane");
    }

    #[test]
    fn capacity_is_explicit_and_zero_fails_closed() {
        assert_eq!(
            ModelCallScheduler::new(4)
                .expect("four lanes are valid")
                .maximum_parallel_calls(),
            4
        );
        assert!(matches!(
            ModelCallScheduler::new(0),
            Err(ModelCallSchedulerError::ZeroCapacity)
        ));
    }
}
