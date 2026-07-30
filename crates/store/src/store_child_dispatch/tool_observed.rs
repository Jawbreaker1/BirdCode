//! Guarded repository-tool execution and durable known-terminal publication.

use super::super::{
    EventEnvelope, EventId, EventPayload, MAX_SQLITE_INTEGER_U64, NewEvent, Provenance, RunState,
    Store, StoreError, apply_exact_event_envelope_with_admission, child_attempt_clock_accepts,
    current_run_state, durable_run_for_claim_refresh, latest_broker_epoch_before,
    latest_cancellation_generation, latest_claim_for_run, load_child_replay, load_event_by_id,
    preallocate_identified_event_envelope,
};
use super::tool::{retained_artifact, taint_lane};
use super::tool_start::{
    ChildToolExecutionHandoff, ChildToolExecutionMaterial, prepared_projection,
};
use super::{
    CHILD_REPOSITORY_TOOL_PREPARATION_PRODUCER, CHILD_TOOL_DISPATCH_START_PRODUCER,
    CHILD_TOOL_OBSERVED_PRODUCER,
};
use birdcode_protocol::{ArtifactRef, RuntimeClockReading};
use birdcode_tooling::{
    ObservedRepositoryToolCallV2, RepositoryBrokerErrorV2, RepositoryToolExecuteErrorV2,
    RepositoryToolExecuteInputV2, RepositoryToolTerminalV2, project_observed_event_v2,
    verify_terminal_output_v2,
};
use chrono::Utc;
use rusqlite::TransactionBehavior;
use std::error::Error;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use thiserror::Error;

/// Retry-stable identity for one durable known terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildRepositoryExplorerToolObservedCommitAuthority {
    pub event_id: EventId,
}

/// Durable evidence that the exact known terminal is committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildToolObservedEvidence {
    pub observed_event: Box<EventEnvelope>,
}

/// A definitely pre-effect failure for which the same execution handoff is safe.
#[derive(Debug, Error)]
pub enum ChildToolExecutionRejection {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Broker(#[from] RepositoryBrokerErrorV2),
}

/// Why a durable Started call now requires explicit terminal reconciliation.
#[derive(Debug, Error)]
pub enum ChildToolExecutionRecoveryReason {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Broker(#[from] RepositoryBrokerErrorV2),
    #[error("repository broker or finish-clock callback panicked after dispatch admission")]
    ExecutionPanicked,
    #[error("repository broker returned an invalid known terminal")]
    InvalidTerminal,
    #[error("repository broker returned an Unknown terminal from the known-result execution path")]
    UnexpectedUnknownTerminal,
}

/// Evidence-only recovery boundary after execution authority has been destroyed.
#[derive(Debug)]
pub struct ChildToolExecutionRecovery {
    pub started: super::ChildToolDispatchStartedEvidence,
    pub reason: ChildToolExecutionRecoveryReason,
}

/// Execution failure distinguishes safe pre-effect retry from reconciliation.
pub enum ChildToolExecutionError {
    Rejected {
        reason: ChildToolExecutionRejection,
        execution: ChildToolExecutionHandoff,
    },
    RecoveryRequired(ChildToolExecutionRecovery),
}

impl fmt::Debug for ChildToolExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason, .. } => formatter
                .debug_struct("Rejected")
                .field("reason", reason)
                .field("execution", &"<affine>")
                .finish(),
            Self::RecoveryRequired(recovery) => formatter
                .debug_tuple("RecoveryRequired")
                .field(recovery)
                .finish(),
        }
    }
}

impl fmt::Display for ChildToolExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason, .. } => write!(formatter, "tool execution rejected: {reason}"),
            Self::RecoveryRequired(recovery) => {
                write!(
                    formatter,
                    "tool execution requires recovery: {}",
                    recovery.reason
                )
            }
        }
    }
}

impl Error for ChildToolExecutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rejected { reason, .. } => Some(reason),
            Self::RecoveryRequired(recovery) => Some(&recovery.reason),
        }
    }
}

impl ChildToolExecutionError {
    /// Recovers execution authority only when no effect began.
    ///
    /// # Errors
    ///
    /// Returns the unchanged recovery error after an indeterminate boundary.
    pub fn into_rejected(
        self,
    ) -> Result<(ChildToolExecutionRejection, ChildToolExecutionHandoff), Self> {
        match self {
            Self::Rejected { reason, execution } => Ok((reason, execution)),
            recovery @ Self::RecoveryRequired(_) => Err(recovery),
        }
    }
}

struct ChildToolObservedCommitMaterial {
    execution: ChildToolExecutionMaterial,
    observed: ObservedRepositoryToolCallV2,
}

/// Affine known-result authority; dropping it taints the broker publication lane.
///
/// ```compile_fail
/// use birdcode_store::ChildToolObservedCommitHandoff;
///
/// fn duplicate(value: ChildToolObservedCommitHandoff) {
///     let _copy = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolObservedCommitHandoff;
///
/// let _forged = ChildToolObservedCommitHandoff::default();
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolObservedCommitHandoff;
///
/// fn serialize(value: &ChildToolObservedCommitHandoff) {
///     let _encoded = serde_json::to_string(value).unwrap();
/// }
/// ```
#[must_use = "a known repository-tool result must be durably committed or explicitly recovered"]
pub struct ChildToolObservedCommitHandoff {
    material: Option<Box<ChildToolObservedCommitMaterial>>,
}

const _: () =
    assert!(std::mem::size_of::<ChildToolObservedCommitHandoff>() == std::mem::size_of::<usize>());

impl ChildToolObservedCommitHandoff {
    fn new(execution: ChildToolExecutionMaterial, observed: ObservedRepositoryToolCallV2) -> Self {
        Self {
            material: Some(Box::new(ChildToolObservedCommitMaterial {
                execution,
                observed,
            })),
        }
    }

    fn material(&self) -> &ChildToolObservedCommitMaterial {
        self.material
            .as_deref()
            .expect("observed handoff material exists until consumed")
    }

    fn disarm(&mut self) -> Box<ChildToolObservedCommitMaterial> {
        self.material
            .take()
            .expect("observed handoff material exists until consumed")
    }

    /// Returns the durable start boundary that authorized this result.
    #[must_use]
    pub fn started_event(&self) -> &EventEnvelope {
        &self.material().execution.started_event
    }

    /// Returns the exact terminal receipt reference awaiting Store commit.
    #[must_use]
    pub fn terminal_receipt_artifact(&self) -> &ArtifactRef {
        &self.material().observed.terminal_receipt.artifact
    }
}

impl Drop for ChildToolObservedCommitHandoff {
    fn drop(&mut self) {
        if let Some(material) = &self.material {
            taint_lane(&material.execution.dispatch.lane);
        }
    }
}

/// Closed durable publication result for one known terminal.
#[derive(Debug)]
#[must_use = "known-terminal publication returns durable evidence"]
pub enum ChildToolObservedCommitOutcome {
    Appended { evidence: ChildToolObservedEvidence },
    AlreadyPresent { evidence: ChildToolObservedEvidence },
}

/// Known-terminal commit failure preserves the result only after proven rollback.
pub enum ChildToolObservedCommitError {
    Rejected {
        reason: StoreError,
        observed: ChildToolObservedCommitHandoff,
    },
    CommitUncertain(StoreError),
}

impl fmt::Debug for ChildToolObservedCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason, .. } => formatter
                .debug_struct("Rejected")
                .field("reason", reason)
                .field("observed", &"<affine>")
                .finish(),
            Self::CommitUncertain(error) => formatter
                .debug_tuple("CommitUncertain")
                .field(error)
                .finish(),
        }
    }
}

impl fmt::Display for ChildToolObservedCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason, .. } => {
                write!(formatter, "known tool terminal was not committed: {reason}")
            }
            Self::CommitUncertain(error) => {
                write!(
                    formatter,
                    "known tool terminal commit is uncertain: {error}"
                )
            }
        }
    }
}

impl Error for ChildToolObservedCommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rejected { reason, .. } | Self::CommitUncertain(reason) => Some(reason),
        }
    }
}

impl ChildToolObservedCommitError {
    /// Recovers the known result only after a proven pre-commit rollback.
    ///
    /// # Errors
    ///
    /// Returns the unchanged error when commit status is uncertain.
    pub fn into_rejected(self) -> Result<(StoreError, ChildToolObservedCommitHandoff), Self> {
        match self {
            Self::Rejected { reason, observed } => Ok((reason, observed)),
            uncertain @ Self::CommitUncertain(_) => Err(uncertain),
        }
    }
}

fn run_claim(event: &EventEnvelope) -> Result<&birdcode_protocol::RunClaimed, StoreError> {
    let EventPayload::RunClaimed(claim) = &event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(claim)
}

fn preflight_execution(
    connection: &rusqlite::Connection,
    artifact_root: &std::path::Path,
    material: &ChildToolExecutionMaterial,
) -> Result<(), StoreError> {
    let prepared = prepared_projection(&material.dispatch)?;
    let EventPayload::ChildToolDispatchStartedV2(started) = &material.started_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if load_event_by_id(connection, material.dispatch.prepared_event.id)?
        != Some(material.dispatch.prepared_event.clone())
        || load_event_by_id(connection, material.started_event.id)?
            != Some((*material.started_event).clone())
        || material.dispatch.prepared_event.provenance.producer
            != CHILD_REPOSITORY_TOOL_PREPARATION_PRODUCER
        || material.started_event.provenance.producer != CHILD_TOOL_DISPATCH_START_PRODUCER
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let run_id = material
        .started_event
        .run_id
        .ok_or(StoreError::InvalidStateEvent)?;
    let (replay, _, _, _) = load_child_replay(
        connection,
        artifact_root,
        run_id,
        prepared.binding.work_order_id,
    )?;
    let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
    let run = durable_run_for_claim_refresh(connection, run_id)?;
    let claim_event = latest_claim_for_run(connection, run.spec.session_id, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let claim = run_claim(&claim_event)?;
    let epoch_event = latest_broker_epoch_before(
        connection,
        run.spec.session_id,
        run_id,
        MAX_SQLITE_INTEGER_U64,
    )?
    .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::RepositoryBrokerEpochActivatedV1(epoch) = &epoch_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let attempt = replay
        .attempts
        .last()
        .ok_or(StoreError::InvalidStateEvent)?;
    let pending = attempt
        .pending_tool
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    let now = Utc::now();
    if current_run_state(connection, run.spec.session_id, run_id)? != RunState::Running
        || claim_event.id != replay.active_claim.event_id
        || claim.runtime_instance_id != replay.active_claim.runtime_instance_id
        || claim.runtime_instance_id != started.runtime_instance_id
        || claim.cancellation_generation != replay.active_claim.cancellation_generation
        || claim.cancellation_generation != started.cancellation_generation
        || claim.lease_expires_at != replay.active_claim.lease_expires_at
        || claim.lease_expires_at <= now
        || latest_cancellation_generation(connection, run.spec.session_id, run_id)?
            != claim.cancellation_generation
        || replay
            .issued
            .spec
            .run_deadline
            .is_some_and(|deadline| deadline < now)
        || attempt.projection.outcome.is_some()
        || attempt.pending_effect_requires_unknown
        || pending.prepared_event_id != material.dispatch.prepared_event.id
        || pending.tool_call_id != prepared.tool_call_id
        || pending.action_binding != prepared.action_binding
        || pending.prepared_receipt_digest != prepared.prepared_receipt_digest
        || pending.started_event_id != Some(material.started_event.id)
        || pending.broker_epoch_activation_event_id
            != Some(started.broker_epoch_activation_event_id)
        || epoch_event.id != started.broker_epoch_activation_event_id
        || epoch.state.active_broker_instance_id != pending.broker_instance_id
        || epoch
            .state
            .closed_broker_instance_ids
            .contains(&pending.broker_instance_id)
        || material.dispatch.lane.inner.broker.epoch() != &epoch.state
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn recovery_required(
    execution: ChildToolExecutionHandoff,
    reason: ChildToolExecutionRecoveryReason,
) -> ChildToolExecutionError {
    let material = execution.into_material();
    taint_lane(&material.dispatch.lane);
    let started = super::ChildToolDispatchStartedEvidence {
        started_event: material.started_event.clone(),
    };
    drop(material);
    ChildToolExecutionError::RecoveryRequired(ChildToolExecutionRecovery { started, reason })
}

fn terminal_clock_is_valid(
    material: &ChildToolExecutionMaterial,
    observed: &ObservedRepositoryToolCallV2,
) -> bool {
    let EventPayload::ChildToolDispatchStartedV2(started) = &material.started_event.payload else {
        return false;
    };
    let finished = &observed.receipt.runtime_finished_at;
    finished.runtime_instance_id == started.runtime_instance_id
        && finished.monotonic_nanos >= started.started_at.monotonic_nanos
        && finished.observed_at >= started.started_at.observed_at
        && finished.observed_at <= Utc::now()
}

fn exact_existing_observation(
    connection: &rusqlite::Connection,
    artifact_root: &std::path::Path,
    authority: &ChildRepositoryExplorerToolObservedCommitAuthority,
    material: &ChildToolObservedCommitMaterial,
) -> Result<Option<ChildToolObservedEvidence>, StoreError> {
    let Some(existing) = load_event_by_id(connection, authority.event_id)? else {
        return Ok(None);
    };
    let payload =
        project_observed_event_v2(&material.execution.dispatch.prepared, &material.observed)
            .map_err(|_| StoreError::InvalidStateEvent)?;
    let started = &material.execution.started_event;
    if existing.session_id != started.session_id
        || existing.run_id != started.run_id
        || existing.actor_id != started.actor_id
        || existing.provenance.producer != CHILD_TOOL_OBSERVED_PRODUCER
        || existing.provenance.backend
            != material
                .execution
                .dispatch
                .prepared_event
                .provenance
                .backend
        || existing.provenance.raw_artifact
            != Some(material.observed.terminal_receipt.artifact.clone())
        || existing.payload != EventPayload::ChildToolObservedV2(payload.clone())
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    load_child_replay(
        connection,
        artifact_root,
        existing.run_id.ok_or(StoreError::InvalidStateEvent)?,
        payload.binding.work_order_id,
    )?;
    Ok(Some(ChildToolObservedEvidence {
        observed_event: Box::new(existing),
    }))
}

fn derive_observed_event(
    transaction: &rusqlite::Transaction<'_>,
    artifact_root: &std::path::Path,
    material: &ChildToolObservedCommitMaterial,
) -> Result<Box<NewEvent>, StoreError> {
    let prepared = prepared_projection(&material.execution.dispatch)?;
    let started_event = &material.execution.started_event;
    if load_event_by_id(transaction, material.execution.dispatch.prepared_event.id)?
        != Some(material.execution.dispatch.prepared_event.clone())
        || load_event_by_id(transaction, started_event.id)? != Some((**started_event).clone())
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let payload =
        project_observed_event_v2(&material.execution.dispatch.prepared, &material.observed)
            .map_err(|_| StoreError::InvalidStateEvent)?;
    let run_id = started_event.run_id.ok_or(StoreError::InvalidStateEvent)?;
    let (replay, _, _, _) = load_child_replay(
        transaction,
        artifact_root,
        run_id,
        prepared.binding.work_order_id,
    )?;
    let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
    let attempt = replay
        .attempts
        .last()
        .ok_or(StoreError::InvalidStateEvent)?;
    let pending = attempt
        .pending_tool
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    if attempt.projection.outcome.is_some()
        || attempt.pending_effect_requires_unknown
        || pending.prepared_event_id != material.execution.dispatch.prepared_event.id
        || pending.started_event_id != Some(started_event.id)
        || payload.finished_at.runtime_instance_id != replay.active_claim.runtime_instance_id
        || !child_attempt_clock_accepts(attempt, &payload.finished_at)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(Box::new(NewEvent {
        session_id: started_event.session_id,
        run_id: Some(run_id),
        actor_id: started_event.actor_id,
        causal_parent: Some(started_event.id),
        provenance: Provenance {
            producer: CHILD_TOOL_OBSERVED_PRODUCER.to_owned(),
            backend: material
                .execution
                .dispatch
                .prepared_event
                .provenance
                .backend
                .clone(),
            raw_artifact: Some(material.observed.terminal_receipt.artifact.clone()),
        },
        payload: EventPayload::ChildToolObservedV2(payload),
    }))
}

fn reject_observed(
    reason: StoreError,
    observed: ChildToolObservedCommitHandoff,
) -> ChildToolObservedCommitError {
    ChildToolObservedCommitError::Rejected { reason, observed }
}

fn uncertain_observed(
    reason: StoreError,
    mut observed: ChildToolObservedCommitHandoff,
) -> ChildToolObservedCommitError {
    let material = observed.disarm();
    taint_lane(&material.execution.dispatch.lane);
    drop(material);
    ChildToolObservedCommitError::CommitUncertain(reason)
}

impl Store {
    /// Executes one exact durable Started call through its descriptor-confined broker.
    ///
    /// No Store transaction or publication-lane lock is held across the
    /// repository read, so independent child calls can run in parallel.
    ///
    /// # Errors
    ///
    /// A proven pre-effect rejection returns the same affine authority.
    /// Any post-consumption ambiguity destroys it and requires typed recovery.
    pub fn execute_child_repository_explorer_tool_dispatch<F>(
        &mut self,
        execution: ChildToolExecutionHandoff,
        runtime_finished_at: F,
    ) -> Result<ChildToolObservedCommitHandoff, ChildToolExecutionError>
    where
        F: FnOnce() -> RuntimeClockReading + Send + 'static,
    {
        let transaction = match self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
        {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(ChildToolExecutionError::Rejected {
                    reason: StoreError::from(error).into(),
                    execution,
                });
            }
        };
        let preflight =
            preflight_execution(&transaction, &self.artifact_root, execution.material());
        let rollback = transaction.rollback().map_err(StoreError::from);
        if let Err(error) = preflight {
            if error.is_retryable() {
                return Err(ChildToolExecutionError::Rejected {
                    reason: error.into(),
                    execution,
                });
            }
            return Err(recovery_required(execution, error.into()));
        }
        if let Err(error) = rollback {
            return Err(ChildToolExecutionError::Rejected {
                reason: error.into(),
                execution,
            });
        }
        if !execution.material().dispatch.lane.is_healthy() {
            return Err(recovery_required(
                execution,
                StoreError::InvalidStateEvent.into(),
            ));
        }
        let input = RepositoryToolExecuteInputV2 {
            prepared: execution.material().dispatch.prepared.clone(),
            prepared_event_id: execution.material().dispatch.prepared_event.id,
        };
        let terminal = catch_unwind(AssertUnwindSafe(|| {
            execution
                .material()
                .dispatch
                .lane
                .inner
                .broker
                .execute_classified(input, Box::new(runtime_finished_at))
        }));
        let terminal = match terminal {
            Ok(Ok(terminal)) => terminal,
            Ok(Err(RepositoryToolExecuteErrorV2::NotStarted(error)))
                if error == RepositoryBrokerErrorV2::BrokerStateUnavailable =>
            {
                return Err(ChildToolExecutionError::Rejected {
                    reason: error.into(),
                    execution,
                });
            }
            Ok(Err(
                RepositoryToolExecuteErrorV2::NotStarted(error)
                | RepositoryToolExecuteErrorV2::OutcomeIndeterminate(error),
            )) => {
                return Err(recovery_required(execution, error.into()));
            }
            Err(_) => {
                return Err(recovery_required(
                    execution,
                    ChildToolExecutionRecoveryReason::ExecutionPanicked,
                ));
            }
        };
        if !verify_terminal_output_v2(&execution.material().dispatch.prepared, &terminal) {
            return Err(recovery_required(
                execution,
                ChildToolExecutionRecoveryReason::InvalidTerminal,
            ));
        }
        let RepositoryToolTerminalV2::Observed(observed) = terminal else {
            return Err(recovery_required(
                execution,
                ChildToolExecutionRecoveryReason::UnexpectedUnknownTerminal,
            ));
        };
        if !terminal_clock_is_valid(execution.material(), &observed) {
            return Err(recovery_required(
                execution,
                ChildToolExecutionRecoveryReason::InvalidTerminal,
            ));
        }
        Ok(ChildToolObservedCommitHandoff::new(
            execution.into_material(),
            observed,
        ))
    }

    /// Durably publishes one exact broker-validated known terminal.
    ///
    /// A failed transaction returns the same known-result handoff only when
    /// rollback is proven. It never recreates execution authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChildToolObservedCommitError::CommitUncertain`] when durable
    /// commit status cannot be proven, tainting the broker lane.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes affine result authority"
    )]
    pub fn commit_child_repository_explorer_tool_observation(
        &mut self,
        authority: ChildRepositoryExplorerToolObservedCommitAuthority,
        mut observed: ChildToolObservedCommitHandoff,
    ) -> Result<ChildToolObservedCommitOutcome, ChildToolObservedCommitError> {
        match exact_existing_observation(
            &self.connection,
            &self.artifact_root,
            &authority,
            observed.material(),
        ) {
            Ok(Some(evidence)) => {
                drop(observed.disarm());
                return Ok(ChildToolObservedCommitOutcome::AlreadyPresent { evidence });
            }
            Ok(None) => {}
            Err(error) => return Err(reject_observed(error, observed)),
        }
        for artifact in &observed.material().observed.supporting_artifacts {
            if let Err(error) = retained_artifact(&self.artifact_root, artifact) {
                return Err(reject_observed(error, observed));
            }
        }
        if let Err(error) = retained_artifact(
            &self.artifact_root,
            &observed.material().observed.terminal_receipt,
        ) {
            return Err(reject_observed(error, observed));
        }
        let transaction = match self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(error) => return Err(reject_observed(error.into(), observed)),
        };
        match exact_existing_observation(
            &transaction,
            &self.artifact_root,
            &authority,
            observed.material(),
        ) {
            Ok(Some(evidence)) => {
                return match transaction.rollback() {
                    Ok(()) => {
                        drop(observed.disarm());
                        Ok(ChildToolObservedCommitOutcome::AlreadyPresent { evidence })
                    }
                    Err(error) => Err(uncertain_observed(error.into(), observed)),
                };
            }
            Ok(None) => {}
            Err(error) => {
                return match transaction.rollback() {
                    Ok(()) => Err(reject_observed(error, observed)),
                    Err(rollback) => Err(uncertain_observed(rollback.into(), observed)),
                };
            }
        }
        let event =
            match derive_observed_event(&transaction, &self.artifact_root, observed.material()) {
                Ok(event) => event,
                Err(error) => {
                    return match transaction.rollback() {
                        Ok(()) => Err(reject_observed(error, observed)),
                        Err(rollback) => Err(uncertain_observed(rollback.into(), observed)),
                    };
                }
            };
        let envelope =
            match preallocate_identified_event_envelope(&transaction, authority.event_id, *event) {
                Ok(envelope) => Box::new(envelope),
                Err(error) => {
                    return match transaction.rollback() {
                        Ok(()) => Err(reject_observed(error, observed)),
                        Err(rollback) => Err(uncertain_observed(rollback.into(), observed)),
                    };
                }
            };
        if let Err(error) = apply_exact_event_envelope_with_admission(
            &transaction,
            &self.artifact_root,
            &envelope,
            super::super::EventAdmission::ChildToolObserved,
        ) {
            return match transaction.rollback() {
                Ok(()) => Err(reject_observed(error, observed)),
                Err(rollback) => Err(uncertain_observed(rollback.into(), observed)),
            };
        }
        if let Err(error) = transaction.commit() {
            return Err(uncertain_observed(error.into(), observed));
        }
        drop(observed.disarm());
        Ok(ChildToolObservedCommitOutcome::Appended {
            evidence: ChildToolObservedEvidence {
                observed_event: envelope,
            },
        })
    }
}

#[cfg(test)]
#[path = "../tests/child_tool_observed.rs"]
mod tests;
