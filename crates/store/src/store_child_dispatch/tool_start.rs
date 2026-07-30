//! Store-owned durable dispatch-start admission for child repository tools.

use super::super::{
    ChildPendingEffectProjection, ChildRecoveryState, EventEnvelope, EventId, EventPayload,
    MAX_SQLITE_INTEGER_U64, NewEvent, Provenance, Store, StoreError, TransactionBehavior,
    apply_exact_event_envelope_with_admission, child_attempt_clock_accepts, current_run_state,
    durable_run_for_claim_refresh, latest_broker_epoch_before, latest_cancellation_generation,
    latest_claim_for_run, load_child_replay, load_event_by_id,
    preallocate_identified_event_envelope, project_child_work_order,
};
use super::CHILD_TOOL_DISPATCH_START_PRODUCER;
use super::tool::{
    ChildToolDispatchHandoff, ChildToolDispatchMaterial, ChildToolPreparedEvidence, ToolLaneState,
    taint_lane,
};
use birdcode_protocol::{
    ChildToolDispatchStartedV2, RepositoryBrokerInstanceId, RunState, RuntimeClockReading,
};
use birdcode_tooling::project_prepared_event_v2;
use chrono::Utc;
use std::error::Error;
use std::fmt;
use thiserror::Error;

/// Retry-stable identity and runtime clock for one durable dispatch start.
///
/// Store derives every semantic binding from the affine Prepared handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildRepositoryExplorerToolDispatchStartAuthority {
    pub event_id: EventId,
    pub started_at: RuntimeClockReading,
}

/// Durable evidence that one exact broker-v2 dispatch start exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildToolDispatchStartedEvidence {
    pub started_event: Box<EventEnvelope>,
}

/// Evidence-only recovery for a pending broker-v2 tool effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildToolDispatchRecovery {
    pub prepared: ChildToolPreparedEvidence,
    pub started: Option<ChildToolDispatchStartedEvidence>,
}

pub(super) struct ChildToolExecutionMaterial {
    pub(super) dispatch: Box<ChildToolDispatchMaterial>,
    pub(super) started_event: Box<EventEnvelope>,
}

/// Opaque affine authority released only after the durable Started commit.
///
/// This type deliberately exposes no execution method in protocol v9.
///
/// ```compile_fail
/// use birdcode_store::ChildToolExecutionHandoff;
///
/// fn duplicate(value: ChildToolExecutionHandoff) {
///     let _copy = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolExecutionHandoff;
///
/// fn serialize(value: &ChildToolExecutionHandoff) {
///     let _encoded = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolExecutionHandoff;
///
/// let _forged = ChildToolExecutionHandoff::default();
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolExecutionHandoff;
///
/// let _decoded: ChildToolExecutionHandoff = serde_json::from_str("{}").unwrap();
/// ```
#[must_use = "execution authority must later be consumed by a guarded terminal slice"]
pub struct ChildToolExecutionHandoff {
    material: Option<Box<ChildToolExecutionMaterial>>,
}

const _: () =
    assert!(std::mem::size_of::<ChildToolExecutionHandoff>() == std::mem::size_of::<usize>());

impl ChildToolExecutionHandoff {
    pub(super) fn new(material: ChildToolExecutionMaterial) -> Self {
        Self {
            material: Some(Box::new(material)),
        }
    }

    pub(super) fn material(&self) -> &ChildToolExecutionMaterial {
        self.material
            .as_deref()
            .expect("execution handoff material exists until consumed")
    }

    pub(super) fn into_material(mut self) -> ChildToolExecutionMaterial {
        *self
            .material
            .take()
            .expect("execution handoff material exists until consumed")
    }

    /// Returns the exact durable start boundary for this opaque authority.
    #[must_use]
    pub fn started_event(&self) -> &EventEnvelope {
        &self.material().started_event
    }

    /// Returns the broker epoch retained inside the private Prepared bundle.
    #[must_use]
    pub fn broker_instance_id(&self) -> RepositoryBrokerInstanceId {
        self.material()
            .dispatch
            .prepared
            .receipt
            .broker_prepared_at
            .broker_instance_id
    }
}

impl Drop for ChildToolExecutionHandoff {
    fn drop(&mut self) {
        if let Some(material) = &self.material {
            taint_lane(&material.dispatch.lane);
        }
    }
}

/// Closed start result separating fresh execution authority from replay.
#[must_use = "a dispatch start must preserve fresh authority or durable evidence"]
pub enum ChildToolDispatchStartOutcome {
    Appended {
        evidence: ChildToolDispatchStartedEvidence,
        execution: ChildToolExecutionHandoff,
    },
    AlreadyPresent {
        evidence: ChildToolDispatchStartedEvidence,
    },
}

/// Definitely pre-commit reason that preserves the affine Prepared handoff.
#[derive(Debug, Error)]
pub enum ChildToolDispatchStartRejection {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("child repository-tool publication lane is unavailable")]
    LaneUnavailable,
    #[error("child repository-tool broker epoch requires rotation and reconciliation")]
    LaneRequiresReconciliation,
}

/// Start failure distinguishes rolled-back rejection from commit ambiguity.
pub enum ChildToolDispatchStartError {
    Rejected {
        reason: ChildToolDispatchStartRejection,
        dispatch: ChildToolDispatchHandoff,
    },
    NoLongerStartable(ChildToolDispatchStartRejection),
    CommitUncertain(StoreError),
}

impl fmt::Debug for ChildToolDispatchStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason, .. } => formatter
                .debug_struct("Rejected")
                .field("reason", reason)
                .field("dispatch", &"<affine>")
                .finish(),
            Self::CommitUncertain(error) => formatter
                .debug_tuple("CommitUncertain")
                .field(error)
                .finish(),
            Self::NoLongerStartable(error) => formatter
                .debug_tuple("NoLongerStartable")
                .field(error)
                .finish(),
        }
    }
}

impl fmt::Display for ChildToolDispatchStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason, .. } => write!(formatter, "dispatch start rejected: {reason}"),
            Self::CommitUncertain(error) => {
                write!(formatter, "dispatch start commit is uncertain: {error}")
            }
            Self::NoLongerStartable(error) => {
                write!(
                    formatter,
                    "dispatch authority is no longer startable: {error}"
                )
            }
        }
    }
}

impl Error for ChildToolDispatchStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rejected { reason, .. } | Self::NoLongerStartable(reason) => Some(reason),
            Self::CommitUncertain(error) => Some(error),
        }
    }
}

impl ChildToolDispatchStartError {
    /// Recovers the original handoff only after a proven pre-commit rollback.
    ///
    /// # Errors
    ///
    /// Returns the unchanged error when commit status is uncertain or durable
    /// state proved that the dispatch can no longer start.
    pub fn into_rejected(
        self,
    ) -> Result<(ChildToolDispatchStartRejection, ChildToolDispatchHandoff), Self> {
        match self {
            Self::Rejected { reason, dispatch } => Ok((reason, dispatch)),
            uncertain => Err(uncertain),
        }
    }
}

struct DerivedStart {
    event: Box<NewEvent>,
}

fn started_payload(
    prepared: &birdcode_protocol::ChildToolPreparedV2,
    material: &ChildToolDispatchMaterial,
    claim_event: &EventEnvelope,
    claim: &birdcode_protocol::RunClaimed,
    epoch_event: &EventEnvelope,
    pending: &super::PendingChildTool,
    authority: &ChildRepositoryExplorerToolDispatchStartAuthority,
) -> ChildToolDispatchStartedV2 {
    ChildToolDispatchStartedV2 {
        binding: prepared.binding.clone(),
        tool_call_id: prepared.tool_call_id,
        prepared_event_id: material.prepared_event.id,
        action_binding: prepared.action_binding.clone(),
        prepared_receipt_digest: prepared.prepared_receipt_digest.clone(),
        claim_event_id: claim_event.id,
        claim_id: claim.claim_id,
        claim_generation: claim.claim_generation,
        runtime_instance_id: claim.runtime_instance_id,
        cancellation_generation: claim.cancellation_generation,
        broker_epoch_activation_event_id: epoch_event.id,
        broker_instance_id: pending.broker_instance_id,
        started_at: authority.started_at.clone(),
    }
}

pub(super) fn prepared_projection(
    material: &ChildToolDispatchMaterial,
) -> Result<&birdcode_protocol::ChildToolPreparedV2, StoreError> {
    let EventPayload::ChildToolPreparedV2(prepared) = &material.prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if project_prepared_event_v2(&material.prepared).map_err(|_| StoreError::InvalidStateEvent)?
        != *prepared
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(prepared)
}

fn exact_existing_start(
    connection: &rusqlite::Connection,
    artifact_root: &std::path::Path,
    authority: &ChildRepositoryExplorerToolDispatchStartAuthority,
    material: &ChildToolDispatchMaterial,
) -> Result<Option<ChildToolDispatchStartedEvidence>, StoreError> {
    let Some(existing) = load_event_by_id(connection, authority.event_id)? else {
        return Ok(None);
    };
    let prepared = prepared_projection(material)?;
    let EventPayload::ChildToolDispatchStartedV2(started) = &existing.payload else {
        return Err(StoreError::IdentifiedEventConflict);
    };
    if existing.session_id != material.prepared_event.session_id
        || existing.run_id != material.prepared_event.run_id
        || existing.actor_id != material.prepared_event.actor_id
        || existing.provenance.producer != CHILD_TOOL_DISPATCH_START_PRODUCER
        || existing.provenance.backend != material.prepared_event.provenance.backend
        || existing.provenance.raw_artifact.is_some()
        || started.binding != prepared.binding
        || started.tool_call_id != prepared.tool_call_id
        || started.prepared_event_id != material.prepared_event.id
        || started.action_binding != prepared.action_binding
        || started.prepared_receipt_digest != prepared.prepared_receipt_digest
        || started.broker_instance_id != prepared.broker_instance_id
        || started.started_at != authority.started_at
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    load_child_replay(
        connection,
        artifact_root,
        existing.run_id.ok_or(StoreError::InvalidStateEvent)?,
        prepared.binding.work_order_id,
    )?;
    Ok(Some(ChildToolDispatchStartedEvidence {
        started_event: Box::new(existing),
    }))
}

fn persisted_prepared_run_id(
    transaction: &rusqlite::Transaction<'_>,
    material: &ChildToolDispatchMaterial,
) -> Result<birdcode_protocol::RunId, StoreError> {
    let run_id = material
        .prepared_event
        .run_id
        .ok_or(StoreError::InvalidStateEvent)?;
    let persisted = load_event_by_id(transaction, material.prepared_event.id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    if persisted != material.prepared_event {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(run_id)
}

fn run_claim_payload(event: &EventEnvelope) -> Result<&birdcode_protocol::RunClaimed, StoreError> {
    let EventPayload::RunClaimed(claim) = &event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(claim)
}

fn derive_start(
    transaction: &rusqlite::Transaction<'_>,
    artifact_root: &std::path::Path,
    authority: &ChildRepositoryExplorerToolDispatchStartAuthority,
    material: &ChildToolDispatchMaterial,
) -> Result<DerivedStart, StoreError> {
    let prepared = prepared_projection(material)?;
    let run_id = persisted_prepared_run_id(transaction, material)?;
    let (replay, _, _, _) = load_child_replay(
        transaction,
        artifact_root,
        run_id,
        prepared.binding.work_order_id,
    )?;
    let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
    let run = durable_run_for_claim_refresh(transaction, run_id)?;
    let claim_event = latest_claim_for_run(transaction, run.spec.session_id, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let claim = run_claim_payload(&claim_event)?;
    let epoch_event = latest_broker_epoch_before(
        transaction,
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
    if current_run_state(transaction, run.spec.session_id, run_id)? != RunState::Running
        || replay.issued.spec.work_order_id != prepared.binding.work_order_id
        || claim_event.id != replay.active_claim.event_id
        || claim.claim_id != replay.active_claim.claim_id
        || claim.claim_generation != replay.active_claim.generation
        || claim.runtime_instance_id != replay.active_claim.runtime_instance_id
        || claim.cancellation_generation != replay.active_claim.cancellation_generation
        || claim.lease_expires_at != replay.active_claim.lease_expires_at
        || claim.lease_expires_at <= now
        || claim.lease_expires_at <= authority.started_at.observed_at
        || authority.started_at.observed_at > now
        || latest_cancellation_generation(transaction, run.spec.session_id, run_id)?
            != replay.active_claim.cancellation_generation
        || replay
            .issued
            .spec
            .run_deadline
            .is_some_and(|deadline| deadline < now || authority.started_at.observed_at > deadline)
        || authority.started_at.runtime_instance_id != replay.active_claim.runtime_instance_id
        || !child_attempt_clock_accepts(attempt, &authority.started_at)
        || attempt.projection.outcome.is_some()
        || attempt.pending_effect_requires_unknown
        || pending.prepared_event_id != material.prepared_event.id
        || pending.tool_call_id != prepared.tool_call_id
        || pending.action_binding != prepared.action_binding
        || pending.prepared_receipt_digest != prepared.prepared_receipt_digest
        || pending.broker_instance_id != prepared.broker_instance_id
        || pending.started_event_id.is_some()
        || pending.broker_epoch_activation_event_id != Some(epoch_event.id)
        || epoch.state.active_broker_instance_id != pending.broker_instance_id
        || epoch
            .state
            .closed_broker_instance_ids
            .contains(&pending.broker_instance_id)
        || epoch.activated_at.runtime_instance_id != replay.active_claim.runtime_instance_id
        || material.lane.inner.broker.epoch() != &epoch.state
        || material
            .prepared
            .receipt
            .broker_prepared_at
            .broker_instance_id
            != pending.broker_instance_id
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(DerivedStart {
        event: Box::new(NewEvent {
            session_id: run.spec.session_id,
            run_id: Some(run_id),
            actor_id: replay.issued.spec.child_event_actor_id,
            causal_parent: Some(attempt.tail_event_id),
            provenance: Provenance {
                producer: CHILD_TOOL_DISPATCH_START_PRODUCER.to_owned(),
                backend: Some(replay.issued.spec.backend.clone()),
                raw_artifact: None,
            },
            payload: EventPayload::ChildToolDispatchStartedV2(started_payload(
                prepared,
                material,
                &claim_event,
                claim,
                &epoch_event,
                pending,
                authority,
            )),
        }),
    })
}

fn dispatch_remains_startable(
    transaction: &rusqlite::Transaction<'_>,
    artifact_root: &std::path::Path,
    material: &ChildToolDispatchMaterial,
) -> Result<bool, StoreError> {
    let prepared = prepared_projection(material)?;
    let run_id = material
        .prepared_event
        .run_id
        .ok_or(StoreError::InvalidStateEvent)?;
    if load_event_by_id(transaction, material.prepared_event.id)?
        != Some(material.prepared_event.clone())
    {
        return Ok(false);
    }
    let (replay, _, _, _) = load_child_replay(
        transaction,
        artifact_root,
        run_id,
        prepared.binding.work_order_id,
    )?;
    let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
    let run = durable_run_for_claim_refresh(transaction, run_id)?;
    let claim_event = latest_claim_for_run(transaction, run.spec.session_id, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Ok(false);
    };
    let epoch_event = latest_broker_epoch_before(
        transaction,
        run.spec.session_id,
        run_id,
        MAX_SQLITE_INTEGER_U64,
    )?
    .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::RepositoryBrokerEpochActivatedV1(epoch) = &epoch_event.payload else {
        return Ok(false);
    };
    let Some(attempt) = replay.attempts.last() else {
        return Ok(false);
    };
    let Some(pending) = attempt.pending_tool.as_ref() else {
        return Ok(false);
    };
    let now = Utc::now();
    Ok(
        current_run_state(transaction, run.spec.session_id, run_id)? == RunState::Running
            && claim_event.id == replay.active_claim.event_id
            && claim.claim_id == replay.active_claim.claim_id
            && claim.claim_generation == replay.active_claim.generation
            && claim.runtime_instance_id == replay.active_claim.runtime_instance_id
            && claim.cancellation_generation == replay.active_claim.cancellation_generation
            && claim.lease_expires_at == replay.active_claim.lease_expires_at
            && claim.lease_expires_at > now
            && latest_cancellation_generation(transaction, run.spec.session_id, run_id)?
                == replay.active_claim.cancellation_generation
            && replay
                .issued
                .spec
                .run_deadline
                .is_none_or(|deadline| deadline >= now)
            && attempt.projection.outcome.is_none()
            && !attempt.pending_effect_requires_unknown
            && pending.prepared_event_id == material.prepared_event.id
            && pending.tool_call_id == prepared.tool_call_id
            && pending.action_binding == prepared.action_binding
            && pending.prepared_receipt_digest == prepared.prepared_receipt_digest
            && pending.broker_instance_id == prepared.broker_instance_id
            && pending.started_event_id.is_none()
            && pending.broker_epoch_activation_event_id == Some(epoch_event.id)
            && epoch.state.active_broker_instance_id == pending.broker_instance_id
            && !epoch
                .state
                .closed_broker_instance_ids
                .contains(&pending.broker_instance_id)
            && epoch.activated_at.runtime_instance_id == replay.active_claim.runtime_instance_id
            && material.lane.inner.broker.epoch() == &epoch.state,
    )
}

fn rejected(
    reason: impl Into<ChildToolDispatchStartRejection>,
    dispatch: ChildToolDispatchHandoff,
) -> ChildToolDispatchStartError {
    ChildToolDispatchStartError::Rejected {
        reason: reason.into(),
        dispatch,
    }
}

fn lane_requires_reconciliation() -> ChildToolDispatchStartError {
    ChildToolDispatchStartError::NoLongerStartable(
        ChildToolDispatchStartRejection::LaneRequiresReconciliation,
    )
}

fn rollback_for_lane_reconciliation(
    transaction: rusqlite::Transaction<'_>,
) -> ChildToolDispatchStartError {
    match transaction.rollback() {
        Ok(()) => lane_requires_reconciliation(),
        Err(error) => ChildToolDispatchStartError::CommitUncertain(StoreError::from(error)),
    }
}

fn rollback_rejection(
    transaction: rusqlite::Transaction<'_>,
    artifact_root: &std::path::Path,
    error: StoreError,
    dispatch: ChildToolDispatchHandoff,
) -> ChildToolDispatchStartError {
    let remains_startable =
        dispatch_remains_startable(&transaction, artifact_root, &dispatch.material)
            .unwrap_or(false);
    match transaction.rollback() {
        Ok(()) if remains_startable => rejected(error, dispatch),
        Ok(()) => ChildToolDispatchStartError::NoLongerStartable(error.into()),
        Err(rollback) => ChildToolDispatchStartError::CommitUncertain(StoreError::from(rollback)),
    }
}

fn preallocate_start_envelope(
    transaction: &rusqlite::Transaction<'_>,
    event_id: EventId,
    event: Box<NewEvent>,
) -> Result<Box<EventEnvelope>, StoreError> {
    preallocate_identified_event_envelope(transaction, event_id, *event).map(Box::new)
}

fn commit_derived_start(
    transaction: rusqlite::Transaction<'_>,
    artifact_root: &std::path::Path,
    authority: &ChildRepositoryExplorerToolDispatchStartAuthority,
    dispatch: ChildToolDispatchHandoff,
    lane_guard: std::sync::MutexGuard<'_, ToolLaneState>,
    derived: DerivedStart,
) -> Result<ChildToolDispatchStartOutcome, ChildToolDispatchStartError> {
    let envelope = match preallocate_start_envelope(&transaction, authority.event_id, derived.event)
    {
        Ok(envelope) => envelope,
        Err(error) => {
            return Err(rollback_rejection(
                transaction,
                artifact_root,
                error,
                dispatch,
            ));
        }
    };
    if let Err(error) = apply_exact_event_envelope_with_admission(
        &transaction,
        artifact_root,
        &envelope,
        super::super::EventAdmission::ChildToolDispatchStart,
    ) {
        return match transaction.rollback() {
            Ok(()) => Err(rejected(error, dispatch)),
            Err(rollback) => Err(ChildToolDispatchStartError::CommitUncertain(
                StoreError::from(rollback),
            )),
        };
    }
    if let Err(error) = transaction.commit() {
        return Err(ChildToolDispatchStartError::CommitUncertain(
            StoreError::from(error),
        ));
    }
    drop(lane_guard);
    let evidence = ChildToolDispatchStartedEvidence {
        started_event: envelope.clone(),
    };
    Ok(ChildToolDispatchStartOutcome::Appended {
        evidence,
        execution: ChildToolExecutionHandoff::new(ChildToolExecutionMaterial {
            dispatch: dispatch.material,
            started_event: envelope,
        }),
    })
}

fn start_missing_dispatch(
    connection: &mut rusqlite::Connection,
    artifact_root: &std::path::Path,
    authority: &ChildRepositoryExplorerToolDispatchStartAuthority,
    dispatch: ChildToolDispatchHandoff,
    lane_guard: std::sync::MutexGuard<'_, ToolLaneState>,
) -> Result<ChildToolDispatchStartOutcome, ChildToolDispatchStartError> {
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) if *lane_guard == ToolLaneState::Active => {
            return Err(rejected(StoreError::from(error), dispatch));
        }
        Err(_) => return Err(lane_requires_reconciliation()),
    };
    match exact_existing_start(&transaction, artifact_root, authority, &dispatch.material) {
        Ok(Some(evidence)) => {
            return match transaction.rollback() {
                Ok(()) => Ok(ChildToolDispatchStartOutcome::AlreadyPresent { evidence }),
                Err(error) => Err(ChildToolDispatchStartError::CommitUncertain(
                    StoreError::from(error),
                )),
            };
        }
        Ok(None) => {}
        Err(error) => {
            if *lane_guard != ToolLaneState::Active {
                return Err(rollback_for_lane_reconciliation(transaction));
            }
            return Err(rollback_rejection(
                transaction,
                artifact_root,
                error,
                dispatch,
            ));
        }
    }
    if *lane_guard != ToolLaneState::Active {
        return Err(rollback_for_lane_reconciliation(transaction));
    }
    let derived = match derive_start(&transaction, artifact_root, authority, &dispatch.material) {
        Ok(derived) => derived,
        Err(error) => {
            return Err(rollback_rejection(
                transaction,
                artifact_root,
                error,
                dispatch,
            ));
        }
    };
    commit_derived_start(
        transaction,
        artifact_root,
        authority,
        dispatch,
        lane_guard,
        derived,
    )
}

impl Store {
    /// Durably fences one exact Prepared-v2 call before any repository effect.
    ///
    /// The stored lane lock and `SQLite` immediate transaction stay held
    /// through validation and commit. Exact replay returns evidence only.
    ///
    /// # Errors
    ///
    /// Proven pre-commit rejection returns the original affine handoff.
    /// Commit ambiguity destroys authority and requires evidence-only recovery.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes retry authority"
    )]
    pub fn start_child_repository_explorer_tool_dispatch(
        &mut self,
        authority: ChildRepositoryExplorerToolDispatchStartAuthority,
        dispatch: ChildToolDispatchHandoff,
    ) -> Result<ChildToolDispatchStartOutcome, ChildToolDispatchStartError> {
        let artifact_root = self.artifact_root.clone();
        // Evidence-only replay precedes lane health. Every mutating path then
        // preserves Prepare's lane -> immediate-transaction lock order and
        // repeats the identity read under that transaction.
        match exact_existing_start(
            &self.connection,
            &artifact_root,
            &authority,
            &dispatch.material,
        ) {
            Ok(Some(evidence)) => {
                return Ok(ChildToolDispatchStartOutcome::AlreadyPresent { evidence });
            }
            Ok(None) => {}
            Err(error) => {
                return Err(ChildToolDispatchStartError::NoLongerStartable(error.into()));
            }
        }
        let lane = dispatch.material.lane.clone();
        let Ok(lane_state) = lane.inner.publication.lock() else {
            return Err(ChildToolDispatchStartError::NoLongerStartable(
                ChildToolDispatchStartRejection::LaneUnavailable,
            ));
        };
        start_missing_dispatch(
            &mut self.connection,
            &artifact_root,
            &authority,
            dispatch,
            lane_state,
        )
    }

    /// Recovers Prepared and optional Started evidence without effect authority.
    ///
    /// # Errors
    ///
    /// Returns an error for contradictory replay or retained artifact drift.
    pub fn recover_child_repository_explorer_tool_dispatch(
        &self,
        run_id: birdcode_protocol::RunId,
        work_order_id: birdcode_protocol::ChildWorkOrderId,
    ) -> Result<Option<ChildToolDispatchRecovery>, StoreError> {
        let Some(projection) =
            project_child_work_order(&self.connection, &self.artifact_root, run_id, work_order_id)?
        else {
            return Ok(None);
        };
        let ChildRecoveryState::PendingEffect(ChildPendingEffectProjection::Tool {
            prepared_event,
            started_event,
        }) = projection.recovery
        else {
            return Ok(None);
        };
        if !matches!(prepared_event.payload, EventPayload::ChildToolPreparedV2(_)) {
            return Ok(None);
        }
        Ok(Some(ChildToolDispatchRecovery {
            prepared: ChildToolPreparedEvidence { prepared_event },
            started: started_event
                .map(|started_event| ChildToolDispatchStartedEvidence { started_event }),
        }))
    }
}

#[cfg(test)]
#[path = "../tests/child_tool_dispatch_start_authority.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/child_tool_dispatch_start_edges.rs"]
mod edge_tests;
