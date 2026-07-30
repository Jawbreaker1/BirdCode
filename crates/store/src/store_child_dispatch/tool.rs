//! Store-owned child repository-tool preparation and dispatch authority.

use super::super::{
    CHILD_RECONNAISSANCE_CONTRACT_VERSION, CHILD_VALIDATED_ACTION_MEDIA_TYPE, ChildToolCallId,
    ChildValidatedActionBindingV1, ChildValidatedActionDocumentV1, ChildWorkOrderId, EventEnvelope,
    EventId, EventPayload, IdentifiedNewEvent, MAX_SQLITE_INTEGER_U64, NewEvent, Provenance, RunId,
    Store, StoreError, apply_exact_event_envelope_with_admission, artifact_digest,
    child_attempt_clock_accepts, child_execution_binding, current_run_state,
    decode_canonical_event, durable_run_for_claim_refresh, latest_broker_epoch_before,
    latest_cancellation_generation, latest_claim_for_run, load_child_replay, load_event_by_id,
    preallocate_identified_event_envelope, put_artifact_at,
    validate_child_action_against_authority,
};
use super::CHILD_REPOSITORY_TOOL_PREPARATION_PRODUCER;
use birdcode_protocol::{
    ArtifactRef, ChildRepositoryAuthorityV1, ChildValidatedActionId,
    REPOSITORY_BROKER_CONTRACT_VERSION, REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES,
    RepositoryBrokerEpochStateV1, RepositoryBrokerInstanceId,
    RepositoryToolAuthorizationDecisionV2, RepositoryToolCanonicalParametersV1,
    RepositoryToolReceiptAuthorityV2, RunState, RuntimeClockReading, Sha256Digest,
};
use birdcode_tooling::{
    PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2, RepositoryToolBroker,
    RepositoryToolExecuteErrorV2, RepositoryToolExecuteInputV2, RepositoryToolPrepareInputV2,
    RepositoryToolTerminalV2, RetainedArtifactV2, project_prepared_event_v2,
};
use chrono::Utc;
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Runtime-owned retry-stable identities and clock authority for one child
/// repository-tool preparation.
///
/// Store derives the execution binding, model-selected action, tool grant,
/// operation, attempt-local ordinal, broker parameters, parent, actor, and
/// provenance from authoritative replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildRepositoryExplorerToolPreparationAuthority {
    pub event_id: EventId,
    pub action_id: ChildValidatedActionId,
    pub tool_call_id: ChildToolCallId,
    pub prepared_at: RuntimeClockReading,
}

/// Durable evidence that one exact child tool Prepared-v2 boundary exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildToolPreparedEvidence {
    pub prepared_event: EventEnvelope,
}

pub(super) trait RepositoryToolPreparer: Send + Sync {
    fn authority(&self) -> &RepositoryToolReceiptAuthorityV2;
    fn epoch(&self) -> &RepositoryBrokerEpochStateV1;
    fn prepare(
        &self,
        input: RepositoryToolPrepareInputV2,
    ) -> Result<PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2>;
    fn execute_classified(
        &self,
        input: RepositoryToolExecuteInputV2,
        runtime_finished_at: Box<dyn FnOnce() -> RuntimeClockReading + Send>,
    ) -> Result<RepositoryToolTerminalV2, RepositoryToolExecuteErrorV2>;
}

impl RepositoryToolPreparer for RepositoryToolBroker {
    fn authority(&self) -> &RepositoryToolReceiptAuthorityV2 {
        self.authority()
    }

    fn epoch(&self) -> &RepositoryBrokerEpochStateV1 {
        self.epoch()
    }

    fn prepare(
        &self,
        input: RepositoryToolPrepareInputV2,
    ) -> Result<PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2> {
        self.prepare(input)
    }

    fn execute_classified(
        &self,
        input: RepositoryToolExecuteInputV2,
        runtime_finished_at: Box<dyn FnOnce() -> RuntimeClockReading + Send>,
    ) -> Result<RepositoryToolTerminalV2, RepositoryToolExecuteErrorV2> {
        self.execute_classified(input, runtime_finished_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ToolLaneState {
    Active,
    Tainted,
}

pub(super) struct ChildRepositoryToolLaneInner {
    pub(super) broker: Box<dyn RepositoryToolPreparer>,
    pub(super) publication: Mutex<ToolLaneState>,
}

pub(super) fn taint_lane(lane: &ChildRepositoryToolLane) {
    match lane.inner.publication.lock() {
        Ok(mut state) => *state = ToolLaneState::Tainted,
        Err(poisoned) => *poisoned.into_inner() = ToolLaneState::Tainted,
    }
}

/// Shared broker-epoch preparation lane.
///
/// The lane owns the only broker handle used by the Store-backed child path.
/// Its publication lock covers broker Prepare, exact artifact retention, and
/// the durable Store acknowledgement. The lock is released before a future
/// execution slice, so independently committed calls can still execute in
/// parallel.
#[derive(Clone)]
pub struct ChildRepositoryToolLane {
    pub(super) inner: Arc<ChildRepositoryToolLaneInner>,
}

impl ChildRepositoryToolLane {
    /// Seals one repository broker inside a Store-backed publication lane.
    #[must_use]
    pub fn new(broker: RepositoryToolBroker) -> Self {
        Self::from_preparer(Box::new(broker))
    }

    fn from_preparer(broker: Box<dyn RepositoryToolPreparer>) -> Self {
        Self {
            inner: Arc::new(ChildRepositoryToolLaneInner {
                broker,
                publication: Mutex::new(ToolLaneState::Active),
            }),
        }
    }

    /// Reports whether the epoch can accept another preparation.
    ///
    /// A failure after broker Prepare irreversibly taints the lane because its
    /// in-memory sequence cannot be rolled back. Recovery must rotate the
    /// durable broker epoch instead of retrying a later sequence.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.inner
            .publication
            .lock()
            .is_ok_and(|state| *state == ToolLaneState::Active)
    }
}

pub(super) struct ChildToolDispatchMaterial {
    pub(super) prepared_event: EventEnvelope,
    pub(super) prepared: PreparedRepositoryToolCallV2,
    pub(super) lane: ChildRepositoryToolLane,
}

/// Fresh, affine authority for one Store-committed child tool dispatch start.
///
/// The raw cloneable broker bundle remains private. This handoff deliberately
/// has no execution method and can only be consumed by Store's durable
/// dispatch-start admission. Exact replay and recovery never recreate this
/// authority.
///
/// ```compile_fail
/// use birdcode_store::ChildToolDispatchHandoff;
///
/// fn duplicate(value: ChildToolDispatchHandoff) {
///     let _copy = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolDispatchHandoff;
///
/// let _forged = ChildToolDispatchHandoff::default();
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolDispatchHandoff;
///
/// fn serialize(value: &ChildToolDispatchHandoff) {
///     let _encoded = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildToolDispatchHandoff;
///
/// let _decoded: ChildToolDispatchHandoff = serde_json::from_str("{}").unwrap();
/// ```
#[must_use = "a fresh child tool dispatch handoff must be consumed by durable dispatch-start admission"]
pub struct ChildToolDispatchHandoff {
    pub(super) material: Box<ChildToolDispatchMaterial>,
}

const _: () =
    assert!(std::mem::size_of::<ChildToolDispatchHandoff>() == std::mem::size_of::<usize>());

impl ChildToolDispatchHandoff {
    fn from_prepared(
        prepared_event: EventEnvelope,
        prepared: PreparedRepositoryToolCallV2,
        lane: ChildRepositoryToolLane,
    ) -> Self {
        Self {
            material: Box::new(ChildToolDispatchMaterial {
                prepared_event,
                prepared,
                lane,
            }),
        }
    }

    /// Returns the exact durable Prepared boundary consumed by dispatch-start admission.
    #[must_use]
    pub const fn prepared_event(&self) -> &EventEnvelope {
        &self.material.prepared_event
    }

    /// Returns the broker epoch bound into the private prepared receipt.
    #[must_use]
    pub const fn broker_instance_id(&self) -> RepositoryBrokerInstanceId {
        self.material
            .prepared
            .receipt
            .broker_prepared_at
            .broker_instance_id
    }
}

/// Closed preparation result separating fresh dispatch-start authority from replay.
#[must_use = "child tool preparation must start once or reconcile durable evidence"]
pub enum ChildToolDispatchPreparationOutcome {
    Appended {
        evidence: ChildToolPreparedEvidence,
        dispatch: ChildToolDispatchHandoff,
    },
    AlreadyPresent {
        evidence: ChildToolPreparedEvidence,
    },
}

/// Typed failure for the Store-backed broker publication lane.
#[derive(Debug, Error)]
pub enum ChildToolDispatchError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Broker(#[from] RepositoryBrokerErrorV2),
    #[error("child repository-tool publication lane is unavailable")]
    LaneUnavailable,
    #[error("child repository-tool broker epoch requires rotation and reconciliation")]
    LaneRequiresReconciliation,
}

struct DerivedToolPreparation {
    session_id: birdcode_protocol::SessionId,
    actor_id: birdcode_protocol::ActorId,
    causal_parent: EventId,
    backend: birdcode_protocol::BackendSelection,
    validated_action: RetainedArtifactV2,
    parameters: RepositoryToolCanonicalParametersV1,
    expected_broker_sequence: u64,
}

fn receipt_authority(authority: &ChildRepositoryAuthorityV1) -> RepositoryToolReceiptAuthorityV2 {
    RepositoryToolReceiptAuthorityV2 {
        policy_id: authority.policy_id.clone(),
        policy_artifact: authority.policy_artifact.clone(),
        policy_digest: authority.policy_digest.clone(),
        snapshot: authority.snapshot.clone(),
        root: authority.root.clone(),
        broker_bounds: authority.broker_bounds,
        tool_grants: authority.tool_grants.clone(),
    }
}

pub(super) fn retained_artifact(
    artifact_root: &std::path::Path,
    retained: &RetainedArtifactV2,
) -> Result<(), StoreError> {
    if !retained.is_exact() {
        return Err(StoreError::ArtifactIntegrity);
    }
    let stored = put_artifact_at(
        artifact_root,
        &retained.bytes,
        retained.artifact.media_type.clone(),
    )?;
    if stored != retained.artifact {
        return Err(StoreError::ArtifactIntegrity);
    }
    Ok(())
}

fn exact_existing_preparation(
    connection: &Connection,
    artifact_root: &std::path::Path,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
    authority: &ChildRepositoryExplorerToolPreparationAuthority,
) -> Result<Option<ChildToolPreparedEvidence>, StoreError> {
    let Some(existing) = load_event_by_id(connection, authority.event_id)? else {
        return Ok(None);
    };
    let EventPayload::ChildToolPreparedV2(prepared) = &existing.payload else {
        return Err(StoreError::IdentifiedEventConflict);
    };
    if existing.run_id != Some(run_id)
        || prepared.binding.work_order_id != work_order_id
        || prepared.action_binding.action_id != authority.action_id
        || prepared.tool_call_id != authority.tool_call_id
        || prepared.prepared_at != authority.prepared_at
        || existing.provenance.producer != CHILD_REPOSITORY_TOOL_PREPARATION_PRODUCER
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    load_child_replay(connection, artifact_root, run_id, work_order_id)?;
    Ok(Some(ChildToolPreparedEvidence {
        prepared_event: existing,
    }))
}

fn next_global_broker_sequence(
    transaction: &Transaction<'_>,
    broker_instance_id: RepositoryBrokerInstanceId,
) -> Result<u64, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT value_json FROM events
         WHERE json_extract(value_json, '$.payload.type') IN
                   ('child_tool_prepared', 'child_tool_prepared_v2')
           AND json_extract(value_json, '$.payload.data.broker_instance_id') = ?1
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map([broker_instance_id.to_string()], |row| {
        row.get::<_, String>(0)
    })?;
    let mut expected = 1_u64;
    for row in rows {
        let envelope = decode_canonical_event(&row?)?;
        let sequence = match envelope.payload {
            EventPayload::ChildToolPrepared(prepared) => prepared.broker_call_sequence,
            EventPayload::ChildToolPreparedV2(prepared) => prepared.broker_call_sequence,
            _ => return Err(StoreError::InvalidStateEvent),
        };
        if sequence != expected {
            return Err(StoreError::InvalidStateEvent);
        }
        expected = expected
            .checked_add(1)
            .ok_or(StoreError::InvalidStateEvent)?;
    }
    Ok(expected)
}

fn identity_is_unused(
    transaction: &Transaction<'_>,
    json_path: &str,
    identity: &str,
) -> Result<bool, StoreError> {
    let count = transaction.query_row(
        "SELECT COUNT(*) FROM events
         WHERE json_extract(value_json, '$.payload.type') IN
                   ('child_tool_prepared', 'child_tool_prepared_v2')
           AND json_extract(value_json, ?1) = ?2",
        params![json_path, identity],
        |row| row.get::<_, u64>(0),
    )?;
    Ok(count == 0)
}

pub(crate) fn repository_broker_epoch_identity_is_unused(
    connection: &Connection,
    broker_instance_id: RepositoryBrokerInstanceId,
) -> Result<bool, StoreError> {
    let usage_count = connection.query_row(
        "SELECT COUNT(*) FROM events
         WHERE (json_extract(value_json, '$.payload.type') IN
                    ('child_tool_prepared', 'child_tool_prepared_v2')
                AND json_extract(value_json, '$.payload.data.broker_instance_id') = ?1)
            OR (json_extract(value_json, '$.payload.type')
                    = 'repository_broker_epoch_activated_v1'
                AND json_extract(
                        value_json,
                        '$.payload.data.state.active_broker_instance_id'
                    ) = ?1)",
        [broker_instance_id.to_string()],
        |row| row.get::<_, u64>(0),
    )?;
    Ok(usage_count == 0)
}

fn require_fresh_child_effect_authority(
    transaction: &Transaction<'_>,
    run: &birdcode_protocol::Run,
    replay: &super::super::ChildReplay,
    authority: &ChildRepositoryExplorerToolPreparationAuthority,
) -> Result<(), StoreError> {
    if current_run_state(transaction, run.spec.session_id, run.id)? != RunState::Running {
        return Err(StoreError::InvalidStateEvent);
    }
    let claim_event = latest_claim_for_run(transaction, run.spec.session_id, run.id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let now = Utc::now();
    if claim_event.id != replay.active_claim.event_id
        || claim.claim_id != replay.active_claim.claim_id
        || claim.claim_generation != replay.active_claim.generation
        || claim.runtime_instance_id != replay.active_claim.runtime_instance_id
        || claim.cancellation_generation != replay.active_claim.cancellation_generation
        || claim.lease_expires_at != replay.active_claim.lease_expires_at
        || claim.lease_expires_at <= authority.prepared_at.observed_at
        || claim.lease_expires_at <= now
        || latest_cancellation_generation(transaction, run.spec.session_id, run.id)?
            != replay.active_claim.cancellation_generation
        || replay
            .issued
            .spec
            .run_deadline
            .is_some_and(|deadline| deadline < now)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn derive_tool_parameters(
    replay: &super::super::ChildReplay,
    attempt: &super::super::ReplayedChildAttempt,
    source: &super::super::SuccessfulChildModel,
    authority: &ChildRepositoryExplorerToolPreparationAuthority,
    tool_ordinal: u32,
) -> Result<(RepositoryToolCanonicalParametersV1, RetainedArtifactV2), StoreError> {
    let Some((_grant, operation)) = validate_child_action_against_authority(
        &source.proposed_action,
        &replay.issued.spec.repository_authority,
    )?
    else {
        return Err(StoreError::InvalidStateEvent);
    };
    let tool_grant_id = source
        .proposed_action
        .tool_grant_id()
        .ok_or(StoreError::InvalidStateEvent)?;
    let binding = child_execution_binding(replay, attempt);
    let action_document = ChildValidatedActionDocumentV1 {
        contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        binding: binding.clone(),
        action_id: authority.action_id,
        source_model_call_id: source.model_call_id,
        source_model_call_ordinal: source.model_call_ordinal,
        source_model_observed_event_id: source.observed_event_id,
        source_model_evidence_digest: source.evidence_digest.clone(),
        source_plan: source.plan_binding.clone(),
        active_plan_step_id: source.plan.active_step_id.clone(),
        completion_handoff_id: None,
        action: source.proposed_action.clone(),
    };
    let action_bytes = serde_json::to_vec(&action_document)?;
    let action_digest = Sha256Digest::of_bytes(&action_bytes);
    let validated_action = RetainedArtifactV2 {
        artifact: ArtifactRef {
            sha256: action_digest.as_str().to_owned(),
            size_bytes: u64::try_from(action_bytes.len())
                .map_err(|_| StoreError::ArtifactTooLarge)?,
            media_type: CHILD_VALIDATED_ACTION_MEDIA_TYPE.to_owned(),
        },
        bytes: action_bytes,
    };
    let action_binding = ChildValidatedActionBindingV1 {
        action_id: authority.action_id,
        source_model_call_id: source.model_call_id,
        source_model_call_ordinal: source.model_call_ordinal,
        source_model_observed_event_id: source.observed_event_id,
        source_model_evidence_digest: source.evidence_digest.clone(),
        source_plan: source.plan_binding.clone(),
        active_plan_step_id: source.plan.active_step_id.clone(),
        completion_handoff_id: None,
        validated_action_digest: artifact_digest(&validated_action.artifact)?,
        validated_action_artifact: validated_action.artifact.clone(),
    };
    Ok((
        RepositoryToolCanonicalParametersV1 {
            schema_version: REPOSITORY_BROKER_CONTRACT_VERSION,
            binding,
            tool_call_id: authority.tool_call_id,
            tool_ordinal,
            action_binding,
            tool_grant_id,
            operation,
        },
        validated_action,
    ))
}

fn require_authorized_broker_preparation(
    transaction: &Transaction<'_>,
    session_id: birdcode_protocol::SessionId,
    run_id: RunId,
    repository_authority: &ChildRepositoryAuthorityV1,
    parameters: &RepositoryToolCanonicalParametersV1,
    broker: &dyn RepositoryToolPreparer,
) -> Result<u64, StoreError> {
    let expected_receipt_authority = receipt_authority(repository_authority);
    let epoch =
        latest_broker_epoch_before(transaction, session_id, run_id, MAX_SQLITE_INTEGER_U64)?
            .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::RepositoryBrokerEpochActivatedV1(epoch) = epoch.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let activation_count = transaction.query_row(
        "SELECT COUNT(*) FROM events
         WHERE json_extract(value_json, '$.payload.type')
                   = 'repository_broker_epoch_activated_v1'
           AND json_extract(
                   value_json,
                   '$.payload.data.state.active_broker_instance_id'
               ) = ?1",
        [epoch.state.active_broker_instance_id.to_string()],
        |row| row.get::<_, u64>(0),
    )?;
    if activation_count != 1
        || broker.authority() != &expected_receipt_authority
        || broker.epoch() != &epoch.state
        || epoch
            .state
            .closed_broker_instance_ids
            .contains(&epoch.state.active_broker_instance_id)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let expected_broker_sequence =
        next_global_broker_sequence(transaction, epoch.state.active_broker_instance_id)?;
    let parameter_bytes = serde_json::to_vec(parameters)?;
    let parameter_size =
        u64::try_from(parameter_bytes.len()).map_err(|_| StoreError::ArtifactTooLarge)?;
    if expected_broker_sequence > repository_authority.broker_bounds.max_calls_per_broker
        || parameter_size
            > repository_authority
                .broker_bounds
                .max_request_bytes
                .min(REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES)
        || !matches!(
            birdcode_protocol::evaluate_repository_tool_authorization_v1(
                &expected_receipt_authority.broker_bounds,
                &expected_receipt_authority.tool_grants,
                parameters,
                parameter_size,
                expected_broker_sequence,
            ),
            RepositoryToolAuthorizationDecisionV2::Authorized
        )
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(expected_broker_sequence)
}

fn derive_tool_preparation(
    transaction: &Transaction<'_>,
    artifact_root: &std::path::Path,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
    authority: &ChildRepositoryExplorerToolPreparationAuthority,
    broker: &dyn RepositoryToolPreparer,
) -> Result<DerivedToolPreparation, StoreError> {
    let (replay, _, _, _) = load_child_replay(transaction, artifact_root, run_id, work_order_id)?;
    let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
    let run = durable_run_for_claim_refresh(transaction, run_id)?;
    require_fresh_child_effect_authority(transaction, &run, &replay, authority)?;
    let attempt = replay
        .attempts
        .last()
        .ok_or(StoreError::InvalidStateEvent)?;
    let source = attempt
        .last_successful_model
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    let tool_ordinal = attempt
        .projection
        .completed_tool_calls
        .checked_add(1)
        .ok_or(StoreError::InvalidStateEvent)?;
    if replay.issued.spec.work_order_id != work_order_id
        || attempt.projection.outcome.is_some()
        || attempt.pending_model.is_some()
        || attempt.pending_tool.is_some()
        || attempt.projection.handoff_event_id.is_some()
        || attempt.model_turn_required
        || attempt.required_model_terminal_retry.is_some()
        || tool_ordinal > replay.issued.spec.max_tool_calls_per_attempt
        || authority.prepared_at.runtime_instance_id != replay.active_claim.runtime_instance_id
        || !child_attempt_clock_accepts(attempt, &authority.prepared_at)
        || replay
            .issued
            .spec
            .run_deadline
            .is_some_and(|deadline| authority.prepared_at.observed_at > deadline)
        || !identity_is_unused(
            transaction,
            "$.payload.data.tool_call_id",
            &authority.tool_call_id.to_string(),
        )?
        || !identity_is_unused(
            transaction,
            "$.payload.data.action_binding.action_id",
            &authority.action_id.to_string(),
        )?
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let (parameters, validated_action) =
        derive_tool_parameters(&replay, attempt, source, authority, tool_ordinal)?;
    let expected_broker_sequence = require_authorized_broker_preparation(
        transaction,
        run.spec.session_id,
        run_id,
        &replay.issued.spec.repository_authority,
        &parameters,
        broker,
    )?;
    Ok(DerivedToolPreparation {
        session_id: run.spec.session_id,
        actor_id: replay.issued.spec.child_event_actor_id,
        causal_parent: attempt.tail_event_id,
        backend: replay.issued.spec.backend,
        validated_action,
        parameters,
        expected_broker_sequence,
    })
}

fn verify_prepared_bundle(
    prepared: &PreparedRepositoryToolCallV2,
    derived: &DerivedToolPreparation,
    prepared_at: &RuntimeClockReading,
    broker: &dyn RepositoryToolPreparer,
) -> Result<birdcode_protocol::ChildToolPreparedV2, StoreError> {
    if prepared.receipt.authority != *broker.authority()
        || prepared.receipt.binding != derived.parameters.binding
        || prepared.receipt.tool_call_id != derived.parameters.tool_call_id
        || prepared.receipt.tool_ordinal != derived.parameters.tool_ordinal
        || prepared.receipt.action_binding != derived.parameters.action_binding
        || prepared.receipt.operation != derived.parameters.operation
        || prepared.receipt.broker_call_sequence != derived.expected_broker_sequence
        || prepared.receipt.runtime_prepared_at != *prepared_at
        || prepared.receipt.broker_prepared_at.broker_instance_id
            != broker.epoch().active_broker_instance_id
        || !matches!(
            prepared.receipt.authorization,
            RepositoryToolAuthorizationDecisionV2::Authorized
        )
    {
        return Err(StoreError::InvalidStateEvent);
    }
    project_prepared_event_v2(prepared).map_err(|_| StoreError::InvalidStateEvent)
}

impl Store {
    /// Publishes one broker-v2 Prepared boundary and returns fresh dispatch
    /// authority only after the exact event commit is durably acknowledged.
    ///
    /// The shared lane lock and `SQLite` immediate transaction jointly serialize
    /// the complete broker Prepare → artifact retention → Store commit
    /// boundary. Exact replay never calls the broker and returns evidence only.
    ///
    /// # Errors
    ///
    /// Fails closed for stale child state, reused identities, invalid clocks,
    /// inactive or mismatched broker epochs, exhausted limits, artifact drift,
    /// broker failure, or durable publication failure. Any failure after
    /// successful broker Prepare taints the lane and requires epoch rotation.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh runtime authority"
    )]
    #[allow(clippy::too_many_lines, reason = "one transactional publication fence")]
    pub fn prepare_child_repository_explorer_tool_dispatch(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: ChildRepositoryExplorerToolPreparationAuthority,
        lane: &ChildRepositoryToolLane,
    ) -> Result<ChildToolDispatchPreparationOutcome, ChildToolDispatchError> {
        if let Some(evidence) = exact_existing_preparation(
            &self.connection,
            &self.artifact_root,
            run_id,
            work_order_id,
            &authority,
        )? {
            return Ok(ChildToolDispatchPreparationOutcome::AlreadyPresent { evidence });
        }
        let mut lane_state = lane
            .inner
            .publication
            .lock()
            .map_err(|_| ChildToolDispatchError::LaneUnavailable)?;
        let artifact_root = self.artifact_root.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        if let Some(evidence) = exact_existing_preparation(
            &transaction,
            &artifact_root,
            run_id,
            work_order_id,
            &authority,
        )? {
            transaction.commit().map_err(StoreError::from)?;
            return Ok(ChildToolDispatchPreparationOutcome::AlreadyPresent { evidence });
        }
        if *lane_state != ToolLaneState::Active {
            return Err(ChildToolDispatchError::LaneRequiresReconciliation);
        }
        let derived = derive_tool_preparation(
            &transaction,
            &artifact_root,
            run_id,
            work_order_id,
            &authority,
            lane.inner.broker.as_ref(),
        )?;
        let prepared = lane.inner.broker.prepare(RepositoryToolPrepareInputV2 {
            parameters: derived.parameters.clone(),
            runtime_prepared_at: authority.prepared_at.clone(),
        })?;
        let publication = (|| -> Result<EventEnvelope, StoreError> {
            let projected = verify_prepared_bundle(
                &prepared,
                &derived,
                &authority.prepared_at,
                lane.inner.broker.as_ref(),
            )?;
            if projected.prepared_at != authority.prepared_at {
                return Err(StoreError::InvalidStateEvent);
            }
            retained_artifact(&artifact_root, &derived.validated_action)?;
            retained_artifact(&artifact_root, &prepared.canonical_parameters)?;
            retained_artifact(&artifact_root, &prepared.prepared_receipt)?;
            let identified = IdentifiedNewEvent {
                event_id: authority.event_id,
                event: NewEvent {
                    session_id: derived.session_id,
                    run_id: Some(run_id),
                    actor_id: derived.actor_id,
                    causal_parent: Some(derived.causal_parent),
                    provenance: Provenance {
                        producer: CHILD_REPOSITORY_TOOL_PREPARATION_PRODUCER.to_owned(),
                        backend: Some(derived.backend),
                        raw_artifact: Some(projected.prepared_receipt_artifact.clone()),
                    },
                    payload: EventPayload::ChildToolPreparedV2(projected),
                },
            };
            let envelope = preallocate_identified_event_envelope(
                &transaction,
                identified.event_id,
                identified.event,
            )?;
            apply_exact_event_envelope_with_admission(
                &transaction,
                &artifact_root,
                &envelope,
                super::super::EventAdmission::ChildToolPreparation,
            )?;
            transaction.commit()?;
            Ok(envelope)
        })();
        let prepared_event = match publication {
            Ok(event) => event,
            Err(error) => {
                *lane_state = ToolLaneState::Tainted;
                return Err(error.into());
            }
        };
        let evidence = ChildToolPreparedEvidence {
            prepared_event: prepared_event.clone(),
        };
        Ok(ChildToolDispatchPreparationOutcome::Appended {
            evidence,
            dispatch: ChildToolDispatchHandoff::from_prepared(
                prepared_event,
                prepared,
                lane.clone(),
            ),
        })
    }
}

#[cfg(test)]
#[path = "../tests/child_tool_dispatch_authority.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "../tests/child_tool_dispatch_real_broker.rs"]
mod real_broker_tests;
