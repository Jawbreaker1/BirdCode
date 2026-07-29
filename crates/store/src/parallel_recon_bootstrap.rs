//! Atomic authorization, issuance, and initial-attempt bootstrap for the
//! bounded Parallel Repository Reconnaissance v1 pair.

use super::store_child_agent_api::child_repository_explorer_attempt_start_event;
use super::{
    ArtifactRef, BTreeSet, ChildActorId, ChildExecutionId, ChildRecoveryState,
    ChildRepositoryExplorerAttemptStartAuthority, EventAdmission, EventEnvelope, EventId,
    EventPayload, PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS, ParallelReconExactPairMaterialMode,
    RepositorySnapshotLifecycleReplay, RunId, RunPurpose, Store, StoreError, TransactionBehavior,
    Utc, apply_exact_event_envelope_with_admission, current_run_state, decode_canonical_event,
    derive_parallel_recon_exact_pair_material, durable_run_for_claim_refresh,
    latest_cancellation_generation, latest_claim_for_run, load_child_replay, load_event_by_id,
    new_event_from_envelope, parallel_recon_exact_pair_authority_event_ids,
    parallel_recon_exact_pair_authority_from_committed, parallel_recon_exact_pair_committed_events,
    parallel_recon_exact_pair_events, parallel_recon_exact_pair_history_counts,
    parallel_recon_exact_pair_outcome_children, preallocate_identified_event_envelope,
    recheck_parallel_recon_exact_pair_guard, replay_repository_snapshot_lifecycle,
};
use birdcode_protocol::{
    ActorId, ChildAttemptId, ChildContextId, ChildDelegationAuthorizationId, ChildLocalPlanId,
    ChildWorkOrderId, RepositoryToolGrantId, RuntimeClockReading,
};
use rusqlite::{Connection, OptionalExtension, Transaction};

const CHILDREN: usize = PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS as usize;

/// Fresh identities for one member of an atomic exact-pair delegation.
///
/// Store assigns the bundle after canonically sorting the two accepted planner
/// work orders, so callers cannot choose either child's objective, authority,
/// model, artifacts, claim, or causal ancestry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelReconExactPairChildIdentityAuthority {
    pub authorization_event_id: EventId,
    pub authorization_id: ChildDelegationAuthorizationId,
    pub issuance_event_id: EventId,
    pub work_order_id: ChildWorkOrderId,
    pub execution_id: ChildExecutionId,
    pub child_actor_id: ChildActorId,
    pub child_event_actor_id: ActorId,
    pub context_id: ChildContextId,
}

/// Mechanical identity authority for the Store-derived two-child delegation.
///
/// The grant identities are ordered as repository tree, file read, and
/// literal search and are shared by the complete pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelReconExactPairIssuanceAuthority {
    pub accepted_planner_turn_event_id: EventId,
    pub snapshot_lease_event_id: EventId,
    pub children: [ParallelReconExactPairChildIdentityAuthority; CHILDREN],
    pub repository_tool_grant_ids: [RepositoryToolGrantId; 3],
}

/// Internal authorization/issuance projection used while deriving bootstrap
/// and by the exhaustive test-only pair suite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParallelReconExactPairIssuedChild {
    pub authorization_event: EventEnvelope,
    pub issuance_event: EventEnvelope,
    pub projection: super::ChildWorkOrderProjection,
}

/// Test-only restart view for the pre-bootstrap pair derivation suite.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParallelReconExactPairRecovery {
    pub policy_artifact: ArtifactRef,
    pub children: [ParallelReconExactPairIssuedChild; CHILDREN],
}

/// Test-only result retained for exhaustive pair-derivation coverage. Product
/// callers cannot issue a stranded four-event pair.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ParallelReconExactPairIssuanceOutcome {
    Appended {
        policy_artifact: ArtifactRef,
        children: [ParallelReconExactPairIssuedChild; CHILDREN],
    },
    AlreadyPresent {
        policy_artifact: ArtifactRef,
        children: [ParallelReconExactPairIssuedChild; CHILDREN],
    },
}

/// Mechanical identity and clock authority for one exact two-child bootstrap.
///
/// The caller cannot supply objectives, roles, model identity, tool authority,
/// limits, claim bindings, deadlines, actors, lineage, provenance, or causal
/// parents. Store derives those fields from the accepted planner turn, active
/// snapshot, active run claim, and immutable child contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelReconBootstrapAuthority {
    pub pair: ParallelReconExactPairIssuanceAuthority,
    pub starts: [ChildRepositoryExplorerAttemptStartAuthority; CHILDREN],
}

/// One canonically ordered child in the exact durable bootstrap.
///
/// Authorization, issuance, and initial start share one boxed current
/// projection, avoiding duplicate large protocol values while preserving an
/// explicit index binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelReconBootstrappedChild {
    pub authorization_event: EventEnvelope,
    pub issuance_event: EventEnvelope,
    pub started_event: EventEnvelope,
    pub projection: Box<super::ChildWorkOrderProjection>,
}

/// Exact durable six-event bootstrap plus current replay-derived child state.
///
/// This material proves persistence only. It grants no permission to dispatch
/// a model or tool call; later Store preparation boundaries own that authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelReconBootstrapMaterial {
    pub policy_artifact: ArtifactRef,
    pub children: Box<[ParallelReconBootstrappedChild; CHILDREN]>,
}

/// Restart view of a complete committed bootstrap. Recovery never mints
/// dispatch, model, or tool authority.
pub type ParallelReconBootstrapRecovery = ParallelReconBootstrapMaterial;

/// Closed idempotent outcome for the complete six-event bootstrap boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParallelReconBootstrapOutcome {
    Appended {
        material: ParallelReconBootstrapMaterial,
    },
    AlreadyPresent {
        material: ParallelReconBootstrapMaterial,
    },
}

fn bootstrap_event_ids(authority: &ParallelReconBootstrapAuthority) -> [EventId; 6] {
    let pair = parallel_recon_exact_pair_authority_event_ids(&authority.pair);
    [
        pair[0],
        pair[1],
        pair[2],
        pair[3],
        authority.starts[0].event_id,
        authority.starts[1].event_id,
    ]
}

fn validate_bootstrap_identity_budget(
    authority: &ParallelReconBootstrapAuthority,
) -> Result<(), StoreError> {
    let event_ids = bootstrap_event_ids(authority)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let attempt_ids = authority
        .starts
        .iter()
        .map(|start| start.attempt_id)
        .collect::<BTreeSet<ChildAttemptId>>();
    let local_plan_ids = authority
        .starts
        .iter()
        .map(|start| start.local_plan_id)
        .collect::<BTreeSet<ChildLocalPlanId>>();
    let pair_has_nil_identity = authority.pair.children.iter().any(|child| {
        child.authorization_event_id.as_uuid().is_nil()
            || child.authorization_id.as_uuid().is_nil()
            || child.issuance_event_id.as_uuid().is_nil()
            || child.work_order_id.as_uuid().is_nil()
            || child.execution_id.as_uuid().is_nil()
            || child.child_actor_id.as_uuid().is_nil()
            || child.child_event_actor_id.as_uuid().is_nil()
            || child.context_id.as_uuid().is_nil()
    }) || authority
        .pair
        .repository_tool_grant_ids
        .iter()
        .any(|identity| identity.as_uuid().is_nil());
    if event_ids.len() != 6
        || event_ids.iter().any(|identity| identity.as_uuid().is_nil())
        || pair_has_nil_identity
        || attempt_ids.len() != CHILDREN
        || attempt_ids
            .iter()
            .any(|identity| identity.as_uuid().is_nil())
        || local_plan_ids.len() != CHILDREN
        || local_plan_ids
            .iter()
            .any(|identity| identity.as_uuid().is_nil())
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn authority_events(
    connection: &Connection,
    authority: &ParallelReconBootstrapAuthority,
) -> Result<Vec<Option<EventEnvelope>>, StoreError> {
    bootstrap_event_ids(authority)
        .into_iter()
        .map(|event_id| load_event_by_id(connection, event_id))
        .collect()
}

fn require_contiguous_bundle(events: &[EventEnvelope]) -> Result<(), StoreError> {
    if events.len() == 6
        && events.windows(2).all(|pair| {
            pair[0].sequence.checked_add(1) == Some(pair[1].sequence)
                && pair[0].session_id == pair[1].session_id
                && pair[0].run_id == pair[1].run_id
        })
    {
        Ok(())
    } else {
        Err(StoreError::InvalidStateEvent)
    }
}

fn bootstrap_start_authority(
    event: &EventEnvelope,
) -> Result<ChildRepositoryExplorerAttemptStartAuthority, StoreError> {
    let EventPayload::ChildExecutionStarted(started) = &event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(ChildRepositoryExplorerAttemptStartAuthority {
        event_id: event.id,
        attempt_id: started.binding.attempt_id,
        local_plan_id: started.local_plan_id,
        started_at: started.started_at.clone(),
    })
}

fn first_bootstrap_start_events(
    connection: &Connection,
    pair_events: &[EventEnvelope; 4],
) -> Result<Vec<EventEnvelope>, StoreError> {
    let session_id = pair_events[0].session_id;
    let run_id = pair_events[0].run_id.ok_or(StoreError::InvalidStateEvent)?;
    let left_sequence = pair_events[3]
        .sequence
        .checked_add(1)
        .ok_or(StoreError::SequenceOverflow)?;
    let right_sequence = left_sequence
        .checked_add(1)
        .ok_or(StoreError::SequenceOverflow)?;
    let load = |sequence: u64| -> Result<EventEnvelope, StoreError> {
        let json = connection
            .query_row(
                "SELECT value_json FROM events
                 WHERE session_id = ?1 AND run_id = ?2 AND sequence = ?3",
                rusqlite::params![session_id.to_string(), run_id.to_string(), sequence],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(StoreError::InvalidStateEvent)?;
        decode_canonical_event(&json)
    };
    Ok(vec![load(left_sequence)?, load(right_sequence)?])
}

fn no_parallel_recon_child_history(
    connection: &Connection,
    run_id: RunId,
) -> Result<bool, StoreError> {
    let count = connection.query_row(
        "SELECT COUNT(*) FROM events
         WHERE run_id = ?1
           AND json_extract(value_json, '$.payload.type') IN (
               'child_delegation_authorized',
               'child_delegation_authorized_v2',
               'child_work_order_issued',
               'child_execution_started'
           )",
        [run_id.to_string()],
        |row| row.get::<_, u64>(0),
    )?;
    Ok(count == 0)
}

fn validate_start_clock(
    authority: &ChildRepositoryExplorerAttemptStartAuthority,
    claim_event: &EventEnvelope,
    claim: &birdcode_protocol::RunClaimed,
    snapshot_event: &EventEnvelope,
    deadline: chrono::DateTime<Utc>,
    checked_at: chrono::DateTime<Utc>,
) -> Result<(), StoreError> {
    let RuntimeClockReading {
        runtime_instance_id,
        monotonic_nanos,
        observed_at,
    } = &authority.started_at;
    if *runtime_instance_id != claim.runtime_instance_id
        || *monotonic_nanos == 0
        || *observed_at > checked_at
        || *observed_at < claim_event.occurred_at
        || *observed_at < snapshot_event.occurred_at
        || *observed_at > deadline
        || *observed_at >= claim.lease_expires_at
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn bootstrap_material_from_events(
    transaction: &Transaction<'_>,
    artifact_root: &std::path::Path,
    run_id: RunId,
    authority: &ParallelReconBootstrapAuthority,
    events: &[EventEnvelope],
) -> Result<ParallelReconBootstrapMaterial, StoreError> {
    require_contiguous_bundle(events)?;
    if events.iter().any(|event| event.run_id != Some(run_id)) {
        return Err(StoreError::InvalidStateEvent);
    }
    let pair_material = derive_parallel_recon_exact_pair_material(
        transaction,
        artifact_root,
        run_id,
        &authority.pair,
        ParallelReconExactPairMaterialMode::Historical {
            authorization_sequence: events[0].sequence,
        },
    )?;
    let expected_pair = parallel_recon_exact_pair_events(&pair_material);
    if events[..4]
        .iter()
        .zip(&expected_pair)
        .any(|(committed, expected)| {
            committed.id != expected.event_id
                || new_event_from_envelope(committed) != expected.event
        })
        || events[..4].iter().any(|event| {
            event.occurred_at > pair_material.deadline
                || event.occurred_at >= pair_material.claim.lease_expires_at
        })
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    let (authorization_count, source_authorization_count, issuance_count) =
        parallel_recon_exact_pair_history_counts(
            transaction,
            pair_material.session_id,
            run_id,
            authority.pair.accepted_planner_turn_event_id,
        )?;
    if authorization_count != u64::from(PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS)
        || source_authorization_count != u64::from(PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS)
        || issuance_count != u64::from(PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS)
    {
        return Err(StoreError::InvalidStateEvent);
    }

    let pair_children = parallel_recon_exact_pair_outcome_children(
        transaction,
        artifact_root,
        run_id,
        &pair_material,
        &events[..4],
        false,
    )?;
    let mut children = Vec::with_capacity(CHILDREN);
    for (index, (child, committed)) in pair_children.into_iter().zip(&events[4..]).enumerate() {
        let (replay, _, _, _) = load_child_replay(
            transaction,
            artifact_root,
            run_id,
            child.projection.spec.work_order_id,
        )?;
        let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
        let first_attempt = replay
            .attempts
            .first()
            .ok_or(StoreError::InvalidStateEvent)?;
        if first_attempt.projection.started_event_id != committed.id
            || first_attempt.projection.attempt_id != authority.starts[index].attempt_id
            || first_attempt.projection.local_plan_id != authority.starts[index].local_plan_id
            || first_attempt.projection.started_at != authority.starts[index].started_at
        {
            return Err(StoreError::IdentifiedEventConflict);
        }
        let expected = child_repository_explorer_attempt_start_event(
            pair_material.session_id,
            run_id,
            &replay,
            0,
            authority.starts[index].attempt_id,
            authority.starts[index].local_plan_id,
            authority.starts[index].started_at.clone(),
        )?;
        if committed.id != authority.starts[index].event_id
            || new_event_from_envelope(committed) != expected
            || committed.occurred_at > pair_material.deadline
            || committed.occurred_at >= pair_material.claim.lease_expires_at
        {
            return Err(StoreError::IdentifiedEventConflict);
        }
        children.push(ParallelReconBootstrappedChild {
            authorization_event: child.authorization_event,
            issuance_event: child.issuance_event,
            started_event: committed.clone(),
            projection: Box::new(child.projection),
        });
    }
    let children: Box<[ParallelReconBootstrappedChild]> = children.into_boxed_slice();
    let children: Box<[ParallelReconBootstrappedChild; CHILDREN]> = children
        .try_into()
        .map_err(|_| StoreError::InvalidStateEvent)?;
    Ok(ParallelReconBootstrapMaterial {
        policy_artifact: pair_material.policy_artifact,
        children,
    })
}

fn committed_bootstrap_events(
    connection: &Connection,
    session_id: birdcode_protocol::SessionId,
    run_id: RunId,
    accepted_event_id: EventId,
) -> Result<Option<Vec<EventEnvelope>>, StoreError> {
    let Some(pair) = parallel_recon_exact_pair_committed_events(
        connection,
        session_id,
        run_id,
        accepted_event_id,
    )?
    else {
        return if no_parallel_recon_child_history(connection, run_id)? {
            Ok(None)
        } else {
            Err(StoreError::InvalidStateEvent)
        };
    };
    let starts = first_bootstrap_start_events(connection, &pair)?;
    let mut events = pair.into_iter().collect::<Vec<_>>();
    events.extend(starts);
    require_contiguous_bundle(&events)?;
    Ok(Some(events))
}

fn authority_from_committed(
    accepted_event_id: EventId,
    events: &[EventEnvelope],
) -> Result<ParallelReconBootstrapAuthority, StoreError> {
    Ok(ParallelReconBootstrapAuthority {
        pair: parallel_recon_exact_pair_authority_from_committed(accepted_event_id, &events[..4])?,
        starts: [
            bootstrap_start_authority(&events[4])?,
            bootstrap_start_authority(&events[5])?,
        ],
    })
}

fn validate_fresh_child_replay(
    transaction: &Transaction<'_>,
    artifact_root: &std::path::Path,
    run_id: RunId,
    child: &ParallelReconExactPairIssuedChild,
    claim_event: &EventEnvelope,
    claim: &birdcode_protocol::RunClaimed,
) -> Result<super::ChildReplay, StoreError> {
    let (replay, _, _, _) = load_child_replay(
        transaction,
        artifact_root,
        run_id,
        child.projection.spec.work_order_id,
    )?;
    let replay = replay.ok_or(StoreError::InvalidStateEvent)?;
    if !replay.attempts.is_empty()
        || replay.issued.spec != child.projection.spec
        || replay.active_claim.event_id != claim_event.id
        || replay.active_claim.claim_id != claim.claim_id
        || replay.active_claim.generation != claim.claim_generation
        || replay.active_claim.runtime_instance_id != claim.runtime_instance_id
        || replay.active_claim.cancellation_generation != claim.cancellation_generation
        || replay.active_claim.lease_expires_at != claim.lease_expires_at
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(replay)
}

impl Store {
    /// Atomically authorizes and issues the exact accepted pair and starts
    /// both initial repository-explorer attempts.
    ///
    /// The immediate writer transaction commits exactly six contiguous events
    /// in the order `Authorize[0], Authorize[1], Issue[0], Issue[1],
    /// Started[0], Started[1]`, or commits none. Exact same-authority replay
    /// returns the original envelopes; partial, mixed, or competing history
    /// fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for stale run, cancellation, claim, snapshot, lease or
    /// deadline authority; any semantic or identity collision; partial
    /// history; or a failed precommit liveness recheck.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "one visibly atomic boundary owns the complete six-event bootstrap"
    )]
    pub fn bootstrap_parallel_recon_exact_pair(
        &mut self,
        run_id: RunId,
        authority: ParallelReconBootstrapAuthority,
    ) -> Result<ParallelReconBootstrapOutcome, StoreError> {
        validate_bootstrap_identity_budget(&authority)?;
        let artifact_root = self.artifact_root.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = durable_run_for_claim_refresh(&transaction, run_id)?;
        if run.id != run_id || run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1 {
            return Err(StoreError::InvalidStateEvent);
        }

        let existing = authority_events(&transaction, &authority)?;
        let present = existing.iter().filter(|event| event.is_some()).count();
        if present != 0 && present != 6 {
            return Err(StoreError::InvalidStateEvent);
        }
        if present == 6 {
            let events = existing
                .into_iter()
                .map(|event| event.ok_or(StoreError::InvalidStateEvent))
                .collect::<Result<Vec<_>, _>>()?;
            let material = bootstrap_material_from_events(
                &transaction,
                &artifact_root,
                run_id,
                &authority,
                &events,
            )?;
            transaction.commit()?;
            return Ok(ParallelReconBootstrapOutcome::AlreadyPresent { material });
        }

        let pair_material = derive_parallel_recon_exact_pair_material(
            &transaction,
            &artifact_root,
            run_id,
            &authority.pair,
            ParallelReconExactPairMaterialMode::Fresh,
        )?;
        let (authorization_count, source_authorization_count, issuance_count) =
            parallel_recon_exact_pair_history_counts(
                &transaction,
                pair_material.session_id,
                run_id,
                authority.pair.accepted_planner_turn_event_id,
            )?;
        if authorization_count != 0 || source_authorization_count != 0 || issuance_count != 0 {
            return Err(StoreError::InvalidStateEvent);
        }
        let snapshot_event =
            load_event_by_id(&transaction, authority.pair.snapshot_lease_event_id)?
                .ok_or(StoreError::InvalidStateEvent)?;
        let checked_at = Utc::now();
        for start in &authority.starts {
            validate_start_clock(
                start,
                &pair_material.claim_event,
                &pair_material.claim,
                &snapshot_event,
                pair_material.deadline,
                checked_at,
            )?;
        }

        let mut committed = Vec::with_capacity(6);
        for identified in parallel_recon_exact_pair_events(&pair_material) {
            let envelope = preallocate_identified_event_envelope(
                &transaction,
                identified.event_id,
                identified.event,
            )?;
            apply_exact_event_envelope_with_admission(
                &transaction,
                &artifact_root,
                &envelope,
                EventAdmission::ParallelReconBootstrap,
            )?;
            committed.push(envelope);
        }
        let pair_children = parallel_recon_exact_pair_outcome_children(
            &transaction,
            &artifact_root,
            run_id,
            &pair_material,
            &committed,
            true,
        )?;
        for (index, child) in pair_children.iter().enumerate() {
            let replay = validate_fresh_child_replay(
                &transaction,
                &artifact_root,
                run_id,
                child,
                &pair_material.claim_event,
                &pair_material.claim,
            )?;
            let start = &authority.starts[index];
            let event = child_repository_explorer_attempt_start_event(
                pair_material.session_id,
                run_id,
                &replay,
                0,
                start.attempt_id,
                start.local_plan_id,
                start.started_at.clone(),
            )?;
            let envelope =
                preallocate_identified_event_envelope(&transaction, start.event_id, event)?;
            apply_exact_event_envelope_with_admission(
                &transaction,
                &artifact_root,
                &envelope,
                EventAdmission::ParallelReconBootstrap,
            )?;
            committed.push(envelope);
        }

        recheck_parallel_recon_exact_pair_guard(&transaction, &pair_material)?;
        let lifecycle = replay_repository_snapshot_lifecycle(&transaction, &artifact_root, &run)?;
        if !matches!(
            lifecycle,
            RepositorySnapshotLifecycleReplay::Active {
                ref lease_event,
                ..
            } if lease_event.id == authority.pair.snapshot_lease_event_id
        ) || current_run_state(&transaction, run.spec.session_id, run_id)?
            != birdcode_protocol::RunState::Running
            || latest_cancellation_generation(&transaction, run.spec.session_id, run_id)? != 0
            || latest_claim_for_run(&transaction, run.spec.session_id, run_id)?
                != Some(pair_material.claim_event.clone())
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let material = bootstrap_material_from_events(
            &transaction,
            &artifact_root,
            run_id,
            &authority,
            &committed,
        )?;
        if material
            .children
            .iter()
            .any(|child| !matches!(child.projection.recovery, ChildRecoveryState::ReadyForModel))
        {
            return Err(StoreError::InvalidStateEvent);
        }
        recheck_parallel_recon_exact_pair_guard(&transaction, &pair_material)?;
        transaction.commit()?;
        Ok(ParallelReconBootstrapOutcome::Appended { material })
    }

    /// Recovers a complete committed six-event bootstrap by durable planner
    /// acceptance. `None` means no child lifecycle event exists for the run.
    ///
    /// Partial authorization, issuance, or initial-start history fails closed.
    /// The returned material is historical evidence, not dispatch authority.
    ///
    /// # Errors
    ///
    /// Returns an error for a contradictory key, incomplete or non-contiguous
    /// history, altered artifacts, or any semantic substitution.
    pub fn recover_parallel_recon_bootstrap(
        &self,
        run_id: RunId,
        accepted_planner_turn_event_id: EventId,
    ) -> Result<Option<ParallelReconBootstrapRecovery>, StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let run = durable_run_for_claim_refresh(&transaction, run_id)?;
        if run.id != run_id || run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1 {
            return Err(StoreError::InvalidStateEvent);
        }
        let Some(events) = committed_bootstrap_events(
            &transaction,
            run.spec.session_id,
            run_id,
            accepted_planner_turn_event_id,
        )?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let authority = authority_from_committed(accepted_planner_turn_event_id, &events)?;
        let material = bootstrap_material_from_events(
            &transaction,
            &self.artifact_root,
            run_id,
            &authority,
            &events,
        )?;
        transaction.commit()?;
        Ok(Some(material))
    }
}
