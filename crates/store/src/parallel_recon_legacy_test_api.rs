//! Test-only compatibility surface for four-event Parallel Recon history.
//!
//! Product code cannot issue or recover the legacy split boundary. The
//! implementation remains available only to construct historical fixtures
//! that prove the six-event bootstrap fails closed.

use super::{
    EventAdmission, EventId, EventPayload, PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS,
    ParallelReconExactPairIssuanceAuthority, ParallelReconExactPairIssuanceOutcome,
    ParallelReconExactPairMaterialMode, ParallelReconExactPairRecovery, RunId, RunPurpose, Store,
    StoreError, TransactionBehavior, apply_exact_event_envelope_with_admission, decode_stored_run,
    derive_parallel_recon_exact_pair_material, durable_run_for_claim_refresh, load_event_by_id,
    new_event_from_envelope, parallel_recon_exact_pair_authority_event_ids,
    parallel_recon_exact_pair_authority_from_committed, parallel_recon_exact_pair_committed_events,
    parallel_recon_exact_pair_events, parallel_recon_exact_pair_history_counts,
    parallel_recon_exact_pair_outcome_children, preallocate_identified_event_envelope,
    recheck_parallel_recon_exact_pair_guard, stored_event_for_run,
};
use rusqlite::OptionalExtension;

impl Store {
    /// Constructs the historical four-event split boundary for fail-closed
    /// compatibility tests. This method is never compiled into product code.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "the historical fixture consumes the original identity authority"
    )]
    pub(crate) fn issue_parallel_recon_exact_pair(
        &mut self,
        run_id: RunId,
        authority: ParallelReconExactPairIssuanceAuthority,
    ) -> Result<ParallelReconExactPairIssuanceOutcome, StoreError> {
        let artifact_root = self.artifact_root.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = durable_run_for_claim_refresh(&transaction, run_id)?;
        if run.id != run_id || run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1 {
            return Err(StoreError::InvalidStateEvent);
        }
        let event_ids = parallel_recon_exact_pair_authority_event_ids(&authority);
        let mut existing = Vec::with_capacity(event_ids.len());
        for event_id in event_ids {
            existing.push(load_event_by_id(&transaction, event_id)?);
        }
        let present = existing.iter().filter(|event| event.is_some()).count();
        if present != 0 && present != existing.len() {
            return Err(StoreError::InvalidStateEvent);
        }
        if present == existing.len() {
            let existing = existing
                .into_iter()
                .map(|event| event.ok_or(StoreError::InvalidStateEvent))
                .collect::<Result<Vec<_>, _>>()?;
            let [
                authorization_left,
                authorization_right,
                issuance_left,
                issuance_right,
            ] = existing.as_slice()
            else {
                return Err(StoreError::InvalidStateEvent);
            };
            if authorization_left.sequence.checked_add(1) != Some(authorization_right.sequence)
                || authorization_right.sequence.checked_add(1) != Some(issuance_left.sequence)
                || issuance_left.sequence.checked_add(1) != Some(issuance_right.sequence)
            {
                return Err(StoreError::InvalidStateEvent);
            }
            let material = derive_parallel_recon_exact_pair_material(
                &transaction,
                &artifact_root,
                run_id,
                &authority,
                ParallelReconExactPairMaterialMode::Historical {
                    authorization_sequence: authorization_left.sequence,
                },
            )?;
            let expected = parallel_recon_exact_pair_events(&material);
            let (authorization_count, source_authorization_count, issuance_count) =
                parallel_recon_exact_pair_history_counts(
                    &transaction,
                    material.session_id,
                    run_id,
                    authority.accepted_planner_turn_event_id,
                )?;
            if authorization_count != u64::from(PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS)
                || source_authorization_count != u64::from(PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS)
                || issuance_count != u64::from(PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS)
            {
                return Err(StoreError::InvalidStateEvent);
            }
            if existing.iter().zip(&expected).any(|(committed, expected)| {
                committed.id != expected.event_id
                    || new_event_from_envelope(committed) != expected.event
            }) {
                return Err(StoreError::IdentifiedEventConflict);
            }
            if existing.iter().any(|event| {
                event.occurred_at > material.deadline
                    || event.occurred_at >= material.claim.lease_expires_at
            }) {
                return Err(StoreError::InvalidStateEvent);
            }
            let children = parallel_recon_exact_pair_outcome_children(
                &transaction,
                &artifact_root,
                run_id,
                &material,
                &existing,
                false,
            )?;
            transaction.commit()?;
            return Ok(ParallelReconExactPairIssuanceOutcome::AlreadyPresent {
                policy_artifact: material.policy_artifact,
                children,
            });
        }
        let material = derive_parallel_recon_exact_pair_material(
            &transaction,
            &artifact_root,
            run_id,
            &authority,
            ParallelReconExactPairMaterialMode::Fresh,
        )?;
        let (authorization_count, source_authorization_count, issuance_count) =
            parallel_recon_exact_pair_history_counts(
                &transaction,
                material.session_id,
                run_id,
                authority.accepted_planner_turn_event_id,
            )?;
        if authorization_count != 0 || source_authorization_count != 0 || issuance_count != 0 {
            return Err(StoreError::InvalidStateEvent);
        }

        let expected = parallel_recon_exact_pair_events(&material);
        let mut appended = Vec::with_capacity(expected.len());
        for identified in expected {
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
            appended.push(envelope);
        }
        recheck_parallel_recon_exact_pair_guard(&transaction, &material)?;
        let children = parallel_recon_exact_pair_outcome_children(
            &transaction,
            &artifact_root,
            run_id,
            &material,
            &appended,
            true,
        )?;
        recheck_parallel_recon_exact_pair_guard(&transaction, &material)?;
        transaction.commit()?;
        Ok(ParallelReconExactPairIssuanceOutcome::Appended {
            policy_artifact: material.policy_artifact,
            children,
        })
    }

    /// Recovers historical four-event fixtures so tests can distinguish
    /// complete legacy history from forbidden partial history.
    pub(crate) fn recover_parallel_recon_exact_pair(
        &self,
        run_id: RunId,
        accepted_planner_turn_event_id: EventId,
    ) -> Result<Option<ParallelReconExactPairRecovery>, StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let run_json = transaction
            .query_row(
                "SELECT value_json FROM runs WHERE id = ?1",
                [run_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(run_json) = run_json else {
            return Err(StoreError::InvalidStateEvent);
        };
        let run = decode_stored_run(&run_json)?;
        if run.id != run_id
            || run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1
            || run.spec.limits.max_subagents != PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let accepted_event = stored_event_for_run(
            &transaction,
            run.spec.session_id,
            run_id,
            accepted_planner_turn_event_id,
        )?;
        if !matches!(
            accepted_event.payload,
            EventPayload::PlannerTurnAcceptedV1(ref accepted)
                if accepted.purpose
                    == birdcode_protocol::PlannerTurnPurposeV1::InitialDelegation
        ) {
            return Err(StoreError::InvalidStateEvent);
        }

        let Some(events) = parallel_recon_exact_pair_committed_events(
            &transaction,
            run.spec.session_id,
            run_id,
            accepted_planner_turn_event_id,
        )?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let authority = parallel_recon_exact_pair_authority_from_committed(
            accepted_planner_turn_event_id,
            &events,
        )?;
        let material = derive_parallel_recon_exact_pair_material(
            &transaction,
            &self.artifact_root,
            run_id,
            &authority,
            ParallelReconExactPairMaterialMode::Historical {
                authorization_sequence: events[0].sequence,
            },
        )?;
        let expected = parallel_recon_exact_pair_events(&material);
        if events.iter().zip(&expected).any(|(committed, expected)| {
            committed.id != expected.event_id
                || new_event_from_envelope(committed) != expected.event
        }) {
            return Err(StoreError::IdentifiedEventConflict);
        }
        if events.iter().any(|event| {
            event.occurred_at > material.deadline
                || event.occurred_at >= material.claim.lease_expires_at
        }) {
            return Err(StoreError::InvalidStateEvent);
        }
        let children = parallel_recon_exact_pair_outcome_children(
            &transaction,
            &self.artifact_root,
            run_id,
            &material,
            &events,
            false,
        )?;
        let recovery = ParallelReconExactPairRecovery {
            policy_artifact: material.policy_artifact,
            children,
        };
        transaction.commit()?;
        Ok(Some(recovery))
    }
}
