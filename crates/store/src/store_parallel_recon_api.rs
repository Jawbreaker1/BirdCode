//! Store-owned Parallel Repository Reconnaissance lifecycle and completion APIs.

use super::{
    BTreeSet, ChildClaimAdoptionKindV1, DurableRunClaimProjection, EventAdmission, EventId,
    EventPayload, IdempotentAppendOutcome, IdentifiedNewEvent, MAX_SQLITE_INTEGER_U64, NewEvent,
    PARALLEL_RECON_CLAIM_REFRESH_PRODUCER,
    PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD, ParallelReconChildClaimAdoption,
    ParallelReconClaimRefreshAuthority, ParallelReconClaimRefreshOutcome,
    ParallelReconSnapshotRefreshStatus, Provenance, RECON_COMPLETION_GATE_PRODUCER,
    ReconCompletionGateAcceptanceOutcome, ReconCompletionGateAuthority, ReconRunProjection,
    RepositorySnapshotCaptureClaimAdoptedV1, RepositorySnapshotLifecycleProjection,
    RepositorySnapshotLifecycleReplay, RunId, RunPurpose, RunState, Sha256Digest, Store,
    StoreError, TransactionBehavior, Utc, apply_exact_event_envelope_with_admission,
    child_claim_matches, contiguous_adoption_leases_cover, current_run_state,
    derive_recon_completion_gate_material, durable_run_for_claim_refresh, is_terminal_run_state,
    latest_cancellation_for_run_before, latest_cancellation_generation, latest_claim_for_run,
    latest_run_event, load_event_by_id, nonterminal_child_replays_for_claim_refresh,
    preallocate_identified_event_envelope, prepare_fresh_snapshot_claim_handoff,
    prepare_renewed_snapshot_claim_handoff, project_recon_run, recon_completion_gate_projection,
    replay_repository_snapshot_lifecycle,
};
impl Store {
    /// Replays the bounded, Store-total repository snapshot lifecycle for one
    /// Parallel Repository Reconnaissance v1 run.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong run purpose or for any incomplete,
    /// ambiguous, over-budget, or structurally invalid lifecycle history.
    pub fn repository_snapshot_lifecycle(
        &self,
        run_id: RunId,
    ) -> Result<RepositorySnapshotLifecycleProjection, StoreError> {
        let run = durable_run_for_claim_refresh(&self.connection, run_id)?;
        if run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1 {
            return Err(StoreError::InvalidStateEvent);
        }
        Ok(
            replay_repository_snapshot_lifecycle(&self.connection, &self.artifact_root, &run)?
                .projection(),
        )
    }

    /// Atomically refreshes the active claim for one running Parallel
    /// Repository Reconnaissance run and rebinds every non-terminal issued
    /// child work order to that claim.
    ///
    /// The complete decision executes under one `BEGIN IMMEDIATE` writer
    /// transaction. Store derives claim/cancellation generations and the child
    /// set from durable state, sorts children by canonical work-order identity,
    /// and commits either the renewal plus every adoption or nothing. Two
    /// concurrent same-runtime callers therefore coalesce: after one commits
    /// `Renewed`, the next observes the fresh fully rebound claim and returns
    /// `Fresh` without appending another event.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong run purpose/state, missing or corrupt
    /// claim/child history, invalid lease authority, an incomplete identity
    /// budget, replay-budget exhaustion, or any event-admission failure. Any
    /// such failure rolls the entire transaction back.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "the transaction boundary intentionally consumes fresh mechanical identities"
    )]
    pub fn refresh_parallel_recon_claim(
        &mut self,
        run_id: RunId,
        authority: ParallelReconClaimRefreshAuthority,
    ) -> Result<ParallelReconClaimRefreshOutcome, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = durable_run_for_claim_refresh(&transaction, run_id)?;
        if run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1 {
            return Err(StoreError::InvalidStateEvent);
        }
        let snapshot_lifecycle =
            replay_repository_snapshot_lifecycle(&transaction, &self.artifact_root, &run)?;
        if let RepositorySnapshotLifecycleReplay::PendingCleanup { grants, .. } =
            &snapshot_lifecycle
        {
            let cleanup_grant_event = grants
                .last()
                .ok_or(StoreError::InvalidStateEvent)?
                .event
                .clone();
            let snapshot = snapshot_lifecycle.refresh_status();
            transaction.commit()?;
            return Ok(ParallelReconClaimRefreshOutcome::CleanupInProgress {
                cleanup_grant_event,
                snapshot,
            });
        }
        let state = current_run_state(&transaction, run.spec.session_id, run_id)?;
        if is_terminal_run_state(state) {
            transaction.commit()?;
            return Ok(ParallelReconClaimRefreshOutcome::Terminal { state });
        }
        if state != RunState::Running {
            return Err(StoreError::InvalidStateEvent);
        }

        let cancellation_generation =
            latest_cancellation_generation(&transaction, run.spec.session_id, run_id)?;
        if cancellation_generation != 0 {
            let cancellation_event = latest_cancellation_for_run_before(
                &transaction,
                run.spec.session_id,
                run_id,
                MAX_SQLITE_INTEGER_U64,
            )?
            .ok_or(StoreError::InvalidStateEvent)?;
            let EventPayload::CancellationRequested(cancellation) =
                cancellation_event.payload.clone()
            else {
                return Err(StoreError::InvalidStateEvent);
            };
            if cancellation.cancellation_generation != cancellation_generation {
                return Err(StoreError::InvalidStateEvent);
            }
            transaction.commit()?;
            return Ok(ParallelReconClaimRefreshOutcome::Cancelled {
                cancellation_event,
                cancellation,
            });
        }

        let claim_event = latest_claim_for_run(&transaction, run.spec.session_id, run_id)?
            .ok_or(StoreError::InvalidStateEvent)?;
        let EventPayload::RunClaimed(claim) = &claim_event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        if claim.cancellation_generation != cancellation_generation {
            return Err(StoreError::InvalidStateEvent);
        }
        let current_claim = DurableRunClaimProjection {
            event: claim_event.clone(),
            claim: claim.clone(),
        };
        let checked_at = Utc::now();
        if authority.fresh_through <= checked_at
            || authority.renewed_lease_expires_at <= authority.fresh_through
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let same_owner = claim_event.actor_id == authority.actor_id
            && claim.runtime_instance_id == authority.runtime_instance_id;
        if !same_owner && claim.lease_expires_at > checked_at {
            transaction.commit()?;
            return Ok(ParallelReconClaimRefreshOutcome::ForeignOwner {
                claim: current_claim,
                snapshot: snapshot_lifecycle.refresh_status(),
            });
        }

        let children =
            nonterminal_child_replays_for_claim_refresh(&transaction, &self.artifact_root, &run)?;
        let nonterminal_work_orders = children
            .iter()
            .map(|child| child.work_order_id)
            .collect::<Vec<_>>();
        let children_already_bound = children
            .iter()
            .all(|child| child_claim_matches(&child.replay.active_claim, &claim_event, claim));
        let snapshot_already_bound = match &snapshot_lifecycle {
            RepositorySnapshotLifecycleReplay::Open(open) => {
                open.active_claim_event.id == claim_event.id && open.active_claim == *claim
            }
            _ => true,
        };
        if same_owner
            && claim.lease_expires_at > authority.fresh_through
            && children_already_bound
            && snapshot_already_bound
        {
            let snapshot = snapshot_lifecycle.refresh_status();
            let pending_snapshot_claim = prepare_fresh_snapshot_claim_handoff(
                &snapshot_lifecycle,
                claim_event.clone(),
                &snapshot,
            )?;
            transaction.commit()?;
            return Ok(ParallelReconClaimRefreshOutcome::Fresh {
                claim: current_claim,
                nonterminal_work_orders,
                snapshot,
                snapshot_claim: pending_snapshot_claim.issue_after_commit(),
            });
        }
        let unique_adoption_ids = authority
            .child_adoption_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if unique_adoption_ids.len() != authority.child_adoption_ids.len()
            || authority
                .child_adoption_ids
                .iter()
                .any(|identity| identity.as_uuid().is_nil())
            || children.len() > authority.child_adoption_ids.len()
            || authority.refreshed_at.runtime_instance_id != authority.runtime_instance_id
            || authority.refreshed_at.monotonic_nanos == 0
            || authority.refreshed_at.observed_at > checked_at
            || authority.refreshed_at.observed_at >= authority.fresh_through
            || authority.refreshed_at.observed_at >= authority.renewed_lease_expires_at
            || children.iter().any(|child| {
                child.prior_adoption_count
                    >= PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD as usize
            })
        {
            return Err(StoreError::InvalidStateEvent);
        }

        let claim_generation = claim
            .claim_generation
            .checked_add(1)
            .ok_or(StoreError::InvalidStateEvent)?;
        let claim_parent = latest_run_event(&transaction, run.spec.session_id, run_id)?.id;
        let renewed_claim = birdcode_protocol::RunClaimed {
            claim_id: authority.renewal_claim_id,
            runtime_instance_id: authority.runtime_instance_id,
            claim_generation,
            cancellation_generation,
            lease_expires_at: authority.renewed_lease_expires_at,
        };
        let renewed_claim_event = preallocate_identified_event_envelope(
            &transaction,
            EventId::new(),
            NewEvent {
                session_id: run.spec.session_id,
                run_id: Some(run_id),
                actor_id: authority.actor_id,
                causal_parent: Some(claim_parent),
                provenance: Provenance {
                    producer: PARALLEL_RECON_CLAIM_REFRESH_PRODUCER.to_owned(),
                    backend: None,
                    raw_artifact: None,
                },
                payload: EventPayload::RunClaimed(renewed_claim.clone()),
            },
        )?;
        if authority.refreshed_at.runtime_instance_id != renewed_claim.runtime_instance_id
            || authority.refreshed_at.observed_at > renewed_claim_event.occurred_at
        {
            return Err(StoreError::InvalidStateEvent);
        }
        apply_exact_event_envelope_with_admission(
            &transaction,
            &self.artifact_root,
            &renewed_claim_event,
            EventAdmission::ParallelReconClaimRefresh,
        )?;

        let (snapshot_adoption, snapshot) = match &snapshot_lifecycle {
            RepositorySnapshotLifecycleReplay::Open(open)
                if same_owner
                    && open.active_claim_event.id == claim_event.id
                    && open.active_claim == *claim
                    && claim.lease_expires_at > renewed_claim_event.occurred_at =>
            {
                let identity = open
                    .identity
                    .as_ref()
                    .ok_or(StoreError::InvalidStateEvent)?;
                let adopted = RepositorySnapshotCaptureClaimAdoptedV1 {
                    adoption_id: authority.snapshot_capture_adoption_id,
                    issuer_actor_id: authority.actor_id,
                    snapshot_id: identity.snapshot_id.clone(),
                    lease_id: identity.lease_id,
                    snapshot_lease_event_id: identity.lease_event_id,
                    workspace_writer_lease_id: open.writer_evidence.writer_lease_id.clone(),
                    writer_lease_generation: open.writer_evidence.writer_lease_generation,
                    writer_revocation_event_id: open.writer_revocation_event.id,
                    prior_claim_event_id: claim_event.id,
                    prior_claim_id: claim.claim_id,
                    prior_claim_generation: claim.claim_generation,
                    prior_runtime_instance_id: claim.runtime_instance_id,
                    new_claim_event_id: renewed_claim_event.id,
                    new_claim_id: renewed_claim.claim_id,
                    new_claim_generation: renewed_claim.claim_generation,
                    new_runtime_instance_id: renewed_claim.runtime_instance_id,
                    cancellation_generation,
                    adopted_at: authority.refreshed_at.clone(),
                };
                let adoption_event = preallocate_identified_event_envelope(
                    &transaction,
                    EventId::new(),
                    NewEvent {
                        session_id: run.spec.session_id,
                        run_id: Some(run_id),
                        actor_id: authority.actor_id,
                        causal_parent: Some(open.latest_capture_event.id),
                        provenance: Provenance {
                            producer: PARALLEL_RECON_CLAIM_REFRESH_PRODUCER.to_owned(),
                            backend: None,
                            raw_artifact: None,
                        },
                        payload: EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(adopted),
                    },
                )?;
                if authority.refreshed_at.observed_at > adoption_event.occurred_at {
                    return Err(StoreError::InvalidStateEvent);
                }
                if claim.lease_expires_at <= adoption_event.occurred_at {
                    (
                        None,
                        ParallelReconSnapshotRefreshStatus::RecoveryRequired {
                            writer_revocation_event_id: open.writer_revocation_event.id,
                            prior_claim_event_id: open.active_claim_event.id,
                        },
                    )
                } else {
                    apply_exact_event_envelope_with_admission(
                        &transaction,
                        &self.artifact_root,
                        &adoption_event,
                        EventAdmission::ParallelReconClaimRefresh,
                    )?;
                    let refreshed = replay_repository_snapshot_lifecycle(
                        &transaction,
                        &self.artifact_root,
                        &run,
                    )?;
                    (Some(adoption_event), refreshed.refresh_status())
                }
            }
            RepositorySnapshotLifecycleReplay::Open(open) => (
                None,
                ParallelReconSnapshotRefreshStatus::RecoveryRequired {
                    writer_revocation_event_id: open.writer_revocation_event.id,
                    prior_claim_event_id: open.active_claim_event.id,
                },
            ),
            other => (None, other.refresh_status()),
        };

        let mut adoptions = Vec::with_capacity(children.len());
        let mut contiguous_child_adoption_deadlines = Vec::with_capacity(children.len());
        for (child, adoption_id) in children.into_iter().zip(authority.child_adoption_ids) {
            let kind = if child.replay.active_claim.runtime_instance_id
                == renewed_claim.runtime_instance_id
            {
                ChildClaimAdoptionKindV1::Renewal
            } else {
                ChildClaimAdoptionKindV1::Takeover
            };
            let attempt_id = child
                .replay
                .attempts
                .last()
                .map(|attempt| attempt.projection.attempt_id);
            let causal_parent = child
                .replay
                .attempts
                .last()
                .map_or(child.replay.pre_attempt_tail_event_id, |attempt| {
                    attempt.tail_event_id
                });
            let adopted = birdcode_protocol::ChildExecutionClaimAdoptedV1 {
                adoption_id,
                work_order_id: child.work_order_id,
                execution_id: child.replay.issued.spec.execution_id,
                attempt_id,
                prior_claim_event_id: child.replay.active_claim.event_id,
                prior_claim_id: child.replay.active_claim.claim_id,
                prior_claim_generation: child.replay.active_claim.generation,
                prior_runtime_instance_id: child.replay.active_claim.runtime_instance_id,
                new_claim_event_id: renewed_claim_event.id,
                new_claim_id: renewed_claim.claim_id,
                new_claim_generation: renewed_claim.claim_generation,
                new_runtime_instance_id: renewed_claim.runtime_instance_id,
                cancellation_generation,
                kind,
            };
            let event = preallocate_identified_event_envelope(
                &transaction,
                EventId::new(),
                NewEvent {
                    session_id: run.spec.session_id,
                    run_id: Some(run_id),
                    actor_id: authority.actor_id,
                    causal_parent: Some(causal_parent),
                    provenance: Provenance {
                        producer: PARALLEL_RECON_CLAIM_REFRESH_PRODUCER.to_owned(),
                        backend: None,
                        raw_artifact: None,
                    },
                    payload: EventPayload::ChildExecutionClaimAdopted(adopted),
                },
            )?;
            apply_exact_event_envelope_with_admission(
                &transaction,
                &self.artifact_root,
                &event,
                EventAdmission::ParallelReconClaimRefresh,
            )?;
            if kind == ChildClaimAdoptionKindV1::Renewal
                && child.replay.active_claim.lease_expires_at > event.occurred_at
            {
                contiguous_child_adoption_deadlines
                    .push(child.replay.active_claim.lease_expires_at);
            }
            adoptions.push(ParallelReconChildClaimAdoption {
                work_order_id: child.work_order_id,
                event,
            });
        }
        let precommit_checked_at = Utc::now();
        if renewed_claim.lease_expires_at <= precommit_checked_at
            || !contiguous_adoption_leases_cover(
                snapshot_adoption.as_ref().map(|_| claim.lease_expires_at),
                &contiguous_child_adoption_deadlines,
                precommit_checked_at,
            )
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let pending_snapshot_claim = prepare_renewed_snapshot_claim_handoff(
            &snapshot_lifecycle,
            claim_event,
            renewed_claim_event.clone(),
            snapshot_adoption,
            &snapshot,
        )?;
        transaction.commit()?;
        Ok(ParallelReconClaimRefreshOutcome::Renewed {
            claim: DurableRunClaimProjection {
                event: renewed_claim_event,
                claim: renewed_claim,
            },
            snapshot,
            snapshot_claim: pending_snapshot_claim.issue_after_commit(),
            adoptions,
        })
    }

    /// Replays the bounded run guard and planner-v2 control history.
    ///
    /// The result contains exact committed envelopes for every recovery
    /// boundary and a closed next action. It never selects behavior by parsing
    /// model-authored text. Unknown runs return `None`; known runs with the
    /// wrong purpose or contradictory history fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt projections, oversized planner history,
    /// broken turn chains, missing artifacts, or non-reconnaissance runs.
    pub fn recon_run_projection(
        &self,
        run_id: RunId,
    ) -> Result<Option<ReconRunProjection>, StoreError> {
        project_recon_run(&self.connection, &self.artifact_root, run_id)
    }

    /// Derives the canonical completion receipt exclusively from durable
    /// state, persists it, and commits the accept-only gate idempotently.
    ///
    /// No caller-supplied planner claim, child outcome, evidence identity,
    /// snapshot binding, or provenance is accepted by this API.
    ///
    /// # Errors
    ///
    /// Returns an error unless the run is at the exact post-release
    /// completion boundary and every planner, child, overlap, obligation,
    /// claim, cancellation, artifact, and runtime-clock invariant validates.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh completion authority"
    )]
    pub fn accept_recon_completion_gate(
        &mut self,
        run_id: RunId,
        authority: ReconCompletionGateAuthority,
    ) -> Result<ReconCompletionGateAcceptanceOutcome, StoreError> {
        if let Some(existing) = load_event_by_id(&self.connection, authority.event_id)? {
            let EventPayload::ReconCompletionGateAcceptedV1(gate) = &existing.payload else {
                return Err(StoreError::IdentifiedEventConflict);
            };
            if existing.run_id != Some(run_id)
                || gate.gate_id != authority.gate_id
                || gate.accepted_at != authority.accepted_at
            {
                return Err(StoreError::IdentifiedEventConflict);
            }
            let projection = recon_completion_gate_projection(
                &self.connection,
                &self.artifact_root,
                existing.session_id,
                run_id,
            )?
            .filter(|projection| projection.event.id == existing.id)
            .ok_or(StoreError::InvalidStateEvent)?;
            return Ok(ReconCompletionGateAcceptanceOutcome {
                append: IdempotentAppendOutcome::AlreadyPresent { event: existing },
                projection,
            });
        }
        let material = derive_recon_completion_gate_material(
            &self.connection,
            &self.artifact_root,
            run_id,
            authority.gate_id,
            &authority.accepted_at,
        )?;
        let receipt_artifact = self.put_artifact(
            &serde_json::to_vec(&material.receipt)?,
            birdcode_protocol::RECON_COMPLETION_GATE_RECEIPT_V1_MEDIA_TYPE,
        )?;
        let receipt_digest = Sha256Digest::parse(receipt_artifact.sha256.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?;
        let payload = material.accepted_payload(receipt_artifact.clone(), receipt_digest);
        let identified = IdentifiedNewEvent {
            event_id: authority.event_id,
            event: NewEvent {
                session_id: material.session_id,
                run_id: Some(run_id),
                actor_id: material.actor_id,
                causal_parent: Some(material.gate_parent_event_id),
                provenance: Provenance {
                    producer: RECON_COMPLETION_GATE_PRODUCER.to_owned(),
                    backend: None,
                    raw_artifact: Some(receipt_artifact),
                },
                payload: EventPayload::ReconCompletionGateAcceptedV1(payload),
            },
        };
        let append = self.append_identified_event(identified)?;
        let projection = recon_completion_gate_projection(
            &self.connection,
            &self.artifact_root,
            material.session_id,
            run_id,
        )?
        .filter(|projection| projection.event.id == authority.event_id)
        .ok_or(StoreError::InvalidStateEvent)?;
        Ok(ReconCompletionGateAcceptanceOutcome { append, projection })
    }
}
