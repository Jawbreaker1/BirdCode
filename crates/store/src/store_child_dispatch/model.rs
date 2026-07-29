//! Store-owned child model dispatch and recovery APIs.

use super::super::{
    CHILD_REPOSITORY_EXPLORER_PREPARATION_PRODUCER, ChildPendingEffectProjection,
    ChildRecoveryState, ChildRepositoryExplorerPreparationAuthority,
    ChildRepositoryExplorerPreparedMaterial, ChildWorkOrderId, EventEnvelope, EventPayload,
    IdempotentAppendOutcome, IdentifiedNewEvent, RunId, Store, StoreError,
    build_child_repository_explorer_prepared_event, child_repository_explorer_committed_material,
    child_repository_explorer_current_prepared_material, load_event_by_id,
};
#[cfg(test)]
use super::super::{ChildRepositoryExplorerUnknownAuthority, EventId};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChildRepositoryExplorerPreparationOutcome {
    pub(crate) append: IdempotentAppendOutcome,
    pub(crate) material: ChildRepositoryExplorerPreparedMaterial,
}

/// Durable evidence that one exact child model Prepared boundary exists.
///
/// The normal preparation and recovery APIs return no compiled prompt,
/// backend-ready request, or adapter authority alongside this evidence.
/// Callers can use it to identify the boundary that must be reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildModelPreparedEvidence {
    pub prepared_event: EventEnvelope,
}

/// Fresh, affine authority for dispatching one Store-committed child model
/// request.
///
/// The handoff is intentionally neither `Clone` nor serializable. It is issued
/// only when this call appended the Prepared boundary and must be consumed by
/// the daemon's model-effect lane. A recovered or idempotently replayed
/// Prepared boundary never recreates this authority.
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// fn duplicate(value: ChildModelDispatchHandoff) {
///     let _copy = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// let _forged = ChildModelDispatchHandoff::default();
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// fn serialize(value: &ChildModelDispatchHandoff) {
///     let _encoded = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::ChildModelDispatchHandoff;
///
/// let _decoded: ChildModelDispatchHandoff = serde_json::from_str("{}").unwrap();
/// ```
#[must_use = "a fresh child model dispatch handoff must be consumed or explicitly discarded"]
pub struct ChildModelDispatchHandoff {
    material: Box<ChildRepositoryExplorerPreparedMaterial>,
}

const _: () =
    assert!(std::mem::size_of::<ChildModelDispatchHandoff>() == std::mem::size_of::<usize>());

impl ChildModelDispatchHandoff {
    /// Returns the exact durable boundary that authorized this one dispatch.
    #[must_use]
    pub const fn prepared_event(&self) -> &EventEnvelope {
        &self.material.prepared_event
    }

    /// Consumes the affine handoff and releases the exact compiled provider
    /// request to the trusted model-effect lane.
    #[must_use]
    pub fn into_backend_request(self) -> birdcode_backends::StructuredInferenceRequest {
        let ChildRepositoryExplorerPreparedMaterial {
            backend_request, ..
        } = *self.material;
        backend_request
    }
}

/// Closed preparation result that distinguishes fresh effect authority from
/// replay-only evidence.
#[must_use = "child model preparation must either dispatch once or reconcile durable evidence"]
pub enum ChildModelDispatchPreparationOutcome {
    Appended {
        evidence: ChildModelPreparedEvidence,
        dispatch: ChildModelDispatchHandoff,
    },
    AlreadyPresent {
        evidence: ChildModelPreparedEvidence,
    },
}

fn child_model_dispatch_outcome(
    outcome: ChildRepositoryExplorerPreparationOutcome,
) -> Result<ChildModelDispatchPreparationOutcome, StoreError> {
    let prepared_event = outcome.material.prepared_event.clone();
    let evidence = ChildModelPreparedEvidence {
        prepared_event: prepared_event.clone(),
    };
    match outcome.append {
        IdempotentAppendOutcome::Appended { event } if event == prepared_event => {
            Ok(ChildModelDispatchPreparationOutcome::Appended {
                evidence,
                dispatch: ChildModelDispatchHandoff {
                    material: Box::new(outcome.material),
                },
            })
        }
        IdempotentAppendOutcome::AlreadyPresent { event } if event == prepared_event => {
            Ok(ChildModelDispatchPreparationOutcome::AlreadyPresent { evidence })
        }
        IdempotentAppendOutcome::Appended { .. }
        | IdempotentAppendOutcome::AlreadyPresent { .. } => Err(StoreError::InvalidStateEvent),
    }
}

fn exact_existing_child_repository_explorer_prepared_event(
    store: &Store,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
    authority: &ChildRepositoryExplorerPreparationAuthority,
) -> Result<Option<EventEnvelope>, StoreError> {
    let Some(existing) = load_event_by_id(&store.connection, authority.event_id)? else {
        return Ok(None);
    };
    let EventPayload::ChildModelInferencePreparedV2(prepared_v2) = &existing.payload else {
        return Err(StoreError::IdentifiedEventConflict);
    };
    if existing.run_id != Some(run_id)
        || prepared_v2.prepared.binding.work_order_id != work_order_id
        || prepared_v2.prepared.model_call_id != authority.model_call_id
        || prepared_v2.prepared.token_reservation != authority.token_reservation
        || prepared_v2.prepared.prepared_at != authority.prepared_at
        || existing.provenance.producer != CHILD_REPOSITORY_EXPLORER_PREPARATION_PRODUCER
    {
        return Err(StoreError::IdentifiedEventConflict);
    }
    Ok(Some(existing))
}

fn existing_child_repository_explorer_preparation(
    store: &Store,
    run_id: RunId,
    work_order_id: ChildWorkOrderId,
    authority: &ChildRepositoryExplorerPreparationAuthority,
) -> Result<Option<ChildModelPreparedEvidence>, StoreError> {
    let Some(existing) = exact_existing_child_repository_explorer_prepared_event(
        store,
        run_id,
        work_order_id,
        authority,
    )?
    else {
        return Ok(None);
    };
    child_repository_explorer_committed_material(
        &store.connection,
        &store.artifact_root,
        existing.clone(),
    )?;
    Ok(Some(ChildModelPreparedEvidence {
        prepared_event: existing,
    }))
}

enum ChildRepositoryExplorerPreparationBeforeAppend {
    Existing(Box<ChildRepositoryExplorerPreparationOutcome>),
    Identified(Box<IdentifiedNewEvent>),
}

impl Store {
    /// Commits one exact repository-explorer model preparation and returns
    /// fresh dispatch authority only to the writer that appended it.
    ///
    /// Exact replay returns the same durable evidence without a handoff. The
    /// normal public preparation and recovery paths do not directly return a
    /// backend-ready request unless this call owns the fresh append.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale child boundary, reused identities, invalid
    /// reservation or clock authority, exhausted budget, artifact drift, or a
    /// child history that does not replay exactly.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh runtime authority"
    )]
    pub fn prepare_child_repository_explorer_dispatch(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: ChildRepositoryExplorerPreparationAuthority,
    ) -> Result<ChildModelDispatchPreparationOutcome, StoreError> {
        self.prepare_child_repository_explorer_dispatch_after_initial_miss(
            run_id,
            work_order_id,
            &authority,
            || {},
            || {},
        )
    }

    fn prepare_child_repository_explorer_dispatch_after_initial_miss<F, G>(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: &ChildRepositoryExplorerPreparationAuthority,
        after_initial_miss: F,
        after_build_before_append: G,
    ) -> Result<ChildModelDispatchPreparationOutcome, StoreError>
    where
        F: FnOnce(),
        G: FnOnce(),
    {
        let before_append = match self.child_repository_explorer_preparation_before_append(
            run_id,
            work_order_id,
            authority,
            after_initial_miss,
        ) {
            Ok(before_append) => before_append,
            Err(error) => {
                return match existing_child_repository_explorer_preparation(
                    self,
                    run_id,
                    work_order_id,
                    authority,
                )? {
                    Some(evidence) => {
                        Ok(ChildModelDispatchPreparationOutcome::AlreadyPresent { evidence })
                    }
                    None => Err(error),
                };
            }
        };
        if matches!(
            &before_append,
            ChildRepositoryExplorerPreparationBeforeAppend::Identified(_)
        ) {
            after_build_before_append();
        }
        child_model_dispatch_outcome(
            self.commit_child_repository_explorer_preparation(before_append)?,
        )
    }

    /// Returns replay-only evidence for the current pending child model
    /// boundary. Recovery never recreates model dispatch authority.
    ///
    /// # Errors
    ///
    /// Returns an error for contradictory child replay, retained artifact
    /// drift, or a Prepared event that no longer recompiles exactly.
    pub fn recover_child_repository_explorer_dispatch(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
    ) -> Result<Option<ChildModelPreparedEvidence>, StoreError> {
        self.recover_child_repository_explorer_turn(run_id, work_order_id)
            .map(|material| {
                material.map(|material| ChildModelPreparedEvidence {
                    prepared_event: material.prepared_event,
                })
            })
    }

    /// Derives the complete repository-explorer turn from authoritative child
    /// history, persists the compiled prompt/request/manifest, and commits the
    /// Prepared-v2 event before returning crate-internal compiled material.
    ///
    /// The caller supplies only fresh lifecycle identities, a bounded token
    /// reservation, and the runtime clock reading. Work order, context,
    /// cumulative tool transcript, supplied-once results, model selection,
    /// causal parent, actor, and provenance cannot be overridden.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale child boundary, reused identities, invalid
    /// reservation or clock authority, exhausted budget, artifact drift, or a
    /// child history that does not replay exactly.
    #[cfg(test)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the command boundary intentionally consumes fresh runtime authority"
    )]
    pub(crate) fn prepare_child_repository_explorer_turn(
        &mut self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: ChildRepositoryExplorerPreparationAuthority,
    ) -> Result<ChildRepositoryExplorerPreparationOutcome, StoreError> {
        let before_append = self.child_repository_explorer_preparation_before_append(
            run_id,
            work_order_id,
            &authority,
            || {},
        )?;
        self.commit_child_repository_explorer_preparation(before_append)
    }

    fn child_repository_explorer_preparation_before_append<F>(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
        authority: &ChildRepositoryExplorerPreparationAuthority,
        after_initial_miss: F,
    ) -> Result<ChildRepositoryExplorerPreparationBeforeAppend, StoreError>
    where
        F: FnOnce(),
    {
        if let Some(existing) = exact_existing_child_repository_explorer_prepared_event(
            self,
            run_id,
            work_order_id,
            authority,
        )? {
            let material = child_repository_explorer_current_prepared_material(
                &self.connection,
                &self.artifact_root,
                existing.clone(),
            )?;
            return Ok(ChildRepositoryExplorerPreparationBeforeAppend::Existing(
                Box::new(ChildRepositoryExplorerPreparationOutcome {
                    append: IdempotentAppendOutcome::AlreadyPresent { event: existing },
                    material,
                }),
            ));
        }
        after_initial_miss();

        let identified =
            build_child_repository_explorer_prepared_event(self, run_id, work_order_id, authority)?;
        Ok(ChildRepositoryExplorerPreparationBeforeAppend::Identified(
            Box::new(identified),
        ))
    }

    fn commit_child_repository_explorer_preparation(
        &mut self,
        before_append: ChildRepositoryExplorerPreparationBeforeAppend,
    ) -> Result<ChildRepositoryExplorerPreparationOutcome, StoreError> {
        let identified = match before_append {
            ChildRepositoryExplorerPreparationBeforeAppend::Existing(outcome) => {
                return Ok(*outcome);
            }
            ChildRepositoryExplorerPreparationBeforeAppend::Identified(identified) => *identified,
        };
        let append = self.append_identified_event(identified)?;
        let material = match &append {
            IdempotentAppendOutcome::Appended { event } => {
                child_repository_explorer_current_prepared_material(
                    &self.connection,
                    &self.artifact_root,
                    event.clone(),
                )?
            }
            IdempotentAppendOutcome::AlreadyPresent { event } => {
                child_repository_explorer_committed_material(
                    &self.connection,
                    &self.artifact_root,
                    event.clone(),
                )?
            }
        };
        Ok(ChildRepositoryExplorerPreparationOutcome { append, material })
    }

    /// Reconstructs the exact committed repository-explorer request only for
    /// crate-internal validation while it is the current pre-effect boundary.
    ///
    /// Product recovery uses
    /// [`Self::recover_child_repository_explorer_dispatch`], which cannot
    /// expose these provider request bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for contradictory child replay, retained artifact
    /// drift, or a Prepared event that no longer recompiles exactly.
    pub(crate) fn recover_child_repository_explorer_turn(
        &self,
        run_id: RunId,
        work_order_id: ChildWorkOrderId,
    ) -> Result<Option<ChildRepositoryExplorerPreparedMaterial>, StoreError> {
        let Some(projection) = self.child_work_order_projection(run_id, work_order_id)? else {
            return Ok(None);
        };
        let ChildRecoveryState::PendingEffect(ChildPendingEffectProjection::Model {
            prepared_event,
        }) = projection.recovery
        else {
            return Ok(None);
        };
        if !matches!(
            prepared_event.payload,
            EventPayload::ChildModelInferencePreparedV2(_)
        ) {
            return Ok(None);
        }
        child_repository_explorer_current_prepared_material(
            &self.connection,
            &self.artifact_root,
            prepared_event,
        )
        .map(Some)
    }
}

#[cfg(test)]
#[path = "../tests/child_model_dispatch_authority.rs"]
mod tests;
