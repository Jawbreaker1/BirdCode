//! Controller-owned current-generation state for repository candidates.
//!
//! Immutable candidate publication answers "what did this exact producer
//! attempt create?". This module separately answers "which candidate did the
//! controller most recently select for this logical track?". Selection is an
//! explicit compare-and-swap operation over a private track capability; ready
//! order, timestamps, filenames and model-authored text never choose a head.
//!
//! A [`RepositoryCandidateHeadBindingV1`] is an observable state binding, not
//! promotion authority. In particular, reading a current head and then acting
//! on it would be a time-of-check/time-of-use bug. A future promotion boundary
//! must re-read and atomically claim the same generation while also proving
//! semantic review, mechanical validation and destination write authority.

use crate::repository_candidate::{RepositoryCandidateError, RepositoryCandidateProducerLocatorV1};
use crate::repository_candidate_resolver::VerifiedRepositoryReviewSubjectV1;
use birdcode_orchestrator::{SchedulerEventId, WorkOrderId};
use birdcode_protocol::{ArtifactRef, EventId, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// Opaque identity of one controller-owned candidate-selection track.
///
/// The identifier is serializable provenance, not mutation authority. Only
/// the private process-local [`RepositoryCandidateTrackAuthorityV1`] can
/// select or read the track through this reference implementation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RepositoryCandidateTrackIdV1(Uuid);

impl RepositoryCandidateTrackIdV1 {
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Domain-separated identity of one candidate-head selection request.
///
/// This deliberately is not a generic protocol [`EventId`]. The in-memory
/// registry has no authority to append to the global durable event journal, so
/// representing a local selection as a global event would permit identity
/// aliasing with publication, cleanup or ready events.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RepositoryCandidateSelectionIdV1(Uuid);

impl RepositoryCandidateSelectionIdV1 {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for RepositoryCandidateSelectionIdV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RepositoryCandidateTrackAuthorityMaterialV1 {
    track_id: RepositoryCandidateTrackIdV1,
    target_work_order_id: WorkOrderId,
    secret: Uuid,
}

/// Process-local authority to operate one explicit candidate track.
///
/// This type has no public constructor and implements neither `Clone` nor
/// serialization. Knowing a track ID is therefore not enough to advance it.
///
/// ```compile_fail
/// use birdcode_daemon::repository_candidate_head::RepositoryCandidateTrackAuthorityV1;
///
/// fn duplicate(authority: RepositoryCandidateTrackAuthorityV1) {
///     let _copy = authority.clone();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_daemon::repository_candidate_head::RepositoryCandidateTrackAuthorityV1;
///
/// let _forged = RepositoryCandidateTrackAuthorityV1::default();
/// ```
#[must_use = "candidate-track authority must be retained by its controller"]
#[derive(Debug, Eq, PartialEq)]
pub struct RepositoryCandidateTrackAuthorityV1 {
    material: Box<RepositoryCandidateTrackAuthorityMaterialV1>,
}

const _: () = assert!(
    std::mem::size_of::<RepositoryCandidateTrackAuthorityV1>() == std::mem::size_of::<usize>()
);

impl RepositoryCandidateTrackAuthorityV1 {
    #[must_use]
    pub const fn track_id(&self) -> RepositoryCandidateTrackIdV1 {
        self.material.track_id
    }

    #[must_use]
    pub const fn target_work_order_id(&self) -> WorkOrderId {
        self.material.target_work_order_id
    }
}

/// Monotonic, non-zero selection generation within one candidate track.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryCandidateGenerationV1(NonZeroU64);

impl RepositoryCandidateGenerationV1 {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact provenance selected as one generation of a logical candidate track.
///
/// This value is cloneable because it is an observation and a CAS expectation,
/// not an effect capability. All fields are private and are derived from a
/// journal-verified review subject plus its fully revalidated ready lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCandidateHeadBindingV1 {
    track_id: RepositoryCandidateTrackIdV1,
    generation: RepositoryCandidateGenerationV1,
    selection_id: RepositoryCandidateSelectionIdV1,
    previous_selection_id: Option<RepositoryCandidateSelectionIdV1>,
    graph_accepted_event_id: SchedulerEventId,
    reviewer_dispatch_event_id: SchedulerEventId,
    producer_dispatch_event_id: SchedulerEventId,
    dependency_handoff_event_id: SchedulerEventId,
    target_work_order_id: WorkOrderId,
    producer: RepositoryCandidateProducerLocatorV1,
    candidate_sha256: Sha256Digest,
    candidate_manifest_artifact: ArtifactRef,
    publication_event_id: EventId,
    publication_receipt_artifact: ArtifactRef,
    cleanup_prepared_event_id: EventId,
    cleanup_observed_event_id: EventId,
    cleanup_receipt_artifact: ArtifactRef,
    ready_event_id: EventId,
    ready_receipt_artifact: ArtifactRef,
}

impl RepositoryCandidateHeadBindingV1 {
    #[must_use]
    pub const fn track_id(&self) -> RepositoryCandidateTrackIdV1 {
        self.track_id
    }

    #[must_use]
    pub const fn generation(&self) -> RepositoryCandidateGenerationV1 {
        self.generation
    }

    #[must_use]
    pub const fn selection_id(&self) -> RepositoryCandidateSelectionIdV1 {
        self.selection_id
    }

    #[must_use]
    pub const fn previous_selection_id(&self) -> Option<RepositoryCandidateSelectionIdV1> {
        self.previous_selection_id
    }

    #[must_use]
    pub const fn graph_accepted_event_id(&self) -> SchedulerEventId {
        self.graph_accepted_event_id
    }

    #[must_use]
    pub const fn reviewer_dispatch_event_id(&self) -> SchedulerEventId {
        self.reviewer_dispatch_event_id
    }

    #[must_use]
    pub const fn producer_dispatch_event_id(&self) -> SchedulerEventId {
        self.producer_dispatch_event_id
    }

    #[must_use]
    pub const fn dependency_handoff_event_id(&self) -> SchedulerEventId {
        self.dependency_handoff_event_id
    }

    #[must_use]
    pub const fn target_work_order_id(&self) -> WorkOrderId {
        self.target_work_order_id
    }

    #[must_use]
    pub const fn producer(&self) -> &RepositoryCandidateProducerLocatorV1 {
        &self.producer
    }

    #[must_use]
    pub const fn candidate_sha256(&self) -> &Sha256Digest {
        &self.candidate_sha256
    }

    #[must_use]
    pub const fn candidate_manifest_artifact(&self) -> &ArtifactRef {
        &self.candidate_manifest_artifact
    }

    #[must_use]
    pub const fn publication_event_id(&self) -> EventId {
        self.publication_event_id
    }

    #[must_use]
    pub const fn publication_receipt_artifact(&self) -> &ArtifactRef {
        &self.publication_receipt_artifact
    }

    #[must_use]
    pub const fn cleanup_prepared_event_id(&self) -> EventId {
        self.cleanup_prepared_event_id
    }

    #[must_use]
    pub const fn cleanup_observed_event_id(&self) -> EventId {
        self.cleanup_observed_event_id
    }

    #[must_use]
    pub const fn cleanup_receipt_artifact(&self) -> &ArtifactRef {
        &self.cleanup_receipt_artifact
    }

    #[must_use]
    pub const fn ready_event_id(&self) -> EventId {
        self.ready_event_id
    }

    #[must_use]
    pub const fn ready_receipt_artifact(&self) -> &ArtifactRef {
        &self.ready_receipt_artifact
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositoryCandidateSelectionSubjectV1 {
    graph_accepted_event_id: SchedulerEventId,
    reviewer_dispatch_event_id: SchedulerEventId,
    producer_dispatch_event_id: SchedulerEventId,
    dependency_handoff_event_id: SchedulerEventId,
    target_work_order_id: WorkOrderId,
    producer: RepositoryCandidateProducerLocatorV1,
    candidate_sha256: Sha256Digest,
    candidate_manifest_artifact: ArtifactRef,
    publication_event_id: EventId,
    publication_receipt_artifact: ArtifactRef,
    cleanup_prepared_event_id: EventId,
    cleanup_observed_event_id: EventId,
    cleanup_receipt_artifact: ArtifactRef,
    ready_event_id: EventId,
    ready_receipt_artifact: ArtifactRef,
}

impl RepositoryCandidateSelectionSubjectV1 {
    fn derive(
        subject: &VerifiedRepositoryReviewSubjectV1,
    ) -> Result<Self, RepositoryCandidateHeadErrorV1> {
        let producer = subject.producer_locator();
        let candidate = subject.candidate();
        candidate
            .validate_for(producer)
            .map_err(RepositoryCandidateHeadErrorV1::InvalidCandidate)?;
        if subject.target_work_order_id() != producer.work_order_id
            || subject.target_work_order().id != producer.work_order_id
            || candidate.bundle.manifest.body.producer_work_order_id != producer.work_order_id
        {
            return Err(RepositoryCandidateHeadErrorV1::SubjectMismatch);
        }
        Ok(Self {
            graph_accepted_event_id: subject.graph_accepted_event_id(),
            reviewer_dispatch_event_id: subject.reviewer_dispatch_event_id(),
            producer_dispatch_event_id: subject.producer_dispatch_event_id(),
            dependency_handoff_event_id: subject.dependency_handoff_event_id(),
            target_work_order_id: subject.target_work_order_id(),
            producer: producer.clone(),
            candidate_sha256: candidate.bundle.manifest.candidate_sha256.clone(),
            candidate_manifest_artifact: candidate.bundle.manifest_artifact.artifact.clone(),
            publication_event_id: candidate.publication.published_event_id(),
            publication_receipt_artifact: candidate.publication.receipt_artifact().artifact.clone(),
            cleanup_prepared_event_id: candidate.cleanup.cleanup_prepared_event_id(),
            cleanup_observed_event_id: candidate.cleanup.cleanup_observed_event_id(),
            cleanup_receipt_artifact: candidate.cleanup.receipt_artifact().artifact.clone(),
            ready_event_id: candidate.ready.ready_event_id(),
            ready_receipt_artifact: candidate.ready.receipt_artifact().artifact.clone(),
        })
    }

    fn bind_head(
        self,
        track_id: RepositoryCandidateTrackIdV1,
        generation: RepositoryCandidateGenerationV1,
        selection_id: RepositoryCandidateSelectionIdV1,
        previous_selection_id: Option<RepositoryCandidateSelectionIdV1>,
    ) -> RepositoryCandidateHeadBindingV1 {
        RepositoryCandidateHeadBindingV1 {
            track_id,
            generation,
            selection_id,
            previous_selection_id,
            graph_accepted_event_id: self.graph_accepted_event_id,
            reviewer_dispatch_event_id: self.reviewer_dispatch_event_id,
            producer_dispatch_event_id: self.producer_dispatch_event_id,
            dependency_handoff_event_id: self.dependency_handoff_event_id,
            target_work_order_id: self.target_work_order_id,
            producer: self.producer,
            candidate_sha256: self.candidate_sha256,
            candidate_manifest_artifact: self.candidate_manifest_artifact,
            publication_event_id: self.publication_event_id,
            publication_receipt_artifact: self.publication_receipt_artifact,
            cleanup_prepared_event_id: self.cleanup_prepared_event_id,
            cleanup_observed_event_id: self.cleanup_observed_event_id,
            cleanup_receipt_artifact: self.cleanup_receipt_artifact,
            ready_event_id: self.ready_event_id,
            ready_receipt_artifact: self.ready_receipt_artifact,
        }
    }
}

/// Closed result of an atomic candidate selection.
///
/// Historical exact replay returns both the originally recorded generation and
/// the head that is current now, so replay cannot be confused with renewed
/// current authority.
#[must_use = "candidate selection or exact replay must be handled"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryCandidateHeadSelectionOutcomeV1 {
    Selected {
        current: RepositoryCandidateHeadBindingV1,
    },
    ExactReplay {
        recorded: RepositoryCandidateHeadBindingV1,
        current: Box<RepositoryCandidateHeadBindingV1>,
    },
}

impl RepositoryCandidateHeadSelectionOutcomeV1 {
    #[must_use]
    pub fn current(&self) -> &RepositoryCandidateHeadBindingV1 {
        match self {
            Self::Selected { current } => current,
            Self::ExactReplay { current, .. } => current.as_ref(),
        }
    }

    #[must_use]
    pub const fn recorded(&self) -> &RepositoryCandidateHeadBindingV1 {
        match self {
            Self::Selected { current } => current,
            Self::ExactReplay { recorded, .. } => recorded,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositoryCandidateSelectionRequestV1 {
    track_id: RepositoryCandidateTrackIdV1,
    expected: Option<RepositoryCandidateHeadBindingV1>,
    subject: RepositoryCandidateSelectionSubjectV1,
    selection_id: RepositoryCandidateSelectionIdV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositoryCandidateSelectionRecordV1 {
    request: RepositoryCandidateSelectionRequestV1,
    selected: RepositoryCandidateHeadBindingV1,
}

#[derive(Debug)]
struct RepositoryCandidateTrackStateV1 {
    secret: Uuid,
    target_work_order_id: WorkOrderId,
    current: Option<RepositoryCandidateHeadBindingV1>,
}

#[derive(Debug, Default)]
struct RepositoryCandidateHeadRegistryStateV1 {
    tracks: BTreeMap<RepositoryCandidateTrackIdV1, RepositoryCandidateTrackStateV1>,
    selections: BTreeMap<RepositoryCandidateSelectionIdV1, RepositoryCandidateSelectionRecordV1>,
}

/// Volatile reference implementation of explicit candidate-generation CAS.
///
/// Production wiring must replace this with a durable transactional store.
/// The single mutex models the required transaction boundary, including the
/// registry-wide identified-selection conflict check.
#[derive(Debug, Default)]
pub struct InMemoryRepositoryCandidateHeadRegistryV1 {
    state: Mutex<RepositoryCandidateHeadRegistryStateV1>,
}

impl InMemoryRepositoryCandidateHeadRegistryV1 {
    /// Opens a new logical track and returns its non-forgeable controller
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry lock is poisoned.
    pub fn open_track(
        &self,
        target_work_order_id: WorkOrderId,
    ) -> Result<RepositoryCandidateTrackAuthorityV1, RepositoryCandidateHeadErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryCandidateHeadErrorV1::Unavailable)?;
        let (track_id, secret) = loop {
            let track_id = RepositoryCandidateTrackIdV1(Uuid::new_v4());
            let secret = Uuid::new_v4();
            if !state.tracks.contains_key(&track_id) {
                break (track_id, secret);
            }
        };
        state.tracks.insert(
            track_id,
            RepositoryCandidateTrackStateV1 {
                secret,
                target_work_order_id,
                current: None,
            },
        );
        Ok(RepositoryCandidateTrackAuthorityV1 {
            material: Box::new(RepositoryCandidateTrackAuthorityMaterialV1 {
                track_id,
                target_work_order_id,
                secret,
            }),
        })
    }

    /// Reads the current head after validating the private track authority.
    ///
    /// This is observability only. The returned binding must not be accepted
    /// as effect authority without a new CAS at the effect boundary.
    ///
    /// # Errors
    ///
    /// Rejects a foreign authority or poisoned registry.
    pub fn current(
        &self,
        authority: &RepositoryCandidateTrackAuthorityV1,
    ) -> Result<Option<RepositoryCandidateHeadBindingV1>, RepositoryCandidateHeadErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| RepositoryCandidateHeadErrorV1::Unavailable)?;
        let track = authorized_track(&state, authority)?;
        Ok(track.current.clone())
    }

    /// Atomically selects one verified ready candidate as the next generation.
    ///
    /// `expected` must be the complete current binding, or `None` only for an
    /// empty track. Exact identified-selection replay is idempotent even after a
    /// later generation exists; the outcome then distinguishes the historical
    /// record from the current head.
    ///
    /// # Errors
    ///
    /// Rejects invalid candidate evidence, foreign authority, stale expected
    /// state, selection-ID reuse with different input, or generation exhaustion.
    pub fn select_successor(
        &self,
        authority: &RepositoryCandidateTrackAuthorityV1,
        expected: Option<&RepositoryCandidateHeadBindingV1>,
        subject: &VerifiedRepositoryReviewSubjectV1,
        selection_id: RepositoryCandidateSelectionIdV1,
    ) -> Result<RepositoryCandidateHeadSelectionOutcomeV1, RepositoryCandidateHeadErrorV1> {
        if selection_id.as_uuid().is_nil() {
            return Err(RepositoryCandidateHeadErrorV1::InvalidSelectionIdentity);
        }
        let subject = RepositoryCandidateSelectionSubjectV1::derive(subject)?;
        let request = RepositoryCandidateSelectionRequestV1 {
            track_id: authority.track_id(),
            expected: expected.cloned(),
            subject,
            selection_id,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryCandidateHeadErrorV1::Unavailable)?;
        authorized_track(&state, authority)?;
        if request.subject.target_work_order_id != authority.target_work_order_id() {
            return Err(RepositoryCandidateHeadErrorV1::TrackScopeMismatch);
        }
        if let Some(recorded) = state.selections.get(&selection_id) {
            if recorded.request != request {
                return Err(RepositoryCandidateHeadErrorV1::IdentifiedSelectionConflict);
            }
            let current = state
                .tracks
                .get(&request.track_id)
                .and_then(|track| track.current.clone())
                .ok_or(RepositoryCandidateHeadErrorV1::InvalidRetainedState)?;
            return Ok(RepositoryCandidateHeadSelectionOutcomeV1::ExactReplay {
                recorded: recorded.selected.clone(),
                current: Box::new(current),
            });
        }
        let track = state
            .tracks
            .get(&request.track_id)
            .ok_or(RepositoryCandidateHeadErrorV1::UnknownOrForeignTrack)?;
        if request.expected.as_ref() != track.current.as_ref() {
            return Err(RepositoryCandidateHeadErrorV1::StaleCandidateHead {
                expected_generation: request
                    .expected
                    .as_ref()
                    .map(|head| head.generation().get()),
                current_generation: track.current.as_ref().map(|head| head.generation().get()),
            });
        }
        let generation = next_generation(track.current.as_ref())?;
        let previous_selection_id = track
            .current
            .as_ref()
            .map(RepositoryCandidateHeadBindingV1::selection_id);
        let selected = request.subject.clone().bind_head(
            request.track_id,
            generation,
            selection_id,
            previous_selection_id,
        );
        state.selections.insert(
            selection_id,
            RepositoryCandidateSelectionRecordV1 {
                request: request.clone(),
                selected: selected.clone(),
            },
        );
        state
            .tracks
            .get_mut(&request.track_id)
            .ok_or(RepositoryCandidateHeadErrorV1::InvalidRetainedState)?
            .current = Some(selected.clone());
        Ok(RepositoryCandidateHeadSelectionOutcomeV1::Selected { current: selected })
    }
}

fn authorized_track<'a>(
    state: &'a RepositoryCandidateHeadRegistryStateV1,
    authority: &RepositoryCandidateTrackAuthorityV1,
) -> Result<&'a RepositoryCandidateTrackStateV1, RepositoryCandidateHeadErrorV1> {
    let track = state
        .tracks
        .get(&authority.material.track_id)
        .ok_or(RepositoryCandidateHeadErrorV1::UnknownOrForeignTrack)?;
    if track.secret != authority.material.secret {
        return Err(RepositoryCandidateHeadErrorV1::UnknownOrForeignTrack);
    }
    if track.target_work_order_id != authority.material.target_work_order_id {
        return Err(RepositoryCandidateHeadErrorV1::UnknownOrForeignTrack);
    }
    Ok(track)
}

fn next_generation(
    current: Option<&RepositoryCandidateHeadBindingV1>,
) -> Result<RepositoryCandidateGenerationV1, RepositoryCandidateHeadErrorV1> {
    let value = match current {
        None => 1,
        Some(current) => current
            .generation
            .get()
            .checked_add(1)
            .ok_or(RepositoryCandidateHeadErrorV1::GenerationExhausted)?,
    };
    Ok(RepositoryCandidateGenerationV1(
        NonZeroU64::new(value).expect("generation one and checked successors are non-zero"),
    ))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RepositoryCandidateHeadErrorV1 {
    #[error("repository candidate head registry is unavailable")]
    Unavailable,
    #[error("candidate-track authority is unknown or foreign")]
    UnknownOrForeignTrack,
    #[error("repository review subject differs from its exact candidate")]
    SubjectMismatch,
    #[error("repository review subject differs from the candidate track's bound work order")]
    TrackScopeMismatch,
    #[error("repository candidate is invalid: {0}")]
    InvalidCandidate(RepositoryCandidateError),
    #[error("candidate selection identity must not be nil")]
    InvalidSelectionIdentity,
    #[error("candidate selection identity was reused with different input")]
    IdentifiedSelectionConflict,
    #[error(
        "candidate head compare-and-swap was stale (expected generation {expected_generation:?}, current generation {current_generation:?})"
    )]
    StaleCandidateHead {
        expected_generation: Option<u64>,
        current_generation: Option<u64>,
    },
    #[error("candidate selection generation is exhausted")]
    GenerationExhausted,
    #[error("candidate head registry retained inconsistent state")]
    InvalidRetainedState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository_candidate::{
        InMemoryRepositoryCandidateStore, publish_ready_test_candidate_with_artifacts,
    };
    use birdcode_orchestrator::{
        AgentAssignment, AgentBudget, GraphActorId, ModelProfileId, PermissionGrant, RoleId,
        WorkspaceAccess, WorkspaceGrant, WorkspaceLeaseId, WorkspaceSourceBinding,
    };
    use birdcode_protocol::ModelLineage;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Barrier};

    const BASE_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn subject(
        work_order_id: WorkOrderId,
        graph_material: &[u8],
        candidate_material: &[u8],
    ) -> VerifiedRepositoryReviewSubjectV1 {
        let graph_sha256 = Sha256Digest::of_bytes(graph_material);
        let context_sha256 = Sha256Digest::of_bytes(b"candidate-head-context");
        let work_order_sha256 = Sha256Digest::of_bytes(b"candidate-head-work-order");
        let baseline_sha256 = birdcode_workspace::git_baseline_sha256(BASE_COMMIT);
        let lease_id =
            WorkspaceLeaseId::new("candidate-head-test-lease").expect("valid test lease");
        let lineage = ModelLineage {
            backend_id: "scripted".to_owned(),
            model_id: "candidate-head-fixture".to_owned(),
            deployment_id: "candidate-head-tests".to_owned(),
            independence_domain_id: "candidate-head-producer".to_owned(),
        };
        let assignment = AgentAssignment {
            role_id: RoleId::new("candidate-head-implementer").expect("valid role"),
            model_profile_id: ModelProfileId::new("candidate-head-model")
                .expect("valid model profile"),
            lineage: lineage.clone(),
        };
        let workspace = WorkspaceGrant {
            lease_id,
            source: WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
                git_baseline_sha256: baseline_sha256.as_str().to_owned(),
            },
            access: WorkspaceAccess::Write,
        };
        let budget = AgentBudget {
            max_output_tokens: 4_096,
            max_tool_calls: 4,
            max_wall_time_ms: 10_000,
            max_cleanup_time_ms: 1_000,
            max_attempts: 1,
        };
        let work_order = birdcode_orchestrator::WorkOrder {
            id: work_order_id,
            objective: "produce the exact candidate".to_owned(),
            acceptance_criteria: vec!["candidate evidence is exact".to_owned()],
            dependencies: BTreeSet::new(),
            candidate_group: None,
            priority: 0,
            context_manifest_sha256: context_sha256.as_str().to_owned(),
            assignment: assignment.clone(),
            permissions: PermissionGrant::default(),
            workspace: workspace.clone(),
            budget,
            reviews: BTreeSet::new(),
        };
        let locator = RepositoryCandidateProducerLocatorV1 {
            graph_sha256: graph_sha256.clone(),
            work_order_id,
            actor_id: GraphActorId::new(),
            execution_id: birdcode_orchestrator::ExecutionId::new(),
            attempt_id: birdcode_orchestrator::AgentAttemptId::new(),
        };
        let dispatch_attestation = birdcode_orchestrator::DispatchAttestation {
            graph_sha256: graph_sha256.as_str().to_owned(),
            work_order_sha256: work_order_sha256.as_str().to_owned(),
            permissions_sha256: Sha256Digest::of_bytes(b"candidate-head-permissions")
                .as_str()
                .to_owned(),
            assignment,
            context_manifest_sha256: context_sha256.as_str().to_owned(),
            workspace,
            budget,
        };
        let store = InMemoryRepositoryCandidateStore::default();
        let mut postimage = b"state=".to_vec();
        postimage.extend_from_slice(candidate_material);
        postimage.push(b'\n');
        let candidate = publish_ready_test_candidate_with_artifacts(
            &store,
            &locator,
            lineage,
            dispatch_attestation,
            BASE_COMMIT,
            b"state=grounded\n",
            &postimage,
            candidate_material,
        );
        VerifiedRepositoryReviewSubjectV1::for_test(work_order, candidate)
    }

    fn selected(
        outcome: RepositoryCandidateHeadSelectionOutcomeV1,
    ) -> RepositoryCandidateHeadBindingV1 {
        match outcome {
            RepositoryCandidateHeadSelectionOutcomeV1::Selected { current } => current,
            RepositoryCandidateHeadSelectionOutcomeV1::ExactReplay { .. } => {
                panic!("expected a fresh selection")
            }
        }
    }

    #[test]
    fn explicit_track_advances_across_graphs_and_exact_replay_stays_historical() {
        let registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let work_order_id = WorkOrderId::new();
        let authority = registry.open_track(work_order_id).expect("open track");
        let first = subject(work_order_id, b"graph-one", b"flying");
        let second = subject(work_order_id, b"graph-two", b"soaring");
        let first_selection_id = RepositoryCandidateSelectionIdV1::new();
        let second_selection_id = RepositoryCandidateSelectionIdV1::new();

        let head_one = selected(
            registry
                .select_successor(&authority, None, &first, first_selection_id)
                .expect("select first"),
        );
        assert_eq!(head_one.generation().get(), 1);
        assert_eq!(head_one.previous_selection_id(), None);

        let head_two = selected(
            registry
                .select_successor(&authority, Some(&head_one), &second, second_selection_id)
                .expect("select successor"),
        );
        assert_eq!(head_two.generation().get(), 2);
        assert_eq!(
            head_two.previous_selection_id(),
            Some(head_one.selection_id())
        );
        assert_ne!(
            head_one.producer().graph_sha256,
            head_two.producer().graph_sha256
        );

        let replay = registry
            .select_successor(&authority, None, &first, first_selection_id)
            .expect("replay first selection");
        assert!(matches!(
            replay,
            RepositoryCandidateHeadSelectionOutcomeV1::ExactReplay {
                ref recorded,
                ref current,
            } if recorded == &head_one && current.as_ref() == &head_two
        ));
        assert_eq!(
            registry.current(&authority).expect("read current"),
            Some(head_two)
        );
    }

    #[test]
    fn superseded_head_cannot_select_or_substitute_a_later_candidate() {
        let registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let work_order_id = WorkOrderId::new();
        let authority = registry.open_track(work_order_id).expect("open track");
        let first = subject(work_order_id, b"graph", b"candidate-one");
        let second = subject(work_order_id, b"graph", b"candidate-two");
        let third = subject(work_order_id, b"graph", b"candidate-three");
        let head_one = selected(
            registry
                .select_successor(
                    &authority,
                    None,
                    &first,
                    RepositoryCandidateSelectionIdV1::new(),
                )
                .expect("select first"),
        );
        let head_two = selected(
            registry
                .select_successor(
                    &authority,
                    Some(&head_one),
                    &second,
                    RepositoryCandidateSelectionIdV1::new(),
                )
                .expect("select second"),
        );

        assert_eq!(
            registry.select_successor(
                &authority,
                Some(&head_one),
                &third,
                RepositoryCandidateSelectionIdV1::new(),
            ),
            Err(RepositoryCandidateHeadErrorV1::StaleCandidateHead {
                expected_generation: Some(1),
                current_generation: Some(2),
            })
        );
        assert_eq!(
            registry.current(&authority).expect("read current"),
            Some(head_two)
        );
    }

    #[test]
    fn identified_selection_reuse_with_another_candidate_fails_closed() {
        let registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let work_order_id = WorkOrderId::new();
        let authority = registry.open_track(work_order_id).expect("open track");
        let first = subject(work_order_id, b"graph", b"candidate-one");
        let substituted = subject(work_order_id, b"graph", b"candidate-two");
        let selection_id = RepositoryCandidateSelectionIdV1::new();

        let _first_selection = registry
            .select_successor(&authority, None, &first, selection_id)
            .expect("select first");
        assert_eq!(
            registry.select_successor(&authority, None, &substituted, selection_id),
            Err(RepositoryCandidateHeadErrorV1::IdentifiedSelectionConflict)
        );
        assert_eq!(
            registry
                .current(&authority)
                .expect("read current")
                .expect("head")
                .candidate_sha256(),
            &first.candidate().bundle.manifest.candidate_sha256
        );
    }

    #[test]
    fn two_successors_racing_one_expected_head_cannot_both_commit() {
        let registry = Arc::new(InMemoryRepositoryCandidateHeadRegistryV1::default());
        let work_order_id = WorkOrderId::new();
        let authority = Arc::new(registry.open_track(work_order_id).expect("open track"));
        let first = subject(work_order_id, b"graph", b"candidate-one");
        let left = subject(work_order_id, b"graph", b"candidate-left");
        let right = subject(work_order_id, b"graph", b"candidate-right");
        let head_one = selected(
            registry
                .select_successor(
                    &authority,
                    None,
                    &first,
                    RepositoryCandidateSelectionIdV1::new(),
                )
                .expect("select first"),
        );
        let barrier = Arc::new(Barrier::new(3));

        let (left_result, right_result) = std::thread::scope(|scope| {
            let left_task = {
                let registry = Arc::clone(&registry);
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let head_one = head_one.clone();
                scope.spawn(move || {
                    barrier.wait();
                    registry.select_successor(
                        &authority,
                        Some(&head_one),
                        &left,
                        RepositoryCandidateSelectionIdV1::new(),
                    )
                })
            };
            let right_task = {
                let registry = Arc::clone(&registry);
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let head_one = head_one.clone();
                scope.spawn(move || {
                    barrier.wait();
                    registry.select_successor(
                        &authority,
                        Some(&head_one),
                        &right,
                        RepositoryCandidateSelectionIdV1::new(),
                    )
                })
            };
            barrier.wait();
            (
                left_task.join().expect("left task"),
                right_task.join().expect("right task"),
            )
        });

        let successes = [&left_result, &right_result]
            .into_iter()
            .filter(|result| {
                matches!(
                    result,
                    Ok(RepositoryCandidateHeadSelectionOutcomeV1::Selected { .. })
                )
            })
            .count();
        let stale = [left_result, right_result]
            .into_iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(RepositoryCandidateHeadErrorV1::StaleCandidateHead {
                        expected_generation: Some(1),
                        current_generation: Some(2),
                    })
                )
            })
            .count();
        assert_eq!((successes, stale), (1, 1));
        assert_eq!(
            registry
                .current(&authority)
                .expect("read current")
                .expect("current")
                .generation()
                .get(),
            2
        );
    }

    #[test]
    fn track_identity_is_not_authority_for_another_registry() {
        let first_registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let second_registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let work_order_id = WorkOrderId::new();
        let authority = first_registry
            .open_track(work_order_id)
            .expect("open first track");
        let candidate = subject(work_order_id, b"graph", b"candidate");

        assert_eq!(
            second_registry.select_successor(
                &authority,
                None,
                &candidate,
                RepositoryCandidateSelectionIdV1::new(),
            ),
            Err(RepositoryCandidateHeadErrorV1::UnknownOrForeignTrack)
        );
        assert_eq!(
            second_registry.current(&authority),
            Err(RepositoryCandidateHeadErrorV1::UnknownOrForeignTrack)
        );
    }

    #[test]
    fn track_scope_rejects_another_work_order_before_any_mutation() {
        let registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let scoped_work_order_id = WorkOrderId::new();
        let foreign_work_order_id = WorkOrderId::new();
        let authority = registry
            .open_track(scoped_work_order_id)
            .expect("open scoped track");
        let foreign = subject(foreign_work_order_id, b"graph", b"foreign-candidate");

        assert_eq!(
            registry.select_successor(
                &authority,
                None,
                &foreign,
                RepositoryCandidateSelectionIdV1::new(),
            ),
            Err(RepositoryCandidateHeadErrorV1::TrackScopeMismatch)
        );
        assert_eq!(registry.current(&authority).expect("read current"), None);
    }

    #[test]
    fn identical_selection_race_is_one_commit_and_one_exact_replay() {
        let registry = Arc::new(InMemoryRepositoryCandidateHeadRegistryV1::default());
        let work_order_id = WorkOrderId::new();
        let authority = Arc::new(registry.open_track(work_order_id).expect("open track"));
        let candidate = subject(work_order_id, b"graph", b"candidate");
        let selection_id = RepositoryCandidateSelectionIdV1::new();
        let barrier = Arc::new(Barrier::new(3));

        let (left_result, right_result) = std::thread::scope(|scope| {
            let left_task = {
                let registry = Arc::clone(&registry);
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let candidate = candidate.clone();
                scope.spawn(move || {
                    barrier.wait();
                    registry.select_successor(&authority, None, &candidate, selection_id)
                })
            };
            let right_task = {
                let registry = Arc::clone(&registry);
                let authority = Arc::clone(&authority);
                let barrier = Arc::clone(&barrier);
                let candidate = candidate.clone();
                scope.spawn(move || {
                    barrier.wait();
                    registry.select_successor(&authority, None, &candidate, selection_id)
                })
            };
            barrier.wait();
            (
                left_task.join().expect("left task"),
                right_task.join().expect("right task"),
            )
        });

        let outcomes = [left_result.expect("left"), right_result.expect("right")];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    RepositoryCandidateHeadSelectionOutcomeV1::Selected { .. }
                ))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    RepositoryCandidateHeadSelectionOutcomeV1::ExactReplay { .. }
                ))
                .count(),
            1
        );
        assert!(outcomes.iter().all(|outcome| {
            outcome.recorded() == outcome.current()
                && outcome.current().generation().get() == 1
                && outcome.current().selection_id() == selection_id
        }));
    }

    #[test]
    fn selection_identity_conflict_is_global_within_one_registry() {
        let registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let first_work_order_id = WorkOrderId::new();
        let second_work_order_id = WorkOrderId::new();
        let first_authority = registry
            .open_track(first_work_order_id)
            .expect("open first track");
        let second_authority = registry
            .open_track(second_work_order_id)
            .expect("open second track");
        let first = subject(first_work_order_id, b"graph-one", b"first");
        let second = subject(second_work_order_id, b"graph-two", b"second");
        let selection_id = RepositoryCandidateSelectionIdV1::new();

        let _first_selection = registry
            .select_successor(&first_authority, None, &first, selection_id)
            .expect("select first track");
        assert_eq!(
            registry.select_successor(&second_authority, None, &second, selection_id),
            Err(RepositoryCandidateHeadErrorV1::IdentifiedSelectionConflict)
        );
        assert_eq!(
            registry.current(&second_authority).expect("read second"),
            None
        );
    }

    #[test]
    fn generation_exhaustion_does_not_partially_record_selection() {
        let registry = InMemoryRepositoryCandidateHeadRegistryV1::default();
        let work_order_id = WorkOrderId::new();
        let authority = registry.open_track(work_order_id).expect("open track");
        let first = subject(work_order_id, b"graph", b"first");
        let successor = subject(work_order_id, b"graph", b"successor");
        let mut exhausted = selected(
            registry
                .select_successor(
                    &authority,
                    None,
                    &first,
                    RepositoryCandidateSelectionIdV1::new(),
                )
                .expect("select first"),
        );
        exhausted.generation =
            RepositoryCandidateGenerationV1(NonZeroU64::new(u64::MAX).expect("non-zero"));
        {
            let mut state = registry.state.lock().expect("test registry lock");
            state
                .tracks
                .get_mut(&authority.track_id())
                .expect("test track")
                .current = Some(exhausted.clone());
        }
        let selection_id = RepositoryCandidateSelectionIdV1::new();
        let selection_count_before = registry
            .state
            .lock()
            .expect("test registry lock")
            .selections
            .len();

        assert_eq!(
            registry.select_successor(&authority, Some(&exhausted), &successor, selection_id,),
            Err(RepositoryCandidateHeadErrorV1::GenerationExhausted)
        );
        let state = registry.state.lock().expect("test registry lock");
        assert_eq!(
            state
                .tracks
                .get(&authority.track_id())
                .expect("test track")
                .current,
            Some(exhausted)
        );
        assert_eq!(state.selections.len(), selection_count_before);
        assert!(!state.selections.contains_key(&selection_id));
    }
}
