//! Immutable repository candidate publication.
//!
//! The implementation model never authors this document. The trusted adapter
//! seals exact producer, Git-baseline, preimage, postimage, diff and Finish
//! evidence into one content-addressed bundle before the isolated worktree may
//! be released. Later reviewers resolve the full typed artifact references;
//! they never select a candidate by parsing summaries or arbitrary digest
//! lists.

use crate::worktree_write_lane::WorktreeReleaseObservationV1;
use birdcode_orchestrator::{
    AgentAttemptId, DispatchAttestation, ExecutionId, GraphActorId, WorkOrderId, WorkspaceAccess,
    WorkspaceLeaseId, WorkspaceSourceBinding,
};
use birdcode_protocol::{
    ArtifactRef, CHILD_HANDOFF_MEDIA_TYPE, ChildExecutionBinding, ChildHandoffDocument, EventId,
    ModelLineage, RepositoryRelativePathV1, Sha256Digest,
};
use birdcode_workspace::{
    ArtifactBoundary, CanonicalArtifactBoundary, GIT_WORKTREE_DIFF_MEDIA_TYPE,
    GitWorktreeFileObservationV1, RetainedArtifact, git_baseline_sha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

pub const REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION: u32 = 1;
pub const REPOSITORY_CANDIDATE_V1_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-candidate.v1+json";
pub const REPOSITORY_CANDIDATE_PUBLICATION_V1_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-candidate-publication.v1+json";
pub const REPOSITORY_CANDIDATE_READY_V1_MEDIA_TYPE: &str =
    "application/vnd.birdcode.repository-candidate-ready.v1+json";
pub const REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE: &str = "text/plain;charset=utf-8";

const CANDIDATE_ID_DOMAIN: &[u8] = b"birdcode.repository-candidate.v1\0";
const PRODUCER_LOCATOR_DOMAIN: &[u8] = b"birdcode.repository-candidate-producer.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCandidateProducerLocatorV1 {
    pub graph_sha256: Sha256Digest,
    pub work_order_id: WorkOrderId,
    pub actor_id: GraphActorId,
    pub execution_id: ExecutionId,
    pub attempt_id: AgentAttemptId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCandidateProducerV1 {
    pub locator: RepositoryCandidateProducerLocatorV1,
    pub binding: ChildExecutionBinding,
    pub lineage: ModelLineage,
    pub dispatch_attestation: DispatchAttestation,
    pub dispatch_attestation_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCandidateBaselineV1 {
    pub workspace_lease_id: WorkspaceLeaseId,
    pub git_baseline_sha256: Sha256Digest,
    pub base_commit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactUtf8ReplaceCandidateV1 {
    pub path: RepositoryRelativePathV1,
    pub preimage: GitWorktreeFileObservationV1,
    pub postimage: GitWorktreeFileObservationV1,
    pub preimage_artifact: ArtifactRef,
    pub postimage_artifact: ArtifactRef,
    pub diff_artifact: ArtifactRef,
    pub replace_event_id: EventId,
    pub diff_event_id: EventId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCandidateBodyV1 {
    pub contract_version: u32,
    pub producer_work_order_id: WorkOrderId,
    pub producer: RepositoryCandidateProducerV1,
    pub baseline: RepositoryCandidateBaselineV1,
    pub change: ExactUtf8ReplaceCandidateV1,
    pub finish_event_id: EventId,
    pub producer_handoff_artifact: ArtifactRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCandidateManifestV1 {
    pub candidate_sha256: Sha256Digest,
    pub body: RepositoryCandidateBodyV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCandidateBundleV1 {
    pub manifest: RepositoryCandidateManifestV1,
    pub manifest_artifact: RetainedArtifact,
    pub preimage_artifact: RetainedArtifact,
    pub postimage_artifact: RetainedArtifact,
    pub diff_artifact: RetainedArtifact,
    pub producer_handoff_artifact: RetainedArtifact,
}

impl RepositoryCandidateBundleV1 {
    /// Seals exact implementation evidence into one immutable candidate.
    ///
    /// # Errors
    ///
    /// Rejects every substituted digest, length, media type, producer binding,
    /// or non-UTF-8 file artifact.
    pub fn seal(
        body: RepositoryCandidateBodyV1,
        preimage_bytes: Vec<u8>,
        postimage_artifact: RetainedArtifact,
        diff_artifact: RetainedArtifact,
        producer_handoff_artifact: RetainedArtifact,
    ) -> Result<Self, RepositoryCandidateError> {
        let preimage_artifact = CanonicalArtifactBoundary
            .retain(REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE, preimage_bytes)
            .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
        let candidate_sha256 = candidate_body_digest(&body)?;
        let manifest = RepositoryCandidateManifestV1 {
            candidate_sha256,
            body,
        };
        let manifest_artifact = CanonicalArtifactBoundary
            .retain(
                REPOSITORY_CANDIDATE_V1_MEDIA_TYPE,
                serde_json::to_vec(&manifest)
                    .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?,
            )
            .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
        let bundle = Self {
            manifest,
            manifest_artifact,
            preimage_artifact,
            postimage_artifact,
            diff_artifact,
            producer_handoff_artifact,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    /// Revalidates every byte and cross-reference in the retained bundle.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical ID or any artifact/body mismatch.
    pub fn validate(&self) -> Result<(), RepositoryCandidateError> {
        let body = &self.manifest.body;
        if body.contract_version != REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION
            || !producer_binding_matches(body)
            || !dispatch_binding_matches(body)?
            || !valid_git_commit(&body.baseline.base_commit)
            || body.baseline.git_baseline_sha256 != git_baseline_sha256(&body.baseline.base_commit)
            || self.manifest.candidate_sha256 != candidate_body_digest(body)?
        {
            return Err(RepositoryCandidateError::ManifestMismatch);
        }
        verify_artifact(&self.manifest_artifact, REPOSITORY_CANDIDATE_V1_MEDIA_TYPE)?;
        let encoded_manifest = serde_json::to_vec(&self.manifest)
            .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
        if self.manifest_artifact.bytes != encoded_manifest {
            return Err(RepositoryCandidateError::ManifestMismatch);
        }
        verify_artifact(
            &self.preimage_artifact,
            REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE,
        )?;
        verify_artifact(
            &self.postimage_artifact,
            REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE,
        )?;
        verify_artifact(&self.diff_artifact, GIT_WORKTREE_DIFF_MEDIA_TYPE)?;
        verify_artifact(&self.producer_handoff_artifact, CHILD_HANDOFF_MEDIA_TYPE)?;
        if std::str::from_utf8(&self.preimage_artifact.bytes).is_err()
            || std::str::from_utf8(&self.postimage_artifact.bytes).is_err()
            || body.change.preimage_artifact != self.preimage_artifact.artifact
            || body.change.postimage_artifact != self.postimage_artifact.artifact
            || body.change.diff_artifact != self.diff_artifact.artifact
            || body.producer_handoff_artifact != self.producer_handoff_artifact.artifact
            || body.change.preimage.sha256 != self.preimage_artifact.digest
            || body.change.preimage.byte_len != self.preimage_artifact.artifact.size_bytes
            || body.change.postimage.sha256 != self.postimage_artifact.digest
            || body.change.postimage.byte_len != self.postimage_artifact.artifact.size_bytes
            || body.change.preimage.sha256 == body.change.postimage.sha256
        {
            return Err(RepositoryCandidateError::ArtifactMismatch);
        }
        let handoff =
            serde_json::from_slice::<ChildHandoffDocument>(&self.producer_handoff_artifact.bytes)
                .map_err(|_| RepositoryCandidateError::ProvenanceMismatch)?;
        if handoff.contract_version != REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION
            || handoff.binding != body.producer.binding
        {
            return Err(RepositoryCandidateError::ProvenanceMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.manifest_artifact.artifact.sha256
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCandidatePublicationDocumentV1 {
    pub contract_version: u32,
    pub published_event_id: EventId,
    pub candidate_sha256: Sha256Digest,
    pub candidate_manifest_artifact: ArtifactRef,
    pub producer: RepositoryCandidateProducerLocatorV1,
    pub producer_binding: ChildExecutionBinding,
    pub baseline: RepositoryCandidateBaselineV1,
    pub change: ExactUtf8ReplaceCandidateV1,
}

/// Store-issued capability proving that one exact candidate bundle was
/// durably acknowledged. Its fields are private so a naked event ID cannot be
/// substituted at the cleanup boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCandidatePublicationV1 {
    document: RepositoryCandidatePublicationDocumentV1,
    receipt_artifact: RetainedArtifact,
}

impl RepositoryCandidatePublicationV1 {
    #[must_use]
    pub const fn published_event_id(&self) -> EventId {
        self.document.published_event_id
    }

    #[must_use]
    pub const fn candidate_sha256(&self) -> &Sha256Digest {
        &self.document.candidate_sha256
    }

    #[must_use]
    pub const fn candidate_manifest_artifact(&self) -> &ArtifactRef {
        &self.document.candidate_manifest_artifact
    }

    #[must_use]
    pub const fn producer(&self) -> &RepositoryCandidateProducerLocatorV1 {
        &self.document.producer
    }

    #[must_use]
    pub const fn receipt_artifact(&self) -> &RetainedArtifact {
        &self.receipt_artifact
    }

    pub(crate) const fn document(&self) -> &RepositoryCandidatePublicationDocumentV1 {
        &self.document
    }

    pub(crate) fn validate(&self) -> Result<(), RepositoryCandidateError> {
        if self.document.contract_version != REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION {
            return Err(RepositoryCandidateError::ProvenanceMismatch);
        }
        verify_artifact(
            &self.receipt_artifact,
            REPOSITORY_CANDIDATE_PUBLICATION_V1_MEDIA_TYPE,
        )?;
        let encoded = serde_json::to_vec(&self.document)
            .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
        if encoded != self.receipt_artifact.bytes {
            return Err(RepositoryCandidateError::ProvenanceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCandidateReadyDocumentV1 {
    pub contract_version: u32,
    pub ready_event_id: EventId,
    pub published_event_id: EventId,
    pub publication_receipt_artifact: ArtifactRef,
    pub candidate_sha256: Sha256Digest,
    pub candidate_manifest_artifact: ArtifactRef,
    pub producer: RepositoryCandidateProducerLocatorV1,
    pub cleanup_receipt_artifact: ArtifactRef,
    pub cleanup_prepared_event_id: EventId,
    pub cleanup_observed_event_id: EventId,
    pub worktree_id: uuid::Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCandidateReadyV1 {
    document: RepositoryCandidateReadyDocumentV1,
    receipt_artifact: RetainedArtifact,
}

impl RepositoryCandidateReadyV1 {
    #[must_use]
    pub const fn ready_event_id(&self) -> EventId {
        self.document.ready_event_id
    }

    #[must_use]
    pub const fn cleanup_observed_event_id(&self) -> EventId {
        self.document.cleanup_observed_event_id
    }

    #[must_use]
    pub const fn receipt_artifact(&self) -> &RetainedArtifact {
        &self.receipt_artifact
    }

    fn validate(
        &self,
        publication: &RepositoryCandidatePublicationV1,
        cleanup: &WorktreeReleaseObservationV1,
    ) -> Result<(), RepositoryCandidateError> {
        publication.validate()?;
        cleanup
            .validate(publication)
            .map_err(|_| RepositoryCandidateError::ProvenanceMismatch)?;
        verify_artifact(
            &self.receipt_artifact,
            REPOSITORY_CANDIDATE_READY_V1_MEDIA_TYPE,
        )?;
        let encoded = serde_json::to_vec(&self.document)
            .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
        if self.document.contract_version != REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION
            || encoded != self.receipt_artifact.bytes
            || self.document.published_event_id != publication.published_event_id()
            || self.document.publication_receipt_artifact != publication.receipt_artifact.artifact
            || &self.document.candidate_sha256 != publication.candidate_sha256()
            || &self.document.candidate_manifest_artifact
                != publication.candidate_manifest_artifact()
            || &self.document.producer != publication.producer()
            || self.document.cleanup_receipt_artifact != cleanup.receipt_artifact().artifact
            || self.document.cleanup_prepared_event_id != cleanup.cleanup_prepared_event_id()
            || self.document.cleanup_observed_event_id != cleanup.cleanup_observed_event_id()
            || self.document.worktree_id != cleanup.worktree_id()
        {
            return Err(RepositoryCandidateError::ProvenanceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRepositoryCandidateV1 {
    pub publication: RepositoryCandidatePublicationV1,
    pub cleanup: WorktreeReleaseObservationV1,
    pub ready: RepositoryCandidateReadyV1,
    pub bundle: RepositoryCandidateBundleV1,
}

impl RetainedRepositoryCandidateV1 {
    /// Revalidates the complete retained lifecycle for one exact producer.
    ///
    /// This is intentionally crate-private: callers must first derive the
    /// producer locator from trusted scheduler authority rather than accepting
    /// an arbitrary locator from a model or transport payload.
    pub(crate) fn validate_for(
        &self,
        producer: &RepositoryCandidateProducerLocatorV1,
    ) -> Result<(), RepositoryCandidateError> {
        self.bundle.validate()?;
        validate_publication_for_bundle(&self.publication, &self.bundle)?;
        self.ready.validate(&self.publication, &self.cleanup)?;
        if self.publication.producer() != producer
            || &self.bundle.manifest.body.producer.locator != producer
        {
            return Err(RepositoryCandidateError::ProvenanceMismatch);
        }
        Ok(())
    }
}

/// Narrow, read-only view used by reviewers and provenance resolvers.
///
/// Keeping publication methods off this interface prevents an artifact-only
/// reviewer from accidentally acquiring candidate mutation authority.
pub trait RepositoryCandidateReader: Send + Sync {
    /// Resolves only a cleanup-complete candidate for one exact producer
    /// attempt. Every artifact and receipt is revalidated on read.
    ///
    /// # Errors
    ///
    /// Returns an error when retained state is corrupt or unavailable.
    fn resolve_ready(
        &self,
        producer: &RepositoryCandidateProducerLocatorV1,
    ) -> Result<Option<RetainedRepositoryCandidateV1>, RepositoryCandidateStoreError>;
}

pub trait RepositoryCandidateStore: RepositoryCandidateReader {
    /// Durably publishes one exact candidate and returns a sealed,
    /// execution-scoped acknowledgement. Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Rejects invalid evidence, a contradictory publication for the same
    /// producer attempt, or a failed durable acknowledgement.
    fn publish(
        &self,
        bundle: RepositoryCandidateBundleV1,
    ) -> Result<RepositoryCandidatePublicationV1, RepositoryCandidateStoreError>;

    /// Marks a published candidate reviewable only after an exact, lane-issued
    /// cleanup receipt was observed. Exact receipt replay is idempotent.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/substituted publication or conflicting cleanup.
    fn mark_cleanup_observed(
        &self,
        publication: &RepositoryCandidatePublicationV1,
        cleanup: &WorktreeReleaseObservationV1,
    ) -> Result<RepositoryCandidateReadyV1, RepositoryCandidateStoreError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InMemoryCandidateRecordV1 {
    bundle: RepositoryCandidateBundleV1,
    publication: RepositoryCandidatePublicationV1,
    cleanup: Option<WorktreeReleaseObservationV1>,
    ready: Option<RepositoryCandidateReadyV1>,
}

/// Volatile reference implementation for tests. Production callers must
/// inject a durable store; the implementation worker has no hidden default.
#[derive(Debug, Default)]
pub struct InMemoryRepositoryCandidateStore {
    candidates: Mutex<BTreeMap<Sha256Digest, InMemoryCandidateRecordV1>>,
}

impl RepositoryCandidateStore for InMemoryRepositoryCandidateStore {
    fn publish(
        &self,
        bundle: RepositoryCandidateBundleV1,
    ) -> Result<RepositoryCandidatePublicationV1, RepositoryCandidateStoreError> {
        bundle
            .validate()
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        let key = producer_locator_digest(&bundle.manifest.body.producer.locator)
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        let mut candidates = self
            .candidates
            .lock()
            .map_err(|_| RepositoryCandidateStoreError::Unavailable)?;
        if let Some(existing) = candidates.get(&key) {
            return if existing.bundle == bundle {
                Ok(existing.publication.clone())
            } else {
                Err(RepositoryCandidateStoreError::ConflictingProducerAttempt)
            };
        }
        let publication = publication_for_bundle(&bundle, EventId::new())
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        candidates.insert(
            key,
            InMemoryCandidateRecordV1 {
                bundle,
                publication: publication.clone(),
                cleanup: None,
                ready: None,
            },
        );
        Ok(publication)
    }

    fn mark_cleanup_observed(
        &self,
        publication: &RepositoryCandidatePublicationV1,
        cleanup: &WorktreeReleaseObservationV1,
    ) -> Result<RepositoryCandidateReadyV1, RepositoryCandidateStoreError> {
        publication
            .validate()
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        cleanup.validate(publication).map_err(|_| {
            RepositoryCandidateStoreError::InvalidCandidate(
                RepositoryCandidateError::ProvenanceMismatch,
            )
        })?;
        let key = producer_locator_digest(publication.producer())
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        let mut candidates = self
            .candidates
            .lock()
            .map_err(|_| RepositoryCandidateStoreError::Unavailable)?;
        let record = candidates
            .get_mut(&key)
            .ok_or(RepositoryCandidateStoreError::UnknownPublication)?;
        if &record.publication != publication {
            return Err(RepositoryCandidateStoreError::UnknownPublication);
        }
        if let Some(ready) = &record.ready {
            return if record.cleanup.as_ref() == Some(cleanup) {
                Ok(ready.clone())
            } else {
                Err(RepositoryCandidateStoreError::ConflictingCleanup)
            };
        }
        if record.cleanup.is_some() {
            return Err(RepositoryCandidateStoreError::InvalidRetainedState);
        }
        let ready = ready_after_cleanup(publication, cleanup)
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        record.cleanup = Some(cleanup.clone());
        record.ready = Some(ready.clone());
        Ok(ready)
    }
}

impl RepositoryCandidateReader for InMemoryRepositoryCandidateStore {
    fn resolve_ready(
        &self,
        producer: &RepositoryCandidateProducerLocatorV1,
    ) -> Result<Option<RetainedRepositoryCandidateV1>, RepositoryCandidateStoreError> {
        let key = producer_locator_digest(producer)
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        let candidates = self
            .candidates
            .lock()
            .map_err(|_| RepositoryCandidateStoreError::Unavailable)?;
        let Some(record) = candidates.get(&key) else {
            return Ok(None);
        };
        if &record.bundle.manifest.body.producer.locator != producer {
            return Err(RepositoryCandidateStoreError::InvalidRetainedState);
        }
        let (cleanup, ready) = match (&record.cleanup, &record.ready) {
            (None, None) => return Ok(None),
            (Some(cleanup), Some(ready)) => (cleanup, ready),
            _ => return Err(RepositoryCandidateStoreError::InvalidRetainedState),
        };
        let retained = RetainedRepositoryCandidateV1 {
            publication: record.publication.clone(),
            cleanup: cleanup.clone(),
            ready: ready.clone(),
            bundle: record.bundle.clone(),
        };
        retained
            .validate_for(producer)
            .map_err(RepositoryCandidateStoreError::InvalidCandidate)?;
        Ok(Some(retained))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryCandidateError {
    ArtifactEncoding,
    ManifestMismatch,
    ArtifactMismatch,
    ProvenanceMismatch,
}

impl fmt::Display for RepositoryCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArtifactEncoding => "repository candidate artifact encoding failed",
            Self::ManifestMismatch => "repository candidate manifest binding differs",
            Self::ArtifactMismatch => "repository candidate artifact binding differs",
            Self::ProvenanceMismatch => "repository candidate provenance binding differs",
        })
    }
}

impl std::error::Error for RepositoryCandidateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryCandidateStoreError {
    InvalidCandidate(RepositoryCandidateError),
    ConflictingProducerAttempt,
    UnknownPublication,
    ConflictingCleanup,
    InvalidRetainedState,
    Unavailable,
}

impl fmt::Display for RepositoryCandidateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCandidate(error) => write!(formatter, "candidate rejected: {error}"),
            Self::ConflictingProducerAttempt => formatter
                .write_str("candidate store contains a different candidate for this attempt"),
            Self::UnknownPublication => {
                formatter.write_str("candidate publication receipt is unknown or substituted")
            }
            Self::ConflictingCleanup => {
                formatter.write_str("candidate publication has a different cleanup observation")
            }
            Self::InvalidRetainedState => {
                formatter.write_str("candidate store retained inconsistent locator state")
            }
            Self::Unavailable => formatter.write_str("candidate store is unavailable"),
        }
    }
}

impl std::error::Error for RepositoryCandidateStoreError {}

fn publication_for_bundle(
    bundle: &RepositoryCandidateBundleV1,
    published_event_id: EventId,
) -> Result<RepositoryCandidatePublicationV1, RepositoryCandidateError> {
    bundle.validate()?;
    let body = &bundle.manifest.body;
    let document = RepositoryCandidatePublicationDocumentV1 {
        contract_version: REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
        published_event_id,
        candidate_sha256: bundle.manifest.candidate_sha256.clone(),
        candidate_manifest_artifact: bundle.manifest_artifact.artifact.clone(),
        producer: body.producer.locator.clone(),
        producer_binding: body.producer.binding.clone(),
        baseline: body.baseline.clone(),
        change: body.change.clone(),
    };
    let receipt_artifact = CanonicalArtifactBoundary
        .retain(
            REPOSITORY_CANDIDATE_PUBLICATION_V1_MEDIA_TYPE,
            serde_json::to_vec(&document)
                .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?,
        )
        .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
    let publication = RepositoryCandidatePublicationV1 {
        document,
        receipt_artifact,
    };
    validate_publication_for_bundle(&publication, bundle)?;
    Ok(publication)
}

fn validate_publication_for_bundle(
    publication: &RepositoryCandidatePublicationV1,
    bundle: &RepositoryCandidateBundleV1,
) -> Result<(), RepositoryCandidateError> {
    publication.validate()?;
    let body = &bundle.manifest.body;
    let document = publication.document();
    if document.candidate_sha256 != bundle.manifest.candidate_sha256
        || document.candidate_manifest_artifact != bundle.manifest_artifact.artifact
        || document.producer != body.producer.locator
        || document.producer_binding != body.producer.binding
        || document.baseline != body.baseline
        || document.change != body.change
    {
        return Err(RepositoryCandidateError::ProvenanceMismatch);
    }
    Ok(())
}

fn ready_after_cleanup(
    publication: &RepositoryCandidatePublicationV1,
    cleanup: &WorktreeReleaseObservationV1,
) -> Result<RepositoryCandidateReadyV1, RepositoryCandidateError> {
    publication.validate()?;
    cleanup
        .validate(publication)
        .map_err(|_| RepositoryCandidateError::ProvenanceMismatch)?;
    let document = RepositoryCandidateReadyDocumentV1 {
        contract_version: REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
        ready_event_id: EventId::new(),
        published_event_id: publication.published_event_id(),
        publication_receipt_artifact: publication.receipt_artifact.artifact.clone(),
        candidate_sha256: publication.candidate_sha256().clone(),
        candidate_manifest_artifact: publication.candidate_manifest_artifact().clone(),
        producer: publication.producer().clone(),
        cleanup_receipt_artifact: cleanup.receipt_artifact().artifact.clone(),
        cleanup_prepared_event_id: cleanup.cleanup_prepared_event_id(),
        cleanup_observed_event_id: cleanup.cleanup_observed_event_id(),
        worktree_id: cleanup.worktree_id(),
    };
    let receipt_artifact = CanonicalArtifactBoundary
        .retain(
            REPOSITORY_CANDIDATE_READY_V1_MEDIA_TYPE,
            serde_json::to_vec(&document)
                .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?,
        )
        .map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
    let ready = RepositoryCandidateReadyV1 {
        document,
        receipt_artifact,
    };
    ready.validate(publication, cleanup)?;
    Ok(ready)
}

#[cfg(test)]
pub(crate) fn seal_test_publication(
    document: RepositoryCandidatePublicationDocumentV1,
) -> RepositoryCandidatePublicationV1 {
    let receipt_artifact = CanonicalArtifactBoundary
        .retain(
            REPOSITORY_CANDIDATE_PUBLICATION_V1_MEDIA_TYPE,
            serde_json::to_vec(&document).expect("test publication encodes"),
        )
        .expect("test publication retains");
    let publication = RepositoryCandidatePublicationV1 {
        document,
        receipt_artifact,
    };
    publication.validate().expect("test publication is exact");
    publication
}

#[cfg(test)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture seals the complete candidate publication/cleanup/ready lifecycle"
)]
pub(crate) fn publish_ready_test_candidate(
    store: &InMemoryRepositoryCandidateStore,
    locator: &RepositoryCandidateProducerLocatorV1,
    lineage: ModelLineage,
    dispatch_attestation: DispatchAttestation,
    base_commit: &str,
) -> RetainedRepositoryCandidateV1 {
    publish_ready_test_candidate_with_artifacts(
        store,
        locator,
        lineage,
        dispatch_attestation,
        base_commit,
        b"state=grounded\n",
        b"state=flying\n",
        b"candidate-test-diff",
    )
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the fixture accepts exact semantic artifacts and seals their complete lifecycle"
)]
pub(crate) fn publish_ready_test_candidate_with_artifacts(
    store: &InMemoryRepositoryCandidateStore,
    locator: &RepositoryCandidateProducerLocatorV1,
    lineage: ModelLineage,
    dispatch_attestation: DispatchAttestation,
    base_commit: &str,
    preimage_bytes: &[u8],
    postimage_bytes: &[u8],
    diff_bytes: &[u8],
) -> RetainedRepositoryCandidateV1 {
    use crate::worktree_write_lane::seal_test_release_observation;
    use birdcode_protocol::{
        ChildActorId, ChildAttemptId, ChildContextId, ChildExecutionId, ChildHandoffContentV1,
        ChildHandoffId, ChildHandoffStatus, ChildWorkOrderId,
    };

    let work_order_digest = Sha256Digest::parse(dispatch_attestation.work_order_sha256.clone())
        .expect("test work-order digest");
    let context_manifest_digest =
        Sha256Digest::parse(dispatch_attestation.context_manifest_sha256.clone())
            .expect("test context digest");
    let binding = ChildExecutionBinding {
        work_order_id: ChildWorkOrderId::from_uuid(locator.work_order_id.as_uuid()),
        execution_id: ChildExecutionId::from_uuid(locator.execution_id.as_uuid()),
        attempt_id: ChildAttemptId::from_uuid(locator.attempt_id.as_uuid()),
        child_actor_id: ChildActorId::from_uuid(locator.actor_id.as_uuid()),
        context_id: ChildContextId::new(),
        work_order_digest,
        context_manifest_digest,
    };
    let handoff_document = ChildHandoffDocument {
        contract_version: REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
        binding: binding.clone(),
        handoff_id: ChildHandoffId::new(),
        content: ChildHandoffContentV1 {
            status: ChildHandoffStatus::Complete,
            summary: "typed test candidate".to_owned(),
            findings: Vec::new(),
            unknowns: Vec::new(),
            recommended_followups: Vec::new(),
        },
    };
    let producer_handoff_artifact = CanonicalArtifactBoundary
        .retain(
            CHILD_HANDOFF_MEDIA_TYPE,
            serde_json::to_vec(&handoff_document).expect("test handoff encodes"),
        )
        .expect("test handoff retains");
    let preimage_artifact = CanonicalArtifactBoundary
        .retain(
            REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE,
            preimage_bytes.to_vec(),
        )
        .expect("test preimage retains");
    let postimage_artifact = CanonicalArtifactBoundary
        .retain(
            REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE,
            postimage_bytes.to_vec(),
        )
        .expect("test postimage retains");
    let diff_artifact = CanonicalArtifactBoundary
        .retain(GIT_WORKTREE_DIFF_MEDIA_TYPE, diff_bytes.to_vec())
        .expect("test diff retains");
    let WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
        git_baseline_sha256,
    } = &dispatch_attestation.workspace.source
    else {
        panic!("test producer must use a clean committed Git head");
    };
    let baseline = RepositoryCandidateBaselineV1 {
        workspace_lease_id: dispatch_attestation.workspace.lease_id.clone(),
        git_baseline_sha256: Sha256Digest::parse(git_baseline_sha256.clone())
            .expect("test baseline digest"),
        base_commit: base_commit.to_owned(),
    };
    let preimage = GitWorktreeFileObservationV1 {
        byte_len: u64::try_from(preimage_bytes.len()).expect("test preimage length"),
        sha256: Sha256Digest::of_bytes(preimage_bytes),
    };
    let postimage = GitWorktreeFileObservationV1 {
        byte_len: u64::try_from(postimage_bytes.len()).expect("test postimage length"),
        sha256: Sha256Digest::of_bytes(postimage_bytes),
    };
    let body = RepositoryCandidateBodyV1 {
        contract_version: REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
        producer_work_order_id: locator.work_order_id,
        producer: RepositoryCandidateProducerV1 {
            locator: locator.clone(),
            binding,
            lineage,
            dispatch_attestation_sha256: dispatch_attestation_digest(&dispatch_attestation)
                .expect("test dispatch digest"),
            dispatch_attestation,
        },
        baseline,
        change: ExactUtf8ReplaceCandidateV1 {
            path: RepositoryRelativePathV1::Unix {
                components: vec![b"flight.txt".to_vec()],
            },
            preimage,
            postimage,
            preimage_artifact: preimage_artifact.artifact,
            postimage_artifact: postimage_artifact.artifact.clone(),
            diff_artifact: diff_artifact.artifact.clone(),
            replace_event_id: EventId::new(),
            diff_event_id: EventId::new(),
        },
        finish_event_id: EventId::new(),
        producer_handoff_artifact: producer_handoff_artifact.artifact.clone(),
    };
    let bundle = RepositoryCandidateBundleV1::seal(
        body,
        preimage_bytes.to_vec(),
        postimage_artifact,
        diff_artifact,
        producer_handoff_artifact,
    )
    .expect("test candidate seals");
    let publication = store.publish(bundle).expect("test candidate publishes");
    let cleanup = seal_test_release_observation(
        &publication,
        uuid::Uuid::now_v7(),
        EventId::new(),
        EventId::new(),
    );
    store
        .mark_cleanup_observed(&publication, &cleanup)
        .expect("test cleanup marks candidate ready");
    store
        .resolve_ready(locator)
        .expect("test candidate resolves")
        .expect("test candidate is ready")
}

fn producer_locator_digest(
    producer: &RepositoryCandidateProducerLocatorV1,
) -> Result<Sha256Digest, RepositoryCandidateError> {
    let bytes =
        serde_json::to_vec(producer).map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
    let mut digest = Sha256::new();
    digest.update(PRODUCER_LOCATOR_DOMAIN);
    digest.update(bytes);
    Ok(Sha256Digest::parse(format!("{:x}", digest.finalize()))
        .expect("SHA-256 formatting is canonical"))
}

fn producer_binding_matches(body: &RepositoryCandidateBodyV1) -> bool {
    let producer = &body.producer;
    let locator = &producer.locator;
    body.producer_work_order_id == locator.work_order_id
        && body.producer_work_order_id.as_uuid() == producer.binding.work_order_id.as_uuid()
        && locator.actor_id.as_uuid() == producer.binding.child_actor_id.as_uuid()
        && locator.execution_id.as_uuid() == producer.binding.execution_id.as_uuid()
        && locator.attempt_id.as_uuid() == producer.binding.attempt_id.as_uuid()
}

fn dispatch_binding_matches(
    body: &RepositoryCandidateBodyV1,
) -> Result<bool, RepositoryCandidateError> {
    let producer = &body.producer;
    let attestation = &producer.dispatch_attestation;
    let WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
        git_baseline_sha256,
    } = &attestation.workspace.source
    else {
        return Ok(false);
    };
    Ok(
        attestation.graph_sha256 == producer.locator.graph_sha256.as_str()
            && attestation.work_order_sha256 == producer.binding.work_order_digest.as_str()
            && attestation.context_manifest_sha256
                == producer.binding.context_manifest_digest.as_str()
            && attestation.assignment.lineage == producer.lineage
            && attestation.workspace.lease_id == body.baseline.workspace_lease_id
            && attestation.workspace.access == WorkspaceAccess::Write
            && git_baseline_sha256 == body.baseline.git_baseline_sha256.as_str()
            && producer.dispatch_attestation_sha256 == dispatch_attestation_digest(attestation)?,
    )
}

/// Content-addresses the exact scheduler dispatch attestation repeated by a
/// candidate producer.
///
/// # Errors
///
/// Returns an encoding failure if the closed attestation cannot be serialized.
pub fn dispatch_attestation_digest(
    attestation: &DispatchAttestation,
) -> Result<Sha256Digest, RepositoryCandidateError> {
    let bytes =
        serde_json::to_vec(attestation).map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
    Ok(Sha256Digest::of_bytes(&bytes))
}

fn candidate_body_digest(
    body: &RepositoryCandidateBodyV1,
) -> Result<Sha256Digest, RepositoryCandidateError> {
    let bytes = serde_json::to_vec(body).map_err(|_| RepositoryCandidateError::ArtifactEncoding)?;
    let mut digest = Sha256::new();
    digest.update(CANDIDATE_ID_DOMAIN);
    digest.update(bytes);
    Ok(Sha256Digest::parse(format!("{:x}", digest.finalize()))
        .expect("SHA-256 formatting is canonical"))
}

fn verify_artifact(
    artifact: &RetainedArtifact,
    media_type: &str,
) -> Result<(), RepositoryCandidateError> {
    let bytes_len = u64::try_from(artifact.bytes.len()).unwrap_or(u64::MAX);
    let digest = Sha256Digest::of_bytes(&artifact.bytes);
    if artifact.artifact.media_type != media_type
        || artifact.artifact.sha256 != digest.as_str()
        || artifact.artifact.size_bytes != bytes_len
        || artifact.digest != digest
    {
        return Err(RepositoryCandidateError::ArtifactMismatch);
    }
    Ok(())
}

fn valid_git_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree_write_lane::seal_test_release_observation;
    use birdcode_orchestrator::{
        AgentAssignment, AgentBudget, ModelProfileId, RoleId, WorkspaceGrant,
    };
    use birdcode_protocol::{
        ChildActorId, ChildAttemptId, ChildContextId, ChildExecutionId, ChildHandoffContentV1,
        ChildHandoffId, ChildHandoffStatus, ChildWorkOrderId,
    };

    const PREIMAGE: &[u8] = b"state=grounded\n";
    const POSTIMAGE: &[u8] = b"state=flying\n";
    const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone)]
    struct ProducerFixture {
        locator: RepositoryCandidateProducerLocatorV1,
        binding: ChildExecutionBinding,
        lineage: ModelLineage,
        attestation: DispatchAttestation,
        baseline: RepositoryCandidateBaselineV1,
    }

    fn retain(media_type: &'static str, bytes: &[u8]) -> RetainedArtifact {
        CanonicalArtifactBoundary
            .retain(media_type, bytes.to_vec())
            .expect("retain fixture")
    }

    fn producer_fixture(work_order_id: WorkOrderId) -> ProducerFixture {
        let actor_id = GraphActorId::new();
        let execution_id = ExecutionId::new();
        let attempt_id = AgentAttemptId::new();
        let graph_sha256 = Sha256Digest::of_bytes(b"candidate-test-graph");
        let work_order_digest = Sha256Digest::of_bytes(b"candidate-test-work-order");
        let context_manifest_digest = Sha256Digest::of_bytes(b"candidate-test-context");
        let lineage = ModelLineage {
            backend_id: "scripted".to_owned(),
            model_id: "review-fixture".to_owned(),
            deployment_id: "fixture-deployment".to_owned(),
            independence_domain_id: "fixture-domain".to_owned(),
        };
        let baseline = RepositoryCandidateBaselineV1 {
            workspace_lease_id: WorkspaceLeaseId::new("candidate-test-lease").expect("valid lease"),
            git_baseline_sha256: git_baseline_sha256(COMMIT),
            base_commit: COMMIT.to_owned(),
        };
        let binding = ChildExecutionBinding {
            work_order_id: ChildWorkOrderId::from_uuid(work_order_id.as_uuid()),
            execution_id: ChildExecutionId::from_uuid(execution_id.as_uuid()),
            attempt_id: ChildAttemptId::from_uuid(attempt_id.as_uuid()),
            child_actor_id: ChildActorId::from_uuid(actor_id.as_uuid()),
            context_id: ChildContextId::new(),
            work_order_digest: work_order_digest.clone(),
            context_manifest_digest: context_manifest_digest.clone(),
        };
        let attestation = DispatchAttestation {
            graph_sha256: graph_sha256.as_str().to_owned(),
            work_order_sha256: work_order_digest.as_str().to_owned(),
            permissions_sha256: Sha256Digest::of_bytes(b"candidate-test-permissions")
                .as_str()
                .to_owned(),
            assignment: AgentAssignment {
                role_id: RoleId::new("candidate-test-implementer").expect("valid role"),
                model_profile_id: ModelProfileId::new("candidate-test-model")
                    .expect("valid model profile"),
                lineage: lineage.clone(),
            },
            context_manifest_sha256: context_manifest_digest.as_str().to_owned(),
            workspace: WorkspaceGrant {
                lease_id: baseline.workspace_lease_id.clone(),
                source: WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
                    git_baseline_sha256: baseline.git_baseline_sha256.as_str().to_owned(),
                },
                access: WorkspaceAccess::Write,
            },
            budget: AgentBudget {
                max_output_tokens: 4_096,
                max_tool_calls: 2,
                max_wall_time_ms: 10_000,
                max_cleanup_time_ms: 1_000,
                max_attempts: 1,
            },
        };
        ProducerFixture {
            locator: RepositoryCandidateProducerLocatorV1 {
                graph_sha256,
                work_order_id,
                actor_id,
                execution_id,
                attempt_id,
            },
            binding,
            lineage,
            attestation,
            baseline,
        }
    }

    fn valid_handoff(binding: &ChildExecutionBinding) -> RetainedArtifact {
        let document = ChildHandoffDocument {
            contract_version: REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
            binding: binding.clone(),
            handoff_id: ChildHandoffId::new(),
            content: ChildHandoffContentV1 {
                status: ChildHandoffStatus::Complete,
                summary: "candidate fixture completed".to_owned(),
                findings: Vec::new(),
                unknowns: Vec::new(),
                recommended_followups: Vec::new(),
            },
        };
        retain(
            CHILD_HANDOFF_MEDIA_TYPE,
            &serde_json::to_vec(&document).expect("handoff encodes"),
        )
    }

    fn seal_with_handoff(
        producer: &ProducerFixture,
        postimage_bytes: &[u8],
        handoff_artifact: RetainedArtifact,
    ) -> Result<RepositoryCandidateBundleV1, RepositoryCandidateError> {
        let preimage = GitWorktreeFileObservationV1 {
            byte_len: u64::try_from(PREIMAGE.len()).expect("fixture length"),
            sha256: Sha256Digest::of_bytes(PREIMAGE),
        };
        let postimage = GitWorktreeFileObservationV1 {
            byte_len: u64::try_from(postimage_bytes.len()).expect("fixture length"),
            sha256: Sha256Digest::of_bytes(postimage_bytes),
        };
        let preimage_artifact = retain(REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE, PREIMAGE);
        let postimage_artifact = retain(REPOSITORY_UTF8_FILE_CONTENT_MEDIA_TYPE, postimage_bytes);
        let mut diff_bytes = b"candidate-diff-v1\0".to_vec();
        diff_bytes.extend_from_slice(postimage_bytes);
        let diff_artifact = retain(GIT_WORKTREE_DIFF_MEDIA_TYPE, &diff_bytes);
        let body = RepositoryCandidateBodyV1 {
            contract_version: REPOSITORY_CANDIDATE_V1_CONTRACT_VERSION,
            producer_work_order_id: producer.locator.work_order_id,
            producer: RepositoryCandidateProducerV1 {
                locator: producer.locator.clone(),
                binding: producer.binding.clone(),
                lineage: producer.lineage.clone(),
                dispatch_attestation: producer.attestation.clone(),
                dispatch_attestation_sha256: dispatch_attestation_digest(&producer.attestation)?,
            },
            baseline: producer.baseline.clone(),
            change: ExactUtf8ReplaceCandidateV1 {
                path: RepositoryRelativePathV1::Unix {
                    components: vec![b"flight.txt".to_vec()],
                },
                preimage: preimage.clone(),
                postimage: postimage.clone(),
                preimage_artifact: preimage_artifact.artifact,
                postimage_artifact: postimage_artifact.artifact.clone(),
                diff_artifact: diff_artifact.artifact.clone(),
                replace_event_id: EventId::new(),
                diff_event_id: EventId::new(),
            },
            finish_event_id: EventId::new(),
            producer_handoff_artifact: handoff_artifact.artifact.clone(),
        };
        RepositoryCandidateBundleV1::seal(
            body,
            PREIMAGE.to_vec(),
            postimage_artifact,
            diff_artifact,
            handoff_artifact,
        )
    }

    fn bundle(producer: &ProducerFixture) -> RepositoryCandidateBundleV1 {
        seal_with_handoff(producer, POSTIMAGE, valid_handoff(&producer.binding))
            .expect("valid candidate bundle")
    }

    fn cleanup_receipt(
        publication: &RepositoryCandidatePublicationV1,
    ) -> WorktreeReleaseObservationV1 {
        seal_test_release_observation(
            publication,
            uuid::Uuid::now_v7(),
            EventId::new(),
            EventId::new(),
        )
    }

    #[test]
    fn provisional_candidate_is_not_resolvable_before_cleanup() {
        let producer = producer_fixture(WorkOrderId::new());
        let bundle = bundle(&producer);
        let store = InMemoryRepositoryCandidateStore::default();

        let publication = store.publish(bundle.clone()).expect("publish provisional");
        assert_eq!(
            store.resolve_ready(&producer.locator).expect("resolve"),
            None
        );

        let cleanup = cleanup_receipt(&publication);
        let ready = store
            .mark_cleanup_observed(&publication, &cleanup)
            .expect("mark cleanup observed");
        let retained = store
            .resolve_ready(&producer.locator)
            .expect("resolve ready")
            .expect("ready candidate");

        assert_eq!(
            ready.cleanup_observed_event_id(),
            cleanup.cleanup_observed_event_id()
        );
        assert_eq!(retained.publication, publication);
        assert_eq!(retained.cleanup, cleanup);
        assert_eq!(retained.ready, ready);
        assert_eq!(retained.bundle, bundle);
    }

    #[test]
    fn exact_publish_and_cleanup_replay_are_idempotent() {
        let producer = producer_fixture(WorkOrderId::new());
        let bundle = bundle(&producer);
        let store = InMemoryRepositoryCandidateStore::default();

        let first_publication = store.publish(bundle.clone()).expect("first publish");
        let replayed_publication = store.publish(bundle).expect("publish replay");
        assert_eq!(replayed_publication, first_publication);

        let cleanup = cleanup_receipt(&first_publication);
        let first_ready = store
            .mark_cleanup_observed(&first_publication, &cleanup)
            .expect("first cleanup observation");
        let replayed_ready = store
            .mark_cleanup_observed(&replayed_publication, &cleanup)
            .expect("cleanup replay");
        assert_eq!(replayed_ready, first_ready);
        assert_eq!(
            store.mark_cleanup_observed(&first_publication, &cleanup_receipt(&first_publication)),
            Err(RepositoryCandidateStoreError::ConflictingCleanup)
        );
    }

    #[test]
    fn conflicting_candidate_for_same_locator_fails_closed() {
        let producer = producer_fixture(WorkOrderId::new());
        let first = bundle(&producer);
        let conflicting = seal_with_handoff(
            &producer,
            b"state=soaring\n",
            valid_handoff(&producer.binding),
        )
        .expect("conflicting candidate is internally valid");
        let store = InMemoryRepositoryCandidateStore::default();

        store.publish(first).expect("first publish");
        assert_eq!(
            store.publish(conflicting),
            Err(RepositoryCandidateStoreError::ConflictingProducerAttempt)
        );
    }

    #[test]
    fn separate_executions_with_same_work_order_resolve_independently() {
        let work_order_id = WorkOrderId::new();
        let first_producer = producer_fixture(work_order_id);
        let second_producer = producer_fixture(work_order_id);
        let first_bundle = bundle(&first_producer);
        let second_bundle = bundle(&second_producer);
        let store = InMemoryRepositoryCandidateStore::default();

        let first_publication = store.publish(first_bundle.clone()).expect("first publish");
        let second_publication = store
            .publish(second_bundle.clone())
            .expect("second execution publish");
        store
            .mark_cleanup_observed(&first_publication, &cleanup_receipt(&first_publication))
            .expect("first cleanup");
        store
            .mark_cleanup_observed(&second_publication, &cleanup_receipt(&second_publication))
            .expect("second cleanup");

        assert_ne!(first_producer.locator, second_producer.locator);
        assert_eq!(
            store
                .resolve_ready(&first_producer.locator)
                .expect("first resolve")
                .expect("first ready")
                .bundle,
            first_bundle
        );
        assert_eq!(
            store
                .resolve_ready(&second_producer.locator)
                .expect("second resolve")
                .expect("second ready")
                .bundle,
            second_bundle
        );
    }

    #[test]
    fn cleanup_receipt_for_another_publication_cannot_make_candidate_ready() {
        let first_producer = producer_fixture(WorkOrderId::new());
        let second_producer = producer_fixture(WorkOrderId::new());
        let store = InMemoryRepositoryCandidateStore::default();
        let first_publication = store
            .publish(bundle(&first_producer))
            .expect("first publication");
        let second_publication = store
            .publish(bundle(&second_producer))
            .expect("second publication");
        let foreign_cleanup = cleanup_receipt(&second_publication);

        assert_eq!(
            store.mark_cleanup_observed(&first_publication, &foreign_cleanup),
            Err(RepositoryCandidateStoreError::InvalidCandidate(
                RepositoryCandidateError::ProvenanceMismatch
            ))
        );
        assert_eq!(
            store
                .resolve_ready(&first_producer.locator)
                .expect("resolve"),
            None
        );
    }

    #[test]
    fn invalid_or_mismatched_handoff_fails_closed() {
        let producer = producer_fixture(WorkOrderId::new());
        assert_eq!(
            seal_with_handoff(
                &producer,
                POSTIMAGE,
                retain(CHILD_HANDOFF_MEDIA_TYPE, b"{}"),
            ),
            Err(RepositoryCandidateError::ProvenanceMismatch)
        );

        let other_producer = producer_fixture(WorkOrderId::new());
        assert_eq!(
            seal_with_handoff(&producer, POSTIMAGE, valid_handoff(&other_producer.binding),),
            Err(RepositoryCandidateError::ProvenanceMismatch)
        );
    }

    #[test]
    fn store_rejects_substituted_bytes_size_and_media_type() {
        let producer = producer_fixture(WorkOrderId::new());
        let store = InMemoryRepositoryCandidateStore::default();

        let mut bytes = bundle(&producer);
        bytes.postimage_artifact.bytes.push(b'!');
        assert!(matches!(
            store.publish(bytes),
            Err(RepositoryCandidateStoreError::InvalidCandidate(
                RepositoryCandidateError::ArtifactMismatch
            ))
        ));

        let mut size = bundle(&producer);
        size.diff_artifact.artifact.size_bytes += 1;
        assert!(matches!(
            store.publish(size),
            Err(RepositoryCandidateStoreError::InvalidCandidate(
                RepositoryCandidateError::ArtifactMismatch
            ))
        ));

        let mut media_type = bundle(&producer);
        media_type.diff_artifact.artifact.media_type = "text/plain".to_owned();
        assert!(matches!(
            store.publish(media_type),
            Err(RepositoryCandidateStoreError::InvalidCandidate(
                RepositoryCandidateError::ArtifactMismatch
            ))
        ));
    }
}
