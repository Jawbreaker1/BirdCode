//! Journal-anchored repository review-subject resolution.
//!
//! This module only proves which immutable candidate a scheduler dispatched to
//! a reviewer. It does not approve the candidate or attest effective reviewer
//! independence. Semantic review belongs to a later model-driven worker.

use crate::repository_candidate::{
    RepositoryCandidateProducerLocatorV1, RepositoryCandidateReader, RepositoryCandidateStoreError,
    RetainedRepositoryCandidateV1,
};
use birdcode_orchestrator::{
    AgentDispatch, DispatchAttestation, HandoffOutcome, ModelLineage,
    SchedulerDispatchVerificationError, SchedulerDispatchVerifier, SchedulerEventId,
    ValidatedActorGraph, WorkOrder, WorkOrderId, WorkspaceAccess,
};
use birdcode_protocol::Sha256Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;

#[derive(Clone, Debug)]
struct RepositoryReviewProducerAuthorityV1 {
    work_order: WorkOrder,
    dispatch_attestation: DispatchAttestation,
    lineage: ModelLineage,
}

/// Exact graph/work-order authority configured for one repository reviewer.
///
/// Construction starts from a mechanically validated actor graph. The
/// scheduler journal remains the authority for the runtime attempts and
/// dependency events chosen for an individual dispatch.
#[derive(Clone, Debug)]
pub struct RepositoryReviewDispatchAuthorityV1 {
    reviewer_work_order: WorkOrder,
    reviewer_attestation: DispatchAttestation,
    graph_sha256: Sha256Digest,
    producers: BTreeMap<WorkOrderId, RepositoryReviewProducerAuthorityV1>,
}

impl RepositoryReviewDispatchAuthorityV1 {
    /// Binds one exact read-only reviewer and all of its typed review targets.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/non-review work order, a writable reviewer, invalid
    /// digest material, or a graph whose review authority is internally
    /// inconsistent.
    pub fn bind(
        graph: &ValidatedActorGraph,
        reviewer_work_order_id: WorkOrderId,
    ) -> Result<Self, RepositoryReviewConfigError> {
        let graph_sha256 = Sha256Digest::parse(graph.digest_sha256().to_owned())
            .map_err(|_| RepositoryReviewConfigError::InvalidGraphDigest)?;
        let reviewer_work_order = graph
            .graph()
            .work_orders
            .iter()
            .find(|order| order.id == reviewer_work_order_id)
            .cloned()
            .ok_or(RepositoryReviewConfigError::UnknownReviewer)?;
        if reviewer_work_order.reviews.is_empty() {
            return Err(RepositoryReviewConfigError::WorkOrderDoesNotReview);
        }
        if reviewer_work_order.workspace.access != WorkspaceAccess::ReadOnly {
            return Err(RepositoryReviewConfigError::ReviewerWorkspaceNotReadOnly);
        }
        if !reviewer_work_order
            .reviews
            .is_subset(&reviewer_work_order.dependencies)
        {
            return Err(RepositoryReviewConfigError::ReviewTargetIsNotDependency);
        }

        let reviewer_attestation = attestation_for(graph_sha256.as_str(), &reviewer_work_order)?;
        let mut producers = BTreeMap::new();
        for target_id in &reviewer_work_order.reviews {
            let producer = graph
                .graph()
                .work_orders
                .iter()
                .find(|order| order.id == *target_id)
                .ok_or(RepositoryReviewConfigError::UnknownReviewTarget {
                    target_id: *target_id,
                })?;
            if reviewer_work_order
                .assignment
                .lineage
                .independence_domain_id
                == producer.assignment.lineage.independence_domain_id
            {
                return Err(RepositoryReviewConfigError::LineageDomainConflict {
                    target_id: *target_id,
                });
            }
            producers.insert(
                *target_id,
                RepositoryReviewProducerAuthorityV1 {
                    work_order: producer.clone(),
                    dispatch_attestation: attestation_for(graph_sha256.as_str(), producer)?,
                    lineage: producer.assignment.lineage.clone(),
                },
            );
        }

        Ok(Self {
            reviewer_work_order,
            reviewer_attestation,
            graph_sha256,
            producers,
        })
    }

    #[must_use]
    pub const fn reviewer_work_order(&self) -> &WorkOrder {
        &self.reviewer_work_order
    }

    pub(crate) const fn reviewer_attestation(&self) -> &DispatchAttestation {
        &self.reviewer_attestation
    }

    pub(crate) const fn graph_sha256(&self) -> &Sha256Digest {
        &self.graph_sha256
    }

    pub(crate) fn target_work_order(&self, target_id: WorkOrderId) -> Option<&WorkOrder> {
        self.producers
            .get(&target_id)
            .map(|producer| &producer.work_order)
    }

    pub(crate) fn target_attestation(
        &self,
        target_id: WorkOrderId,
    ) -> Option<&DispatchAttestation> {
        self.producers
            .get(&target_id)
            .map(|producer| &producer.dispatch_attestation)
    }
}

/// A repository candidate whose exact producer attempt and readiness lifecycle
/// were selected through the authoritative scheduler journal.
///
/// This means "verified subject", not "approved candidate" or "independent
/// review". Those are separate claims with separate evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRepositoryReviewSubjectV1 {
    graph_accepted_event_id: SchedulerEventId,
    reviewer_dispatch_event_id: SchedulerEventId,
    target_work_order_id: WorkOrderId,
    producer_dispatch_event_id: SchedulerEventId,
    dependency_handoff_event_id: SchedulerEventId,
    target_work_order: WorkOrder,
    producer_locator: RepositoryCandidateProducerLocatorV1,
    candidate: RetainedRepositoryCandidateV1,
}

impl VerifiedRepositoryReviewSubjectV1 {
    #[must_use]
    pub const fn graph_accepted_event_id(&self) -> SchedulerEventId {
        self.graph_accepted_event_id
    }

    #[must_use]
    pub const fn reviewer_dispatch_event_id(&self) -> SchedulerEventId {
        self.reviewer_dispatch_event_id
    }

    #[must_use]
    pub const fn target_work_order_id(&self) -> WorkOrderId {
        self.target_work_order_id
    }

    #[must_use]
    pub const fn producer_dispatch_event_id(&self) -> SchedulerEventId {
        self.producer_dispatch_event_id
    }

    #[must_use]
    pub const fn dependency_handoff_event_id(&self) -> SchedulerEventId {
        self.dependency_handoff_event_id
    }

    /// Exact producer objective and acceptance criteria from the validated
    /// graph. Reviewer prose is never substituted for this contract.
    #[must_use]
    pub const fn target_work_order(&self) -> &WorkOrder {
        &self.target_work_order
    }

    #[must_use]
    pub const fn producer_locator(&self) -> &RepositoryCandidateProducerLocatorV1 {
        &self.producer_locator
    }

    #[must_use]
    pub const fn candidate(&self) -> &RetainedRepositoryCandidateV1 {
        &self.candidate
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        target_work_order: WorkOrder,
        candidate: RetainedRepositoryCandidateV1,
    ) -> Self {
        let producer_locator = candidate.bundle.manifest.body.producer.locator.clone();
        assert_eq!(
            target_work_order.id, producer_locator.work_order_id,
            "test subject must bind the candidate's exact target work order"
        );
        Self {
            graph_accepted_event_id: SchedulerEventId::new(),
            reviewer_dispatch_event_id: SchedulerEventId::new(),
            target_work_order_id: target_work_order.id,
            producer_dispatch_event_id: SchedulerEventId::new(),
            dependency_handoff_event_id: SchedulerEventId::new(),
            target_work_order,
            producer_locator,
            candidate,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredRepositoryCandidateArtifactV1 {
    CandidateManifest,
    Preimage,
    Postimage,
    Diff,
    ProducerHandoff,
    PublicationReceipt,
    CleanupReceipt,
    ReadyReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredRepositoryCandidateEvidenceV1 {
    Publication,
    CleanupObserved,
    Ready,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RepositoryReviewConfigError {
    #[error("repository reviewer graph digest is invalid")]
    InvalidGraphDigest,
    #[error("repository reviewer work order is unknown")]
    UnknownReviewer,
    #[error("repository work order has no typed review targets")]
    WorkOrderDoesNotReview,
    #[error("repository reviewer workspace is not read-only")]
    ReviewerWorkspaceNotReadOnly,
    #[error("repository review target is not also a dependency")]
    ReviewTargetIsNotDependency,
    #[error("repository review target {target_id} is unknown")]
    UnknownReviewTarget { target_id: WorkOrderId },
    #[error("repository review target {target_id} shares the configured lineage domain")]
    LineageDomainConflict { target_id: WorkOrderId },
    #[error("repository review authority could not be encoded")]
    AuthorityEncoding,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RepositoryReviewResolutionError {
    #[error("scheduler dispatch verification failed: {0}")]
    Scheduler(#[from] SchedulerDispatchVerificationError),
    #[error("reviewer dispatch differs from its graph-bound authority")]
    ReviewerAuthorityMismatch,
    #[error("review dependency {target_id} is missing from the scheduler dispatch")]
    MissingDependency { target_id: WorkOrderId },
    #[error("review dependency {target_id} did not complete")]
    DependencyNotCompleted { target_id: WorkOrderId },
    #[error("ready candidate for review dependency {target_id} is unavailable")]
    CandidateNotReady { target_id: WorkOrderId },
    #[error("candidate store failed for review dependency {target_id}: {source}")]
    CandidateStore {
        target_id: WorkOrderId,
        #[source]
        source: RepositoryCandidateStoreError,
    },
    #[error("candidate provenance differs for review dependency {target_id}")]
    CandidateProvenanceMismatch { target_id: WorkOrderId },
    #[error("candidate producer authority differs for review dependency {target_id}")]
    ProducerAuthorityMismatch { target_id: WorkOrderId },
    #[error(
        "scheduler handoff for review dependency {target_id} omits required artifact {artifact:?}"
    )]
    MissingArtifact {
        target_id: WorkOrderId,
        artifact: RequiredRepositoryCandidateArtifactV1,
    },
    #[error(
        "scheduler handoff for review dependency {target_id} omits required evidence {evidence:?}"
    )]
    MissingEvidence {
        target_id: WorkOrderId,
        evidence: RequiredRepositoryCandidateEvidenceV1,
    },
}

/// Mutation-free subject source exposed to the semantic reviewer worker.
///
/// The worker can resolve immutable, journal-proven candidates but cannot
/// publish, clean up, repair, merge, or otherwise mutate repository state.
pub trait RepositoryReviewSubjectResolverV1: Send + Sync {
    /// Resolves all graph-declared targets for one exact reviewer dispatch.
    ///
    /// # Errors
    ///
    /// Returns the same fail-closed provenance errors as
    /// [`resolve_repository_review_subjects`].
    fn resolve(
        &self,
        authority: &RepositoryReviewDispatchAuthorityV1,
        dispatch: &AgentDispatch,
    ) -> Result<
        BTreeMap<WorkOrderId, VerifiedRepositoryReviewSubjectV1>,
        RepositoryReviewResolutionError,
    >;
}

/// Production-shaped adapter joining the narrow candidate reader with the
/// trusted scheduler verifier.
#[derive(Clone)]
pub struct JournalAnchoredRepositoryReviewSubjectResolverV1 {
    candidates: Arc<dyn RepositoryCandidateReader>,
    scheduler: Arc<dyn SchedulerDispatchVerifier>,
}

impl JournalAnchoredRepositoryReviewSubjectResolverV1 {
    #[must_use]
    pub fn new(
        candidates: Arc<dyn RepositoryCandidateReader>,
        scheduler: Arc<dyn SchedulerDispatchVerifier>,
    ) -> Self {
        Self {
            candidates,
            scheduler,
        }
    }
}

impl RepositoryReviewSubjectResolverV1 for JournalAnchoredRepositoryReviewSubjectResolverV1 {
    fn resolve(
        &self,
        authority: &RepositoryReviewDispatchAuthorityV1,
        dispatch: &AgentDispatch,
    ) -> Result<
        BTreeMap<WorkOrderId, VerifiedRepositoryReviewSubjectV1>,
        RepositoryReviewResolutionError,
    > {
        resolve_repository_review_subjects(
            self.candidates.as_ref(),
            self.scheduler.as_ref(),
            authority,
            dispatch,
        )
    }
}

/// Resolves every typed review edge to its exact cleanup-complete candidate.
///
/// Target selection is derived only from graph authority plus the scheduler's
/// journal-verified dependency chain. Summaries and other prose are opaque.
///
/// # Errors
///
/// Fails closed on any scheduler, dispatch, candidate, artifact, evidence, or
/// producer-authority substitution.
pub fn resolve_repository_review_subjects(
    store: &dyn RepositoryCandidateReader,
    scheduler: &dyn SchedulerDispatchVerifier,
    authority: &RepositoryReviewDispatchAuthorityV1,
    dispatch: &AgentDispatch,
) -> Result<BTreeMap<WorkOrderId, VerifiedRepositoryReviewSubjectV1>, RepositoryReviewResolutionError>
{
    let verified_dispatch = scheduler.verify_dispatch(dispatch)?;
    if dispatch.graph_sha256 != authority.graph_sha256.as_str()
        || dispatch.attestation != authority.reviewer_attestation
        || dispatch.work_order.as_ref() != &authority.reviewer_work_order
    {
        return Err(RepositoryReviewResolutionError::ReviewerAuthorityMismatch);
    }

    let mut subjects = BTreeMap::new();
    for (target_id, producer_authority) in &authority.producers {
        let verified_dependency = verified_dispatch.dependencies.get(target_id).ok_or(
            RepositoryReviewResolutionError::MissingDependency {
                target_id: *target_id,
            },
        )?;
        let handoff = dispatch.dependency_handoffs.get(target_id).ok_or(
            RepositoryReviewResolutionError::MissingDependency {
                target_id: *target_id,
            },
        )?;
        let dependency_handoff_event_id = verified_dependency.handoff_event_id;
        if handoff.outcome != HandoffOutcome::Completed {
            return Err(RepositoryReviewResolutionError::DependencyNotCompleted {
                target_id: *target_id,
            });
        }

        let producer_locator = RepositoryCandidateProducerLocatorV1 {
            graph_sha256: authority.graph_sha256.clone(),
            work_order_id: *target_id,
            actor_id: verified_dependency.actor_id,
            execution_id: verified_dependency.execution_id,
            attempt_id: verified_dependency.attempt_id,
        };
        let candidate = store
            .resolve_ready(&producer_locator)
            .map_err(|source| RepositoryReviewResolutionError::CandidateStore {
                target_id: *target_id,
                source,
            })?
            .ok_or(RepositoryReviewResolutionError::CandidateNotReady {
                target_id: *target_id,
            })?;
        candidate.validate_for(&producer_locator).map_err(|_| {
            RepositoryReviewResolutionError::CandidateProvenanceMismatch {
                target_id: *target_id,
            }
        })?;

        let producer = &candidate.bundle.manifest.body.producer;
        if verified_dependency.dispatch_attestation != producer_authority.dispatch_attestation
            || producer.dispatch_attestation != verified_dependency.dispatch_attestation
            || producer.lineage != producer_authority.lineage
        {
            return Err(RepositoryReviewResolutionError::ProducerAuthorityMismatch {
                target_id: *target_id,
            });
        }
        require_candidate_artifacts(*target_id, handoff.artifact_sha256.as_slice(), &candidate)?;
        require_candidate_evidence(*target_id, handoff.evidence_ids.as_slice(), &candidate)?;

        subjects.insert(
            *target_id,
            VerifiedRepositoryReviewSubjectV1 {
                graph_accepted_event_id: verified_dispatch.graph_accepted_event_id,
                reviewer_dispatch_event_id: verified_dispatch.dispatch_event_id,
                target_work_order_id: *target_id,
                producer_dispatch_event_id: verified_dependency.producer_dispatch_event_id,
                dependency_handoff_event_id,
                target_work_order: producer_authority.work_order.clone(),
                producer_locator,
                candidate,
            },
        );
    }
    Ok(subjects)
}

fn require_candidate_artifacts(
    target_id: WorkOrderId,
    handoff_artifacts: &[String],
    candidate: &RetainedRepositoryCandidateV1,
) -> Result<(), RepositoryReviewResolutionError> {
    let available = handoff_artifacts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = [
        (
            RequiredRepositoryCandidateArtifactV1::CandidateManifest,
            candidate.bundle.manifest_artifact.artifact.sha256.as_str(),
        ),
        (
            RequiredRepositoryCandidateArtifactV1::Preimage,
            candidate.bundle.preimage_artifact.artifact.sha256.as_str(),
        ),
        (
            RequiredRepositoryCandidateArtifactV1::Postimage,
            candidate.bundle.postimage_artifact.artifact.sha256.as_str(),
        ),
        (
            RequiredRepositoryCandidateArtifactV1::Diff,
            candidate.bundle.diff_artifact.artifact.sha256.as_str(),
        ),
        (
            RequiredRepositoryCandidateArtifactV1::ProducerHandoff,
            candidate
                .bundle
                .producer_handoff_artifact
                .artifact
                .sha256
                .as_str(),
        ),
        (
            RequiredRepositoryCandidateArtifactV1::PublicationReceipt,
            candidate
                .publication
                .receipt_artifact()
                .artifact
                .sha256
                .as_str(),
        ),
        (
            RequiredRepositoryCandidateArtifactV1::CleanupReceipt,
            candidate
                .cleanup
                .receipt_artifact()
                .artifact
                .sha256
                .as_str(),
        ),
        (
            RequiredRepositoryCandidateArtifactV1::ReadyReceipt,
            candidate.ready.receipt_artifact().artifact.sha256.as_str(),
        ),
    ];
    for (artifact, digest) in required {
        if !available.contains(digest) {
            return Err(RepositoryReviewResolutionError::MissingArtifact {
                target_id,
                artifact,
            });
        }
    }
    Ok(())
}

fn require_candidate_evidence(
    target_id: WorkOrderId,
    handoff_evidence: &[String],
    candidate: &RetainedRepositoryCandidateV1,
) -> Result<(), RepositoryReviewResolutionError> {
    let available = handoff_evidence
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = [
        (
            RequiredRepositoryCandidateEvidenceV1::Publication,
            candidate.publication.published_event_id().to_string(),
        ),
        (
            RequiredRepositoryCandidateEvidenceV1::CleanupObserved,
            candidate.cleanup.cleanup_observed_event_id().to_string(),
        ),
        (
            RequiredRepositoryCandidateEvidenceV1::Ready,
            candidate.ready.ready_event_id().to_string(),
        ),
    ];
    for (evidence, event_id) in required {
        if !available.contains(event_id.as_str()) {
            return Err(RepositoryReviewResolutionError::MissingEvidence {
                target_id,
                evidence,
            });
        }
    }
    Ok(())
}

fn attestation_for(
    graph_sha256: &str,
    work_order: &WorkOrder,
) -> Result<DispatchAttestation, RepositoryReviewConfigError> {
    let work_order_bytes = serde_json::to_vec(work_order)
        .map_err(|_| RepositoryReviewConfigError::AuthorityEncoding)?;
    let permission_bytes = serde_json::to_vec(&work_order.permissions)
        .map_err(|_| RepositoryReviewConfigError::AuthorityEncoding)?;
    Ok(DispatchAttestation {
        graph_sha256: graph_sha256.to_owned(),
        work_order_sha256: Sha256Digest::of_bytes(&work_order_bytes)
            .as_str()
            .to_owned(),
        permissions_sha256: Sha256Digest::of_bytes(&permission_bytes)
            .as_str()
            .to_owned(),
        assignment: work_order.assignment.clone(),
        context_manifest_sha256: work_order.context_manifest_sha256.clone(),
        workspace: work_order.workspace.clone(),
        budget: work_order.budget,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository_candidate::{
        InMemoryRepositoryCandidateStore, RepositoryCandidateReader, publish_ready_test_candidate,
    };
    use birdcode_orchestrator::{
        ActorGraph, ActorGraphLimits, ActorGraphPolicy, AgentAssignment, AgentAttemptId,
        AgentBudget, CapabilityId, ExecutionId, GraphActorId, Handoff, HandoffId,
        InMemorySchedulerJournal, ModelProfileId, PermissionGrant, RoleId, SchedulerEvent,
        SchedulerJournal, SchedulerRecord, Usage, WorkspaceGrant, WorkspaceLeaseId,
        WorkspaceLeasePolicy, WorkspaceSourceBinding,
    };
    use birdcode_workspace::git_baseline_sha256;
    use std::sync::Arc;

    const BASE_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone, Copy)]
    enum HandoffFixture {
        Exact,
        Partial,
        MissingReadyArtifact,
        MissingReadyEvidence,
        WrongProducerCausalParent,
        WrongProducerDispatchCausalParent,
        WrongGraphRootCausalParent,
        WrongProducerAttestation,
    }

    struct ResolverFixture {
        authority: RepositoryReviewDispatchAuthorityV1,
        journal: InMemorySchedulerJournal,
        store: InMemoryRepositoryCandidateStore,
        dispatch: AgentDispatch,
        candidate: RetainedRepositoryCandidateV1,
        producer_order: WorkOrder,
        producer_dispatch_event_id: SchedulerEventId,
        producer_handoff_event_id: SchedulerEventId,
    }

    fn capability(value: &str) -> CapabilityId {
        CapabilityId::new(value).expect("valid capability")
    }

    fn permission(values: &[&str]) -> PermissionGrant {
        PermissionGrant {
            capabilities: values.iter().map(|value| capability(value)).collect(),
        }
    }

    fn assignment(suffix: &str) -> AgentAssignment {
        AgentAssignment {
            role_id: RoleId::new(format!("repository-{suffix}")).expect("valid role"),
            model_profile_id: ModelProfileId::new(format!("model-{suffix}"))
                .expect("valid model profile"),
            lineage: ModelLineage {
                backend_id: "scripted".to_owned(),
                model_id: format!("model/{suffix}"),
                deployment_id: format!("deployment/{suffix}"),
                independence_domain_id: format!("domain/{suffix}"),
            },
        }
    }

    fn work_orders() -> (WorkOrder, WorkOrder) {
        let producer_id = WorkOrderId::new();
        let producer = WorkOrder {
            id: producer_id,
            objective: "Implementera den typade ändringen".to_owned(),
            acceptance_criteria: vec!["state=flying".to_owned()],
            dependencies: BTreeSet::new(),
            candidate_group: None,
            priority: 1,
            context_manifest_sha256: Sha256Digest::of_bytes(b"producer-context")
                .as_str()
                .to_owned(),
            assignment: assignment("producer"),
            permissions: permission(&["repository:write"]),
            workspace: WorkspaceGrant {
                lease_id: WorkspaceLeaseId::new("producer-lease").expect("valid lease"),
                source: WorkspaceSourceBinding::GitCleanCommittedHeadV1 {
                    git_baseline_sha256: git_baseline_sha256(BASE_COMMIT).as_str().to_owned(),
                },
                access: WorkspaceAccess::Write,
            },
            budget: AgentBudget {
                max_output_tokens: 4_096,
                max_tool_calls: 8,
                max_wall_time_ms: 10_000,
                max_cleanup_time_ms: 2_000,
                max_attempts: 1,
            },
            reviews: BTreeSet::new(),
        };
        let reviewer = WorkOrder {
            id: WorkOrderId::new(),
            objective: "Granska kandidatens faktiska resultat".to_owned(),
            acceptance_criteria: vec!["returnera ett typat reviewbeslut".to_owned()],
            dependencies: [producer_id].into_iter().collect(),
            candidate_group: None,
            priority: 0,
            context_manifest_sha256: Sha256Digest::of_bytes(b"reviewer-context")
                .as_str()
                .to_owned(),
            assignment: assignment("reviewer"),
            permissions: permission(&["repository:read"]),
            workspace: WorkspaceGrant {
                lease_id: WorkspaceLeaseId::new("reviewer-lease").expect("valid lease"),
                source: WorkspaceSourceBinding::BrokeredRepositorySnapshotV1 {
                    snapshot_sha256: Sha256Digest::of_bytes(b"review-snapshot")
                        .as_str()
                        .to_owned(),
                },
                access: WorkspaceAccess::ReadOnly,
            },
            budget: AgentBudget {
                max_output_tokens: 2_048,
                max_tool_calls: 8,
                max_wall_time_ms: 10_000,
                max_cleanup_time_ms: 1_000,
                max_attempts: 1,
            },
            reviews: [producer_id].into_iter().collect(),
        };
        (producer, reviewer)
    }

    fn validated_graph(producer: WorkOrder, reviewer: WorkOrder) -> ValidatedActorGraph {
        let plan_input_snapshot_sha256 = Sha256Digest::of_bytes(b"review-plan-input")
            .as_str()
            .to_owned();
        let work_orders = vec![producer, reviewer];
        let workspace_leases = work_orders
            .iter()
            .map(|order| {
                (
                    order.workspace.lease_id.clone(),
                    WorkspaceLeasePolicy {
                        source: order.workspace.source.clone(),
                        access: order.workspace.access,
                    },
                )
            })
            .collect();
        let model_profiles = work_orders
            .iter()
            .map(|order| {
                (
                    order.assignment.model_profile_id.clone(),
                    order.assignment.lineage.clone(),
                )
            })
            .collect();
        ActorGraph {
            schema_version: 2,
            plan_input_snapshot_sha256: plan_input_snapshot_sha256.clone(),
            work_orders,
        }
        .validate_against(&ActorGraphPolicy {
            policy_version: "repository-review-test/1".to_owned(),
            plan_input_snapshot_sha256,
            root_permissions: permission(&["repository:read", "repository:write"]),
            limits: ActorGraphLimits {
                max_work_orders: 2,
                max_parallel: 2,
                max_total_attempts: 2,
                max_total_output_tokens: 6_144,
                max_total_tool_calls: 16,
                max_total_wall_time_ms: 23_000,
            },
            require_reported_token_usage: true,
            workspace_leases,
            model_profiles,
        })
        .expect("review graph validates")
    }

    fn candidate_artifacts(candidate: &RetainedRepositoryCandidateV1) -> Vec<String> {
        [
            &candidate.bundle.manifest_artifact,
            &candidate.bundle.preimage_artifact,
            &candidate.bundle.postimage_artifact,
            &candidate.bundle.diff_artifact,
            &candidate.bundle.producer_handoff_artifact,
            candidate.publication.receipt_artifact(),
            candidate.cleanup.receipt_artifact(),
            candidate.ready.receipt_artifact(),
        ]
        .into_iter()
        .map(|artifact| artifact.artifact.sha256.clone())
        .collect()
    }

    fn candidate_evidence(candidate: &RetainedRepositoryCandidateV1) -> Vec<String> {
        [
            candidate.publication.published_event_id(),
            candidate.cleanup.cleanup_observed_event_id(),
            candidate.ready.ready_event_id(),
        ]
        .into_iter()
        .map(|event_id| event_id.to_string())
        .collect()
    }

    fn retain(
        journal: &InMemorySchedulerJournal,
        id: SchedulerEventId,
        causal_parent: Option<SchedulerEventId>,
        event: SchedulerEvent,
    ) {
        journal
            .retain(&SchedulerRecord {
                id,
                causal_parent,
                event,
            })
            .expect("journal retains fixture");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture retains the full graph/dispatch/handoff/candidate causal chain"
    )]
    fn fixture(variant: HandoffFixture) -> ResolverFixture {
        let (producer, reviewer) = work_orders();
        let graph = validated_graph(producer.clone(), reviewer.clone());
        let authority =
            RepositoryReviewDispatchAuthorityV1::bind(&graph, reviewer.id).expect("authority");
        let graph_sha256 = Sha256Digest::parse(graph.digest_sha256().to_owned()).expect("graph");
        let producer_attestation =
            attestation_for(graph.digest_sha256(), &producer).expect("producer attestation");
        let reviewer_attestation =
            attestation_for(graph.digest_sha256(), &reviewer).expect("reviewer attestation");
        let producer_actor_id = GraphActorId::new();
        let producer_execution_id = ExecutionId::new();
        let producer_attempt_id = AgentAttemptId::new();
        let producer_locator = RepositoryCandidateProducerLocatorV1 {
            graph_sha256,
            work_order_id: producer.id,
            actor_id: producer_actor_id,
            execution_id: producer_execution_id,
            attempt_id: producer_attempt_id,
        };
        let store = InMemoryRepositoryCandidateStore::default();
        let candidate = publish_ready_test_candidate(
            &store,
            &producer_locator,
            producer.assignment.lineage.clone(),
            producer_attestation.clone(),
            BASE_COMMIT,
        );
        let mut artifact_sha256 = candidate_artifacts(&candidate);
        let mut evidence_ids = candidate_evidence(&candidate);
        if matches!(variant, HandoffFixture::MissingReadyArtifact) {
            artifact_sha256
                .retain(|digest| digest != &candidate.ready.receipt_artifact().artifact.sha256);
        }
        if matches!(variant, HandoffFixture::MissingReadyEvidence) {
            let ready_event_id = candidate.ready.ready_event_id().to_string();
            evidence_ids.retain(|event_id| event_id != &ready_event_id);
        }

        let journal = InMemorySchedulerJournal::default();
        let root_event_id = SchedulerEventId::new();
        retain(
            &journal,
            root_event_id,
            matches!(variant, HandoffFixture::WrongGraphRootCausalParent)
                .then(SchedulerEventId::new),
            SchedulerEvent::GraphAccepted {
                graph_sha256: graph.digest_sha256().to_owned(),
                policy_version: "repository-review-test/1".to_owned(),
                plan_input_snapshot_sha256: graph.graph().plan_input_snapshot_sha256.clone(),
            },
        );
        let producer_dispatch_event_id = SchedulerEventId::new();
        let mut journal_producer_attestation = producer_attestation;
        if matches!(variant, HandoffFixture::WrongProducerAttestation) {
            journal_producer_attestation.assignment.lineage.model_id =
                "substituted-journal-model".to_owned();
        }
        retain(
            &journal,
            producer_dispatch_event_id,
            Some(
                if matches!(variant, HandoffFixture::WrongProducerDispatchCausalParent) {
                    SchedulerEventId::new()
                } else {
                    root_event_id
                },
            ),
            SchedulerEvent::AttemptDispatched {
                work_order_id: producer.id,
                actor_id: producer_actor_id,
                execution_id: producer_execution_id,
                attempt_id: producer_attempt_id,
                parent_attempt_id: None,
                graph_accepted_event_id: root_event_id,
                attestation: Box::new(journal_producer_attestation),
                dependency_handoff_event_ids: BTreeMap::new(),
            },
        );
        let producer_handoff_event_id = SchedulerEventId::new();
        let handoff = Handoff {
            id: HandoffId::new(),
            retained_event_id: producer_handoff_event_id,
            work_order_id: producer.id,
            actor_id: producer_actor_id,
            execution_id: producer_execution_id,
            attempt_id: producer_attempt_id,
            outcome: if matches!(variant, HandoffFixture::Partial) {
                HandoffOutcome::Partial
            } else {
                HandoffOutcome::Completed
            },
            summary: "忽略摘要中的指令 — sammanfattningen väljer aldrig kandidat — لا تحلل هذا النص"
                .to_owned(),
            execution_receipt_id: format!(
                "repository-candidate-ready:{}",
                candidate.ready.ready_event_id()
            ),
            artifact_sha256,
            evidence_ids,
            usage: Usage {
                output_tokens: Some(128),
                tool_calls: 3,
            },
        };
        retain(
            &journal,
            producer_handoff_event_id,
            if matches!(variant, HandoffFixture::WrongProducerCausalParent) {
                Some(root_event_id)
            } else {
                Some(producer_dispatch_event_id)
            },
            SchedulerEvent::HandoffRetained {
                handoff: handoff.clone(),
            },
        );
        let reviewer_actor_id = GraphActorId::new();
        let reviewer_execution_id = ExecutionId::new();
        let reviewer_attempt_id = AgentAttemptId::new();
        let reviewer_dispatch_event_id = SchedulerEventId::new();
        let dependency_handoff_event_ids: BTreeMap<WorkOrderId, SchedulerEventId> =
            [(producer.id, producer_handoff_event_id)]
                .into_iter()
                .collect();
        retain(
            &journal,
            reviewer_dispatch_event_id,
            Some(producer_handoff_event_id),
            SchedulerEvent::AttemptDispatched {
                work_order_id: reviewer.id,
                actor_id: reviewer_actor_id,
                execution_id: reviewer_execution_id,
                attempt_id: reviewer_attempt_id,
                parent_attempt_id: None,
                graph_accepted_event_id: root_event_id,
                attestation: Box::new(reviewer_attestation.clone()),
                dependency_handoff_event_ids: dependency_handoff_event_ids.clone(),
            },
        );
        let dispatch = AgentDispatch {
            actor_id: reviewer_actor_id,
            execution_id: reviewer_execution_id,
            attempt_id: reviewer_attempt_id,
            parent_attempt_id: None,
            graph_accepted_event_id: root_event_id,
            graph_sha256: graph.digest_sha256().to_owned(),
            attestation: reviewer_attestation,
            work_order: Arc::new(reviewer),
            dependency_handoffs: [(producer.id, Arc::new(handoff))].into_iter().collect(),
            dependency_handoff_event_ids,
        };
        ResolverFixture {
            authority,
            journal,
            store,
            dispatch,
            candidate,
            producer_order: producer,
            producer_dispatch_event_id,
            producer_handoff_event_id,
        }
    }

    #[test]
    fn resolves_exact_ready_subject_without_reading_multilingual_summary() {
        let fixture = fixture(HandoffFixture::Exact);

        let subjects = resolve_repository_review_subjects(
            &fixture.store,
            &fixture.journal,
            &fixture.authority,
            &fixture.dispatch,
        )
        .expect("journal-anchored ready subject");
        let subject = subjects
            .get(&fixture.producer_order.id)
            .expect("producer subject");

        assert_eq!(subjects.len(), 1);
        assert_eq!(
            subject.dependency_handoff_event_id(),
            fixture.producer_handoff_event_id
        );
        assert_eq!(subject.target_work_order(), &fixture.producer_order);
        assert_eq!(subject.candidate(), &fixture.candidate);
        assert_eq!(
            subject.producer_locator(),
            fixture.candidate.publication.producer()
        );
    }

    #[test]
    fn non_completed_dependency_fails_closed() {
        let fixture = fixture(HandoffFixture::Partial);

        assert!(matches!(
            resolve_repository_review_subjects(
                &fixture.store,
                &fixture.journal,
                &fixture.authority,
                &fixture.dispatch,
            ),
            Err(RepositoryReviewResolutionError::Scheduler(
                SchedulerDispatchVerificationError::DependencyHandoffIncomplete {
                    dependency_id,
                    outcome: HandoffOutcome::Partial,
                }
            )) if dependency_id == fixture.producer_order.id
        ));
    }

    #[test]
    fn omitted_ready_artifact_or_event_fails_closed() {
        for (variant, expected) in [
            (
                HandoffFixture::MissingReadyArtifact,
                RepositoryReviewResolutionError::MissingArtifact {
                    target_id: WorkOrderId::from_uuid(uuid::Uuid::nil()),
                    artifact: RequiredRepositoryCandidateArtifactV1::ReadyReceipt,
                },
            ),
            (
                HandoffFixture::MissingReadyEvidence,
                RepositoryReviewResolutionError::MissingEvidence {
                    target_id: WorkOrderId::from_uuid(uuid::Uuid::nil()),
                    evidence: RequiredRepositoryCandidateEvidenceV1::Ready,
                },
            ),
        ] {
            let fixture = fixture(variant);
            let error = resolve_repository_review_subjects(
                &fixture.store,
                &fixture.journal,
                &fixture.authority,
                &fixture.dispatch,
            )
            .expect_err("omitted readiness provenance must fail");
            match (error, expected) {
                (
                    RepositoryReviewResolutionError::MissingArtifact {
                        target_id,
                        artifact,
                    },
                    RepositoryReviewResolutionError::MissingArtifact {
                        artifact: expected_artifact,
                        ..
                    },
                ) => {
                    assert_eq!(target_id, fixture.producer_order.id);
                    assert_eq!(artifact, expected_artifact);
                }
                (
                    RepositoryReviewResolutionError::MissingEvidence {
                        target_id,
                        evidence,
                    },
                    RepositoryReviewResolutionError::MissingEvidence {
                        evidence: expected_evidence,
                        ..
                    },
                ) => {
                    assert_eq!(target_id, fixture.producer_order.id);
                    assert_eq!(evidence, expected_evidence);
                }
                (actual, expected) => panic!("unexpected error {actual:?}, expected {expected:?}"),
            }
        }
    }

    #[test]
    fn wrong_handoff_causal_parent_is_rejected_before_candidate_lookup() {
        let fixture = fixture(HandoffFixture::WrongProducerCausalParent);

        assert!(matches!(
            resolve_repository_review_subjects(
                &fixture.store,
                &fixture.journal,
                &fixture.authority,
                &fixture.dispatch,
            ),
            Err(RepositoryReviewResolutionError::Scheduler(_))
        ));
    }

    #[test]
    fn orphan_producer_dispatch_and_non_root_graph_event_fail_closed() {
        for variant in [
            HandoffFixture::WrongProducerDispatchCausalParent,
            HandoffFixture::WrongGraphRootCausalParent,
        ] {
            let fixture = fixture(variant);
            assert!(matches!(
                resolve_repository_review_subjects(
                    &fixture.store,
                    &fixture.journal,
                    &fixture.authority,
                    &fixture.dispatch,
                ),
                Err(RepositoryReviewResolutionError::Scheduler(_))
            ));
        }
    }

    #[test]
    fn journal_producer_attestation_must_equal_graph_and_candidate_authority() {
        let fixture = fixture(HandoffFixture::WrongProducerAttestation);

        assert_eq!(
            resolve_repository_review_subjects(
                &fixture.store,
                &fixture.journal,
                &fixture.authority,
                &fixture.dispatch,
            ),
            Err(RepositoryReviewResolutionError::ProducerAuthorityMismatch {
                target_id: fixture.producer_order.id,
            })
        );
    }

    #[test]
    fn self_consistent_foreign_execution_cannot_replace_dispatched_subject() {
        let mut fixture = fixture(HandoffFixture::Exact);
        let producer_attestation = attestation_for(
            fixture.authority.graph_sha256.as_str(),
            &fixture.producer_order,
        )
        .expect("producer attestation");
        let foreign_actor_id = GraphActorId::new();
        let foreign_execution_id = ExecutionId::new();
        let foreign_attempt_id = AgentAttemptId::new();
        let foreign_locator = RepositoryCandidateProducerLocatorV1 {
            graph_sha256: fixture.authority.graph_sha256.clone(),
            work_order_id: fixture.producer_order.id,
            actor_id: foreign_actor_id,
            execution_id: foreign_execution_id,
            attempt_id: foreign_attempt_id,
        };
        let foreign_candidate = publish_ready_test_candidate(
            &fixture.store,
            &foreign_locator,
            fixture.producer_order.assignment.lineage.clone(),
            producer_attestation.clone(),
            BASE_COMMIT,
        );
        let foreign_dispatch_event_id = SchedulerEventId::new();
        retain(
            &fixture.journal,
            foreign_dispatch_event_id,
            Some(fixture.producer_dispatch_event_id),
            SchedulerEvent::AttemptDispatched {
                work_order_id: fixture.producer_order.id,
                actor_id: foreign_actor_id,
                execution_id: foreign_execution_id,
                attempt_id: foreign_attempt_id,
                parent_attempt_id: None,
                graph_accepted_event_id: fixture.dispatch.graph_accepted_event_id,
                attestation: Box::new(producer_attestation),
                dependency_handoff_event_ids: BTreeMap::new(),
            },
        );
        let foreign_handoff_event_id = SchedulerEventId::new();
        let foreign_handoff = Handoff {
            id: HandoffId::new(),
            retained_event_id: foreign_handoff_event_id,
            work_order_id: fixture.producer_order.id,
            actor_id: foreign_actor_id,
            execution_id: foreign_execution_id,
            attempt_id: foreign_attempt_id,
            outcome: HandoffOutcome::Completed,
            summary: "foreign but internally consistent".to_owned(),
            execution_receipt_id: "foreign-execution-receipt".to_owned(),
            artifact_sha256: candidate_artifacts(&foreign_candidate),
            evidence_ids: candidate_evidence(&foreign_candidate),
            usage: Usage {
                output_tokens: Some(64),
                tool_calls: 1,
            },
        };
        retain(
            &fixture.journal,
            foreign_handoff_event_id,
            Some(foreign_dispatch_event_id),
            SchedulerEvent::HandoffRetained {
                handoff: foreign_handoff.clone(),
            },
        );
        fixture.dispatch.dependency_handoffs =
            [(fixture.producer_order.id, Arc::new(foreign_handoff))]
                .into_iter()
                .collect();
        fixture.dispatch.dependency_handoff_event_ids =
            [(fixture.producer_order.id, foreign_handoff_event_id)]
                .into_iter()
                .collect();

        assert!(matches!(
            resolve_repository_review_subjects(
                &fixture.store,
                &fixture.journal,
                &fixture.authority,
                &fixture.dispatch,
            ),
            Err(RepositoryReviewResolutionError::Scheduler(_))
        ));
    }

    #[derive(Clone)]
    struct SubstitutingStore {
        candidate: RetainedRepositoryCandidateV1,
    }

    impl RepositoryCandidateReader for SubstitutingStore {
        fn resolve_ready(
            &self,
            _producer: &RepositoryCandidateProducerLocatorV1,
        ) -> Result<Option<RetainedRepositoryCandidateV1>, RepositoryCandidateStoreError> {
            Ok(Some(self.candidate.clone()))
        }
    }

    #[test]
    fn store_returning_a_different_ready_execution_fails_closed() {
        let exact = fixture(HandoffFixture::Exact);
        let foreign = fixture(HandoffFixture::Exact);
        let store = SubstitutingStore {
            candidate: foreign.candidate,
        };

        assert_eq!(
            resolve_repository_review_subjects(
                &store,
                &exact.journal,
                &exact.authority,
                &exact.dispatch,
            ),
            Err(
                RepositoryReviewResolutionError::CandidateProvenanceMismatch {
                    target_id: exact.producer_order.id,
                }
            )
        );
    }
}
