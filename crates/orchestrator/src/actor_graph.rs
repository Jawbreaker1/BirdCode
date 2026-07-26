//! Deterministic execution of validated, model-authored actor graphs.
//!
//! This module deliberately does not inspect user prose, source code, role
//! names, or model names. A semantic planner is responsible for proposing the
//! graph. The validator and executor enforce only mechanical invariants:
//! dependencies, budgets, authority, broker-attested workspace leases, bounded
//! retries, reviewer independence, concurrency, and journal-acknowledged
//! handoffs.

pub use birdcode_protocol::ModelLineage;
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

const ACTOR_GRAPH_SCHEMA_VERSION: u32 = 2;
const HARD_MAX_WORK_ORDERS: usize = 1_024;
const HARD_MAX_POLICY_LEASES: usize = 2_048;
const HARD_MAX_MODEL_PROFILES: usize = 1_024;
const HARD_MAX_CAPABILITIES: usize = 4_096;
const HARD_MAX_TOTAL_CAPABILITY_REFERENCES: usize = 32_768;
const HARD_MAX_DEPENDENCIES: usize = 256;
const HARD_MAX_REVIEWS: usize = 256;
const HARD_MAX_GRAPH_TEXT_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_OBJECTIVE_BYTES: usize = 256 * 1_024;
const MAX_ACCEPTANCE_CRITERIA: usize = 256;
const MAX_ACCEPTANCE_CRITERION_BYTES: usize = 32 * 1_024;
const MAX_ASSIGNMENT_ID_BYTES: usize = 512;
const MAX_HANDOFF_SUMMARY_BYTES: usize = 256 * 1_024;
const MAX_FAILURE_MESSAGE_BYTES: usize = 256 * 1_024;
const MAX_HANDOFF_REFERENCES: usize = 512;
const MAX_EVIDENCE_ID_BYTES: usize = 512;

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
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

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(WorkOrderId);
uuid_id!(ActorId);
uuid_id!(ExecutionId);
uuid_id!(AttemptId);
uuid_id!(HandoffId);
uuid_id!(SchedulerEventId);

macro_rules! opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a bounded, non-empty opaque identifier.
            ///
            /// # Errors
            ///
            /// Returns a validation error for an empty or overlong value.
            pub fn new(value: impl Into<String>) -> Result<Self, ActorGraphValidationError> {
                let value = value.into();
                if value.is_empty() || value.len() > 512 {
                    return Err(ActorGraphValidationError::Identifier {
                        field: $field,
                        message: "must contain between 1 and 512 bytes".to_owned(),
                    });
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ActorGraphValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

opaque_id!(CapabilityId, "capability_id");
opaque_id!(RoleId, "role_id");
opaque_id!(CandidateGroupId, "candidate_group_id");
opaque_id!(WorkspaceLeaseId, "workspace_lease_id");
opaque_id!(ModelProfileId, "model_profile_id");

/// The planner's concrete, profile-bound worker assignment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAssignment {
    pub role_id: RoleId,
    pub model_profile_id: ModelProfileId,
    pub lineage: ModelLineage,
}

/// Authority is represented by opaque capabilities minted by the permission broker.
///
/// Exact set inclusion is intentional here. Path containment, network origin
/// normalization, tool argument policy, and expiry are responsibilities of the
/// broker that mints these IDs, never of this scheduler.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionGrant {
    pub capabilities: BTreeSet<CapabilityId>,
}

impl PermissionGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.capabilities.is_subset(&parent.capabilities)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAccess {
    ReadOnly,
    Write,
}

impl WorkspaceAccess {
    const fn permits(self, child: Self) -> bool {
        matches!(self, Self::Write) || matches!(child, Self::ReadOnly)
    }
}

/// Exact source material backing a broker-attested workspace lease.
///
/// The variants are deliberately closed. A plan-input snapshot identifies the
/// evidence used to author an actor graph; it is not interchangeable with
/// either a brokered repository snapshot or a Git baseline used for execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceSourceBinding {
    BrokeredRepositorySnapshotV1 { snapshot_sha256: String },
    GitCleanCommittedHeadV1 { git_baseline_sha256: String },
}

impl WorkspaceSourceBinding {
    #[must_use]
    pub fn digest_sha256(&self) -> &str {
        match self {
            Self::BrokeredRepositorySnapshotV1 { snapshot_sha256 } => snapshot_sha256,
            Self::GitCleanCommittedHeadV1 {
                git_baseline_sha256,
            } => git_baseline_sha256,
        }
    }

    const fn supports_write(&self) -> bool {
        matches!(self, Self::GitCleanCommittedHeadV1 { .. })
    }
}

/// A pre-provisioned workspace lease at one immutable source binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceGrant {
    pub lease_id: WorkspaceLeaseId,
    pub source: WorkspaceSourceBinding,
    pub access: WorkspaceAccess,
}

/// Broker-attested workspace lease material in the trusted policy snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceLeasePolicy {
    pub source: WorkspaceSourceBinding,
    pub access: WorkspaceAccess,
}

/// Maximum usage for one attempt of one work order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBudget {
    pub max_output_tokens: u64,
    pub max_tool_calls: u64,
    pub max_wall_time_ms: u64,
    pub max_cleanup_time_ms: u64,
    pub max_attempts: u32,
}

/// Root ceilings reserved before any actor is dispatched.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorGraphLimits {
    pub max_work_orders: u32,
    pub max_parallel: u32,
    pub max_total_attempts: u64,
    pub max_total_output_tokens: u64,
    pub max_total_tool_calls: u64,
    pub max_total_wall_time_ms: u64,
}

/// Trusted mechanical envelope supplied independently of the semantic planner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorGraphPolicy {
    pub policy_version: String,
    pub plan_input_snapshot_sha256: String,
    pub root_permissions: PermissionGrant,
    pub limits: ActorGraphLimits,
    /// Whether successful workers must supply provider-reported output usage.
    pub require_reported_token_usage: bool,
    pub workspace_leases: BTreeMap<WorkspaceLeaseId, WorkspaceLeasePolicy>,
    pub model_profiles: BTreeMap<ModelProfileId, ModelLineage>,
}

/// One semantic work order. Free-form fields are opaque to this module.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrder {
    pub id: WorkOrderId,
    pub objective: String,
    pub acceptance_criteria: Vec<String>,
    pub dependencies: BTreeSet<WorkOrderId>,
    pub candidate_group: Option<CandidateGroupId>,
    pub priority: i32,
    /// Exact compiled context manifest selected for this actor.
    pub context_manifest_sha256: String,
    pub assignment: AgentAssignment,
    pub permissions: PermissionGrant,
    pub workspace: WorkspaceGrant,
    pub budget: AgentBudget,
    /// Work orders reviewed by this actor. Review nodes must use read-only
    /// workspaces and depend on every reviewed producer. Every review edge
    /// requires a distinct policy-attested independence domain.
    pub reviews: BTreeSet<WorkOrderId>,
}

/// A complete semantic-planner proposal. It carries no trusted authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorGraph {
    pub schema_version: u32,
    pub plan_input_snapshot_sha256: String,
    pub work_orders: Vec<WorkOrder>,
}

/// Structural violations fail fast; otherwise semantic/mechanical violations
/// are collected before execution begins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActorGraphViolation {
    UnsupportedSchemaVersion {
        actual: u32,
    },
    EmptyPolicyVersion,
    PolicyVersionTooLarge {
        maximum: usize,
        actual: usize,
    },
    PolicyWorkspaceLeaseLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    PolicyModelProfileLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    RootCapabilityLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    TotalCapabilityReferenceLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    InvalidWorkspaceLeasePolicy {
        lease_id: WorkspaceLeaseId,
    },
    InvalidModelProfilePolicy {
        model_profile_id: ModelProfileId,
    },
    InvalidPolicySnapshotDigest,
    InvalidSnapshotDigest,
    RootSnapshotMismatch,
    EmptyGraph,
    WorkOrderLimitExceeded {
        maximum: u32,
        actual: usize,
    },
    HardWorkOrderLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    GraphTextLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    InvalidParallelLimit,
    EmptyObjective {
        work_order_id: WorkOrderId,
    },
    ObjectiveTooLarge {
        work_order_id: WorkOrderId,
        maximum: usize,
        actual: usize,
    },
    EmptyAcceptanceCriteria {
        work_order_id: WorkOrderId,
    },
    AcceptanceCriteriaLimitExceeded {
        work_order_id: WorkOrderId,
        maximum: usize,
        actual: usize,
    },
    AcceptanceCriterionTooLarge {
        work_order_id: WorkOrderId,
        index: usize,
        maximum: usize,
        actual: usize,
    },
    InvalidAssignment {
        work_order_id: WorkOrderId,
        field: String,
    },
    UnknownModelProfile {
        work_order_id: WorkOrderId,
        model_profile_id: ModelProfileId,
    },
    ModelLineageMismatch {
        work_order_id: WorkOrderId,
        model_profile_id: ModelProfileId,
    },
    InvalidContextManifestDigest {
        work_order_id: WorkOrderId,
    },
    InvalidBudget {
        work_order_id: WorkOrderId,
    },
    DependencyLimitExceeded {
        work_order_id: WorkOrderId,
        maximum: usize,
        actual: usize,
    },
    ReviewLimitExceeded {
        work_order_id: WorkOrderId,
        maximum: usize,
        actual: usize,
    },
    CapabilityLimitExceeded {
        work_order_id: WorkOrderId,
        maximum: usize,
        actual: usize,
    },
    DuplicateWorkOrder {
        work_order_id: WorkOrderId,
    },
    UnknownDependency {
        work_order_id: WorkOrderId,
        dependency_id: WorkOrderId,
    },
    SelfDependency {
        work_order_id: WorkOrderId,
    },
    DependencyCycle {
        work_order_ids: Vec<WorkOrderId>,
    },
    AuthorityExpansion {
        work_order_id: WorkOrderId,
    },
    UnknownWorkspaceLease {
        work_order_id: WorkOrderId,
        lease_id: WorkspaceLeaseId,
    },
    WorkspaceLeaseMismatch {
        work_order_id: WorkOrderId,
        lease_id: WorkspaceLeaseId,
    },
    InvalidWorkspaceSourceDigest {
        work_order_id: WorkOrderId,
    },
    SharedWriterLease {
        lease_id: WorkspaceLeaseId,
    },
    WorkspaceExecutionProfileUnsupported {
        work_order_id: WorkOrderId,
        source: WorkspaceSourceBinding,
        access: WorkspaceAccess,
        max_attempts: u32,
    },
    CandidateSnapshotMismatch {
        candidate_group_id: CandidateGroupId,
    },
    CandidateGroupTooSmall {
        candidate_group_id: CandidateGroupId,
        actual: usize,
    },
    CandidateDependency {
        candidate_group_id: CandidateGroupId,
        work_order_id: WorkOrderId,
        dependency_id: WorkOrderId,
    },
    CandidateContractMismatch {
        candidate_group_id: CandidateGroupId,
    },
    CandidateSharedWorkspaceLease {
        candidate_group_id: CandidateGroupId,
        lease_id: WorkspaceLeaseId,
    },
    UnknownReviewTarget {
        reviewer_id: WorkOrderId,
        target_id: WorkOrderId,
    },
    ReviewMissingDependency {
        reviewer_id: WorkOrderId,
        target_id: WorkOrderId,
    },
    ReviewerHasWriteWorkspace {
        reviewer_id: WorkOrderId,
    },
    ReviewerLineageConflict {
        reviewer_id: WorkOrderId,
        target_id: WorkOrderId,
    },
    /// A review work order is a terminal evidence producer until a typed
    /// verdict controller has committed a route. Scheduler `Completed` only
    /// means that the review work itself finished; it is not approval.
    UngatedReviewDependency {
        downstream_id: WorkOrderId,
        reviewer_id: WorkOrderId,
    },
    /// A reviewed producer cannot also feed another consumer in the same
    /// graph. Such a fork would let the consumer run before the review verdict
    /// is typed and committed. The reviewer itself is the sole allowed direct
    /// consumer until a later controller creates a new gated graph.
    UngatedReviewedTargetDependency {
        downstream_id: WorkOrderId,
        target_id: WorkOrderId,
    },
    BudgetOverflow,
    AttemptBudgetExceeded {
        maximum: u64,
        actual: u64,
    },
    OutputTokenBudgetExceeded {
        maximum: u64,
        actual: u64,
    },
    MissingOutputTokenUsage,
    ToolCallBudgetExceeded {
        maximum: u64,
        actual: u64,
    },
    WallTimeBudgetExceeded {
        maximum_ms: u64,
        actual_ms: u64,
    },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ActorGraphValidationError {
    #[error("{field} {message}")]
    Identifier {
        field: &'static str,
        message: String,
    },
    #[error("actor graph is invalid: {violations:?}")]
    Violations {
        violations: Vec<ActorGraphViolation>,
    },
    #[error("actor graph could not be encoded canonically: {0}")]
    Encoding(String),
}

/// A normalized, validated graph. Construction sorts work orders by ID so the
/// same proposal has one stable digest and dispatch tie-break order.
#[derive(Clone, Debug)]
pub struct ValidatedActorGraph {
    graph: ActorGraph,
    policy: ActorGraphPolicy,
    digest_sha256: String,
}

impl ActorGraph {
    /// Validates every mechanical invariant and returns a normalized graph.
    ///
    /// # Errors
    ///
    /// Returns fail-fast structural violations, or all detected bounded
    /// mechanical violations after structural preflight. No worker is called.
    pub fn validate_against(
        mut self,
        policy: &ActorGraphPolicy,
    ) -> Result<ValidatedActorGraph, ActorGraphValidationError> {
        let structural_violations = structural_limit_violations(&self, policy);
        if !structural_violations.is_empty() {
            return Err(ActorGraphValidationError::Violations {
                violations: structural_violations,
            });
        }
        self.work_orders.sort_by_key(|order| order.id);
        let violations = graph_violations(&self, policy);
        if !violations.is_empty() {
            return Err(ActorGraphValidationError::Violations { violations });
        }
        let digest_sha256 = canonical_json_digest(&ActorGraphHashMaterial {
            graph: &self,
            policy,
        })
        .map_err(|error| ActorGraphValidationError::Encoding(error.to_string()))?;
        Ok(ValidatedActorGraph {
            graph: self,
            policy: policy.clone(),
            digest_sha256,
        })
    }
}

impl ValidatedActorGraph {
    #[must_use]
    pub const fn graph(&self) -> &ActorGraph {
        &self.graph
    }

    #[must_use]
    pub const fn policy(&self) -> &ActorGraphPolicy {
        &self.policy
    }

    #[must_use]
    pub fn digest_sha256(&self) -> &str {
        &self.digest_sha256
    }
}

#[derive(Serialize)]
struct ActorGraphHashMaterial<'a> {
    graph: &'a ActorGraph,
    policy: &'a ActorGraphPolicy,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    /// `None` preserves that the provider did not report token usage.
    pub output_tokens: Option<u64>,
    pub tool_calls: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffOutcome {
    Completed,
    Partial,
    Blocked,
}

/// Bounded semantic result returned by a worker. The scheduler supplies all
/// causal identities and refuses usage outside the reserved ceiling.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCompletion {
    pub outcome: HandoffOutcome,
    pub summary: String,
    /// Adapter-issued receipt binding the actual backend execution to the assignment.
    pub execution_receipt_id: String,
    pub artifact_sha256: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub usage: Usage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentFailureKind {
    /// The adapter attests that the failed attempt produced no external effect.
    RetryableNoEffect,
    PermanentBackend,
    PermissionDenied,
    Cancelled,
}

/// A typed worker failure. Retry policy depends only on `kind`, never message text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFailure {
    pub kind: AgentFailureKind,
    pub message: String,
    pub usage: Usage,
    /// Adapter-issued receipt binding the failed attempt to its actual execution.
    pub execution_receipt_id: String,
    /// Adapter-issued durable receipt proving the effect disposition.
    pub effect_receipt_id: Option<String>,
}

impl AgentFailure {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, AgentFailureKind::RetryableNoEffect)
            && self.effect_receipt_id.as_ref().is_some_and(|receipt| {
                !receipt.is_empty() && receipt.len() <= MAX_EVIDENCE_ID_BYTES
            })
    }
}

/// Immutable inputs for one causally identified attempt.
#[derive(Clone, Debug)]
pub struct AgentDispatch {
    pub actor_id: ActorId,
    pub execution_id: ExecutionId,
    pub attempt_id: AttemptId,
    pub parent_attempt_id: Option<AttemptId>,
    /// Durable root identifying this exact execution of the validated graph.
    pub graph_accepted_event_id: SchedulerEventId,
    pub graph_sha256: String,
    pub attestation: DispatchAttestation,
    pub work_order: Arc<WorkOrder>,
    pub dependency_handoffs: BTreeMap<WorkOrderId, Arc<Handoff>>,
    pub dependency_handoff_event_ids: BTreeMap<WorkOrderId, SchedulerEventId>,
}

pub type AgentFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AgentCompletion, AgentFailure>> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct TimedOutAttempt {
    pub actor_id: ActorId,
    pub execution_id: ExecutionId,
    pub attempt_id: AttemptId,
    pub attestation: DispatchAttestation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupReceipt {
    pub cleanup_receipt_id: String,
}

pub type AgentCleanupFuture<'a> = Pin<Box<dyn Future<Output = Option<CleanupReceipt>> + Send + 'a>>;

/// Provider-neutral execution boundary for a real model or external agent harness.
///
/// Implementations are trusted adapters: they must enforce request ceilings,
/// bind actual backend identity to the attested assignment, and own every
/// spawned resource by attempt ID. `RetryableNoEffect` may be returned only
/// with a durable no-effect receipt. On deadline, the scheduler invokes
/// `cancel_and_cleanup`; completion is not claimed unless its receipt verifies.
pub trait AgentWorker: Send + Sync {
    fn execute(&self, dispatch: AgentDispatch) -> AgentFuture<'_>;

    fn cancel_and_cleanup(&self, _attempt: TimedOutAttempt) -> AgentCleanupFuture<'_> {
        Box::pin(async { None })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    pub id: HandoffId,
    /// Journal event that durably retained this exact handoff.
    pub retained_event_id: SchedulerEventId,
    pub work_order_id: WorkOrderId,
    pub actor_id: ActorId,
    pub execution_id: ExecutionId,
    pub attempt_id: AttemptId,
    pub outcome: HandoffOutcome,
    pub summary: String,
    pub execution_receipt_id: String,
    pub artifact_sha256: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub usage: Usage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HandoffViolation {
    EmptySummary,
    InvalidExecutionReceipt,
    SummaryTooLarge { maximum: usize, actual: usize },
    ArtifactReferenceLimitExceeded { maximum: usize, actual: usize },
    InvalidArtifactDigest { index: usize },
    DuplicateArtifactDigest,
    MissingCompletionEvidence,
    EvidenceReferenceLimitExceeded { maximum: usize, actual: usize },
    InvalidEvidenceId { index: usize },
    DuplicateEvidenceId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentFailureViolation {
    EmptyMessage,
    MessageTooLarge { maximum: usize, actual: usize },
    InvalidExecutionReceipt,
    InvalidEffectReceipt,
    MissingNoEffectReceipt,
}

/// Bounded reconciliation material retained even when a worker result is invalid.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptObservation {
    pub execution_receipt_id: Option<String>,
    pub effect_receipt_id: Option<String>,
    pub usage: Usage,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkOrderFailure {
    Worker {
        failure: AgentFailure,
    },
    InvalidWorkerFailure {
        violations: Vec<AgentFailureViolation>,
        usage_violation: Option<ActorGraphViolation>,
        observation: AttemptObservation,
    },
    DeadlineExceeded {
        maximum_ms: u64,
        cleanup_receipt_id: String,
    },
    CleanupUnproven {
        maximum_ms: u64,
        cleanup_maximum_ms: u64,
    },
    UsageViolation {
        violation: ActorGraphViolation,
    },
    InvalidHandoff {
        violations: Vec<HandoffViolation>,
        usage_violation: Option<ActorGraphViolation>,
        observation: AttemptObservation,
    },
    IncompleteHandoff {
        outcome: HandoffOutcome,
    },
    DependencyFailed {
        dependency_ids: Vec<WorkOrderId>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorGraphOutcome {
    Completed,
    Failed,
}

/// Terminal projection of one scheduler run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorGraphRun {
    pub graph_sha256: String,
    /// Durable causal root for this execution of the graph.
    pub accepted_event_id: SchedulerEventId,
    /// Durable terminal record for this execution of the graph.
    pub finished_event_id: SchedulerEventId,
    pub terminal_event_ids: BTreeMap<WorkOrderId, SchedulerEventId>,
    pub outcome: ActorGraphOutcome,
    pub handoffs: BTreeMap<WorkOrderId, Handoff>,
    pub failures: BTreeMap<WorkOrderId, WorkOrderFailure>,
    /// Maximum number of dispatched worker futures simultaneously owned by the scheduler.
    /// Actual backend/process overlap is separate adapter provenance.
    pub maximum_in_flight: u32,
}

/// Bounded dispatch material that a durable journal can verify without parsing prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAttestation {
    pub graph_sha256: String,
    pub work_order_sha256: String,
    pub permissions_sha256: String,
    pub assignment: AgentAssignment,
    pub context_manifest_sha256: String,
    pub workspace: WorkspaceGrant,
    pub budget: AgentBudget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SchedulerEvent {
    GraphAccepted {
        graph_sha256: String,
        policy_version: String,
        plan_input_snapshot_sha256: String,
    },
    AttemptDispatched {
        work_order_id: WorkOrderId,
        actor_id: ActorId,
        execution_id: ExecutionId,
        attempt_id: AttemptId,
        parent_attempt_id: Option<AttemptId>,
        graph_accepted_event_id: SchedulerEventId,
        attestation: Box<DispatchAttestation>,
        dependency_handoff_event_ids: BTreeMap<WorkOrderId, SchedulerEventId>,
    },
    AttemptFailed {
        work_order_id: WorkOrderId,
        execution_id: ExecutionId,
        attempt_id: AttemptId,
        failure: WorkOrderFailure,
        will_retry: bool,
    },
    HandoffRetained {
        handoff: Handoff,
    },
    WorkOrderBlocked {
        work_order_id: WorkOrderId,
        dependency_ids: Vec<WorkOrderId>,
        dependency_terminal_event_ids: BTreeMap<WorkOrderId, SchedulerEventId>,
    },
    GraphFinished {
        outcome: ActorGraphOutcome,
        terminal_event_ids: BTreeMap<WorkOrderId, SchedulerEventId>,
    },
    GraphSuspended {
        cleanup_unproven_work_order_ids: Vec<WorkOrderId>,
        pending_work_order_ids: Vec<WorkOrderId>,
        terminal_event_ids: BTreeMap<WorkOrderId, SchedulerEventId>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRecord {
    pub id: SchedulerEventId,
    pub causal_parent: Option<SchedulerEventId>,
    pub event: SchedulerEvent,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct SchedulerJournalError {
    pub message: String,
}

impl SchedulerJournalError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Persistence acknowledgement required before execution crosses a boundary.
pub trait SchedulerJournal: Send + Sync {
    /// Retains one event and acknowledges the configured durability contract.
    ///
    /// # Errors
    ///
    /// Returns an error unless the event and every referenced receipt or
    /// artifact are durably accepted. The scheduler fails closed on rejection.
    fn retain(&self, record: &SchedulerRecord) -> Result<(), SchedulerJournalError>;
}

/// Typed failure returned when a worker dispatch cannot be proven to be the
/// exact scheduler-journal subject it claims to be.
///
/// Verification compares only identities, typed records, canonical hashes, and
/// causal references. It never interprets handoff prose or artifact contents.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SchedulerDispatchVerificationError {
    #[error(transparent)]
    Journal(#[from] SchedulerJournalError),
    #[error("dispatch attestation does not match its exact graph and work order")]
    AttestationMismatch,
    #[error("dispatch dependency handoff keys do not equal the work-order dependency set")]
    DependencyHandoffKeySetMismatch,
    #[error("dispatch dependency event keys do not equal the work-order dependency set")]
    DependencyEventKeySetMismatch,
    #[error("dependency {dependency_id} is bound to handoff work order {handoff_work_order_id}")]
    DependencyHandoffWorkOrderMismatch {
        dependency_id: WorkOrderId,
        handoff_work_order_id: WorkOrderId,
    },
    #[error(
        "dependency {dependency_id} maps event {mapped_event_id}, but its handoff was retained by {handoff_event_id}"
    )]
    DependencyHandoffEventMismatch {
        dependency_id: WorkOrderId,
        mapped_event_id: SchedulerEventId,
        handoff_event_id: SchedulerEventId,
    },
    #[error("dependency {dependency_id} handoff is not completed: {outcome:?}")]
    DependencyHandoffIncomplete {
        dependency_id: WorkOrderId,
        outcome: HandoffOutcome,
    },
    #[error("no retained dispatch record exists for attempt {attempt_id}")]
    DispatchRecordNotFound { attempt_id: AttemptId },
    #[error("multiple retained dispatch records exist for attempt {attempt_id}")]
    DispatchRecordAmbiguous { attempt_id: AttemptId },
    #[error("retained dispatch work-order identity does not match")]
    DispatchWorkOrderMismatch,
    #[error("retained dispatch actor identity does not match")]
    DispatchActorMismatch,
    #[error("retained dispatch execution identity does not match")]
    DispatchExecutionMismatch,
    #[error("retained dispatch parent-attempt identity does not match")]
    DispatchParentAttemptMismatch,
    #[error("retained dispatch graph-run root does not match")]
    DispatchGraphRootMismatch,
    #[error("retained dispatch attestation does not match")]
    DispatchAttestationMismatch,
    #[error("retained dispatch dependency event bindings do not match")]
    DispatchDependencyEventsMismatch,
    #[error("retained dispatch causal parent does not match its dependency chain")]
    DispatchCausalParentMismatch,
    #[error("dependency {dependency_id} references missing journal event {event_id}")]
    DependencyRecordNotFound {
        dependency_id: WorkOrderId,
        event_id: SchedulerEventId,
    },
    #[error("dependency {dependency_id} references ambiguous journal event {event_id}")]
    DependencyRecordAmbiguous {
        dependency_id: WorkOrderId,
        event_id: SchedulerEventId,
    },
    #[error("dependency {dependency_id} does not reference a retained handoff event")]
    DependencyRecordTypeMismatch { dependency_id: WorkOrderId },
    #[error("dependency {dependency_id} does not equal its exact retained handoff record")]
    DependencyRetainedHandoffMismatch { dependency_id: WorkOrderId },
    #[error("dependency {dependency_id} retained handoff has no causal producer dispatch")]
    DependencyProducerDispatchMissing { dependency_id: WorkOrderId },
    #[error("dependency {dependency_id} retained handoff has an ambiguous causal parent")]
    DependencyProducerDispatchAmbiguous { dependency_id: WorkOrderId },
    #[error("dependency {dependency_id} retained handoff parent is not a dispatch")]
    DependencyProducerRecordTypeMismatch { dependency_id: WorkOrderId },
    #[error("dependency {dependency_id} producer dispatch identity does not match its handoff")]
    DependencyProducerIdentityMismatch { dependency_id: WorkOrderId },
    #[error("dependency {dependency_id} producer dispatch belongs to another actor graph")]
    DependencyProducerGraphMismatch { dependency_id: WorkOrderId },
    #[error("root dispatch causal parent is missing")]
    RootRecordNotFound,
    #[error("root dispatch causal parent is ambiguous")]
    RootRecordAmbiguous,
    #[error("root dispatch causal parent is not the matching accepted graph")]
    RootRecordMismatch,
}

/// Exact producer dispatch recovered for one dependency by a trusted scheduler
/// verifier.
///
/// This is typed verification evidence, not a standalone capability. Callers
/// must consume it directly from the configured [`SchedulerDispatchVerifier`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSchedulerDependencyV1 {
    pub dependency_id: WorkOrderId,
    pub graph_accepted_event_id: SchedulerEventId,
    pub handoff_event_id: SchedulerEventId,
    pub producer_dispatch_event_id: SchedulerEventId,
    pub actor_id: ActorId,
    pub execution_id: ExecutionId,
    pub attempt_id: AttemptId,
    pub dispatch_attestation: DispatchAttestation,
}

/// Journal-derived identity and dependency evidence for one exact scheduler
/// dispatch.
///
/// Implementations of [`SchedulerDispatchVerifier`] are trusted to construct
/// this only after validating the complete retained causal chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSchedulerDispatchV1 {
    pub dispatch_event_id: SchedulerEventId,
    pub graph_accepted_event_id: SchedulerEventId,
    pub dependencies: BTreeMap<WorkOrderId, VerifiedSchedulerDependencyV1>,
}

/// Read-only authority boundary proving that an [`AgentDispatch`] is exactly
/// backed by the scheduler's retained dispatch and dependency-handoff chain.
///
/// This is deliberately separate from [`SchedulerJournal`] so append-only
/// journal implementations are not forced to expose reads. Durable journals
/// can implement this trait with indexed transactional reads or sealed proofs.
pub trait SchedulerDispatchVerifier: Send + Sync {
    /// Verifies the complete typed dispatch subject without interpreting prose.
    ///
    /// # Errors
    ///
    /// Returns a typed error unless the dispatch, its attestation, every
    /// dependency handoff, and every causal journal edge match exactly.
    fn verify_dispatch(
        &self,
        dispatch: &AgentDispatch,
    ) -> Result<VerifiedSchedulerDispatchV1, SchedulerDispatchVerificationError>;
}

#[derive(Debug, Default)]
pub struct InMemorySchedulerJournal {
    records: Mutex<Vec<SchedulerRecord>>,
}

impl InMemorySchedulerJournal {
    /// Returns a stable snapshot in acknowledgement order.
    ///
    /// # Errors
    ///
    /// Returns an error if the journal lock was poisoned.
    pub fn snapshot(&self) -> Result<Vec<SchedulerRecord>, SchedulerJournalError> {
        self.records
            .lock()
            .map(|records| records.clone())
            .map_err(|_| SchedulerJournalError::new("scheduler journal lock was poisoned"))
    }
}

impl SchedulerJournal for InMemorySchedulerJournal {
    fn retain(&self, record: &SchedulerRecord) -> Result<(), SchedulerJournalError> {
        self.records
            .lock()
            .map_err(|_| SchedulerJournalError::new("scheduler journal lock was poisoned"))?
            .push(record.clone());
        Ok(())
    }
}

impl SchedulerDispatchVerifier for InMemorySchedulerJournal {
    fn verify_dispatch(
        &self,
        dispatch: &AgentDispatch,
    ) -> Result<VerifiedSchedulerDispatchV1, SchedulerDispatchVerificationError> {
        verify_dispatch_shape(dispatch)?;

        let records = self.snapshot()?;
        let dispatch_record = unique_dispatch_record_for_attempt(&records, dispatch.attempt_id)?;
        let SchedulerEvent::AttemptDispatched {
            work_order_id,
            actor_id,
            execution_id,
            parent_attempt_id,
            graph_accepted_event_id,
            attestation,
            dependency_handoff_event_ids,
            ..
        } = &dispatch_record.event
        else {
            unreachable!("dispatch lookup only returns AttemptDispatched records")
        };
        if *work_order_id != dispatch.work_order.id {
            return Err(SchedulerDispatchVerificationError::DispatchWorkOrderMismatch);
        }
        if *actor_id != dispatch.actor_id {
            return Err(SchedulerDispatchVerificationError::DispatchActorMismatch);
        }
        if *execution_id != dispatch.execution_id {
            return Err(SchedulerDispatchVerificationError::DispatchExecutionMismatch);
        }
        if *parent_attempt_id != dispatch.parent_attempt_id {
            return Err(SchedulerDispatchVerificationError::DispatchParentAttemptMismatch);
        }
        if *graph_accepted_event_id != dispatch.graph_accepted_event_id {
            return Err(SchedulerDispatchVerificationError::DispatchGraphRootMismatch);
        }
        if attestation.as_ref() != &dispatch.attestation {
            return Err(SchedulerDispatchVerificationError::DispatchAttestationMismatch);
        }
        if dependency_handoff_event_ids != &dispatch.dependency_handoff_event_ids {
            return Err(SchedulerDispatchVerificationError::DispatchDependencyEventsMismatch);
        }

        verify_graph_root_record(
            &records,
            dispatch.graph_accepted_event_id,
            &dispatch.graph_sha256,
        )?;
        verify_dispatch_causal_parent(&records, dispatch_record, dispatch)?;

        let mut verified_dependencies = BTreeMap::new();
        for (dependency_id, handoff) in &dispatch.dependency_handoffs {
            let retained_record =
                unique_dependency_record(&records, *dependency_id, handoff.retained_event_id)?;
            let SchedulerEvent::HandoffRetained {
                handoff: retained_handoff,
            } = &retained_record.event
            else {
                return Err(
                    SchedulerDispatchVerificationError::DependencyRecordTypeMismatch {
                        dependency_id: *dependency_id,
                    },
                );
            };
            if retained_handoff != handoff.as_ref() {
                return Err(
                    SchedulerDispatchVerificationError::DependencyRetainedHandoffMismatch {
                        dependency_id: *dependency_id,
                    },
                );
            }
            let verified_dependency = verify_dependency_producer(
                &records,
                *dependency_id,
                retained_record,
                retained_handoff,
                &dispatch.graph_sha256,
                dispatch.graph_accepted_event_id,
            )?;
            verified_dependencies.insert(*dependency_id, verified_dependency);
        }

        Ok(VerifiedSchedulerDispatchV1 {
            dispatch_event_id: dispatch_record.id,
            graph_accepted_event_id: dispatch.graph_accepted_event_id,
            dependencies: verified_dependencies,
        })
    }
}

fn verify_dispatch_shape(
    dispatch: &AgentDispatch,
) -> Result<(), SchedulerDispatchVerificationError> {
    let expected_attestation =
        dispatch_attestation(&dispatch.graph_sha256, dispatch.work_order.as_ref())?;
    if dispatch.attestation != expected_attestation {
        return Err(SchedulerDispatchVerificationError::AttestationMismatch);
    }

    let dependency_ids = &dispatch.work_order.dependencies;
    if !map_keys_equal_set(&dispatch.dependency_handoffs, dependency_ids) {
        return Err(SchedulerDispatchVerificationError::DependencyHandoffKeySetMismatch);
    }
    if !map_keys_equal_set(&dispatch.dependency_handoff_event_ids, dependency_ids) {
        return Err(SchedulerDispatchVerificationError::DependencyEventKeySetMismatch);
    }
    for (dependency_id, handoff) in &dispatch.dependency_handoffs {
        if handoff.work_order_id != *dependency_id {
            return Err(
                SchedulerDispatchVerificationError::DependencyHandoffWorkOrderMismatch {
                    dependency_id: *dependency_id,
                    handoff_work_order_id: handoff.work_order_id,
                },
            );
        }
        let mapped_event_id = dispatch.dependency_handoff_event_ids[dependency_id];
        if handoff.retained_event_id != mapped_event_id {
            return Err(
                SchedulerDispatchVerificationError::DependencyHandoffEventMismatch {
                    dependency_id: *dependency_id,
                    mapped_event_id,
                    handoff_event_id: handoff.retained_event_id,
                },
            );
        }
        if handoff.outcome != HandoffOutcome::Completed {
            return Err(
                SchedulerDispatchVerificationError::DependencyHandoffIncomplete {
                    dependency_id: *dependency_id,
                    outcome: handoff.outcome,
                },
            );
        }
    }
    Ok(())
}

fn map_keys_equal_set<K: Ord, V>(map: &BTreeMap<K, V>, set: &BTreeSet<K>) -> bool {
    map.len() == set.len() && map.keys().eq(set.iter())
}

fn unique_dispatch_record_for_attempt(
    records: &[SchedulerRecord],
    attempt_id: AttemptId,
) -> Result<&SchedulerRecord, SchedulerDispatchVerificationError> {
    let mut matches = records.iter().filter(|record| {
        matches!(
            record.event,
            SchedulerEvent::AttemptDispatched {
                attempt_id: retained_attempt_id,
                ..
            } if retained_attempt_id == attempt_id
        )
    });
    let Some(record) = matches.next() else {
        return Err(SchedulerDispatchVerificationError::DispatchRecordNotFound { attempt_id });
    };
    if matches.next().is_some() {
        return Err(SchedulerDispatchVerificationError::DispatchRecordAmbiguous { attempt_id });
    }
    Ok(record)
}

fn unique_dependency_record(
    records: &[SchedulerRecord],
    dependency_id: WorkOrderId,
    event_id: SchedulerEventId,
) -> Result<&SchedulerRecord, SchedulerDispatchVerificationError> {
    let mut matches = records.iter().filter(|record| record.id == event_id);
    let Some(record) = matches.next() else {
        return Err(
            SchedulerDispatchVerificationError::DependencyRecordNotFound {
                dependency_id,
                event_id,
            },
        );
    };
    if matches.next().is_some() {
        return Err(
            SchedulerDispatchVerificationError::DependencyRecordAmbiguous {
                dependency_id,
                event_id,
            },
        );
    }
    Ok(record)
}

fn verify_dependency_producer(
    records: &[SchedulerRecord],
    dependency_id: WorkOrderId,
    handoff_record: &SchedulerRecord,
    handoff: &Handoff,
    graph_sha256: &str,
    graph_accepted_event_id: SchedulerEventId,
) -> Result<VerifiedSchedulerDependencyV1, SchedulerDispatchVerificationError> {
    let Some(parent_event_id) = handoff_record.causal_parent else {
        return Err(
            SchedulerDispatchVerificationError::DependencyProducerDispatchMissing { dependency_id },
        );
    };
    let mut matches = records.iter().filter(|record| record.id == parent_event_id);
    let Some(parent) = matches.next() else {
        return Err(
            SchedulerDispatchVerificationError::DependencyProducerDispatchMissing { dependency_id },
        );
    };
    if matches.next().is_some() {
        return Err(
            SchedulerDispatchVerificationError::DependencyProducerDispatchAmbiguous {
                dependency_id,
            },
        );
    }
    let SchedulerEvent::AttemptDispatched {
        work_order_id,
        actor_id,
        execution_id,
        attempt_id,
        graph_accepted_event_id: producer_graph_accepted_event_id,
        attestation,
        ..
    } = &parent.event
    else {
        return Err(
            SchedulerDispatchVerificationError::DependencyProducerRecordTypeMismatch {
                dependency_id,
            },
        );
    };
    if *work_order_id != handoff.work_order_id
        || *actor_id != handoff.actor_id
        || *execution_id != handoff.execution_id
        || *attempt_id != handoff.attempt_id
    {
        return Err(
            SchedulerDispatchVerificationError::DependencyProducerIdentityMismatch {
                dependency_id,
            },
        );
    }
    if attestation.graph_sha256 != graph_sha256 {
        return Err(
            SchedulerDispatchVerificationError::DependencyProducerGraphMismatch { dependency_id },
        );
    }
    if *producer_graph_accepted_event_id != graph_accepted_event_id {
        return Err(SchedulerDispatchVerificationError::DispatchGraphRootMismatch);
    }
    Ok(VerifiedSchedulerDependencyV1 {
        dependency_id,
        graph_accepted_event_id,
        handoff_event_id: handoff_record.id,
        producer_dispatch_event_id: parent.id,
        actor_id: *actor_id,
        execution_id: *execution_id,
        attempt_id: *attempt_id,
        dispatch_attestation: attestation.as_ref().clone(),
    })
}

fn verify_dispatch_causal_parent(
    records: &[SchedulerRecord],
    dispatch_record: &SchedulerRecord,
    dispatch: &AgentDispatch,
) -> Result<(), SchedulerDispatchVerificationError> {
    verify_full_dispatch_ancestry(
        records,
        dispatch_record,
        dispatch.graph_accepted_event_id,
        &dispatch.graph_sha256,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the iterative walk keeps every retry and dependency edge auditable without recursion"
)]
fn verify_full_dispatch_ancestry(
    records: &[SchedulerRecord],
    dispatch_record: &SchedulerRecord,
    graph_accepted_event_id: SchedulerEventId,
    graph_sha256: &str,
) -> Result<(), SchedulerDispatchVerificationError> {
    let mut index = BTreeMap::new();
    for (position, record) in records.iter().enumerate() {
        if index.insert(record.id, (position, record)).is_some() {
            return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
        }
    }
    verify_graph_root_record(records, graph_accepted_event_id, graph_sha256)?;

    let mut pending = vec![dispatch_record.id];
    let mut verified = BTreeSet::new();
    while let Some(dispatch_event_id) = pending.pop() {
        if !verified.insert(dispatch_event_id) {
            continue;
        }
        let Some((dispatch_position, current)) = index.get(&dispatch_event_id).copied() else {
            return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
        };
        let SchedulerEvent::AttemptDispatched {
            work_order_id,
            actor_id,
            execution_id,
            parent_attempt_id,
            graph_accepted_event_id: retained_root,
            attestation,
            dependency_handoff_event_ids,
            ..
        } = &current.event
        else {
            return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
        };
        if *retained_root != graph_accepted_event_id || attestation.graph_sha256 != graph_sha256 {
            return Err(SchedulerDispatchVerificationError::DispatchGraphRootMismatch);
        }

        if let Some(parent_attempt_id) = parent_attempt_id {
            let Some(failed_event_id) = current.causal_parent else {
                return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
            };
            let failed = preceding_record(&index, failed_event_id, dispatch_position)?;
            let SchedulerEvent::AttemptFailed {
                work_order_id: failed_work_order_id,
                execution_id: failed_execution_id,
                attempt_id: failed_attempt_id,
                will_retry,
                ..
            } = &failed.event
            else {
                return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
            };
            if failed_work_order_id != work_order_id
                || failed_execution_id != execution_id
                || failed_attempt_id != parent_attempt_id
                || !will_retry
            {
                return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
            }
            let Some(parent_dispatch_event_id) = failed.causal_parent else {
                return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
            };
            let failed_position = index[&failed.id].0;
            let parent_dispatch =
                preceding_record(&index, parent_dispatch_event_id, failed_position)?;
            let SchedulerEvent::AttemptDispatched {
                work_order_id: parent_work_order_id,
                actor_id: parent_actor_id,
                execution_id: parent_execution_id,
                attempt_id: retained_parent_attempt_id,
                graph_accepted_event_id: parent_root,
                attestation: parent_attestation,
                dependency_handoff_event_ids: parent_dependencies,
                ..
            } = &parent_dispatch.event
            else {
                return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
            };
            if parent_work_order_id != work_order_id
                || parent_actor_id != actor_id
                || parent_execution_id != execution_id
                || retained_parent_attempt_id != parent_attempt_id
                || *parent_root != graph_accepted_event_id
                || parent_attestation != attestation
                || parent_dependencies != dependency_handoff_event_ids
            {
                return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
            }
            pending.push(parent_dispatch.id);
            continue;
        }

        let Some(first_dependency_event_id) = dependency_handoff_event_ids.values().next().copied()
        else {
            if current.causal_parent != Some(graph_accepted_event_id) {
                return Err(SchedulerDispatchVerificationError::RootRecordMismatch);
            }
            let root_position = index
                .get(&graph_accepted_event_id)
                .map(|(position, _)| *position)
                .ok_or(SchedulerDispatchVerificationError::RootRecordNotFound)?;
            if root_position >= dispatch_position {
                return Err(SchedulerDispatchVerificationError::RootRecordMismatch);
            }
            continue;
        };
        if current.causal_parent != Some(first_dependency_event_id) {
            return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
        }

        let mut unique_dependency_events = BTreeSet::new();
        for (dependency_id, handoff_event_id) in dependency_handoff_event_ids {
            if !unique_dependency_events.insert(*handoff_event_id) {
                return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
            }
            let handoff_record = preceding_record(&index, *handoff_event_id, dispatch_position)?;
            let SchedulerEvent::HandoffRetained { handoff } = &handoff_record.event else {
                return Err(
                    SchedulerDispatchVerificationError::DependencyRecordTypeMismatch {
                        dependency_id: *dependency_id,
                    },
                );
            };
            if handoff.retained_event_id != *handoff_event_id
                || handoff.work_order_id != *dependency_id
            {
                return Err(
                    SchedulerDispatchVerificationError::DependencyRetainedHandoffMismatch {
                        dependency_id: *dependency_id,
                    },
                );
            }
            if handoff.outcome != HandoffOutcome::Completed {
                return Err(
                    SchedulerDispatchVerificationError::DependencyHandoffIncomplete {
                        dependency_id: *dependency_id,
                        outcome: handoff.outcome,
                    },
                );
            }
            let Some(producer_dispatch_event_id) = handoff_record.causal_parent else {
                return Err(
                    SchedulerDispatchVerificationError::DependencyProducerDispatchMissing {
                        dependency_id: *dependency_id,
                    },
                );
            };
            let handoff_position = index[&handoff_record.id].0;
            let producer_dispatch =
                preceding_record(&index, producer_dispatch_event_id, handoff_position)?;
            let SchedulerEvent::AttemptDispatched {
                work_order_id: producer_work_order_id,
                actor_id: producer_actor_id,
                execution_id: producer_execution_id,
                attempt_id: producer_attempt_id,
                graph_accepted_event_id: producer_root,
                attestation: producer_attestation,
                ..
            } = &producer_dispatch.event
            else {
                return Err(
                    SchedulerDispatchVerificationError::DependencyProducerRecordTypeMismatch {
                        dependency_id: *dependency_id,
                    },
                );
            };
            if *producer_work_order_id != handoff.work_order_id
                || *producer_actor_id != handoff.actor_id
                || *producer_execution_id != handoff.execution_id
                || *producer_attempt_id != handoff.attempt_id
                || *producer_root != graph_accepted_event_id
                || producer_attestation.graph_sha256 != graph_sha256
            {
                return Err(
                    SchedulerDispatchVerificationError::DependencyProducerIdentityMismatch {
                        dependency_id: *dependency_id,
                    },
                );
            }
            pending.push(producer_dispatch.id);
        }
    }
    Ok(())
}

fn preceding_record<'a>(
    index: &BTreeMap<SchedulerEventId, (usize, &'a SchedulerRecord)>,
    event_id: SchedulerEventId,
    child_position: usize,
) -> Result<&'a SchedulerRecord, SchedulerDispatchVerificationError> {
    let Some((position, record)) = index.get(&event_id).copied() else {
        return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
    };
    if position >= child_position {
        return Err(SchedulerDispatchVerificationError::DispatchCausalParentMismatch);
    }
    Ok(record)
}

fn verify_graph_root_record(
    records: &[SchedulerRecord],
    graph_accepted_event_id: SchedulerEventId,
    graph_sha256: &str,
) -> Result<(), SchedulerDispatchVerificationError> {
    let mut matches = records
        .iter()
        .filter(|record| record.id == graph_accepted_event_id);
    let Some(parent) = matches.next() else {
        return Err(SchedulerDispatchVerificationError::RootRecordNotFound);
    };
    if matches.next().is_some() {
        return Err(SchedulerDispatchVerificationError::RootRecordAmbiguous);
    }
    if parent.causal_parent.is_some()
        || !matches!(
            &parent.event,
            SchedulerEvent::GraphAccepted {
                graph_sha256: retained_graph_sha256,
                ..
            } if retained_graph_sha256 == graph_sha256
        )
    {
        return Err(SchedulerDispatchVerificationError::RootRecordMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ActorGraphExecutionError {
    #[error(transparent)]
    Journal(#[from] SchedulerJournalError),
    #[error(
        "actor graph suspended because cleanup is unproven for work orders {work_order_ids:?}; suspension event {suspended_event_id}"
    )]
    CleanupUnproven {
        work_order_ids: Vec<WorkOrderId>,
        suspended_event_id: SchedulerEventId,
    },
    #[error("validated actor graph made no scheduling progress; pending work orders: {pending:?}")]
    SchedulerInvariant { pending: Vec<WorkOrderId> },
}

/// Executes a validated graph with deterministic dispatch ordering and real overlap.
pub struct ActorGraphExecutor<'a, W: AgentWorker + ?Sized, J: SchedulerJournal + ?Sized> {
    worker: &'a W,
    journal: &'a J,
}

impl<'a, W, J> ActorGraphExecutor<'a, W, J>
where
    W: AgentWorker + ?Sized,
    J: SchedulerJournal + ?Sized,
{
    #[must_use]
    pub const fn new(worker: &'a W, journal: &'a J) -> Self {
        Self { worker, journal }
    }

    /// Runs every dependency-ready order, bounded by `max_parallel`.
    ///
    /// Journal failures stop dispatch. An unproven cleanup stops new dispatch,
    /// drains already-started scheduler futures, retains `GraphSuspended`, and
    /// returns an error instead of a terminal projection. The caller must keep
    /// external reservations quarantined until reconciliation.
    ///
    /// # Errors
    ///
    /// Returns when durable journal acknowledgement fails, cleanup cannot be
    /// proven, or an internal scheduling invariant is violated.
    #[allow(clippy::too_many_lines)]
    pub async fn execute(
        &self,
        graph: &ValidatedActorGraph,
    ) -> Result<ActorGraphRun, ActorGraphExecutionError> {
        let root = self.retain(
            None,
            SchedulerEvent::GraphAccepted {
                graph_sha256: graph.digest_sha256.clone(),
                policy_version: graph.policy.policy_version.clone(),
                plan_input_snapshot_sha256: graph.policy.plan_input_snapshot_sha256.clone(),
            },
        )?;
        let orders = graph
            .graph
            .work_orders
            .iter()
            .map(|order| (order.id, Arc::new(order.clone())))
            .collect::<BTreeMap<_, _>>();
        let mut pending = orders.keys().copied().collect::<BTreeSet<_>>();
        let mut handoffs: BTreeMap<WorkOrderId, Arc<Handoff>> = BTreeMap::new();
        let mut failures: BTreeMap<WorkOrderId, WorkOrderFailure> = BTreeMap::new();
        let mut terminal_event_ids: BTreeMap<WorkOrderId, SchedulerEventId> = BTreeMap::new();
        let mut cleanup_unproven = BTreeSet::new();
        let mut active = FuturesUnordered::new();
        let mut maximum_in_flight = 0_u32;

        loop {
            if !cleanup_unproven.is_empty() {
                if active.is_empty() {
                    let work_order_ids = cleanup_unproven.iter().copied().collect::<Vec<_>>();
                    let causal_parent = work_order_ids
                        .iter()
                        .find_map(|id| terminal_event_ids.get(id))
                        .copied()
                        .unwrap_or(root);
                    let suspended_event_id = self.retain(
                        Some(causal_parent),
                        SchedulerEvent::GraphSuspended {
                            cleanup_unproven_work_order_ids: work_order_ids.clone(),
                            pending_work_order_ids: pending.iter().copied().collect(),
                            terminal_event_ids: terminal_event_ids.clone(),
                        },
                    )?;
                    return Err(ActorGraphExecutionError::CleanupUnproven {
                        work_order_ids,
                        suspended_event_id,
                    });
                }
                let Some(terminal) = active.next().await else {
                    return Err(ActorGraphExecutionError::SchedulerInvariant {
                        pending: pending.iter().copied().collect(),
                    });
                };
                apply_terminal(
                    terminal?,
                    &mut handoffs,
                    &mut failures,
                    &mut terminal_event_ids,
                    &mut cleanup_unproven,
                );
                continue;
            }
            let mut made_progress = false;
            let blocked = pending
                .iter()
                .filter_map(|id| {
                    let order = &orders[id];
                    let failed = order
                        .dependencies
                        .iter()
                        .filter(|dependency| failures.contains_key(*dependency))
                        .copied()
                        .collect::<Vec<_>>();
                    (!failed.is_empty()).then_some((*id, failed))
                })
                .collect::<Vec<_>>();
            for (id, dependency_ids) in blocked {
                made_progress = true;
                pending.remove(&id);
                let dependency_terminal_event_ids = dependency_ids
                    .iter()
                    .filter_map(|dependency_id| {
                        terminal_event_ids
                            .get(dependency_id)
                            .map(|event_id| (*dependency_id, *event_id))
                    })
                    .collect::<BTreeMap<_, _>>();
                let causal_parent = dependency_terminal_event_ids
                    .values()
                    .next()
                    .copied()
                    .unwrap_or(root);
                let blocked_event_id = self.retain(
                    Some(causal_parent),
                    SchedulerEvent::WorkOrderBlocked {
                        work_order_id: id,
                        dependency_ids: dependency_ids.clone(),
                        dependency_terminal_event_ids,
                    },
                )?;
                failures.insert(id, WorkOrderFailure::DependencyFailed { dependency_ids });
                terminal_event_ids.insert(id, blocked_event_id);
            }

            let slots = usize::try_from(graph.policy.limits.max_parallel)
                .unwrap_or(usize::MAX)
                .saturating_sub(active.len());
            if slots > 0 {
                let mut ready = pending
                    .iter()
                    .filter(|id| {
                        orders[id]
                            .dependencies
                            .iter()
                            .all(|dependency| handoffs.contains_key(dependency))
                    })
                    .map(|id| Arc::clone(&orders[id]))
                    .collect::<Vec<_>>();
                ready.sort_by(|left, right| {
                    right
                        .priority
                        .cmp(&left.priority)
                        .then_with(|| left.id.cmp(&right.id))
                });
                for order in ready.into_iter().take(slots) {
                    made_progress = true;
                    pending.remove(&order.id);
                    let dependencies = order
                        .dependencies
                        .iter()
                        .map(|id| (*id, handoffs[id].clone()))
                        .collect::<BTreeMap<_, _>>();
                    active.push(run_work_order(
                        self.worker,
                        self.journal,
                        root,
                        graph.digest_sha256.clone(),
                        graph.policy.require_reported_token_usage,
                        order,
                        dependencies,
                    ));
                }
                maximum_in_flight =
                    maximum_in_flight.max(u32::try_from(active.len()).unwrap_or(u32::MAX));
            }

            if active.is_empty() {
                if pending.is_empty() {
                    break;
                }
                if made_progress {
                    continue;
                }
                return Err(ActorGraphExecutionError::SchedulerInvariant {
                    pending: pending.iter().copied().collect(),
                });
            }
            let Some(terminal) = active.next().await else {
                return Err(ActorGraphExecutionError::SchedulerInvariant {
                    pending: pending.iter().copied().collect(),
                });
            };
            apply_terminal(
                terminal?,
                &mut handoffs,
                &mut failures,
                &mut terminal_event_ids,
                &mut cleanup_unproven,
            );
        }

        let outcome = if failures.is_empty() && handoffs.len() == orders.len() {
            ActorGraphOutcome::Completed
        } else {
            ActorGraphOutcome::Failed
        };
        let terminal_parent = terminal_event_ids.values().next().copied().unwrap_or(root);
        let finished_event_id = self.retain(
            Some(terminal_parent),
            SchedulerEvent::GraphFinished {
                outcome,
                terminal_event_ids: terminal_event_ids.clone(),
            },
        )?;
        Ok(ActorGraphRun {
            graph_sha256: graph.digest_sha256.clone(),
            accepted_event_id: root,
            finished_event_id,
            terminal_event_ids,
            outcome,
            handoffs: handoffs
                .into_iter()
                .map(|(id, handoff)| (id, (*handoff).clone()))
                .collect(),
            failures,
            maximum_in_flight,
        })
    }

    fn retain(
        &self,
        causal_parent: Option<SchedulerEventId>,
        event: SchedulerEvent,
    ) -> Result<SchedulerEventId, SchedulerJournalError> {
        retain(self.journal, causal_parent, event)
    }
}

fn apply_terminal(
    terminal: WorkOrderTerminal,
    handoffs: &mut BTreeMap<WorkOrderId, Arc<Handoff>>,
    failures: &mut BTreeMap<WorkOrderId, WorkOrderFailure>,
    terminal_event_ids: &mut BTreeMap<WorkOrderId, SchedulerEventId>,
    cleanup_unproven: &mut BTreeSet<WorkOrderId>,
) {
    match terminal {
        WorkOrderTerminal::Handoff(handoff) => {
            let work_order_id = handoff.work_order_id;
            terminal_event_ids.insert(work_order_id, handoff.retained_event_id);
            if handoff.outcome != HandoffOutcome::Completed {
                failures.insert(
                    work_order_id,
                    WorkOrderFailure::IncompleteHandoff {
                        outcome: handoff.outcome,
                    },
                );
            }
            handoffs.insert(work_order_id, handoff);
        }
        WorkOrderTerminal::Failed {
            work_order_id,
            failure,
            terminal_event_id,
        } => {
            if matches!(*failure, WorkOrderFailure::CleanupUnproven { .. }) {
                cleanup_unproven.insert(work_order_id);
            }
            failures.insert(work_order_id, *failure);
            terminal_event_ids.insert(work_order_id, terminal_event_id);
        }
    }
}

enum WorkOrderTerminal {
    Handoff(Arc<Handoff>),
    Failed {
        work_order_id: WorkOrderId,
        failure: Box<WorkOrderFailure>,
        terminal_event_id: SchedulerEventId,
    },
}

#[allow(clippy::too_many_lines)]
async fn run_work_order<W, J>(
    worker: &W,
    journal: &J,
    root_event: SchedulerEventId,
    graph_sha256: String,
    require_reported_token_usage: bool,
    work_order: Arc<WorkOrder>,
    dependency_handoffs: BTreeMap<WorkOrderId, Arc<Handoff>>,
) -> Result<WorkOrderTerminal, SchedulerJournalError>
where
    W: AgentWorker + ?Sized,
    J: SchedulerJournal + ?Sized,
{
    let actor_id = ActorId::new();
    let execution_id = ExecutionId::new();
    let mut parent_attempt_id = None;
    let dependency_handoff_event_ids = dependency_handoffs
        .iter()
        .map(|(work_order_id, handoff)| (*work_order_id, handoff.retained_event_id))
        .collect::<BTreeMap<_, _>>();
    let mut causal_parent = dependency_handoff_event_ids
        .values()
        .next()
        .copied()
        .unwrap_or(root_event);
    let attestation = dispatch_attestation(&graph_sha256, &work_order)?;

    for attempt_number in 0..work_order.budget.max_attempts {
        let attempt_id = AttemptId::new();
        let dispatched = retain(
            journal,
            Some(causal_parent),
            SchedulerEvent::AttemptDispatched {
                work_order_id: work_order.id,
                actor_id,
                execution_id,
                attempt_id,
                parent_attempt_id,
                graph_accepted_event_id: root_event,
                attestation: Box::new(attestation.clone()),
                dependency_handoff_event_ids: dependency_handoff_event_ids.clone(),
            },
        )?;
        let dispatch = AgentDispatch {
            actor_id,
            execution_id,
            attempt_id,
            parent_attempt_id,
            graph_accepted_event_id: root_event,
            graph_sha256: graph_sha256.clone(),
            attestation: attestation.clone(),
            work_order: Arc::clone(&work_order),
            dependency_handoffs: dependency_handoffs.clone(),
            dependency_handoff_event_ids: dependency_handoff_event_ids.clone(),
        };
        let timed_out_attempt = TimedOutAttempt {
            actor_id,
            execution_id,
            attempt_id,
            attestation: attestation.clone(),
        };
        let result = tokio::time::timeout(
            Duration::from_millis(work_order.budget.max_wall_time_ms),
            worker.execute(dispatch),
        )
        .await;
        match result {
            Ok(Ok(completion)) => {
                let handoff_violations = handoff_violations(&completion);
                let usage_violation = usage_violation(
                    completion.usage,
                    work_order.budget,
                    require_reported_token_usage,
                );
                if !handoff_violations.is_empty() {
                    let failure = WorkOrderFailure::InvalidHandoff {
                        violations: handoff_violations,
                        usage_violation,
                        observation: completion_observation(&completion)?,
                    };
                    let terminal_event_id = retain(
                        journal,
                        Some(dispatched),
                        SchedulerEvent::AttemptFailed {
                            work_order_id: work_order.id,
                            execution_id,
                            attempt_id,
                            failure: failure.clone(),
                            will_retry: false,
                        },
                    )?;
                    return Ok(WorkOrderTerminal::Failed {
                        work_order_id: work_order.id,
                        failure: Box::new(failure),
                        terminal_event_id,
                    });
                }
                if let Some(violation) = usage_violation {
                    let failure = WorkOrderFailure::UsageViolation { violation };
                    let terminal_event_id = retain(
                        journal,
                        Some(dispatched),
                        SchedulerEvent::AttemptFailed {
                            work_order_id: work_order.id,
                            execution_id,
                            attempt_id,
                            failure: failure.clone(),
                            will_retry: false,
                        },
                    )?;
                    return Ok(WorkOrderTerminal::Failed {
                        work_order_id: work_order.id,
                        failure: Box::new(failure),
                        terminal_event_id,
                    });
                }
                let retained_event_id = SchedulerEventId::new();
                let handoff = Handoff {
                    id: HandoffId::new(),
                    retained_event_id,
                    work_order_id: work_order.id,
                    actor_id,
                    execution_id,
                    attempt_id,
                    outcome: completion.outcome,
                    summary: completion.summary,
                    execution_receipt_id: completion.execution_receipt_id,
                    artifact_sha256: completion.artifact_sha256,
                    evidence_ids: completion.evidence_ids,
                    usage: completion.usage,
                };
                retain_with_id(
                    journal,
                    retained_event_id,
                    Some(dispatched),
                    SchedulerEvent::HandoffRetained {
                        handoff: handoff.clone(),
                    },
                )?;
                return Ok(WorkOrderTerminal::Handoff(Arc::new(handoff)));
            }
            Ok(Err(worker_failure)) => {
                let contract_violations = worker_failure_violations(&worker_failure);
                let usage_violation =
                    usage_violation(worker_failure.usage, work_order.budget, false);
                if !contract_violations.is_empty() {
                    let failure = WorkOrderFailure::InvalidWorkerFailure {
                        violations: contract_violations,
                        usage_violation,
                        observation: failure_observation(&worker_failure)?,
                    };
                    let terminal_event_id = retain(
                        journal,
                        Some(dispatched),
                        SchedulerEvent::AttemptFailed {
                            work_order_id: work_order.id,
                            execution_id,
                            attempt_id,
                            failure: failure.clone(),
                            will_retry: false,
                        },
                    )?;
                    return Ok(WorkOrderTerminal::Failed {
                        work_order_id: work_order.id,
                        failure: Box::new(failure),
                        terminal_event_id,
                    });
                }
                let usage_failure =
                    usage_violation.map(|violation| WorkOrderFailure::UsageViolation { violation });
                let retryable = usage_failure.is_none()
                    && worker_failure.is_retryable()
                    && attempt_number + 1 < work_order.budget.max_attempts;
                let failure = usage_failure.unwrap_or(WorkOrderFailure::Worker {
                    failure: worker_failure,
                });
                let failed = retain(
                    journal,
                    Some(dispatched),
                    SchedulerEvent::AttemptFailed {
                        work_order_id: work_order.id,
                        execution_id,
                        attempt_id,
                        failure: failure.clone(),
                        will_retry: retryable,
                    },
                )?;
                if !retryable {
                    return Ok(WorkOrderTerminal::Failed {
                        work_order_id: work_order.id,
                        failure: Box::new(failure),
                        terminal_event_id: failed,
                    });
                }
                parent_attempt_id = Some(attempt_id);
                causal_parent = failed;
            }
            Err(_) => {
                let cleanup = tokio::time::timeout(
                    Duration::from_millis(work_order.budget.max_cleanup_time_ms),
                    worker.cancel_and_cleanup(timed_out_attempt),
                )
                .await;
                let failure = match cleanup {
                    Ok(Some(receipt)) if bounded_receipt(&receipt.cleanup_receipt_id).is_some() => {
                        WorkOrderFailure::DeadlineExceeded {
                            maximum_ms: work_order.budget.max_wall_time_ms,
                            cleanup_receipt_id: receipt.cleanup_receipt_id,
                        }
                    }
                    Ok(Some(_) | None) | Err(_) => WorkOrderFailure::CleanupUnproven {
                        maximum_ms: work_order.budget.max_wall_time_ms,
                        cleanup_maximum_ms: work_order.budget.max_cleanup_time_ms,
                    },
                };
                let terminal_event_id = retain(
                    journal,
                    Some(dispatched),
                    SchedulerEvent::AttemptFailed {
                        work_order_id: work_order.id,
                        execution_id,
                        attempt_id,
                        failure: failure.clone(),
                        will_retry: false,
                    },
                )?;
                return Ok(WorkOrderTerminal::Failed {
                    work_order_id: work_order.id,
                    failure: Box::new(failure),
                    terminal_event_id,
                });
            }
        }
    }
    unreachable!("validated work order has at least one attempt")
}

fn dispatch_attestation(
    graph_sha256: &str,
    work_order: &WorkOrder,
) -> Result<DispatchAttestation, SchedulerJournalError> {
    let work_order_sha256 = canonical_json_digest(work_order).map_err(|error| {
        SchedulerJournalError::new(format!("work order attestation failed: {error}"))
    })?;
    let permissions_sha256 = canonical_json_digest(&work_order.permissions).map_err(|error| {
        SchedulerJournalError::new(format!("permission attestation failed: {error}"))
    })?;
    Ok(DispatchAttestation {
        graph_sha256: graph_sha256.to_owned(),
        work_order_sha256,
        permissions_sha256,
        assignment: work_order.assignment.clone(),
        context_manifest_sha256: work_order.context_manifest_sha256.clone(),
        workspace: work_order.workspace.clone(),
        budget: work_order.budget,
    })
}

fn completion_observation(
    completion: &AgentCompletion,
) -> Result<AttemptObservation, SchedulerJournalError> {
    Ok(AttemptObservation {
        execution_receipt_id: bounded_receipt(&completion.execution_receipt_id),
        effect_receipt_id: None,
        usage: completion.usage,
        payload_sha256: canonical_json_digest(completion).map_err(|error| {
            SchedulerJournalError::new(format!("completion observation failed: {error}"))
        })?,
    })
}

fn failure_observation(
    failure: &AgentFailure,
) -> Result<AttemptObservation, SchedulerJournalError> {
    Ok(AttemptObservation {
        execution_receipt_id: bounded_receipt(&failure.execution_receipt_id),
        effect_receipt_id: failure
            .effect_receipt_id
            .as_deref()
            .and_then(bounded_receipt),
        usage: failure.usage,
        payload_sha256: canonical_json_digest(failure).map_err(|error| {
            SchedulerJournalError::new(format!("failure observation failed: {error}"))
        })?,
    })
}

fn bounded_receipt(receipt: &str) -> Option<String> {
    (!receipt.is_empty() && receipt.len() <= MAX_EVIDENCE_ID_BYTES).then(|| receipt.to_owned())
}

fn retain<J: SchedulerJournal + ?Sized>(
    journal: &J,
    causal_parent: Option<SchedulerEventId>,
    event: SchedulerEvent,
) -> Result<SchedulerEventId, SchedulerJournalError> {
    let id = SchedulerEventId::new();
    retain_with_id(journal, id, causal_parent, event)?;
    Ok(id)
}

fn retain_with_id<J: SchedulerJournal + ?Sized>(
    journal: &J,
    id: SchedulerEventId,
    causal_parent: Option<SchedulerEventId>,
    event: SchedulerEvent,
) -> Result<(), SchedulerJournalError> {
    journal.retain(&SchedulerRecord {
        id,
        causal_parent,
        event,
    })
}

fn usage_violation(
    usage: Usage,
    budget: AgentBudget,
    require_reported_token_usage: bool,
) -> Option<ActorGraphViolation> {
    if require_reported_token_usage && usage.output_tokens.is_none() {
        return Some(ActorGraphViolation::MissingOutputTokenUsage);
    }
    if let Some(actual) = usage.output_tokens
        && actual > budget.max_output_tokens
    {
        return Some(ActorGraphViolation::OutputTokenBudgetExceeded {
            maximum: budget.max_output_tokens,
            actual,
        });
    }
    (usage.tool_calls > budget.max_tool_calls).then_some(
        ActorGraphViolation::ToolCallBudgetExceeded {
            maximum: budget.max_tool_calls,
            actual: usage.tool_calls,
        },
    )
}

fn handoff_violations(completion: &AgentCompletion) -> Vec<HandoffViolation> {
    let mut violations = Vec::new();
    if completion.summary.trim().is_empty() {
        violations.push(HandoffViolation::EmptySummary);
    }
    if completion.execution_receipt_id.is_empty()
        || completion.execution_receipt_id.len() > MAX_EVIDENCE_ID_BYTES
    {
        violations.push(HandoffViolation::InvalidExecutionReceipt);
    }
    if completion.summary.len() > MAX_HANDOFF_SUMMARY_BYTES {
        violations.push(HandoffViolation::SummaryTooLarge {
            maximum: MAX_HANDOFF_SUMMARY_BYTES,
            actual: completion.summary.len(),
        });
    }
    if completion.artifact_sha256.len() > MAX_HANDOFF_REFERENCES {
        violations.push(HandoffViolation::ArtifactReferenceLimitExceeded {
            maximum: MAX_HANDOFF_REFERENCES,
            actual: completion.artifact_sha256.len(),
        });
    }
    let mut artifacts = BTreeSet::new();
    for (index, digest) in completion.artifact_sha256.iter().enumerate() {
        if !valid_sha256(digest) {
            violations.push(HandoffViolation::InvalidArtifactDigest { index });
        }
        if !artifacts.insert(digest) {
            violations.push(HandoffViolation::DuplicateArtifactDigest);
        }
    }
    if completion.outcome == HandoffOutcome::Completed && completion.evidence_ids.is_empty() {
        violations.push(HandoffViolation::MissingCompletionEvidence);
    }
    if completion.evidence_ids.len() > MAX_HANDOFF_REFERENCES {
        violations.push(HandoffViolation::EvidenceReferenceLimitExceeded {
            maximum: MAX_HANDOFF_REFERENCES,
            actual: completion.evidence_ids.len(),
        });
    }
    let mut evidence = BTreeSet::new();
    for (index, evidence_id) in completion.evidence_ids.iter().enumerate() {
        if evidence_id.is_empty() || evidence_id.len() > MAX_EVIDENCE_ID_BYTES {
            violations.push(HandoffViolation::InvalidEvidenceId { index });
        }
        if !evidence.insert(evidence_id) {
            violations.push(HandoffViolation::DuplicateEvidenceId);
        }
    }
    violations
}

fn worker_failure_violations(failure: &AgentFailure) -> Vec<AgentFailureViolation> {
    let mut violations = Vec::new();
    if failure.message.trim().is_empty() {
        violations.push(AgentFailureViolation::EmptyMessage);
    }
    if failure.message.len() > MAX_FAILURE_MESSAGE_BYTES {
        violations.push(AgentFailureViolation::MessageTooLarge {
            maximum: MAX_FAILURE_MESSAGE_BYTES,
            actual: failure.message.len(),
        });
    }
    if failure.execution_receipt_id.is_empty()
        || failure.execution_receipt_id.len() > MAX_EVIDENCE_ID_BYTES
    {
        violations.push(AgentFailureViolation::InvalidExecutionReceipt);
    }
    if failure
        .effect_receipt_id
        .as_ref()
        .is_some_and(|receipt| receipt.is_empty() || receipt.len() > MAX_EVIDENCE_ID_BYTES)
    {
        violations.push(AgentFailureViolation::InvalidEffectReceipt);
    }
    if matches!(failure.kind, AgentFailureKind::RetryableNoEffect) && !failure.is_retryable() {
        violations.push(AgentFailureViolation::MissingNoEffectReceipt);
    }
    violations
}

/// Rejects hostile collection shapes before sorting, hashing, graph traversal,
/// or any collect-all semantic validation. Transport adapters must additionally
/// cap encoded request bytes before deserialization.
fn structural_limit_violations(
    graph: &ActorGraph,
    policy: &ActorGraphPolicy,
) -> Vec<ActorGraphViolation> {
    let mut violations = Vec::new();
    if graph.work_orders.len() > HARD_MAX_WORK_ORDERS {
        violations.push(ActorGraphViolation::HardWorkOrderLimitExceeded {
            maximum: HARD_MAX_WORK_ORDERS,
            actual: graph.work_orders.len(),
        });
    }
    if policy.workspace_leases.len() > HARD_MAX_POLICY_LEASES {
        violations.push(ActorGraphViolation::PolicyWorkspaceLeaseLimitExceeded {
            maximum: HARD_MAX_POLICY_LEASES,
            actual: policy.workspace_leases.len(),
        });
    }
    if policy.model_profiles.len() > HARD_MAX_MODEL_PROFILES {
        violations.push(ActorGraphViolation::PolicyModelProfileLimitExceeded {
            maximum: HARD_MAX_MODEL_PROFILES,
            actual: policy.model_profiles.len(),
        });
    }
    if policy.root_permissions.capabilities.len() > HARD_MAX_CAPABILITIES {
        violations.push(ActorGraphViolation::RootCapabilityLimitExceeded {
            maximum: HARD_MAX_CAPABILITIES,
            actual: policy.root_permissions.capabilities.len(),
        });
    }

    if graph.work_orders.len() <= HARD_MAX_WORK_ORDERS {
        let mut total_capability_references = policy.root_permissions.capabilities.len();
        for order in &graph.work_orders {
            if order.acceptance_criteria.len() > MAX_ACCEPTANCE_CRITERIA {
                violations.push(ActorGraphViolation::AcceptanceCriteriaLimitExceeded {
                    work_order_id: order.id,
                    maximum: MAX_ACCEPTANCE_CRITERIA,
                    actual: order.acceptance_criteria.len(),
                });
            }
            if order.dependencies.len() > HARD_MAX_DEPENDENCIES {
                violations.push(ActorGraphViolation::DependencyLimitExceeded {
                    work_order_id: order.id,
                    maximum: HARD_MAX_DEPENDENCIES,
                    actual: order.dependencies.len(),
                });
            }
            if order.reviews.len() > HARD_MAX_REVIEWS {
                violations.push(ActorGraphViolation::ReviewLimitExceeded {
                    work_order_id: order.id,
                    maximum: HARD_MAX_REVIEWS,
                    actual: order.reviews.len(),
                });
            }
            if order.permissions.capabilities.len() > HARD_MAX_CAPABILITIES {
                violations.push(ActorGraphViolation::CapabilityLimitExceeded {
                    work_order_id: order.id,
                    maximum: HARD_MAX_CAPABILITIES,
                    actual: order.permissions.capabilities.len(),
                });
            }
            total_capability_references =
                total_capability_references.saturating_add(order.permissions.capabilities.len());
        }
        if total_capability_references > HARD_MAX_TOTAL_CAPABILITY_REFERENCES {
            violations.push(ActorGraphViolation::TotalCapabilityReferenceLimitExceeded {
                maximum: HARD_MAX_TOTAL_CAPABILITY_REFERENCES,
                actual: total_capability_references,
            });
        }
    }
    violations
}

#[allow(clippy::too_many_lines)]
fn graph_violations(graph: &ActorGraph, policy: &ActorGraphPolicy) -> Vec<ActorGraphViolation> {
    let mut violations = Vec::new();
    if graph.schema_version != ACTOR_GRAPH_SCHEMA_VERSION {
        violations.push(ActorGraphViolation::UnsupportedSchemaVersion {
            actual: graph.schema_version,
        });
    }
    if policy.policy_version.trim().is_empty() {
        violations.push(ActorGraphViolation::EmptyPolicyVersion);
    }
    if policy.policy_version.len() > MAX_ASSIGNMENT_ID_BYTES {
        violations.push(ActorGraphViolation::PolicyVersionTooLarge {
            maximum: MAX_ASSIGNMENT_ID_BYTES,
            actual: policy.policy_version.len(),
        });
    }
    if policy.workspace_leases.len() > HARD_MAX_POLICY_LEASES {
        violations.push(ActorGraphViolation::PolicyWorkspaceLeaseLimitExceeded {
            maximum: HARD_MAX_POLICY_LEASES,
            actual: policy.workspace_leases.len(),
        });
    }
    if policy.model_profiles.len() > HARD_MAX_MODEL_PROFILES {
        violations.push(ActorGraphViolation::PolicyModelProfileLimitExceeded {
            maximum: HARD_MAX_MODEL_PROFILES,
            actual: policy.model_profiles.len(),
        });
    }
    if policy.root_permissions.capabilities.len() > HARD_MAX_CAPABILITIES {
        violations.push(ActorGraphViolation::RootCapabilityLimitExceeded {
            maximum: HARD_MAX_CAPABILITIES,
            actual: policy.root_permissions.capabilities.len(),
        });
    }
    for (lease_id, lease) in &policy.workspace_leases {
        if !valid_sha256(lease.source.digest_sha256())
            || (lease.access == WorkspaceAccess::Write && !lease.source.supports_write())
        {
            violations.push(ActorGraphViolation::InvalidWorkspaceLeasePolicy {
                lease_id: lease_id.clone(),
            });
        }
    }
    for (model_profile_id, lineage) in &policy.model_profiles {
        if !valid_lineage(lineage) {
            violations.push(ActorGraphViolation::InvalidModelProfilePolicy {
                model_profile_id: model_profile_id.clone(),
            });
        }
    }
    if !valid_sha256(&policy.plan_input_snapshot_sha256) {
        violations.push(ActorGraphViolation::InvalidPolicySnapshotDigest);
    }
    if !valid_sha256(&graph.plan_input_snapshot_sha256) {
        violations.push(ActorGraphViolation::InvalidSnapshotDigest);
    }
    if graph.plan_input_snapshot_sha256 != policy.plan_input_snapshot_sha256 {
        violations.push(ActorGraphViolation::RootSnapshotMismatch);
    }
    if graph.work_orders.is_empty() {
        violations.push(ActorGraphViolation::EmptyGraph);
    }
    if graph.work_orders.len()
        > usize::try_from(policy.limits.max_work_orders).unwrap_or(usize::MAX)
    {
        violations.push(ActorGraphViolation::WorkOrderLimitExceeded {
            maximum: policy.limits.max_work_orders,
            actual: graph.work_orders.len(),
        });
    }
    if graph.work_orders.len() > HARD_MAX_WORK_ORDERS {
        violations.push(ActorGraphViolation::HardWorkOrderLimitExceeded {
            maximum: HARD_MAX_WORK_ORDERS,
            actual: graph.work_orders.len(),
        });
    }
    if policy.limits.max_parallel == 0 {
        violations.push(ActorGraphViolation::InvalidParallelLimit);
    }

    let mut orders = BTreeMap::new();
    let mut lease_uses: BTreeMap<WorkspaceLeaseId, (usize, bool)> = BTreeMap::new();
    let mut total_attempts = 0_u64;
    let mut total_output_tokens = 0_u64;
    let mut total_tool_calls = 0_u64;
    let mut total_wall_time_ms = 0_u64;
    let mut total_graph_text_bytes = 0_usize;
    let mut overflow = false;
    for order in &graph.work_orders {
        if orders.insert(order.id, order).is_some() {
            violations.push(ActorGraphViolation::DuplicateWorkOrder {
                work_order_id: order.id,
            });
        }
        if order.objective.trim().is_empty() {
            violations.push(ActorGraphViolation::EmptyObjective {
                work_order_id: order.id,
            });
        }
        if order.objective.len() > MAX_OBJECTIVE_BYTES {
            violations.push(ActorGraphViolation::ObjectiveTooLarge {
                work_order_id: order.id,
                maximum: MAX_OBJECTIVE_BYTES,
                actual: order.objective.len(),
            });
        }
        total_graph_text_bytes = total_graph_text_bytes.saturating_add(order.objective.len());
        if order.acceptance_criteria.is_empty()
            || order
                .acceptance_criteria
                .iter()
                .any(|criterion| criterion.trim().is_empty())
        {
            violations.push(ActorGraphViolation::EmptyAcceptanceCriteria {
                work_order_id: order.id,
            });
        }
        if order.acceptance_criteria.len() > MAX_ACCEPTANCE_CRITERIA {
            violations.push(ActorGraphViolation::AcceptanceCriteriaLimitExceeded {
                work_order_id: order.id,
                maximum: MAX_ACCEPTANCE_CRITERIA,
                actual: order.acceptance_criteria.len(),
            });
        }
        for (index, criterion) in order.acceptance_criteria.iter().enumerate() {
            total_graph_text_bytes = total_graph_text_bytes.saturating_add(criterion.len());
            if criterion.len() > MAX_ACCEPTANCE_CRITERION_BYTES {
                violations.push(ActorGraphViolation::AcceptanceCriterionTooLarge {
                    work_order_id: order.id,
                    index,
                    maximum: MAX_ACCEPTANCE_CRITERION_BYTES,
                    actual: criterion.len(),
                });
            }
        }
        for (field, value) in [
            ("backend_id", order.assignment.lineage.backend_id.as_str()),
            ("model_id", order.assignment.lineage.model_id.as_str()),
            (
                "deployment_id",
                order.assignment.lineage.deployment_id.as_str(),
            ),
            (
                "independence_domain_id",
                order.assignment.lineage.independence_domain_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() || value.len() > MAX_ASSIGNMENT_ID_BYTES {
                violations.push(ActorGraphViolation::InvalidAssignment {
                    work_order_id: order.id,
                    field: field.to_owned(),
                });
            }
        }
        match policy
            .model_profiles
            .get(&order.assignment.model_profile_id)
        {
            None => violations.push(ActorGraphViolation::UnknownModelProfile {
                work_order_id: order.id,
                model_profile_id: order.assignment.model_profile_id.clone(),
            }),
            Some(lineage) if lineage != &order.assignment.lineage => {
                violations.push(ActorGraphViolation::ModelLineageMismatch {
                    work_order_id: order.id,
                    model_profile_id: order.assignment.model_profile_id.clone(),
                });
            }
            Some(_) => {}
        }
        if !valid_sha256(&order.context_manifest_sha256) {
            violations.push(ActorGraphViolation::InvalidContextManifestDigest {
                work_order_id: order.id,
            });
        }
        if order.budget.max_attempts == 0
            || order.budget.max_wall_time_ms == 0
            || order.budget.max_cleanup_time_ms == 0
        {
            violations.push(ActorGraphViolation::InvalidBudget {
                work_order_id: order.id,
            });
        }
        if order.dependencies.len() > HARD_MAX_DEPENDENCIES {
            violations.push(ActorGraphViolation::DependencyLimitExceeded {
                work_order_id: order.id,
                maximum: HARD_MAX_DEPENDENCIES,
                actual: order.dependencies.len(),
            });
        }
        if order.reviews.len() > HARD_MAX_REVIEWS {
            violations.push(ActorGraphViolation::ReviewLimitExceeded {
                work_order_id: order.id,
                maximum: HARD_MAX_REVIEWS,
                actual: order.reviews.len(),
            });
        }
        if order.permissions.capabilities.len() > HARD_MAX_CAPABILITIES {
            violations.push(ActorGraphViolation::CapabilityLimitExceeded {
                work_order_id: order.id,
                maximum: HARD_MAX_CAPABILITIES,
                actual: order.permissions.capabilities.len(),
            });
        }
        if !order.permissions.is_subset_of(&policy.root_permissions) {
            violations.push(ActorGraphViolation::AuthorityExpansion {
                work_order_id: order.id,
            });
        }
        let workspace_source_is_valid = valid_sha256(order.workspace.source.digest_sha256());
        if !workspace_source_is_valid {
            violations.push(ActorGraphViolation::InvalidWorkspaceSourceDigest {
                work_order_id: order.id,
            });
        }
        match policy.workspace_leases.get(&order.workspace.lease_id) {
            None => violations.push(ActorGraphViolation::UnknownWorkspaceLease {
                work_order_id: order.id,
                lease_id: order.workspace.lease_id.clone(),
            }),
            Some(lease)
                if lease.source != order.workspace.source
                    || !lease.access.permits(order.workspace.access) =>
            {
                violations.push(ActorGraphViolation::WorkspaceLeaseMismatch {
                    work_order_id: order.id,
                    lease_id: order.workspace.lease_id.clone(),
                });
            }
            Some(_) => {}
        }
        let lease_use = lease_uses
            .entry(order.workspace.lease_id.clone())
            .or_insert((0, false));
        lease_use.0 += 1;
        lease_use.1 |= order.workspace.access == WorkspaceAccess::Write;
        if workspace_source_is_valid
            && order.workspace.access == WorkspaceAccess::Write
            && (!order.workspace.source.supports_write() || order.budget.max_attempts != 1)
        {
            violations.push(ActorGraphViolation::WorkspaceExecutionProfileUnsupported {
                work_order_id: order.id,
                source: order.workspace.source.clone(),
                access: order.workspace.access,
                max_attempts: order.budget.max_attempts,
            });
        }
        if !order.reviews.is_empty() && order.workspace.access == WorkspaceAccess::Write {
            violations.push(ActorGraphViolation::ReviewerHasWriteWorkspace {
                reviewer_id: order.id,
            });
        }
        let attempts = u64::from(order.budget.max_attempts);
        total_attempts = total_attempts.checked_add(attempts).unwrap_or_else(|| {
            overflow = true;
            u64::MAX
        });
        total_output_tokens = total_output_tokens
            .checked_add(
                order
                    .budget
                    .max_output_tokens
                    .checked_mul(attempts)
                    .unwrap_or_else(|| {
                        overflow = true;
                        u64::MAX
                    }),
            )
            .unwrap_or_else(|| {
                overflow = true;
                u64::MAX
            });
        total_tool_calls = total_tool_calls
            .checked_add(
                order
                    .budget
                    .max_tool_calls
                    .checked_mul(attempts)
                    .unwrap_or_else(|| {
                        overflow = true;
                        u64::MAX
                    }),
            )
            .unwrap_or_else(|| {
                overflow = true;
                u64::MAX
            });
        total_wall_time_ms = total_wall_time_ms
            .checked_add(
                order
                    .budget
                    .max_wall_time_ms
                    .checked_add(order.budget.max_cleanup_time_ms)
                    .unwrap_or_else(|| {
                        overflow = true;
                        u64::MAX
                    })
                    .checked_mul(attempts)
                    .unwrap_or_else(|| {
                        overflow = true;
                        u64::MAX
                    }),
            )
            .unwrap_or_else(|| {
                overflow = true;
                u64::MAX
            });
    }

    for (lease_id, (uses, has_writer)) in lease_uses {
        if uses > 1 && has_writer {
            violations.push(ActorGraphViolation::SharedWriterLease { lease_id });
        }
    }
    if total_graph_text_bytes > HARD_MAX_GRAPH_TEXT_BYTES {
        violations.push(ActorGraphViolation::GraphTextLimitExceeded {
            maximum: HARD_MAX_GRAPH_TEXT_BYTES,
            actual: total_graph_text_bytes,
        });
    }

    let reviewed_targets = graph
        .work_orders
        .iter()
        .flat_map(|order| order.reviews.iter().copied())
        .collect::<BTreeSet<_>>();
    for order in &graph.work_orders {
        for dependency in &order.dependencies {
            if *dependency == order.id {
                violations.push(ActorGraphViolation::SelfDependency {
                    work_order_id: order.id,
                });
            } else {
                match orders.get(dependency) {
                    None => violations.push(ActorGraphViolation::UnknownDependency {
                        work_order_id: order.id,
                        dependency_id: *dependency,
                    }),
                    Some(review_order) if !review_order.reviews.is_empty() => {
                        violations.push(ActorGraphViolation::UngatedReviewDependency {
                            downstream_id: order.id,
                            reviewer_id: *dependency,
                        });
                    }
                    Some(_) => {}
                }
                if reviewed_targets.contains(dependency) && !order.reviews.contains(dependency) {
                    violations.push(ActorGraphViolation::UngatedReviewedTargetDependency {
                        downstream_id: order.id,
                        target_id: *dependency,
                    });
                }
            }
        }
        for target in &order.reviews {
            let Some(producer) = orders.get(target) else {
                violations.push(ActorGraphViolation::UnknownReviewTarget {
                    reviewer_id: order.id,
                    target_id: *target,
                });
                continue;
            };
            if !order.dependencies.contains(target) {
                violations.push(ActorGraphViolation::ReviewMissingDependency {
                    reviewer_id: order.id,
                    target_id: *target,
                });
            }
            if order.assignment.lineage.independence_domain_id
                == producer.assignment.lineage.independence_domain_id
            {
                violations.push(ActorGraphViolation::ReviewerLineageConflict {
                    reviewer_id: order.id,
                    target_id: *target,
                });
            }
        }
    }

    let mut candidate_groups: BTreeMap<&CandidateGroupId, Vec<&WorkOrder>> = BTreeMap::new();
    for order in &graph.work_orders {
        if let Some(group) = &order.candidate_group {
            candidate_groups.entry(group).or_default().push(order);
        }
    }
    for (group, candidates) in candidate_groups {
        let Some(first) = candidates.first() else {
            continue;
        };
        if candidates.len() < 2 {
            violations.push(ActorGraphViolation::CandidateGroupTooSmall {
                candidate_group_id: group.clone(),
                actual: candidates.len(),
            });
        }
        let peer_ids = candidates
            .iter()
            .map(|candidate| candidate.id)
            .collect::<BTreeSet<_>>();
        let mut leases = BTreeSet::new();
        for candidate in &candidates {
            for peer_id in peer_ids.iter().filter(|peer_id| **peer_id != candidate.id) {
                if dependency_reachable(candidate.id, *peer_id, &orders) {
                    violations.push(ActorGraphViolation::CandidateDependency {
                        candidate_group_id: group.clone(),
                        work_order_id: candidate.id,
                        dependency_id: *peer_id,
                    });
                }
            }
            if candidate.workspace.source != first.workspace.source {
                violations.push(ActorGraphViolation::CandidateSnapshotMismatch {
                    candidate_group_id: group.clone(),
                });
            }
            if candidate.objective != first.objective
                || candidate.acceptance_criteria != first.acceptance_criteria
                || candidate.budget != first.budget
                || candidate.context_manifest_sha256 != first.context_manifest_sha256
                || candidate.permissions != first.permissions
                || candidate.workspace.access != first.workspace.access
                || candidate.dependencies != first.dependencies
                || candidate.reviews != first.reviews
            {
                violations.push(ActorGraphViolation::CandidateContractMismatch {
                    candidate_group_id: group.clone(),
                });
            }
            if !leases.insert(candidate.workspace.lease_id.clone()) {
                violations.push(ActorGraphViolation::CandidateSharedWorkspaceLease {
                    candidate_group_id: group.clone(),
                    lease_id: candidate.workspace.lease_id.clone(),
                });
            }
        }
    }

    if let Some(cycle) = dependency_cycle(&orders) {
        violations.push(ActorGraphViolation::DependencyCycle {
            work_order_ids: cycle,
        });
    }
    if overflow {
        violations.push(ActorGraphViolation::BudgetOverflow);
    }
    if total_attempts > policy.limits.max_total_attempts {
        violations.push(ActorGraphViolation::AttemptBudgetExceeded {
            maximum: policy.limits.max_total_attempts,
            actual: total_attempts,
        });
    }
    if total_output_tokens > policy.limits.max_total_output_tokens {
        violations.push(ActorGraphViolation::OutputTokenBudgetExceeded {
            maximum: policy.limits.max_total_output_tokens,
            actual: total_output_tokens,
        });
    }
    if total_tool_calls > policy.limits.max_total_tool_calls {
        violations.push(ActorGraphViolation::ToolCallBudgetExceeded {
            maximum: policy.limits.max_total_tool_calls,
            actual: total_tool_calls,
        });
    }
    if total_wall_time_ms > policy.limits.max_total_wall_time_ms {
        violations.push(ActorGraphViolation::WallTimeBudgetExceeded {
            maximum_ms: policy.limits.max_total_wall_time_ms,
            actual_ms: total_wall_time_ms,
        });
    }
    violations
}

fn dependency_reachable(
    from: WorkOrderId,
    target: WorkOrderId,
    orders: &BTreeMap<WorkOrderId, &WorkOrder>,
) -> bool {
    let mut pending = vec![from];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        let Some(order) = orders.get(&current) else {
            continue;
        };
        for dependency in &order.dependencies {
            if *dependency == target {
                return true;
            }
            if orders.contains_key(dependency) {
                pending.push(*dependency);
            }
        }
    }
    false
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DependencyVisit {
    Visiting,
    Visited,
}

fn dependency_cycle(orders: &BTreeMap<WorkOrderId, &WorkOrder>) -> Option<Vec<WorkOrderId>> {
    fn visit(
        id: WorkOrderId,
        orders: &BTreeMap<WorkOrderId, &WorkOrder>,
        states: &mut BTreeMap<WorkOrderId, DependencyVisit>,
        stack: &mut Vec<WorkOrderId>,
    ) -> Option<Vec<WorkOrderId>> {
        states.insert(id, DependencyVisit::Visiting);
        stack.push(id);
        for dependency in &orders[&id].dependencies {
            if !orders.contains_key(dependency) {
                continue;
            }
            match states.get(dependency) {
                Some(DependencyVisit::Visiting) => {
                    let start = stack.iter().position(|entry| entry == dependency)?;
                    return Some(stack[start..].to_vec());
                }
                Some(DependencyVisit::Visited) => {}
                None => {
                    if let Some(cycle) = visit(*dependency, orders, states, stack) {
                        return Some(cycle);
                    }
                }
            }
        }
        stack.pop();
        states.insert(id, DependencyVisit::Visited);
        None
    }

    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    for id in orders.keys() {
        if !states.contains_key(id)
            && let Some(cycle) = visit(*id, orders, &mut states, &mut stack)
        {
            return Some(cycle);
        }
    }
    None
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_lineage(lineage: &ModelLineage) -> bool {
    [
        lineage.backend_id.as_str(),
        lineage.model_id.as_str(),
        lineage.deployment_id.as_str(),
        lineage.independence_domain_id.as_str(),
    ]
    .into_iter()
    .all(|value| !value.trim().is_empty() && value.len() <= MAX_ASSIGNMENT_ID_BYTES)
}

struct DigestWriter(Sha256);

impl DigestWriter {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn finish(self) -> String {
        encode_digest(self.0.finalize())
    }
}

impl io::Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_json_digest(value: &impl Serialize) -> Result<String, serde_json::Error> {
    let mut writer = DigestWriter::new();
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.finish())
}

fn encode_digest(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = digest.as_ref();
    let mut output = String::with_capacity(64);
    for byte in digest.iter().copied() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
