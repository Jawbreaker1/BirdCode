//! Versioned semantic planner/replanner contract for initial delegation and
//! evidence-driven replanning.
//!
//! This module is additive to the frozen v1 prompt. It keeps semantic choices
//! in one structured model output while mechanically binding every authority,
//! evidence, inference, and budget input. Deterministic code validates shape,
//! identity, provenance, and content addresses only; it never classifies prose.

use crate::compiler::{
    DataProvenance, DataSection, PromptInvocation, PromptLimits, RuntimeConstraint, SourceKind,
    TrustLevel,
};
use crate::planner_replanner::{
    PlannerChildExecutionBinding, PlannerChildHandoff, PlannerEvidenceArtifactRef,
    PlannerEvidenceEntry, PlannerEvidenceEntryMaterial, PlannerEvidencePacketViolation,
    PlannerReplannerBindings, PlannerReplannerDecisionBasis, PlannerReplannerDirectiveKind,
    PlannerReplannerOutput,
};
use crate::root_planner::{RootPlannerDirective, RootPlannerOutput};
use crate::{PromptId, PromptKey};
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const PLANNER_REPLANNER_V2_ID: &str = "birdcode.planner-replanner-v2";
const BASE_PLAN_SECTION: &str = "base_plan";
const OBLIGATION_CATALOG_SECTION: &str = "protected_obligation_catalog";
const CONTEXT_CATALOG_SECTION: &str = "planner_context_catalog";
const EVIDENCE_PACKET_SECTION: &str = "planner_evidence_packet";
const POLICY_CONSTRAINT: &str = "planner_policy";
const BINDINGS_CONSTRAINT: &str = "planner_turn_bindings";
const EVIDENCE_DELTA_CONSTRAINT: &str = "planner_turn_evidence_delta";
const EVIDENCE_PACKET_SCHEMA_VERSION: u32 = 2;
pub const PLANNER_REPLANNER_V2_SOURCE_CONTRACT_VERSION: u32 = 1;
const MAX_EVIDENCE_PACKET_ENTRIES: usize = 256;
const MAX_EVIDENCE_PACKET_BYTES: usize = 1024 * 1024;
const MAX_EVIDENCE_ID_BYTES: usize = 512;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_BACKEND_ENDPOINT_ORIGIN_BYTES: usize = 2_048;
const MAX_MEDIA_TYPE_BYTES: usize = 256;
const ACCEPTED_PLAN_MEDIA_TYPE: &str = "application/vnd.birdcode.accepted-plan+json";
const PLAN_CRITIQUE_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-critique+json";
const PLAN_VALIDATION_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-validation+json";
const CHILD_HANDOFF_MEDIA_TYPE: &str = "application/vnd.birdcode.child-handoff+json";
const CHILD_EXECUTION_FAILURE_MEDIA_TYPE: &str =
    "application/vnd.birdcode.child-execution-failure.v1+json";
/// Hard provider-output ceiling accepted by the planner/replanner v2 binding.
/// Runtime admission and request construction use this same mechanical bound.
pub const PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS: u32 = 16_384;
const MAX_WORK_ORDERS: usize = 256;
const MAX_VERIFICATION_TARGETS: usize = 512;
const MAX_DEPENDENCIES: usize = 64;
const MAX_OBLIGATIONS: usize = 4_096;
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_FAILURE_DIAGNOSTIC_BYTES: usize = 64 * 1024;

/// The semantic purpose of one v2 planner turn.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReplannerV2Purpose {
    /// Decide the next directive from one exact accepted root plan.
    InitialDelegation,
    /// Replan from one or more exact terminal child outcomes.
    EvidenceReplan,
}

/// Provider-neutral reasoning setting bound before inference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReplannerV2Reasoning {
    Off,
    On,
    Low,
    Medium,
    High,
}

/// Exact echo bindings for one v2 model request.
///
/// Backend instance fields are runtime-configured request-routing identities.
/// They attest exact configured dispatch equivalence only, not model weights,
/// physical infrastructure, or semantic-review independence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2Bindings {
    pub purpose: PlannerReplannerV2Purpose,
    pub prompt_id: String,
    pub prompt_version: String,
    pub prompt_manifest_sha256: String,
    pub plan_id: String,
    pub base_revision: u64,
    pub base_plan_sha256: String,
    pub obligation_snapshot_sha256: String,
    pub acceptance_policy_sha256: String,
    pub context_manifest_sha256: String,
    pub planner_policy_sha256: String,
    pub evidence_packet_sha256: String,
    pub previous_evidence_packet_sha256: Option<String>,
    pub evidence_delta_sha256: String,
    pub backend_id: String,
    pub backend_configured_deployment_id: String,
    pub backend_endpoint_origin: String,
    pub backend_instance_sha256: String,
    pub model_id: String,
    pub reasoning: Option<PlannerReplannerV2Reasoning>,
    pub budget_reservation_id: String,
    pub max_output_tokens: u32,
}

impl PlannerReplannerV2Bindings {
    /// Returns the exact v1-shaped binding DTO consumed by the authoritative
    /// orchestrator proposal domain.
    #[must_use]
    pub fn authoritative_bindings(&self) -> PlannerReplannerBindings {
        PlannerReplannerBindings {
            plan_id: self.plan_id.clone(),
            base_revision: self.base_revision,
            base_plan_sha256: self.base_plan_sha256.clone(),
            obligation_snapshot_sha256: self.obligation_snapshot_sha256.clone(),
            acceptance_policy_sha256: self.acceptance_policy_sha256.clone(),
            context_manifest_sha256: self.context_manifest_sha256.clone(),
            planner_policy_sha256: self.planner_policy_sha256.clone(),
        }
    }
}

/// Frozen prompt projection of one authoritative verification target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2VerificationTarget {
    pub id: String,
    pub statement: String,
    pub obligations: BTreeSet<crate::planner_replanner::PlannerReplannerObligationRef>,
    pub basis: PlannerReplannerDecisionBasis,
}

/// Frozen prompt projection of the authoritative work-order state vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReplannerV2PlannedWorkOrderState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Frozen prompt projection of one authoritative planned work order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2PlannedWorkOrder {
    pub id: String,
    pub revision: u32,
    pub objective: String,
    pub obligations: BTreeSet<crate::planner_replanner::PlannerReplannerObligationRef>,
    pub dependencies: BTreeSet<String>,
    pub verification_targets: BTreeSet<String>,
    pub required_access: crate::planner_replanner::PlannerReplannerAccess,
    pub state: PlannerReplannerV2PlannedWorkOrderState,
    pub basis: PlannerReplannerDecisionBasis,
}

/// Strict frozen mirror of the authoritative plan snapshot read by one turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2PlanSnapshot {
    pub schema_version: u32,
    pub plan_id: String,
    pub revision: u64,
    pub parent_plan_sha256: Option<String>,
    pub obligation_snapshot_sha256: String,
    pub acceptance_policy_sha256: String,
    pub strategy_summary: String,
    pub verification_targets: BTreeMap<String, PlannerReplannerV2VerificationTarget>,
    pub work_orders: BTreeMap<String, PlannerReplannerV2PlannedWorkOrder>,
}

impl PlannerReplannerV2PlanSnapshot {
    /// Creates the exact authoritative empty-plan projection used only for an
    /// initial-delegation turn.
    #[must_use]
    pub fn empty(
        plan_id: impl Into<String>,
        obligation_snapshot_sha256: impl Into<String>,
        acceptance_policy_sha256: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: PLANNER_REPLANNER_V2_SOURCE_CONTRACT_VERSION,
            plan_id: plan_id.into(),
            revision: 0,
            parent_plan_sha256: None,
            obligation_snapshot_sha256: obligation_snapshot_sha256.into(),
            acceptance_policy_sha256: acceptance_policy_sha256.into(),
            strategy_summary: String::new(),
            verification_targets: BTreeMap::new(),
            work_orders: BTreeMap::new(),
        }
    }

    /// Derives the same deterministic JSON-byte digest as the authoritative
    /// planner domain.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialization fails.
    pub fn sha256(&self) -> Result<String, String> {
        wire_sha256(self)
    }
}

/// One immutable protected obligation in the frozen prompt projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2ProtectedObligation {
    pub id: String,
    pub content_sha256: String,
    pub statement: String,
    pub required: bool,
}

/// Strict frozen mirror of the runtime-authored obligation catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2ProtectedObligationCatalog {
    pub snapshot_sha256: String,
    pub acceptance_policy_sha256: String,
    pub obligations: BTreeMap<String, PlannerReplannerV2ProtectedObligation>,
}

impl PlannerReplannerV2ProtectedObligationCatalog {
    /// Derives the authoritative catalog snapshot digest from acceptance
    /// policy plus the exact sorted obligation map.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialization fails.
    pub fn derived_snapshot_sha256(&self) -> Result<String, String> {
        wire_sha256(&ObligationCatalogHashMaterial {
            acceptance_policy_sha256: &self.acceptance_policy_sha256,
            obligations: &self.obligations,
        })
    }
}

/// One exact opaque context identity/content-address binding.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2ContextEvidenceBinding {
    pub id: String,
    pub content_sha256: String,
}

/// Strict frozen mirror of the trusted planner context catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2ContextCatalog {
    pub manifest_sha256: String,
    pub evidence_bindings: Vec<PlannerReplannerV2ContextEvidenceBinding>,
}

impl PlannerReplannerV2ContextCatalog {
    /// Derives the authoritative context manifest digest.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialization fails.
    pub fn derived_manifest_sha256(&self) -> Result<String, String> {
        wire_sha256(&ContextCatalogHashMaterial {
            schema_version: PLANNER_REPLANNER_V2_SOURCE_CONTRACT_VERSION,
            evidence_bindings: &self.evidence_bindings,
        })
    }
}

/// Strict frozen mirror of the authoritative mechanical planner limits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2PolicyLimits {
    pub max_work_orders: u32,
    pub max_verification_targets: u32,
    pub max_patch_operations: u32,
    pub max_dependencies_per_work_order: u32,
    pub max_delegations: u32,
    pub max_questions: u32,
    pub max_text_bytes: u64,
}

/// Strict frozen mirror of the runtime-authored read-only planner policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2Policy {
    pub policy_sha256: String,
    pub maximum_access: crate::planner_replanner::PlannerReplannerAccess,
    pub limits: PlannerReplannerV2PolicyLimits,
}

impl PlannerReplannerV2Policy {
    /// Derives the authoritative policy digest without including the digest
    /// field itself.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialization fails.
    pub fn derived_policy_sha256(&self) -> Result<String, String> {
        wire_sha256(&PlannerPolicyHashMaterial {
            maximum_access: self.maximum_access,
            limits: &self.limits,
        })
    }
}

/// Exact accepted-root-plan evidence required for an initial-delegation turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerAcceptedRootPlanEvidenceV2 {
    pub contract_version: u32,
    pub review_event_id: String,
    pub review_id: String,
    pub proposal_event_id: String,
    pub plan_revision: u64,
    pub plan_digest: String,
    pub plan_artifact: PlannerEvidenceArtifactRef,
    pub critique_artifact: PlannerEvidenceArtifactRef,
    pub validation_evidence_artifact: PlannerEvidenceArtifactRef,
    pub plan: RootPlannerOutput,
}

/// Exact successful handoff and its durable commit provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerVerifiedChildHandoffV2 {
    pub contract_version: u32,
    pub committed_event_id: String,
    pub handoff_artifact: PlannerEvidenceArtifactRef,
    pub handoff: PlannerChildHandoff,
}

/// Closed child failure classification copied from the terminal event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerChildFailureKindV2 {
    Model,
    Tool,
    Context,
    Budget,
    Protocol,
    DurableState,
}

/// Closed retry disposition copied from the terminal event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerChildRetryDispositionV2 {
    Never,
    RequiresNewAttempt,
}

/// Exact typed cause of a failed child attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "source", rename_all = "snake_case")]
pub enum PlannerChildFailureCauseV2 {
    ModelTerminal {
        terminal_event_id: String,
        model_call_id: String,
    },
    ToolTerminal {
        terminal_event_id: String,
        tool_call_id: String,
    },
    RuntimeEvidence {
        evidence_artifact: PlannerEvidenceArtifactRef,
        evidence_digest: String,
    },
}

/// Exact failed-child terminal evidence. No prose summary is synthesized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildFailedV2 {
    pub contract_version: u32,
    pub binding: PlannerChildExecutionBinding,
    pub finished_event_id: String,
    pub completed_model_calls: u32,
    pub completed_tool_calls: u32,
    pub kind: PlannerChildFailureKindV2,
    pub retry: PlannerChildRetryDispositionV2,
    pub cause: PlannerChildFailureCauseV2,
    /// Verified canonical `ChildExecutionFailureEvidenceV1` artifact.
    pub evidence_artifact: PlannerEvidenceArtifactRef,
    pub evidence_digest: String,
    /// Exact bounded diagnostic loaded from that verified artifact. It remains
    /// data and is never classified by deterministic string logic.
    pub diagnostic: Value,
}

/// Exact durable cancellation request consumed by a child terminal record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildCancellationCauseV2 {
    pub request_event_id: String,
    pub request_id: String,
    pub cancellation_generation: u64,
}

/// Exact cancelled-child terminal evidence. No failure or handoff is invented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildCancelledV2 {
    pub contract_version: u32,
    pub binding: PlannerChildExecutionBinding,
    pub finished_event_id: String,
    pub completed_model_calls: u32,
    pub completed_tool_calls: u32,
    pub cause: PlannerChildCancellationCauseV2,
}

/// Closed evidence vocabulary visible to the v2 semantic planner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReplannerV2EvidenceKind {
    AcceptedRootPlan,
    ChildHandoff,
    ChildFailed,
    ChildCancelled,
}

/// Constructor material whose normalized digest is derived locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlannerReplannerV2EvidenceMaterial {
    AcceptedRootPlan {
        evidence_id: String,
        accepted_root_plan: PlannerAcceptedRootPlanEvidenceV2,
    },
    ChildHandoff {
        evidence_id: String,
        child_handoff: PlannerVerifiedChildHandoffV2,
    },
    ChildFailed {
        evidence_id: String,
        child_failed: PlannerChildFailedV2,
    },
    ChildCancelled {
        evidence_id: String,
        child_cancelled: PlannerChildCancelledV2,
    },
}

/// One content-addressed, lossless normalized evidence item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum PlannerReplannerV2EvidenceEntry {
    AcceptedRootPlan {
        evidence_id: String,
        accepted_root_plan: PlannerAcceptedRootPlanEvidenceV2,
        normalized_content_sha256: String,
    },
    ChildHandoff {
        evidence_id: String,
        child_handoff: PlannerVerifiedChildHandoffV2,
        normalized_content_sha256: String,
    },
    ChildFailed {
        evidence_id: String,
        child_failed: PlannerChildFailedV2,
        normalized_content_sha256: String,
    },
    ChildCancelled {
        evidence_id: String,
        child_cancelled: PlannerChildCancelledV2,
        normalized_content_sha256: String,
    },
}

impl PlannerReplannerV2EvidenceEntry {
    /// Builds and mechanically validates one normalized evidence item.
    ///
    /// # Errors
    ///
    /// Returns all safely collectable shape, identity, bound, and digest
    /// defects. Natural-language content is never classified.
    pub fn new(
        material: PlannerReplannerV2EvidenceMaterial,
    ) -> Result<Self, Vec<PlannerReplannerV2EvidenceViolation>> {
        let mut entry = match material {
            PlannerReplannerV2EvidenceMaterial::AcceptedRootPlan {
                evidence_id,
                accepted_root_plan,
            } => Self::AcceptedRootPlan {
                evidence_id,
                accepted_root_plan,
                normalized_content_sha256: String::new(),
            },
            PlannerReplannerV2EvidenceMaterial::ChildHandoff {
                evidence_id,
                child_handoff,
            } => Self::ChildHandoff {
                evidence_id,
                child_handoff,
                normalized_content_sha256: String::new(),
            },
            PlannerReplannerV2EvidenceMaterial::ChildFailed {
                evidence_id,
                child_failed,
            } => Self::ChildFailed {
                evidence_id,
                child_failed,
                normalized_content_sha256: String::new(),
            },
            PlannerReplannerV2EvidenceMaterial::ChildCancelled {
                evidence_id,
                child_cancelled,
            } => Self::ChildCancelled {
                evidence_id,
                child_cancelled,
                normalized_content_sha256: String::new(),
            },
        };
        let violations = evidence_entry_structure_violations(&entry);
        if !violations.is_empty() {
            return Err(violations);
        }
        let digest = evidence_entry_sha256(&entry).map_err(|message| {
            vec![PlannerReplannerV2EvidenceViolation::CanonicalEncoding { message }]
        })?;
        *entry.normalized_content_sha256_mut() = digest;
        Ok(entry)
    }

    #[must_use]
    pub fn evidence_id(&self) -> &str {
        match self {
            Self::AcceptedRootPlan { evidence_id, .. }
            | Self::ChildHandoff { evidence_id, .. }
            | Self::ChildFailed { evidence_id, .. }
            | Self::ChildCancelled { evidence_id, .. } => evidence_id,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> PlannerReplannerV2EvidenceKind {
        match self {
            Self::AcceptedRootPlan { .. } => PlannerReplannerV2EvidenceKind::AcceptedRootPlan,
            Self::ChildHandoff { .. } => PlannerReplannerV2EvidenceKind::ChildHandoff,
            Self::ChildFailed { .. } => PlannerReplannerV2EvidenceKind::ChildFailed,
            Self::ChildCancelled { .. } => PlannerReplannerV2EvidenceKind::ChildCancelled,
        }
    }

    #[must_use]
    pub fn normalized_content_sha256(&self) -> &str {
        match self {
            Self::AcceptedRootPlan {
                normalized_content_sha256,
                ..
            }
            | Self::ChildHandoff {
                normalized_content_sha256,
                ..
            }
            | Self::ChildFailed {
                normalized_content_sha256,
                ..
            }
            | Self::ChildCancelled {
                normalized_content_sha256,
                ..
            } => normalized_content_sha256,
        }
    }

    fn normalized_content_sha256_mut(&mut self) -> &mut String {
        match self {
            Self::AcceptedRootPlan {
                normalized_content_sha256,
                ..
            }
            | Self::ChildHandoff {
                normalized_content_sha256,
                ..
            }
            | Self::ChildFailed {
                normalized_content_sha256,
                ..
            }
            | Self::ChildCancelled {
                normalized_content_sha256,
                ..
            } => normalized_content_sha256,
        }
    }

    /// Revalidates the item and its normalized content address.
    ///
    /// # Errors
    ///
    /// Returns every detected mechanical integrity violation.
    pub fn validate_integrity(&self) -> Result<(), Vec<PlannerReplannerV2EvidenceViolation>> {
        let violations = evidence_entry_integrity_violations(self);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Purpose-bound, content-addressed evidence packet.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2EvidencePacket {
    pub schema_version: u32,
    pub purpose: PlannerReplannerV2Purpose,
    pub context_manifest_sha256: String,
    pub entries: Vec<PlannerReplannerV2EvidenceEntry>,
    pub packet_sha256: String,
}

impl PlannerReplannerV2EvidencePacket {
    /// Builds a canonical packet ordered by opaque evidence identity.
    ///
    /// Initial delegation accepts exactly one accepted-root-plan entry.
    /// Evidence replanning accepts one or more terminal child entries and does
    /// not require a successful handoff.
    ///
    /// # Errors
    ///
    /// Rejects wrong-purpose evidence, malformed items, duplicates, bounds,
    /// and content-address mismatches.
    pub fn new(
        purpose: PlannerReplannerV2Purpose,
        context_manifest_sha256: impl Into<String>,
        mut entries: Vec<PlannerReplannerV2EvidenceEntry>,
    ) -> Result<Self, Vec<PlannerReplannerV2EvidenceViolation>> {
        entries.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
        let mut packet = Self {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            purpose,
            context_manifest_sha256: context_manifest_sha256.into(),
            entries,
            packet_sha256: String::new(),
        };
        let violations = evidence_packet_structure_violations(&packet);
        if !violations.is_empty() {
            return Err(violations);
        }
        packet.packet_sha256 = evidence_packet_sha256(&packet).map_err(|message| {
            vec![PlannerReplannerV2EvidenceViolation::CanonicalEncoding { message }]
        })?;
        packet.validate_integrity()?;
        Ok(packet)
    }

    /// Revalidates the packet, canonical order, and all content addresses.
    ///
    /// # Errors
    ///
    /// Returns every safely collectable mechanical integrity violation.
    pub fn validate_integrity(&self) -> Result<(), Vec<PlannerReplannerV2EvidenceViolation>> {
        let violations = evidence_packet_integrity_violations(self);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// One exact evidence identity/content-address pair made newly available to a
/// turn. The cumulative packet may contain older evidence as well.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2EvidenceBinding {
    pub evidence_id: String,
    pub normalized_content_sha256: String,
}

/// Purpose-bound evidence delta used to prove what changed for this turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2EvidenceDelta {
    pub schema_version: u32,
    pub purpose: PlannerReplannerV2Purpose,
    /// Durable predecessor packet identity. It is absent only for the initial
    /// delegation turn and must be attested by the Store adapter.
    pub previous_packet_sha256: Option<String>,
    /// Exact predecessor identity/content index used to derive a set delta.
    pub previous_evidence: Vec<PlannerReplannerV2EvidenceBinding>,
    pub newly_available: Vec<PlannerReplannerV2EvidenceBinding>,
    pub delta_sha256: String,
}

impl PlannerReplannerV2EvidenceDelta {
    /// Derives newly available identities as the exact set difference between
    /// the current cumulative packet and an optional predecessor packet.
    ///
    /// # Errors
    ///
    /// Rejects unknown, duplicate, wrong-purpose, empty, or noncanonical
    /// evidence deltas.
    pub fn new(
        purpose: PlannerReplannerV2Purpose,
        packet: &PlannerReplannerV2EvidencePacket,
        previous_packet: Option<&PlannerReplannerV2EvidencePacket>,
    ) -> Result<Self, Vec<PlannerReplannerV2EvidenceViolation>> {
        let packet_entries = packet
            .entries
            .iter()
            .map(|entry| (entry.evidence_id(), entry))
            .collect::<BTreeMap<_, _>>();
        let previous_packet_sha256 = previous_packet.map(|packet| packet.packet_sha256.clone());
        let mut previous_evidence = previous_packet
            .map(|packet| {
                packet
                    .entries
                    .iter()
                    .map(evidence_binding)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        previous_evidence.sort();
        let previous_ids = previous_evidence
            .iter()
            .map(|binding| binding.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        let newly_available = packet_entries
            .values()
            .filter(|entry| !previous_ids.contains(entry.evidence_id()))
            .map(|entry| evidence_binding(entry))
            .collect();
        let mut delta = Self {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            purpose,
            previous_packet_sha256,
            previous_evidence,
            newly_available,
            delta_sha256: String::new(),
        };
        let mut violations = previous_packet
            .and_then(|packet| packet.validate_integrity().err())
            .unwrap_or_default();
        violations.extend(evidence_delta_structure_violations(&delta, packet));
        if !violations.is_empty() {
            return Err(violations);
        }
        delta.delta_sha256 = evidence_delta_sha256(&delta).map_err(|message| {
            vec![PlannerReplannerV2EvidenceViolation::CanonicalEncoding { message }]
        })?;
        delta.validate_against(packet)?;
        Ok(delta)
    }

    /// Revalidates the delta and every packet binding.
    ///
    /// # Errors
    ///
    /// Returns all safely collectable identity, purpose, and digest defects.
    pub fn validate_against(
        &self,
        packet: &PlannerReplannerV2EvidencePacket,
    ) -> Result<(), Vec<PlannerReplannerV2EvidenceViolation>> {
        let violations = evidence_delta_integrity_violations(self, packet);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Mechanical evidence defect; no variant classifies prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerReplannerV2EvidenceViolation {
    SchemaVersion {
        expected: u32,
        actual: u32,
    },
    EntryCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    InitialDelegationEvidenceShape,
    EvidenceReplanEvidenceShape,
    EmptyEvidenceId,
    EvidenceIdTooLong {
        maximum: u32,
        actual: u32,
    },
    DuplicateEvidenceId {
        evidence_id: String,
    },
    DuplicateSourceEvent {
        event_id: String,
    },
    DuplicateTerminalBinding,
    NonCanonicalOrder {
        index: u32,
    },
    InvalidDigest {
        field: String,
    },
    InvalidIdentifier {
        field: String,
    },
    InvalidContractVersion {
        field: String,
        expected: u32,
        actual: u32,
    },
    InvalidArtifact {
        field: String,
    },
    AcceptedRootPlanShape,
    ChildHandoff {
        violation: PlannerEvidencePacketViolation,
    },
    FailureCauseMismatch,
    NormalizedContentDigestMismatch {
        evidence_id: String,
    },
    PacketDigestMismatch,
    DeltaPurposeMismatch,
    DeltaPredecessorMismatch,
    DeltaShapeMismatch,
    DeltaUnknownEvidence {
        evidence_id: String,
    },
    DeltaDigestMismatch {
        evidence_id: String,
    },
    DeltaSha256Mismatch,
    PacketTooLarge {
        maximum: u32,
        actual: u32,
    },
    CanonicalEncoding {
        message: String,
    },
}

/// Complete invocation material for one v2 turn.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannerReplannerV2InvocationMaterial {
    pub base_plan: PlannerReplannerV2PlanSnapshot,
    pub protected_obligation_catalog: PlannerReplannerV2ProtectedObligationCatalog,
    pub planner_context_catalog: PlannerReplannerV2ContextCatalog,
    pub evidence_packet: PlannerReplannerV2EvidencePacket,
    pub evidence_delta: PlannerReplannerV2EvidenceDelta,
    pub planner_policy: PlannerReplannerV2Policy,
    pub bindings: PlannerReplannerV2Bindings,
}

/// Provider output with v2 request bindings and the exact authoritative plan
/// patch/directive shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerV2Output {
    pub schema_version: u32,
    pub bindings: PlannerReplannerV2Bindings,
    pub turn_basis: PlannerReplannerDecisionBasis,
    pub patch: crate::planner_replanner::PlannerReplannerPlanPatch,
    pub directive: crate::planner_replanner::PlannerReplannerDirective,
}

/// Total conversion result. V2-only provenance is retained alongside the
/// exact orchestrator-isomorphic proposal instead of being silently dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerReplannerV2AuthoritativeParts {
    pub proposal: PlannerReplannerOutput,
    pub source_schema_version: u32,
    pub turn_basis: PlannerReplannerDecisionBasis,
    pub request_bindings: PlannerReplannerV2Bindings,
}

impl PlannerReplannerV2Output {
    /// Validates and performs the total, field-explicit conversion to the
    /// authoritative orchestrator-isomorphic DTO.
    ///
    /// # Errors
    ///
    /// Fails closed if this output is not bound to the exact invocation or
    /// violates any v2 prompt-boundary invariant.
    pub fn into_authoritative_parts(
        self,
        invocation: &PromptInvocation,
    ) -> Result<PlannerReplannerV2AuthoritativeParts, Vec<PlannerReplannerV2InvariantViolation>>
    {
        let value = serde_json::to_value(&self).map_err(|error| {
            vec![PlannerReplannerV2InvariantViolation::TypedOutputDecode {
                message: error.to_string(),
            }]
        })?;
        let registry = crate::manifest::builtin_registry()
            .map_err(|error| contract_validation_error(&error))?;
        let compiled = registry
            .compile(&planner_replanner_v2_key(), invocation)
            .map_err(|error| contract_validation_error(&error))?;
        if let Err(error) = registry.validate_output(&compiled, invocation, &value) {
            return match error {
                crate::PromptError::PlannerReplannerV2OutputInvariant(violations) => {
                    Err(violations)
                }
                error => Err(contract_validation_error(&error)),
            };
        }
        let authoritative_bindings = self.bindings.authoritative_bindings();
        Ok(PlannerReplannerV2AuthoritativeParts {
            proposal: PlannerReplannerOutput {
                schema_version: 1,
                bindings: authoritative_bindings,
                patch: self.patch,
                directive: self.directive,
            },
            source_schema_version: self.schema_version,
            turn_basis: self.turn_basis,
            request_bindings: self.bindings,
        })
    }
}

/// Mechanical prompt-boundary violation for v2.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerReplannerV2InvariantViolation {
    TypedOutputDecode {
        message: String,
    },
    ContractValidation {
        message: String,
    },
    OutputSchemaVersion {
        expected: u32,
        actual: u32,
    },
    RuntimeConstraintShape,
    InvalidBindings {
        field: String,
    },
    MissingContextCatalog,
    ContextCatalogDecode {
        message: String,
    },
    MissingEvidencePacket,
    EvidencePacketDecode {
        message: String,
    },
    EvidencePacketIntegrity {
        violation: PlannerReplannerV2EvidenceViolation,
    },
    EvidenceDeltaDecode {
        message: String,
    },
    EvidenceDeltaIntegrity {
        violation: PlannerReplannerV2EvidenceViolation,
    },
    PurposeMismatch,
    AcceptedRootPlanBindingMismatch {
        field: String,
    },
    AuthorityIntegrity {
        field: String,
    },
    BasePlanEvidenceOmission {
        evidence_id: String,
    },
    EvidencePacketContextMismatch,
    EvidencePacketOmission {
        evidence_id: String,
    },
    EvidencePacketUnknownId {
        evidence_id: String,
    },
    EvidencePacketDigestMismatch {
        evidence_id: String,
    },
    InvocationBindingMismatch {
        field: String,
    },
    BindingMismatch {
        field: String,
    },
    UnknownEvidenceId {
        evidence_id: String,
    },
    EmptyTurnBasis,
    TurnBasisMissesDelta,
    InitialFinishForbidden,
}

fn contract_validation_error(
    error: &crate::PromptError,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    vec![PlannerReplannerV2InvariantViolation::ContractValidation {
        message: error.to_string(),
    }]
}

fn authority_payload(
    field: &str,
    value: &impl Serialize,
) -> Result<Value, Vec<PlannerReplannerV2InvariantViolation>> {
    serde_json::to_value(value).map_err(|_| {
        vec![PlannerReplannerV2InvariantViolation::AuthorityIntegrity {
            field: field.to_owned(),
        }]
    })
}

/// Returns the immutable bundled key for planner-replanner v2.
///
/// # Panics
///
/// Panics only if the compile-time identifier is invalid.
#[must_use]
pub fn planner_replanner_v2_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(PLANNER_REPLANNER_V2_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 0, 0),
    )
}

pub(crate) fn is_planner_replanner_v2_key(key: &PromptKey) -> bool {
    key == &planner_replanner_v2_key()
}

/// Compiles exact domain serializations into trust-labelled prompt input.
///
/// # Errors
///
/// Rejects mismatched purpose, evidence, provenance, inference, budget, or
/// base-plan bindings before a prompt can be compiled.
pub fn planner_replanner_v2_invocation(
    material: &PlannerReplannerV2InvocationMaterial,
) -> Result<PromptInvocation, Vec<PlannerReplannerV2InvariantViolation>> {
    let base_plan_payload = authority_payload("base_plan", &material.base_plan)?;
    let obligation_catalog_payload = authority_payload(
        "protected_obligation_catalog",
        &material.protected_obligation_catalog,
    )?;
    let context_catalog_payload =
        authority_payload("planner_context_catalog", &material.planner_context_catalog)?;
    let policy_payload = authority_payload("planner_policy", &material.planner_policy)?;
    let evidence_packet_payload =
        serde_json::to_value(&material.evidence_packet).map_err(|error| {
            vec![PlannerReplannerV2InvariantViolation::EvidencePacketDecode {
                message: error.to_string(),
            }]
        })?;
    let bindings_payload = serde_json::to_value(&material.bindings).map_err(|error| {
        vec![PlannerReplannerV2InvariantViolation::RuntimeConstraintShape]
            .into_iter()
            .chain(std::iter::once(
                PlannerReplannerV2InvariantViolation::InvalidBindings {
                    field: error.to_string(),
                },
            ))
            .collect::<Vec<_>>()
    })?;
    let evidence_delta_payload =
        serde_json::to_value(&material.evidence_delta).map_err(|error| {
            vec![PlannerReplannerV2InvariantViolation::EvidenceDeltaDecode {
                message: error.to_string(),
            }]
        })?;
    let sections = vec![
        DataSection {
            name: BASE_PLAN_SECTION.to_owned(),
            trust: TrustLevel::UntrustedExternal,
            provenance: DataProvenance {
                source_kind: SourceKind::External,
                source_id: format!(
                    "accepted-plan:{}:{}",
                    material.bindings.plan_id, material.bindings.base_revision
                ),
                artifact_sha256: Some(material.bindings.base_plan_sha256.clone()),
                event_id: None,
            },
            payload: base_plan_payload,
        },
        DataSection {
            name: OBLIGATION_CATALOG_SECTION.to_owned(),
            trust: TrustLevel::User,
            provenance: DataProvenance {
                source_kind: SourceKind::User,
                source_id: "protected-obligation-catalog".to_owned(),
                artifact_sha256: Some(material.bindings.obligation_snapshot_sha256.clone()),
                event_id: None,
            },
            payload: obligation_catalog_payload,
        },
        DataSection {
            name: CONTEXT_CATALOG_SECTION.to_owned(),
            trust: TrustLevel::Tool,
            provenance: DataProvenance {
                source_kind: SourceKind::Tool,
                source_id: "planner-context-catalog".to_owned(),
                artifact_sha256: Some(material.bindings.context_manifest_sha256.clone()),
                event_id: None,
            },
            payload: context_catalog_payload,
        },
        DataSection {
            name: EVIDENCE_PACKET_SECTION.to_owned(),
            trust: TrustLevel::Tool,
            provenance: DataProvenance {
                source_kind: SourceKind::Tool,
                source_id: "normalized-planner-evidence-v2".to_owned(),
                artifact_sha256: Some(material.evidence_packet.packet_sha256.clone()),
                event_id: None,
            },
            payload: evidence_packet_payload,
        },
    ];
    let invocation = PromptInvocation::with_runtime_constraints(
        sections,
        PromptLimits::new(0),
        vec![
            RuntimeConstraint {
                name: POLICY_CONSTRAINT.to_owned(),
                payload: policy_payload,
            },
            RuntimeConstraint {
                name: BINDINGS_CONSTRAINT.to_owned(),
                payload: bindings_payload,
            },
            RuntimeConstraint {
                name: EVIDENCE_DELTA_CONSTRAINT.to_owned(),
                payload: evidence_delta_payload,
            },
        ],
    );
    validate_planner_replanner_v2_invocation(&invocation)?;
    Ok(invocation)
}

/// Validates output echo bindings and exact evidence membership.
///
/// Semantic patch validity and directive selection remain authoritative in
/// the orchestrator's `validate_and_apply` transition.
///
/// # Errors
///
/// Returns every safely collectable mechanical prompt-boundary violation.
pub fn validate_planner_replanner_v2_output(
    value: &Value,
    invocation: &PromptInvocation,
) -> Result<(), Vec<PlannerReplannerV2InvariantViolation>> {
    let output =
        serde_json::from_value::<PlannerReplannerV2Output>(value.clone()).map_err(|error| {
            vec![PlannerReplannerV2InvariantViolation::TypedOutputDecode {
                message: error.to_string(),
            }]
        })?;
    let validated = validate_invocation(invocation)?;
    let mut violations = binding_violations(&output.bindings, &validated.bindings);
    if output.schema_version != EVIDENCE_PACKET_SCHEMA_VERSION {
        violations.push(PlannerReplannerV2InvariantViolation::OutputSchemaVersion {
            expected: EVIDENCE_PACKET_SCHEMA_VERSION,
            actual: output.schema_version,
        });
    }
    for evidence_id in output_evidence_ids(&output) {
        if !validated.evidence_bindings.contains_key(evidence_id) {
            violations.push(PlannerReplannerV2InvariantViolation::UnknownEvidenceId {
                evidence_id: evidence_id.clone(),
            });
        }
    }
    if output.turn_basis.evidence_ids.is_empty() {
        violations.push(PlannerReplannerV2InvariantViolation::EmptyTurnBasis);
    } else if output
        .turn_basis
        .evidence_ids
        .is_disjoint(&validated.delta_evidence_ids)
    {
        violations.push(PlannerReplannerV2InvariantViolation::TurnBasisMissesDelta);
    }
    if output.bindings.purpose == PlannerReplannerV2Purpose::InitialDelegation
        && output.directive.kind == PlannerReplannerDirectiveKind::Finish
    {
        violations.push(PlannerReplannerV2InvariantViolation::InitialFinishForbidden);
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Validates an independently supplied v2 prompt input before inference.
///
/// # Errors
///
/// Rejects purpose drift, malformed runtime constraints, stale base bindings,
/// evidence substitution/omission, and unbound inference or budget inputs.
pub fn validate_planner_replanner_v2_invocation(
    invocation: &PromptInvocation,
) -> Result<(), Vec<PlannerReplannerV2InvariantViolation>> {
    validate_invocation(invocation).map(|_| ())
}

struct ValidatedInvocation {
    bindings: PlannerReplannerV2Bindings,
    evidence_bindings: BTreeMap<String, String>,
    delta_evidence_ids: BTreeSet<String>,
}

struct AuthorityRefs<'a> {
    base_plan: &'a PlannerReplannerV2PlanSnapshot,
    obligations: &'a PlannerReplannerV2ProtectedObligationCatalog,
    context: &'a PlannerReplannerV2ContextCatalog,
    policy: &'a PlannerReplannerV2Policy,
}

fn validate_invocation(
    invocation: &PromptInvocation,
) -> Result<ValidatedInvocation, Vec<PlannerReplannerV2InvariantViolation>> {
    let Some(bindings) = exact_bindings_constraint(invocation) else {
        return Err(vec![
            PlannerReplannerV2InvariantViolation::RuntimeConstraintShape,
        ]);
    };
    let base_plan =
        decode_authority_section::<PlannerReplannerV2PlanSnapshot>(invocation, BASE_PLAN_SECTION)?;
    let obligations = decode_authority_section::<PlannerReplannerV2ProtectedObligationCatalog>(
        invocation,
        OBLIGATION_CATALOG_SECTION,
    )?;
    let context = decode_context_catalog(invocation)?;
    let policy = decode_policy(invocation)?;
    let packet = decode_evidence_packet(invocation)?;
    let delta = decode_evidence_delta(invocation)?;
    let authority = AuthorityRefs {
        base_plan: &base_plan,
        obligations: &obligations,
        context: &context,
        policy: &policy,
    };
    let mut violations = binding_structure_violations(&bindings);
    violations.extend(invocation_binding_violations(
        invocation, &bindings, &authority, &packet, &delta,
    ));
    violations.extend(authority_integrity_violations(
        &bindings, &authority, &packet,
    ));
    violations.extend(evidence_packet_violations(&packet, &context));
    violations.extend(
        delta
            .validate_against(&packet)
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(
                |violation| PlannerReplannerV2InvariantViolation::EvidenceDeltaIntegrity {
                    violation,
                },
            ),
    );
    if violations.is_empty() {
        Ok(ValidatedInvocation {
            bindings,
            evidence_bindings: packet
                .entries
                .into_iter()
                .map(|entry| {
                    (
                        entry.evidence_id().to_owned(),
                        entry.normalized_content_sha256().to_owned(),
                    )
                })
                .collect(),
            delta_evidence_ids: delta
                .newly_available
                .into_iter()
                .map(|binding| binding.evidence_id)
                .collect(),
        })
    } else {
        Err(violations)
    }
}

fn decode_context_catalog(
    invocation: &PromptInvocation,
) -> Result<PlannerReplannerV2ContextCatalog, Vec<PlannerReplannerV2InvariantViolation>> {
    let Some(value) = section_payload(invocation, CONTEXT_CATALOG_SECTION) else {
        return Err(vec![
            PlannerReplannerV2InvariantViolation::MissingContextCatalog,
        ]);
    };
    serde_json::from_value::<PlannerReplannerV2ContextCatalog>(value.clone()).map_err(|error| {
        vec![PlannerReplannerV2InvariantViolation::ContextCatalogDecode {
            message: error.to_string(),
        }]
    })
}

fn decode_authority_section<T: DeserializeOwned>(
    invocation: &PromptInvocation,
    section_name: &str,
) -> Result<T, Vec<PlannerReplannerV2InvariantViolation>> {
    let Some(value) = section_payload(invocation, section_name) else {
        return Err(vec![
            PlannerReplannerV2InvariantViolation::AuthorityIntegrity {
                field: section_name.to_owned(),
            },
        ]);
    };
    serde_json::from_value(value.clone()).map_err(|_| {
        vec![PlannerReplannerV2InvariantViolation::AuthorityIntegrity {
            field: section_name.to_owned(),
        }]
    })
}

fn decode_policy(
    invocation: &PromptInvocation,
) -> Result<PlannerReplannerV2Policy, Vec<PlannerReplannerV2InvariantViolation>> {
    let Some(value) = invocation
        .runtime_constraints
        .first()
        .filter(|constraint| constraint.name == POLICY_CONSTRAINT)
        .map(|constraint| &constraint.payload)
    else {
        return Err(vec![
            PlannerReplannerV2InvariantViolation::RuntimeConstraintShape,
        ]);
    };
    serde_json::from_value(value.clone()).map_err(|_| {
        vec![PlannerReplannerV2InvariantViolation::AuthorityIntegrity {
            field: POLICY_CONSTRAINT.to_owned(),
        }]
    })
}

fn decode_evidence_packet(
    invocation: &PromptInvocation,
) -> Result<PlannerReplannerV2EvidencePacket, Vec<PlannerReplannerV2InvariantViolation>> {
    let Some(value) = section_payload(invocation, EVIDENCE_PACKET_SECTION) else {
        return Err(vec![
            PlannerReplannerV2InvariantViolation::MissingEvidencePacket,
        ]);
    };
    serde_json::from_value::<PlannerReplannerV2EvidencePacket>(value.clone()).map_err(|error| {
        vec![PlannerReplannerV2InvariantViolation::EvidencePacketDecode {
            message: error.to_string(),
        }]
    })
}

fn decode_evidence_delta(
    invocation: &PromptInvocation,
) -> Result<PlannerReplannerV2EvidenceDelta, Vec<PlannerReplannerV2InvariantViolation>> {
    let Some(value) = invocation
        .runtime_constraints
        .iter()
        .find(|constraint| constraint.name == EVIDENCE_DELTA_CONSTRAINT)
        .map(|constraint| &constraint.payload)
    else {
        return Err(vec![
            PlannerReplannerV2InvariantViolation::RuntimeConstraintShape,
        ]);
    };
    serde_json::from_value::<PlannerReplannerV2EvidenceDelta>(value.clone()).map_err(|error| {
        vec![PlannerReplannerV2InvariantViolation::EvidenceDeltaDecode {
            message: error.to_string(),
        }]
    })
}

fn exact_bindings_constraint(invocation: &PromptInvocation) -> Option<PlannerReplannerV2Bindings> {
    if invocation.runtime_constraints.len() != 3
        || invocation.runtime_constraints[0].name != POLICY_CONSTRAINT
        || invocation.runtime_constraints[1].name != BINDINGS_CONSTRAINT
        || invocation.runtime_constraints[2].name != EVIDENCE_DELTA_CONSTRAINT
    {
        return None;
    }
    serde_json::from_value(invocation.runtime_constraints[1].payload.clone()).ok()
}

#[allow(
    clippy::too_many_lines,
    reason = "one closed structural audit reports every exact v2 binding field without splitting precedence across helpers"
)]
fn binding_structure_violations(
    bindings: &PlannerReplannerV2Bindings,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = Vec::new();
    for (field, digest) in [
        (
            "prompt_manifest_sha256",
            bindings.prompt_manifest_sha256.as_str(),
        ),
        ("base_plan_sha256", bindings.base_plan_sha256.as_str()),
        (
            "obligation_snapshot_sha256",
            bindings.obligation_snapshot_sha256.as_str(),
        ),
        (
            "acceptance_policy_sha256",
            bindings.acceptance_policy_sha256.as_str(),
        ),
        (
            "context_manifest_sha256",
            bindings.context_manifest_sha256.as_str(),
        ),
        (
            "planner_policy_sha256",
            bindings.planner_policy_sha256.as_str(),
        ),
        (
            "evidence_packet_sha256",
            bindings.evidence_packet_sha256.as_str(),
        ),
        (
            "evidence_delta_sha256",
            bindings.evidence_delta_sha256.as_str(),
        ),
        (
            "backend_instance_sha256",
            bindings.backend_instance_sha256.as_str(),
        ),
    ] {
        if !is_lowercase_sha256(digest) {
            violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
                field: field.to_owned(),
            });
        }
    }
    for (field, identifier) in [
        ("plan_id", bindings.plan_id.as_str()),
        (
            "budget_reservation_id",
            bindings.budget_reservation_id.as_str(),
        ),
    ] {
        if !is_uuid_v7(identifier) {
            violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
                field: field.to_owned(),
            });
        }
    }
    if bindings.prompt_id != PLANNER_REPLANNER_V2_ID || bindings.prompt_version != "1.0.0" {
        violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
            field: "prompt".to_owned(),
        });
    }
    if bindings.prompt_manifest_sha256 != bundled_manifest_sha256() {
        violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
            field: "prompt_manifest_sha256".to_owned(),
        });
    }
    match (
        bindings.purpose,
        bindings.previous_evidence_packet_sha256.as_deref(),
    ) {
        (PlannerReplannerV2Purpose::InitialDelegation, None) => {}
        (PlannerReplannerV2Purpose::EvidenceReplan, Some(digest))
            if is_lowercase_sha256(digest) => {}
        _ => violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
            field: "previous_evidence_packet_sha256".to_owned(),
        }),
    }
    for (field, identifier) in [
        ("backend_id", bindings.backend_id.as_str()),
        (
            "backend_configured_deployment_id",
            bindings.backend_configured_deployment_id.as_str(),
        ),
        ("model_id", bindings.model_id.as_str()),
    ] {
        if identifier.is_empty() || identifier.len() > MAX_IDENTIFIER_BYTES {
            violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
                field: field.to_owned(),
            });
        }
    }
    if bindings.backend_endpoint_origin.is_empty()
        || bindings.backend_endpoint_origin.len() > MAX_BACKEND_ENDPOINT_ORIGIN_BYTES
    {
        violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
            field: "backend_endpoint_origin".to_owned(),
        });
    }
    if !(1..=PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS).contains(&bindings.max_output_tokens) {
        violations.push(PlannerReplannerV2InvariantViolation::InvalidBindings {
            field: "max_output_tokens".to_owned(),
        });
    }
    violations
}

fn invocation_binding_violations(
    invocation: &PromptInvocation,
    bindings: &PlannerReplannerV2Bindings,
    authority: &AuthorityRefs<'_>,
    packet: &PlannerReplannerV2EvidencePacket,
    delta: &PlannerReplannerV2EvidenceDelta,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = payload_binding_violations(bindings, authority);
    violations.extend(provenance_binding_violations(invocation, bindings));
    if bindings.purpose != packet.purpose {
        violations.push(PlannerReplannerV2InvariantViolation::PurposeMismatch);
    }
    if bindings.evidence_packet_sha256 != packet.packet_sha256 {
        violations.push(
            PlannerReplannerV2InvariantViolation::InvocationBindingMismatch {
                field: "evidence_packet_sha256".to_owned(),
            },
        );
    }
    if bindings.purpose != delta.purpose {
        violations.push(PlannerReplannerV2InvariantViolation::PurposeMismatch);
    }
    if bindings.evidence_delta_sha256 != delta.delta_sha256 {
        violations.push(
            PlannerReplannerV2InvariantViolation::InvocationBindingMismatch {
                field: "evidence_delta_sha256".to_owned(),
            },
        );
    }
    if bindings.previous_evidence_packet_sha256 != delta.previous_packet_sha256 {
        violations.push(
            PlannerReplannerV2InvariantViolation::InvocationBindingMismatch {
                field: "previous_evidence_packet_sha256".to_owned(),
            },
        );
    }
    if bindings.purpose == PlannerReplannerV2Purpose::InitialDelegation {
        validate_initial_base_and_root_evidence(
            authority.base_plan,
            bindings,
            packet,
            &mut violations,
        );
    }
    violations
}

fn payload_binding_violations(
    bindings: &PlannerReplannerV2Bindings,
    authority: &AuthorityRefs<'_>,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let AuthorityRefs {
        base_plan,
        obligations,
        context,
        policy,
    } = authority;
    let mut violations = Vec::new();
    for (field, matches) in [
        ("base_plan.plan_id", base_plan.plan_id == bindings.plan_id),
        (
            "base_plan.revision",
            base_plan.revision == bindings.base_revision,
        ),
        (
            "base_plan.obligation_snapshot_sha256",
            base_plan.obligation_snapshot_sha256 == bindings.obligation_snapshot_sha256,
        ),
        (
            "base_plan.acceptance_policy_sha256",
            base_plan.acceptance_policy_sha256 == bindings.acceptance_policy_sha256,
        ),
        (
            "protected_obligation_catalog.snapshot_sha256",
            obligations.snapshot_sha256 == bindings.obligation_snapshot_sha256,
        ),
        (
            "protected_obligation_catalog.acceptance_policy_sha256",
            obligations.acceptance_policy_sha256 == bindings.acceptance_policy_sha256,
        ),
        (
            "planner_context_catalog.manifest_sha256",
            context.manifest_sha256 == bindings.context_manifest_sha256,
        ),
        (
            "planner_policy.policy_sha256",
            policy.policy_sha256 == bindings.planner_policy_sha256,
        ),
    ] {
        if !matches {
            violations.push(
                PlannerReplannerV2InvariantViolation::InvocationBindingMismatch {
                    field: field.to_owned(),
                },
            );
        }
    }
    violations
}

fn provenance_binding_violations(
    invocation: &PromptInvocation,
    bindings: &PlannerReplannerV2Bindings,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = Vec::new();
    for (section_name, expected) in [
        (BASE_PLAN_SECTION, &bindings.base_plan_sha256),
        (
            OBLIGATION_CATALOG_SECTION,
            &bindings.obligation_snapshot_sha256,
        ),
        (CONTEXT_CATALOG_SECTION, &bindings.context_manifest_sha256),
        (EVIDENCE_PACKET_SECTION, &bindings.evidence_packet_sha256),
    ] {
        let actual = invocation
            .sections
            .iter()
            .find(|section| section.name == section_name)
            .and_then(|section| section.provenance.artifact_sha256.as_ref());
        if actual != Some(expected) {
            violations.push(
                PlannerReplannerV2InvariantViolation::InvocationBindingMismatch {
                    field: format!("{section_name}.provenance.artifact_sha256"),
                },
            );
        }
    }
    violations
}

fn validate_initial_base_and_root_evidence(
    base_plan: &PlannerReplannerV2PlanSnapshot,
    bindings: &PlannerReplannerV2Bindings,
    packet: &PlannerReplannerV2EvidencePacket,
    violations: &mut Vec<PlannerReplannerV2InvariantViolation>,
) {
    let Some(PlannerReplannerV2EvidenceEntry::AcceptedRootPlan {
        accepted_root_plan, ..
    }) = packet.entries.first()
    else {
        violations.push(PlannerReplannerV2InvariantViolation::PurposeMismatch);
        return;
    };
    for (field, matches) in [
        ("base_revision", bindings.base_revision == 0),
        ("base_plan.schema_version", base_plan.schema_version == 1),
        (
            "base_plan.parent_plan_sha256",
            base_plan.parent_plan_sha256.is_none(),
        ),
        (
            "base_plan.strategy_summary",
            base_plan.strategy_summary.is_empty(),
        ),
        (
            "base_plan.verification_targets",
            base_plan.verification_targets.is_empty(),
        ),
        ("base_plan.work_orders", base_plan.work_orders.is_empty()),
        (
            "accepted_root_plan.directive",
            accepted_root_plan.plan.directive == RootPlannerDirective::Plan,
        ),
    ] {
        if !matches {
            violations.push(
                PlannerReplannerV2InvariantViolation::AcceptedRootPlanBindingMismatch {
                    field: field.to_owned(),
                },
            );
        }
    }
}

fn authority_integrity_violations(
    bindings: &PlannerReplannerV2Bindings,
    authority: &AuthorityRefs<'_>,
    packet: &PlannerReplannerV2EvidencePacket,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations =
        base_plan_integrity_violations(authority.base_plan, authority.obligations, packet);
    violations.extend(obligation_catalog_integrity_violations(
        authority.obligations,
    ));
    violations.extend(context_catalog_integrity_violations(authority.context));
    violations.extend(policy_integrity_violations(authority.policy));
    if authority.base_plan.sha256().as_deref() != Ok(bindings.base_plan_sha256.as_str()) {
        violations.push(PlannerReplannerV2InvariantViolation::AuthorityIntegrity {
            field: "base_plan_sha256".to_owned(),
        });
    }
    violations
}

fn base_plan_integrity_violations(
    plan: &PlannerReplannerV2PlanSnapshot,
    obligations: &PlannerReplannerV2ProtectedObligationCatalog,
    packet: &PlannerReplannerV2EvidencePacket,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = Vec::new();
    authority_check(
        plan.schema_version == PLANNER_REPLANNER_V2_SOURCE_CONTRACT_VERSION,
        "base_plan.schema_version",
        &mut violations,
    );
    authority_check(
        is_uuid_v7(&plan.plan_id),
        "base_plan.plan_id",
        &mut violations,
    );
    authority_check(
        is_lowercase_sha256(&plan.obligation_snapshot_sha256),
        "base_plan.obligation_snapshot_sha256",
        &mut violations,
    );
    authority_check(
        is_lowercase_sha256(&plan.acceptance_policy_sha256),
        "base_plan.acceptance_policy_sha256",
        &mut violations,
    );
    authority_check(
        plan.strategy_summary.len() <= MAX_FIELD_BYTES,
        "base_plan.strategy_summary",
        &mut violations,
    );
    authority_check(
        (plan.revision == 0 && plan.parent_plan_sha256.is_none())
            || (plan.revision > 0
                && plan
                    .parent_plan_sha256
                    .as_deref()
                    .is_some_and(is_lowercase_sha256)),
        "base_plan.parent_plan_sha256",
        &mut violations,
    );
    authority_check(
        plan.work_orders.len() <= MAX_WORK_ORDERS,
        "base_plan.work_orders",
        &mut violations,
    );
    authority_check(
        plan.verification_targets.len() <= MAX_VERIFICATION_TARGETS,
        "base_plan.verification_targets",
        &mut violations,
    );
    let packet_ids = packet
        .entries
        .iter()
        .map(PlannerReplannerV2EvidenceEntry::evidence_id)
        .collect::<BTreeSet<_>>();
    for (key, target) in &plan.verification_targets {
        validate_base_target(key, target, obligations, &packet_ids, &mut violations);
    }
    for (key, work_order) in &plan.work_orders {
        validate_base_work_order(
            key,
            work_order,
            plan,
            obligations,
            &packet_ids,
            &mut violations,
        );
    }
    violations
}

fn validate_base_target(
    key: &str,
    target: &PlannerReplannerV2VerificationTarget,
    obligations: &PlannerReplannerV2ProtectedObligationCatalog,
    packet_ids: &BTreeSet<&str>,
    violations: &mut Vec<PlannerReplannerV2InvariantViolation>,
) {
    authority_check(
        key == target.id,
        "base_plan.verification_target.map_key",
        violations,
    );
    authority_check(
        is_plan_child_uuid(&target.id),
        "base_plan.verification_target.id",
        violations,
    );
    authority_check(
        !target.statement.trim().is_empty() && target.statement.len() <= MAX_FIELD_BYTES,
        "base_plan.verification_target.statement",
        violations,
    );
    validate_base_obligation_refs(&target.obligations, obligations, violations);
    validate_base_basis(&target.basis, packet_ids, violations);
}

fn validate_base_work_order(
    key: &str,
    work_order: &PlannerReplannerV2PlannedWorkOrder,
    plan: &PlannerReplannerV2PlanSnapshot,
    obligations: &PlannerReplannerV2ProtectedObligationCatalog,
    packet_ids: &BTreeSet<&str>,
    violations: &mut Vec<PlannerReplannerV2InvariantViolation>,
) {
    authority_check(
        key == work_order.id,
        "base_plan.work_order.map_key",
        violations,
    );
    authority_check(
        is_plan_child_uuid(&work_order.id),
        "base_plan.work_order.id",
        violations,
    );
    authority_check(
        !work_order.objective.trim().is_empty() && work_order.objective.len() <= MAX_FIELD_BYTES,
        "base_plan.work_order.objective",
        violations,
    );
    authority_check(
        work_order.dependencies.len() <= MAX_DEPENDENCIES
            && work_order
                .dependencies
                .iter()
                .all(|id| is_plan_child_uuid(id))
            && work_order
                .dependencies
                .iter()
                .all(|id| plan.work_orders.contains_key(id)),
        "base_plan.work_order.dependencies",
        violations,
    );
    authority_check(
        work_order
            .verification_targets
            .iter()
            .all(|id| is_plan_child_uuid(id) && plan.verification_targets.contains_key(id)),
        "base_plan.work_order.verification_targets",
        violations,
    );
    validate_base_obligation_refs(&work_order.obligations, obligations, violations);
    validate_base_basis(&work_order.basis, packet_ids, violations);
}

fn validate_base_obligation_refs(
    references: &BTreeSet<crate::planner_replanner::PlannerReplannerObligationRef>,
    obligations: &PlannerReplannerV2ProtectedObligationCatalog,
    violations: &mut Vec<PlannerReplannerV2InvariantViolation>,
) {
    authority_check(!references.is_empty(), "base_plan.obligations", violations);
    for reference in references {
        authority_check(
            obligations
                .obligations
                .get(&reference.id)
                .is_some_and(|obligation| obligation.content_sha256 == reference.content_sha256),
            "base_plan.obligation_ref",
            violations,
        );
    }
}

fn validate_base_basis(
    basis: &PlannerReplannerDecisionBasis,
    packet_ids: &BTreeSet<&str>,
    violations: &mut Vec<PlannerReplannerV2InvariantViolation>,
) {
    authority_check(
        !basis.evidence_ids.is_empty()
            && basis.evidence_ids.len() <= 64
            && !basis.rationale.trim().is_empty()
            && basis.rationale.len() <= MAX_FIELD_BYTES,
        "base_plan.basis",
        violations,
    );
    for evidence_id in &basis.evidence_ids {
        if !packet_ids.contains(evidence_id.as_str()) {
            violations.push(
                PlannerReplannerV2InvariantViolation::BasePlanEvidenceOmission {
                    evidence_id: evidence_id.clone(),
                },
            );
        }
    }
}

fn obligation_catalog_integrity_violations(
    catalog: &PlannerReplannerV2ProtectedObligationCatalog,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = Vec::new();
    authority_check(
        is_lowercase_sha256(&catalog.snapshot_sha256),
        "protected_obligation_catalog.snapshot_sha256",
        &mut violations,
    );
    authority_check(
        is_lowercase_sha256(&catalog.acceptance_policy_sha256),
        "protected_obligation_catalog.acceptance_policy_sha256",
        &mut violations,
    );
    authority_check(
        (1..=MAX_OBLIGATIONS).contains(&catalog.obligations.len()),
        "protected_obligation_catalog.obligations",
        &mut violations,
    );
    for (key, obligation) in &catalog.obligations {
        authority_check(
            key == &obligation.id && is_uuid_v7(&obligation.id),
            "protected_obligation_catalog.obligation.id",
            &mut violations,
        );
        authority_check(
            !obligation.statement.trim().is_empty()
                && obligation.statement.len() <= MAX_FIELD_BYTES,
            "protected_obligation_catalog.obligation.statement",
            &mut violations,
        );
        let statement_digest = format!("{:x}", Sha256::digest(obligation.statement.as_bytes()));
        authority_check(
            obligation.content_sha256 == statement_digest,
            "protected_obligation_catalog.obligation.content_sha256",
            &mut violations,
        );
    }
    authority_check(
        catalog.derived_snapshot_sha256().as_deref() == Ok(catalog.snapshot_sha256.as_str()),
        "protected_obligation_catalog.snapshot_sha256",
        &mut violations,
    );
    violations
}

fn context_catalog_integrity_violations(
    catalog: &PlannerReplannerV2ContextCatalog,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = Vec::new();
    authority_check(
        is_lowercase_sha256(&catalog.manifest_sha256),
        "planner_context_catalog.manifest_sha256",
        &mut violations,
    );
    authority_check(
        (1..=MAX_EVIDENCE_PACKET_ENTRIES).contains(&catalog.evidence_bindings.len()),
        "planner_context_catalog.evidence_bindings",
        &mut violations,
    );
    for binding in &catalog.evidence_bindings {
        authority_check(
            !binding.id.is_empty()
                && binding.id.len() <= MAX_EVIDENCE_ID_BYTES
                && is_lowercase_sha256(&binding.content_sha256),
            "planner_context_catalog.evidence_binding",
            &mut violations,
        );
    }
    authority_check(
        catalog
            .evidence_bindings
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id),
        "planner_context_catalog.evidence_bindings",
        &mut violations,
    );
    authority_check(
        catalog.derived_manifest_sha256().as_deref() == Ok(catalog.manifest_sha256.as_str()),
        "planner_context_catalog.manifest_sha256",
        &mut violations,
    );
    violations
}

fn policy_integrity_violations(
    policy: &PlannerReplannerV2Policy,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = Vec::new();
    let limits = policy.limits;
    authority_check(
        policy.maximum_access == crate::planner_replanner::PlannerReplannerAccess::ReadOnly,
        "planner_policy.maximum_access",
        &mut violations,
    );
    authority_check(
        (1..=wire_u32(MAX_WORK_ORDERS)).contains(&limits.max_work_orders)
            && (1..=wire_u32(MAX_VERIFICATION_TARGETS)).contains(&limits.max_verification_targets)
            && (1..=wire_u32(MAX_VERIFICATION_TARGETS)).contains(&limits.max_patch_operations)
            && (1..=wire_u32(MAX_DEPENDENCIES)).contains(&limits.max_dependencies_per_work_order)
            && (1..=64).contains(&limits.max_delegations)
            && (1..=16).contains(&limits.max_questions)
            && (1..=MAX_TEXT_BYTES as u64).contains(&limits.max_text_bytes),
        "planner_policy.limits",
        &mut violations,
    );
    authority_check(
        policy.derived_policy_sha256().as_deref() == Ok(policy.policy_sha256.as_str()),
        "planner_policy.policy_sha256",
        &mut violations,
    );
    violations
}

fn authority_check(
    valid: bool,
    field: &str,
    violations: &mut Vec<PlannerReplannerV2InvariantViolation>,
) {
    if !valid {
        violations.push(PlannerReplannerV2InvariantViolation::AuthorityIntegrity {
            field: field.to_owned(),
        });
    }
}

fn evidence_packet_violations(
    packet: &PlannerReplannerV2EvidencePacket,
    context: &PlannerReplannerV2ContextCatalog,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let mut violations = packet
        .validate_integrity()
        .err()
        .unwrap_or_default()
        .into_iter()
        .map(
            |violation| PlannerReplannerV2InvariantViolation::EvidencePacketIntegrity { violation },
        )
        .collect::<Vec<_>>();
    if packet.context_manifest_sha256 != context.manifest_sha256 {
        violations.push(PlannerReplannerV2InvariantViolation::EvidencePacketContextMismatch);
    }
    if context
        .evidence_bindings
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        violations.push(
            PlannerReplannerV2InvariantViolation::InvocationBindingMismatch {
                field: "planner_context_catalog.evidence_bindings".to_owned(),
            },
        );
    }
    let packet_bindings = packet
        .entries
        .iter()
        .map(|entry| (entry.evidence_id(), entry.normalized_content_sha256()))
        .collect::<BTreeMap<_, _>>();
    let context_bindings = context
        .evidence_bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding.content_sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for (evidence_id, expected_digest) in &context_bindings {
        match packet_bindings.get(evidence_id) {
            None => violations.push(
                PlannerReplannerV2InvariantViolation::EvidencePacketOmission {
                    evidence_id: (*evidence_id).to_owned(),
                },
            ),
            Some(actual_digest) if actual_digest != expected_digest => violations.push(
                PlannerReplannerV2InvariantViolation::EvidencePacketDigestMismatch {
                    evidence_id: (*evidence_id).to_owned(),
                },
            ),
            Some(_) => {}
        }
    }
    for evidence_id in packet_bindings.keys() {
        if !context_bindings.contains_key(*evidence_id) {
            violations.push(
                PlannerReplannerV2InvariantViolation::EvidencePacketUnknownId {
                    evidence_id: (*evidence_id).to_owned(),
                },
            );
        }
    }
    violations
}

fn binding_violations(
    actual: &PlannerReplannerV2Bindings,
    expected: &PlannerReplannerV2Bindings,
) -> Vec<PlannerReplannerV2InvariantViolation> {
    let actual = serde_json::to_value(actual)
        .expect("planner-replanner v2 bindings are infallibly serializable");
    let expected = serde_json::to_value(expected)
        .expect("planner-replanner v2 bindings are infallibly serializable");
    let Some(actual) = actual.as_object() else {
        return vec![PlannerReplannerV2InvariantViolation::BindingMismatch {
            field: "bindings".to_owned(),
        }];
    };
    expected
        .as_object()
        .expect("planner-replanner v2 bindings serialize as an object")
        .iter()
        .filter(|(field, value)| actual.get(*field) != Some(*value))
        .map(
            |(field, _)| PlannerReplannerV2InvariantViolation::BindingMismatch {
                field: field.clone(),
            },
        )
        .collect()
}

fn output_evidence_ids(output: &PlannerReplannerV2Output) -> Vec<&String> {
    let mut evidence = output.turn_basis.evidence_ids.iter().collect::<Vec<_>>();
    for target in &output.patch.add_verification_targets {
        evidence.extend(&target.basis.evidence_ids);
    }
    for work_order in &output.patch.add_work_orders {
        evidence.extend(&work_order.basis.evidence_ids);
    }
    for work_order in &output.patch.replace_work_orders {
        evidence.extend(&work_order.basis.evidence_ids);
    }
    for work_order in &output.patch.cancel_work_orders {
        evidence.extend(&work_order.basis.evidence_ids);
    }
    for delegation in &output.directive.delegations {
        evidence.extend(&delegation.basis.evidence_ids);
    }
    for clarification in &output.directive.clarifications {
        evidence.extend(&clarification.basis.evidence_ids);
    }
    for escalation in &output.directive.escalations {
        evidence.extend(&escalation.basis.evidence_ids);
    }
    for claim in &output.directive.finish_claims {
        evidence.extend(&claim.evidence_ids);
    }
    evidence
}

fn section_payload<'a>(invocation: &'a PromptInvocation, name: &str) -> Option<&'a Value> {
    invocation
        .sections
        .iter()
        .find(|section| section.name == name)
        .map(|section| &section.payload)
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EvidenceEntryHashMaterial<'a> {
    AcceptedRootPlan {
        schema_version: u32,
        evidence_id: &'a str,
        accepted_root_plan: &'a PlannerAcceptedRootPlanEvidenceV2,
    },
    ChildHandoff {
        schema_version: u32,
        evidence_id: &'a str,
        child_handoff: &'a PlannerVerifiedChildHandoffV2,
    },
    ChildFailed {
        schema_version: u32,
        evidence_id: &'a str,
        child_failed: &'a PlannerChildFailedV2,
    },
    ChildCancelled {
        schema_version: u32,
        evidence_id: &'a str,
        child_cancelled: &'a PlannerChildCancelledV2,
    },
}

#[derive(Serialize)]
struct EvidencePacketHashMaterial<'a> {
    schema_version: u32,
    purpose: PlannerReplannerV2Purpose,
    context_manifest_sha256: &'a str,
    entries: &'a [PlannerReplannerV2EvidenceEntry],
}

#[derive(Serialize)]
struct EvidenceDeltaHashMaterial<'a> {
    schema_version: u32,
    purpose: PlannerReplannerV2Purpose,
    previous_packet_sha256: &'a Option<String>,
    previous_evidence: &'a [PlannerReplannerV2EvidenceBinding],
    newly_available: &'a [PlannerReplannerV2EvidenceBinding],
}

#[derive(Serialize)]
struct ObligationCatalogHashMaterial<'a> {
    acceptance_policy_sha256: &'a str,
    obligations: &'a BTreeMap<String, PlannerReplannerV2ProtectedObligation>,
}

#[derive(Serialize)]
struct ContextCatalogHashMaterial<'a> {
    schema_version: u32,
    evidence_bindings: &'a [PlannerReplannerV2ContextEvidenceBinding],
}

#[derive(Serialize)]
struct PlannerPolicyHashMaterial<'a> {
    maximum_access: crate::planner_replanner::PlannerReplannerAccess,
    limits: &'a PlannerReplannerV2PolicyLimits,
}

#[derive(Serialize)]
struct ChildHandoffContentHashMaterial<'a> {
    status: crate::planner_replanner::PlannerChildHandoffStatus,
    summary: &'a str,
    findings: &'a [crate::planner_replanner::PlannerChildHandoffFinding],
    unknowns: &'a [crate::planner_replanner::PlannerChildHandoffUnknown],
    recommended_followups: &'a [crate::planner_replanner::PlannerChildHandoffRecommendedFollowup],
}

#[derive(Serialize)]
struct ChildHandoffArtifactHashMaterial<'a> {
    contract_version: u32,
    binding: &'a PlannerChildExecutionBinding,
    handoff_id: &'a str,
    content: ChildHandoffContentHashMaterial<'a>,
}

#[derive(Serialize)]
struct ChildFailureArtifactHashMaterial<'a> {
    contract_version: u32,
    binding: &'a PlannerChildExecutionBinding,
    kind: PlannerChildFailureKindV2,
    retry: PlannerChildRetryDispositionV2,
    diagnostic: &'a Value,
}

fn evidence_entry_sha256(entry: &PlannerReplannerV2EvidenceEntry) -> Result<String, String> {
    let material = match entry {
        PlannerReplannerV2EvidenceEntry::AcceptedRootPlan {
            evidence_id,
            accepted_root_plan,
            ..
        } => EvidenceEntryHashMaterial::AcceptedRootPlan {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            evidence_id,
            accepted_root_plan,
        },
        PlannerReplannerV2EvidenceEntry::ChildHandoff {
            evidence_id,
            child_handoff,
            ..
        } => EvidenceEntryHashMaterial::ChildHandoff {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            evidence_id,
            child_handoff,
        },
        PlannerReplannerV2EvidenceEntry::ChildFailed {
            evidence_id,
            child_failed,
            ..
        } => EvidenceEntryHashMaterial::ChildFailed {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            evidence_id,
            child_failed,
        },
        PlannerReplannerV2EvidenceEntry::ChildCancelled {
            evidence_id,
            child_cancelled,
            ..
        } => EvidenceEntryHashMaterial::ChildCancelled {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            evidence_id,
            child_cancelled,
        },
    };
    canonical_sha256(&material)
}

fn evidence_packet_sha256(packet: &PlannerReplannerV2EvidencePacket) -> Result<String, String> {
    canonical_sha256(&EvidencePacketHashMaterial {
        schema_version: packet.schema_version,
        purpose: packet.purpose,
        context_manifest_sha256: &packet.context_manifest_sha256,
        entries: &packet.entries,
    })
}

fn evidence_delta_sha256(delta: &PlannerReplannerV2EvidenceDelta) -> Result<String, String> {
    canonical_sha256(&EvidenceDeltaHashMaterial {
        schema_version: delta.schema_version,
        purpose: delta.purpose,
        previous_packet_sha256: &delta.previous_packet_sha256,
        previous_evidence: &delta.previous_evidence,
        newly_available: &delta.newly_available,
    })
}

fn evidence_binding(entry: &PlannerReplannerV2EvidenceEntry) -> PlannerReplannerV2EvidenceBinding {
    PlannerReplannerV2EvidenceBinding {
        evidence_id: entry.evidence_id().to_owned(),
        normalized_content_sha256: entry.normalized_content_sha256().to_owned(),
    }
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let encoded = crate::canonical::encode(&value).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(encoded.as_bytes())))
}

fn wire_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|encoded| format!("{:x}", Sha256::digest(encoded)))
        .map_err(|error| error.to_string())
}

fn wire_artifact_matches(value: &impl Serialize, artifact: &PlannerEvidenceArtifactRef) -> bool {
    serde_json::to_vec(value).is_ok_and(|encoded| {
        artifact.size_bytes == u64::try_from(encoded.len()).unwrap_or(u64::MAX)
            && artifact.sha256 == format!("{:x}", Sha256::digest(&encoded))
    })
}

fn child_handoff_artifact_sha256(handoff: &PlannerChildHandoff) -> Result<String, String> {
    wire_sha256(&ChildHandoffArtifactHashMaterial {
        contract_version: handoff.contract_version,
        binding: &handoff.binding,
        handoff_id: &handoff.handoff_id,
        content: ChildHandoffContentHashMaterial {
            status: handoff.status,
            summary: &handoff.summary,
            findings: &handoff.findings,
            unknowns: &handoff.unknowns,
            recommended_followups: &handoff.recommended_followups,
        },
    })
}

fn child_handoff_artifact_size(handoff: &PlannerChildHandoff) -> Option<u64> {
    serde_json::to_vec(&ChildHandoffArtifactHashMaterial {
        contract_version: handoff.contract_version,
        binding: &handoff.binding,
        handoff_id: &handoff.handoff_id,
        content: ChildHandoffContentHashMaterial {
            status: handoff.status,
            summary: &handoff.summary,
            findings: &handoff.findings,
            unknowns: &handoff.unknowns,
            recommended_followups: &handoff.recommended_followups,
        },
    })
    .ok()
    .and_then(|encoded| u64::try_from(encoded.len()).ok())
}

fn child_failure_artifact_sha256(failure: &PlannerChildFailedV2) -> Result<String, String> {
    wire_sha256(&ChildFailureArtifactHashMaterial {
        contract_version: failure.contract_version,
        binding: &failure.binding,
        kind: failure.kind,
        retry: failure.retry,
        diagnostic: &failure.diagnostic,
    })
}

fn child_failure_artifact_size(failure: &PlannerChildFailedV2) -> Option<u64> {
    serde_json::to_vec(&ChildFailureArtifactHashMaterial {
        contract_version: failure.contract_version,
        binding: &failure.binding,
        kind: failure.kind,
        retry: failure.retry,
        diagnostic: &failure.diagnostic,
    })
    .ok()
    .and_then(|encoded| u64::try_from(encoded.len()).ok())
}

fn evidence_entry_structure_violations(
    entry: &PlannerReplannerV2EvidenceEntry,
) -> Vec<PlannerReplannerV2EvidenceViolation> {
    let mut violations = Vec::new();
    let evidence_id_bytes = entry.evidence_id().len();
    if evidence_id_bytes == 0 {
        violations.push(PlannerReplannerV2EvidenceViolation::EmptyEvidenceId);
    } else if evidence_id_bytes > MAX_EVIDENCE_ID_BYTES {
        violations.push(PlannerReplannerV2EvidenceViolation::EvidenceIdTooLong {
            maximum: wire_u32(MAX_EVIDENCE_ID_BYTES),
            actual: wire_u32(evidence_id_bytes),
        });
    }
    match entry {
        PlannerReplannerV2EvidenceEntry::AcceptedRootPlan {
            accepted_root_plan, ..
        } => validate_accepted_root_plan(accepted_root_plan, &mut violations),
        PlannerReplannerV2EvidenceEntry::ChildHandoff { child_handoff, .. } => {
            validate_child_handoff(child_handoff, &mut violations);
        }
        PlannerReplannerV2EvidenceEntry::ChildFailed { child_failed, .. } => {
            validate_child_failed(child_failed, &mut violations);
        }
        PlannerReplannerV2EvidenceEntry::ChildCancelled {
            child_cancelled, ..
        } => validate_child_cancelled(child_cancelled, &mut violations),
    }
    violations
}

fn validate_accepted_root_plan(
    evidence: &PlannerAcceptedRootPlanEvidenceV2,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    validate_contract_version(
        "accepted_root_plan.contract_version",
        evidence.contract_version,
        violations,
    );
    validate_uuid(
        "accepted_root_plan.review_event_id",
        &evidence.review_event_id,
        violations,
    );
    validate_uuid(
        "accepted_root_plan.review_id",
        &evidence.review_id,
        violations,
    );
    validate_uuid(
        "accepted_root_plan.proposal_event_id",
        &evidence.proposal_event_id,
        violations,
    );
    validate_digest(
        "accepted_root_plan.plan_digest",
        &evidence.plan_digest,
        violations,
    );
    validate_artifact(
        "accepted_root_plan.plan_artifact",
        &evidence.plan_artifact,
        violations,
    );
    validate_artifact_media_type(
        "accepted_root_plan.plan_artifact",
        &evidence.plan_artifact,
        ACCEPTED_PLAN_MEDIA_TYPE,
        violations,
    );
    validate_artifact(
        "accepted_root_plan.critique_artifact",
        &evidence.critique_artifact,
        violations,
    );
    validate_artifact_media_type(
        "accepted_root_plan.critique_artifact",
        &evidence.critique_artifact,
        PLAN_CRITIQUE_MEDIA_TYPE,
        violations,
    );
    validate_artifact(
        "accepted_root_plan.validation_evidence_artifact",
        &evidence.validation_evidence_artifact,
        violations,
    );
    validate_artifact_media_type(
        "accepted_root_plan.validation_evidence_artifact",
        &evidence.validation_evidence_artifact,
        PLAN_VALIDATION_MEDIA_TYPE,
        violations,
    );
    if evidence.plan_artifact.sha256 != evidence.plan_digest {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidArtifact {
            field: "accepted_root_plan.plan_artifact.sha256".to_owned(),
        });
    }
    if !wire_artifact_matches(&evidence.plan, &evidence.plan_artifact) {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidArtifact {
            field: "accepted_root_plan.plan_artifact.content".to_owned(),
        });
    }
    if evidence.plan.schema_version != PLANNER_REPLANNER_V2_SOURCE_CONTRACT_VERSION
        || evidence.plan.directive != RootPlannerDirective::Plan
    {
        violations.push(PlannerReplannerV2EvidenceViolation::AcceptedRootPlanShape);
    }
}

fn validate_child_handoff(
    evidence: &PlannerVerifiedChildHandoffV2,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    validate_contract_version(
        "child_handoff.contract_version",
        evidence.contract_version,
        violations,
    );
    validate_uuid(
        "child_handoff.committed_event_id",
        &evidence.committed_event_id,
        violations,
    );
    validate_artifact(
        "child_handoff.handoff_artifact",
        &evidence.handoff_artifact,
        violations,
    );
    validate_artifact_media_type(
        "child_handoff.handoff_artifact",
        &evidence.handoff_artifact,
        CHILD_HANDOFF_MEDIA_TYPE,
        violations,
    );
    if child_handoff_artifact_sha256(&evidence.handoff).as_deref()
        != Ok(evidence.handoff_artifact.sha256.as_str())
        || child_handoff_artifact_size(&evidence.handoff)
            != Some(evidence.handoff_artifact.size_bytes)
    {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidArtifact {
            field: "child_handoff.handoff_artifact.content".to_owned(),
        });
    }
    if let Err(handoff_violations) = PlannerEvidenceEntry::new(PlannerEvidenceEntryMaterial {
        evidence_id: "v2-handoff-validation".to_owned(),
        source_artifact_sha256: evidence.handoff_artifact.sha256.clone(),
        handoff: evidence.handoff.clone(),
    }) {
        violations.extend(
            handoff_violations
                .into_iter()
                .map(|violation| PlannerReplannerV2EvidenceViolation::ChildHandoff { violation }),
        );
    }
}

fn validate_child_failed(
    evidence: &PlannerChildFailedV2,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    validate_contract_version(
        "child_failed.contract_version",
        evidence.contract_version,
        violations,
    );
    validate_child_binding("child_failed.binding", &evidence.binding, violations);
    validate_uuid(
        "child_failed.finished_event_id",
        &evidence.finished_event_id,
        violations,
    );
    validate_artifact(
        "child_failed.evidence_artifact",
        &evidence.evidence_artifact,
        violations,
    );
    validate_artifact_media_type(
        "child_failed.evidence_artifact",
        &evidence.evidence_artifact,
        CHILD_EXECUTION_FAILURE_MEDIA_TYPE,
        violations,
    );
    validate_digest(
        "child_failed.evidence_digest",
        &evidence.evidence_digest,
        violations,
    );
    let diagnostic_size = serde_json::to_vec(&evidence.diagnostic).map(|encoded| encoded.len());
    if evidence.diagnostic.is_null()
        || evidence.evidence_artifact.sha256 != evidence.evidence_digest
        || child_failure_artifact_sha256(evidence).as_deref()
            != Ok(evidence.evidence_digest.as_str())
        || child_failure_artifact_size(evidence) != Some(evidence.evidence_artifact.size_bytes)
        || diagnostic_size.is_err()
        || diagnostic_size.is_ok_and(|size| size > MAX_FAILURE_DIAGNOSTIC_BYTES)
    {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidArtifact {
            field: "child_failed.evidence_artifact.content".to_owned(),
        });
    }
    validate_child_failure_cause(evidence, violations);
}

fn validate_child_failure_cause(
    evidence: &PlannerChildFailedV2,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    match (&evidence.kind, &evidence.cause) {
        (
            PlannerChildFailureKindV2::Model,
            PlannerChildFailureCauseV2::ModelTerminal {
                terminal_event_id,
                model_call_id,
            },
        ) => {
            validate_uuid(
                "child_failed.cause.terminal_event_id",
                terminal_event_id,
                violations,
            );
            validate_uuid(
                "child_failed.cause.model_call_id",
                model_call_id,
                violations,
            );
        }
        (
            PlannerChildFailureKindV2::Tool,
            PlannerChildFailureCauseV2::ToolTerminal {
                terminal_event_id,
                tool_call_id,
            },
        ) => {
            validate_uuid(
                "child_failed.cause.terminal_event_id",
                terminal_event_id,
                violations,
            );
            validate_uuid("child_failed.cause.tool_call_id", tool_call_id, violations);
        }
        (
            PlannerChildFailureKindV2::Context
            | PlannerChildFailureKindV2::Budget
            | PlannerChildFailureKindV2::Protocol
            | PlannerChildFailureKindV2::DurableState,
            PlannerChildFailureCauseV2::RuntimeEvidence {
                evidence_artifact,
                evidence_digest,
            },
        ) => {
            validate_artifact(
                "child_failed.cause.evidence_artifact",
                evidence_artifact,
                violations,
            );
            validate_artifact_media_type(
                "child_failed.cause.evidence_artifact",
                evidence_artifact,
                CHILD_EXECUTION_FAILURE_MEDIA_TYPE,
                violations,
            );
            validate_digest(
                "child_failed.cause.evidence_digest",
                evidence_digest,
                violations,
            );
            if evidence_artifact.sha256 != *evidence_digest
                || evidence_artifact != &evidence.evidence_artifact
                || evidence_digest != &evidence.evidence_digest
            {
                violations.push(PlannerReplannerV2EvidenceViolation::FailureCauseMismatch);
            }
        }
        _ => violations.push(PlannerReplannerV2EvidenceViolation::FailureCauseMismatch),
    }
}

fn validate_child_cancelled(
    evidence: &PlannerChildCancelledV2,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    validate_contract_version(
        "child_cancelled.contract_version",
        evidence.contract_version,
        violations,
    );
    validate_child_binding("child_cancelled.binding", &evidence.binding, violations);
    validate_uuid(
        "child_cancelled.finished_event_id",
        &evidence.finished_event_id,
        violations,
    );
    validate_uuid(
        "child_cancelled.cause.request_event_id",
        &evidence.cause.request_event_id,
        violations,
    );
    validate_uuid(
        "child_cancelled.cause.request_id",
        &evidence.cause.request_id,
        violations,
    );
}

fn validate_child_binding(
    prefix: &str,
    binding: &PlannerChildExecutionBinding,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    if !is_plan_child_uuid(&binding.work_order_id) {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidIdentifier {
            field: format!("{prefix}.work_order_id"),
        });
    }
    for (field, identifier) in [
        ("execution_id", binding.execution_id.as_str()),
        ("attempt_id", binding.attempt_id.as_str()),
        ("child_actor_id", binding.child_actor_id.as_str()),
        ("context_id", binding.context_id.as_str()),
    ] {
        validate_uuid(&format!("{prefix}.{field}"), identifier, violations);
    }
    for (field, digest) in [
        ("work_order_digest", binding.work_order_digest.as_str()),
        (
            "context_manifest_digest",
            binding.context_manifest_digest.as_str(),
        ),
    ] {
        validate_digest(&format!("{prefix}.{field}"), digest, violations);
    }
}

fn validate_contract_version(
    field: &str,
    actual: u32,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    if actual != PLANNER_REPLANNER_V2_SOURCE_CONTRACT_VERSION {
        violations.push(
            PlannerReplannerV2EvidenceViolation::InvalidContractVersion {
                field: field.to_owned(),
                expected: PLANNER_REPLANNER_V2_SOURCE_CONTRACT_VERSION,
                actual,
            },
        );
    }
}

fn validate_artifact(
    field: &str,
    artifact: &PlannerEvidenceArtifactRef,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    validate_digest(&format!("{field}.sha256"), &artifact.sha256, violations);
    let media_bytes = artifact.media_type.len();
    if media_bytes == 0 || media_bytes > MAX_MEDIA_TYPE_BYTES {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidArtifact {
            field: format!("{field}.media_type"),
        });
    }
}

fn validate_artifact_media_type(
    field: &str,
    artifact: &PlannerEvidenceArtifactRef,
    expected: &str,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    if artifact.media_type != expected {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidArtifact {
            field: format!("{field}.media_type"),
        });
    }
}

fn validate_uuid(
    field: &str,
    value: &str,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    if !is_uuid_v7(value) {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidIdentifier {
            field: field.to_owned(),
        });
    }
}

fn validate_digest(
    field: &str,
    value: &str,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    if !is_lowercase_sha256(value) {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidDigest {
            field: field.to_owned(),
        });
    }
}

fn evidence_entry_integrity_violations(
    entry: &PlannerReplannerV2EvidenceEntry,
) -> Vec<PlannerReplannerV2EvidenceViolation> {
    let mut violations = evidence_entry_structure_violations(entry);
    if !is_lowercase_sha256(entry.normalized_content_sha256()) {
        violations.push(PlannerReplannerV2EvidenceViolation::InvalidDigest {
            field: "normalized_content_sha256".to_owned(),
        });
    }
    match evidence_entry_sha256(entry) {
        Ok(expected) if expected != entry.normalized_content_sha256() => violations.push(
            PlannerReplannerV2EvidenceViolation::NormalizedContentDigestMismatch {
                evidence_id: entry.evidence_id().to_owned(),
            },
        ),
        Ok(_) => {}
        Err(message) => {
            violations.push(PlannerReplannerV2EvidenceViolation::CanonicalEncoding { message });
        }
    }
    violations
}

fn evidence_source_event_id(entry: &PlannerReplannerV2EvidenceEntry) -> &str {
    match entry {
        PlannerReplannerV2EvidenceEntry::AcceptedRootPlan {
            accepted_root_plan, ..
        } => &accepted_root_plan.review_event_id,
        PlannerReplannerV2EvidenceEntry::ChildHandoff { child_handoff, .. } => {
            &child_handoff.committed_event_id
        }
        PlannerReplannerV2EvidenceEntry::ChildFailed { child_failed, .. } => {
            &child_failed.finished_event_id
        }
        PlannerReplannerV2EvidenceEntry::ChildCancelled {
            child_cancelled, ..
        } => &child_cancelled.finished_event_id,
    }
}

fn terminal_binding_key(
    entry: &PlannerReplannerV2EvidenceEntry,
) -> Option<(String, String, String)> {
    match entry {
        PlannerReplannerV2EvidenceEntry::AcceptedRootPlan { .. } => None,
        PlannerReplannerV2EvidenceEntry::ChildHandoff { child_handoff, .. } => Some((
            child_handoff.handoff.binding.work_order_id.clone(),
            child_handoff.handoff.binding.execution_id.clone(),
            child_handoff.handoff.binding.attempt_id.clone(),
        )),
        PlannerReplannerV2EvidenceEntry::ChildFailed { child_failed, .. } => Some((
            child_failed.binding.work_order_id.clone(),
            child_failed.binding.execution_id.clone(),
            child_failed.binding.attempt_id.clone(),
        )),
        PlannerReplannerV2EvidenceEntry::ChildCancelled {
            child_cancelled, ..
        } => Some((
            child_cancelled.binding.work_order_id.clone(),
            child_cancelled.binding.execution_id.clone(),
            child_cancelled.binding.attempt_id.clone(),
        )),
    }
}

fn evidence_packet_structure_violations(
    packet: &PlannerReplannerV2EvidencePacket,
) -> Vec<PlannerReplannerV2EvidenceViolation> {
    let mut violations = Vec::new();
    if packet.schema_version != EVIDENCE_PACKET_SCHEMA_VERSION {
        violations.push(PlannerReplannerV2EvidenceViolation::SchemaVersion {
            expected: EVIDENCE_PACKET_SCHEMA_VERSION,
            actual: packet.schema_version,
        });
    }
    validate_digest(
        "context_manifest_sha256",
        &packet.context_manifest_sha256,
        &mut violations,
    );
    if !(1..=MAX_EVIDENCE_PACKET_ENTRIES).contains(&packet.entries.len()) {
        violations.push(PlannerReplannerV2EvidenceViolation::EntryCount {
            minimum: 1,
            maximum: wire_u32(MAX_EVIDENCE_PACKET_ENTRIES),
            actual: wire_u32(packet.entries.len()),
        });
    }
    match packet.purpose {
        PlannerReplannerV2Purpose::InitialDelegation
            if packet.entries.len() != 1
                || packet
                    .entries
                    .first()
                    .map(PlannerReplannerV2EvidenceEntry::kind)
                    != Some(PlannerReplannerV2EvidenceKind::AcceptedRootPlan) =>
        {
            violations.push(PlannerReplannerV2EvidenceViolation::InitialDelegationEvidenceShape);
        }
        PlannerReplannerV2Purpose::EvidenceReplan
            if packet.entries.len() < 2
                || packet
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.kind() == PlannerReplannerV2EvidenceKind::AcceptedRootPlan
                    })
                    .count()
                    != 1
                || !packet.entries.iter().any(|entry| {
                    entry.kind() != PlannerReplannerV2EvidenceKind::AcceptedRootPlan
                }) =>
        {
            violations.push(PlannerReplannerV2EvidenceViolation::EvidenceReplanEvidenceShape);
        }
        _ => {}
    }
    let mut evidence_ids = BTreeSet::new();
    let mut source_event_ids = BTreeSet::new();
    let mut terminal_bindings = BTreeSet::new();
    let mut previous = None;
    for (index, entry) in packet.entries.iter().enumerate() {
        violations.extend(evidence_entry_integrity_violations(entry));
        if !evidence_ids.insert(entry.evidence_id()) {
            violations.push(PlannerReplannerV2EvidenceViolation::DuplicateEvidenceId {
                evidence_id: entry.evidence_id().to_owned(),
            });
        }
        let source_event_id = evidence_source_event_id(entry);
        if !source_event_ids.insert(source_event_id) {
            violations.push(PlannerReplannerV2EvidenceViolation::DuplicateSourceEvent {
                event_id: source_event_id.to_owned(),
            });
        }
        if let Some(binding) = terminal_binding_key(entry)
            && !terminal_bindings.insert(binding)
        {
            violations.push(PlannerReplannerV2EvidenceViolation::DuplicateTerminalBinding);
        }
        if previous.is_some_and(|previous: &str| previous >= entry.evidence_id()) {
            violations.push(PlannerReplannerV2EvidenceViolation::NonCanonicalOrder {
                index: wire_u32(index),
            });
        }
        previous = Some(entry.evidence_id());
    }
    match serde_json::to_vec(packet) {
        Ok(encoded) if encoded.len() > MAX_EVIDENCE_PACKET_BYTES => {
            violations.push(PlannerReplannerV2EvidenceViolation::PacketTooLarge {
                maximum: wire_u32(MAX_EVIDENCE_PACKET_BYTES),
                actual: wire_u32(encoded.len()),
            });
        }
        Ok(_) => {}
        Err(error) => violations.push(PlannerReplannerV2EvidenceViolation::CanonicalEncoding {
            message: error.to_string(),
        }),
    }
    violations
}

fn evidence_packet_integrity_violations(
    packet: &PlannerReplannerV2EvidencePacket,
) -> Vec<PlannerReplannerV2EvidenceViolation> {
    let mut violations = evidence_packet_structure_violations(packet);
    validate_digest("packet_sha256", &packet.packet_sha256, &mut violations);
    match evidence_packet_sha256(packet) {
        Ok(expected) if expected != packet.packet_sha256 => {
            violations.push(PlannerReplannerV2EvidenceViolation::PacketDigestMismatch);
        }
        Ok(_) => {}
        Err(message) => {
            violations.push(PlannerReplannerV2EvidenceViolation::CanonicalEncoding { message });
        }
    }
    violations
}

fn evidence_delta_structure_violations(
    delta: &PlannerReplannerV2EvidenceDelta,
    packet: &PlannerReplannerV2EvidencePacket,
) -> Vec<PlannerReplannerV2EvidenceViolation> {
    let mut violations = Vec::new();
    if delta.schema_version != EVIDENCE_PACKET_SCHEMA_VERSION {
        violations.push(PlannerReplannerV2EvidenceViolation::SchemaVersion {
            expected: EVIDENCE_PACKET_SCHEMA_VERSION,
            actual: delta.schema_version,
        });
    }
    if delta.purpose != packet.purpose {
        violations.push(PlannerReplannerV2EvidenceViolation::DeltaPurposeMismatch);
    }
    let packet_by_id = packet
        .entries
        .iter()
        .map(|entry| (entry.evidence_id(), entry))
        .collect::<BTreeMap<_, _>>();
    validate_delta_bindings(&delta.previous_evidence, &packet_by_id, &mut violations);
    validate_delta_bindings(&delta.newly_available, &packet_by_id, &mut violations);
    let previous_ids = delta
        .previous_evidence
        .iter()
        .map(|binding| binding.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let newly_available_ids = delta
        .newly_available
        .iter()
        .map(|binding| binding.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    if !previous_ids.is_disjoint(&newly_available_ids)
        || previous_ids
            .union(&newly_available_ids)
            .copied()
            .collect::<BTreeSet<_>>()
            != packet_by_id.keys().copied().collect::<BTreeSet<_>>()
    {
        violations.push(PlannerReplannerV2EvidenceViolation::DeltaShapeMismatch);
    }
    match delta.purpose {
        PlannerReplannerV2Purpose::InitialDelegation => {
            let valid = delta.previous_packet_sha256.is_none()
                && delta.previous_evidence.is_empty()
                && delta.newly_available.len() == 1
                && delta.newly_available.first().is_some_and(|binding| {
                    packet_by_id
                        .get(binding.evidence_id.as_str())
                        .is_some_and(|entry| {
                            entry.kind() == PlannerReplannerV2EvidenceKind::AcceptedRootPlan
                        })
                });
            if !valid {
                violations.push(PlannerReplannerV2EvidenceViolation::DeltaShapeMismatch);
            }
        }
        PlannerReplannerV2Purpose::EvidenceReplan => {
            let valid = delta
                .previous_packet_sha256
                .as_deref()
                .is_some_and(is_lowercase_sha256)
                && !delta.previous_evidence.is_empty()
                && delta.previous_evidence.iter().any(|binding| {
                    packet_by_id
                        .get(binding.evidence_id.as_str())
                        .is_some_and(|entry| {
                            entry.kind() == PlannerReplannerV2EvidenceKind::AcceptedRootPlan
                        })
                })
                && !delta.newly_available.is_empty()
                && delta.newly_available.iter().all(|binding| {
                    packet_by_id
                        .get(binding.evidence_id.as_str())
                        .is_some_and(|entry| {
                            entry.kind() != PlannerReplannerV2EvidenceKind::AcceptedRootPlan
                        })
                });
            if !valid {
                violations.push(PlannerReplannerV2EvidenceViolation::DeltaShapeMismatch);
            }
        }
    }
    violations
}

fn validate_delta_bindings(
    bindings: &[PlannerReplannerV2EvidenceBinding],
    packet_by_id: &BTreeMap<&str, &PlannerReplannerV2EvidenceEntry>,
    violations: &mut Vec<PlannerReplannerV2EvidenceViolation>,
) {
    let mut previous = None;
    let mut identities = BTreeSet::new();
    for binding in bindings {
        if previous.is_some_and(|previous: &str| previous >= binding.evidence_id.as_str())
            || !identities.insert(binding.evidence_id.as_str())
        {
            violations.push(PlannerReplannerV2EvidenceViolation::DeltaShapeMismatch);
        }
        previous = Some(binding.evidence_id.as_str());
        match packet_by_id.get(binding.evidence_id.as_str()) {
            None => violations.push(PlannerReplannerV2EvidenceViolation::DeltaUnknownEvidence {
                evidence_id: binding.evidence_id.clone(),
            }),
            Some(entry)
                if entry.normalized_content_sha256() != binding.normalized_content_sha256 =>
            {
                violations.push(PlannerReplannerV2EvidenceViolation::DeltaDigestMismatch {
                    evidence_id: binding.evidence_id.clone(),
                });
            }
            Some(_) => {}
        }
    }
}

fn evidence_delta_integrity_violations(
    delta: &PlannerReplannerV2EvidenceDelta,
    packet: &PlannerReplannerV2EvidencePacket,
) -> Vec<PlannerReplannerV2EvidenceViolation> {
    let mut violations = evidence_delta_structure_violations(delta, packet);
    validate_digest("delta_sha256", &delta.delta_sha256, &mut violations);
    match evidence_delta_sha256(delta) {
        Ok(expected) if expected != delta.delta_sha256 => {
            violations.push(PlannerReplannerV2EvidenceViolation::DeltaSha256Mismatch);
        }
        Ok(_) => {}
        Err(message) => {
            violations.push(PlannerReplannerV2EvidenceViolation::CanonicalEncoding { message });
        }
    }
    violations
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn bundled_manifest_sha256() -> String {
    crate::manifest::parse_manifest(crate::manifest::PLANNER_REPLANNER_V2_MANIFEST_JSON.as_bytes())
        .and_then(|manifest| manifest.content_sha256())
        .expect("bundled planner-replanner-v2 manifest must remain valid")
}

fn is_uuid_v7(value: &str) -> bool {
    is_uuid_with_version(value, b'7')
}

/// Plan-child identities are either externally allocated `UUIDv7` values or the
/// deterministic RFC 9562 `UUIDv8` values produced by the authoritative plan
/// transition. Event, execution, budget, plan, and obligation identities stay
/// UUIDv7-only and use [`is_uuid_v7`] instead.
fn is_plan_child_uuid(value: &str) -> bool {
    is_uuid_with_version(value, b'7') || is_uuid_with_version(value, b'8')
}

fn is_uuid_with_version(value: &str, version: u8) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == version
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
        })
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
