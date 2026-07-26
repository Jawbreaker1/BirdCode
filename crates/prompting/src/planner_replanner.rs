//! Stable prompt DTOs for one semantic planner or replanner turn.
//!
//! This module owns only the provider-neutral wire contract. The durable plan
//! domain and its authoritative `validate_and_apply` transition remain in the
//! orchestrator crate, which deliberately depends on this crate in one
//! direction.

use crate::compiler::{
    DataProvenance, DataSection, PromptInvocation, PromptLimits, RuntimeConstraint, SourceKind,
    TrustLevel,
};
use crate::{PromptId, PromptKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const PLANNER_REPLANNER_ID: &str = "birdcode.planner-replanner";
const BASE_PLAN_SECTION: &str = "base_plan";
const OBLIGATION_CATALOG_SECTION: &str = "protected_obligation_catalog";
const CONTEXT_CATALOG_SECTION: &str = "planner_context_catalog";
const EVIDENCE_PACKET_SECTION: &str = "planner_evidence_packet";
const POLICY_CONSTRAINT: &str = "planner_policy";
const BINDINGS_CONSTRAINT: &str = "planner_turn_bindings";
const EVIDENCE_PACKET_SCHEMA_VERSION: u32 = 1;
const MAX_EVIDENCE_PACKET_ENTRIES: usize = 256;
const MAX_EVIDENCE_PACKET_BYTES: usize = 1024 * 1024;
const MAX_EVIDENCE_FINDINGS: usize = 64;
const MAX_EVIDENCE_UNKNOWNS: usize = 64;
const MAX_EVIDENCE_FOLLOWUPS: usize = 64;
const MAX_EVIDENCE_REFERENCES: usize = 64;
const MAX_EVIDENCE_SUMMARY_CHARACTERS: usize = 16_384;
const MAX_EVIDENCE_TEXT_CHARACTERS: usize = 8_192;
const MAX_EVIDENCE_FINDING_ID_CHARACTERS: usize = 128;
const MAX_EVIDENCE_ID_CHARACTERS: usize = 512;
const MAX_EVIDENCE_STABLE_ID_CHARACTERS: usize = 128;
const MAX_EVIDENCE_MEDIA_TYPE_CHARACTERS: usize = 256;

/// Exact echo bindings for one planner/replanner inference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerBindings {
    pub plan_id: String,
    pub base_revision: u64,
    pub base_plan_sha256: String,
    pub obligation_snapshot_sha256: String,
    pub acceptance_policy_sha256: String,
    pub context_manifest_sha256: String,
    pub planner_policy_sha256: String,
}

/// Normalized evidence source visible to the semantic replanner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerEvidenceKind {
    ChildHandoff,
}

/// Confidence copied losslessly from the normalized child handoff.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerChildFindingConfidence {
    Low,
    Medium,
    High,
}

/// Terminal status copied losslessly from the normalized child handoff.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerChildHandoffStatus {
    Complete,
    Partial,
    Blocked,
}

/// Exact content-addressed artifact reference used by evidence citations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerEvidenceArtifactRef {
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
}

/// Immutable child-execution identity copied from the handoff wire.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildExecutionBinding {
    pub work_order_id: String,
    pub execution_id: String,
    pub attempt_id: String,
    pub child_actor_id: String,
    pub context_id: String,
    pub work_order_digest: String,
    pub context_manifest_digest: String,
}

/// Exact successful tool observation supporting one child finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildHandoffEvidenceBinding {
    pub tool_call_id: String,
    pub observed_event_id: String,
    pub result_artifact: PlannerEvidenceArtifactRef,
}

/// One bounded affirmative finding from a normalized child handoff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildHandoffFinding {
    pub finding_id: String,
    pub statement: String,
    pub confidence: PlannerChildFindingConfidence,
    pub evidence: Vec<PlannerChildHandoffEvidenceBinding>,
}

/// One stable unresolved question copied from a normalized child handoff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildHandoffUnknown {
    pub unknown_id: String,
    pub question: String,
}

/// One stable recommended follow-up copied from a normalized child handoff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildHandoffRecommendedFollowup {
    pub followup_id: String,
    pub text: String,
}

/// Full bounded normalized child-handoff wire visible to the replanner.
///
/// This deliberately mirrors the protocol handoff instead of reducing it to
/// common summary strings. Status, execution identity, confidence, exact tool
/// citations, stable unknown identities, and follow-ups remain available for
/// semantic replanning and provenance review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChildHandoff {
    pub contract_version: u32,
    pub binding: PlannerChildExecutionBinding,
    pub handoff_id: String,
    pub status: PlannerChildHandoffStatus,
    pub summary: String,
    pub findings: Vec<PlannerChildHandoffFinding>,
    pub unknowns: Vec<PlannerChildHandoffUnknown>,
    pub recommended_followups: Vec<PlannerChildHandoffRecommendedFollowup>,
}

/// Constructor material whose content digest is derived locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerEvidenceEntryMaterial {
    pub evidence_id: String,
    pub source_artifact_sha256: String,
    pub handoff: PlannerChildHandoff,
}

/// One content-addressed normalized evidence item.
///
/// There is intentionally no raw transcript, command output, tool request,
/// grant, workspace, model, or role field in this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum PlannerEvidenceEntry {
    ChildHandoff {
        evidence_id: String,
        source_artifact_sha256: String,
        handoff: PlannerChildHandoff,
        normalized_content_sha256: String,
    },
}

impl PlannerEvidenceEntry {
    /// Builds a bounded normalized entry and derives its content address.
    ///
    /// # Errors
    ///
    /// Returns every mechanical field, bound, uniqueness, or digest defect.
    pub fn new(
        material: PlannerEvidenceEntryMaterial,
    ) -> Result<Self, Vec<PlannerEvidencePacketViolation>> {
        let mut entry = Self::ChildHandoff {
            evidence_id: material.evidence_id,
            source_artifact_sha256: material.source_artifact_sha256,
            handoff: material.handoff,
            normalized_content_sha256: String::new(),
        };
        let violations = evidence_entry_structure_violations(&entry);
        if !violations.is_empty() {
            return Err(violations);
        }
        let digest = evidence_entry_sha256(&entry).map_err(|message| {
            vec![PlannerEvidencePacketViolation::CanonicalEncoding { message }]
        })?;
        *entry.normalized_content_sha256_mut() = digest;
        Ok(entry)
    }

    #[must_use]
    pub fn evidence_id(&self) -> &str {
        match self {
            Self::ChildHandoff { evidence_id, .. } => evidence_id,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> PlannerEvidenceKind {
        match self {
            Self::ChildHandoff { .. } => PlannerEvidenceKind::ChildHandoff,
        }
    }

    #[must_use]
    pub fn source_artifact_sha256(&self) -> &str {
        match self {
            Self::ChildHandoff {
                source_artifact_sha256,
                ..
            } => source_artifact_sha256,
        }
    }

    #[must_use]
    pub fn normalized_content_sha256(&self) -> &str {
        match self {
            Self::ChildHandoff {
                normalized_content_sha256,
                ..
            } => normalized_content_sha256,
        }
    }

    fn normalized_content_sha256_mut(&mut self) -> &mut String {
        match self {
            Self::ChildHandoff {
                normalized_content_sha256,
                ..
            } => normalized_content_sha256,
        }
    }

    /// Verifies bounded fields and re-derives the normalized content address.
    ///
    /// # Errors
    ///
    /// Returns every detected mechanical integrity violation.
    pub fn validate_integrity(&self) -> Result<(), Vec<PlannerEvidencePacketViolation>> {
        let violations = evidence_entry_integrity_violations(self);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Content-addressed, bounded context supplied as untrusted tool data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerEvidencePacket {
    pub schema_version: u32,
    pub context_manifest_sha256: String,
    pub entries: Vec<PlannerEvidenceEntry>,
    pub packet_sha256: String,
}

impl PlannerEvidencePacket {
    /// Builds a canonical packet ordered by opaque evidence identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed entries, duplicates, over-limit content, and invalid
    /// context digests before deriving the packet content address.
    pub fn new(
        context_manifest_sha256: impl Into<String>,
        mut entries: Vec<PlannerEvidenceEntry>,
    ) -> Result<Self, Vec<PlannerEvidencePacketViolation>> {
        entries.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
        let mut packet = Self {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            context_manifest_sha256: context_manifest_sha256.into(),
            entries,
            packet_sha256: String::new(),
        };
        let violations = evidence_packet_structure_violations(&packet);
        if !violations.is_empty() {
            return Err(violations);
        }
        packet.packet_sha256 = evidence_packet_sha256(&packet).map_err(|message| {
            vec![PlannerEvidencePacketViolation::CanonicalEncoding { message }]
        })?;
        packet.validate_integrity()?;
        Ok(packet)
    }

    /// Revalidates every entry, canonical order, aggregate bound, and digest.
    ///
    /// # Errors
    ///
    /// Returns every safely collectable mechanical integrity violation.
    pub fn validate_integrity(&self) -> Result<(), Vec<PlannerEvidencePacketViolation>> {
        let violations = evidence_packet_integrity_violations(self);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Mechanical normalized-evidence defect. No variant classifies prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerEvidencePacketViolation {
    SchemaVersion {
        expected: u32,
        actual: u32,
    },
    HandoffContractVersion {
        expected: u32,
        actual: u32,
    },
    InvalidDigest {
        field: String,
    },
    EntryCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    EmptyEvidenceId {
        index: u32,
    },
    EvidenceIdTooLong {
        index: u32,
        maximum: u32,
        actual: u32,
    },
    DuplicateEvidenceId {
        evidence_id: String,
    },
    NonCanonicalOrder {
        index: u32,
    },
    EmptyText {
        field: String,
    },
    TextTooLong {
        field: String,
        maximum: u32,
        actual: u32,
    },
    FindingCount {
        entry_index: u32,
        maximum: u32,
        actual: u32,
    },
    UnknownCount {
        entry_index: u32,
        maximum: u32,
        actual: u32,
    },
    FollowupCount {
        entry_index: u32,
        maximum: u32,
        actual: u32,
    },
    EvidenceReferenceCount {
        entry_index: u32,
        finding_index: u32,
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    DuplicateFindingId {
        entry_index: u32,
        finding_id: String,
    },
    DuplicateUnknownId {
        entry_index: u32,
        unknown_id: String,
    },
    DuplicateFollowupId {
        entry_index: u32,
        followup_id: String,
    },
    NormalizedContentDigestMismatch {
        evidence_id: String,
    },
    PacketDigestMismatch,
    PacketTooLarge {
        maximum: u32,
        actual: u32,
    },
    CanonicalEncoding {
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReplannerAccess {
    None,
    ReadOnly,
    WorkspaceWrite,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PlannerReplannerLocalWorkOrderId(pub u32);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PlannerReplannerLocalVerificationTargetId(pub u32);

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerObligationRef {
    pub id: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerDecisionBasis {
    pub evidence_ids: BTreeSet<String>,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerNewVerificationTarget {
    pub local_id: PlannerReplannerLocalVerificationTargetId,
    pub statement: String,
    pub obligations: BTreeSet<PlannerReplannerObligationRef>,
    pub basis: PlannerReplannerDecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerNewWorkOrder {
    pub local_id: PlannerReplannerLocalWorkOrderId,
    pub objective: String,
    pub obligations: BTreeSet<PlannerReplannerObligationRef>,
    pub existing_dependencies: BTreeSet<String>,
    pub new_dependencies: BTreeSet<PlannerReplannerLocalWorkOrderId>,
    pub existing_verification_targets: BTreeSet<String>,
    pub new_verification_targets: BTreeSet<PlannerReplannerLocalVerificationTargetId>,
    pub required_access: PlannerReplannerAccess,
    pub basis: PlannerReplannerDecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerProtectedWorkOrderRef {
    pub id: String,
    pub revision_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerReplaceWorkOrder {
    pub target: PlannerReplannerProtectedWorkOrderRef,
    pub objective: String,
    pub obligations: BTreeSet<PlannerReplannerObligationRef>,
    pub existing_dependencies: BTreeSet<String>,
    pub new_dependencies: BTreeSet<PlannerReplannerLocalWorkOrderId>,
    pub existing_verification_targets: BTreeSet<String>,
    pub new_verification_targets: BTreeSet<PlannerReplannerLocalVerificationTargetId>,
    pub required_access: PlannerReplannerAccess,
    pub basis: PlannerReplannerDecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerCancelWorkOrder {
    pub target: PlannerReplannerProtectedWorkOrderRef,
    pub basis: PlannerReplannerDecisionBasis,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerPlanPatch {
    pub strategy_summary: Option<String>,
    pub add_verification_targets: Vec<PlannerReplannerNewVerificationTarget>,
    pub add_work_orders: Vec<PlannerReplannerNewWorkOrder>,
    pub replace_work_orders: Vec<PlannerReplannerReplaceWorkOrder>,
    pub cancel_work_orders: Vec<PlannerReplannerCancelWorkOrder>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerWorkSelection {
    pub existing: BTreeSet<String>,
    pub new: BTreeSet<PlannerReplannerLocalWorkOrderId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerDelegationRequest {
    pub work_orders: PlannerReplannerWorkSelection,
    pub basis: PlannerReplannerDecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerClarificationRequest {
    pub question: String,
    pub blocked_obligations: BTreeSet<PlannerReplannerObligationRef>,
    pub basis: PlannerReplannerDecisionBasis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReplannerEscalationKind {
    Authority,
    Budget,
    ModelCapability,
    HumanDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerEscalationRequest {
    pub kind: PlannerReplannerEscalationKind,
    pub request: String,
    pub blocked_obligations: BTreeSet<PlannerReplannerObligationRef>,
    pub basis: PlannerReplannerDecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerFinishClaim {
    pub obligation: PlannerReplannerObligationRef,
    pub evidence_ids: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerReplannerDirectiveKind {
    Execute,
    Delegate,
    Clarify,
    Escalate,
    Finish,
}

/// Fixed-shape directive. Unused collections must be empty; the orchestrator
/// enforces that semantic branch invariant after decoding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerDirective {
    pub kind: PlannerReplannerDirectiveKind,
    pub execute: PlannerReplannerWorkSelection,
    pub delegations: Vec<PlannerReplannerDelegationRequest>,
    pub clarifications: Vec<PlannerReplannerClarificationRequest>,
    pub escalations: Vec<PlannerReplannerEscalationRequest>,
    pub finish_claims: Vec<PlannerReplannerFinishClaim>,
}

/// Provider-neutral DTO exactly isomorphic to the orchestrator's
/// `PlannerTurnProposal` wire shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerOutput {
    pub schema_version: u32,
    pub bindings: PlannerReplannerBindings,
    pub patch: PlannerReplannerPlanPatch,
    pub directive: PlannerReplannerDirective,
}

/// Exact serialized domain inputs supplied by the orchestrator adapter.
///
/// Values remain deliberately opaque here: this crate cannot depend on the
/// orchestrator domain without creating a circular dependency. The bundled
/// input schema checks their wire shapes and the adapter constructs them only
/// by serializing the corresponding authoritative Rust values.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannerReplannerInvocationMaterial {
    pub base_plan: Value,
    pub protected_obligation_catalog: Value,
    pub planner_context_catalog: Value,
    pub evidence_packet: PlannerEvidencePacket,
    pub planner_policy: Value,
    pub bindings: PlannerReplannerBindings,
}

/// Mechanical defects checked at the prompt trust boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerReplannerInvariantViolation {
    TypedOutputDecode {
        message: String,
    },
    RuntimeConstraintShape,
    MissingContextCatalog,
    ContextCatalogDecode {
        message: String,
    },
    MissingEvidencePacket,
    EvidencePacketDecode {
        message: String,
    },
    EvidencePacketIntegrity {
        violation: PlannerEvidencePacketViolation,
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextCatalogWire {
    #[serde(rename = "manifest_sha256")]
    manifest_sha256: String,
    evidence_bindings: Vec<ContextEvidenceBindingWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextEvidenceBindingWire {
    id: String,
    content_sha256: String,
}

/// Returns the immutable bundled key for the semantic planner/replanner.
///
/// # Panics
///
/// Panics only if the compile-time identifier is invalid.
#[must_use]
pub fn planner_replanner_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(PLANNER_REPLANNER_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 0, 0),
    )
}

pub(crate) fn is_planner_replanner_key(key: &PromptKey) -> bool {
    key == &planner_replanner_key()
}

/// Compiles exact domain serializations into explicitly trust-labelled input.
#[must_use]
pub fn planner_replanner_invocation(
    material: PlannerReplannerInvocationMaterial,
) -> PromptInvocation {
    let bindings = &material.bindings;
    let evidence_packet_sha256 = material.evidence_packet.packet_sha256.clone();
    let evidence_packet_payload = serde_json::json!({
        "schema_version": material.evidence_packet.schema_version,
        "context_manifest_sha256": material.evidence_packet.context_manifest_sha256,
        "entries": material.evidence_packet.entries,
        "packet_sha256": material.evidence_packet.packet_sha256,
    });
    let binding_payload = serde_json::json!({
        "plan_id": bindings.plan_id,
        "base_revision": bindings.base_revision,
        "base_plan_sha256": bindings.base_plan_sha256,
        "obligation_snapshot_sha256": bindings.obligation_snapshot_sha256,
        "acceptance_policy_sha256": bindings.acceptance_policy_sha256,
        "context_manifest_sha256": bindings.context_manifest_sha256,
        "planner_policy_sha256": bindings.planner_policy_sha256,
    });
    let sections = vec![
        DataSection {
            name: BASE_PLAN_SECTION.to_owned(),
            trust: TrustLevel::UntrustedExternal,
            provenance: DataProvenance {
                source_kind: SourceKind::External,
                source_id: format!(
                    "accepted-plan:{}:{}",
                    bindings.plan_id, bindings.base_revision
                ),
                artifact_sha256: Some(bindings.base_plan_sha256.clone()),
                event_id: None,
            },
            payload: material.base_plan,
        },
        DataSection {
            name: OBLIGATION_CATALOG_SECTION.to_owned(),
            trust: TrustLevel::User,
            provenance: DataProvenance {
                source_kind: SourceKind::User,
                source_id: "protected-obligation-catalog".to_owned(),
                artifact_sha256: Some(bindings.obligation_snapshot_sha256.clone()),
                event_id: None,
            },
            payload: material.protected_obligation_catalog,
        },
        DataSection {
            name: CONTEXT_CATALOG_SECTION.to_owned(),
            trust: TrustLevel::Tool,
            provenance: DataProvenance {
                source_kind: SourceKind::Tool,
                source_id: "planner-context-catalog".to_owned(),
                artifact_sha256: Some(bindings.context_manifest_sha256.clone()),
                event_id: None,
            },
            payload: material.planner_context_catalog,
        },
        DataSection {
            name: EVIDENCE_PACKET_SECTION.to_owned(),
            trust: TrustLevel::Tool,
            provenance: DataProvenance {
                source_kind: SourceKind::Tool,
                source_id: "normalized-planner-evidence".to_owned(),
                artifact_sha256: Some(evidence_packet_sha256),
                event_id: None,
            },
            payload: evidence_packet_payload,
        },
    ];
    PromptInvocation::with_runtime_constraints(
        sections,
        PromptLimits::new(0),
        vec![
            RuntimeConstraint {
                name: POLICY_CONSTRAINT.to_owned(),
                payload: material.planner_policy,
            },
            RuntimeConstraint {
                name: BINDINGS_CONSTRAINT.to_owned(),
                payload: binding_payload,
            },
        ],
    )
}

/// Validates exact echo bindings and evidence membership after JSON Schema.
///
/// Semantic plan correctness, obligation coverage, graph validity, access,
/// policy limits, and the state transition are intentionally left to the
/// orchestrator's authoritative `PlannerTurnProposal::validate_and_apply`.
///
/// # Errors
///
/// Returns every safely collectable mechanical prompt-boundary violation.
pub fn validate_planner_replanner_output(
    value: &Value,
    invocation: &PromptInvocation,
) -> Result<(), Vec<PlannerReplannerInvariantViolation>> {
    let output =
        serde_json::from_value::<PlannerReplannerOutput>(value.clone()).map_err(|error| {
            vec![PlannerReplannerInvariantViolation::TypedOutputDecode {
                message: error.to_string(),
            }]
        })?;
    let validated = validate_invocation(invocation)?;
    let mut violations = binding_violations(&output.bindings, &validated.bindings);
    for evidence_id in output_evidence_ids(&output) {
        if !validated.evidence_ids.contains(evidence_id) {
            violations.push(PlannerReplannerInvariantViolation::UnknownEvidenceId {
                evidence_id: evidence_id.clone(),
            });
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Validates the independently supplied prompt input before inference.
///
/// # Errors
///
/// Rejects malformed runtime constraints, substituted or omitted evidence,
/// mismatched content addresses, unbound provenance, and over-limit packets.
pub fn validate_planner_replanner_invocation(
    invocation: &PromptInvocation,
) -> Result<(), Vec<PlannerReplannerInvariantViolation>> {
    validate_invocation(invocation).map(|_| ())
}

struct ValidatedPlannerReplannerInvocation {
    bindings: PlannerReplannerBindings,
    evidence_ids: BTreeSet<String>,
}

fn validate_invocation(
    invocation: &PromptInvocation,
) -> Result<ValidatedPlannerReplannerInvocation, Vec<PlannerReplannerInvariantViolation>> {
    let Some(bindings) = exact_bindings_constraint(invocation) else {
        return Err(vec![
            PlannerReplannerInvariantViolation::RuntimeConstraintShape,
        ]);
    };
    let context = decode_context_catalog(invocation)?;
    let packet = decode_evidence_packet(invocation)?;
    let mut violations = invocation_binding_violations(invocation, &bindings);
    violations.extend(evidence_packet_violations(&packet, &context));
    if violations.is_empty() {
        Ok(ValidatedPlannerReplannerInvocation {
            bindings,
            evidence_ids: packet
                .entries
                .into_iter()
                .map(|entry| entry.evidence_id().to_owned())
                .collect(),
        })
    } else {
        Err(violations)
    }
}

fn decode_context_catalog(
    invocation: &PromptInvocation,
) -> Result<ContextCatalogWire, Vec<PlannerReplannerInvariantViolation>> {
    let Some(value) = section_payload(invocation, CONTEXT_CATALOG_SECTION) else {
        return Err(vec![
            PlannerReplannerInvariantViolation::MissingContextCatalog,
        ]);
    };
    serde_json::from_value::<ContextCatalogWire>(value.clone()).map_err(|error| {
        vec![PlannerReplannerInvariantViolation::ContextCatalogDecode {
            message: error.to_string(),
        }]
    })
}

fn decode_evidence_packet(
    invocation: &PromptInvocation,
) -> Result<PlannerEvidencePacket, Vec<PlannerReplannerInvariantViolation>> {
    let Some(value) = section_payload(invocation, EVIDENCE_PACKET_SECTION) else {
        return Err(vec![
            PlannerReplannerInvariantViolation::MissingEvidencePacket,
        ]);
    };
    serde_json::from_value::<PlannerEvidencePacket>(value.clone()).map_err(|error| {
        vec![PlannerReplannerInvariantViolation::EvidencePacketDecode {
            message: error.to_string(),
        }]
    })
}

fn evidence_packet_violations(
    packet: &PlannerEvidencePacket,
    context: &ContextCatalogWire,
) -> Vec<PlannerReplannerInvariantViolation> {
    let mut violations = packet
        .validate_integrity()
        .err()
        .unwrap_or_default()
        .into_iter()
        .map(|violation| PlannerReplannerInvariantViolation::EvidencePacketIntegrity { violation })
        .collect::<Vec<_>>();
    if packet.context_manifest_sha256 != context.manifest_sha256 {
        violations.push(PlannerReplannerInvariantViolation::EvidencePacketContextMismatch);
    }
    if context
        .evidence_bindings
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        violations.push(
            PlannerReplannerInvariantViolation::InvocationBindingMismatch {
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
            None => violations.push(PlannerReplannerInvariantViolation::EvidencePacketOmission {
                evidence_id: (*evidence_id).to_owned(),
            }),
            Some(actual_digest) if actual_digest != expected_digest => violations.push(
                PlannerReplannerInvariantViolation::EvidencePacketDigestMismatch {
                    evidence_id: (*evidence_id).to_owned(),
                },
            ),
            Some(_) => {}
        }
    }
    for evidence_id in packet_bindings.keys() {
        if !context_bindings.contains_key(*evidence_id) {
            violations.push(
                PlannerReplannerInvariantViolation::EvidencePacketUnknownId {
                    evidence_id: (*evidence_id).to_owned(),
                },
            );
        }
    }
    violations
}

fn invocation_binding_violations(
    invocation: &PromptInvocation,
    bindings: &PlannerReplannerBindings,
) -> Vec<PlannerReplannerInvariantViolation> {
    let mut violations = Vec::new();
    let base_plan = section_payload(invocation, BASE_PLAN_SECTION);
    let obligations = section_payload(invocation, OBLIGATION_CATALOG_SECTION);
    let context = section_payload(invocation, CONTEXT_CATALOG_SECTION);
    let policy = invocation
        .runtime_constraints
        .first()
        .filter(|constraint| constraint.name == POLICY_CONSTRAINT)
        .map(|constraint| &constraint.payload);

    for (field, actual, expected) in [
        (
            "base_plan.plan_id",
            base_plan.and_then(|value| value.get("plan_id")),
            Value::String(bindings.plan_id.clone()),
        ),
        (
            "base_plan.revision",
            base_plan.and_then(|value| value.get("revision")),
            Value::from(bindings.base_revision),
        ),
        (
            "base_plan.obligation_snapshot_sha256",
            base_plan.and_then(|value| value.get("obligation_snapshot_sha256")),
            Value::String(bindings.obligation_snapshot_sha256.clone()),
        ),
        (
            "base_plan.acceptance_policy_sha256",
            base_plan.and_then(|value| value.get("acceptance_policy_sha256")),
            Value::String(bindings.acceptance_policy_sha256.clone()),
        ),
        (
            "protected_obligation_catalog.snapshot_sha256",
            obligations.and_then(|value| value.get("snapshot_sha256")),
            Value::String(bindings.obligation_snapshot_sha256.clone()),
        ),
        (
            "protected_obligation_catalog.acceptance_policy_sha256",
            obligations.and_then(|value| value.get("acceptance_policy_sha256")),
            Value::String(bindings.acceptance_policy_sha256.clone()),
        ),
        (
            "planner_context_catalog.manifest_sha256",
            context.and_then(|value| value.get("manifest_sha256")),
            Value::String(bindings.context_manifest_sha256.clone()),
        ),
        (
            "planner_policy.policy_sha256",
            policy.and_then(|value| value.get("policy_sha256")),
            Value::String(bindings.planner_policy_sha256.clone()),
        ),
    ] {
        if actual != Some(&expected) {
            violations.push(
                PlannerReplannerInvariantViolation::InvocationBindingMismatch {
                    field: field.to_owned(),
                },
            );
        }
    }

    for (section_name, expected) in [
        (BASE_PLAN_SECTION, &bindings.base_plan_sha256),
        (
            OBLIGATION_CATALOG_SECTION,
            &bindings.obligation_snapshot_sha256,
        ),
        (CONTEXT_CATALOG_SECTION, &bindings.context_manifest_sha256),
    ] {
        let actual = invocation
            .sections
            .iter()
            .find(|section| section.name == section_name)
            .and_then(|section| section.provenance.artifact_sha256.as_ref());
        if actual != Some(expected) {
            violations.push(
                PlannerReplannerInvariantViolation::InvocationBindingMismatch {
                    field: format!("{section_name}.provenance.artifact_sha256"),
                },
            );
        }
    }
    let packet_digest = section_payload(invocation, EVIDENCE_PACKET_SECTION)
        .and_then(|value| value.get("packet_sha256"))
        .and_then(Value::as_str);
    let packet_provenance = invocation
        .sections
        .iter()
        .find(|section| section.name == EVIDENCE_PACKET_SECTION)
        .and_then(|section| section.provenance.artifact_sha256.as_deref());
    if packet_digest != packet_provenance {
        violations.push(
            PlannerReplannerInvariantViolation::InvocationBindingMismatch {
                field: "planner_evidence_packet.provenance.artifact_sha256".to_owned(),
            },
        );
    }
    violations
}

fn section_payload<'a>(invocation: &'a PromptInvocation, name: &str) -> Option<&'a Value> {
    invocation
        .sections
        .iter()
        .find(|section| section.name == name)
        .map(|section| &section.payload)
}

fn exact_bindings_constraint(invocation: &PromptInvocation) -> Option<PlannerReplannerBindings> {
    if invocation.runtime_constraints.len() != 2
        || invocation.runtime_constraints[0].name != POLICY_CONSTRAINT
        || invocation.runtime_constraints[1].name != BINDINGS_CONSTRAINT
    {
        return None;
    }
    serde_json::from_value(invocation.runtime_constraints[1].payload.clone()).ok()
}

fn binding_violations(
    actual: &PlannerReplannerBindings,
    expected: &PlannerReplannerBindings,
) -> Vec<PlannerReplannerInvariantViolation> {
    let actual_value = serde_json::to_value(actual)
        .expect("planner replanner bindings are infallibly serializable");
    let expected_value = serde_json::to_value(expected)
        .expect("planner replanner bindings are infallibly serializable");
    let Some(actual) = actual_value.as_object() else {
        return vec![PlannerReplannerInvariantViolation::BindingMismatch {
            field: "bindings".to_owned(),
        }];
    };
    let expected = expected_value
        .as_object()
        .expect("planner replanner bindings serialize as an object");
    expected
        .iter()
        .filter(|(field, value)| actual.get(*field) != Some(*value))
        .map(
            |(field, _)| PlannerReplannerInvariantViolation::BindingMismatch {
                field: field.clone(),
            },
        )
        .collect()
}

fn output_evidence_ids(output: &PlannerReplannerOutput) -> Vec<&String> {
    let mut evidence = Vec::new();
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

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PlannerEvidenceEntryHashMaterial<'a> {
    ChildHandoff {
        schema_version: u32,
        evidence_id: &'a str,
        source_artifact_sha256: &'a str,
        handoff: &'a PlannerChildHandoff,
    },
}

#[derive(Serialize)]
struct PlannerEvidencePacketHashMaterial<'a> {
    schema_version: u32,
    context_manifest_sha256: &'a str,
    entries: &'a [PlannerEvidenceEntry],
}

fn evidence_entry_sha256(entry: &PlannerEvidenceEntry) -> Result<String, String> {
    let material = match entry {
        PlannerEvidenceEntry::ChildHandoff {
            evidence_id,
            source_artifact_sha256,
            handoff,
            ..
        } => PlannerEvidenceEntryHashMaterial::ChildHandoff {
            schema_version: EVIDENCE_PACKET_SCHEMA_VERSION,
            evidence_id,
            source_artifact_sha256,
            handoff,
        },
    };
    canonical_sha256(&material)
}

fn evidence_packet_sha256(packet: &PlannerEvidencePacket) -> Result<String, String> {
    canonical_sha256(&PlannerEvidencePacketHashMaterial {
        schema_version: packet.schema_version,
        context_manifest_sha256: &packet.context_manifest_sha256,
        entries: &packet.entries,
    })
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let encoded = crate::canonical::encode(&value).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(encoded.as_bytes())))
}

fn evidence_entry_structure_violations(
    entry: &PlannerEvidenceEntry,
) -> Vec<PlannerEvidencePacketViolation> {
    let mut violations = Vec::new();
    let evidence_id_characters = entry.evidence_id().chars().count();
    if evidence_id_characters == 0 {
        violations.push(PlannerEvidencePacketViolation::EmptyEvidenceId { index: 0 });
    } else if evidence_id_characters > MAX_EVIDENCE_ID_CHARACTERS {
        violations.push(PlannerEvidencePacketViolation::EvidenceIdTooLong {
            index: 0,
            maximum: wire_u32(MAX_EVIDENCE_ID_CHARACTERS),
            actual: wire_u32(evidence_id_characters),
        });
    }
    if !is_lowercase_sha256(entry.source_artifact_sha256()) {
        violations.push(PlannerEvidencePacketViolation::InvalidDigest {
            field: "source_artifact_sha256".to_owned(),
        });
    }
    match entry {
        PlannerEvidenceEntry::ChildHandoff { handoff, .. } => {
            validate_child_handoff(handoff, &mut violations);
        }
    }
    violations
}

#[allow(clippy::too_many_lines)]
fn validate_child_handoff(
    handoff: &PlannerChildHandoff,
    violations: &mut Vec<PlannerEvidencePacketViolation>,
) {
    if handoff.contract_version != EVIDENCE_PACKET_SCHEMA_VERSION {
        violations.push(PlannerEvidencePacketViolation::HandoffContractVersion {
            expected: EVIDENCE_PACKET_SCHEMA_VERSION,
            actual: handoff.contract_version,
        });
    }
    validate_stable_id("handoff.handoff_id", &handoff.handoff_id, violations);
    validate_child_execution_binding(&handoff.binding, violations);
    validate_evidence_text(
        "handoff.summary",
        &handoff.summary,
        MAX_EVIDENCE_SUMMARY_CHARACTERS,
        violations,
    );
    validate_count(
        handoff.findings.len(),
        MAX_EVIDENCE_FINDINGS,
        |maximum, actual| PlannerEvidencePacketViolation::FindingCount {
            entry_index: 0,
            maximum,
            actual,
        },
        violations,
    );
    validate_count(
        handoff.unknowns.len(),
        MAX_EVIDENCE_UNKNOWNS,
        |maximum, actual| PlannerEvidencePacketViolation::UnknownCount {
            entry_index: 0,
            maximum,
            actual,
        },
        violations,
    );
    validate_count(
        handoff.recommended_followups.len(),
        MAX_EVIDENCE_FOLLOWUPS,
        |maximum, actual| PlannerEvidencePacketViolation::FollowupCount {
            entry_index: 0,
            maximum,
            actual,
        },
        violations,
    );

    let mut finding_ids = BTreeSet::new();
    for (index, finding) in handoff.findings.iter().enumerate() {
        validate_evidence_text(
            &format!("handoff.findings[{index}].finding_id"),
            &finding.finding_id,
            MAX_EVIDENCE_FINDING_ID_CHARACTERS,
            violations,
        );
        validate_evidence_text(
            &format!("handoff.findings[{index}].statement"),
            &finding.statement,
            MAX_EVIDENCE_TEXT_CHARACTERS,
            violations,
        );
        if !finding_ids.insert(&finding.finding_id) {
            violations.push(PlannerEvidencePacketViolation::DuplicateFindingId {
                entry_index: 0,
                finding_id: finding.finding_id.clone(),
            });
        }
        if !(1..=MAX_EVIDENCE_REFERENCES).contains(&finding.evidence.len()) {
            violations.push(PlannerEvidencePacketViolation::EvidenceReferenceCount {
                entry_index: 0,
                finding_index: wire_u32(index),
                minimum: 1,
                maximum: wire_u32(MAX_EVIDENCE_REFERENCES),
                actual: wire_u32(finding.evidence.len()),
            });
        }
        for (citation_index, citation) in finding.evidence.iter().enumerate() {
            validate_stable_id(
                &format!("handoff.findings[{index}].evidence[{citation_index}].tool_call_id"),
                &citation.tool_call_id,
                violations,
            );
            validate_stable_id(
                &format!("handoff.findings[{index}].evidence[{citation_index}].observed_event_id"),
                &citation.observed_event_id,
                violations,
            );
            validate_artifact(
                &format!("handoff.findings[{index}].evidence[{citation_index}].result_artifact"),
                &citation.result_artifact,
                violations,
            );
        }
    }

    let mut unknown_ids = BTreeSet::new();
    for (index, unknown) in handoff.unknowns.iter().enumerate() {
        validate_stable_id(
            &format!("handoff.unknowns[{index}].unknown_id"),
            &unknown.unknown_id,
            violations,
        );
        validate_evidence_text(
            &format!("handoff.unknowns[{index}].question"),
            &unknown.question,
            MAX_EVIDENCE_TEXT_CHARACTERS,
            violations,
        );
        if !unknown_ids.insert(&unknown.unknown_id) {
            violations.push(PlannerEvidencePacketViolation::DuplicateUnknownId {
                entry_index: 0,
                unknown_id: unknown.unknown_id.clone(),
            });
        }
    }

    let mut followup_ids = BTreeSet::new();
    for (index, followup) in handoff.recommended_followups.iter().enumerate() {
        validate_stable_id(
            &format!("handoff.recommended_followups[{index}].followup_id"),
            &followup.followup_id,
            violations,
        );
        validate_evidence_text(
            &format!("handoff.recommended_followups[{index}].text"),
            &followup.text,
            MAX_EVIDENCE_TEXT_CHARACTERS,
            violations,
        );
        if !followup_ids.insert(&followup.followup_id) {
            violations.push(PlannerEvidencePacketViolation::DuplicateFollowupId {
                entry_index: 0,
                followup_id: followup.followup_id.clone(),
            });
        }
    }
}

fn validate_child_execution_binding(
    binding: &PlannerChildExecutionBinding,
    violations: &mut Vec<PlannerEvidencePacketViolation>,
) {
    for (field, value) in [
        ("work_order_id", binding.work_order_id.as_str()),
        ("execution_id", binding.execution_id.as_str()),
        ("attempt_id", binding.attempt_id.as_str()),
        ("child_actor_id", binding.child_actor_id.as_str()),
        ("context_id", binding.context_id.as_str()),
    ] {
        validate_stable_id(&format!("handoff.binding.{field}"), value, violations);
    }
    for (field, value) in [
        ("work_order_digest", binding.work_order_digest.as_str()),
        (
            "context_manifest_digest",
            binding.context_manifest_digest.as_str(),
        ),
    ] {
        if !is_lowercase_sha256(value) {
            violations.push(PlannerEvidencePacketViolation::InvalidDigest {
                field: format!("handoff.binding.{field}"),
            });
        }
    }
}

fn validate_artifact(
    field: &str,
    artifact: &PlannerEvidenceArtifactRef,
    violations: &mut Vec<PlannerEvidencePacketViolation>,
) {
    if !is_lowercase_sha256(&artifact.sha256) {
        violations.push(PlannerEvidencePacketViolation::InvalidDigest {
            field: format!("{field}.sha256"),
        });
    }
    validate_evidence_text(
        &format!("{field}.media_type"),
        &artifact.media_type,
        MAX_EVIDENCE_MEDIA_TYPE_CHARACTERS,
        violations,
    );
}

fn validate_stable_id(
    field: &str,
    value: &str,
    violations: &mut Vec<PlannerEvidencePacketViolation>,
) {
    validate_evidence_text(field, value, MAX_EVIDENCE_STABLE_ID_CHARACTERS, violations);
}

fn validate_count(
    actual: usize,
    maximum: usize,
    violation: impl FnOnce(u32, u32) -> PlannerEvidencePacketViolation,
    violations: &mut Vec<PlannerEvidencePacketViolation>,
) {
    if actual > maximum {
        violations.push(violation(wire_u32(maximum), wire_u32(actual)));
    }
}

fn evidence_entry_integrity_violations(
    entry: &PlannerEvidenceEntry,
) -> Vec<PlannerEvidencePacketViolation> {
    let mut violations = evidence_entry_structure_violations(entry);
    if !is_lowercase_sha256(entry.normalized_content_sha256()) {
        violations.push(PlannerEvidencePacketViolation::InvalidDigest {
            field: "normalized_content_sha256".to_owned(),
        });
    }
    match evidence_entry_sha256(entry) {
        Ok(expected) if expected != entry.normalized_content_sha256() => violations.push(
            PlannerEvidencePacketViolation::NormalizedContentDigestMismatch {
                evidence_id: entry.evidence_id().to_owned(),
            },
        ),
        Ok(_) => {}
        Err(message) => {
            violations.push(PlannerEvidencePacketViolation::CanonicalEncoding { message });
        }
    }
    violations
}

fn evidence_packet_structure_violations(
    packet: &PlannerEvidencePacket,
) -> Vec<PlannerEvidencePacketViolation> {
    let mut violations = Vec::new();
    if packet.schema_version != EVIDENCE_PACKET_SCHEMA_VERSION {
        violations.push(PlannerEvidencePacketViolation::SchemaVersion {
            expected: EVIDENCE_PACKET_SCHEMA_VERSION,
            actual: packet.schema_version,
        });
    }
    if !is_lowercase_sha256(&packet.context_manifest_sha256) {
        violations.push(PlannerEvidencePacketViolation::InvalidDigest {
            field: "context_manifest_sha256".to_owned(),
        });
    }
    if !(1..=MAX_EVIDENCE_PACKET_ENTRIES).contains(&packet.entries.len()) {
        violations.push(PlannerEvidencePacketViolation::EntryCount {
            minimum: 1,
            maximum: wire_u32(MAX_EVIDENCE_PACKET_ENTRIES),
            actual: wire_u32(packet.entries.len()),
        });
    }
    let mut evidence_ids = BTreeSet::new();
    let mut previous = None;
    for (index, entry) in packet.entries.iter().enumerate() {
        for violation in evidence_entry_integrity_violations(entry) {
            violations.push(reindex_entry_violation(violation, index));
        }
        if !evidence_ids.insert(entry.evidence_id()) {
            violations.push(PlannerEvidencePacketViolation::DuplicateEvidenceId {
                evidence_id: entry.evidence_id().to_owned(),
            });
        }
        if previous.is_some_and(|previous: &str| previous >= entry.evidence_id()) {
            violations.push(PlannerEvidencePacketViolation::NonCanonicalOrder {
                index: wire_u32(index),
            });
        }
        previous = Some(entry.evidence_id());
    }
    match serde_json::to_vec(packet) {
        Ok(encoded) if encoded.len() > MAX_EVIDENCE_PACKET_BYTES => {
            violations.push(PlannerEvidencePacketViolation::PacketTooLarge {
                maximum: wire_u32(MAX_EVIDENCE_PACKET_BYTES),
                actual: wire_u32(encoded.len()),
            });
        }
        Ok(_) => {}
        Err(error) => violations.push(PlannerEvidencePacketViolation::CanonicalEncoding {
            message: error.to_string(),
        }),
    }
    violations
}

fn evidence_packet_integrity_violations(
    packet: &PlannerEvidencePacket,
) -> Vec<PlannerEvidencePacketViolation> {
    let mut violations = evidence_packet_structure_violations(packet);
    if !is_lowercase_sha256(&packet.packet_sha256) {
        violations.push(PlannerEvidencePacketViolation::InvalidDigest {
            field: "packet_sha256".to_owned(),
        });
    }
    match evidence_packet_sha256(packet) {
        Ok(expected) if expected != packet.packet_sha256 => {
            violations.push(PlannerEvidencePacketViolation::PacketDigestMismatch);
        }
        Ok(_) => {}
        Err(message) => {
            violations.push(PlannerEvidencePacketViolation::CanonicalEncoding { message });
        }
    }
    violations
}

fn validate_evidence_text(
    field: &str,
    value: &str,
    maximum: usize,
    violations: &mut Vec<PlannerEvidencePacketViolation>,
) {
    let characters = value.chars().count();
    if characters == 0 {
        violations.push(PlannerEvidencePacketViolation::EmptyText {
            field: field.to_owned(),
        });
    } else if characters > maximum {
        violations.push(PlannerEvidencePacketViolation::TextTooLong {
            field: field.to_owned(),
            maximum: wire_u32(maximum),
            actual: wire_u32(characters),
        });
    }
}

fn reindex_entry_violation(
    violation: PlannerEvidencePacketViolation,
    index: usize,
) -> PlannerEvidencePacketViolation {
    let index = wire_u32(index);
    match violation {
        PlannerEvidencePacketViolation::EmptyEvidenceId { .. } => {
            PlannerEvidencePacketViolation::EmptyEvidenceId { index }
        }
        PlannerEvidencePacketViolation::EvidenceIdTooLong {
            maximum, actual, ..
        } => PlannerEvidencePacketViolation::EvidenceIdTooLong {
            index,
            maximum,
            actual,
        },
        PlannerEvidencePacketViolation::FindingCount {
            maximum, actual, ..
        } => PlannerEvidencePacketViolation::FindingCount {
            entry_index: index,
            maximum,
            actual,
        },
        PlannerEvidencePacketViolation::UnknownCount {
            maximum, actual, ..
        } => PlannerEvidencePacketViolation::UnknownCount {
            entry_index: index,
            maximum,
            actual,
        },
        PlannerEvidencePacketViolation::FollowupCount {
            maximum, actual, ..
        } => PlannerEvidencePacketViolation::FollowupCount {
            entry_index: index,
            maximum,
            actual,
        },
        PlannerEvidencePacketViolation::EvidenceReferenceCount {
            finding_index,
            minimum,
            maximum,
            actual,
            ..
        } => PlannerEvidencePacketViolation::EvidenceReferenceCount {
            entry_index: index,
            finding_index,
            minimum,
            maximum,
            actual,
        },
        PlannerEvidencePacketViolation::DuplicateFindingId { finding_id, .. } => {
            PlannerEvidencePacketViolation::DuplicateFindingId {
                entry_index: index,
                finding_id,
            }
        }
        PlannerEvidencePacketViolation::DuplicateUnknownId { unknown_id, .. } => {
            PlannerEvidencePacketViolation::DuplicateUnknownId {
                entry_index: index,
                unknown_id,
            }
        }
        PlannerEvidencePacketViolation::DuplicateFollowupId { followup_id, .. } => {
            PlannerEvidencePacketViolation::DuplicateFollowupId {
                entry_index: index,
                followup_id,
            }
        }
        other => other,
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
