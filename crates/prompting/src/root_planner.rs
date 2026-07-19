use crate::compiler::{PromptInvocation, TrustLevel};
use crate::{PromptId, PromptKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ROOT_PLANNER_ID: &str = "birdcode.root-planner-turn";
const SHA256_HEX_LENGTH: usize = 64;
const MAX_POLICY_OBLIGATIONS: usize = 32;
const MAX_OBLIGATION_ID_CHARACTERS: usize = 128;
const MAX_OBLIGATION_STATEMENT_CHARACTERS: usize = 4_000;
const MAX_EVIDENCE_REQUIREMENTS: usize = 8;
const MAX_EVIDENCE_REQUIREMENT_CHARACTERS: usize = 1_000;
const MAX_ALLOWED_VERIFICATION_KINDS: usize = 4;
const MAX_POLICY_WORK_ORDERS: u32 = 16;
const MAX_POLICY_DEPENDENCY_REFERENCES: u32 = 32;
const MAX_POLICY_VERIFICATION_TARGETS: u32 = 32;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootPlannerDirective {
    Plan,
    Clarify,
    Escalate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationKind {
    RepositoryTree,
    RepositoryFile,
    RepositorySearch,
    ExistingEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedObligationRef {
    pub obligation_id: String,
    pub obligation_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPlannerDecisionEvidence {
    pub section: String,
    pub basis: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedVerificationTarget {
    pub kind: VerificationKind,
    pub selector: String,
    pub question: String,
    pub obligation_refs: Vec<ProtectedObligationRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPlannerWorkOrder {
    pub local_id: String,
    pub objective: String,
    pub obligation_refs: Vec<ProtectedObligationRef>,
    pub depends_on: Vec<String>,
    pub proposed_verification_targets: Vec<ProposedVerificationTarget>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPlannerEscalationRequest {
    pub reason: String,
    pub blocked_obligation_refs: Vec<ProtectedObligationRef>,
    pub requested_decision: String,
}

/// Exact typed output for `birdcode.root-planner-turn@1.0.0`.
///
/// This is a proposal, not an authority-bearing execution plan. In particular,
/// it intentionally has no grants, budgets, leases, workspaces, model choices,
/// tool calls, or child actor specifications.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPlannerOutput {
    pub schema_version: u32,
    pub root_snapshot_sha256: String,
    pub planner_policy_sha256: String,
    pub context_manifest_sha256: String,
    pub directive: RootPlannerDirective,
    pub rationale: String,
    pub decision_evidence: Vec<RootPlannerDecisionEvidence>,
    pub work_orders: Vec<RootPlannerWorkOrder>,
    pub clarification_questions: Vec<String>,
    pub escalation_requests: Vec<RootPlannerEscalationRequest>,
}

/// A mechanical defect in runtime-owned obligation material.
///
/// These checks deliberately concern only representation, bounds, and content
/// binding. They do not infer the meaning of any natural-language field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtectedObligationViolation {
    EmptyObligationId,
    ObligationIdTooLong {
        maximum: u32,
        actual: u32,
    },
    EmptyStatement,
    StatementTooLong {
        maximum: u32,
        actual: u32,
    },
    EvidenceRequirementCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    EmptyEvidenceRequirement {
        index: u32,
    },
    EvidenceRequirementTooLong {
        index: u32,
        maximum: u32,
        actual: u32,
    },
    InvalidObligationSha256 {
        actual: String,
    },
    ObligationSha256Mismatch {
        expected: String,
        actual: String,
    },
    CanonicalEncoding {
        message: String,
    },
}

/// A mechanical defect in the runtime-owned root planner policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootPlannerPolicyViolation {
    InvalidRootSnapshotSha256 {
        actual: String,
    },
    InvalidPlannerPolicySha256 {
        actual: String,
    },
    InvalidContextManifestSha256 {
        actual: String,
    },
    ObligationCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    Obligation {
        index: u32,
        violation: ProtectedObligationViolation,
    },
    DuplicateObligationId {
        obligation_id: String,
        occurrences: u32,
    },
    DuplicateObligationReference {
        obligation_id: String,
        obligation_sha256: String,
        occurrences: u32,
    },
    AllowedVerificationKindCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    DuplicateAllowedVerificationKind {
        verification_kind: VerificationKind,
        occurrences: u32,
    },
    MaxWorkOrdersOutOfRange {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    MaxDependencyReferencesOutOfRange {
        maximum: u32,
        actual: u32,
    },
    MaxVerificationTargetsOutOfRange {
        maximum: u32,
        actual: u32,
    },
    PlannerPolicySha256Mismatch {
        expected: String,
        actual: String,
    },
    CanonicalEncoding {
        message: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedObligation {
    pub obligation_id: String,
    pub obligation_sha256: String,
    pub statement: String,
    pub mandatory: bool,
    pub evidence_requirements: Vec<String>,
}

impl ProtectedObligation {
    /// Builds an obligation whose digest is derived from its canonical content.
    ///
    /// Evidence requirement order is intentionally part of the authoritative
    /// material. Callers that want set semantics must establish their ordering
    /// before construction.
    ///
    /// # Errors
    ///
    /// Returns all mechanical field and manifest-cap violations.
    pub fn new(
        obligation_id: impl Into<String>,
        statement: impl Into<String>,
        mandatory: bool,
        evidence_requirements: Vec<String>,
    ) -> Result<Self, Vec<ProtectedObligationViolation>> {
        let mut obligation = Self {
            obligation_id: obligation_id.into(),
            obligation_sha256: String::new(),
            statement: statement.into(),
            mandatory,
            evidence_requirements,
        };
        let violations = obligation_structure_violations(&obligation);
        if !violations.is_empty() {
            return Err(violations);
        }
        obligation.obligation_sha256 = obligation_content_sha256(&obligation)
            .map_err(|message| vec![ProtectedObligationViolation::CanonicalEncoding { message }])?;
        Ok(obligation)
    }

    #[must_use]
    pub fn reference(&self) -> ProtectedObligationRef {
        ProtectedObligationRef {
            obligation_id: self.obligation_id.clone(),
            obligation_sha256: self.obligation_sha256.clone(),
        }
    }

    /// Checks that this deserialized obligation has valid bounded fields and a
    /// digest derived from its current content.
    ///
    /// # Errors
    ///
    /// Returns all detected structural and digest violations.
    pub fn validate_integrity(&self) -> Result<(), Vec<ProtectedObligationViolation>> {
        let violations = obligation_integrity_violations(self);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Runtime-owned policy extracted from the single `planner_policy` constraint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPlannerPolicy {
    pub root_snapshot_sha256: String,
    pub planner_policy_sha256: String,
    pub context_manifest_sha256: String,
    pub obligations: Vec<ProtectedObligation>,
    pub allowed_verification_kinds: Vec<VerificationKind>,
    pub max_work_orders: u32,
    pub max_dependency_references: u32,
    pub max_verification_targets: u32,
}

impl RootPlannerPolicy {
    /// Builds a policy whose self-digest is derived from all authoritative
    /// fields except `planner_policy_sha256` itself.
    ///
    /// Obligation and verification-kind order is intentionally bound by the
    /// digest, so ordering changes are visible provenance changes.
    ///
    /// # Errors
    ///
    /// Returns all mechanical integrity and manifest-cap violations.
    #[allow(
        clippy::too_many_arguments,
        reason = "the flat constructor mirrors the stable serialized policy shape"
    )]
    pub fn new(
        root_snapshot_sha256: impl Into<String>,
        context_manifest_sha256: impl Into<String>,
        obligations: Vec<ProtectedObligation>,
        allowed_verification_kinds: Vec<VerificationKind>,
        max_work_orders: u32,
        max_dependency_references: u32,
        max_verification_targets: u32,
    ) -> Result<Self, Vec<RootPlannerPolicyViolation>> {
        let mut policy = Self {
            root_snapshot_sha256: root_snapshot_sha256.into(),
            planner_policy_sha256: String::new(),
            context_manifest_sha256: context_manifest_sha256.into(),
            obligations,
            allowed_verification_kinds,
            max_work_orders,
            max_dependency_references,
            max_verification_targets,
        };
        let violations = policy_structure_violations(&policy);
        if !violations.is_empty() {
            return Err(violations);
        }
        policy.planner_policy_sha256 = policy_content_sha256(&policy)
            .map_err(|message| vec![RootPlannerPolicyViolation::CanonicalEncoding { message }])?;
        Ok(policy)
    }

    /// Checks field bounds, nested obligation hashes, and the policy self-hash.
    ///
    /// # Errors
    ///
    /// Returns all detected structural and digest violations.
    pub fn validate_integrity(&self) -> Result<(), Vec<RootPlannerPolicyViolation>> {
        let violations = policy_integrity_violations(self);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerDigestField {
    RootSnapshotSha256,
    PlannerPolicySha256,
    ContextManifestSha256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObligationReferenceSite {
    WorkOrder {
        work_order_index: u32,
        reference_index: u32,
    },
    VerificationTarget {
        work_order_index: u32,
        target_index: u32,
        reference_index: u32,
    },
    EscalationRequest {
        escalation_index: u32,
        reference_index: u32,
    },
}

/// A mechanical failure of the root planner contract.
///
/// None of these variants attempts to classify natural-language meaning. They
/// enforce only typed authority, identifiers, exact digests, cardinalities,
/// and graph invariants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootPlannerInvariantViolation {
    TypedOutputDecode {
        message: String,
    },
    PlannerPolicyConstraintCount {
        actual: u32,
    },
    PlannerPolicyConstraintName {
        actual: String,
    },
    PlannerPolicyDecode {
        message: String,
    },
    PlannerPolicyIntegrity {
        violation: RootPlannerPolicyViolation,
    },
    DuplicatePolicyObligationId {
        obligation_id: String,
        occurrences: u32,
    },
    DuplicatePolicyObligationReference {
        obligation_id: String,
        obligation_sha256: String,
        occurrences: u32,
    },
    DuplicateAllowedVerificationKind {
        verification_kind: VerificationKind,
        occurrences: u32,
    },
    SchemaVersion {
        expected: u32,
        actual: u32,
    },
    DigestMismatch {
        field: PlannerDigestField,
        expected: String,
        actual: String,
    },
    DirectiveShape {
        directive: RootPlannerDirective,
        work_orders: u32,
        clarification_questions: u32,
        escalation_requests: u32,
    },
    TooManyWorkOrders {
        maximum: u32,
        actual: u32,
    },
    TooManyDependencyReferences {
        maximum: u32,
        actual: u32,
    },
    TooManyVerificationTargets {
        maximum: u32,
        actual: u32,
    },
    UnknownEvidenceSection {
        index: u32,
        section: String,
    },
    DuplicateEvidenceSection {
        section: String,
        occurrences: u32,
    },
    UserSectionCount {
        actual: u32,
    },
    UserEvidenceCitationCount {
        section: String,
        actual: u32,
    },
    DuplicateLocalId {
        local_id: String,
        occurrences: u32,
    },
    SelfDependency {
        local_id: String,
    },
    UnknownDependency {
        local_id: String,
        dependency: String,
    },
    DependencyCycle,
    UnknownObligationReference {
        site: ObligationReferenceSite,
        obligation_id: String,
        obligation_sha256: String,
    },
    ObligationDigestMismatch {
        site: ObligationReferenceSite,
        obligation_id: String,
        expected_sha256: String,
        actual_sha256: String,
    },
    MandatoryObligationUncovered {
        obligation_id: String,
        obligation_sha256: String,
    },
    VerificationKindNotAllowed {
        work_order_index: u32,
        target_index: u32,
        verification_kind: VerificationKind,
    },
}

/// Returns the stable key of the bundled root planning turn.
///
/// # Panics
///
/// Panics only if the compile-time identifier is invalid.
#[must_use]
pub fn root_planner_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(ROOT_PLANNER_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 0, 0),
    )
}

pub(crate) fn is_root_planner_key(key: &PromptKey) -> bool {
    key == &root_planner_key()
}

/// Validates a schema-checked model value against authoritative runtime policy.
///
/// Callers must pass the independently retained [`PromptInvocation`], never a
/// policy reconstructed from model output. The function deliberately performs
/// no natural-language classification.
///
/// # Errors
///
/// Returns every detected mechanical contract violation. JSON Schema
/// validation remains the registry's responsibility and should run first.
pub fn validate_root_planner_output(
    value: &Value,
    invocation: &PromptInvocation,
) -> Result<(), Vec<RootPlannerInvariantViolation>> {
    let output = serde_json::from_value::<RootPlannerOutput>(value.clone()).map_err(|error| {
        vec![RootPlannerInvariantViolation::TypedOutputDecode {
            message: error.to_string(),
        }]
    })?;
    let policy = extract_policy(invocation)?;
    let violations = root_planner_invariant_violations(&output, invocation, &policy);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn extract_policy(
    invocation: &PromptInvocation,
) -> Result<RootPlannerPolicy, Vec<RootPlannerInvariantViolation>> {
    if invocation.runtime_constraints.len() != 1 {
        return Err(vec![
            RootPlannerInvariantViolation::PlannerPolicyConstraintCount {
                actual: wire_u32(invocation.runtime_constraints.len()),
            },
        ]);
    }
    let constraint = &invocation.runtime_constraints[0];
    if constraint.name != "planner_policy" {
        return Err(vec![
            RootPlannerInvariantViolation::PlannerPolicyConstraintName {
                actual: constraint.name.clone(),
            },
        ]);
    }
    let policy = serde_json::from_value::<RootPlannerPolicy>(constraint.payload.clone()).map_err(
        |error| {
            vec![RootPlannerInvariantViolation::PlannerPolicyDecode {
                message: error.to_string(),
            }]
        },
    )?;
    let policy_violations = policy_invariant_violations(&policy);
    if policy_violations.is_empty() {
        Ok(policy)
    } else {
        Err(policy_violations)
    }
}

fn policy_invariant_violations(policy: &RootPlannerPolicy) -> Vec<RootPlannerInvariantViolation> {
    policy_integrity_violations(policy)
        .into_iter()
        .map(|violation| match violation {
            RootPlannerPolicyViolation::DuplicateObligationId {
                obligation_id,
                occurrences,
            } => RootPlannerInvariantViolation::DuplicatePolicyObligationId {
                obligation_id,
                occurrences,
            },
            RootPlannerPolicyViolation::DuplicateObligationReference {
                obligation_id,
                obligation_sha256,
                occurrences,
            } => RootPlannerInvariantViolation::DuplicatePolicyObligationReference {
                obligation_id,
                obligation_sha256,
                occurrences,
            },
            RootPlannerPolicyViolation::DuplicateAllowedVerificationKind {
                verification_kind,
                occurrences,
            } => RootPlannerInvariantViolation::DuplicateAllowedVerificationKind {
                verification_kind,
                occurrences,
            },
            violation => RootPlannerInvariantViolation::PlannerPolicyIntegrity { violation },
        })
        .collect()
}

#[derive(Serialize)]
struct ProtectedObligationHashMaterial<'a> {
    obligation_id: &'a str,
    statement: &'a str,
    mandatory: bool,
    evidence_requirements: &'a [String],
}

#[derive(Serialize)]
struct RootPlannerPolicyHashMaterial<'a> {
    root_snapshot_sha256: &'a str,
    context_manifest_sha256: &'a str,
    obligations: &'a [ProtectedObligation],
    allowed_verification_kinds: &'a [VerificationKind],
    max_work_orders: u32,
    max_dependency_references: u32,
    max_verification_targets: u32,
}

fn obligation_structure_violations(
    obligation: &ProtectedObligation,
) -> Vec<ProtectedObligationViolation> {
    let mut violations = Vec::new();
    let id_characters = obligation.obligation_id.chars().count();
    if id_characters == 0 {
        violations.push(ProtectedObligationViolation::EmptyObligationId);
    } else if id_characters > MAX_OBLIGATION_ID_CHARACTERS {
        violations.push(ProtectedObligationViolation::ObligationIdTooLong {
            maximum: wire_u32(MAX_OBLIGATION_ID_CHARACTERS),
            actual: wire_u32(id_characters),
        });
    }

    let statement_characters = obligation.statement.chars().count();
    if statement_characters == 0 {
        violations.push(ProtectedObligationViolation::EmptyStatement);
    } else if statement_characters > MAX_OBLIGATION_STATEMENT_CHARACTERS {
        violations.push(ProtectedObligationViolation::StatementTooLong {
            maximum: wire_u32(MAX_OBLIGATION_STATEMENT_CHARACTERS),
            actual: wire_u32(statement_characters),
        });
    }

    let evidence_count = obligation.evidence_requirements.len();
    if !(1..=MAX_EVIDENCE_REQUIREMENTS).contains(&evidence_count) {
        violations.push(ProtectedObligationViolation::EvidenceRequirementCount {
            minimum: 1,
            maximum: wire_u32(MAX_EVIDENCE_REQUIREMENTS),
            actual: wire_u32(evidence_count),
        });
    }
    for (index, requirement) in obligation.evidence_requirements.iter().enumerate() {
        let characters = requirement.chars().count();
        if characters == 0 {
            violations.push(ProtectedObligationViolation::EmptyEvidenceRequirement {
                index: wire_u32(index),
            });
        } else if characters > MAX_EVIDENCE_REQUIREMENT_CHARACTERS {
            violations.push(ProtectedObligationViolation::EvidenceRequirementTooLong {
                index: wire_u32(index),
                maximum: wire_u32(MAX_EVIDENCE_REQUIREMENT_CHARACTERS),
                actual: wire_u32(characters),
            });
        }
    }
    violations
}

fn obligation_integrity_violations(
    obligation: &ProtectedObligation,
) -> Vec<ProtectedObligationViolation> {
    let mut violations = obligation_structure_violations(obligation);
    if !is_lowercase_sha256(&obligation.obligation_sha256) {
        violations.push(ProtectedObligationViolation::InvalidObligationSha256 {
            actual: obligation.obligation_sha256.clone(),
        });
    }
    match obligation_content_sha256(obligation) {
        Ok(expected) if expected != obligation.obligation_sha256 => {
            violations.push(ProtectedObligationViolation::ObligationSha256Mismatch {
                expected,
                actual: obligation.obligation_sha256.clone(),
            });
        }
        Ok(_) => {}
        Err(message) => {
            violations.push(ProtectedObligationViolation::CanonicalEncoding { message });
        }
    }
    violations
}

#[allow(
    clippy::too_many_lines,
    reason = "one deterministic pass reports all independently repairable policy defects"
)]
fn policy_structure_violations(policy: &RootPlannerPolicy) -> Vec<RootPlannerPolicyViolation> {
    let mut violations = Vec::new();
    if !is_lowercase_sha256(&policy.root_snapshot_sha256) {
        violations.push(RootPlannerPolicyViolation::InvalidRootSnapshotSha256 {
            actual: policy.root_snapshot_sha256.clone(),
        });
    }
    if !is_lowercase_sha256(&policy.context_manifest_sha256) {
        violations.push(RootPlannerPolicyViolation::InvalidContextManifestSha256 {
            actual: policy.context_manifest_sha256.clone(),
        });
    }

    let obligation_count = policy.obligations.len();
    if !(1..=MAX_POLICY_OBLIGATIONS).contains(&obligation_count) {
        violations.push(RootPlannerPolicyViolation::ObligationCount {
            minimum: 1,
            maximum: wire_u32(MAX_POLICY_OBLIGATIONS),
            actual: wire_u32(obligation_count),
        });
    }

    let mut id_counts = BTreeMap::<&str, usize>::new();
    let mut reference_counts = BTreeMap::<(&str, &str), usize>::new();
    for (index, obligation) in policy.obligations.iter().enumerate() {
        violations.extend(obligation_integrity_violations(obligation).into_iter().map(
            |violation| RootPlannerPolicyViolation::Obligation {
                index: wire_u32(index),
                violation,
            },
        ));
        *id_counts
            .entry(obligation.obligation_id.as_str())
            .or_default() += 1;
        *reference_counts
            .entry((
                obligation.obligation_id.as_str(),
                obligation.obligation_sha256.as_str(),
            ))
            .or_default() += 1;
    }
    for (obligation_id, occurrences) in id_counts {
        if occurrences > 1 {
            violations.push(RootPlannerPolicyViolation::DuplicateObligationId {
                obligation_id: obligation_id.to_owned(),
                occurrences: wire_u32(occurrences),
            });
        }
    }
    for ((obligation_id, obligation_sha256), occurrences) in reference_counts {
        if occurrences > 1 {
            violations.push(RootPlannerPolicyViolation::DuplicateObligationReference {
                obligation_id: obligation_id.to_owned(),
                obligation_sha256: obligation_sha256.to_owned(),
                occurrences: wire_u32(occurrences),
            });
        }
    }

    let kind_count = policy.allowed_verification_kinds.len();
    if !(1..=MAX_ALLOWED_VERIFICATION_KINDS).contains(&kind_count) {
        violations.push(RootPlannerPolicyViolation::AllowedVerificationKindCount {
            minimum: 1,
            maximum: wire_u32(MAX_ALLOWED_VERIFICATION_KINDS),
            actual: wire_u32(kind_count),
        });
    }
    let mut kind_counts = BTreeMap::<VerificationKind, usize>::new();
    for kind in &policy.allowed_verification_kinds {
        *kind_counts.entry(*kind).or_default() += 1;
    }
    for (verification_kind, occurrences) in kind_counts {
        if occurrences > 1 {
            violations.push(
                RootPlannerPolicyViolation::DuplicateAllowedVerificationKind {
                    verification_kind,
                    occurrences: wire_u32(occurrences),
                },
            );
        }
    }

    if !(1..=MAX_POLICY_WORK_ORDERS).contains(&policy.max_work_orders) {
        violations.push(RootPlannerPolicyViolation::MaxWorkOrdersOutOfRange {
            minimum: 1,
            maximum: MAX_POLICY_WORK_ORDERS,
            actual: policy.max_work_orders,
        });
    }
    if policy.max_dependency_references > MAX_POLICY_DEPENDENCY_REFERENCES {
        violations.push(
            RootPlannerPolicyViolation::MaxDependencyReferencesOutOfRange {
                maximum: MAX_POLICY_DEPENDENCY_REFERENCES,
                actual: policy.max_dependency_references,
            },
        );
    }
    if policy.max_verification_targets > MAX_POLICY_VERIFICATION_TARGETS {
        violations.push(
            RootPlannerPolicyViolation::MaxVerificationTargetsOutOfRange {
                maximum: MAX_POLICY_VERIFICATION_TARGETS,
                actual: policy.max_verification_targets,
            },
        );
    }
    violations
}

fn policy_integrity_violations(policy: &RootPlannerPolicy) -> Vec<RootPlannerPolicyViolation> {
    let mut violations = policy_structure_violations(policy);
    if !is_lowercase_sha256(&policy.planner_policy_sha256) {
        violations.push(RootPlannerPolicyViolation::InvalidPlannerPolicySha256 {
            actual: policy.planner_policy_sha256.clone(),
        });
    }
    match policy_content_sha256(policy) {
        Ok(expected) if expected != policy.planner_policy_sha256 => {
            violations.push(RootPlannerPolicyViolation::PlannerPolicySha256Mismatch {
                expected,
                actual: policy.planner_policy_sha256.clone(),
            });
        }
        Ok(_) => {}
        Err(message) => {
            violations.push(RootPlannerPolicyViolation::CanonicalEncoding { message });
        }
    }
    violations
}

fn obligation_content_sha256(obligation: &ProtectedObligation) -> Result<String, String> {
    canonical_sha256(&ProtectedObligationHashMaterial {
        obligation_id: &obligation.obligation_id,
        statement: &obligation.statement,
        mandatory: obligation.mandatory,
        evidence_requirements: &obligation.evidence_requirements,
    })
}

fn policy_content_sha256(policy: &RootPlannerPolicy) -> Result<String, String> {
    canonical_sha256(&RootPlannerPolicyHashMaterial {
        root_snapshot_sha256: &policy.root_snapshot_sha256,
        context_manifest_sha256: &policy.context_manifest_sha256,
        obligations: &policy.obligations,
        allowed_verification_kinds: &policy.allowed_verification_kinds,
        max_work_orders: policy.max_work_orders,
        max_dependency_references: policy.max_dependency_references,
        max_verification_targets: policy.max_verification_targets,
    })
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let canonical = crate::canonical::encode(&value).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hexadecimal = String::with_capacity(SHA256_HEX_LENGTH);
    for byte in digest {
        hexadecimal.push(char::from(HEX[usize::from(byte >> 4)]));
        hexadecimal.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(hexadecimal)
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[allow(
    clippy::too_many_lines,
    reason = "one collect-all pass exposes simultaneous planner defects to bounded repair"
)]
fn root_planner_invariant_violations(
    output: &RootPlannerOutput,
    invocation: &PromptInvocation,
    policy: &RootPlannerPolicy,
) -> Vec<RootPlannerInvariantViolation> {
    let mut violations = Vec::new();
    if output.schema_version != 1 {
        violations.push(RootPlannerInvariantViolation::SchemaVersion {
            expected: 1,
            actual: output.schema_version,
        });
    }
    collect_digest_violations(output, policy, &mut violations);
    collect_directive_shape_violations(output, &mut violations);
    collect_evidence_violations(output, invocation, &mut violations);

    if exceeds(output.work_orders.len(), policy.max_work_orders) {
        violations.push(RootPlannerInvariantViolation::TooManyWorkOrders {
            maximum: policy.max_work_orders,
            actual: wire_u32(output.work_orders.len()),
        });
    }

    let dependency_count = output.work_orders.iter().fold(0_u64, |count, work_order| {
        count.saturating_add(wire_u64(work_order.depends_on.len()))
    });
    if dependency_count > u64::from(policy.max_dependency_references) {
        violations.push(RootPlannerInvariantViolation::TooManyDependencyReferences {
            maximum: policy.max_dependency_references,
            actual: wire_u32_from_u64(dependency_count),
        });
    }

    let verification_count = output
        .work_orders
        .iter()
        .flat_map(|work_order| &work_order.proposed_verification_targets)
        .count();
    if exceeds(verification_count, policy.max_verification_targets) {
        violations.push(RootPlannerInvariantViolation::TooManyVerificationTargets {
            maximum: policy.max_verification_targets,
            actual: wire_u32(verification_count),
        });
    }

    let obligations_by_id = policy
        .obligations
        .iter()
        .map(|obligation| {
            (
                obligation.obligation_id.as_str(),
                obligation.obligation_sha256.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let allowed_kinds = policy
        .allowed_verification_kinds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut covered_obligations = BTreeSet::new();

    for (work_order_index, work_order) in output.work_orders.iter().enumerate() {
        for (reference_index, obligation_ref) in work_order.obligation_refs.iter().enumerate() {
            if reference_is_valid(
                obligation_ref,
                ObligationReferenceSite::WorkOrder {
                    work_order_index: wire_u32(work_order_index),
                    reference_index: wire_u32(reference_index),
                },
                &obligations_by_id,
                &mut violations,
            ) {
                covered_obligations.insert(obligation_ref.clone());
            }
        }
        for (target_index, target) in work_order.proposed_verification_targets.iter().enumerate() {
            if !allowed_kinds.contains(&target.kind) {
                violations.push(RootPlannerInvariantViolation::VerificationKindNotAllowed {
                    work_order_index: wire_u32(work_order_index),
                    target_index: wire_u32(target_index),
                    verification_kind: target.kind,
                });
            }
            for (reference_index, obligation_ref) in target.obligation_refs.iter().enumerate() {
                reference_is_valid(
                    obligation_ref,
                    ObligationReferenceSite::VerificationTarget {
                        work_order_index: wire_u32(work_order_index),
                        target_index: wire_u32(target_index),
                        reference_index: wire_u32(reference_index),
                    },
                    &obligations_by_id,
                    &mut violations,
                );
            }
        }
    }
    for (escalation_index, escalation) in output.escalation_requests.iter().enumerate() {
        for (reference_index, obligation_ref) in
            escalation.blocked_obligation_refs.iter().enumerate()
        {
            reference_is_valid(
                obligation_ref,
                ObligationReferenceSite::EscalationRequest {
                    escalation_index: wire_u32(escalation_index),
                    reference_index: wire_u32(reference_index),
                },
                &obligations_by_id,
                &mut violations,
            );
        }
    }

    if output.directive == RootPlannerDirective::Plan {
        for obligation in policy
            .obligations
            .iter()
            .filter(|obligation| obligation.mandatory)
        {
            let obligation_ref = obligation.reference();
            if !covered_obligations.contains(&obligation_ref) {
                violations.push(
                    RootPlannerInvariantViolation::MandatoryObligationUncovered {
                        obligation_id: obligation_ref.obligation_id,
                        obligation_sha256: obligation_ref.obligation_sha256,
                    },
                );
            }
        }
    }

    collect_dependency_violations(output, &mut violations);
    violations
}

fn collect_digest_violations(
    output: &RootPlannerOutput,
    policy: &RootPlannerPolicy,
    violations: &mut Vec<RootPlannerInvariantViolation>,
) {
    for (field, expected, actual) in [
        (
            PlannerDigestField::RootSnapshotSha256,
            &policy.root_snapshot_sha256,
            &output.root_snapshot_sha256,
        ),
        (
            PlannerDigestField::PlannerPolicySha256,
            &policy.planner_policy_sha256,
            &output.planner_policy_sha256,
        ),
        (
            PlannerDigestField::ContextManifestSha256,
            &policy.context_manifest_sha256,
            &output.context_manifest_sha256,
        ),
    ] {
        if expected != actual {
            violations.push(RootPlannerInvariantViolation::DigestMismatch {
                field,
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
    }
}

fn collect_directive_shape_violations(
    output: &RootPlannerOutput,
    violations: &mut Vec<RootPlannerInvariantViolation>,
) {
    let shape_is_valid = match output.directive {
        RootPlannerDirective::Plan => {
            !output.work_orders.is_empty()
                && output.clarification_questions.is_empty()
                && output.escalation_requests.is_empty()
        }
        RootPlannerDirective::Clarify => {
            output.work_orders.is_empty()
                && (1..=3).contains(&output.clarification_questions.len())
                && output.escalation_requests.is_empty()
        }
        RootPlannerDirective::Escalate => {
            output.work_orders.is_empty()
                && output.clarification_questions.is_empty()
                && output.escalation_requests.len() == 1
        }
    };
    if !shape_is_valid {
        violations.push(RootPlannerInvariantViolation::DirectiveShape {
            directive: output.directive,
            work_orders: wire_u32(output.work_orders.len()),
            clarification_questions: wire_u32(output.clarification_questions.len()),
            escalation_requests: wire_u32(output.escalation_requests.len()),
        });
    }
}

fn collect_evidence_violations(
    output: &RootPlannerOutput,
    invocation: &PromptInvocation,
    violations: &mut Vec<RootPlannerInvariantViolation>,
) {
    let section_names = invocation
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut citation_counts = BTreeMap::<&str, usize>::new();
    for (index, evidence) in output.decision_evidence.iter().enumerate() {
        *citation_counts
            .entry(evidence.section.as_str())
            .or_default() += 1;
        if !section_names.contains(evidence.section.as_str()) {
            violations.push(RootPlannerInvariantViolation::UnknownEvidenceSection {
                index: wire_u32(index),
                section: evidence.section.clone(),
            });
        }
    }
    for (section, occurrences) in &citation_counts {
        if *occurrences > 1 {
            violations.push(RootPlannerInvariantViolation::DuplicateEvidenceSection {
                section: (*section).to_owned(),
                occurrences: wire_u32(*occurrences),
            });
        }
    }

    let user_sections = invocation
        .sections
        .iter()
        .filter(|section| section.trust == TrustLevel::User)
        .collect::<Vec<_>>();
    if user_sections.len() == 1 {
        let section = &user_sections[0].name;
        let actual = citation_counts
            .get(section.as_str())
            .copied()
            .unwrap_or_default();
        if actual != 1 {
            violations.push(RootPlannerInvariantViolation::UserEvidenceCitationCount {
                section: section.clone(),
                actual: wire_u32(actual),
            });
        }
    } else {
        violations.push(RootPlannerInvariantViolation::UserSectionCount {
            actual: wire_u32(user_sections.len()),
        });
    }
}

fn collect_dependency_violations(
    output: &RootPlannerOutput,
    violations: &mut Vec<RootPlannerInvariantViolation>,
) {
    let mut work_orders = BTreeMap::<&str, &RootPlannerWorkOrder>::new();
    let mut id_counts = BTreeMap::<&str, usize>::new();
    for work_order in &output.work_orders {
        *id_counts.entry(work_order.local_id.as_str()).or_default() += 1;
        work_orders
            .entry(work_order.local_id.as_str())
            .or_insert(work_order);
    }
    for (local_id, occurrences) in id_counts {
        if occurrences > 1 {
            violations.push(RootPlannerInvariantViolation::DuplicateLocalId {
                local_id: local_id.to_owned(),
                occurrences: wire_u32(occurrences),
            });
        }
    }
    for work_order in &output.work_orders {
        for dependency in &work_order.depends_on {
            if dependency == &work_order.local_id {
                violations.push(RootPlannerInvariantViolation::SelfDependency {
                    local_id: work_order.local_id.clone(),
                });
            } else if !work_orders.contains_key(dependency.as_str()) {
                violations.push(RootPlannerInvariantViolation::UnknownDependency {
                    local_id: work_order.local_id.clone(),
                    dependency: dependency.clone(),
                });
            }
        }
    }
    if dependency_graph_has_cycle(&work_orders) {
        violations.push(RootPlannerInvariantViolation::DependencyCycle);
    }
}

fn reference_is_valid(
    obligation_ref: &ProtectedObligationRef,
    site: ObligationReferenceSite,
    obligations_by_id: &BTreeMap<&str, &str>,
    violations: &mut Vec<RootPlannerInvariantViolation>,
) -> bool {
    let Some(expected_sha256) = obligations_by_id.get(obligation_ref.obligation_id.as_str()) else {
        violations.push(RootPlannerInvariantViolation::UnknownObligationReference {
            site,
            obligation_id: obligation_ref.obligation_id.clone(),
            obligation_sha256: obligation_ref.obligation_sha256.clone(),
        });
        return false;
    };
    if *expected_sha256 == obligation_ref.obligation_sha256 {
        true
    } else {
        violations.push(RootPlannerInvariantViolation::ObligationDigestMismatch {
            site,
            obligation_id: obligation_ref.obligation_id.clone(),
            expected_sha256: (*expected_sha256).to_owned(),
            actual_sha256: obligation_ref.obligation_sha256.clone(),
        });
        false
    }
}

fn dependency_graph_has_cycle(work_orders: &BTreeMap<&str, &RootPlannerWorkOrder>) -> bool {
    fn visit<'a>(
        local_id: &'a str,
        work_orders: &BTreeMap<&'a str, &'a RootPlannerWorkOrder>,
        active: &mut BTreeSet<&'a str>,
        complete: &mut BTreeSet<&'a str>,
    ) -> bool {
        if complete.contains(local_id) {
            return false;
        }
        if !active.insert(local_id) {
            return true;
        }
        for dependency in &work_orders[local_id].depends_on {
            if work_orders.contains_key(dependency.as_str())
                && visit(dependency, work_orders, active, complete)
            {
                return true;
            }
        }
        active.remove(local_id);
        complete.insert(local_id);
        false
    }

    let mut active = BTreeSet::new();
    let mut complete = BTreeSet::new();
    for local_id in work_orders.keys().copied() {
        if visit(local_id, work_orders, &mut active, &mut complete) {
            return true;
        }
    }
    false
}

fn exceeds(actual: usize, maximum: u32) -> bool {
    wire_u64(actual) > u64::from(maximum)
}

fn wire_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn wire_u32_from_u64(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
