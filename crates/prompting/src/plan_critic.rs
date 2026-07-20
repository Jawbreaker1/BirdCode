use crate::compiler::PromptInvocation;
use crate::root_planner::{
    ProtectedObligation, ProtectedObligationRef, ProtectedObligationViolation,
    RootPlannerDecisionEvidence,
};
use crate::{PromptId, PromptKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const PLAN_CRITIC_ID: &str = "birdcode.plan-semantic-critic";
const SHA256_HEX_LENGTH: usize = 64;
const MAX_POLICY_OBLIGATIONS: usize = 32;
const MAX_CANDIDATE_WORK_ORDERS: usize = 16;
const MAX_POLICY_FINDINGS: u32 = 32;
const MAX_POLICY_EVIDENCE_REFERENCES: u32 = 64;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Closed v1 ceiling for findings emitted by the semantic plan critic.
pub const PLAN_CRITIC_POLICY_V1_MAX_FINDINGS: u32 = 16;

/// Closed v1 ceiling for evidence references emitted by the semantic critic.
pub const PLAN_CRITIC_POLICY_V1_MAX_EVIDENCE_REFERENCES: u32 = 48;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanCriticVerdict {
    Accept,
    Revise,
    Clarify,
    Escalate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationAssessmentStatus {
    Addressed,
    Partial,
    Missing,
    Altered,
    Ambiguous,
    Conflicting,
    Unverifiable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanCriticFindingSeverity {
    Blocker,
    Major,
    Minor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanCriticFindingCategory {
    ObligationCoverage,
    Decomposition,
    Parallelism,
    DependencyOrdering,
    Handoff,
    IndependentReview,
    Verification,
    Feasibility,
    Ambiguity,
    Conflict,
    AuthorityBoundary,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCriticBindings {
    pub root_snapshot_sha256: String,
    pub planner_policy_sha256: String,
    pub context_manifest_sha256: String,
    pub candidate_plan_sha256: String,
    pub critic_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationAssessment {
    pub obligation_ref: ProtectedObligationRef,
    pub status: ObligationAssessmentStatus,
    pub basis: String,
    pub affected_work_order_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCriticFinding {
    pub finding_id: String,
    pub severity: PlanCriticFindingSeverity,
    pub category: PlanCriticFindingCategory,
    pub statement: String,
    pub source_sections: Vec<String>,
    pub affected_work_order_ids: Vec<String>,
    pub required_change: String,
}

/// Typed semantic assessment of one immutable root-plan candidate.
///
/// The output contains no authority, model selection, permission grant,
/// budget, tool call, or replacement plan. A separate runtime gate decides
/// whether the critic's configured lineage is policy-eligible to influence
/// acceptance; this type does not claim provider attestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCriticOutput {
    pub schema_version: u32,
    pub bindings: PlanCriticBindings,
    pub verdict: PlanCriticVerdict,
    pub summary: String,
    pub obligation_assessments: Vec<ObligationAssessment>,
    pub findings: Vec<PlanCriticFinding>,
    pub clarification_questions: Vec<String>,
    pub escalation_requests: Vec<String>,
    pub decision_evidence: Vec<RootPlannerDecisionEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCriticPolicy {
    pub root_snapshot_sha256: String,
    pub planner_policy_sha256: String,
    pub context_manifest_sha256: String,
    pub candidate_plan_sha256: String,
    pub obligations: Vec<ProtectedObligation>,
    pub candidate_work_order_ids: Vec<String>,
    pub max_findings: u32,
    pub max_evidence_references: u32,
    pub critic_policy_sha256: String,
}

/// Complete owned material used to construct one immutable critic policy.
///
/// Keeping the inputs named prevents digest, limit, and collection fields from
/// being accidentally transposed at call sites. This construction-only type is
/// deliberately not serialized; [`PlanCriticPolicy`] remains the wire format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCriticPolicyMaterial {
    pub root_snapshot_sha256: String,
    pub planner_policy_sha256: String,
    pub context_manifest_sha256: String,
    pub candidate_plan_sha256: String,
    pub obligations: Vec<ProtectedObligation>,
    pub candidate_work_order_ids: Vec<String>,
    pub max_findings: u32,
    pub max_evidence_references: u32,
}

impl PlanCriticPolicy {
    /// Binds a critic to immutable root authority and one exact plan candidate.
    ///
    /// # Errors
    ///
    /// Returns every mechanical defect in the supplied policy material. No
    /// natural-language meaning is classified here.
    pub fn new(material: PlanCriticPolicyMaterial) -> Result<Self, Vec<PlanCriticPolicyViolation>> {
        let mut policy = Self {
            root_snapshot_sha256: material.root_snapshot_sha256,
            planner_policy_sha256: material.planner_policy_sha256,
            context_manifest_sha256: material.context_manifest_sha256,
            candidate_plan_sha256: material.candidate_plan_sha256,
            obligations: material.obligations,
            candidate_work_order_ids: material.candidate_work_order_ids,
            max_findings: material.max_findings,
            max_evidence_references: material.max_evidence_references,
            critic_policy_sha256: String::new(),
        };
        let violations = policy_structure_violations(&policy);
        if !violations.is_empty() {
            return Err(violations);
        }
        policy.critic_policy_sha256 = policy_content_sha256(&policy)
            .map_err(|message| vec![PlanCriticPolicyViolation::CanonicalEncoding { message }])?;
        Ok(policy)
    }

    #[must_use]
    pub fn bindings(&self) -> PlanCriticBindings {
        PlanCriticBindings {
            root_snapshot_sha256: self.root_snapshot_sha256.clone(),
            planner_policy_sha256: self.planner_policy_sha256.clone(),
            context_manifest_sha256: self.context_manifest_sha256.clone(),
            candidate_plan_sha256: self.candidate_plan_sha256.clone(),
            critic_policy_sha256: self.critic_policy_sha256.clone(),
        }
    }
}

/// Derives the one canonical v1 critic policy for an authoritative root policy
/// and one exact candidate artifact.
///
/// This function is deliberately mechanical: semantic authority comes from
/// `root_policy`, candidate identities come from `candidate`, and v1 limits
/// are closed constants. Callers must not copy fields from an untrusted critic
/// policy and then merely verify that it signs itself.
///
/// # Errors
///
/// Returns every mechanical policy violation, including a malformed candidate
/// digest or invalid inherited authority material.
pub fn derive_plan_critic_policy_v1(
    root_policy: &crate::root_planner::RootPlannerPolicy,
    candidate: &crate::root_planner::RootPlannerOutput,
    candidate_plan_sha256: &str,
) -> Result<PlanCriticPolicy, Vec<PlanCriticPolicyViolation>> {
    PlanCriticPolicy::new(PlanCriticPolicyMaterial {
        root_snapshot_sha256: root_policy.root_snapshot_sha256.clone(),
        planner_policy_sha256: root_policy.planner_policy_sha256.clone(),
        context_manifest_sha256: root_policy.context_manifest_sha256.clone(),
        candidate_plan_sha256: candidate_plan_sha256.to_owned(),
        obligations: root_policy.obligations.clone(),
        candidate_work_order_ids: candidate
            .work_orders
            .iter()
            .map(|work_order| work_order.local_id.clone())
            .collect(),
        max_findings: PLAN_CRITIC_POLICY_V1_MAX_FINDINGS,
        max_evidence_references: PLAN_CRITIC_POLICY_V1_MAX_EVIDENCE_REFERENCES,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanCriticPolicyViolation {
    InvalidDigest {
        field: String,
        actual: String,
    },
    ObligationCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    ObligationIntegrity {
        index: u32,
        violations: Vec<ProtectedObligationViolation>,
    },
    DuplicateObligationId {
        obligation_id: String,
    },
    DuplicateObligationReference {
        obligation_id: String,
        obligation_sha256: String,
    },
    CandidateWorkOrderCount {
        maximum: u32,
        actual: u32,
    },
    EmptyCandidateWorkOrderId {
        index: u32,
    },
    DuplicateCandidateWorkOrderId {
        work_order_id: String,
    },
    MaxFindingsOutOfRange {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    MaxEvidenceReferencesOutOfRange {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    CriticPolicySha256Mismatch {
        expected: String,
        actual: String,
    },
    CanonicalEncoding {
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanCriticBindingField {
    RootSnapshotSha256,
    PlannerPolicySha256,
    ContextManifestSha256,
    CandidatePlanSha256,
    CriticPolicySha256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanCriticInvariantViolation {
    TypedOutputDecode {
        message: String,
    },
    CriticPolicyConstraintCount {
        actual: u32,
    },
    CriticPolicyConstraintName {
        actual: String,
    },
    CriticPolicyDecode {
        message: String,
    },
    CriticPolicyIntegrity {
        violation: PlanCriticPolicyViolation,
    },
    SchemaVersion {
        expected: u32,
        actual: u32,
    },
    BindingMismatch {
        field: PlanCriticBindingField,
        expected: String,
        actual: String,
    },
    AssessmentCount {
        expected: u32,
        actual: u32,
    },
    DuplicateAssessment {
        obligation_id: String,
        obligation_sha256: String,
    },
    UnknownObligationReference {
        obligation_id: String,
        obligation_sha256: String,
    },
    ObligationDigestMismatch {
        obligation_id: String,
        expected_sha256: String,
        actual_sha256: String,
    },
    MandatoryObligationMissing {
        obligation_id: String,
        obligation_sha256: String,
    },
    AcceptedMandatoryObligationNotAddressed {
        obligation_id: String,
        status: ObligationAssessmentStatus,
    },
    UnknownWorkOrderReference {
        work_order_id: String,
    },
    DuplicateFindingId {
        finding_id: String,
    },
    FindingLimitExceeded {
        maximum: u32,
        actual: u32,
    },
    EvidenceReferenceLimitExceeded {
        maximum: u32,
        actual: u32,
    },
    UnknownEvidenceSection {
        section: String,
    },
    DuplicateEvidenceSection {
        section: String,
    },
    DirectiveShapeMismatch {
        verdict: PlanCriticVerdict,
    },
}

/// Returns the immutable key of the bundled semantic critic prompt.
///
/// # Panics
///
/// Panics only if the compile-time identifier is invalid.
#[must_use]
pub fn plan_critic_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(PLAN_CRITIC_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 0, 0),
    )
}

pub(crate) fn is_plan_critic_key(key: &PromptKey) -> bool {
    key == &plan_critic_key()
}

/// Validates schema-checked critic output against retained runtime authority.
///
/// # Errors
///
/// Returns all safely collectable mechanical violations. It never decides
/// whether a plan actually satisfies natural-language intent.
pub fn validate_plan_critic_output(
    value: &Value,
    invocation: &PromptInvocation,
) -> Result<(), Vec<PlanCriticInvariantViolation>> {
    let output = serde_json::from_value::<PlanCriticOutput>(value.clone()).map_err(|error| {
        vec![PlanCriticInvariantViolation::TypedOutputDecode {
            message: error.to_string(),
        }]
    })?;
    let policy = extract_policy(invocation)?;
    let violations = critic_invariant_violations(&output, invocation, &policy);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn extract_policy(
    invocation: &PromptInvocation,
) -> Result<PlanCriticPolicy, Vec<PlanCriticInvariantViolation>> {
    if invocation.runtime_constraints.len() != 1 {
        return Err(vec![
            PlanCriticInvariantViolation::CriticPolicyConstraintCount {
                actual: wire_u32(invocation.runtime_constraints.len()),
            },
        ]);
    }
    let constraint = &invocation.runtime_constraints[0];
    if constraint.name != "critic_policy" {
        return Err(vec![
            PlanCriticInvariantViolation::CriticPolicyConstraintName {
                actual: constraint.name.clone(),
            },
        ]);
    }
    let policy = serde_json::from_value::<PlanCriticPolicy>(constraint.payload.clone()).map_err(
        |error| {
            vec![PlanCriticInvariantViolation::CriticPolicyDecode {
                message: error.to_string(),
            }]
        },
    )?;
    let violations = policy_integrity_violations(&policy)
        .into_iter()
        .map(|violation| PlanCriticInvariantViolation::CriticPolicyIntegrity { violation })
        .collect::<Vec<_>>();
    if violations.is_empty() {
        Ok(policy)
    } else {
        Err(violations)
    }
}

#[derive(Serialize)]
struct PlanCriticPolicyHashMaterial<'a> {
    root_snapshot_sha256: &'a str,
    planner_policy_sha256: &'a str,
    context_manifest_sha256: &'a str,
    candidate_plan_sha256: &'a str,
    obligations: &'a [ProtectedObligation],
    candidate_work_order_ids: &'a [String],
    max_findings: u32,
    max_evidence_references: u32,
}

fn policy_content_sha256(policy: &PlanCriticPolicy) -> Result<String, String> {
    canonical_sha256(&PlanCriticPolicyHashMaterial {
        root_snapshot_sha256: &policy.root_snapshot_sha256,
        planner_policy_sha256: &policy.planner_policy_sha256,
        context_manifest_sha256: &policy.context_manifest_sha256,
        candidate_plan_sha256: &policy.candidate_plan_sha256,
        obligations: &policy.obligations,
        candidate_work_order_ids: &policy.candidate_work_order_ids,
        max_findings: policy.max_findings,
        max_evidence_references: policy.max_evidence_references,
    })
}

fn policy_structure_violations(policy: &PlanCriticPolicy) -> Vec<PlanCriticPolicyViolation> {
    let mut violations = Vec::new();
    for (field, value) in [
        ("root_snapshot_sha256", &policy.root_snapshot_sha256),
        ("planner_policy_sha256", &policy.planner_policy_sha256),
        ("context_manifest_sha256", &policy.context_manifest_sha256),
        ("candidate_plan_sha256", &policy.candidate_plan_sha256),
    ] {
        if !is_lowercase_sha256(value) {
            violations.push(PlanCriticPolicyViolation::InvalidDigest {
                field: field.to_owned(),
                actual: value.clone(),
            });
        }
    }
    if !(1..=MAX_POLICY_OBLIGATIONS).contains(&policy.obligations.len()) {
        violations.push(PlanCriticPolicyViolation::ObligationCount {
            minimum: 1,
            maximum: wire_u32(MAX_POLICY_OBLIGATIONS),
            actual: wire_u32(policy.obligations.len()),
        });
    }
    let mut obligation_ids = BTreeSet::new();
    let mut obligation_refs = BTreeSet::new();
    for (index, obligation) in policy.obligations.iter().enumerate() {
        if let Err(nested) = obligation.validate_integrity() {
            violations.push(PlanCriticPolicyViolation::ObligationIntegrity {
                index: wire_u32(index),
                violations: nested,
            });
        }
        if !obligation_ids.insert(obligation.obligation_id.as_str()) {
            violations.push(PlanCriticPolicyViolation::DuplicateObligationId {
                obligation_id: obligation.obligation_id.clone(),
            });
        }
        if !obligation_refs.insert((
            obligation.obligation_id.as_str(),
            obligation.obligation_sha256.as_str(),
        )) {
            violations.push(PlanCriticPolicyViolation::DuplicateObligationReference {
                obligation_id: obligation.obligation_id.clone(),
                obligation_sha256: obligation.obligation_sha256.clone(),
            });
        }
    }
    if policy.candidate_work_order_ids.len() > MAX_CANDIDATE_WORK_ORDERS {
        violations.push(PlanCriticPolicyViolation::CandidateWorkOrderCount {
            maximum: wire_u32(MAX_CANDIDATE_WORK_ORDERS),
            actual: wire_u32(policy.candidate_work_order_ids.len()),
        });
    }
    let mut work_order_ids = BTreeSet::new();
    for (index, work_order_id) in policy.candidate_work_order_ids.iter().enumerate() {
        if work_order_id.is_empty() {
            violations.push(PlanCriticPolicyViolation::EmptyCandidateWorkOrderId {
                index: wire_u32(index),
            });
        } else if !work_order_ids.insert(work_order_id.as_str()) {
            violations.push(PlanCriticPolicyViolation::DuplicateCandidateWorkOrderId {
                work_order_id: work_order_id.clone(),
            });
        }
    }
    if !(1..=MAX_POLICY_FINDINGS).contains(&policy.max_findings) {
        violations.push(PlanCriticPolicyViolation::MaxFindingsOutOfRange {
            minimum: 1,
            maximum: MAX_POLICY_FINDINGS,
            actual: policy.max_findings,
        });
    }
    if !(1..=MAX_POLICY_EVIDENCE_REFERENCES).contains(&policy.max_evidence_references) {
        violations.push(PlanCriticPolicyViolation::MaxEvidenceReferencesOutOfRange {
            minimum: 1,
            maximum: MAX_POLICY_EVIDENCE_REFERENCES,
            actual: policy.max_evidence_references,
        });
    }
    violations
}

fn policy_integrity_violations(policy: &PlanCriticPolicy) -> Vec<PlanCriticPolicyViolation> {
    let mut violations = policy_structure_violations(policy);
    if !is_lowercase_sha256(&policy.critic_policy_sha256) {
        violations.push(PlanCriticPolicyViolation::InvalidDigest {
            field: "critic_policy_sha256".to_owned(),
            actual: policy.critic_policy_sha256.clone(),
        });
    }
    match policy_content_sha256(policy) {
        Ok(expected) if expected != policy.critic_policy_sha256 => {
            violations.push(PlanCriticPolicyViolation::CriticPolicySha256Mismatch {
                expected,
                actual: policy.critic_policy_sha256.clone(),
            });
        }
        Ok(_) => {}
        Err(message) => violations.push(PlanCriticPolicyViolation::CanonicalEncoding { message }),
    }
    violations
}

fn critic_invariant_violations(
    output: &PlanCriticOutput,
    invocation: &PromptInvocation,
    policy: &PlanCriticPolicy,
) -> Vec<PlanCriticInvariantViolation> {
    let mut violations = Vec::new();
    if output.schema_version != 1 {
        violations.push(PlanCriticInvariantViolation::SchemaVersion {
            expected: 1,
            actual: output.schema_version,
        });
    }
    collect_binding_violations(&output.bindings, policy, &mut violations);
    let candidate_ids = policy
        .candidate_work_order_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    collect_assessment_violations(output, policy, &candidate_ids, &mut violations);
    collect_finding_and_evidence_violations(
        output,
        invocation,
        policy,
        &candidate_ids,
        &mut violations,
    );
    collect_directive_shape_violation(output, &mut violations);
    violations
}

fn collect_assessment_violations(
    output: &PlanCriticOutput,
    policy: &PlanCriticPolicy,
    candidate_ids: &BTreeSet<&str>,
    violations: &mut Vec<PlanCriticInvariantViolation>,
) {
    let expected_refs = policy
        .obligations
        .iter()
        .map(|obligation| {
            (
                obligation.obligation_id.as_str(),
                obligation.obligation_sha256.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut seen_assessments = BTreeSet::new();
    for assessment in &output.obligation_assessments {
        let reference = (
            assessment.obligation_ref.obligation_id.as_str(),
            assessment.obligation_ref.obligation_sha256.as_str(),
        );
        if !seen_assessments.insert(reference) {
            violations.push(PlanCriticInvariantViolation::DuplicateAssessment {
                obligation_id: reference.0.to_owned(),
                obligation_sha256: reference.1.to_owned(),
            });
        }
        if !expected_refs.contains(&reference) {
            if let Some(expected) = policy.obligations.iter().find(|obligation| {
                obligation.obligation_id == assessment.obligation_ref.obligation_id
            }) {
                violations.push(PlanCriticInvariantViolation::ObligationDigestMismatch {
                    obligation_id: reference.0.to_owned(),
                    expected_sha256: expected.obligation_sha256.clone(),
                    actual_sha256: reference.1.to_owned(),
                });
            } else {
                violations.push(PlanCriticInvariantViolation::UnknownObligationReference {
                    obligation_id: reference.0.to_owned(),
                    obligation_sha256: reference.1.to_owned(),
                });
            }
        }
        collect_unknown_work_orders(
            &assessment.affected_work_order_ids,
            candidate_ids,
            violations,
        );
    }
    if output.obligation_assessments.len() != policy.obligations.len() {
        violations.push(PlanCriticInvariantViolation::AssessmentCount {
            expected: wire_u32(policy.obligations.len()),
            actual: wire_u32(output.obligation_assessments.len()),
        });
    }
    for obligation in policy
        .obligations
        .iter()
        .filter(|obligation| obligation.mandatory)
    {
        let assessment = output.obligation_assessments.iter().find(|assessment| {
            assessment.obligation_ref.obligation_id == obligation.obligation_id
                && assessment.obligation_ref.obligation_sha256 == obligation.obligation_sha256
        });
        let Some(assessment) = assessment else {
            violations.push(PlanCriticInvariantViolation::MandatoryObligationMissing {
                obligation_id: obligation.obligation_id.clone(),
                obligation_sha256: obligation.obligation_sha256.clone(),
            });
            continue;
        };
        if output.verdict == PlanCriticVerdict::Accept
            && assessment.status != ObligationAssessmentStatus::Addressed
        {
            violations.push(
                PlanCriticInvariantViolation::AcceptedMandatoryObligationNotAddressed {
                    obligation_id: obligation.obligation_id.clone(),
                    status: assessment.status,
                },
            );
        }
    }
}

fn collect_finding_and_evidence_violations(
    output: &PlanCriticOutput,
    invocation: &PromptInvocation,
    policy: &PlanCriticPolicy,
    candidate_ids: &BTreeSet<&str>,
    violations: &mut Vec<PlanCriticInvariantViolation>,
) {
    if exceeds(output.findings.len(), policy.max_findings) {
        violations.push(PlanCriticInvariantViolation::FindingLimitExceeded {
            maximum: policy.max_findings,
            actual: wire_u32(output.findings.len()),
        });
    }
    let mut finding_ids = BTreeSet::new();
    let mut evidence_references = 0_u64;
    for finding in &output.findings {
        if !finding_ids.insert(finding.finding_id.as_str()) {
            violations.push(PlanCriticInvariantViolation::DuplicateFindingId {
                finding_id: finding.finding_id.clone(),
            });
        }
        evidence_references = evidence_references
            .saturating_add(wire_u64(finding.source_sections.len()))
            .saturating_add(wire_u64(finding.affected_work_order_ids.len()));
        collect_known_sections(&finding.source_sections, invocation, violations);
        collect_unknown_work_orders(&finding.affected_work_order_ids, candidate_ids, violations);
    }
    evidence_references =
        evidence_references
            .saturating_add(wire_u64(output.decision_evidence.len()))
            .saturating_add(output.obligation_assessments.iter().fold(
                0_u64,
                |count, assessment| {
                    count.saturating_add(wire_u64(assessment.affected_work_order_ids.len()))
                },
            ));
    if evidence_references > u64::from(policy.max_evidence_references) {
        violations.push(
            PlanCriticInvariantViolation::EvidenceReferenceLimitExceeded {
                maximum: policy.max_evidence_references,
                actual: wire_u32_from_u64(evidence_references),
            },
        );
    }
    let evidence_sections = output
        .decision_evidence
        .iter()
        .map(|evidence| evidence.section.clone())
        .collect::<Vec<_>>();
    collect_known_sections(&evidence_sections, invocation, violations);
}

fn collect_directive_shape_violation(
    output: &PlanCriticOutput,
    violations: &mut Vec<PlanCriticInvariantViolation>,
) {
    let shape_matches = match output.verdict {
        PlanCriticVerdict::Accept => {
            output.findings.is_empty()
                && output.clarification_questions.is_empty()
                && output.escalation_requests.is_empty()
        }
        PlanCriticVerdict::Revise => {
            !output.findings.is_empty()
                && output.clarification_questions.is_empty()
                && output.escalation_requests.is_empty()
        }
        PlanCriticVerdict::Clarify => {
            (1..=3).contains(&output.clarification_questions.len())
                && output.escalation_requests.is_empty()
        }
        PlanCriticVerdict::Escalate => {
            output.clarification_questions.is_empty() && output.escalation_requests.len() == 1
        }
    };
    if !shape_matches {
        violations.push(PlanCriticInvariantViolation::DirectiveShapeMismatch {
            verdict: output.verdict,
        });
    }
}

fn collect_binding_violations(
    bindings: &PlanCriticBindings,
    policy: &PlanCriticPolicy,
    violations: &mut Vec<PlanCriticInvariantViolation>,
) {
    for (field, expected, actual) in [
        (
            PlanCriticBindingField::RootSnapshotSha256,
            &policy.root_snapshot_sha256,
            &bindings.root_snapshot_sha256,
        ),
        (
            PlanCriticBindingField::PlannerPolicySha256,
            &policy.planner_policy_sha256,
            &bindings.planner_policy_sha256,
        ),
        (
            PlanCriticBindingField::ContextManifestSha256,
            &policy.context_manifest_sha256,
            &bindings.context_manifest_sha256,
        ),
        (
            PlanCriticBindingField::CandidatePlanSha256,
            &policy.candidate_plan_sha256,
            &bindings.candidate_plan_sha256,
        ),
        (
            PlanCriticBindingField::CriticPolicySha256,
            &policy.critic_policy_sha256,
            &bindings.critic_policy_sha256,
        ),
    ] {
        if expected != actual {
            violations.push(PlanCriticInvariantViolation::BindingMismatch {
                field,
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
    }
}

fn collect_known_sections(
    sections: &[String],
    invocation: &PromptInvocation,
    violations: &mut Vec<PlanCriticInvariantViolation>,
) {
    let known = invocation
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for section in sections {
        if !known.contains(section.as_str()) {
            violations.push(PlanCriticInvariantViolation::UnknownEvidenceSection {
                section: section.clone(),
            });
        }
        if !seen.insert(section.as_str()) {
            violations.push(PlanCriticInvariantViolation::DuplicateEvidenceSection {
                section: section.clone(),
            });
        }
    }
}

fn collect_unknown_work_orders(
    ids: &[String],
    known: &BTreeSet<&str>,
    violations: &mut Vec<PlanCriticInvariantViolation>,
) {
    for id in ids {
        if !known.contains(id.as_str()) {
            violations.push(PlanCriticInvariantViolation::UnknownWorkOrderReference {
                work_order_id: id.clone(),
            });
        }
    }
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

fn exceeds(actual: usize, maximum: u32) -> bool {
    u64::try_from(actual).unwrap_or(u64::MAX) > u64::from(maximum)
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn wire_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn wire_u32_from_u64(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
