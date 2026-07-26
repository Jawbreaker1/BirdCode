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

const REPOSITORY_REVIEWER_ID: &str = "birdcode.repository-semantic-reviewer";
pub const REPOSITORY_REVIEW_CONTRACT_VERSION_V1: u32 = 1;
pub const REPOSITORY_REVIEW_SOURCE_SECTION_V1: &str = "review_source";
pub const REPOSITORY_REVIEW_REQUIREMENTS_SECTION_V1: &str = "requirements";
pub const REPOSITORY_REVIEW_CANDIDATE_ARTIFACTS_SECTION_V1: &str = "candidate_artifacts";
pub const REPOSITORY_REVIEW_PRODUCER_CLAIM_SECTION_V1: &str = "producer_claim";
pub const REPOSITORY_REVIEW_POLICY_CONSTRAINT_V1: &str = "review_policy";
pub const REPOSITORY_REVIEW_MAX_REQUIREMENTS_V1: usize = 32;
pub const REPOSITORY_REVIEW_MAX_FINDINGS_V1: u32 = 24;
pub const REPOSITORY_REVIEW_MAX_EVIDENCE_REFERENCES_V1: u32 = 128;
const MAX_IDENTIFIER_CHARACTERS: usize = 128;
const MAX_TEXT_CHARACTERS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 64 * 1_024;
const MAX_PRODUCER_CLAIMS: usize = 32;
const REQUIREMENT_DIGEST_DOMAIN: &[u8] = b"birdcode.repository-review-requirement.v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewScopeV1 {
    ExactUtf8ReplaceArtifactReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewEvidenceHandleV1 {
    Preimage,
    Postimage,
    Diff,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub enum RepositoryReviewPathComponentV1 {
    Utf8 { value: String },
    UnixBytes { value: Vec<u8> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewPathV1 {
    pub components: Vec<RepositoryReviewPathComponentV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewSourceInputV1 {
    pub blind_subject_id: String,
    pub scope: RepositoryReviewScopeV1,
    pub identity_blinding: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewRequirementRefV1 {
    pub requirement_id: String,
    pub requirement_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewRequirementKindV1 {
    Objective,
    AcceptanceCriterion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewRequirementInputV1 {
    pub requirement: RepositoryReviewRequirementRefV1,
    pub kind: RepositoryReviewRequirementKindV1,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewArtifactInputV1 {
    pub handle: RepositoryReviewEvidenceHandleV1,
    pub content_utf8: String,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewCandidateArtifactsInputV1 {
    pub path: RepositoryReviewPathV1,
    pub artifacts: Vec<RepositoryReviewArtifactInputV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewProducerClaimInputV1 {
    pub summary: String,
    pub findings: Vec<String>,
    pub unknowns: Vec<String>,
    pub recommended_followups: Vec<String>,
}

/// Exact runtime-identity-blinded material visible to one repository reviewer.
///
/// This deliberately contains no graph, work-order, actor, execution, attempt,
/// event, artifact, backend, deployment, model, or lineage identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewInputV1 {
    pub source: RepositoryReviewSourceInputV1,
    pub requirements: Vec<RepositoryReviewRequirementInputV1>,
    pub candidate_artifacts: RepositoryReviewCandidateArtifactsInputV1,
    pub producer_claim: RepositoryReviewProducerClaimInputV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewEvidenceBindingV1 {
    pub handle: RepositoryReviewEvidenceHandleV1,
    pub line_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryReviewPolicyMaterialV1 {
    pub blind_subject_id: String,
    pub scope: RepositoryReviewScopeV1,
    pub visible_payload_sha256: String,
    pub requirements: Vec<RepositoryReviewRequirementRefV1>,
    pub evidence: Vec<RepositoryReviewEvidenceBindingV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewPolicyV1 {
    pub contract_version: u32,
    pub blind_subject_id: String,
    pub scope: RepositoryReviewScopeV1,
    pub visible_payload_sha256: String,
    pub requirements: Vec<RepositoryReviewRequirementRefV1>,
    pub evidence: Vec<RepositoryReviewEvidenceBindingV1>,
    pub max_findings: u32,
    pub max_evidence_references: u32,
    pub review_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryReviewPolicyViolationV1 {
    InvalidContractVersion {
        actual: u32,
    },
    InvalidIdentifier {
        field: String,
    },
    InvalidDigest {
        field: String,
    },
    RequirementCount {
        actual: u32,
    },
    DuplicateRequirement {
        requirement_id: String,
    },
    RequirementDigestMismatch {
        requirement_id: String,
    },
    EvidenceSetMismatch,
    EvidenceIncomplete {
        handle: RepositoryReviewEvidenceHandleV1,
    },
    CollectionLimit {
        field: String,
    },
    PolicyDigestMismatch,
    CanonicalEncoding,
}

impl RepositoryReviewPolicyV1 {
    /// Creates a closed v1 policy from controller-owned material.
    ///
    /// # Errors
    ///
    /// Returns mechanical binding, set, digest, or limit violations. Natural
    /// language is never classified here.
    pub fn new(
        material: RepositoryReviewPolicyMaterialV1,
    ) -> Result<Self, Vec<RepositoryReviewPolicyViolationV1>> {
        let mut policy = Self {
            contract_version: REPOSITORY_REVIEW_CONTRACT_VERSION_V1,
            blind_subject_id: material.blind_subject_id,
            scope: material.scope,
            visible_payload_sha256: material.visible_payload_sha256,
            requirements: material.requirements,
            evidence: material.evidence,
            max_findings: REPOSITORY_REVIEW_MAX_FINDINGS_V1,
            max_evidence_references: REPOSITORY_REVIEW_MAX_EVIDENCE_REFERENCES_V1,
            review_policy_sha256: String::new(),
        };
        let violations = policy_structure_violations(&policy);
        if !violations.is_empty() {
            return Err(violations);
        }
        policy.review_policy_sha256 = policy_content_sha256(&policy)
            .map_err(|_| vec![RepositoryReviewPolicyViolationV1::CanonicalEncoding])?;
        Ok(policy)
    }

    /// Revalidates all closed v1 fields and the policy self-commitment.
    ///
    /// # Errors
    ///
    /// Returns every mechanical integrity violation.
    pub fn validate_integrity(&self) -> Result<(), Vec<RepositoryReviewPolicyViolationV1>> {
        let mut violations = policy_structure_violations(self);
        match policy_content_sha256(self) {
            Ok(expected) if expected == self.review_policy_sha256 => {}
            Ok(_) => violations.push(RepositoryReviewPolicyViolationV1::PolicyDigestMismatch),
            Err(_) => violations.push(RepositoryReviewPolicyViolationV1::CanonicalEncoding),
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Derives the exact v1 policy from the material that will cross the model
/// boundary.
///
/// # Errors
///
/// Rejects incomplete artifacts, substituted requirement digests, duplicate
/// handles, invalid bounds, or canonical encoding failures.
pub fn derive_repository_review_policy_v1(
    input: &RepositoryReviewInputV1,
) -> Result<RepositoryReviewPolicyV1, Vec<RepositoryReviewPolicyViolationV1>> {
    let mut violations = input_violations(input);
    let visible_payload_sha256 = match canonical_sha256(input) {
        Ok(digest) => digest,
        Err(_) => {
            violations.push(RepositoryReviewPolicyViolationV1::CanonicalEncoding);
            String::new()
        }
    };
    if !violations.is_empty() {
        return Err(violations);
    }
    let evidence = input
        .candidate_artifacts
        .artifacts
        .iter()
        .map(|artifact| RepositoryReviewEvidenceBindingV1 {
            handle: artifact.handle,
            line_count: logical_line_count(&artifact.content_utf8),
        })
        .collect();
    RepositoryReviewPolicyV1::new(RepositoryReviewPolicyMaterialV1 {
        blind_subject_id: input.source.blind_subject_id.clone(),
        scope: input.source.scope,
        visible_payload_sha256,
        requirements: input
            .requirements
            .iter()
            .map(|requirement| requirement.requirement.clone())
            .collect(),
        evidence,
    })
}

/// Builds the four-section, one-policy invocation used by the versioned prompt.
///
/// # Errors
///
/// Rejects any policy that is not exactly derived from `input`.
pub fn repository_review_invocation_v1(
    input: &RepositoryReviewInputV1,
    policy: &RepositoryReviewPolicyV1,
) -> Result<PromptInvocation, Vec<RepositoryReviewPolicyViolationV1>> {
    let expected = derive_repository_review_policy_v1(input)?;
    if &expected != policy {
        return Err(vec![
            RepositoryReviewPolicyViolationV1::PolicyDigestMismatch,
        ]);
    }
    let sections = vec![
        section(
            REPOSITORY_REVIEW_SOURCE_SECTION_V1,
            TrustLevel::Tool,
            SourceKind::Tool,
            &input.source,
        )?,
        section(
            REPOSITORY_REVIEW_REQUIREMENTS_SECTION_V1,
            TrustLevel::UntrustedExternal,
            SourceKind::External,
            &input.requirements,
        )?,
        section(
            REPOSITORY_REVIEW_CANDIDATE_ARTIFACTS_SECTION_V1,
            TrustLevel::Repository,
            SourceKind::Repository,
            &input.candidate_artifacts,
        )?,
        section(
            REPOSITORY_REVIEW_PRODUCER_CLAIM_SECTION_V1,
            TrustLevel::UntrustedExternal,
            SourceKind::External,
            &input.producer_claim,
        )?,
    ];
    Ok(PromptInvocation::with_runtime_constraints(
        sections,
        PromptLimits::new(0),
        vec![RuntimeConstraint {
            name: REPOSITORY_REVIEW_POLICY_CONSTRAINT_V1.to_owned(),
            payload: serde_json::to_value(policy)
                .map_err(|_| vec![RepositoryReviewPolicyViolationV1::CanonicalEncoding])?,
        }],
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewBindingsV1 {
    pub blind_subject_id: String,
    pub scope: RepositoryReviewScopeV1,
    pub visible_payload_sha256: String,
    pub review_policy_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewVerdictV1 {
    Pass,
    Revise,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewRequirementStatusV1 {
    Satisfied,
    Partial,
    Unsatisfied,
    NotEvaluable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewLineSpanV1 {
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewEvidenceRefV1 {
    pub handle: RepositoryReviewEvidenceHandleV1,
    pub line_span: Option<RepositoryReviewLineSpanV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewRequirementAssessmentV1 {
    pub requirement: RepositoryReviewRequirementRefV1,
    pub status: RepositoryReviewRequirementStatusV1,
    pub basis: String,
    pub evidence: Vec<RepositoryReviewEvidenceRefV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewFindingSeverityV1 {
    Blocker,
    Major,
    Minor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewFindingCategoryV1 {
    Correctness,
    Requirements,
    Buildability,
    Security,
    Maintainability,
    Compatibility,
    DataIntegrity,
    EvidenceGap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryReviewConfidenceV1 {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewFindingV1 {
    pub finding_id: String,
    pub severity: RepositoryReviewFindingSeverityV1,
    pub category: RepositoryReviewFindingCategoryV1,
    pub statement: String,
    pub causal_consequence: String,
    pub required_change: String,
    pub confidence: RepositoryReviewConfidenceV1,
    pub evidence: Vec<RepositoryReviewEvidenceRefV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewMissingEvidenceV1 {
    pub missing_evidence_id: String,
    pub requirement_refs: Vec<RepositoryReviewRequirementRefV1>,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewOutputV1 {
    pub schema_version: u32,
    pub bindings: RepositoryReviewBindingsV1,
    pub verdict: RepositoryReviewVerdictV1,
    pub summary: String,
    pub requirement_assessments: Vec<RepositoryReviewRequirementAssessmentV1>,
    pub findings: Vec<RepositoryReviewFindingV1>,
    pub missing_evidence: Vec<RepositoryReviewMissingEvidenceV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryReviewInvariantViolationV1 {
    InvalidInvocation,
    InvalidOutput,
    BindingMismatch,
    AssessmentCount { expected: u32, actual: u32 },
    DuplicateAssessment { requirement_id: String },
    UnknownRequirement { requirement_id: String },
    RequirementDigestMismatch { requirement_id: String },
    DuplicateFindingId { finding_id: String },
    DuplicateMissingEvidenceId { missing_evidence_id: String },
    MissingEvidenceCoverage { requirement_id: String },
    UnknownEvidenceHandle,
    InvalidEvidenceSpan,
    EvidenceReferenceLimit,
    InvalidText { field: String },
    VerdictShape,
}

/// Checks exact input bindings and the closed verdict/evidence invariants.
///
/// # Errors
///
/// Returns deterministic contract violations. It never judges semantic truth.
pub fn validate_repository_review_output(
    value: &Value,
    invocation: &PromptInvocation,
) -> Result<(), Vec<RepositoryReviewInvariantViolationV1>> {
    let Some((input, policy)) = input_and_policy_from_invocation(invocation) else {
        return Err(vec![
            RepositoryReviewInvariantViolationV1::InvalidInvocation,
        ]);
    };
    let Ok(expected_policy) = derive_repository_review_policy_v1(&input) else {
        return Err(vec![
            RepositoryReviewInvariantViolationV1::InvalidInvocation,
        ]);
    };
    if policy != expected_policy || policy.validate_integrity().is_err() {
        return Err(vec![
            RepositoryReviewInvariantViolationV1::InvalidInvocation,
        ]);
    }
    let Ok(output) = serde_json::from_value::<RepositoryReviewOutputV1>(value.clone()) else {
        return Err(vec![RepositoryReviewInvariantViolationV1::InvalidOutput]);
    };
    let mut violations = Vec::new();
    if output.schema_version != REPOSITORY_REVIEW_CONTRACT_VERSION_V1
        || output.bindings.blind_subject_id != policy.blind_subject_id
        || output.bindings.scope != policy.scope
        || output.bindings.visible_payload_sha256 != policy.visible_payload_sha256
        || output.bindings.review_policy_sha256 != policy.review_policy_sha256
    {
        violations.push(RepositoryReviewInvariantViolationV1::BindingMismatch);
    }
    collect_assessment_violations(&output, &policy, &mut violations);
    collect_finding_violations(&output, &policy, &mut violations);
    collect_missing_evidence_violations(&output, &policy, &mut violations);
    collect_verdict_shape_violations(&output, &mut violations);
    if !bounded_text(&output.summary) {
        violations.push(RepositoryReviewInvariantViolationV1::InvalidText {
            field: "summary".to_owned(),
        });
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[must_use]
pub fn repository_reviewer_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(REPOSITORY_REVIEWER_ID).expect("repository reviewer ID is static and valid"),
        Version::new(1, 0, 0),
    )
}

pub(crate) fn is_repository_reviewer_key(key: &PromptKey) -> bool {
    key == &repository_reviewer_key()
}

#[must_use]
pub fn repository_review_requirement_sha256(text: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(REQUIREMENT_DIGEST_DOMAIN);
    digest.update(text.as_bytes());
    format!("{:x}", digest.finalize())
}

fn section<T: Serialize>(
    name: &str,
    trust: TrustLevel,
    source_kind: SourceKind,
    payload: &T,
) -> Result<DataSection, Vec<RepositoryReviewPolicyViolationV1>> {
    Ok(DataSection {
        name: name.to_owned(),
        trust,
        provenance: DataProvenance {
            source_kind,
            source_id: format!("repository-review:{name}"),
            artifact_sha256: None,
            event_id: None,
        },
        payload: serde_json::to_value(payload)
            .map_err(|_| vec![RepositoryReviewPolicyViolationV1::CanonicalEncoding])?,
    })
}

fn input_violations(input: &RepositoryReviewInputV1) -> Vec<RepositoryReviewPolicyViolationV1> {
    let mut violations = Vec::new();
    if !bounded_identifier(&input.source.blind_subject_id) {
        violations.push(RepositoryReviewPolicyViolationV1::InvalidIdentifier {
            field: "blind_subject_id".to_owned(),
        });
    }
    if input.source.identity_blinding != "runtime_identity_blinded" {
        violations.push(RepositoryReviewPolicyViolationV1::InvalidIdentifier {
            field: "identity_blinding".to_owned(),
        });
    }
    if input.requirements.is_empty()
        || input.requirements.len() > REPOSITORY_REVIEW_MAX_REQUIREMENTS_V1
    {
        violations.push(RepositoryReviewPolicyViolationV1::RequirementCount {
            actual: wire_u32(input.requirements.len()),
        });
    }
    let mut requirements = BTreeSet::new();
    for requirement in &input.requirements {
        if !bounded_identifier(&requirement.requirement.requirement_id) {
            violations.push(RepositoryReviewPolicyViolationV1::InvalidIdentifier {
                field: "requirement_id".to_owned(),
            });
        }
        if !bounded_text(&requirement.text) {
            violations.push(RepositoryReviewPolicyViolationV1::CollectionLimit {
                field: "requirement_text".to_owned(),
            });
        }
        if !requirements.insert(requirement.requirement.requirement_id.as_str()) {
            violations.push(RepositoryReviewPolicyViolationV1::DuplicateRequirement {
                requirement_id: requirement.requirement.requirement_id.clone(),
            });
        }
        if requirement.requirement.requirement_sha256
            != repository_review_requirement_sha256(&requirement.text)
        {
            violations.push(
                RepositoryReviewPolicyViolationV1::RequirementDigestMismatch {
                    requirement_id: requirement.requirement.requirement_id.clone(),
                },
            );
        }
    }
    let mut handles = BTreeSet::new();
    for artifact in &input.candidate_artifacts.artifacts {
        if !artifact.complete {
            violations.push(RepositoryReviewPolicyViolationV1::EvidenceIncomplete {
                handle: artifact.handle,
            });
        }
        if !handles.insert(artifact.handle) {
            violations.push(RepositoryReviewPolicyViolationV1::EvidenceSetMismatch);
        }
    }
    let expected = BTreeSet::from([
        RepositoryReviewEvidenceHandleV1::Preimage,
        RepositoryReviewEvidenceHandleV1::Postimage,
        RepositoryReviewEvidenceHandleV1::Diff,
    ]);
    if handles != expected {
        violations.push(RepositoryReviewPolicyViolationV1::EvidenceSetMismatch);
    }
    let claims = &input.producer_claim;
    if !bounded_text(&claims.summary)
        || claims.findings.len() > MAX_PRODUCER_CLAIMS
        || claims.unknowns.len() > MAX_PRODUCER_CLAIMS
        || claims.recommended_followups.len() > MAX_PRODUCER_CLAIMS
        || claims
            .findings
            .iter()
            .chain(&claims.unknowns)
            .chain(&claims.recommended_followups)
            .any(|text| !bounded_text(text))
    {
        violations.push(RepositoryReviewPolicyViolationV1::CollectionLimit {
            field: "producer_claim".to_owned(),
        });
    }
    violations
}

fn policy_structure_violations(
    policy: &RepositoryReviewPolicyV1,
) -> Vec<RepositoryReviewPolicyViolationV1> {
    let mut violations = Vec::new();
    if policy.contract_version != REPOSITORY_REVIEW_CONTRACT_VERSION_V1 {
        violations.push(RepositoryReviewPolicyViolationV1::InvalidContractVersion {
            actual: policy.contract_version,
        });
    }
    if !bounded_identifier(&policy.blind_subject_id) {
        violations.push(RepositoryReviewPolicyViolationV1::InvalidIdentifier {
            field: "blind_subject_id".to_owned(),
        });
    }
    for (field, digest) in [
        ("visible_payload_sha256", &policy.visible_payload_sha256),
        ("review_policy_sha256", &policy.review_policy_sha256),
    ] {
        if field == "review_policy_sha256" && digest.is_empty() {
            continue;
        }
        if !valid_digest(digest) {
            violations.push(RepositoryReviewPolicyViolationV1::InvalidDigest {
                field: field.to_owned(),
            });
        }
    }
    if policy.requirements.is_empty()
        || policy.requirements.len() > REPOSITORY_REVIEW_MAX_REQUIREMENTS_V1
    {
        violations.push(RepositoryReviewPolicyViolationV1::RequirementCount {
            actual: wire_u32(policy.requirements.len()),
        });
    }
    let mut requirements = BTreeSet::new();
    for requirement in &policy.requirements {
        if !requirements.insert((
            requirement.requirement_id.as_str(),
            requirement.requirement_sha256.as_str(),
        )) {
            violations.push(RepositoryReviewPolicyViolationV1::DuplicateRequirement {
                requirement_id: requirement.requirement_id.clone(),
            });
        }
        if !bounded_identifier(&requirement.requirement_id)
            || !valid_digest(&requirement.requirement_sha256)
        {
            violations.push(RepositoryReviewPolicyViolationV1::InvalidDigest {
                field: "requirement".to_owned(),
            });
        }
    }
    let handles = policy
        .evidence
        .iter()
        .map(|evidence| evidence.handle)
        .collect::<BTreeSet<_>>();
    if handles
        != BTreeSet::from([
            RepositoryReviewEvidenceHandleV1::Preimage,
            RepositoryReviewEvidenceHandleV1::Postimage,
            RepositoryReviewEvidenceHandleV1::Diff,
        ])
        || handles.len() != policy.evidence.len()
    {
        violations.push(RepositoryReviewPolicyViolationV1::EvidenceSetMismatch);
    }
    if policy.max_findings != REPOSITORY_REVIEW_MAX_FINDINGS_V1
        || policy.max_evidence_references != REPOSITORY_REVIEW_MAX_EVIDENCE_REFERENCES_V1
    {
        violations.push(RepositoryReviewPolicyViolationV1::CollectionLimit {
            field: "policy_limits".to_owned(),
        });
    }
    violations
}

fn input_and_policy_from_invocation(
    invocation: &PromptInvocation,
) -> Option<(RepositoryReviewInputV1, RepositoryReviewPolicyV1)> {
    if invocation.limits != PromptLimits::new(0)
        || invocation.runtime_constraints.len() != 1
        || invocation.runtime_constraints[0].name != REPOSITORY_REVIEW_POLICY_CONSTRAINT_V1
    {
        return None;
    }
    let policy = serde_json::from_value::<RepositoryReviewPolicyV1>(
        invocation.runtime_constraints[0].payload.clone(),
    )
    .ok()?;
    let sections = invocation
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section))
        .collect::<BTreeMap<_, _>>();
    if sections.len() != 4 {
        return None;
    }
    let source = section_payload(
        &sections,
        REPOSITORY_REVIEW_SOURCE_SECTION_V1,
        TrustLevel::Tool,
        SourceKind::Tool,
    )?;
    let requirements = section_payload(
        &sections,
        REPOSITORY_REVIEW_REQUIREMENTS_SECTION_V1,
        TrustLevel::UntrustedExternal,
        SourceKind::External,
    )?;
    let candidate_artifacts = section_payload(
        &sections,
        REPOSITORY_REVIEW_CANDIDATE_ARTIFACTS_SECTION_V1,
        TrustLevel::Repository,
        SourceKind::Repository,
    )?;
    let producer_claim = section_payload(
        &sections,
        REPOSITORY_REVIEW_PRODUCER_CLAIM_SECTION_V1,
        TrustLevel::UntrustedExternal,
        SourceKind::External,
    )?;
    Some((
        RepositoryReviewInputV1 {
            source,
            requirements,
            candidate_artifacts,
            producer_claim,
        },
        policy,
    ))
}

fn section_payload<T: for<'de> Deserialize<'de>>(
    sections: &BTreeMap<&str, &DataSection>,
    name: &str,
    trust: TrustLevel,
    source_kind: SourceKind,
) -> Option<T> {
    let section = sections.get(name)?;
    if section.trust != trust || section.provenance.source_kind != source_kind {
        return None;
    }
    serde_json::from_value(section.payload.clone()).ok()
}

fn collect_assessment_violations(
    output: &RepositoryReviewOutputV1,
    policy: &RepositoryReviewPolicyV1,
    violations: &mut Vec<RepositoryReviewInvariantViolationV1>,
) {
    let expected = policy
        .requirements
        .iter()
        .map(|requirement| {
            (
                requirement.requirement_id.as_str(),
                requirement.requirement_sha256.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for assessment in &output.requirement_assessments {
        let reference = (
            assessment.requirement.requirement_id.as_str(),
            assessment.requirement.requirement_sha256.as_str(),
        );
        if !seen.insert(reference) {
            violations.push(RepositoryReviewInvariantViolationV1::DuplicateAssessment {
                requirement_id: reference.0.to_owned(),
            });
        }
        if !expected.contains(&reference) {
            if policy.requirements.iter().any(|requirement| {
                requirement.requirement_id == assessment.requirement.requirement_id
            }) {
                violations.push(
                    RepositoryReviewInvariantViolationV1::RequirementDigestMismatch {
                        requirement_id: reference.0.to_owned(),
                    },
                );
            } else {
                violations.push(RepositoryReviewInvariantViolationV1::UnknownRequirement {
                    requirement_id: reference.0.to_owned(),
                });
            }
        }
        if !bounded_text(&assessment.basis) {
            violations.push(RepositoryReviewInvariantViolationV1::InvalidText {
                field: "assessment_basis".to_owned(),
            });
        }
        if assessment.status != RepositoryReviewRequirementStatusV1::NotEvaluable
            && assessment.evidence.is_empty()
        {
            violations.push(RepositoryReviewInvariantViolationV1::VerdictShape);
        }
        collect_evidence_violations(&assessment.evidence, policy, violations);
    }
    if output.requirement_assessments.len() != policy.requirements.len() {
        violations.push(RepositoryReviewInvariantViolationV1::AssessmentCount {
            expected: wire_u32(policy.requirements.len()),
            actual: wire_u32(output.requirement_assessments.len()),
        });
    }
}

fn collect_finding_violations(
    output: &RepositoryReviewOutputV1,
    policy: &RepositoryReviewPolicyV1,
    violations: &mut Vec<RepositoryReviewInvariantViolationV1>,
) {
    if wire_u32(output.findings.len()) > policy.max_findings {
        violations.push(RepositoryReviewInvariantViolationV1::VerdictShape);
    }
    let mut ids = BTreeSet::new();
    for finding in &output.findings {
        if !bounded_identifier(&finding.finding_id) || !ids.insert(finding.finding_id.as_str()) {
            violations.push(RepositoryReviewInvariantViolationV1::DuplicateFindingId {
                finding_id: finding.finding_id.clone(),
            });
        }
        for (field, text) in [
            ("finding_statement", &finding.statement),
            ("finding_causal_consequence", &finding.causal_consequence),
            ("finding_required_change", &finding.required_change),
        ] {
            if !bounded_text(text) {
                violations.push(RepositoryReviewInvariantViolationV1::InvalidText {
                    field: field.to_owned(),
                });
            }
        }
        if finding.evidence.is_empty() {
            violations.push(RepositoryReviewInvariantViolationV1::VerdictShape);
        }
        collect_evidence_violations(&finding.evidence, policy, violations);
    }
}

fn collect_missing_evidence_violations(
    output: &RepositoryReviewOutputV1,
    policy: &RepositoryReviewPolicyV1,
    violations: &mut Vec<RepositoryReviewInvariantViolationV1>,
) {
    let expected = policy.requirements.iter().collect::<BTreeSet<_>>();
    let not_evaluable = output
        .requirement_assessments
        .iter()
        .filter(|assessment| assessment.status == RepositoryReviewRequirementStatusV1::NotEvaluable)
        .map(|assessment| &assessment.requirement)
        .collect::<BTreeSet<_>>();
    let mut covered = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for missing in &output.missing_evidence {
        if !bounded_identifier(&missing.missing_evidence_id)
            || !ids.insert(missing.missing_evidence_id.as_str())
        {
            violations.push(
                RepositoryReviewInvariantViolationV1::DuplicateMissingEvidenceId {
                    missing_evidence_id: missing.missing_evidence_id.clone(),
                },
            );
        }
        if !bounded_text(&missing.description) || missing.requirement_refs.is_empty() {
            violations.push(RepositoryReviewInvariantViolationV1::VerdictShape);
        }
        for requirement in &missing.requirement_refs {
            covered.insert(requirement);
            if !expected.contains(requirement) {
                violations.push(RepositoryReviewInvariantViolationV1::UnknownRequirement {
                    requirement_id: requirement.requirement_id.clone(),
                });
            }
        }
    }
    for requirement in not_evaluable.difference(&covered) {
        violations.push(
            RepositoryReviewInvariantViolationV1::MissingEvidenceCoverage {
                requirement_id: requirement.requirement_id.clone(),
            },
        );
    }
}

fn collect_evidence_violations(
    evidence: &[RepositoryReviewEvidenceRefV1],
    policy: &RepositoryReviewPolicyV1,
    violations: &mut Vec<RepositoryReviewInvariantViolationV1>,
) {
    let lines = policy
        .evidence
        .iter()
        .map(|binding| (binding.handle, binding.line_count))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for reference in evidence {
        let span_key = reference
            .line_span
            .map(|span| (span.start_line, span.end_line));
        if !seen.insert((reference.handle, span_key)) {
            violations.push(RepositoryReviewInvariantViolationV1::InvalidEvidenceSpan);
        }
        let Some(line_count) = lines.get(&reference.handle) else {
            violations.push(RepositoryReviewInvariantViolationV1::UnknownEvidenceHandle);
            continue;
        };
        if let Some(span) = reference.line_span {
            if span.start_line == 0
                || span.end_line < span.start_line
                || span.end_line > *line_count
            {
                violations.push(RepositoryReviewInvariantViolationV1::InvalidEvidenceSpan);
            }
        }
    }
}

fn collect_verdict_shape_violations(
    output: &RepositoryReviewOutputV1,
    violations: &mut Vec<RepositoryReviewInvariantViolationV1>,
) {
    let has_partial_or_unsatisfied = output.requirement_assessments.iter().any(|assessment| {
        matches!(
            assessment.status,
            RepositoryReviewRequirementStatusV1::Partial
                | RepositoryReviewRequirementStatusV1::Unsatisfied
        )
    });
    let has_not_evaluable = output
        .requirement_assessments
        .iter()
        .any(|assessment| assessment.status == RepositoryReviewRequirementStatusV1::NotEvaluable);
    let valid = match output.verdict {
        RepositoryReviewVerdictV1::Pass => {
            output.requirement_assessments.iter().all(|assessment| {
                assessment.status == RepositoryReviewRequirementStatusV1::Satisfied
            }) && output.findings.is_empty()
                && output.missing_evidence.is_empty()
        }
        RepositoryReviewVerdictV1::Revise => {
            has_partial_or_unsatisfied
                && !output.findings.is_empty()
                && output.missing_evidence.is_empty()
        }
        RepositoryReviewVerdictV1::Inconclusive => {
            has_not_evaluable && !output.missing_evidence.is_empty()
        }
    };
    if !valid {
        violations.push(RepositoryReviewInvariantViolationV1::VerdictShape);
    }
    let evidence_count = output
        .requirement_assessments
        .iter()
        .map(|assessment| assessment.evidence.len() as u64)
        .chain(
            output
                .findings
                .iter()
                .map(|finding| finding.evidence.len() as u64),
        )
        .sum::<u64>();
    if evidence_count > u64::from(REPOSITORY_REVIEW_MAX_EVIDENCE_REFERENCES_V1) {
        violations.push(RepositoryReviewInvariantViolationV1::EvidenceReferenceLimit);
    }
}

fn policy_content_sha256(policy: &RepositoryReviewPolicyV1) -> Result<String, serde_json::Error> {
    let mut material = policy.clone();
    material.review_policy_sha256.clear();
    canonical_sha256(&material)
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let encoded = crate::canonical::encode(&value)?;
    Ok(format!("{:x}", Sha256::digest(encoded.as_bytes())))
}

fn logical_line_count(value: &str) -> u32 {
    if value.is_empty() {
        0
    } else {
        wire_u32(
            value
                .as_bytes()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count()
                .saturating_add(1),
        )
    }
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= MAX_IDENTIFIER_CHARACTERS
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_TEXT_CHARACTERS
        && value.len() <= MAX_TEXT_BYTES
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
