//! One-call, field-isolated repair for missing repository-review evidence.
//!
//! Runtime owns every identity and requirement reference. The repair model can
//! only describe the independent evidence needed for controller-defined slots.
//! The complete original reviewer contract is validated before and after the
//! patch, so the repair can neither alter nor upgrade the semantic verdict.

use birdcode_prompting::{
    CompiledPrompt, DataProvenance, DataSection, PromptError, PromptInvocation, PromptKey,
    PromptLimits, PromptRegistry, RepositoryReviewInputV1, RepositoryReviewMissingEvidenceV1,
    RepositoryReviewOutputV1, RepositoryReviewRequirementRefV1,
    RepositoryReviewRequirementStatusV1, RepositoryReviewVerdictV1, RuntimeConstraint, SourceKind,
    TrustLevel, builtin_registry, parse_manifest, validate_repository_review_output,
};
use birdcode_protocol::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const REPOSITORY_REVIEW_MISSING_EVIDENCE_REPAIR_MANIFEST_JSON: &str =
    include_str!("../../../prompts/repository-review-missing-evidence-repair/1.0.0/manifest.json");
pub(crate) const REPOSITORY_REVIEW_MISSING_EVIDENCE_REPAIR_SCHEMA_NAME_V1: &str =
    "repository_review_missing_evidence_repair_v1";
const REPAIR_SECTION: &str = "missing_evidence_context";
const REPAIR_POLICY_CONSTRAINT: &str = "repair_policy";
const REPAIR_ID_DOMAIN: &str = "birdcode.repository-review-missing-evidence-id.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryReviewMissingEvidenceRepairContextV1 {
    pub slot_id: String,
    pub requirement_text: String,
    pub prior_assessment_basis: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryReviewMissingEvidenceRepairInputV1 {
    pub contexts: Vec<RepositoryReviewMissingEvidenceRepairContextV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryReviewMissingEvidenceRepairSlotV1 {
    pub slot_id: String,
    pub missing_evidence_id: String,
    pub requirement: RepositoryReviewRequirementRefV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryReviewMissingEvidenceRepairPolicyV1 {
    pub contract_version: u32,
    pub repair_ordinal: u32,
    pub blind_subject_id: String,
    pub parent_raw_text_sha256: String,
    pub parent_response_artifact_sha256: String,
    pub immutable_projection_sha256: String,
    pub existing_missing_evidence_sha256: String,
    pub slots: Vec<RepositoryReviewMissingEvidenceRepairSlotV1>,
    pub repair_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryReviewMissingEvidenceRepairBindingsV1 {
    pub blind_subject_id: String,
    pub parent_raw_text_sha256: String,
    pub repair_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryReviewMissingEvidenceCompletionV1 {
    pub slot_id: String,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryReviewMissingEvidenceRepairOutputV1 {
    pub schema_version: u32,
    pub bindings: RepositoryReviewMissingEvidenceRepairBindingsV1,
    pub completions: Vec<RepositoryReviewMissingEvidenceCompletionV1>,
}

pub(crate) struct PreparedRepositoryReviewMissingEvidenceRepairV1 {
    pub input: RepositoryReviewMissingEvidenceRepairInputV1,
    pub policy: RepositoryReviewMissingEvidenceRepairPolicyV1,
    pub invocation: PromptInvocation,
    pub compiled: CompiledPrompt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryReviewMissingEvidenceRepairViolationV1 {
    NotRepairable,
    BindingMismatch,
    CompletionCount { expected: usize, actual: usize },
    CompletionOrder { index: usize },
    DuplicateSlot,
    OriginalProjectionMismatch,
    FinalContractInvalid { detail: String },
}

pub(crate) fn repair_registry() -> Result<(PromptRegistry, PromptKey), PromptError> {
    let manifest =
        parse_manifest(REPOSITORY_REVIEW_MISSING_EVIDENCE_REPAIR_MANIFEST_JSON.as_bytes())?;
    let key = manifest.key();
    PromptRegistry::new([manifest]).map(|registry| (registry, key))
}

/// Proves mechanically that missing-evidence coverage is the only defect,
/// then prepares controller-owned repair slots.
pub(crate) fn prepare_repository_review_missing_evidence_repair_v1(
    input: &RepositoryReviewInputV1,
    original_invocation: &PromptInvocation,
    original_compiled: &CompiledPrompt,
    candidate: &RepositoryReviewOutputV1,
    parent_raw_text_sha256: String,
    parent_response_artifact_sha256: String,
) -> Result<
    PreparedRepositoryReviewMissingEvidenceRepairV1,
    RepositoryReviewMissingEvidenceRepairViolationV1,
> {
    if candidate.verdict != RepositoryReviewVerdictV1::Inconclusive
        || candidate.bindings.blind_subject_id != input.source.blind_subject_id
    {
        return Err(RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable);
    }

    let requirement_texts = input
        .requirements
        .iter()
        .map(|requirement| (&requirement.requirement, requirement.text.as_str()))
        .collect::<BTreeMap<_, _>>();
    let not_evaluable = candidate
        .requirement_assessments
        .iter()
        .filter(|assessment| assessment.status == RepositoryReviewRequirementStatusV1::NotEvaluable)
        .map(|assessment| &assessment.requirement)
        .collect::<BTreeSet<_>>();
    if not_evaluable.is_empty() {
        return Err(RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable);
    }

    let mut covered = BTreeSet::new();
    for missing in &candidate.missing_evidence {
        for requirement in &missing.requirement_refs {
            if !not_evaluable.contains(requirement) || !covered.insert(requirement) {
                return Err(RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable);
            }
        }
    }
    let uncovered = candidate
        .requirement_assessments
        .iter()
        .filter(|assessment| {
            assessment.status == RepositoryReviewRequirementStatusV1::NotEvaluable
                && !covered.contains(&assessment.requirement)
        })
        .collect::<Vec<_>>();
    if uncovered.is_empty() {
        return Err(RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable);
    }

    let existing_ids = candidate
        .missing_evidence
        .iter()
        .map(|missing| missing.missing_evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut generated_ids = BTreeSet::new();
    let mut contexts = Vec::with_capacity(uncovered.len());
    let mut slots = Vec::with_capacity(uncovered.len());
    for (index, assessment) in uncovered.iter().enumerate() {
        let Some(requirement_text) = requirement_texts.get(&assessment.requirement) else {
            return Err(RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable);
        };
        let slot_id = format!("missing-{:03}", index + 1);
        let missing_evidence_id = deterministic_missing_evidence_id(
            &parent_raw_text_sha256,
            &assessment.requirement,
            &existing_ids,
            &generated_ids,
        );
        generated_ids.insert(missing_evidence_id.clone());
        contexts.push(RepositoryReviewMissingEvidenceRepairContextV1 {
            slot_id: slot_id.clone(),
            requirement_text: (*requirement_text).to_owned(),
            prior_assessment_basis: assessment.basis.clone(),
        });
        slots.push(RepositoryReviewMissingEvidenceRepairSlotV1 {
            slot_id,
            missing_evidence_id,
            requirement: assessment.requirement.clone(),
        });
    }

    // If controller-owned valid placeholders make the complete original
    // contract pass, no other invariant can be the reason for repair.
    let mut eligibility_probe = candidate.clone();
    eligibility_probe
        .missing_evidence
        .extend(slots.iter().map(|slot| RepositoryReviewMissingEvidenceV1 {
            missing_evidence_id: slot.missing_evidence_id.clone(),
            requirement_refs: vec![slot.requirement.clone()],
            description:
                "Independent runtime evidence is required to evaluate this requirement.".to_owned(),
        }));
    let probe_value = serde_json::to_value(&eligibility_probe)
        .map_err(|_| RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable)?;
    let original_registry = builtin_registry()
        .map_err(|_| RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable)?;
    if original_registry
        .validate_output(original_compiled, original_invocation, &probe_value)
        .is_err()
        || validate_repository_review_output(&probe_value, original_invocation).is_err()
    {
        return Err(RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable);
    }

    let immutable_projection_sha256 = immutable_projection_sha256(candidate)?;
    let existing_missing_evidence_sha256 = digest_json(&candidate.missing_evidence)?;
    let mut policy = RepositoryReviewMissingEvidenceRepairPolicyV1 {
        contract_version: 1,
        repair_ordinal: 1,
        blind_subject_id: candidate.bindings.blind_subject_id.clone(),
        parent_raw_text_sha256,
        parent_response_artifact_sha256,
        immutable_projection_sha256,
        existing_missing_evidence_sha256,
        slots,
        repair_policy_sha256: String::new(),
    };
    policy.repair_policy_sha256 = digest_json(&policy)?;
    let repair_input = RepositoryReviewMissingEvidenceRepairInputV1 { contexts };
    let invocation = PromptInvocation::with_runtime_constraints(
        vec![DataSection {
            name: REPAIR_SECTION.to_owned(),
            trust: TrustLevel::UntrustedExternal,
            provenance: DataProvenance {
                source_kind: SourceKind::External,
                source_id: format!(
                    "repository-review-response-sha256:{}",
                    policy.parent_raw_text_sha256
                ),
                artifact_sha256: Some(policy.parent_response_artifact_sha256.clone()),
                event_id: None,
            },
            payload: serde_json::to_value(&repair_input)
                .map_err(|_| RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable)?,
        }],
        PromptLimits::new(0),
        vec![RuntimeConstraint {
            name: REPAIR_POLICY_CONSTRAINT.to_owned(),
            payload: serde_json::to_value(&policy)
                .map_err(|_| RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable)?,
        }],
    );
    let (registry, key) = repair_registry()
        .map_err(|_| RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable)?;
    let compiled = registry
        .compile(&key, &invocation)
        .map_err(|_| RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable)?;
    Ok(PreparedRepositoryReviewMissingEvidenceRepairV1 {
        input: repair_input,
        policy,
        invocation,
        compiled,
    })
}

pub(crate) fn apply_repository_review_missing_evidence_repair_v1(
    mut candidate: RepositoryReviewOutputV1,
    original_invocation: &PromptInvocation,
    original_compiled: &CompiledPrompt,
    prepared: &PreparedRepositoryReviewMissingEvidenceRepairV1,
    patch: RepositoryReviewMissingEvidenceRepairOutputV1,
) -> Result<RepositoryReviewOutputV1, Vec<RepositoryReviewMissingEvidenceRepairViolationV1>> {
    let mut violations = Vec::new();
    if patch.schema_version != 1
        || patch.bindings.blind_subject_id != prepared.policy.blind_subject_id
        || patch.bindings.parent_raw_text_sha256 != prepared.policy.parent_raw_text_sha256
        || patch.bindings.repair_policy_sha256 != prepared.policy.repair_policy_sha256
    {
        violations.push(RepositoryReviewMissingEvidenceRepairViolationV1::BindingMismatch);
    }
    if patch.completions.len() != prepared.policy.slots.len() {
        violations.push(
            RepositoryReviewMissingEvidenceRepairViolationV1::CompletionCount {
                expected: prepared.policy.slots.len(),
                actual: patch.completions.len(),
            },
        );
    }
    let mut seen = BTreeSet::new();
    for (index, completion) in patch.completions.iter().enumerate() {
        if !seen.insert(completion.slot_id.as_str()) {
            violations.push(RepositoryReviewMissingEvidenceRepairViolationV1::DuplicateSlot);
        }
        if prepared
            .policy
            .slots
            .get(index)
            .map(|slot| slot.slot_id.as_str())
            != Some(completion.slot_id.as_str())
        {
            violations
                .push(RepositoryReviewMissingEvidenceRepairViolationV1::CompletionOrder { index });
        }
    }
    if immutable_projection_sha256(&candidate).ok().as_deref()
        != Some(prepared.policy.immutable_projection_sha256.as_str())
        || digest_json(&candidate.missing_evidence).ok().as_deref()
            != Some(prepared.policy.existing_missing_evidence_sha256.as_str())
    {
        violations
            .push(RepositoryReviewMissingEvidenceRepairViolationV1::OriginalProjectionMismatch);
    }
    if !violations.is_empty() {
        return Err(violations);
    }

    let existing_len = candidate.missing_evidence.len();
    candidate
        .missing_evidence
        .extend(
            prepared
                .policy
                .slots
                .iter()
                .zip(patch.completions)
                .map(|(slot, completion)| RepositoryReviewMissingEvidenceV1 {
                    missing_evidence_id: slot.missing_evidence_id.clone(),
                    requirement_refs: vec![slot.requirement.clone()],
                    description: completion.description,
                }),
        );
    let final_contract_error = serde_json::to_value(&candidate)
        .map_err(|error| error.to_string())
        .and_then(|value| {
            builtin_registry()
                .map_err(|error| error.to_string())?
                .validate_output(original_compiled, original_invocation, &value)
                .map_err(|error| error.to_string())
        })
        .err();
    if immutable_projection_sha256(&candidate).ok().as_deref()
        != Some(prepared.policy.immutable_projection_sha256.as_str())
        || digest_json(&candidate.missing_evidence[..existing_len])
            .ok()
            .as_deref()
            != Some(prepared.policy.existing_missing_evidence_sha256.as_str())
        || final_contract_error.is_some()
    {
        return Err(vec![
            RepositoryReviewMissingEvidenceRepairViolationV1::FinalContractInvalid {
                detail: final_contract_error
                    .unwrap_or_else(|| "immutable projection changed".to_owned()),
            },
        ]);
    }
    Ok(candidate)
}

fn immutable_projection_sha256(
    candidate: &RepositoryReviewOutputV1,
) -> Result<String, RepositoryReviewMissingEvidenceRepairViolationV1> {
    let mut projection = candidate.clone();
    projection.missing_evidence.clear();
    digest_json(&projection)
}

fn digest_json<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, RepositoryReviewMissingEvidenceRepairViolationV1> {
    serde_json::to_vec(value)
        .map(|bytes| Sha256Digest::of_bytes(&bytes).as_str().to_owned())
        .map_err(|_| RepositoryReviewMissingEvidenceRepairViolationV1::NotRepairable)
}

fn deterministic_missing_evidence_id(
    parent_raw_text_sha256: &str,
    requirement: &RepositoryReviewRequirementRefV1,
    existing: &BTreeSet<&str>,
    generated: &BTreeSet<String>,
) -> String {
    for counter in 0_u32.. {
        let material = format!(
            "{REPAIR_ID_DOMAIN}\0{parent_raw_text_sha256}\0{}\0{}\0{counter}",
            requirement.requirement_id, requirement.requirement_sha256
        );
        let digest = Sha256Digest::of_bytes(material.as_bytes());
        let candidate = format!("missing-{}", &digest.as_str()[..32]);
        if !existing.contains(candidate.as_str()) && !generated.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("finite existing IDs cannot exhaust the SHA-256 identifier space")
}
