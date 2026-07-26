//! Runtime-identity-blinded projection for the artifact-only repository reviewer.
//!
//! Real graph, actor, execution, attempt, event, candidate, artifact, backend,
//! model, and lineage identities stay outside the compiled model messages.

use crate::repository_candidate_resolver::VerifiedRepositoryReviewSubjectV1;
use birdcode_prompting::{
    CompiledPrompt, PromptError, PromptInvocation, RepositoryReviewArtifactInputV1,
    RepositoryReviewCandidateArtifactsInputV1, RepositoryReviewEvidenceHandleV1,
    RepositoryReviewInputV1, RepositoryReviewPathComponentV1, RepositoryReviewPathV1,
    RepositoryReviewPolicyV1, RepositoryReviewPolicyViolationV1,
    RepositoryReviewProducerClaimInputV1, RepositoryReviewRequirementInputV1,
    RepositoryReviewRequirementKindV1, RepositoryReviewRequirementRefV1, RepositoryReviewScopeV1,
    RepositoryReviewSourceInputV1, builtin_registry, derive_repository_review_policy_v1,
    repository_review_invocation_v1, repository_review_requirement_sha256, repository_reviewer_key,
};
use birdcode_protocol::ChildHandoffDocument;
use std::fmt;

pub(crate) const REPOSITORY_REVIEW_OUTPUT_SCHEMA_NAME_V1: &str = "repository_semantic_reviewer_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedRepositoryReviewPromptV1 {
    pub input: RepositoryReviewInputV1,
    pub policy: RepositoryReviewPolicyV1,
    pub invocation: PromptInvocation,
    pub compiled: CompiledPrompt,
}

#[derive(Debug)]
pub(crate) enum RepositoryReviewPromptBuildErrorV1 {
    RequirementsOutsideV1Bounds,
    ArtifactNotUtf8 {
        handle: RepositoryReviewEvidenceHandleV1,
    },
    ProducerClaimInvalid,
    Policy(Vec<RepositoryReviewPolicyViolationV1>),
    Prompt(PromptError),
}

impl fmt::Display for RepositoryReviewPromptBuildErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequirementsOutsideV1Bounds => {
                formatter.write_str("review requirements exceed the exact v1 prompt bounds")
            }
            Self::ArtifactNotUtf8 { handle } => {
                write!(formatter, "review artifact {handle:?} is not exact UTF-8")
            }
            Self::ProducerClaimInvalid => {
                formatter.write_str("producer handoff could not be projected safely")
            }
            Self::Policy(violations) => {
                write!(formatter, "review policy is invalid: {violations:?}")
            }
            Self::Prompt(error) => write!(formatter, "review prompt is invalid: {error}"),
        }
    }
}

impl std::error::Error for RepositoryReviewPromptBuildErrorV1 {}

/// Builds the exact model-visible package for one verified candidate.
///
/// The returned compiled prompt is runtime-identity-blinded. This is not a
/// claim that source style or natural-language content cannot contain indirect
/// attribution clues.
pub(crate) fn prepare_repository_review_prompt_v1(
    subject: &VerifiedRepositoryReviewSubjectV1,
    blind_subject_id: String,
) -> Result<PreparedRepositoryReviewPromptV1, RepositoryReviewPromptBuildErrorV1> {
    let target = subject.target_work_order();
    if target.acceptance_criteria.len().saturating_add(1)
        > birdcode_prompting::REPOSITORY_REVIEW_MAX_REQUIREMENTS_V1
    {
        return Err(RepositoryReviewPromptBuildErrorV1::RequirementsOutsideV1Bounds);
    }
    let mut requirements = Vec::with_capacity(target.acceptance_criteria.len().saturating_add(1));
    requirements.push(requirement(
        "objective".to_owned(),
        RepositoryReviewRequirementKindV1::Objective,
        target.objective.clone(),
    ));
    requirements.extend(
        target
            .acceptance_criteria
            .iter()
            .enumerate()
            .map(|(index, criterion)| {
                requirement(
                    format!("criterion-{ordinal:03}", ordinal = index.saturating_add(1)),
                    RepositoryReviewRequirementKindV1::AcceptanceCriterion,
                    criterion.clone(),
                )
            }),
    );

    let candidate = subject.candidate();
    let artifacts = [
        (
            RepositoryReviewEvidenceHandleV1::Preimage,
            &candidate.bundle.preimage_artifact.bytes,
        ),
        (
            RepositoryReviewEvidenceHandleV1::Postimage,
            &candidate.bundle.postimage_artifact.bytes,
        ),
        (
            RepositoryReviewEvidenceHandleV1::Diff,
            &candidate.bundle.diff_artifact.bytes,
        ),
    ]
    .into_iter()
    .map(|(handle, bytes)| {
        std::str::from_utf8(bytes)
            .map(|content| RepositoryReviewArtifactInputV1 {
                handle,
                content_utf8: content.to_owned(),
                complete: true,
            })
            .map_err(|_| RepositoryReviewPromptBuildErrorV1::ArtifactNotUtf8 { handle })
    })
    .collect::<Result<Vec<_>, _>>()?;

    let handoff = serde_json::from_slice::<ChildHandoffDocument>(
        &candidate.bundle.producer_handoff_artifact.bytes,
    )
    .map_err(|_| RepositoryReviewPromptBuildErrorV1::ProducerClaimInvalid)?;
    let producer_claim = RepositoryReviewProducerClaimInputV1 {
        summary: handoff.content.summary,
        findings: handoff
            .content
            .findings
            .into_iter()
            .map(|finding| finding.statement)
            .collect(),
        unknowns: handoff
            .content
            .unknowns
            .into_iter()
            .map(|unknown| unknown.question)
            .collect(),
        recommended_followups: handoff
            .content
            .recommended_followups
            .into_iter()
            .map(|followup| followup.text)
            .collect(),
    };
    let path = RepositoryReviewPathV1 {
        components: candidate
            .bundle
            .manifest
            .body
            .change
            .path
            .unix_components()
            .iter()
            .map(|component| match std::str::from_utf8(component) {
                Ok(value) => RepositoryReviewPathComponentV1::Utf8 {
                    value: value.to_owned(),
                },
                Err(_) => RepositoryReviewPathComponentV1::UnixBytes {
                    value: component.clone(),
                },
            })
            .collect(),
    };
    let input = RepositoryReviewInputV1 {
        source: RepositoryReviewSourceInputV1 {
            blind_subject_id,
            scope: RepositoryReviewScopeV1::ExactUtf8ReplaceArtifactReview,
            identity_blinding: "runtime_identity_blinded".to_owned(),
        },
        requirements,
        candidate_artifacts: RepositoryReviewCandidateArtifactsInputV1 { path, artifacts },
        producer_claim,
    };
    let policy = derive_repository_review_policy_v1(&input)
        .map_err(RepositoryReviewPromptBuildErrorV1::Policy)?;
    let invocation = repository_review_invocation_v1(&input, &policy)
        .map_err(RepositoryReviewPromptBuildErrorV1::Policy)?;
    let compiled = builtin_registry()
        .map_err(RepositoryReviewPromptBuildErrorV1::Prompt)?
        .compile(&repository_reviewer_key(), &invocation)
        .map_err(RepositoryReviewPromptBuildErrorV1::Prompt)?;
    Ok(PreparedRepositoryReviewPromptV1 {
        input,
        policy,
        invocation,
        compiled,
    })
}

fn requirement(
    requirement_id: String,
    kind: RepositoryReviewRequirementKindV1,
    text: String,
) -> RepositoryReviewRequirementInputV1 {
    RepositoryReviewRequirementInputV1 {
        requirement: RepositoryReviewRequirementRefV1 {
            requirement_id,
            requirement_sha256: repository_review_requirement_sha256(&text),
        },
        kind,
        text,
    }
}
