use crate::{
    ArtifactId, ArtifactKind, AttemptId, CandidateId, CheckEvidence, CheckId, CheckKind,
    CheckOutcome, EvaluationCaseId, ExecutionPhase, ExecutionPlatformKind, ExitRequirement,
    PhaseOutcome, PhaseRequirement, ProcessExit, SealedRunProvenance, Sha256Digest, TargetId,
    TargetKind, ValidationReport,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

/// Failure to import an attribution-free blind identifier.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{field} must be a non-nil UUID v4; received UUID v{actual}")]
pub struct BlindIdError {
    field: &'static str,
    actual: usize,
}

macro_rules! blind_v4_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Imports a random UUID v4 identity.
            ///
            /// # Errors
            ///
            /// Rejects nil and timestamp-bearing UUID versions.
            pub fn try_from_uuid(value: Uuid) -> Result<Self, BlindIdError> {
                let actual = value.get_version_num();
                if value.is_nil() || actual != 4 {
                    return Err(BlindIdError {
                        field: $field,
                        actual,
                    });
                }
                Ok(Self(value))
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

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::try_from_uuid(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

blind_v4_id!(BlindAttemptId, "blind_attempt_id");
blind_v4_id!(BlindArtifactHandle, "blind_artifact_handle");
blind_v4_id!(BlindCandidateId, "blind_candidate_id");
blind_v4_id!(BlindCheckId, "blind_check_id");
blind_v4_id!(BlindRunId, "blind_run_id");

/// Normalized attempt outcome without command, environment, actor, or model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindAttemptOutcome {
    pub attempt_id: BlindAttemptId,
    pub parent_attempt_id: Option<BlindAttemptId>,
    pub phase: ExecutionPhase,
    pub outcome: PhaseOutcome,
    pub process_exit: Option<BlindProcessExit>,
}

/// Provider-neutral process result; launch failure codes stay in local provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum BlindProcessExit {
    Exited { code: i32 },
    Signaled { signal: i32 },
    TimedOut,
    Cancelled,
    LaunchFailed,
}

impl From<&ProcessExit> for BlindProcessExit {
    fn from(value: &ProcessExit) -> Self {
        match value {
            ProcessExit::Exited { code } => Self::Exited { code: *code },
            ProcessExit::Signaled { signal } => Self::Signaled { signal: *signal },
            ProcessExit::TimedOut => Self::TimedOut,
            ProcessExit::Cancelled => Self::Cancelled,
            ProcessExit::LaunchFailed { .. } => Self::LaunchFailed,
        }
    }
}

/// Minimal typed evidence descriptor without source fingerprints or storage metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindArtifact {
    pub handle: BlindArtifactHandle,
    pub attempt_id: BlindAttemptId,
    pub kind: ArtifactKind,
    pub truncated: bool,
}

/// Check evidence rewritten to attribution-free handles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum BlindCheckEvidence {
    Artifact { handle: BlindArtifactHandle },
    AttemptExit { attempt_id: BlindAttemptId },
}

/// Normalized check retained for result-based judging.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindCheck {
    pub check_id: BlindCheckId,
    pub attempt_id: BlindAttemptId,
    pub kind: CheckKind,
    pub outcome: CheckOutcome,
    pub evidence: Vec<BlindCheckEvidence>,
}

/// Acceptance policy rewritten to blind check identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindValidationPolicy {
    pub validation_plan_sha256: Sha256Digest,
    pub validation_policy_sha256: Sha256Digest,
    pub phase_requirements: BTreeMap<ExecutionPhase, PhaseRequirement>,
    pub check_requirements: Vec<BlindCheckRequirement>,
    pub minimum_primary_passes: u32,
}

/// Typed evidence rule rewritten to a blind check identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindCheckRequirement {
    pub check_id: BlindCheckId,
    pub expected_kind: CheckKind,
    pub allowed_artifact_kinds: BTreeSet<ArtifactKind>,
    pub allow_truncated_artifacts: bool,
    pub attempt_exit: ExitRequirement,
    pub minimum_evidence_items: u32,
}

/// Only this value is intended to cross the blind evaluator boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindEvaluationInput {
    pub schema_version: u32,
    pub run_id: BlindRunId,
    pub candidate_id: BlindCandidateId,
    pub evaluation_case_id: EvaluationCaseId,
    pub target_kind: TargetKind,
    pub platform_kind: ExecutionPlatformKind,
    pub policy: BlindValidationPolicy,
    pub attempts: Vec<BlindAttemptOutcome>,
    pub artifacts: Vec<BlindArtifact>,
    pub checks: Vec<BlindCheck>,
}

/// Mapping for one original attempt. Never send this to an evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindIdMapping {
    pub source_attempt_id: AttemptId,
    pub blind_attempt_id: BlindAttemptId,
    pub source_elapsed_ms: u64,
}

/// Mapping from the producer identity to its random evaluator-local identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindCandidateMapping {
    pub source_candidate_id: CandidateId,
    pub blind_candidate_id: BlindCandidateId,
}

/// Local-only binding from a random evaluator run to the sealed controller run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindRunMapping {
    pub source_sealed_run_sha256: Sha256Digest,
    pub blind_run_id: BlindRunId,
}

/// Mapping for one stored artifact. Never send this to an evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindArtifactMapping {
    pub source_artifact_id: ArtifactId,
    pub blind_handle: BlindArtifactHandle,
    pub source_sha256: Sha256Digest,
    pub source_retained_bytes: u64,
    pub source_observed_bytes: Option<u64>,
    pub source_truncated: bool,
    pub source_media_type: String,
    pub source_storage_ref: TargetId,
}

/// Mapping for one check. Never send this to an evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindCheckMapping {
    pub source_check_id: CheckId,
    pub blind_check_id: BlindCheckId,
}

/// Sensitive local disclosure retained separately from evaluator input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindDisclosure {
    pub run: BlindRunMapping,
    pub candidate: BlindCandidateMapping,
    pub attempts: Vec<BlindIdMapping>,
    pub artifacts: Vec<BlindArtifactMapping>,
    pub checks: Vec<BlindCheckMapping>,
}

/// Paired evaluator input and local-only disclosure map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindEvaluationPackage {
    pub input: BlindEvaluationInput,
    /// Digest of the exact serialized evaluator input; verdicts reference this.
    pub input_sha256: Sha256Digest,
    pub disclosure: BlindDisclosure,
}

/// Structurally invalid provenance cannot cross the evaluator boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BlindBuildError {
    #[error("validated provenance could not be projected without an invariant violation")]
    ProjectionInvariant { report: ValidationReport },
    #[error("blind evaluator input could not be serialized for its commitment")]
    InputSerialization { report: ValidationReport },
}

impl BlindBuildError {
    #[must_use]
    pub const fn report(&self) -> &ValidationReport {
        match self {
            Self::ProjectionInvariant { report } | Self::InputSerialization { report } => report,
        }
    }
}

impl SealedRunProvenance {
    /// Creates provider-blind normalized evidence from an immutable sealed run.
    ///
    /// Candidate failures and partial results remain evaluable. The seal has
    /// already consumed the append surface and bound the exact policy, report,
    /// terminal chain hash, and immutable run context.
    ///
    /// # Errors
    ///
    /// Returns a projection or serialization error if the already-validated
    /// sealed snapshot cannot be represented without violating an invariant.
    #[allow(clippy::too_many_lines)]
    pub fn build_blind_evaluation_package(
        &self,
    ) -> Result<BlindEvaluationPackage, BlindBuildError> {
        let provenance = self.provenance();
        let policy = self.policy();
        let report = self.report().clone();
        let projection_error = || BlindBuildError::ProjectionInvariant {
            report: report.clone(),
        };

        let blind_candidate_id = BlindCandidateId::new();
        let blind_run_id = BlindRunId::new();
        let mut attempt_map = BTreeMap::new();
        let mut artifact_map = BTreeMap::new();
        let mut check_map = BTreeMap::new();
        for record in provenance.records() {
            match &record.event {
                crate::ProvenanceEvent::AttemptStarted { attempt_id, .. } => {
                    attempt_map
                        .entry(*attempt_id)
                        .or_insert_with(BlindAttemptId::new);
                }
                crate::ProvenanceEvent::ArtifactRecorded { artifact } => {
                    artifact_map
                        .entry(artifact.artifact_id)
                        .or_insert_with(BlindArtifactHandle::new);
                }
                crate::ProvenanceEvent::CheckRecorded { check } => {
                    check_map
                        .entry(check.check_id)
                        .or_insert_with(BlindCheckId::new);
                }
                crate::ProvenanceEvent::AttemptFinished { .. } => {}
            }
        }
        for check_id in policy.check_requirements().keys() {
            check_map.entry(*check_id).or_insert_with(BlindCheckId::new);
        }

        let mut starts = BTreeMap::new();
        let mut elapsed_by_attempt = BTreeMap::new();
        let mut attempts = Vec::new();
        let mut artifacts = Vec::new();
        let mut checks = Vec::new();
        for record in provenance.records() {
            match &record.event {
                crate::ProvenanceEvent::AttemptStarted {
                    attempt_id,
                    parent_attempt_id,
                    phase,
                    ..
                } => {
                    starts.insert(*attempt_id, (*parent_attempt_id, *phase));
                }
                crate::ProvenanceEvent::AttemptFinished {
                    attempt_id,
                    outcome,
                    process_exit,
                    elapsed_ms,
                    ..
                } => {
                    let (parent_attempt_id, phase) = starts
                        .get(attempt_id)
                        .copied()
                        .ok_or_else(&projection_error)?;
                    let blind_attempt_id = attempt_map
                        .get(attempt_id)
                        .copied()
                        .ok_or_else(&projection_error)?;
                    let blind_parent_attempt_id = match parent_attempt_id {
                        Some(parent) => Some(
                            attempt_map
                                .get(&parent)
                                .copied()
                                .ok_or_else(&projection_error)?,
                        ),
                        None => None,
                    };
                    attempts.push(BlindAttemptOutcome {
                        attempt_id: blind_attempt_id,
                        parent_attempt_id: blind_parent_attempt_id,
                        phase,
                        outcome: *outcome,
                        process_exit: process_exit.as_ref().map(BlindProcessExit::from),
                    });
                    elapsed_by_attempt.insert(*attempt_id, *elapsed_ms);
                }
                crate::ProvenanceEvent::ArtifactRecorded { artifact } => {
                    artifacts.push(BlindArtifact {
                        handle: artifact_map
                            .get(&artifact.artifact_id)
                            .copied()
                            .ok_or_else(&projection_error)?,
                        attempt_id: attempt_map
                            .get(&artifact.attempt_id)
                            .copied()
                            .ok_or_else(&projection_error)?,
                        kind: artifact.kind,
                        truncated: artifact.truncated,
                    });
                }
                crate::ProvenanceEvent::CheckRecorded { check } => {
                    let evidence = check
                        .evidence
                        .iter()
                        .map(|evidence| -> Result<BlindCheckEvidence, BlindBuildError> {
                            Ok(match evidence {
                                CheckEvidence::Artifact { artifact_id } => {
                                    BlindCheckEvidence::Artifact {
                                        handle: artifact_map
                                            .get(artifact_id)
                                            .copied()
                                            .ok_or_else(&projection_error)?,
                                    }
                                }
                                CheckEvidence::AttemptExit { attempt_id } => {
                                    BlindCheckEvidence::AttemptExit {
                                        attempt_id: attempt_map
                                            .get(attempt_id)
                                            .copied()
                                            .ok_or_else(&projection_error)?,
                                    }
                                }
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    checks.push(BlindCheck {
                        check_id: check_map
                            .get(&check.check_id)
                            .copied()
                            .ok_or_else(&projection_error)?,
                        attempt_id: attempt_map
                            .get(&check.attempt_id)
                            .copied()
                            .ok_or_else(&projection_error)?,
                        kind: check.kind,
                        outcome: check.outcome,
                        evidence,
                    });
                }
            }
        }

        let mut artifact_disclosures = Vec::new();
        for record in provenance.records() {
            if let crate::ProvenanceEvent::ArtifactRecorded { artifact } = &record.event {
                artifact_disclosures.push(BlindArtifactMapping {
                    source_artifact_id: artifact.artifact_id,
                    blind_handle: artifact_map
                        .get(&artifact.artifact_id)
                        .copied()
                        .ok_or_else(&projection_error)?,
                    source_sha256: artifact.sha256,
                    source_retained_bytes: artifact.retained_bytes,
                    source_observed_bytes: artifact.observed_bytes,
                    source_truncated: artifact.truncated,
                    source_media_type: artifact.media_type.clone(),
                    source_storage_ref: artifact.storage_ref.clone(),
                });
            }
        }
        let disclosure = BlindDisclosure {
            run: BlindRunMapping {
                source_sealed_run_sha256: self.sealed_run_sha256(),
                blind_run_id,
            },
            candidate: BlindCandidateMapping {
                source_candidate_id: provenance.candidate_id(),
                blind_candidate_id,
            },
            attempts: attempt_map
                .iter()
                .map(|(source_attempt_id, blind_attempt_id)| {
                    Ok(BlindIdMapping {
                        source_attempt_id: *source_attempt_id,
                        blind_attempt_id: *blind_attempt_id,
                        source_elapsed_ms: elapsed_by_attempt
                            .get(source_attempt_id)
                            .copied()
                            .ok_or_else(&projection_error)?,
                    })
                })
                .collect::<Result<Vec<_>, BlindBuildError>>()?,
            artifacts: artifact_disclosures,
            checks: check_map
                .iter()
                .map(|(source_check_id, blind_check_id)| BlindCheckMapping {
                    source_check_id: *source_check_id,
                    blind_check_id: *blind_check_id,
                })
                .collect(),
        };
        let policy = BlindValidationPolicy {
            validation_plan_sha256: policy.validation_plan_sha256(),
            validation_policy_sha256: policy.policy_sha256(),
            phase_requirements: policy.phase_requirements().clone(),
            check_requirements: policy
                .check_requirements()
                .iter()
                .map(|(check_id, requirement)| {
                    Ok(BlindCheckRequirement {
                        check_id: check_map
                            .get(check_id)
                            .copied()
                            .ok_or_else(&projection_error)?,
                        expected_kind: requirement.expected_kind,
                        allowed_artifact_kinds: requirement.allowed_artifact_kinds.clone(),
                        allow_truncated_artifacts: requirement.allow_truncated_artifacts,
                        attempt_exit: requirement.attempt_exit.clone(),
                        minimum_evidence_items: requirement.minimum_evidence_items,
                    })
                })
                .collect::<Result<Vec<_>, BlindBuildError>>()?,
            minimum_primary_passes: policy.minimum_primary_passes(),
        };
        let input = BlindEvaluationInput {
            schema_version: 1,
            run_id: blind_run_id,
            candidate_id: blind_candidate_id,
            evaluation_case_id: provenance.evaluation_case_id(),
            target_kind: provenance.target().kind().map_err(|_| projection_error())?,
            platform_kind: provenance.target().platform().kind(),
            policy,
            attempts,
            artifacts,
            checks,
        };
        let input_sha256 = serde_json::to_vec(&input)
            .map(|bytes| Sha256Digest::of_bytes(&bytes))
            .map_err(|_| BlindBuildError::InputSerialization {
                report: report.clone(),
            })?;
        Ok(BlindEvaluationPackage {
            input,
            input_sha256,
            disclosure,
        })
    }
}
