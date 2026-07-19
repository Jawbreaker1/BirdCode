use crate::{
    AdapterDeclaration, AgentIdentity, ArtifactId, ArtifactRecord, CandidateId, CommandSpec,
    EnvironmentSnapshot, EvaluationCaseId, ExecutionBounds, ExecutionTarget, ProcessExit,
    Sha256Digest, ValidationCheck, ValidationPolicy, ValidationReport,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

/// Current append-only provenance wire schema.
pub const PROVENANCE_SCHEMA_VERSION: u32 = 1;

/// Failure to import a UUID where time-ordered UUID v7 is mandatory.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{field} must be a non-nil UUID v7; received UUID v{actual}")]
pub struct ProvenanceIdError {
    field: &'static str,
    actual: usize,
}

macro_rules! uuid_v7_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a globally unique, time-ordered UUID v7 identity.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Imports a durable identity while preserving the UUID v7 invariant.
            ///
            /// # Errors
            ///
            /// Rejects nil and every UUID version other than v7.
            pub fn try_from_uuid(value: Uuid) -> Result<Self, ProvenanceIdError> {
                let actual = value.get_version_num();
                if value.is_nil() || actual != 7 {
                    return Err(ProvenanceIdError {
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_v7_id!(RunId, "run_id");
uuid_v7_id!(AttemptId, "attempt_id");

/// Canonical application-delivery lifecycle phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Prepare,
    Build,
    Install,
    Launch,
    Readiness,
    Exercise,
    InspectState,
    Collect,
    Validate,
    Terminate,
    Cleanup,
    Package,
}

/// Normative phase order for every completed validation run.
pub const EXECUTION_PHASES: [ExecutionPhase; 12] = [
    ExecutionPhase::Prepare,
    ExecutionPhase::Build,
    ExecutionPhase::Install,
    ExecutionPhase::Launch,
    ExecutionPhase::Readiness,
    ExecutionPhase::Exercise,
    ExecutionPhase::InspectState,
    ExecutionPhase::Collect,
    ExecutionPhase::Validate,
    ExecutionPhase::Terminate,
    ExecutionPhase::Cleanup,
    ExecutionPhase::Package,
];

impl ExecutionPhase {
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::Prepare => 0,
            Self::Build => 1,
            Self::Install => 2,
            Self::Launch => 3,
            Self::Readiness => 4,
            Self::Exercise => 5,
            Self::InspectState => 6,
            Self::Collect => 7,
            Self::Validate => 8,
            Self::Terminate => 9,
            Self::Cleanup => 10,
            Self::Package => 11,
        }
    }
}

/// Normalized attempt outcome, distinct from checks and the final run verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOutcome {
    Succeeded,
    CandidateFailure,
    InfrastructureError,
    TimedOut,
    Cancelled,
    PolicyDenied,
    NotApplicable,
}

/// Immutable digests/configuration required to reproduce and compare one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunContextManifest {
    pub source_workspace_snapshot_sha256: Sha256Digest,
    pub task_fixture_sha256: Sha256Digest,
    pub validation_plan_sha256: Sha256Digest,
    pub validation_policy_sha256: Sha256Digest,
    pub harness_configuration_sha256: Sha256Digest,
    pub adapter: AdapterDeclaration,
    pub permission_policy_sha256: Sha256Digest,
    pub network_policy_sha256: Sha256Digest,
}

/// Immutable event content appended to a run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum ProvenanceEvent {
    AttemptStarted {
        attempt_id: AttemptId,
        parent_attempt_id: Option<AttemptId>,
        phase: ExecutionPhase,
        actor: AgentIdentity,
        timeout_ms: u64,
        command: Option<CommandSpec>,
    },
    AttemptFinished {
        attempt_id: AttemptId,
        outcome: PhaseOutcome,
        process_exit: Option<ProcessExit>,
        elapsed_ms: u64,
        stdout_artifact_id: Option<ArtifactId>,
        stderr_artifact_id: Option<ArtifactId>,
    },
    ArtifactRecorded {
        artifact: ArtifactRecord,
    },
    CheckRecorded {
        check: ValidationCheck,
    },
}

impl ProvenanceEvent {
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        match self {
            Self::AttemptStarted { attempt_id, .. } | Self::AttemptFinished { attempt_id, .. } => {
                *attempt_id
            }
            Self::ArtifactRecorded { artifact } => artifact.attempt_id,
            Self::CheckRecorded { check } => check.attempt_id,
        }
    }
}

/// One sequenced append-only provenance entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub previous_record_sha256: Option<Sha256Digest>,
    pub record_sha256: Sha256Digest,
    pub event: ProvenanceEvent,
}

/// In-memory append failure. Persistence is an integration responsibility.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AppendError {
    #[error("provenance sequence overflow")]
    SequenceOverflow,
    #[error("existing provenance log failed append-prefix integrity validation")]
    InvalidExistingLog,
    #[error("new provenance event would violate append-prefix integrity")]
    InvalidNewRecord,
    #[error("provenance record could not be serialized for hashing")]
    RecordSerialization,
    #[error("provenance run context could not be serialized for hashing")]
    ContextSerialization,
}

/// Failure to freeze a complete run into an immutable review snapshot.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SealError {
    #[error("provenance is structurally incomplete or invalid and cannot be sealed")]
    InvalidProvenance { report: ValidationReport },
    #[error("a complete run has no terminal provenance record")]
    MissingTerminalRecord { report: ValidationReport },
    #[error("the validation report could not be serialized for sealing")]
    ReportSerialization,
    #[error("the seal commitment could not be serialized")]
    SealSerialization,
}

impl SealError {
    #[must_use]
    pub const fn report(&self) -> Option<&ValidationReport> {
        match self {
            Self::InvalidProvenance { report } | Self::MissingTerminalRecord { report } => {
                Some(report)
            }
            Self::ReportSerialization | Self::SealSerialization => None,
        }
    }
}

/// Serializable run provenance with no mutation API other than append.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunProvenance {
    schema_version: u32,
    run_id: RunId,
    candidate_id: CandidateId,
    evaluation_case_id: EvaluationCaseId,
    target: ExecutionTarget,
    bounds: ExecutionBounds,
    environment: EnvironmentSnapshot,
    manifest: RunContextManifest,
    run_context_sha256: Sha256Digest,
    records: Vec<ProvenanceRecord>,
}

impl RunProvenance {
    /// Creates a new append-only provenance log.
    ///
    /// # Errors
    ///
    /// Returns a context serialization error if its immutable header cannot be
    /// encoded for the run-context commitment.
    pub fn new(
        candidate_id: CandidateId,
        evaluation_case_id: EvaluationCaseId,
        target: ExecutionTarget,
        bounds: ExecutionBounds,
        environment: EnvironmentSnapshot,
        manifest: RunContextManifest,
    ) -> Result<Self, AppendError> {
        Self::with_run_id(
            RunId::new(),
            candidate_id,
            evaluation_case_id,
            target,
            bounds,
            environment,
            manifest,
        )
    }

    /// Recreates a log with an existing validated run identity.
    ///
    /// # Errors
    ///
    /// Returns a context serialization error if its immutable header cannot be
    /// encoded for the run-context commitment.
    pub fn with_run_id(
        run_id: RunId,
        candidate_id: CandidateId,
        evaluation_case_id: EvaluationCaseId,
        target: ExecutionTarget,
        bounds: ExecutionBounds,
        environment: EnvironmentSnapshot,
        manifest: RunContextManifest,
    ) -> Result<Self, AppendError> {
        let run_context_sha256 = compute_run_context_hash(
            PROVENANCE_SCHEMA_VERSION,
            run_id,
            candidate_id,
            evaluation_case_id,
            &target,
            &bounds,
            &environment,
            &manifest,
        )?;
        Ok(Self {
            schema_version: PROVENANCE_SCHEMA_VERSION,
            run_id,
            candidate_id,
            evaluation_case_id,
            target,
            bounds,
            environment,
            manifest,
            run_context_sha256,
            records: Vec::new(),
        })
    }

    /// Appends a record with the next contiguous sequence number.
    ///
    /// This operation does not claim durability. Integrations must atomically
    /// retain the resulting record before allowing execution to continue.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError::SequenceOverflow`] at `u64::MAX`.
    pub fn append(
        &mut self,
        observed_at_unix_ms: u64,
        event: ProvenanceEvent,
    ) -> Result<&ProvenanceRecord, AppendError> {
        if !is_appendable_prefix(self) {
            return Err(AppendError::InvalidExistingLog);
        }
        let sequence = self
            .records
            .last()
            .map_or(Some(1), |record| record.sequence.checked_add(1))
            .ok_or(AppendError::SequenceOverflow)?;
        let previous_record_sha256 = self.records.last().map(|record| record.record_sha256);
        let record_sha256 = compute_record_hash(
            self.schema_version,
            self.run_id,
            self.run_context_sha256,
            sequence,
            observed_at_unix_ms,
            previous_record_sha256,
            &event,
        )?;
        self.records.push(ProvenanceRecord {
            sequence,
            observed_at_unix_ms,
            previous_record_sha256,
            record_sha256,
            event,
        });
        if !is_appendable_prefix(self) {
            let _ = self.records.pop();
            return Err(AppendError::InvalidNewRecord);
        }
        self.records.last().ok_or(AppendError::InvalidNewRecord)
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    #[must_use]
    pub const fn evaluation_case_id(&self) -> EvaluationCaseId {
        self.evaluation_case_id
    }

    #[must_use]
    pub const fn target(&self) -> &ExecutionTarget {
        &self.target
    }

    #[must_use]
    pub const fn bounds(&self) -> &ExecutionBounds {
        &self.bounds
    }

    #[must_use]
    pub const fn environment(&self) -> &EnvironmentSnapshot {
        &self.environment
    }

    #[must_use]
    pub const fn manifest(&self) -> &RunContextManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn run_context_sha256(&self) -> Sha256Digest {
        self.run_context_sha256
    }

    #[must_use]
    pub fn records(&self) -> &[ProvenanceRecord] {
        &self.records
    }

    /// Consumes the mutable append surface and freezes a structurally complete run.
    ///
    /// Policy failures and candidate failures may be sealed for blind outcome
    /// review. Structural corruption, unfinished attempts, or missing canonical
    /// phase terminals may not.
    ///
    /// # Errors
    ///
    /// Returns a typed error when validation is structurally unsafe, the run is
    /// incomplete, or commitment material cannot be serialized.
    pub fn seal(self, policy: ValidationPolicy) -> Result<SealedRunProvenance, SealError> {
        let report = self.validate(&policy);
        if report.has_structural_violations() {
            return Err(SealError::InvalidProvenance { report });
        }
        let Some(terminal_record) = self.records.last() else {
            return Err(SealError::MissingTerminalRecord { report });
        };
        let report_sha256 = serde_json::to_vec(&report)
            .map(|bytes| Sha256Digest::of_bytes(&bytes))
            .map_err(|_| SealError::ReportSerialization)?;
        let terminal_sequence = terminal_record.sequence;
        let terminal_record_sha256 = terminal_record.record_sha256;
        let validation_plan_sha256 = policy.validation_plan_sha256();
        let validation_policy_sha256 = policy.policy_sha256();
        let sealed_run_sha256 = compute_seal_hash(&SealHashMaterial {
            schema_version: self.schema_version,
            run_id: self.run_id,
            run_context_sha256: self.run_context_sha256,
            terminal_sequence,
            terminal_record_sha256,
            validation_plan_sha256,
            validation_policy_sha256,
            report_sha256,
        })?;
        Ok(SealedRunProvenance {
            provenance: self,
            policy,
            report,
            terminal_sequence,
            terminal_record_sha256,
            report_sha256,
            sealed_run_sha256,
        })
    }
}

/// Immutable, policy-bound snapshot used as the only blind-review source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedRunProvenance {
    provenance: RunProvenance,
    policy: ValidationPolicy,
    report: ValidationReport,
    terminal_sequence: u64,
    terminal_record_sha256: Sha256Digest,
    report_sha256: Sha256Digest,
    sealed_run_sha256: Sha256Digest,
}

impl SealedRunProvenance {
    #[must_use]
    pub const fn provenance(&self) -> &RunProvenance {
        &self.provenance
    }

    #[must_use]
    pub const fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn report(&self) -> &ValidationReport {
        &self.report
    }

    #[must_use]
    pub const fn terminal_sequence(&self) -> u64 {
        self.terminal_sequence
    }

    #[must_use]
    pub const fn terminal_record_sha256(&self) -> Sha256Digest {
        self.terminal_record_sha256
    }

    #[must_use]
    pub const fn report_sha256(&self) -> Sha256Digest {
        self.report_sha256
    }

    #[must_use]
    pub const fn sealed_run_sha256(&self) -> Sha256Digest {
        self.sealed_run_sha256
    }
}

#[derive(Serialize)]
struct SealHashMaterial {
    schema_version: u32,
    run_id: RunId,
    run_context_sha256: Sha256Digest,
    terminal_sequence: u64,
    terminal_record_sha256: Sha256Digest,
    validation_plan_sha256: Sha256Digest,
    validation_policy_sha256: Sha256Digest,
    report_sha256: Sha256Digest,
}

fn compute_seal_hash(material: &SealHashMaterial) -> Result<Sha256Digest, SealError> {
    serde_json::to_vec(material)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| SealError::SealSerialization)
}

#[derive(Serialize)]
struct RecordHashMaterial<'a> {
    schema_version: u32,
    run_id: RunId,
    run_context_sha256: Sha256Digest,
    sequence: u64,
    observed_at_unix_ms: u64,
    previous_record_sha256: Option<Sha256Digest>,
    event: &'a ProvenanceEvent,
}

pub(crate) fn compute_record_hash(
    schema_version: u32,
    run_id: RunId,
    run_context_sha256: Sha256Digest,
    sequence: u64,
    observed_at_unix_ms: u64,
    previous_record_sha256: Option<Sha256Digest>,
    event: &ProvenanceEvent,
) -> Result<Sha256Digest, AppendError> {
    let material = RecordHashMaterial {
        schema_version,
        run_id,
        run_context_sha256,
        sequence,
        observed_at_unix_ms,
        previous_record_sha256,
        event,
    };
    serde_json::to_vec(&material)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| AppendError::RecordSerialization)
}

#[derive(Serialize)]
struct RunContextHashMaterial<'a> {
    schema_version: u32,
    run_id: RunId,
    candidate_id: CandidateId,
    evaluation_case_id: EvaluationCaseId,
    target: &'a ExecutionTarget,
    bounds: &'a ExecutionBounds,
    environment: &'a EnvironmentSnapshot,
    manifest: &'a RunContextManifest,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_run_context_hash(
    schema_version: u32,
    run_id: RunId,
    candidate_id: CandidateId,
    evaluation_case_id: EvaluationCaseId,
    target: &ExecutionTarget,
    bounds: &ExecutionBounds,
    environment: &EnvironmentSnapshot,
    manifest: &RunContextManifest,
) -> Result<Sha256Digest, AppendError> {
    let material = RunContextHashMaterial {
        schema_version,
        run_id,
        candidate_id,
        evaluation_case_id,
        target,
        bounds,
        environment,
        manifest,
    };
    serde_json::to_vec(&material)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| AppendError::ContextSerialization)
}

#[allow(clippy::too_many_lines)]
fn is_appendable_prefix(provenance: &RunProvenance) -> bool {
    if provenance.schema_version != PROVENANCE_SCHEMA_VERSION
        || provenance.target.kind().is_err()
        || provenance.target.required_adapter().ok()
            != Some(provenance.manifest.adapter.requirement)
        || compute_run_context_hash(
            provenance.schema_version,
            provenance.run_id,
            provenance.candidate_id,
            provenance.evaluation_case_id,
            &provenance.target,
            &provenance.bounds,
            &provenance.environment,
            &provenance.manifest,
        )
        .ok()
            != Some(provenance.run_context_sha256)
    {
        return false;
    }
    if !crate::validation::append_prefix_resources_are_valid(provenance) {
        return false;
    }
    let mut expected_sequence = 1_u64;
    let mut previous_hash = None;
    let mut previous_timestamp = None;
    let mut started = std::collections::BTreeSet::new();
    let mut finished = std::collections::BTreeSet::new();
    let mut artifacts = std::collections::BTreeMap::new();
    let mut checks = std::collections::BTreeSet::new();
    let mut attempt_phases = std::collections::BTreeMap::new();
    let mut unfinished_by_phase = std::collections::BTreeMap::<ExecutionPhase, u32>::new();
    let mut last_started_phase: Option<ExecutionPhase> = None;
    for record in &provenance.records {
        if record.sequence != expected_sequence
            || previous_timestamp.is_some_and(|timestamp| record.observed_at_unix_ms < timestamp)
            || record.previous_record_sha256 != previous_hash
            || compute_record_hash(
                provenance.schema_version,
                provenance.run_id,
                provenance.run_context_sha256,
                record.sequence,
                record.observed_at_unix_ms,
                record.previous_record_sha256,
                &record.event,
            )
            .ok()
                != Some(record.record_sha256)
        {
            return false;
        }
        expected_sequence = match record.sequence.checked_add(1) {
            Some(value) => value,
            None => return false,
        };
        previous_hash = Some(record.record_sha256);
        previous_timestamp = Some(record.observed_at_unix_ms);
        match &record.event {
            ProvenanceEvent::AttemptStarted {
                attempt_id,
                parent_attempt_id,
                phase,
                ..
            } => {
                if started.contains(attempt_id)
                    || parent_attempt_id
                        .is_some_and(|parent| parent == *attempt_id || !started.contains(&parent))
                {
                    return false;
                }
                if let Some(previous_phase) = last_started_phase
                    && (phase.ordinal() < previous_phase.ordinal()
                        || (phase.ordinal() > previous_phase.ordinal()
                            && unfinished_by_phase
                                .get(&previous_phase)
                                .is_some_and(|unfinished| *unfinished > 0)))
                {
                    return false;
                }
                last_started_phase = Some(*phase);
                started.insert(*attempt_id);
                attempt_phases.insert(*attempt_id, *phase);
                let unfinished = unfinished_by_phase.entry(*phase).or_default();
                *unfinished = unfinished.saturating_add(1);
            }
            ProvenanceEvent::AttemptFinished {
                attempt_id,
                stdout_artifact_id,
                stderr_artifact_id,
                ..
            } => {
                if !started.contains(attempt_id)
                    || !finished.insert(*attempt_id)
                    || stdout_artifact_id.is_some_and(|id| {
                        artifacts.get(&id) != Some(&(*attempt_id, crate::ArtifactKind::StdoutLog))
                    })
                    || stderr_artifact_id.is_some_and(|id| {
                        artifacts.get(&id) != Some(&(*attempt_id, crate::ArtifactKind::StderrLog))
                    })
                {
                    return false;
                }
                let Some(phase) = attempt_phases.get(attempt_id) else {
                    return false;
                };
                let Some(unfinished) = unfinished_by_phase.get_mut(phase) else {
                    return false;
                };
                *unfinished = unfinished.saturating_sub(1);
            }
            ProvenanceEvent::ArtifactRecorded { artifact } => {
                if !started.contains(&artifact.attempt_id)
                    || artifacts
                        .insert(artifact.artifact_id, (artifact.attempt_id, artifact.kind))
                        .is_some()
                {
                    return false;
                }
            }
            ProvenanceEvent::CheckRecorded { check } => {
                if !started.contains(&check.attempt_id) || !checks.insert(check.check_id) {
                    return false;
                }
                if check
                    .evidence
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != check.evidence.len()
                {
                    return false;
                }
                for evidence in &check.evidence {
                    match evidence {
                        crate::CheckEvidence::Artifact { artifact_id }
                            if !artifacts.contains_key(artifact_id) =>
                        {
                            return false;
                        }
                        crate::CheckEvidence::AttemptExit { attempt_id }
                            if !finished.contains(attempt_id) =>
                        {
                            return false;
                        }
                        crate::CheckEvidence::Artifact { .. }
                        | crate::CheckEvidence::AttemptExit { .. } => {}
                    }
                }
            }
        }
    }
    true
}
