use crate::{
    ArtifactId, ArtifactKind, ArtifactRecord, AttemptId, CheckEvidence, CheckId, CheckOutcome,
    CommandSpec, EXECUTION_PHASES, EnvironmentValue, EvidenceClass, ExecutionBounds,
    ExecutionPhase, ExecutionPlatform, NativeArgument, NativeEncoding, OperatingSystem,
    PROVENANCE_SCHEMA_VERSION, PhaseOutcome, ProcessExit, ProvenanceEvent, RetainedArgument,
    RunProvenance, TargetError, TargetSurface, ValidationCheck,
};
use birdcode_protocol::WorkspacePath;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_MEDIA_TYPE_BYTES: usize = 256;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 32_768;

/// Whether a phase must succeed or may be explicitly not applicable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum PhaseRequirement {
    RequiredSuccess,
    DeclaredNotApplicable,
}

/// Exact process-exit evidence accepted by a check descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ExitRequirement {
    Disallowed,
    AnyCompleted,
    AllowedCodes { codes: BTreeSet<i32> },
}

impl ExitRequirement {
    fn accepts(&self, process_exit: &ProcessExit) -> bool {
        match self {
            Self::Disallowed => false,
            Self::AnyCompleted => true,
            Self::AllowedCodes { codes } => {
                if let ProcessExit::Exited { code } = process_exit {
                    codes.contains(code)
                } else {
                    false
                }
            }
        }
    }

    const fn tag(&self) -> u8 {
        match self {
            Self::Disallowed => 0,
            Self::AnyCompleted => 1,
            Self::AllowedCodes { .. } => 2,
        }
    }
}

/// Frozen typed evidence contract for one required check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequirement {
    pub expected_kind: crate::CheckKind,
    pub allowed_artifact_kinds: BTreeSet<ArtifactKind>,
    pub allow_truncated_artifacts: bool,
    pub attempt_exit: ExitRequirement,
    pub minimum_evidence_items: u32,
}

/// Deterministic acceptance policy shared by all candidate producers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationPolicy {
    validation_plan_sha256: crate::Sha256Digest,
    phase_requirements: BTreeMap<ExecutionPhase, PhaseRequirement>,
    check_requirements: BTreeMap<CheckId, CheckRequirement>,
    minimum_primary_passes: u32,
}

impl ValidationPolicy {
    #[must_use]
    pub fn new(
        validation_plan_sha256: crate::Sha256Digest,
        phase_requirements: impl IntoIterator<Item = (ExecutionPhase, PhaseRequirement)>,
        check_requirements: impl IntoIterator<Item = (CheckId, CheckRequirement)>,
        minimum_primary_passes: u32,
    ) -> Self {
        Self {
            validation_plan_sha256,
            phase_requirements: phase_requirements.into_iter().collect(),
            check_requirements: check_requirements.into_iter().collect(),
            minimum_primary_passes,
        }
    }

    #[must_use]
    pub const fn phase_requirements(&self) -> &BTreeMap<ExecutionPhase, PhaseRequirement> {
        &self.phase_requirements
    }

    #[must_use]
    pub const fn check_requirements(&self) -> &BTreeMap<CheckId, CheckRequirement> {
        &self.check_requirements
    }

    #[must_use]
    pub const fn validation_plan_sha256(&self) -> crate::Sha256Digest {
        self.validation_plan_sha256
    }

    #[must_use]
    pub const fn minimum_primary_passes(&self) -> u32 {
        self.minimum_primary_passes
    }

    /// Computes the canonical plan digest bound into run provenance.
    #[must_use]
    pub fn policy_sha256(&self) -> crate::Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"birdcode.validation-policy.v1\0");
        hasher.update(self.validation_plan_sha256.as_bytes());
        hasher.update(self.minimum_primary_passes.to_be_bytes());
        hasher.update(
            u32::try_from(self.phase_requirements.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for (phase, requirement) in &self.phase_requirements {
            hasher.update([phase.ordinal(), *requirement as u8]);
        }
        hasher.update(
            u32::try_from(self.check_requirements.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for (check_id, requirement) in &self.check_requirements {
            hasher.update(check_id.as_uuid().as_bytes());
            hasher.update([requirement.expected_kind as u8]);
            hasher.update([u8::from(requirement.allow_truncated_artifacts)]);
            hasher.update(requirement.minimum_evidence_items.to_be_bytes());
            hasher.update([requirement.attempt_exit.tag()]);
            if let ExitRequirement::AllowedCodes { codes } = &requirement.attempt_exit {
                hasher.update(u32::try_from(codes.len()).unwrap_or(u32::MAX).to_be_bytes());
                for code in codes {
                    hasher.update(code.to_be_bytes());
                }
            } else {
                hasher.update(0_u32.to_be_bytes());
            }
            hasher.update(
                u32::try_from(requirement.allowed_artifact_kinds.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            for artifact_kind in &requirement.allowed_artifact_kinds {
                hasher.update([*artifact_kind as u8]);
            }
        }
        crate::Sha256Digest::from_array(hasher.finalize().into())
    }
}

/// Final deterministic decision after collecting every violation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceDecision {
    Accepted,
    Rejected,
}

/// Controller-adjudicated run verdict; adapters and checks cannot set it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunVerdict {
    CompletePass,
    Partial,
    Failed,
    InfrastructureInvalid,
    Cancelled,
}

/// Machine-readable validation result. Violations preserve discovery order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidationReport {
    decision: AcceptanceDecision,
    verdict: RunVerdict,
    violations: Vec<ValidationViolation>,
}

impl ValidationReport {
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self.decision, AcceptanceDecision::Accepted)
    }

    #[must_use]
    pub const fn decision(&self) -> AcceptanceDecision {
        self.decision
    }

    #[must_use]
    pub const fn verdict(&self) -> RunVerdict {
        self.verdict
    }

    #[must_use]
    pub fn violations(&self) -> &[ValidationViolation] {
        &self.violations
    }

    /// Reports whether malformed provenance/evidence makes projection unsafe.
    #[must_use]
    pub fn has_structural_violations(&self) -> bool {
        self.violations.iter().any(is_structural_violation)
    }
}

/// A command component whose native encoding or bytes are invalid.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum CommandComponent {
    Executable,
    WorkingDirectory,
    Argument { index: u32 },
    EnvironmentName { index: u32 },
    EnvironmentValue { index: u32 },
}

/// Environment metadata field with a structural error.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentMetadataField {
    Architecture,
    OsVersion,
    Locale,
}

/// Collect-all structural, resource, causal, and policy violations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub enum ValidationViolation {
    UnsupportedSchemaVersion {
        actual: u32,
        expected: u32,
    },
    InvalidTarget {
        error: String,
    },
    AdapterBindingMismatch,
    TargetEnvironmentMismatch,
    ValidationPlanDigestMismatch,
    RunContextHashMismatch,
    NonContiguousSequence {
        actual: u64,
        expected: u64,
    },
    TimestampRegressed {
        sequence: u64,
    },
    PreviousRecordHashMismatch {
        sequence: u64,
    },
    RecordHashMismatch {
        sequence: u64,
    },
    ZeroPolicyPrimaryMinimum,
    MissingPhaseRequirement {
        phase: ExecutionPhase,
    },
    ZeroRequiredSuccessPhases,
    NoRequiredChecks,
    InvalidCheckRequirement {
        check_id: CheckId,
    },
    PolicyCheckCountOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    PolicyEvidenceMinimumOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    PolicyPrimaryMinimumImpossible {
        actual: u32,
        available: u32,
    },
    ZeroMaximumTimeout,
    RecordCountOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    AttemptCountOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    CheckCountOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    CheckEvidenceItemsOutOfBounds {
        check_id: CheckId,
        actual: u64,
        maximum: u32,
    },
    TotalEvidenceItemsOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    TotalElapsedTimeOutOfBounds {
        actual: u64,
        maximum: u64,
    },
    TargetUrlOutOfBounds {
        actual: u64,
        maximum: u64,
    },
    EnvironmentMetadataEmpty {
        field: EnvironmentMetadataField,
    },
    EnvironmentMetadataOutOfBounds {
        actual: u64,
        maximum: u64,
    },
    EnvironmentValueEncodingMismatch {
        index: u32,
        expected: NativeEncoding,
        actual: NativeEncoding,
    },
    EnvironmentValueContainsNul {
        index: u32,
    },
    EmptySnapshotEnvironmentName {
        index: u32,
    },
    SnapshotEnvironmentNameContainsEquals {
        index: u32,
    },
    DuplicateSnapshotEnvironmentName {
        index: u32,
    },
    SnapshotEnvironmentEntriesOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    ToolchainEntriesOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    ToolchainVersionEmpty {
        index: u32,
    },
    DuplicateAttemptStart {
        attempt_id: AttemptId,
    },
    InvalidParentAttempt {
        attempt_id: AttemptId,
        parent_attempt_id: AttemptId,
    },
    PhaseOutOfOrder {
        attempt_id: AttemptId,
        phase: ExecutionPhase,
        previous_phase: ExecutionPhase,
    },
    PhaseAdvancedBeforeTerminal {
        attempt_id: AttemptId,
        previous_phase: ExecutionPhase,
    },
    MissingPhaseTerminal {
        phase: ExecutionPhase,
    },
    PhaseRequirementNotMet {
        phase: ExecutionPhase,
        requirement: PhaseRequirement,
    },
    DuplicateAttemptFinish {
        attempt_id: AttemptId,
    },
    CommandAttemptMissingProcessExit {
        attempt_id: AttemptId,
    },
    UnexpectedProcessExit {
        attempt_id: AttemptId,
    },
    ContradictoryPhaseOutcome {
        attempt_id: AttemptId,
        outcome: PhaseOutcome,
        process_exit: ProcessExit,
    },
    EventBeforeAttemptStart {
        attempt_id: AttemptId,
        sequence: u64,
    },
    AttemptNotFinished {
        attempt_id: AttemptId,
    },
    EmptyCommandPath {
        attempt_id: AttemptId,
        component: CommandComponent,
    },
    PathOutOfBounds {
        attempt_id: AttemptId,
        component: CommandComponent,
        actual: u64,
        maximum: u64,
    },
    CommandValueContainsNul {
        attempt_id: AttemptId,
        component: CommandComponent,
    },
    CommandEncodingMismatch {
        attempt_id: AttemptId,
        component: CommandComponent,
        expected: NativeEncoding,
        actual: NativeEncoding,
    },
    DuplicateEnvironmentName {
        attempt_id: AttemptId,
        index: u32,
    },
    EmptyEnvironmentName {
        attempt_id: AttemptId,
        index: u32,
    },
    EnvironmentNameContainsEquals {
        attempt_id: AttemptId,
        index: u32,
    },
    TimeoutOutOfBounds {
        attempt_id: AttemptId,
        requested: u64,
        maximum: u64,
    },
    CaptureOutOfBounds {
        attempt_id: AttemptId,
        stream: ArtifactKind,
        requested: u64,
        maximum: u64,
    },
    ArgvItemsOutOfBounds {
        attempt_id: AttemptId,
        actual: u64,
        maximum: u32,
    },
    ArgumentBytesOutOfBounds {
        attempt_id: AttemptId,
        actual: u64,
        maximum: u64,
    },
    EnvironmentEntriesOutOfBounds {
        attempt_id: AttemptId,
        actual: u64,
        maximum: u32,
    },
    EnvironmentBytesOutOfBounds {
        attempt_id: AttemptId,
        actual: u64,
        maximum: u64,
    },
    StdinOutOfBounds {
        attempt_id: AttemptId,
        actual: u64,
        maximum: u64,
    },
    ElapsedTimeOutOfBounds {
        attempt_id: AttemptId,
        actual: u64,
        maximum: u64,
    },
    DuplicateArtifact {
        artifact_id: ArtifactId,
    },
    EmptyMediaType {
        artifact_id: ArtifactId,
    },
    MediaTypeTooLong {
        artifact_id: ArtifactId,
        actual: u64,
    },
    StorageRefOutOfBounds {
        artifact_id: ArtifactId,
        actual: u64,
        maximum: u64,
    },
    InvalidArtifactTruncation {
        artifact_id: ArtifactId,
    },
    ArtifactOutOfBounds {
        artifact_id: ArtifactId,
        actual: u64,
        maximum: u64,
    },
    ArtifactKindOutOfBounds {
        artifact_id: ArtifactId,
        kind: ArtifactKind,
        actual: u64,
        maximum: u64,
    },
    ArtifactCountOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    TotalArtifactBytesOutOfBounds {
        actual: u64,
        maximum: u64,
    },
    ScreenshotCountOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    VideoCountOutOfBounds {
        actual: u64,
        maximum: u32,
    },
    FinishedArtifactMissing {
        attempt_id: AttemptId,
        artifact_id: ArtifactId,
        expected_kind: ArtifactKind,
    },
    FinishedArtifactMismatch {
        attempt_id: AttemptId,
        artifact_id: ArtifactId,
        expected_kind: ArtifactKind,
    },
    DuplicateCheck {
        check_id: CheckId,
    },
    UndeclaredCheck {
        check_id: CheckId,
    },
    CheckKindMismatch {
        check_id: CheckId,
        expected: crate::CheckKind,
        actual: crate::CheckKind,
    },
    CheckEvidenceCountBelowMinimum {
        check_id: CheckId,
        actual: u32,
        minimum: u32,
    },
    DisallowedArtifactEvidence {
        check_id: CheckId,
        artifact_id: ArtifactId,
        kind: ArtifactKind,
    },
    TruncatedArtifactEvidenceDisallowed {
        check_id: CheckId,
        artifact_id: ArtifactId,
    },
    AttemptExitEvidenceRequirementNotMet {
        check_id: CheckId,
        attempt_id: AttemptId,
    },
    CheckHasNoEvidence {
        check_id: CheckId,
    },
    DuplicateCheckEvidence {
        check_id: CheckId,
        evidence: CheckEvidence,
    },
    MissingArtifactEvidence {
        check_id: CheckId,
        artifact_id: ArtifactId,
    },
    MissingExitEvidence {
        check_id: CheckId,
        attempt_id: AttemptId,
    },
    PrimaryCheckHasNoMechanicalEvidence {
        check_id: CheckId,
    },
    VisualCheckHasNoVisionEvidence {
        check_id: CheckId,
    },
    RecordedCheckFailed {
        check_id: CheckId,
    },
    MissingRequiredCheck {
        check_id: CheckId,
    },
    RequiredCheckDidNotPass {
        check_id: CheckId,
        outcome: CheckOutcome,
    },
    InsufficientPrimaryPasses {
        actual: u32,
        required: u32,
    },
}

impl RunProvenance {
    /// Validates the complete log and policy without stopping at the first error.
    #[must_use]
    pub fn validate(&self, policy: &ValidationPolicy) -> ValidationReport {
        let mut validator = Validator::new(self, policy);
        validator.validate();
        let verdict = derive_verdict(self, &validator.violations);
        let decision = if verdict == RunVerdict::CompletePass {
            AcceptanceDecision::Accepted
        } else {
            AcceptanceDecision::Rejected
        };
        ValidationReport {
            decision,
            verdict,
            violations: validator.violations,
        }
    }
}

struct Validator<'a> {
    provenance: &'a RunProvenance,
    policy: &'a ValidationPolicy,
    violations: Vec<ValidationViolation>,
    started: BTreeMap<AttemptId, AttemptStart>,
    finished: BTreeMap<AttemptId, AttemptFinish<'a>>,
    artifacts: BTreeMap<ArtifactId, &'a ArtifactRecord>,
    checks: BTreeMap<CheckId, &'a ValidationCheck>,
    finished_phases: BTreeSet<ExecutionPhase>,
    succeeded_phases: BTreeSet<ExecutionPhase>,
    not_applicable_phases: BTreeSet<ExecutionPhase>,
    unfinished_by_phase: BTreeMap<ExecutionPhase, u32>,
    last_started_phase: Option<ExecutionPhase>,
}

#[derive(Clone, Copy)]
struct AttemptStart {
    timeout_ms: u64,
    has_command: bool,
    phase: ExecutionPhase,
}

#[derive(Clone, Copy)]
struct AttemptFinish<'a> {
    process_exit: Option<&'a ProcessExit>,
}

impl<'a> Validator<'a> {
    fn new(provenance: &'a RunProvenance, policy: &'a ValidationPolicy) -> Self {
        Self {
            provenance,
            policy,
            violations: Vec::new(),
            started: BTreeMap::new(),
            finished: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            checks: BTreeMap::new(),
            finished_phases: BTreeSet::new(),
            succeeded_phases: BTreeSet::new(),
            not_applicable_phases: BTreeSet::new(),
            unfinished_by_phase: BTreeMap::new(),
            last_started_phase: None,
        }
    }

    fn validate(&mut self) {
        self.validate_header();
        self.collect_records();
        self.validate_execution_totals();
        self.validate_attempt_completion();
        self.validate_phase_coverage();
        self.validate_artifact_totals();
        self.validate_finished_artifact_links();
        self.validate_checks();
        self.validate_policy();
    }

    #[allow(clippy::too_many_lines)]
    fn validate_header(&mut self) {
        if self.provenance.schema_version() != PROVENANCE_SCHEMA_VERSION {
            self.violations
                .push(ValidationViolation::UnsupportedSchemaVersion {
                    actual: self.provenance.schema_version(),
                    expected: PROVENANCE_SCHEMA_VERSION,
                });
        }
        if let Err(error) = self.provenance.target().kind() {
            self.violations.push(ValidationViolation::InvalidTarget {
                error: target_error_code(&error).to_owned(),
            });
        }
        if self.provenance.target().required_adapter().ok()
            != Some(self.provenance.manifest().adapter.requirement)
        {
            self.violations
                .push(ValidationViolation::AdapterBindingMismatch);
        }
        if !target_environment_matches(self.provenance.target(), self.provenance.environment()) {
            self.violations
                .push(ValidationViolation::TargetEnvironmentMismatch);
        }
        if self.policy.validation_plan_sha256() != self.provenance.manifest().validation_plan_sha256
            || self.policy.policy_sha256() != self.provenance.manifest().validation_policy_sha256
        {
            self.violations
                .push(ValidationViolation::ValidationPlanDigestMismatch);
        }
        if crate::provenance::compute_run_context_hash(
            self.provenance.schema_version(),
            self.provenance.run_id(),
            self.provenance.candidate_id(),
            self.provenance.evaluation_case_id(),
            self.provenance.target(),
            self.provenance.bounds(),
            self.provenance.environment(),
            self.provenance.manifest(),
        )
        .ok()
            != Some(self.provenance.run_context_sha256())
        {
            self.violations
                .push(ValidationViolation::RunContextHashMismatch);
        }
        if self.provenance.bounds().max_timeout_ms == 0 {
            self.violations
                .push(ValidationViolation::ZeroMaximumTimeout);
        }
        let url_bytes = match self.provenance.target().surface() {
            TargetSurface::WebPlaywright { url } => Some(url.as_str().len()),
            TargetSurface::ApiServer { endpoint } => Some(endpoint.as_str().len()),
            TargetSurface::Cli
            | TargetSurface::Tui
            | TargetSurface::DesktopApplication { .. }
            | TargetSurface::MobileApplication { .. } => None,
        };
        if let Some(actual) = url_bytes
            && u64::try_from(actual).unwrap_or(u64::MAX) > self.provenance.bounds().max_url_bytes
        {
            self.violations
                .push(ValidationViolation::TargetUrlOutOfBounds {
                    actual: u64::try_from(actual).unwrap_or(u64::MAX),
                    maximum: self.provenance.bounds().max_url_bytes,
                });
        }
        validate_environment_snapshot(
            self.provenance.environment(),
            self.provenance.bounds(),
            &mut self.violations,
        );
        if self.policy.minimum_primary_passes == 0 {
            self.violations
                .push(ValidationViolation::ZeroPolicyPrimaryMinimum);
        }
        for phase in EXECUTION_PHASES {
            if !self.policy.phase_requirements.contains_key(&phase) {
                self.violations
                    .push(ValidationViolation::MissingPhaseRequirement { phase });
            }
        }
        if !self
            .policy
            .phase_requirements
            .values()
            .any(|requirement| *requirement == PhaseRequirement::RequiredSuccess)
        {
            self.violations
                .push(ValidationViolation::ZeroRequiredSuccessPhases);
        }
        if self.policy.check_requirements.is_empty() {
            self.violations.push(ValidationViolation::NoRequiredChecks);
        }
        let policy_check_count =
            u64::try_from(self.policy.check_requirements.len()).unwrap_or(u64::MAX);
        if policy_check_count > u64::from(self.provenance.bounds().max_checks) {
            self.violations
                .push(ValidationViolation::PolicyCheckCountOutOfBounds {
                    actual: policy_check_count,
                    maximum: self.provenance.bounds().max_checks,
                });
        }
        let policy_evidence_minimum =
            self.policy
                .check_requirements
                .values()
                .fold(0_u64, |total, requirement| {
                    total.saturating_add(u64::from(requirement.minimum_evidence_items))
                });
        if policy_evidence_minimum > u64::from(self.provenance.bounds().max_total_evidence_items) {
            self.violations
                .push(ValidationViolation::PolicyEvidenceMinimumOutOfBounds {
                    actual: policy_evidence_minimum,
                    maximum: self.provenance.bounds().max_total_evidence_items,
                });
        }
        let available_primary = self
            .policy
            .check_requirements
            .values()
            .filter(|requirement| {
                requirement.expected_kind.evidence_class() == EvidenceClass::PrimaryMechanical
            })
            .count();
        let available_primary = u32::try_from(available_primary).unwrap_or(u32::MAX);
        if self.policy.minimum_primary_passes > available_primary {
            self.violations
                .push(ValidationViolation::PolicyPrimaryMinimumImpossible {
                    actual: self.policy.minimum_primary_passes,
                    available: available_primary,
                });
        }
        for (check_id, requirement) in &self.policy.check_requirements {
            let expected_class = requirement.expected_kind.evidence_class();
            let invalid_artifact_kind = requirement.allowed_artifact_kinds.iter().any(|kind| {
                kind.evidence_class() != Some(expected_class)
                    || !requirement.expected_kind.is_artifact_compatible(*kind)
            });
            let exit_is_allowed = !matches!(requirement.attempt_exit, ExitRequirement::Disallowed);
            let empty_code_set = matches!(
                &requirement.attempt_exit,
                ExitRequirement::AllowedCodes { codes } if codes.is_empty()
            );
            if requirement.minimum_evidence_items == 0
                || requirement.minimum_evidence_items
                    > self.provenance.bounds().max_check_evidence_items
                || (!exit_is_allowed && requirement.allowed_artifact_kinds.is_empty())
                || invalid_artifact_kind
                || empty_code_set
                || (exit_is_allowed && !requirement.expected_kind.is_exit_compatible())
                || (expected_class == EvidenceClass::Vision && exit_is_allowed)
            {
                self.violations
                    .push(ValidationViolation::InvalidCheckRequirement {
                        check_id: *check_id,
                    });
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn collect_records(&mut self) {
        let mut expected_sequence = 1_u64;
        let mut previous_timestamp = None;
        let mut previous_hash = None;
        for record in self.provenance.records() {
            if record.sequence != expected_sequence {
                self.violations
                    .push(ValidationViolation::NonContiguousSequence {
                        actual: record.sequence,
                        expected: expected_sequence,
                    });
            }
            expected_sequence = record.sequence.saturating_add(1);
            if previous_timestamp.is_some_and(|value| record.observed_at_unix_ms < value) {
                self.violations
                    .push(ValidationViolation::TimestampRegressed {
                        sequence: record.sequence,
                    });
            }
            previous_timestamp = Some(record.observed_at_unix_ms);
            if record.previous_record_sha256 != previous_hash {
                self.violations
                    .push(ValidationViolation::PreviousRecordHashMismatch {
                        sequence: record.sequence,
                    });
            }
            if crate::provenance::compute_record_hash(
                self.provenance.schema_version(),
                self.provenance.run_id(),
                self.provenance.run_context_sha256(),
                record.sequence,
                record.observed_at_unix_ms,
                record.previous_record_sha256,
                &record.event,
            )
            .ok()
                != Some(record.record_sha256)
            {
                self.violations
                    .push(ValidationViolation::RecordHashMismatch {
                        sequence: record.sequence,
                    });
            }
            previous_hash = Some(record.record_sha256);

            match &record.event {
                ProvenanceEvent::AttemptStarted {
                    attempt_id,
                    parent_attempt_id,
                    phase,
                    timeout_ms,
                    command,
                    ..
                } => {
                    if let Some(previous_phase) = self.last_started_phase {
                        if phase.ordinal() < previous_phase.ordinal() {
                            self.violations.push(ValidationViolation::PhaseOutOfOrder {
                                attempt_id: *attempt_id,
                                phase: *phase,
                                previous_phase,
                            });
                        } else if phase.ordinal() > previous_phase.ordinal()
                            && self
                                .unfinished_by_phase
                                .get(&previous_phase)
                                .is_some_and(|unfinished| *unfinished > 0)
                        {
                            self.violations.push(
                                ValidationViolation::PhaseAdvancedBeforeTerminal {
                                    attempt_id: *attempt_id,
                                    previous_phase,
                                },
                            );
                        }
                    }
                    if self
                        .last_started_phase
                        .is_none_or(|previous| phase.ordinal() >= previous.ordinal())
                    {
                        self.last_started_phase = Some(*phase);
                    }
                    let unfinished = self.unfinished_by_phase.entry(*phase).or_default();
                    *unfinished = unfinished.saturating_add(1);
                    if let Some(parent_attempt_id) = parent_attempt_id
                        && (*parent_attempt_id == *attempt_id
                            || !self.started.contains_key(parent_attempt_id))
                    {
                        self.violations
                            .push(ValidationViolation::InvalidParentAttempt {
                                attempt_id: *attempt_id,
                                parent_attempt_id: *parent_attempt_id,
                            });
                    }
                    if self
                        .started
                        .insert(
                            *attempt_id,
                            AttemptStart {
                                timeout_ms: *timeout_ms,
                                has_command: command.is_some(),
                                phase: *phase,
                            },
                        )
                        .is_some()
                    {
                        self.violations
                            .push(ValidationViolation::DuplicateAttemptStart {
                                attempt_id: *attempt_id,
                            });
                    }
                    if *timeout_ms == 0 || *timeout_ms > self.provenance.bounds().max_timeout_ms {
                        self.violations
                            .push(ValidationViolation::TimeoutOutOfBounds {
                                attempt_id: *attempt_id,
                                requested: *timeout_ms,
                                maximum: self.provenance.bounds().max_timeout_ms,
                            });
                    }
                    if let Some(command) = command {
                        validate_command(
                            *attempt_id,
                            command,
                            self.provenance.bounds(),
                            operating_system_encoding(
                                &self.provenance.environment().operating_system,
                            ),
                            &mut self.violations,
                        );
                    }
                }
                ProvenanceEvent::AttemptFinished {
                    attempt_id,
                    outcome,
                    process_exit,
                    elapsed_ms,
                    ..
                } => {
                    self.require_started(*attempt_id, record.sequence);
                    let duplicate_finish = self
                        .finished
                        .insert(
                            *attempt_id,
                            AttemptFinish {
                                process_exit: process_exit.as_ref(),
                            },
                        )
                        .is_some();
                    if duplicate_finish {
                        self.violations
                            .push(ValidationViolation::DuplicateAttemptFinish {
                                attempt_id: *attempt_id,
                            });
                    }
                    if !duplicate_finish && let Some(start) = self.started.get(attempt_id) {
                        self.finished_phases.insert(start.phase);
                        if let Some(unfinished) = self.unfinished_by_phase.get_mut(&start.phase) {
                            *unfinished = unfinished.saturating_sub(1);
                        }
                        match outcome {
                            PhaseOutcome::Succeeded => {
                                self.succeeded_phases.insert(start.phase);
                            }
                            PhaseOutcome::NotApplicable => {
                                self.not_applicable_phases.insert(start.phase);
                            }
                            PhaseOutcome::CandidateFailure
                            | PhaseOutcome::InfrastructureError
                            | PhaseOutcome::TimedOut
                            | PhaseOutcome::Cancelled
                            | PhaseOutcome::PolicyDenied => {}
                        }
                    }
                    if self
                        .started
                        .get(attempt_id)
                        .is_some_and(|start| start.has_command)
                        && process_exit.is_none()
                        && !matches!(
                            outcome,
                            PhaseOutcome::PolicyDenied | PhaseOutcome::NotApplicable
                        )
                    {
                        self.violations.push(
                            ValidationViolation::CommandAttemptMissingProcessExit {
                                attempt_id: *attempt_id,
                            },
                        );
                    }
                    if self
                        .started
                        .get(attempt_id)
                        .is_some_and(|start| !start.has_command)
                        && process_exit.is_some()
                    {
                        self.violations
                            .push(ValidationViolation::UnexpectedProcessExit {
                                attempt_id: *attempt_id,
                            });
                    }
                    if let Some(process_exit) = process_exit
                        && phase_outcome_contradicts_exit(*outcome, process_exit)
                    {
                        self.violations
                            .push(ValidationViolation::ContradictoryPhaseOutcome {
                                attempt_id: *attempt_id,
                                outcome: *outcome,
                                process_exit: process_exit.clone(),
                            });
                    }
                    if let Some(start) = self.started.get(attempt_id)
                        && *elapsed_ms > start.timeout_ms
                    {
                        self.violations
                            .push(ValidationViolation::ElapsedTimeOutOfBounds {
                                attempt_id: *attempt_id,
                                actual: *elapsed_ms,
                                maximum: start.timeout_ms,
                            });
                    }
                }
                ProvenanceEvent::ArtifactRecorded { artifact } => {
                    self.require_started(artifact.attempt_id, record.sequence);
                    if self
                        .artifacts
                        .insert(artifact.artifact_id, artifact)
                        .is_some()
                    {
                        self.violations
                            .push(ValidationViolation::DuplicateArtifact {
                                artifact_id: artifact.artifact_id,
                            });
                    }
                    validate_artifact(artifact, self.provenance.bounds(), &mut self.violations);
                }
                ProvenanceEvent::CheckRecorded { check } => {
                    self.require_started(check.attempt_id, record.sequence);
                    if self.checks.insert(check.check_id, check).is_some() {
                        self.violations.push(ValidationViolation::DuplicateCheck {
                            check_id: check.check_id,
                        });
                    }
                }
            }
        }
    }

    fn require_started(&mut self, attempt_id: AttemptId, sequence: u64) {
        if !self.started.contains_key(&attempt_id) {
            self.violations
                .push(ValidationViolation::EventBeforeAttemptStart {
                    attempt_id,
                    sequence,
                });
        }
    }

    fn validate_attempt_completion(&mut self) {
        for attempt_id in self.started.keys() {
            if !self.finished.contains_key(attempt_id) {
                self.violations
                    .push(ValidationViolation::AttemptNotFinished {
                        attempt_id: *attempt_id,
                    });
            }
        }
    }

    fn validate_execution_totals(&mut self) {
        let bounds = self.provenance.bounds();
        let record_count = u64::try_from(self.provenance.records().len()).unwrap_or(u64::MAX);
        if record_count > u64::from(bounds.max_records) {
            self.violations
                .push(ValidationViolation::RecordCountOutOfBounds {
                    actual: record_count,
                    maximum: bounds.max_records,
                });
        }
        let attempt_count = u64::try_from(self.started.len()).unwrap_or(u64::MAX);
        if attempt_count > u64::from(bounds.max_attempts) {
            self.violations
                .push(ValidationViolation::AttemptCountOutOfBounds {
                    actual: attempt_count,
                    maximum: bounds.max_attempts,
                });
        }
        let check_count = u64::try_from(self.checks.len()).unwrap_or(u64::MAX);
        if check_count > u64::from(bounds.max_checks) {
            self.violations
                .push(ValidationViolation::CheckCountOutOfBounds {
                    actual: check_count,
                    maximum: bounds.max_checks,
                });
        }
        let mut total_evidence = 0_u64;
        for check in self.checks.values() {
            let count = u64::try_from(check.evidence.len()).unwrap_or(u64::MAX);
            total_evidence = total_evidence.saturating_add(count);
            if count > u64::from(bounds.max_check_evidence_items) {
                self.violations
                    .push(ValidationViolation::CheckEvidenceItemsOutOfBounds {
                        check_id: check.check_id,
                        actual: count,
                        maximum: bounds.max_check_evidence_items,
                    });
            }
        }
        if total_evidence > u64::from(bounds.max_total_evidence_items) {
            self.violations
                .push(ValidationViolation::TotalEvidenceItemsOutOfBounds {
                    actual: total_evidence,
                    maximum: bounds.max_total_evidence_items,
                });
        }
        let total_elapsed = self
            .provenance
            .records()
            .iter()
            .fold(0_u64, |total, record| {
                if let ProvenanceEvent::AttemptFinished { elapsed_ms, .. } = &record.event {
                    total.saturating_add(*elapsed_ms)
                } else {
                    total
                }
            });
        if total_elapsed > bounds.max_total_elapsed_ms {
            self.violations
                .push(ValidationViolation::TotalElapsedTimeOutOfBounds {
                    actual: total_elapsed,
                    maximum: bounds.max_total_elapsed_ms,
                });
        }
    }

    fn validate_phase_coverage(&mut self) {
        for phase in EXECUTION_PHASES {
            if !self.finished_phases.contains(&phase) {
                self.violations
                    .push(ValidationViolation::MissingPhaseTerminal { phase });
                continue;
            }
            let Some(requirement) = self.policy.phase_requirements.get(&phase) else {
                continue;
            };
            let requirement_met = match requirement {
                PhaseRequirement::RequiredSuccess => self.succeeded_phases.contains(&phase),
                PhaseRequirement::DeclaredNotApplicable => {
                    self.not_applicable_phases.contains(&phase)
                }
            };
            if !requirement_met {
                self.violations
                    .push(ValidationViolation::PhaseRequirementNotMet {
                        phase,
                        requirement: *requirement,
                    });
            }
        }
    }

    fn validate_artifact_totals(&mut self) {
        let bounds = self.provenance.bounds();
        let artifact_count = u64::try_from(self.artifacts.len()).unwrap_or(u64::MAX);
        if artifact_count > u64::from(bounds.max_artifacts) {
            self.violations
                .push(ValidationViolation::ArtifactCountOutOfBounds {
                    actual: artifact_count,
                    maximum: bounds.max_artifacts,
                });
        }
        let total = self.artifacts.values().fold(0_u64, |sum, artifact| {
            sum.saturating_add(artifact.retained_bytes)
        });
        if total > bounds.max_total_artifact_bytes {
            self.violations
                .push(ValidationViolation::TotalArtifactBytesOutOfBounds {
                    actual: total,
                    maximum: bounds.max_total_artifact_bytes,
                });
        }
        let screenshots = self
            .artifacts
            .values()
            .filter(|artifact| artifact.kind == ArtifactKind::Screenshot)
            .count();
        let screenshots = u64::try_from(screenshots).unwrap_or(u64::MAX);
        if screenshots > u64::from(bounds.max_screenshots) {
            self.violations
                .push(ValidationViolation::ScreenshotCountOutOfBounds {
                    actual: screenshots,
                    maximum: bounds.max_screenshots,
                });
        }
        let videos = self
            .artifacts
            .values()
            .filter(|artifact| artifact.kind == ArtifactKind::Video)
            .count();
        let videos = u64::try_from(videos).unwrap_or(u64::MAX);
        if videos > u64::from(bounds.max_videos) {
            self.violations
                .push(ValidationViolation::VideoCountOutOfBounds {
                    actual: videos,
                    maximum: bounds.max_videos,
                });
        }
    }

    fn validate_finished_artifact_links(&mut self) {
        for record in self.provenance.records() {
            let ProvenanceEvent::AttemptFinished {
                attempt_id,
                stdout_artifact_id,
                stderr_artifact_id,
                ..
            } = &record.event
            else {
                continue;
            };
            if let Some(artifact_id) = stdout_artifact_id {
                self.validate_finished_artifact(*attempt_id, *artifact_id, ArtifactKind::StdoutLog);
            }
            if let Some(artifact_id) = stderr_artifact_id {
                self.validate_finished_artifact(*attempt_id, *artifact_id, ArtifactKind::StderrLog);
            }
        }
    }

    fn validate_finished_artifact(
        &mut self,
        attempt_id: AttemptId,
        artifact_id: ArtifactId,
        expected_kind: ArtifactKind,
    ) {
        let Some(artifact) = self.artifacts.get(&artifact_id) else {
            self.violations
                .push(ValidationViolation::FinishedArtifactMissing {
                    attempt_id,
                    artifact_id,
                    expected_kind,
                });
            return;
        };
        if artifact.attempt_id != attempt_id || artifact.kind != expected_kind {
            self.violations
                .push(ValidationViolation::FinishedArtifactMismatch {
                    attempt_id,
                    artifact_id,
                    expected_kind,
                });
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_checks(&mut self) {
        for check in self.checks.values() {
            let mut has_mechanical = false;
            let mut has_vision = false;
            let requirement = self.policy.check_requirements.get(&check.check_id);
            let Some(requirement) = requirement else {
                self.violations.push(ValidationViolation::UndeclaredCheck {
                    check_id: check.check_id,
                });
                continue;
            };
            let mut unique_evidence = BTreeSet::new();
            let mut qualifying_evidence = BTreeSet::new();
            for evidence in &check.evidence {
                if !unique_evidence.insert(*evidence) {
                    self.violations
                        .push(ValidationViolation::DuplicateCheckEvidence {
                            check_id: check.check_id,
                            evidence: *evidence,
                        });
                }
            }
            if check.kind != requirement.expected_kind {
                self.violations
                    .push(ValidationViolation::CheckKindMismatch {
                        check_id: check.check_id,
                        expected: requirement.expected_kind,
                        actual: check.kind,
                    });
            }
            if check.evidence.is_empty() {
                self.violations
                    .push(ValidationViolation::CheckHasNoEvidence {
                        check_id: check.check_id,
                    });
            }
            for evidence in &check.evidence {
                match evidence {
                    CheckEvidence::Artifact { artifact_id } => {
                        let Some(artifact) = self.artifacts.get(artifact_id) else {
                            self.violations
                                .push(ValidationViolation::MissingArtifactEvidence {
                                    check_id: check.check_id,
                                    artifact_id: *artifact_id,
                                });
                            continue;
                        };
                        if !requirement.allowed_artifact_kinds.contains(&artifact.kind) {
                            self.violations
                                .push(ValidationViolation::DisallowedArtifactEvidence {
                                    check_id: check.check_id,
                                    artifact_id: *artifact_id,
                                    kind: artifact.kind,
                                });
                            continue;
                        }
                        if artifact.truncated && !requirement.allow_truncated_artifacts {
                            self.violations.push(
                                ValidationViolation::TruncatedArtifactEvidenceDisallowed {
                                    check_id: check.check_id,
                                    artifact_id: *artifact_id,
                                },
                            );
                            continue;
                        }
                        qualifying_evidence.insert(*evidence);
                        match artifact.kind.evidence_class() {
                            Some(EvidenceClass::PrimaryMechanical) => has_mechanical = true,
                            Some(EvidenceClass::Vision) => has_vision = true,
                            None => {}
                        }
                    }
                    CheckEvidence::AttemptExit { attempt_id } => {
                        let process_exit = self
                            .finished
                            .get(attempt_id)
                            .and_then(|finish| finish.process_exit);
                        let Some(process_exit) = process_exit else {
                            self.violations
                                .push(ValidationViolation::MissingExitEvidence {
                                    check_id: check.check_id,
                                    attempt_id: *attempt_id,
                                });
                            continue;
                        };
                        if !requirement.attempt_exit.accepts(process_exit) {
                            self.violations.push(
                                ValidationViolation::AttemptExitEvidenceRequirementNotMet {
                                    check_id: check.check_id,
                                    attempt_id: *attempt_id,
                                },
                            );
                            continue;
                        }
                        qualifying_evidence.insert(*evidence);
                        has_mechanical = true;
                    }
                }
            }

            match check.kind.evidence_class() {
                EvidenceClass::PrimaryMechanical if !has_mechanical => {
                    self.violations.push(
                        ValidationViolation::PrimaryCheckHasNoMechanicalEvidence {
                            check_id: check.check_id,
                        },
                    );
                }
                EvidenceClass::Vision if !has_vision => {
                    self.violations
                        .push(ValidationViolation::VisualCheckHasNoVisionEvidence {
                            check_id: check.check_id,
                        });
                }
                EvidenceClass::PrimaryMechanical | EvidenceClass::Vision => {}
            }
            let evidence_count = u32::try_from(qualifying_evidence.len()).unwrap_or(u32::MAX);
            if evidence_count < requirement.minimum_evidence_items {
                self.violations
                    .push(ValidationViolation::CheckEvidenceCountBelowMinimum {
                        check_id: check.check_id,
                        actual: evidence_count,
                        minimum: requirement.minimum_evidence_items,
                    });
            }
            if check.outcome == CheckOutcome::Failed {
                self.violations
                    .push(ValidationViolation::RecordedCheckFailed {
                        check_id: check.check_id,
                    });
            }
        }
    }

    fn validate_policy(&mut self) {
        for required_id in self.policy.check_requirements.keys() {
            match self.checks.get(required_id) {
                None => self
                    .violations
                    .push(ValidationViolation::MissingRequiredCheck {
                        check_id: *required_id,
                    }),
                Some(check) if check.outcome != CheckOutcome::Passed => {
                    self.violations
                        .push(ValidationViolation::RequiredCheckDidNotPass {
                            check_id: *required_id,
                            outcome: check.outcome,
                        });
                }
                Some(_) => {}
            }
        }

        let primary_passes = self
            .checks
            .values()
            .filter(|check| {
                check.outcome == CheckOutcome::Passed
                    && check.kind.evidence_class() == EvidenceClass::PrimaryMechanical
                    && self.check_satisfies_requirement(check)
            })
            .count();
        let primary_passes = u32::try_from(primary_passes).unwrap_or(u32::MAX);
        if primary_passes < self.policy.minimum_primary_passes {
            self.violations
                .push(ValidationViolation::InsufficientPrimaryPasses {
                    actual: primary_passes,
                    required: self.policy.minimum_primary_passes,
                });
        }
    }

    fn check_satisfies_requirement(&self, check: &ValidationCheck) -> bool {
        let Some(requirement) = self.policy.check_requirements.get(&check.check_id) else {
            return false;
        };
        let unique_evidence: BTreeSet<_> = check.evidence.iter().copied().collect();
        if check.kind != requirement.expected_kind
            || u32::try_from(unique_evidence.len()).unwrap_or(u32::MAX)
                < requirement.minimum_evidence_items
        {
            return false;
        }
        let mut has_mechanical = false;
        for evidence in &unique_evidence {
            match evidence {
                CheckEvidence::Artifact { artifact_id } => {
                    let Some(artifact) = self.artifacts.get(artifact_id) else {
                        return false;
                    };
                    if !requirement.allowed_artifact_kinds.contains(&artifact.kind) {
                        return false;
                    }
                    if artifact.truncated && !requirement.allow_truncated_artifacts {
                        return false;
                    }
                    has_mechanical |=
                        artifact.kind.evidence_class() == Some(EvidenceClass::PrimaryMechanical);
                }
                CheckEvidence::AttemptExit { attempt_id } => {
                    let Some(process_exit) = self
                        .finished
                        .get(attempt_id)
                        .and_then(|finish| finish.process_exit)
                    else {
                        return false;
                    };
                    if !requirement.attempt_exit.accepts(process_exit) {
                        return false;
                    }
                    has_mechanical = true;
                }
            }
        }
        has_mechanical
    }
}

fn derive_verdict(provenance: &RunProvenance, violations: &[ValidationViolation]) -> RunVerdict {
    let outcomes: Vec<_> = provenance
        .records()
        .iter()
        .filter_map(|record| {
            if let ProvenanceEvent::AttemptFinished { outcome, .. } = &record.event {
                Some(*outcome)
            } else {
                None
            }
        })
        .collect();

    // Structural corruption remains a failed candidate by default. Only a
    // separate trusted controller adjudication may assign InfrastructureInvalid.
    if violations.iter().any(is_structural_violation) {
        return RunVerdict::Failed;
    }
    if outcomes.iter().any(|outcome| {
        matches!(
            outcome,
            PhaseOutcome::CandidateFailure
                | PhaseOutcome::InfrastructureError
                | PhaseOutcome::TimedOut
                | PhaseOutcome::PolicyDenied
        )
    }) || violations
        .iter()
        .any(|violation| matches!(violation, ValidationViolation::RecordedCheckFailed { .. }))
    {
        return RunVerdict::Failed;
    }
    if outcomes.contains(&PhaseOutcome::Cancelled) {
        return RunVerdict::Cancelled;
    }
    if violations.iter().any(|violation| {
        matches!(
            violation,
            ValidationViolation::PhaseRequirementNotMet { .. }
        )
    }) {
        return RunVerdict::Failed;
    }
    if violations.is_empty() {
        RunVerdict::CompletePass
    } else {
        RunVerdict::Partial
    }
}

fn is_structural_violation(violation: &ValidationViolation) -> bool {
    !matches!(
        violation,
        ValidationViolation::RecordedCheckFailed { .. }
            | ValidationViolation::PhaseRequirementNotMet { .. }
            | ValidationViolation::UndeclaredCheck { .. }
            | ValidationViolation::CheckKindMismatch { .. }
            | ValidationViolation::CheckEvidenceCountBelowMinimum { .. }
            | ValidationViolation::DisallowedArtifactEvidence { .. }
            | ValidationViolation::TruncatedArtifactEvidenceDisallowed { .. }
            | ValidationViolation::AttemptExitEvidenceRequirementNotMet { .. }
            | ValidationViolation::CheckHasNoEvidence { .. }
            | ValidationViolation::PrimaryCheckHasNoMechanicalEvidence { .. }
            | ValidationViolation::VisualCheckHasNoVisionEvidence { .. }
            | ValidationViolation::MissingRequiredCheck { .. }
            | ValidationViolation::RequiredCheckDidNotPass { .. }
            | ValidationViolation::InsufficientPrimaryPasses { .. }
    )
}

fn phase_outcome_contradicts_exit(outcome: PhaseOutcome, process_exit: &ProcessExit) -> bool {
    match process_exit {
        ProcessExit::TimedOut => outcome != PhaseOutcome::TimedOut,
        ProcessExit::Cancelled => outcome != PhaseOutcome::Cancelled,
        ProcessExit::LaunchFailed { .. } => {
            matches!(
                outcome,
                PhaseOutcome::Succeeded | PhaseOutcome::NotApplicable
            )
        }
        ProcessExit::Exited { .. } | ProcessExit::Signaled { .. } => matches!(
            outcome,
            PhaseOutcome::TimedOut | PhaseOutcome::Cancelled | PhaseOutcome::NotApplicable
        ),
    }
}

#[allow(clippy::too_many_lines)]
fn validate_environment_snapshot(
    snapshot: &crate::EnvironmentSnapshot,
    bounds: &ExecutionBounds,
    violations: &mut Vec<ValidationViolation>,
) {
    if snapshot.architecture.is_empty() {
        violations.push(ValidationViolation::EnvironmentMetadataEmpty {
            field: EnvironmentMetadataField::Architecture,
        });
    }
    if snapshot.os_version.is_empty() {
        violations.push(ValidationViolation::EnvironmentMetadataEmpty {
            field: EnvironmentMetadataField::OsVersion,
        });
    }
    if snapshot.locale.as_ref().is_some_and(String::is_empty) {
        violations.push(ValidationViolation::EnvironmentMetadataEmpty {
            field: EnvironmentMetadataField::Locale,
        });
    }

    let toolchain_count = u64::try_from(snapshot.toolchain.len()).unwrap_or(u64::MAX);
    if toolchain_count > u64::from(bounds.max_toolchain_entries) {
        violations.push(ValidationViolation::ToolchainEntriesOutOfBounds {
            actual: toolchain_count,
            maximum: bounds.max_toolchain_entries,
        });
    }
    let environment_count = u64::try_from(snapshot.selected_variables.len()).unwrap_or(u64::MAX);
    if environment_count > u64::from(bounds.max_environment_entries) {
        violations.push(ValidationViolation::SnapshotEnvironmentEntriesOutOfBounds {
            actual: environment_count,
            maximum: bounds.max_environment_entries,
        });
    }

    let mut metadata_bytes = u64::try_from(snapshot.architecture.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(snapshot.os_version.len()).unwrap_or(u64::MAX))
        .saturating_add(
            snapshot
                .locale
                .as_ref()
                .map_or(0, |value| u64::try_from(value.len()).unwrap_or(u64::MAX)),
        );
    for (index, tool) in snapshot.toolchain.iter().enumerate() {
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        if tool.version.is_empty() {
            violations.push(ValidationViolation::ToolchainVersionEmpty { index });
        }
        metadata_bytes = metadata_bytes
            .saturating_add(u64::try_from(tool.tool_id.as_str().len()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(tool.version.len()).unwrap_or(u64::MAX));
    }

    let os_encoding = operating_system_encoding(&snapshot.operating_system);
    let mut inferred_other_encoding = None;
    for (index, entry) in snapshot.selected_variables.iter().enumerate() {
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        if entry.name.encoded_bytes() == 0 {
            violations.push(ValidationViolation::EmptySnapshotEnvironmentName { index });
        }
        if entry.name.contains_nul() {
            violations.push(ValidationViolation::EnvironmentValueContainsNul { index });
        }
        if native_name_contains_equals(&entry.name) {
            violations.push(ValidationViolation::SnapshotEnvironmentNameContainsEquals { index });
        }
        if snapshot.selected_variables[..usize::try_from(index).unwrap_or(usize::MAX)]
            .iter()
            .any(|prior| native_environment_names_equal(&prior.name, &entry.name))
        {
            violations.push(ValidationViolation::DuplicateSnapshotEnvironmentName { index });
        }
        let expected = os_encoding.unwrap_or_else(|| {
            *inferred_other_encoding.get_or_insert_with(|| entry.name.encoding())
        });
        if entry.name.encoding() != expected {
            violations.push(ValidationViolation::EnvironmentValueEncodingMismatch {
                index,
                expected,
                actual: entry.name.encoding(),
            });
        }
        metadata_bytes = metadata_bytes
            .saturating_add(u64::try_from(entry.name.encoded_bytes()).unwrap_or(u64::MAX));
        metadata_bytes = metadata_bytes
            .saturating_add(entry.value.resolved_bytes())
            .saturating_add(
                u64::try_from(entry.value.retained_metadata_bytes()).unwrap_or(u64::MAX),
            );
        if entry.value.encoding() != expected {
            violations.push(ValidationViolation::EnvironmentValueEncodingMismatch {
                index,
                expected,
                actual: entry.value.encoding(),
            });
        }
        if let EnvironmentValue::PlainText { value } = &entry.value
            && value.contains_nul()
        {
            violations.push(ValidationViolation::EnvironmentValueContainsNul { index });
        }
    }
    if metadata_bytes > bounds.max_metadata_bytes {
        violations.push(ValidationViolation::EnvironmentMetadataOutOfBounds {
            actual: metadata_bytes,
            maximum: bounds.max_metadata_bytes,
        });
    }
}

fn operating_system_encoding(operating_system: &OperatingSystem) -> Option<NativeEncoding> {
    match operating_system {
        OperatingSystem::Windows => Some(NativeEncoding::WindowsUtf16),
        OperatingSystem::MacOs
        | OperatingSystem::Linux
        | OperatingSystem::Android
        | OperatingSystem::IosSimulator
        | OperatingSystem::IpadOsSimulator
        | OperatingSystem::TvOsSimulator
        | OperatingSystem::WatchOsSimulator
        | OperatingSystem::VisionOsSimulator => Some(NativeEncoding::UnixBytes),
        OperatingSystem::Other { .. } => None,
    }
}

fn target_environment_matches(
    target: &crate::ExecutionTarget,
    environment: &crate::EnvironmentSnapshot,
) -> bool {
    match (target.platform(), &environment.operating_system) {
        (ExecutionPlatform::MacOs { .. }, OperatingSystem::MacOs)
        | (ExecutionPlatform::Windows { .. }, OperatingSystem::Windows)
        | (ExecutionPlatform::Linux { .. }, OperatingSystem::Linux)
        | (ExecutionPlatform::Android { .. }, OperatingSystem::Android) => true,
        (ExecutionPlatform::AppleSimulator { platform, .. }, OperatingSystem::IosSimulator) => {
            *platform == crate::AppleSimulatorPlatform::Ios
        }
        (ExecutionPlatform::AppleSimulator { platform, .. }, OperatingSystem::IpadOsSimulator) => {
            *platform == crate::AppleSimulatorPlatform::IpadOs
        }
        (ExecutionPlatform::AppleSimulator { platform, .. }, OperatingSystem::TvOsSimulator) => {
            *platform == crate::AppleSimulatorPlatform::TvOs
        }
        (ExecutionPlatform::AppleSimulator { platform, .. }, OperatingSystem::WatchOsSimulator) => {
            *platform == crate::AppleSimulatorPlatform::WatchOs
        }
        (
            ExecutionPlatform::AppleSimulator { platform, .. },
            OperatingSystem::VisionOsSimulator,
        ) => *platform == crate::AppleSimulatorPlatform::VisionOs,
        (
            ExecutionPlatform::Other { platform_id, .. },
            OperatingSystem::Other {
                platform_id: environment_platform_id,
            },
        ) => platform_id == environment_platform_id,
        (
            ExecutionPlatform::MacOs { .. }
            | ExecutionPlatform::Windows { .. }
            | ExecutionPlatform::Linux { .. }
            | ExecutionPlatform::AppleSimulator { .. }
            | ExecutionPlatform::Android { .. }
            | ExecutionPlatform::Other { .. },
            _,
        ) => false,
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn append_prefix_resources_are_valid(provenance: &RunProvenance) -> bool {
    let bounds = provenance.bounds();
    if u64::try_from(provenance.records().len()).unwrap_or(u64::MAX) > u64::from(bounds.max_records)
    {
        return false;
    }
    let mut violations = Vec::new();
    if !target_environment_matches(provenance.target(), provenance.environment()) {
        return false;
    }
    validate_environment_snapshot(provenance.environment(), bounds, &mut violations);
    let target_url_bytes = match provenance.target().surface() {
        TargetSurface::WebPlaywright { url } => Some(url.as_str().len()),
        TargetSurface::ApiServer { endpoint } => Some(endpoint.as_str().len()),
        TargetSurface::Cli
        | TargetSurface::Tui
        | TargetSurface::DesktopApplication { .. }
        | TargetSurface::MobileApplication { .. } => None,
    };
    if target_url_bytes
        .is_some_and(|actual| u64::try_from(actual).unwrap_or(u64::MAX) > bounds.max_url_bytes)
    {
        return false;
    }
    let mut starts = BTreeMap::new();
    let mut artifacts = Vec::new();
    let mut check_count = 0_u64;
    let mut total_evidence = 0_u64;
    let mut total_elapsed = 0_u64;
    for record in provenance.records() {
        match &record.event {
            ProvenanceEvent::AttemptStarted {
                attempt_id,
                timeout_ms,
                command,
                ..
            } => {
                starts.insert(*attempt_id, (*timeout_ms, command.is_some()));
                if *timeout_ms == 0 || *timeout_ms > bounds.max_timeout_ms {
                    violations.push(ValidationViolation::TimeoutOutOfBounds {
                        attempt_id: *attempt_id,
                        requested: *timeout_ms,
                        maximum: bounds.max_timeout_ms,
                    });
                }
                if let Some(command) = command {
                    validate_command(
                        *attempt_id,
                        command,
                        bounds,
                        operating_system_encoding(&provenance.environment().operating_system),
                        &mut violations,
                    );
                }
            }
            ProvenanceEvent::AttemptFinished {
                attempt_id,
                outcome,
                process_exit,
                elapsed_ms,
                ..
            } => {
                total_elapsed = total_elapsed.saturating_add(*elapsed_ms);
                if let Some((timeout_ms, has_command)) = starts.get(attempt_id) {
                    if *elapsed_ms > *timeout_ms {
                        violations.push(ValidationViolation::ElapsedTimeOutOfBounds {
                            attempt_id: *attempt_id,
                            actual: *elapsed_ms,
                            maximum: *timeout_ms,
                        });
                    }
                    if *has_command
                        && process_exit.is_none()
                        && !matches!(
                            outcome,
                            PhaseOutcome::PolicyDenied | PhaseOutcome::NotApplicable
                        )
                    {
                        violations.push(ValidationViolation::CommandAttemptMissingProcessExit {
                            attempt_id: *attempt_id,
                        });
                    }
                    if !*has_command && process_exit.is_some() {
                        violations.push(ValidationViolation::UnexpectedProcessExit {
                            attempt_id: *attempt_id,
                        });
                    }
                }
                if let Some(process_exit) = process_exit
                    && phase_outcome_contradicts_exit(*outcome, process_exit)
                {
                    violations.push(ValidationViolation::ContradictoryPhaseOutcome {
                        attempt_id: *attempt_id,
                        outcome: *outcome,
                        process_exit: process_exit.clone(),
                    });
                }
            }
            ProvenanceEvent::ArtifactRecorded { artifact } => {
                validate_artifact(artifact, bounds, &mut violations);
                artifacts.push(artifact);
            }
            ProvenanceEvent::CheckRecorded { check } => {
                check_count = check_count.saturating_add(1);
                let evidence_count = u64::try_from(check.evidence.len()).unwrap_or(u64::MAX);
                total_evidence = total_evidence.saturating_add(evidence_count);
                if evidence_count > u64::from(bounds.max_check_evidence_items) {
                    return false;
                }
            }
        }
    }

    let artifact_count = u64::try_from(artifacts.len()).unwrap_or(u64::MAX);
    let total_bytes = artifacts.iter().fold(0_u64, |sum, artifact| {
        sum.saturating_add(artifact.retained_bytes)
    });
    let screenshots = u64::try_from(
        artifacts
            .iter()
            .filter(|artifact| artifact.kind == ArtifactKind::Screenshot)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let videos = u64::try_from(
        artifacts
            .iter()
            .filter(|artifact| artifact.kind == ArtifactKind::Video)
            .count(),
    )
    .unwrap_or(u64::MAX);
    artifact_count <= u64::from(bounds.max_artifacts)
        && u64::try_from(starts.len()).unwrap_or(u64::MAX) <= u64::from(bounds.max_attempts)
        && check_count <= u64::from(bounds.max_checks)
        && total_evidence <= u64::from(bounds.max_total_evidence_items)
        && total_elapsed <= bounds.max_total_elapsed_ms
        && total_bytes <= bounds.max_total_artifact_bytes
        && screenshots <= u64::from(bounds.max_screenshots)
        && videos <= u64::from(bounds.max_videos)
        && violations.is_empty()
}

fn target_error_code(error: &TargetError) -> &'static str {
    match error {
        TargetError::EmptyTargetId => "empty_target_id",
        TargetError::TargetIdTooLong { .. } => "target_id_too_long",
        TargetError::DuplicateAdapter { .. } => "duplicate_adapter",
        TargetError::AdapterUnavailable { .. } => "adapter_unavailable",
        TargetError::UnsupportedTargetCombination { .. } => "unsupported_target_combination",
        TargetError::CredentialedUrl { .. } => "credentialed_url",
    }
}

#[allow(clippy::too_many_lines)]
fn validate_command(
    attempt_id: AttemptId,
    command: &CommandSpec,
    bounds: &ExecutionBounds,
    required_encoding: Option<NativeEncoding>,
    violations: &mut Vec<ValidationViolation>,
) {
    let executable_encoding = workspace_path_encoding(&command.executable);
    let expected_encoding = required_encoding.unwrap_or(executable_encoding);
    validate_path(
        attempt_id,
        &command.executable,
        CommandComponent::Executable,
        violations,
    );
    for (component, path) in [
        (CommandComponent::Executable, &command.executable),
        (
            CommandComponent::WorkingDirectory,
            &command.working_directory,
        ),
    ] {
        let actual = u64::try_from(workspace_path_bytes(path)).unwrap_or(u64::MAX);
        if actual > bounds.max_path_bytes {
            violations.push(ValidationViolation::PathOutOfBounds {
                attempt_id,
                component,
                actual,
                maximum: bounds.max_path_bytes,
            });
        }
    }
    validate_path(
        attempt_id,
        &command.working_directory,
        CommandComponent::WorkingDirectory,
        violations,
    );
    if executable_encoding != expected_encoding {
        violations.push(ValidationViolation::CommandEncodingMismatch {
            attempt_id,
            component: CommandComponent::Executable,
            expected: expected_encoding,
            actual: executable_encoding,
        });
    }
    let cwd_encoding = workspace_path_encoding(&command.working_directory);
    if cwd_encoding != expected_encoding {
        violations.push(ValidationViolation::CommandEncodingMismatch {
            attempt_id,
            component: CommandComponent::WorkingDirectory,
            expected: expected_encoding,
            actual: cwd_encoding,
        });
    }

    let argv_items = u64::try_from(command.arguments.len()).unwrap_or(u64::MAX);
    if argv_items > u64::from(bounds.max_argv_items) {
        violations.push(ValidationViolation::ArgvItemsOutOfBounds {
            attempt_id,
            actual: argv_items,
            maximum: bounds.max_argv_items,
        });
    }
    let mut argument_bytes = 0_u64;
    for (index, argument) in command.arguments.iter().enumerate() {
        argument_bytes = argument_bytes.saturating_add(argument.resolved_bytes());
        let component = CommandComponent::Argument {
            index: u32::try_from(index).unwrap_or(u32::MAX),
        };
        if argument.encoding() != expected_encoding {
            violations.push(ValidationViolation::CommandEncodingMismatch {
                attempt_id,
                component,
                expected: expected_encoding,
                actual: argument.encoding(),
            });
        }
        if let RetainedArgument::PlainText { value } = argument
            && value.contains_nul()
        {
            violations.push(ValidationViolation::CommandValueContainsNul {
                attempt_id,
                component,
            });
        }
    }
    if argument_bytes > bounds.max_argument_bytes {
        violations.push(ValidationViolation::ArgumentBytesOutOfBounds {
            attempt_id,
            actual: argument_bytes,
            maximum: bounds.max_argument_bytes,
        });
    }

    let environment_entries = u64::try_from(command.environment.len()).unwrap_or(u64::MAX);
    if environment_entries > u64::from(bounds.max_environment_entries) {
        violations.push(ValidationViolation::EnvironmentEntriesOutOfBounds {
            attempt_id,
            actual: environment_entries,
            maximum: bounds.max_environment_entries,
        });
    }
    let mut environment_bytes = 0_u64;
    for (index, entry) in command.environment.iter().enumerate() {
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        let name_bytes = u64::try_from(entry.name.encoded_bytes()).unwrap_or(u64::MAX);
        environment_bytes = environment_bytes.saturating_add(name_bytes);
        if entry.name.encoded_bytes() == 0 {
            violations.push(ValidationViolation::EmptyEnvironmentName { attempt_id, index });
        }
        if native_name_contains_equals(&entry.name) {
            violations
                .push(ValidationViolation::EnvironmentNameContainsEquals { attempt_id, index });
        }
        if name_bytes > u64::try_from(MAX_ENVIRONMENT_NAME_BYTES).unwrap_or(u64::MAX) {
            violations.push(ValidationViolation::EnvironmentBytesOutOfBounds {
                attempt_id,
                actual: name_bytes,
                maximum: u64::try_from(MAX_ENVIRONMENT_NAME_BYTES).unwrap_or(u64::MAX),
            });
        }
        validate_native_value(
            attempt_id,
            &entry.name,
            expected_encoding,
            CommandComponent::EnvironmentName { index },
            violations,
        );
        if command.environment[..usize::try_from(index).unwrap_or(usize::MAX)]
            .iter()
            .any(|prior| native_environment_names_equal(&prior.name, &entry.name))
        {
            violations.push(ValidationViolation::DuplicateEnvironmentName { attempt_id, index });
        }
        environment_bytes = environment_bytes.saturating_add(entry.value.resolved_bytes());
        if entry.value.encoding() != expected_encoding {
            violations.push(ValidationViolation::CommandEncodingMismatch {
                attempt_id,
                component: CommandComponent::EnvironmentValue { index },
                expected: expected_encoding,
                actual: entry.value.encoding(),
            });
        }
        if let EnvironmentValue::PlainText { value } = &entry.value
            && value.contains_nul()
        {
            violations.push(ValidationViolation::CommandValueContainsNul {
                attempt_id,
                component: CommandComponent::EnvironmentValue { index },
            });
        }
    }
    if environment_bytes > bounds.max_environment_bytes {
        violations.push(ValidationViolation::EnvironmentBytesOutOfBounds {
            attempt_id,
            actual: environment_bytes,
            maximum: bounds.max_environment_bytes,
        });
    }

    let stdin_bytes = command
        .stdin
        .as_ref()
        .map_or(0, crate::RetainedStdin::resolved_bytes);
    if stdin_bytes > bounds.max_stdin_bytes {
        violations.push(ValidationViolation::StdinOutOfBounds {
            attempt_id,
            actual: stdin_bytes,
            maximum: bounds.max_stdin_bytes,
        });
    }
    if command.capture.stdout_bytes > bounds.max_stdout_bytes {
        violations.push(ValidationViolation::CaptureOutOfBounds {
            attempt_id,
            stream: ArtifactKind::StdoutLog,
            requested: command.capture.stdout_bytes,
            maximum: bounds.max_stdout_bytes,
        });
    }
    if command.capture.stderr_bytes > bounds.max_stderr_bytes {
        violations.push(ValidationViolation::CaptureOutOfBounds {
            attempt_id,
            stream: ArtifactKind::StderrLog,
            requested: command.capture.stderr_bytes,
            maximum: bounds.max_stderr_bytes,
        });
    }
}

fn workspace_path_encoding(path: &WorkspacePath) -> NativeEncoding {
    if path.unix_bytes().is_some() {
        NativeEncoding::UnixBytes
    } else {
        NativeEncoding::WindowsUtf16
    }
}

fn workspace_path_bytes(path: &WorkspacePath) -> usize {
    path.unix_bytes().map_or_else(
        || {
            path.windows_utf16()
                .map_or(0, |units| units.len().saturating_mul(2))
        },
        <[u8]>::len,
    )
}

fn native_name_contains_equals(value: &NativeArgument) -> bool {
    match value {
        NativeArgument::UnixBytes { bytes } => bytes.contains(&b'='),
        NativeArgument::WindowsUtf16 { code_units } => code_units.contains(&u16::from(b'=')),
    }
}

fn native_environment_names_equal(left: &NativeArgument, right: &NativeArgument) -> bool {
    match (left, right) {
        (NativeArgument::UnixBytes { bytes: left }, NativeArgument::UnixBytes { bytes: right }) => {
            left == right
        }
        (
            NativeArgument::WindowsUtf16 { code_units: left },
            NativeArgument::WindowsUtf16 { code_units: right },
        ) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| ascii_lowercase_u16(*left) == ascii_lowercase_u16(*right))
        }
        (NativeArgument::UnixBytes { .. }, NativeArgument::WindowsUtf16 { .. })
        | (NativeArgument::WindowsUtf16 { .. }, NativeArgument::UnixBytes { .. }) => false,
    }
}

const fn ascii_lowercase_u16(value: u16) -> u16 {
    if value >= 0x41 && value <= 0x5a {
        value + 0x20
    } else {
        value
    }
}

fn validate_path(
    attempt_id: AttemptId,
    path: &WorkspacePath,
    component: CommandComponent,
    violations: &mut Vec<ValidationViolation>,
) {
    let (empty, has_nul) = match (path.unix_bytes(), path.windows_utf16()) {
        (Some(bytes), None) => (bytes.is_empty(), bytes.contains(&0)),
        (None, Some(code_units)) => (code_units.is_empty(), code_units.contains(&0)),
        (Some(_), Some(_)) | (None, None) => (true, true),
    };
    if empty {
        violations.push(ValidationViolation::EmptyCommandPath {
            attempt_id,
            component,
        });
    }
    if has_nul {
        violations.push(ValidationViolation::CommandValueContainsNul {
            attempt_id,
            component,
        });
    }
}

fn validate_native_value(
    attempt_id: AttemptId,
    value: &NativeArgument,
    expected: NativeEncoding,
    component: CommandComponent,
    violations: &mut Vec<ValidationViolation>,
) {
    if value.encoding() != expected {
        violations.push(ValidationViolation::CommandEncodingMismatch {
            attempt_id,
            component,
            expected,
            actual: value.encoding(),
        });
    }
    if value.contains_nul() {
        violations.push(ValidationViolation::CommandValueContainsNul {
            attempt_id,
            component,
        });
    }
}

fn validate_artifact(
    artifact: &ArtifactRecord,
    bounds: &ExecutionBounds,
    violations: &mut Vec<ValidationViolation>,
) {
    if artifact.media_type.is_empty() {
        violations.push(ValidationViolation::EmptyMediaType {
            artifact_id: artifact.artifact_id,
        });
    }
    if artifact.media_type.len() > MAX_MEDIA_TYPE_BYTES {
        violations.push(ValidationViolation::MediaTypeTooLong {
            artifact_id: artifact.artifact_id,
            actual: u64::try_from(artifact.media_type.len()).unwrap_or(u64::MAX),
        });
    }
    let storage_ref_bytes = u64::try_from(artifact.storage_ref.as_str().len()).unwrap_or(u64::MAX);
    if storage_ref_bytes > bounds.max_storage_ref_bytes {
        violations.push(ValidationViolation::StorageRefOutOfBounds {
            artifact_id: artifact.artifact_id,
            actual: storage_ref_bytes,
            maximum: bounds.max_storage_ref_bytes,
        });
    }
    let truncation_is_valid = match (artifact.truncated, artifact.observed_bytes) {
        (true, Some(observed)) => observed > artifact.retained_bytes,
        (false, Some(observed)) => observed == artifact.retained_bytes,
        (false, None) => true,
        (true, None) => false,
    };
    if !truncation_is_valid {
        violations.push(ValidationViolation::InvalidArtifactTruncation {
            artifact_id: artifact.artifact_id,
        });
    }
    if artifact.retained_bytes > bounds.max_artifact_bytes {
        violations.push(ValidationViolation::ArtifactOutOfBounds {
            artifact_id: artifact.artifact_id,
            actual: artifact.retained_bytes,
            maximum: bounds.max_artifact_bytes,
        });
    }
    let kind_maximum = match artifact.kind {
        ArtifactKind::StdoutLog => Some(bounds.max_stdout_bytes),
        ArtifactKind::StderrLog => Some(bounds.max_stderr_bytes),
        ArtifactKind::RuntimeLog => Some(bounds.max_runtime_log_bytes),
        ArtifactKind::Trace => Some(bounds.max_trace_bytes),
        ArtifactKind::CompilerOutput
        | ArtifactKind::TestReport
        | ArtifactKind::AccessibilitySnapshot
        | ArtifactKind::DomSnapshot
        | ArtifactKind::ApiTranscript
        | ArtifactKind::ProcessState
        | ArtifactKind::Screenshot
        | ArtifactKind::Video
        | ArtifactKind::BuildProduct
        | ArtifactKind::Auxiliary => None,
    };
    if let Some(maximum) = kind_maximum
        && artifact.retained_bytes > maximum
    {
        violations.push(ValidationViolation::ArtifactKindOutOfBounds {
            artifact_id: artifact.artifact_id,
            kind: artifact.kind,
            actual: artifact.retained_bytes,
            maximum,
        });
    }
}
