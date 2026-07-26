use crate::compiler::{PromptInvocation, SourceKind, TrustLevel};
use crate::{PromptId, PromptKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const REPOSITORY_EXPLORER_ID: &str = "birdcode.repository-explorer";
const SHA256_HEX_LENGTH: usize = 64;
const MAX_ID_CHARACTERS: usize = 128;
const MAX_SOURCE_ID_CHARACTERS: usize = 512;
const MAX_TOOL_GRANTS: usize = 8;
const MAX_PREVIOUS_OBSERVATIONS: usize = 64;
const MAX_ITERATIONS: u32 = 64;
const MAX_TOOL_REQUESTS: u32 = 64;
const MAX_EVIDENCE_REFERENCES: u32 = 128;
const MAX_HANDOFF_FINDINGS: u32 = 32;
const MAX_HANDOFF_UNKNOWNS: u32 = 32;
const MAX_RECOMMENDED_FOLLOWUPS: u32 = 16;
const MAX_PATH_CHARACTERS: u32 = 4_096;
const MAX_TREE_DEPTH: u32 = 32;
const MAX_TREE_ENTRIES: u32 = 20_000;
const MAX_FILE_OFFSET_BYTES: u64 = 1 << 50;
const MAX_RESULT_BYTES: u32 = 4 * 1_024 * 1_024;
const MAX_QUERY_CHARACTERS: u32 = 4_096;
const MAX_SEARCH_DEPTH: u32 = 32;
const MAX_SEARCH_FILES: u32 = 20_000;
const MAX_SEARCH_MATCHES: u32 = 20_000;
const MAX_SEARCH_BYTES_PER_FILE: u64 = 256 * 1_024 * 1_024;
const MAX_SEARCH_TOTAL_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
const MAX_RATIONALE_CHARACTERS: usize = 4_000;
const MAX_SUMMARY_CHARACTERS: usize = 8_000;
const MAX_FINDING_CHARACTERS: usize = 8_000;
const MAX_UNKNOWN_CHARACTERS: usize = 4_000;
const MAX_FOLLOWUP_CHARACTERS: usize = 4_000;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The only authority represented by the v1 repository-explorer contract.
///
/// This is a binding copied from runtime policy, not authority granted by the
/// model. The broker still resolves paths, checks the repository snapshot,
/// issues call identities, executes tools, and charges budgets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplorerAuthority {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplorerToolKind {
    RepositoryTree,
    RepositoryFileRead,
    RepositoryLiteralSearch,
}

/// One broker-created read-only grant visible to the model.
///
/// Each variant has only the parameters meaningful to that tool. Tree and
/// literal search remain explicit capabilities; callers must never silently
/// replace either with a weaker operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExplorerToolGrant {
    RepositoryTree {
        tool_grant_id: String,
        max_path_characters: u32,
        max_depth: u32,
        max_entries: u32,
    },
    RepositoryFileRead {
        tool_grant_id: String,
        max_path_characters: u32,
        max_offset_bytes: u64,
        max_bytes: u32,
    },
    RepositoryLiteralSearch {
        tool_grant_id: String,
        max_path_characters: u32,
        max_query_characters: u32,
        max_depth: u32,
        max_files: u32,
        max_matches: u32,
        max_bytes_per_file: u64,
        max_total_bytes: u64,
    },
}

impl ExplorerToolGrant {
    #[must_use]
    pub fn tool_grant_id(&self) -> &str {
        match self {
            Self::RepositoryTree { tool_grant_id, .. }
            | Self::RepositoryFileRead { tool_grant_id, .. }
            | Self::RepositoryLiteralSearch { tool_grant_id, .. } => tool_grant_id,
        }
    }

    #[must_use]
    pub const fn tool_kind(&self) -> ExplorerToolKind {
        match self {
            Self::RepositoryTree { .. } => ExplorerToolKind::RepositoryTree,
            Self::RepositoryFileRead { .. } => ExplorerToolKind::RepositoryFileRead,
            Self::RepositoryLiteralSearch { .. } => ExplorerToolKind::RepositoryLiteralSearch,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerArtifactBinding {
    pub artifact_id: String,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExplorerBudget {
    pub budget_id: String,
    pub current_iteration: u32,
    pub max_iterations: u32,
    pub tool_requests_used: u32,
    pub max_tool_requests: u32,
    pub max_previous_observations: u32,
    pub max_evidence_references: u32,
    pub max_handoff_findings: u32,
    pub max_handoff_unknowns: u32,
    pub max_recommended_followups: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerObservationBinding {
    pub observation_id: String,
    pub tool_call_id: String,
    pub tool_grant_id: String,
    pub tool_kind: ExplorerToolKind,
    pub artifact_sha256: String,
}

/// One untrusted tool observation supplied in the dedicated tool section.
///
/// `result` may contain arbitrary repository or tool text. Its binding is
/// checked against runtime-owned policy before the model output is accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExplorerObservation {
    pub binding: ExplorerObservationBinding,
    pub result: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExplorerObservationData {
    pub observations: Vec<RepositoryExplorerObservation>,
}

/// Runtime-owned policy material before its three collection digests and
/// policy self-digest are derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryExplorerPolicyMaterial {
    pub run_id: String,
    pub actor_id: String,
    pub turn_id: String,
    pub root_snapshot_sha256: String,
    pub goal: ExplorerArtifactBinding,
    pub work_order: ExplorerArtifactBinding,
    pub context: ExplorerArtifactBinding,
    pub tool_catalog_id: String,
    pub tool_grants: Vec<ExplorerToolGrant>,
    pub budget: RepositoryExplorerBudget,
    pub observation_manifest_id: String,
    pub previous_observations: Vec<ExplorerObservationBinding>,
    pub model_lineage_id: String,
    pub model_attempt_id: String,
}

/// Exact runtime authority for one iterative repository-explorer turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExplorerPolicy {
    pub authority: ExplorerAuthority,
    pub run_id: String,
    pub actor_id: String,
    pub turn_id: String,
    pub root_snapshot_sha256: String,
    pub goal: ExplorerArtifactBinding,
    pub work_order: ExplorerArtifactBinding,
    pub context: ExplorerArtifactBinding,
    pub tool_catalog_id: String,
    pub tool_catalog_sha256: String,
    pub tool_grants: Vec<ExplorerToolGrant>,
    pub budget: RepositoryExplorerBudget,
    pub budget_sha256: String,
    pub observation_manifest_id: String,
    pub observation_manifest_sha256: String,
    pub previous_observations: Vec<ExplorerObservationBinding>,
    pub model_lineage_id: String,
    pub model_attempt_id: String,
    pub explorer_policy_sha256: String,
}

#[derive(Serialize)]
struct ToolCatalogHashMaterial<'a> {
    tool_catalog_id: &'a str,
    tool_grants: &'a [ExplorerToolGrant],
}

#[derive(Serialize)]
struct ObservationManifestHashMaterial<'a> {
    observation_manifest_id: &'a str,
    previous_observations: &'a [ExplorerObservationBinding],
}

#[derive(Serialize)]
struct RepositoryExplorerPolicyHashMaterial<'a> {
    authority: ExplorerAuthority,
    run_id: &'a str,
    actor_id: &'a str,
    turn_id: &'a str,
    root_snapshot_sha256: &'a str,
    goal: &'a ExplorerArtifactBinding,
    work_order: &'a ExplorerArtifactBinding,
    context: &'a ExplorerArtifactBinding,
    tool_catalog_id: &'a str,
    tool_catalog_sha256: &'a str,
    tool_grants: &'a [ExplorerToolGrant],
    budget: &'a RepositoryExplorerBudget,
    budget_sha256: &'a str,
    observation_manifest_id: &'a str,
    observation_manifest_sha256: &'a str,
    previous_observations: &'a [ExplorerObservationBinding],
    model_lineage_id: &'a str,
    model_attempt_id: &'a str,
}

impl RepositoryExplorerPolicy {
    /// Constructs one read-only policy and derives every collection digest.
    ///
    /// # Errors
    ///
    /// Returns every mechanical identifier, digest, grant, budget, and
    /// observation defect. No natural-language text is interpreted.
    pub fn new(
        material: RepositoryExplorerPolicyMaterial,
    ) -> Result<Self, Vec<RepositoryExplorerPolicyViolation>> {
        let mut policy = Self {
            authority: ExplorerAuthority::ReadOnly,
            run_id: material.run_id,
            actor_id: material.actor_id,
            turn_id: material.turn_id,
            root_snapshot_sha256: material.root_snapshot_sha256,
            goal: material.goal,
            work_order: material.work_order,
            context: material.context,
            tool_catalog_id: material.tool_catalog_id,
            tool_catalog_sha256: String::new(),
            tool_grants: material.tool_grants,
            budget: material.budget,
            budget_sha256: String::new(),
            observation_manifest_id: material.observation_manifest_id,
            observation_manifest_sha256: String::new(),
            previous_observations: material.previous_observations,
            model_lineage_id: material.model_lineage_id,
            model_attempt_id: material.model_attempt_id,
            explorer_policy_sha256: String::new(),
        };
        let violations = policy_structure_violations(&policy);
        if !violations.is_empty() {
            return Err(violations);
        }
        policy.tool_catalog_sha256 = tool_catalog_sha256(&policy).map_err(canonical_violation)?;
        policy.budget_sha256 = canonical_sha256(&policy.budget).map_err(canonical_violation)?;
        policy.observation_manifest_sha256 =
            observation_manifest_sha256(&policy).map_err(canonical_violation)?;
        policy.explorer_policy_sha256 =
            policy_content_sha256(&policy).map_err(canonical_violation)?;
        Ok(policy)
    }

    #[must_use]
    pub fn bindings(&self) -> RepositoryExplorerBindings {
        RepositoryExplorerBindings {
            authority: self.authority,
            run_id: self.run_id.clone(),
            actor_id: self.actor_id.clone(),
            turn_id: self.turn_id.clone(),
            root_snapshot_sha256: self.root_snapshot_sha256.clone(),
            goal: self.goal.clone(),
            work_order: self.work_order.clone(),
            context: self.context.clone(),
            tool_catalog_id: self.tool_catalog_id.clone(),
            tool_catalog_sha256: self.tool_catalog_sha256.clone(),
            budget_id: self.budget.budget_id.clone(),
            budget_sha256: self.budget_sha256.clone(),
            observation_manifest_id: self.observation_manifest_id.clone(),
            observation_manifest_sha256: self.observation_manifest_sha256.clone(),
            model_lineage_id: self.model_lineage_id.clone(),
            model_attempt_id: self.model_attempt_id.clone(),
            explorer_policy_sha256: self.explorer_policy_sha256.clone(),
        }
    }

    /// Verifies all derived digests and closed v1 caps after deserialization.
    ///
    /// # Errors
    ///
    /// Returns every mechanical policy defect.
    pub fn validate_integrity(&self) -> Result<(), Vec<RepositoryExplorerPolicyViolation>> {
        let violations = policy_integrity_violations(self);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExplorerBindings {
    pub authority: ExplorerAuthority,
    pub run_id: String,
    pub actor_id: String,
    pub turn_id: String,
    pub root_snapshot_sha256: String,
    pub goal: ExplorerArtifactBinding,
    pub work_order: ExplorerArtifactBinding,
    pub context: ExplorerArtifactBinding,
    pub tool_catalog_id: String,
    pub tool_catalog_sha256: String,
    pub budget_id: String,
    pub budget_sha256: String,
    pub observation_manifest_id: String,
    pub observation_manifest_sha256: String,
    pub model_lineage_id: String,
    pub model_attempt_id: String,
    pub explorer_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerEvidenceRef {
    pub observation_id: String,
    pub artifact_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplorerHandoffStatus {
    Complete,
    Partial,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerFinding {
    pub finding_id: String,
    pub statement: String,
    pub evidence_refs: Vec<ExplorerEvidenceRef>,
}

/// Final bounded handoff produced by the same iterative explorer contract.
///
/// Every asserted finding must cite at least one exact retained observation.
/// Evidence-free uncertainty belongs in `unknowns`, never in `findings`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExplorerHandoff {
    pub status: ExplorerHandoffStatus,
    pub summary: String,
    pub findings: Vec<ExplorerFinding>,
    pub unknowns: Vec<String>,
    pub recommended_followups: Vec<String>,
}

/// Exactly one model-authored semantic choice for the next explorer step.
///
/// A request is not a tool call or permission. The broker independently
/// checks the selected grant and every bound before executing anything.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RepositoryExplorerNextAction {
    RequestTree {
        tool_grant_id: String,
        path: String,
        max_depth: u32,
        max_entries: u32,
    },
    RequestFileRead {
        tool_grant_id: String,
        path: String,
        offset_bytes: u64,
        max_bytes: u32,
    },
    RequestLiteralSearch {
        tool_grant_id: String,
        root: String,
        query: String,
        max_depth: u32,
        max_files: u32,
        max_matches: u32,
        max_bytes_per_file: u64,
        max_total_bytes: u64,
    },
    Finish {
        handoff: RepositoryExplorerHandoff,
    },
}

impl RepositoryExplorerNextAction {
    const fn tool_kind(&self) -> Option<ExplorerToolKind> {
        match self {
            Self::RequestTree { .. } => Some(ExplorerToolKind::RepositoryTree),
            Self::RequestFileRead { .. } => Some(ExplorerToolKind::RepositoryFileRead),
            Self::RequestLiteralSearch { .. } => Some(ExplorerToolKind::RepositoryLiteralSearch),
            Self::Finish { .. } => None,
        }
    }

    fn tool_grant_id(&self) -> Option<&str> {
        match self {
            Self::RequestTree { tool_grant_id, .. }
            | Self::RequestFileRead { tool_grant_id, .. }
            | Self::RequestLiteralSearch { tool_grant_id, .. } => Some(tool_grant_id),
            Self::Finish { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExplorerOutput {
    pub schema_version: u32,
    pub bindings: RepositoryExplorerBindings,
    pub rationale: String,
    pub decision_evidence: Vec<ExplorerEvidenceRef>,
    pub next_action: RepositoryExplorerNextAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryExplorerPolicyViolation {
    EmptyIdentifier {
        field: String,
    },
    IdentifierTooLong {
        field: String,
        maximum: u32,
        actual: u32,
    },
    InvalidDigest {
        field: String,
        actual: String,
    },
    ToolGrantCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    DuplicateToolGrantId {
        tool_grant_id: String,
    },
    ToolGrantLimitOutOfRange {
        tool_grant_id: String,
        field: String,
        minimum: u64,
        maximum: u64,
        actual: u64,
    },
    BudgetLimitOutOfRange {
        field: String,
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
    BudgetProgressOutOfRange {
        field: String,
        maximum: u32,
        actual: u32,
    },
    PreviousObservationCount {
        maximum: u32,
        actual: u32,
    },
    DuplicateObservationId {
        observation_id: String,
    },
    DuplicateToolCallId {
        tool_call_id: String,
    },
    UnknownObservationToolGrant {
        observation_id: String,
        tool_grant_id: String,
    },
    ObservationToolKindMismatch {
        observation_id: String,
        expected: ExplorerToolKind,
        actual: ExplorerToolKind,
    },
    DerivedDigestMismatch {
        field: String,
        expected: String,
        actual: String,
    },
    CanonicalEncoding {
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplorerBindingField {
    Authority,
    RunId,
    ActorId,
    TurnId,
    RootSnapshotSha256,
    GoalId,
    GoalSha256,
    WorkOrderId,
    WorkOrderSha256,
    ContextId,
    ContextSha256,
    ToolCatalogId,
    ToolCatalogSha256,
    BudgetId,
    BudgetSha256,
    ObservationManifestId,
    ObservationManifestSha256,
    ModelLineageId,
    ModelAttemptId,
    ExplorerPolicySha256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryExplorerInvariantViolation {
    TypedOutputDecode {
        message: String,
    },
    ExplorerPolicyConstraintCount {
        actual: u32,
    },
    ExplorerPolicyConstraintName {
        actual: String,
    },
    ExplorerPolicyDecode {
        message: String,
    },
    ExplorerPolicyIntegrity {
        violation: RepositoryExplorerPolicyViolation,
    },
    PromptSubtaskLimit {
        expected: u32,
        actual: u32,
    },
    InputSectionCount {
        expected: u32,
        actual: u32,
    },
    MissingInputSection {
        section: String,
    },
    DuplicateInputSection {
        section: String,
        occurrences: u32,
    },
    InputSectionTrustMismatch {
        section: String,
        expected: TrustLevel,
        actual: TrustLevel,
    },
    InputSectionSourceKindMismatch {
        section: String,
        expected: SourceKind,
        actual: SourceKind,
    },
    InputSectionSourceIdMismatch {
        section: String,
        expected: String,
        actual: String,
    },
    InputSectionArtifactMismatch {
        section: String,
        expected: String,
        actual: Option<String>,
    },
    ObservationPayloadDecode {
        message: String,
    },
    ObservationPayloadBindingsMismatch,
    SchemaVersion {
        expected: u32,
        actual: u32,
    },
    BindingMismatch {
        field: ExplorerBindingField,
        expected: String,
        actual: String,
    },
    EmptyText {
        field: String,
    },
    TextTooLong {
        field: String,
        maximum: u32,
        actual: u32,
    },
    LoopCeilingRequiresFinish {
        current_iteration: u32,
        max_iterations: u32,
    },
    ToolRequestBudgetExhausted {
        used: u32,
        maximum: u32,
    },
    UnknownToolGrant {
        tool_grant_id: String,
    },
    ToolGrantKindMismatch {
        tool_grant_id: String,
        expected: ExplorerToolKind,
        actual: ExplorerToolKind,
    },
    RequestedLimitOutOfRange {
        field: String,
        minimum: u64,
        maximum: u64,
        actual: u64,
    },
    EvidenceReferenceCount {
        maximum: u32,
        actual: u32,
    },
    EmptyFindingEvidence {
        finding_id: String,
    },
    DuplicateEvidenceReference {
        site: String,
        observation_id: String,
        artifact_sha256: String,
    },
    UnknownEvidenceObservation {
        site: String,
        observation_id: String,
    },
    EvidenceDigestMismatch {
        site: String,
        observation_id: String,
        expected: String,
        actual: String,
    },
    HandoffCollectionLimit {
        field: String,
        maximum: u32,
        actual: u32,
    },
    DuplicateFindingId {
        finding_id: String,
    },
}

/// Returns the stable key for the first iterative repository-explorer prompt.
///
/// # Panics
///
/// Panics only if the compile-time prompt identifier is invalid.
#[must_use]
pub fn repository_explorer_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(REPOSITORY_EXPLORER_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 0, 0),
    )
}

pub(crate) fn is_repository_explorer_key(key: &PromptKey) -> bool {
    key == &repository_explorer_key()
}

/// Validates one schema-checked model turn against independent runtime state.
///
/// The validator enforces only exact bindings, typed read-only grants,
/// cardinality, bounds, observation membership, evidence membership, and the
/// loop ceiling. It never infers semantics from natural-language text,
/// filenames, extensions, model names, regular expressions, or keywords.
///
/// # Errors
///
/// Returns every detected mechanical contract violation.
pub fn validate_repository_explorer_output(
    value: &Value,
    invocation: &PromptInvocation,
) -> Result<(), Vec<RepositoryExplorerInvariantViolation>> {
    let output =
        serde_json::from_value::<RepositoryExplorerOutput>(value.clone()).map_err(|error| {
            vec![RepositoryExplorerInvariantViolation::TypedOutputDecode {
                message: error.to_string(),
            }]
        })?;
    let policy = extract_policy(invocation)?;
    let mut violations = invocation_violations(invocation, &policy);
    violations.extend(output_violations(&output, &policy));
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn extract_policy(
    invocation: &PromptInvocation,
) -> Result<RepositoryExplorerPolicy, Vec<RepositoryExplorerInvariantViolation>> {
    if invocation.runtime_constraints.len() != 1 {
        return Err(vec![
            RepositoryExplorerInvariantViolation::ExplorerPolicyConstraintCount {
                actual: wire_u32(invocation.runtime_constraints.len()),
            },
        ]);
    }
    let constraint = &invocation.runtime_constraints[0];
    if constraint.name != "repository_explorer_policy" {
        return Err(vec![
            RepositoryExplorerInvariantViolation::ExplorerPolicyConstraintName {
                actual: constraint.name.clone(),
            },
        ]);
    }
    let policy = serde_json::from_value::<RepositoryExplorerPolicy>(constraint.payload.clone())
        .map_err(|error| {
            vec![RepositoryExplorerInvariantViolation::ExplorerPolicyDecode {
                message: error.to_string(),
            }]
        })?;
    let policy_violations = policy_integrity_violations(&policy);
    if policy_violations.is_empty() {
        Ok(policy)
    } else {
        Err(policy_violations
            .into_iter()
            .map(
                |violation| RepositoryExplorerInvariantViolation::ExplorerPolicyIntegrity {
                    violation,
                },
            )
            .collect())
    }
}

fn invocation_violations(
    invocation: &PromptInvocation,
    policy: &RepositoryExplorerPolicy,
) -> Vec<RepositoryExplorerInvariantViolation> {
    let mut violations = Vec::new();
    if invocation.limits.max_suggested_subtasks != 0 {
        violations.push(RepositoryExplorerInvariantViolation::PromptSubtaskLimit {
            expected: 0,
            actual: invocation.limits.max_suggested_subtasks,
        });
    }
    if invocation.sections.len() != 4 {
        violations.push(RepositoryExplorerInvariantViolation::InputSectionCount {
            expected: 4,
            actual: wire_u32(invocation.sections.len()),
        });
    }
    validate_section(
        invocation,
        "goal",
        TrustLevel::User,
        SourceKind::User,
        &policy.goal,
        &mut violations,
    );
    validate_section(
        invocation,
        "work_order",
        TrustLevel::UntrustedExternal,
        SourceKind::External,
        &policy.work_order,
        &mut violations,
    );
    validate_section(
        invocation,
        "repository_context",
        TrustLevel::Repository,
        SourceKind::Repository,
        &policy.context,
        &mut violations,
    );
    let observation_artifact = ExplorerArtifactBinding {
        artifact_id: policy.observation_manifest_id.clone(),
        artifact_sha256: policy.observation_manifest_sha256.clone(),
    };
    validate_section(
        invocation,
        "previous_observations",
        TrustLevel::Tool,
        SourceKind::Tool,
        &observation_artifact,
        &mut violations,
    );

    if let Some(section) = invocation
        .sections
        .iter()
        .find(|section| section.name == "previous_observations")
    {
        match serde_json::from_value::<RepositoryExplorerObservationData>(section.payload.clone()) {
            Ok(data) => {
                let actual = data
                    .observations
                    .into_iter()
                    .map(|observation| observation.binding)
                    .collect::<Vec<_>>();
                if actual != policy.previous_observations {
                    violations.push(
                        RepositoryExplorerInvariantViolation::ObservationPayloadBindingsMismatch,
                    );
                }
            }
            Err(error) => violations.push(
                RepositoryExplorerInvariantViolation::ObservationPayloadDecode {
                    message: error.to_string(),
                },
            ),
        }
    }
    violations
}

fn validate_section(
    invocation: &PromptInvocation,
    name: &str,
    expected_trust: TrustLevel,
    expected_source_kind: SourceKind,
    binding: &ExplorerArtifactBinding,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    let matches = invocation
        .sections
        .iter()
        .filter(|section| section.name == name)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        violations.push(RepositoryExplorerInvariantViolation::MissingInputSection {
            section: name.to_owned(),
        });
        return;
    }
    if matches.len() > 1 {
        violations.push(
            RepositoryExplorerInvariantViolation::DuplicateInputSection {
                section: name.to_owned(),
                occurrences: wire_u32(matches.len()),
            },
        );
    }
    let section = matches[0];
    if section.trust != expected_trust {
        violations.push(
            RepositoryExplorerInvariantViolation::InputSectionTrustMismatch {
                section: name.to_owned(),
                expected: expected_trust,
                actual: section.trust,
            },
        );
    }
    if section.provenance.source_kind != expected_source_kind {
        violations.push(
            RepositoryExplorerInvariantViolation::InputSectionSourceKindMismatch {
                section: name.to_owned(),
                expected: expected_source_kind,
                actual: section.provenance.source_kind,
            },
        );
    }
    if section.provenance.source_id != binding.artifact_id {
        violations.push(
            RepositoryExplorerInvariantViolation::InputSectionSourceIdMismatch {
                section: name.to_owned(),
                expected: binding.artifact_id.clone(),
                actual: section.provenance.source_id.clone(),
            },
        );
    }
    if section.provenance.artifact_sha256.as_deref() != Some(&binding.artifact_sha256) {
        violations.push(
            RepositoryExplorerInvariantViolation::InputSectionArtifactMismatch {
                section: name.to_owned(),
                expected: binding.artifact_sha256.clone(),
                actual: section.provenance.artifact_sha256.clone(),
            },
        );
    }
}

fn output_violations(
    output: &RepositoryExplorerOutput,
    policy: &RepositoryExplorerPolicy,
) -> Vec<RepositoryExplorerInvariantViolation> {
    let mut violations = Vec::new();
    if output.schema_version != 1 {
        violations.push(RepositoryExplorerInvariantViolation::SchemaVersion {
            expected: 1,
            actual: output.schema_version,
        });
    }
    binding_violations(&output.bindings, &policy.bindings(), &mut violations);
    validate_text(
        "rationale",
        &output.rationale,
        MAX_RATIONALE_CHARACTERS,
        &mut violations,
    );

    let is_request = output.next_action.tool_kind().is_some();
    if is_request && policy.budget.current_iteration >= policy.budget.max_iterations {
        violations.push(
            RepositoryExplorerInvariantViolation::LoopCeilingRequiresFinish {
                current_iteration: policy.budget.current_iteration,
                max_iterations: policy.budget.max_iterations,
            },
        );
    }
    if is_request && policy.budget.tool_requests_used >= policy.budget.max_tool_requests {
        violations.push(
            RepositoryExplorerInvariantViolation::ToolRequestBudgetExhausted {
                used: policy.budget.tool_requests_used,
                maximum: policy.budget.max_tool_requests,
            },
        );
    }

    validate_action(&output.next_action, policy, &mut violations);
    validate_evidence_refs(
        "decision_evidence",
        &output.decision_evidence,
        policy,
        &mut violations,
    );
    let mut evidence_count = output.decision_evidence.len();
    if let RepositoryExplorerNextAction::Finish { handoff } = &output.next_action {
        validate_handoff(handoff, policy, &mut evidence_count, &mut violations);
    }
    if evidence_count > policy.budget.max_evidence_references as usize {
        violations.push(
            RepositoryExplorerInvariantViolation::EvidenceReferenceCount {
                maximum: policy.budget.max_evidence_references,
                actual: wire_u32(evidence_count),
            },
        );
    }
    violations
}

fn binding_violations(
    actual: &RepositoryExplorerBindings,
    expected: &RepositoryExplorerBindings,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    compare_binding(
        ExplorerBindingField::Authority,
        authority_wire(expected.authority),
        authority_wire(actual.authority),
        violations,
    );
    compare_binding(
        ExplorerBindingField::RunId,
        &expected.run_id,
        &actual.run_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ActorId,
        &expected.actor_id,
        &actual.actor_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::TurnId,
        &expected.turn_id,
        &actual.turn_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::RootSnapshotSha256,
        &expected.root_snapshot_sha256,
        &actual.root_snapshot_sha256,
        violations,
    );
    artifact_binding_violations(actual, expected, violations);
    runtime_binding_violations(actual, expected, violations);
}

fn artifact_binding_violations(
    actual: &RepositoryExplorerBindings,
    expected: &RepositoryExplorerBindings,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    compare_binding(
        ExplorerBindingField::GoalId,
        &expected.goal.artifact_id,
        &actual.goal.artifact_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::GoalSha256,
        &expected.goal.artifact_sha256,
        &actual.goal.artifact_sha256,
        violations,
    );
    compare_binding(
        ExplorerBindingField::WorkOrderId,
        &expected.work_order.artifact_id,
        &actual.work_order.artifact_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::WorkOrderSha256,
        &expected.work_order.artifact_sha256,
        &actual.work_order.artifact_sha256,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ContextId,
        &expected.context.artifact_id,
        &actual.context.artifact_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ContextSha256,
        &expected.context.artifact_sha256,
        &actual.context.artifact_sha256,
        violations,
    );
}

fn runtime_binding_violations(
    actual: &RepositoryExplorerBindings,
    expected: &RepositoryExplorerBindings,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    compare_binding(
        ExplorerBindingField::ToolCatalogId,
        &expected.tool_catalog_id,
        &actual.tool_catalog_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ToolCatalogSha256,
        &expected.tool_catalog_sha256,
        &actual.tool_catalog_sha256,
        violations,
    );
    compare_binding(
        ExplorerBindingField::BudgetId,
        &expected.budget_id,
        &actual.budget_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::BudgetSha256,
        &expected.budget_sha256,
        &actual.budget_sha256,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ObservationManifestId,
        &expected.observation_manifest_id,
        &actual.observation_manifest_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ObservationManifestSha256,
        &expected.observation_manifest_sha256,
        &actual.observation_manifest_sha256,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ModelLineageId,
        &expected.model_lineage_id,
        &actual.model_lineage_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ModelAttemptId,
        &expected.model_attempt_id,
        &actual.model_attempt_id,
        violations,
    );
    compare_binding(
        ExplorerBindingField::ExplorerPolicySha256,
        &expected.explorer_policy_sha256,
        &actual.explorer_policy_sha256,
        violations,
    );
}

fn compare_binding(
    field: ExplorerBindingField,
    expected: &str,
    actual: &str,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    if expected != actual {
        violations.push(RepositoryExplorerInvariantViolation::BindingMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
}

fn authority_wire(authority: ExplorerAuthority) -> &'static str {
    match authority {
        ExplorerAuthority::ReadOnly => "read_only",
    }
}

fn validate_action(
    action: &RepositoryExplorerNextAction,
    policy: &RepositoryExplorerPolicy,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    let Some(grant) = matching_action_grant(action, policy, violations) else {
        return;
    };
    match (action, grant) {
        (
            RepositoryExplorerNextAction::RequestTree {
                path,
                max_depth,
                max_entries,
                ..
            },
            ExplorerToolGrant::RepositoryTree {
                max_path_characters,
                max_depth: granted_depth,
                max_entries: granted_entries,
                ..
            },
        ) => validate_tree_request(
            path,
            *max_depth,
            *max_entries,
            *max_path_characters,
            *granted_depth,
            *granted_entries,
            violations,
        ),
        (
            RepositoryExplorerNextAction::RequestFileRead {
                path,
                offset_bytes,
                max_bytes,
                ..
            },
            ExplorerToolGrant::RepositoryFileRead {
                max_path_characters,
                max_offset_bytes,
                max_bytes: granted_bytes,
                ..
            },
        ) => validate_file_read_request(
            path,
            *offset_bytes,
            *max_bytes,
            *max_path_characters,
            *max_offset_bytes,
            *granted_bytes,
            violations,
        ),
        (
            RepositoryExplorerNextAction::RequestLiteralSearch {
                root,
                query,
                max_depth,
                max_files,
                max_matches,
                max_bytes_per_file,
                max_total_bytes,
                ..
            },
            ExplorerToolGrant::RepositoryLiteralSearch {
                max_path_characters,
                max_query_characters,
                max_depth: granted_depth,
                max_files: granted_files,
                max_matches: granted_matches,
                max_bytes_per_file: granted_bytes_per_file,
                max_total_bytes: granted_total_bytes,
                ..
            },
        ) => validate_literal_search_request(
            root,
            query,
            *max_depth,
            *max_files,
            *max_matches,
            *max_bytes_per_file,
            *max_total_bytes,
            *max_path_characters,
            *max_query_characters,
            *granted_depth,
            *granted_files,
            *granted_matches,
            *granted_bytes_per_file,
            *granted_total_bytes,
            violations,
        ),
        _ => unreachable!("matching tool kinds have matching typed variants"),
    }
}

fn matching_action_grant<'a>(
    action: &RepositoryExplorerNextAction,
    policy: &'a RepositoryExplorerPolicy,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) -> Option<&'a ExplorerToolGrant> {
    let tool_grant_id = action.tool_grant_id()?;
    let Some(grant) = policy
        .tool_grants
        .iter()
        .find(|grant| grant.tool_grant_id() == tool_grant_id)
    else {
        violations.push(RepositoryExplorerInvariantViolation::UnknownToolGrant {
            tool_grant_id: tool_grant_id.to_owned(),
        });
        return None;
    };
    let expected_kind = grant.tool_kind();
    let actual_kind = action
        .tool_kind()
        .expect("tool grant IDs exist only on request variants");
    if expected_kind == actual_kind {
        Some(grant)
    } else {
        violations.push(
            RepositoryExplorerInvariantViolation::ToolGrantKindMismatch {
                tool_grant_id: tool_grant_id.to_owned(),
                expected: expected_kind,
                actual: actual_kind,
            },
        );
        None
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments mirror the request values and exact selected tree grant"
)]
fn validate_tree_request(
    path: &str,
    max_depth: u32,
    max_entries: u32,
    max_path_characters: u32,
    granted_depth: u32,
    granted_entries: u32,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    validate_bounded_text("next_action.path", path, max_path_characters, violations);
    validate_requested_u32(
        "next_action.max_depth",
        max_depth,
        0,
        granted_depth,
        violations,
    );
    validate_requested_u32(
        "next_action.max_entries",
        max_entries,
        1,
        granted_entries,
        violations,
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments mirror the request values and exact selected file-read grant"
)]
fn validate_file_read_request(
    path: &str,
    offset_bytes: u64,
    max_bytes: u32,
    max_path_characters: u32,
    max_offset_bytes: u64,
    granted_bytes: u32,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    validate_bounded_text("next_action.path", path, max_path_characters, violations);
    validate_requested_u64(
        "next_action.offset_bytes",
        offset_bytes,
        0,
        max_offset_bytes,
        violations,
    );
    validate_requested_u32(
        "next_action.max_bytes",
        max_bytes,
        1,
        granted_bytes,
        violations,
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments mirror the request values and exact selected literal-search grant"
)]
fn validate_literal_search_request(
    root: &str,
    query: &str,
    max_depth: u32,
    max_files: u32,
    max_matches: u32,
    max_bytes_per_file: u64,
    max_total_bytes: u64,
    max_path_characters: u32,
    max_query_characters: u32,
    granted_depth: u32,
    granted_files: u32,
    granted_matches: u32,
    granted_bytes_per_file: u64,
    granted_total_bytes: u64,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    validate_bounded_text("next_action.root", root, max_path_characters, violations);
    validate_bounded_text("next_action.query", query, max_query_characters, violations);
    validate_requested_u32(
        "next_action.max_depth",
        max_depth,
        0,
        granted_depth,
        violations,
    );
    validate_requested_u32(
        "next_action.max_files",
        max_files,
        1,
        granted_files,
        violations,
    );
    validate_requested_u32(
        "next_action.max_matches",
        max_matches,
        1,
        granted_matches,
        violations,
    );
    validate_requested_u64(
        "next_action.max_bytes_per_file",
        max_bytes_per_file,
        1,
        granted_bytes_per_file,
        violations,
    );
    validate_requested_u64(
        "next_action.max_total_bytes",
        max_total_bytes,
        1,
        granted_total_bytes,
        violations,
    );
}

fn validate_handoff(
    handoff: &RepositoryExplorerHandoff,
    policy: &RepositoryExplorerPolicy,
    evidence_count: &mut usize,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    validate_text(
        "next_action.handoff.summary",
        &handoff.summary,
        MAX_SUMMARY_CHARACTERS,
        violations,
    );
    validate_collection_limit(
        "findings",
        handoff.findings.len(),
        policy.budget.max_handoff_findings,
        violations,
    );
    validate_collection_limit(
        "unknowns",
        handoff.unknowns.len(),
        policy.budget.max_handoff_unknowns,
        violations,
    );
    validate_collection_limit(
        "recommended_followups",
        handoff.recommended_followups.len(),
        policy.budget.max_recommended_followups,
        violations,
    );
    let mut finding_ids = BTreeSet::new();
    for (index, finding) in handoff.findings.iter().enumerate() {
        validate_bounded_text(
            &format!("next_action.handoff.findings[{index}].finding_id"),
            &finding.finding_id,
            wire_u32(MAX_ID_CHARACTERS),
            violations,
        );
        validate_text(
            &format!("next_action.handoff.findings[{index}].statement"),
            &finding.statement,
            MAX_FINDING_CHARACTERS,
            violations,
        );
        if !finding_ids.insert(&finding.finding_id) {
            violations.push(RepositoryExplorerInvariantViolation::DuplicateFindingId {
                finding_id: finding.finding_id.clone(),
            });
        }
        if finding.evidence_refs.is_empty() {
            violations.push(RepositoryExplorerInvariantViolation::EmptyFindingEvidence {
                finding_id: finding.finding_id.clone(),
            });
        }
        validate_evidence_refs(
            &format!("finding:{}", finding.finding_id),
            &finding.evidence_refs,
            policy,
            violations,
        );
        *evidence_count = evidence_count.saturating_add(finding.evidence_refs.len());
    }
    for (index, unknown) in handoff.unknowns.iter().enumerate() {
        validate_text(
            &format!("next_action.handoff.unknowns[{index}]"),
            unknown,
            MAX_UNKNOWN_CHARACTERS,
            violations,
        );
    }
    for (index, followup) in handoff.recommended_followups.iter().enumerate() {
        validate_text(
            &format!("next_action.handoff.recommended_followups[{index}]"),
            followup,
            MAX_FOLLOWUP_CHARACTERS,
            violations,
        );
    }
}

fn validate_evidence_refs(
    site: &str,
    references: &[ExplorerEvidenceRef],
    policy: &RepositoryExplorerPolicy,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    let observations = policy
        .previous_observations
        .iter()
        .map(|observation| (observation.observation_id.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    let mut unique = BTreeSet::new();
    for reference in references {
        let key = (
            reference.observation_id.as_str(),
            reference.artifact_sha256.as_str(),
        );
        if !unique.insert(key) {
            violations.push(
                RepositoryExplorerInvariantViolation::DuplicateEvidenceReference {
                    site: site.to_owned(),
                    observation_id: reference.observation_id.clone(),
                    artifact_sha256: reference.artifact_sha256.clone(),
                },
            );
        }
        match observations.get(reference.observation_id.as_str()) {
            None => violations.push(
                RepositoryExplorerInvariantViolation::UnknownEvidenceObservation {
                    site: site.to_owned(),
                    observation_id: reference.observation_id.clone(),
                },
            ),
            Some(observation) if observation.artifact_sha256 != reference.artifact_sha256 => {
                violations.push(
                    RepositoryExplorerInvariantViolation::EvidenceDigestMismatch {
                        site: site.to_owned(),
                        observation_id: reference.observation_id.clone(),
                        expected: observation.artifact_sha256.clone(),
                        actual: reference.artifact_sha256.clone(),
                    },
                );
            }
            Some(_) => {}
        }
    }
}

fn validate_collection_limit(
    field: &str,
    actual: usize,
    maximum: u32,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    if actual > maximum as usize {
        violations.push(
            RepositoryExplorerInvariantViolation::HandoffCollectionLimit {
                field: field.to_owned(),
                maximum,
                actual: wire_u32(actual),
            },
        );
    }
}

fn validate_text(
    field: &str,
    value: &str,
    maximum: usize,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    let actual = value.chars().count();
    if actual == 0 {
        violations.push(RepositoryExplorerInvariantViolation::EmptyText {
            field: field.to_owned(),
        });
    } else if actual > maximum {
        violations.push(RepositoryExplorerInvariantViolation::TextTooLong {
            field: field.to_owned(),
            maximum: wire_u32(maximum),
            actual: wire_u32(actual),
        });
    }
}

fn validate_bounded_text(
    field: &str,
    value: &str,
    maximum: u32,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    validate_text(field, value, maximum as usize, violations);
}

fn validate_requested_u32(
    field: &str,
    actual: u32,
    minimum: u32,
    maximum: u32,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    validate_requested_u64(
        field,
        u64::from(actual),
        u64::from(minimum),
        u64::from(maximum),
        violations,
    );
}

fn validate_requested_u64(
    field: &str,
    actual: u64,
    minimum: u64,
    maximum: u64,
    violations: &mut Vec<RepositoryExplorerInvariantViolation>,
) {
    if actual < minimum || actual > maximum {
        violations.push(
            RepositoryExplorerInvariantViolation::RequestedLimitOutOfRange {
                field: field.to_owned(),
                minimum,
                maximum,
                actual,
            },
        );
    }
}

fn policy_structure_violations(
    policy: &RepositoryExplorerPolicy,
) -> Vec<RepositoryExplorerPolicyViolation> {
    let mut violations = Vec::new();
    validate_identifier("run_id", &policy.run_id, MAX_ID_CHARACTERS, &mut violations);
    validate_identifier(
        "actor_id",
        &policy.actor_id,
        MAX_ID_CHARACTERS,
        &mut violations,
    );
    validate_identifier(
        "turn_id",
        &policy.turn_id,
        MAX_ID_CHARACTERS,
        &mut violations,
    );
    validate_digest(
        "root_snapshot_sha256",
        &policy.root_snapshot_sha256,
        &mut violations,
    );
    validate_artifact("goal", &policy.goal, &mut violations);
    validate_artifact("work_order", &policy.work_order, &mut violations);
    validate_artifact("context", &policy.context, &mut violations);
    validate_identifier(
        "tool_catalog_id",
        &policy.tool_catalog_id,
        MAX_ID_CHARACTERS,
        &mut violations,
    );
    validate_identifier(
        "observation_manifest_id",
        &policy.observation_manifest_id,
        MAX_ID_CHARACTERS,
        &mut violations,
    );
    validate_identifier(
        "model_lineage_id",
        &policy.model_lineage_id,
        MAX_ID_CHARACTERS,
        &mut violations,
    );
    validate_identifier(
        "model_attempt_id",
        &policy.model_attempt_id,
        MAX_ID_CHARACTERS,
        &mut violations,
    );
    validate_tool_grants(&policy.tool_grants, &mut violations);
    validate_budget(&policy.budget, &mut violations);
    validate_observations(policy, &mut violations);
    violations
}

fn policy_integrity_violations(
    policy: &RepositoryExplorerPolicy,
) -> Vec<RepositoryExplorerPolicyViolation> {
    let mut violations = policy_structure_violations(policy);
    check_derived_digest(
        "tool_catalog_sha256",
        tool_catalog_sha256(policy),
        &policy.tool_catalog_sha256,
        &mut violations,
    );
    check_derived_digest(
        "budget_sha256",
        canonical_sha256(&policy.budget),
        &policy.budget_sha256,
        &mut violations,
    );
    check_derived_digest(
        "observation_manifest_sha256",
        observation_manifest_sha256(policy),
        &policy.observation_manifest_sha256,
        &mut violations,
    );
    check_derived_digest(
        "explorer_policy_sha256",
        policy_content_sha256(policy),
        &policy.explorer_policy_sha256,
        &mut violations,
    );
    violations
}

fn validate_artifact(
    field: &str,
    binding: &ExplorerArtifactBinding,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    validate_identifier(
        &format!("{field}.artifact_id"),
        &binding.artifact_id,
        MAX_SOURCE_ID_CHARACTERS,
        violations,
    );
    validate_digest(
        &format!("{field}.artifact_sha256"),
        &binding.artifact_sha256,
        violations,
    );
}

fn validate_identifier(
    field: &str,
    value: &str,
    maximum: usize,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    let actual = value.chars().count();
    if actual == 0 {
        violations.push(RepositoryExplorerPolicyViolation::EmptyIdentifier {
            field: field.to_owned(),
        });
    } else if actual > maximum {
        violations.push(RepositoryExplorerPolicyViolation::IdentifierTooLong {
            field: field.to_owned(),
            maximum: wire_u32(maximum),
            actual: wire_u32(actual),
        });
    }
}

fn validate_digest(
    field: &str,
    value: &str,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    if !is_lowercase_sha256(value) {
        violations.push(RepositoryExplorerPolicyViolation::InvalidDigest {
            field: field.to_owned(),
            actual: value.to_owned(),
        });
    }
}

fn validate_tool_grants(
    grants: &[ExplorerToolGrant],
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    if grants.is_empty() || grants.len() > MAX_TOOL_GRANTS {
        violations.push(RepositoryExplorerPolicyViolation::ToolGrantCount {
            minimum: 1,
            maximum: wire_u32(MAX_TOOL_GRANTS),
            actual: wire_u32(grants.len()),
        });
    }
    let mut ids = BTreeSet::new();
    for grant in grants {
        let id = grant.tool_grant_id();
        validate_identifier("tool_grant_id", id, MAX_ID_CHARACTERS, violations);
        if !ids.insert(id) {
            violations.push(RepositoryExplorerPolicyViolation::DuplicateToolGrantId {
                tool_grant_id: id.to_owned(),
            });
        }
        validate_tool_grant(grant, violations);
    }
}

fn validate_tool_grant(
    grant: &ExplorerToolGrant,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    match grant {
        ExplorerToolGrant::RepositoryTree {
            max_path_characters,
            max_depth,
            max_entries,
            ..
        } => validate_tree_grant(
            grant.tool_grant_id(),
            *max_path_characters,
            *max_depth,
            *max_entries,
            violations,
        ),
        ExplorerToolGrant::RepositoryFileRead {
            max_path_characters,
            max_offset_bytes,
            max_bytes,
            ..
        } => validate_file_read_grant(
            grant.tool_grant_id(),
            *max_path_characters,
            *max_offset_bytes,
            *max_bytes,
            violations,
        ),
        ExplorerToolGrant::RepositoryLiteralSearch {
            max_path_characters,
            max_query_characters,
            max_depth,
            max_files,
            max_matches,
            max_bytes_per_file,
            max_total_bytes,
            ..
        } => validate_literal_search_grant(
            grant.tool_grant_id(),
            *max_path_characters,
            *max_query_characters,
            *max_depth,
            *max_files,
            *max_matches,
            *max_bytes_per_file,
            *max_total_bytes,
            violations,
        ),
    }
}

fn validate_tree_grant(
    id: &str,
    max_path_characters: u32,
    max_depth: u32,
    max_entries: u32,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    validate_grant_limit(
        id,
        "max_path_characters",
        max_path_characters,
        1,
        MAX_PATH_CHARACTERS,
        violations,
    );
    validate_grant_limit(id, "max_depth", max_depth, 0, MAX_TREE_DEPTH, violations);
    validate_grant_limit(
        id,
        "max_entries",
        max_entries,
        1,
        MAX_TREE_ENTRIES,
        violations,
    );
}

fn validate_file_read_grant(
    id: &str,
    max_path_characters: u32,
    max_offset_bytes: u64,
    max_bytes: u32,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    validate_grant_limit(
        id,
        "max_path_characters",
        max_path_characters,
        1,
        MAX_PATH_CHARACTERS,
        violations,
    );
    validate_grant_limit_u64(
        id,
        "max_offset_bytes",
        max_offset_bytes,
        0,
        MAX_FILE_OFFSET_BYTES,
        violations,
    );
    validate_grant_limit(id, "max_bytes", max_bytes, 1, MAX_RESULT_BYTES, violations);
}

#[allow(clippy::too_many_arguments)]
fn validate_literal_search_grant(
    id: &str,
    max_path_characters: u32,
    max_query_characters: u32,
    max_depth: u32,
    max_files: u32,
    max_matches: u32,
    max_bytes_per_file: u64,
    max_total_bytes: u64,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    for (field, actual, minimum, maximum) in [
        (
            "max_path_characters",
            max_path_characters,
            1,
            MAX_PATH_CHARACTERS,
        ),
        (
            "max_query_characters",
            max_query_characters,
            1,
            MAX_QUERY_CHARACTERS,
        ),
        ("max_depth", max_depth, 0, MAX_SEARCH_DEPTH),
        ("max_files", max_files, 1, MAX_SEARCH_FILES),
        ("max_matches", max_matches, 1, MAX_SEARCH_MATCHES),
    ] {
        validate_grant_limit(id, field, actual, minimum, maximum, violations);
    }
    validate_grant_limit_u64(
        id,
        "max_bytes_per_file",
        max_bytes_per_file,
        1,
        MAX_SEARCH_BYTES_PER_FILE,
        violations,
    );
    validate_grant_limit_u64(
        id,
        "max_total_bytes",
        max_total_bytes,
        1,
        MAX_SEARCH_TOTAL_BYTES,
        violations,
    );
}

fn validate_grant_limit(
    id: &str,
    field: &str,
    actual: u32,
    minimum: u32,
    maximum: u32,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    validate_grant_limit_u64(
        id,
        field,
        u64::from(actual),
        u64::from(minimum),
        u64::from(maximum),
        violations,
    );
}

fn validate_grant_limit_u64(
    id: &str,
    field: &str,
    actual: u64,
    minimum: u64,
    maximum: u64,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    if actual < minimum || actual > maximum {
        violations.push(
            RepositoryExplorerPolicyViolation::ToolGrantLimitOutOfRange {
                tool_grant_id: id.to_owned(),
                field: field.to_owned(),
                minimum,
                maximum,
                actual,
            },
        );
    }
}

fn validate_budget(
    budget: &RepositoryExplorerBudget,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    validate_identifier(
        "budget_id",
        &budget.budget_id,
        MAX_ID_CHARACTERS,
        violations,
    );
    validate_budget_limit(
        "max_iterations",
        budget.max_iterations,
        1,
        MAX_ITERATIONS,
        violations,
    );
    if budget.current_iteration == 0 || budget.current_iteration > budget.max_iterations {
        violations.push(
            RepositoryExplorerPolicyViolation::BudgetProgressOutOfRange {
                field: "current_iteration".to_owned(),
                maximum: budget.max_iterations,
                actual: budget.current_iteration,
            },
        );
    }
    validate_budget_limit(
        "max_tool_requests",
        budget.max_tool_requests,
        0,
        MAX_TOOL_REQUESTS,
        violations,
    );
    if budget.tool_requests_used > budget.max_tool_requests {
        violations.push(
            RepositoryExplorerPolicyViolation::BudgetProgressOutOfRange {
                field: "tool_requests_used".to_owned(),
                maximum: budget.max_tool_requests,
                actual: budget.tool_requests_used,
            },
        );
    }
    validate_budget_limit(
        "max_previous_observations",
        budget.max_previous_observations,
        0,
        wire_u32(MAX_PREVIOUS_OBSERVATIONS),
        violations,
    );
    validate_budget_limit(
        "max_evidence_references",
        budget.max_evidence_references,
        0,
        MAX_EVIDENCE_REFERENCES,
        violations,
    );
    validate_budget_limit(
        "max_handoff_findings",
        budget.max_handoff_findings,
        0,
        MAX_HANDOFF_FINDINGS,
        violations,
    );
    validate_budget_limit(
        "max_handoff_unknowns",
        budget.max_handoff_unknowns,
        0,
        MAX_HANDOFF_UNKNOWNS,
        violations,
    );
    validate_budget_limit(
        "max_recommended_followups",
        budget.max_recommended_followups,
        0,
        MAX_RECOMMENDED_FOLLOWUPS,
        violations,
    );
}

fn validate_budget_limit(
    field: &str,
    actual: u32,
    minimum: u32,
    maximum: u32,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    if actual < minimum || actual > maximum {
        violations.push(RepositoryExplorerPolicyViolation::BudgetLimitOutOfRange {
            field: field.to_owned(),
            minimum,
            maximum,
            actual,
        });
    }
}

fn validate_observations(
    policy: &RepositoryExplorerPolicy,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    let maximum = policy
        .budget
        .max_previous_observations
        .min(wire_u32(MAX_PREVIOUS_OBSERVATIONS));
    if policy.previous_observations.len() > maximum as usize {
        violations.push(
            RepositoryExplorerPolicyViolation::PreviousObservationCount {
                maximum,
                actual: wire_u32(policy.previous_observations.len()),
            },
        );
    }
    let grants = policy
        .tool_grants
        .iter()
        .map(|grant| (grant.tool_grant_id(), grant.tool_kind()))
        .collect::<BTreeMap<_, _>>();
    let mut observation_ids = BTreeSet::new();
    let mut tool_call_ids = BTreeSet::new();
    for observation in &policy.previous_observations {
        validate_identifier(
            "observation_id",
            &observation.observation_id,
            MAX_ID_CHARACTERS,
            violations,
        );
        validate_identifier(
            "tool_call_id",
            &observation.tool_call_id,
            MAX_ID_CHARACTERS,
            violations,
        );
        validate_identifier(
            "observation.tool_grant_id",
            &observation.tool_grant_id,
            MAX_ID_CHARACTERS,
            violations,
        );
        validate_digest(
            "observation.artifact_sha256",
            &observation.artifact_sha256,
            violations,
        );
        if !observation_ids.insert(&observation.observation_id) {
            violations.push(RepositoryExplorerPolicyViolation::DuplicateObservationId {
                observation_id: observation.observation_id.clone(),
            });
        }
        if !tool_call_ids.insert(&observation.tool_call_id) {
            violations.push(RepositoryExplorerPolicyViolation::DuplicateToolCallId {
                tool_call_id: observation.tool_call_id.clone(),
            });
        }
        match grants.get(observation.tool_grant_id.as_str()) {
            None => violations.push(
                RepositoryExplorerPolicyViolation::UnknownObservationToolGrant {
                    observation_id: observation.observation_id.clone(),
                    tool_grant_id: observation.tool_grant_id.clone(),
                },
            ),
            Some(expected) if *expected != observation.tool_kind => violations.push(
                RepositoryExplorerPolicyViolation::ObservationToolKindMismatch {
                    observation_id: observation.observation_id.clone(),
                    expected: *expected,
                    actual: observation.tool_kind,
                },
            ),
            Some(_) => {}
        }
    }
}

fn check_derived_digest(
    field: &str,
    expected: Result<String, String>,
    actual: &str,
    violations: &mut Vec<RepositoryExplorerPolicyViolation>,
) {
    if !is_lowercase_sha256(actual) {
        violations.push(RepositoryExplorerPolicyViolation::InvalidDigest {
            field: field.to_owned(),
            actual: actual.to_owned(),
        });
    }
    match expected {
        Ok(expected) if expected != actual => {
            violations.push(RepositoryExplorerPolicyViolation::DerivedDigestMismatch {
                field: field.to_owned(),
                expected,
                actual: actual.to_owned(),
            });
        }
        Ok(_) => {}
        Err(message) => {
            violations.push(RepositoryExplorerPolicyViolation::CanonicalEncoding { message });
        }
    }
}

fn tool_catalog_sha256(policy: &RepositoryExplorerPolicy) -> Result<String, String> {
    canonical_sha256(&ToolCatalogHashMaterial {
        tool_catalog_id: &policy.tool_catalog_id,
        tool_grants: &policy.tool_grants,
    })
}

fn observation_manifest_sha256(policy: &RepositoryExplorerPolicy) -> Result<String, String> {
    canonical_sha256(&ObservationManifestHashMaterial {
        observation_manifest_id: &policy.observation_manifest_id,
        previous_observations: &policy.previous_observations,
    })
}

fn policy_content_sha256(policy: &RepositoryExplorerPolicy) -> Result<String, String> {
    canonical_sha256(&RepositoryExplorerPolicyHashMaterial {
        authority: policy.authority,
        run_id: &policy.run_id,
        actor_id: &policy.actor_id,
        turn_id: &policy.turn_id,
        root_snapshot_sha256: &policy.root_snapshot_sha256,
        goal: &policy.goal,
        work_order: &policy.work_order,
        context: &policy.context,
        tool_catalog_id: &policy.tool_catalog_id,
        tool_catalog_sha256: &policy.tool_catalog_sha256,
        tool_grants: &policy.tool_grants,
        budget: &policy.budget,
        budget_sha256: &policy.budget_sha256,
        observation_manifest_id: &policy.observation_manifest_id,
        observation_manifest_sha256: &policy.observation_manifest_sha256,
        previous_observations: &policy.previous_observations,
        model_lineage_id: &policy.model_lineage_id,
        model_attempt_id: &policy.model_attempt_id,
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

fn canonical_violation(message: String) -> Vec<RepositoryExplorerPolicyViolation> {
    vec![RepositoryExplorerPolicyViolation::CanonicalEncoding { message }]
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
