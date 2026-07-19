//! Typed, policy-bounded planning and replanning for a durable root actor.
//!
//! The model may propose semantic work and verification targets. It cannot
//! author authoritative obligations or acceptance policy, mint permissions,
//! reserve budgets, select workspace leases, or attest backend identity. Those
//! values enter through independently supplied runtime snapshots and are
//! checked mechanically before a plan revision can be accepted.

use birdcode_backends::{
    BackendError, BackendId, ModelBackend, ModelId, StructuredInferenceRequest,
    StructuredInferenceResponse,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

const PLAN_SCHEMA_VERSION: u32 = 1;
const HARD_MAX_WORK_ORDERS: usize = 256;
const HARD_MAX_VERIFICATION_TARGETS: usize = 512;
const HARD_MAX_PATCH_OPERATIONS: usize = 512;
const HARD_MAX_DEPENDENCIES: usize = 64;
const HARD_MAX_DELEGATIONS: usize = 64;
const HARD_MAX_QUESTIONS: usize = 16;
const HARD_MAX_ESCALATIONS: usize = 16;
const HARD_MAX_FINISH_CLAIMS: usize = 4_096;
const HARD_MAX_OBLIGATIONS: usize = 4_096;
const HARD_MAX_CONTEXT_EVIDENCE_IDS: usize = 4_096;
const HARD_MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const HARD_MAX_OBLIGATION_CATALOG_ENCODED_BYTES: usize = 4 * 1024 * 1024;
const HARD_MAX_CONTEXT_MANIFEST_ENCODED_BYTES: usize = 2 * 1024 * 1024;
const HARD_MAX_DIRECTIVE_ENCODED_BYTES: usize = 4 * 1024 * 1024;
const HARD_MAX_ACTIVE_JOURNAL_RECORDS: usize = 4_096;
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_EVIDENCE_PER_BASIS: usize = 64;
const MAX_EVIDENCE_ID_BYTES: usize = 512;

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(PlanId);
uuid_id!(PlannerExecutionId);
uuid_id!(PlannerAttemptId);
uuid_id!(BudgetReservationId);
uuid_id!(ObligationId);
uuid_id!(PlanWorkOrderId);
uuid_id!(VerificationTargetId);

/// Canonical lowercase SHA-256 value used at planner trust boundaries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlannerDigest(String);

impl PlannerDigest {
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(encoded)
    }

    /// Parses an exact canonical SHA-256 value.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong length, uppercase, or non-hexadecimal text.
    pub fn parse(value: impl Into<String>) -> Result<Self, PlannerContractError> {
        let value = value.into();
        if valid_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(PlannerContractError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlannerDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for PlannerDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PlannerDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Opaque evidence identity selected from the compiled context manifest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PlannerEvidenceId(String);

impl PlannerEvidenceId {
    /// Creates a bounded opaque evidence identity without interpreting text.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or overlong identity.
    pub fn new(value: impl Into<String>) -> Result<Self, PlannerContractError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_EVIDENCE_ID_BYTES {
            Err(PlannerContractError::InvalidEvidenceId)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlannerEvidenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PlannerEvidenceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PlannerContractError {
    #[error("planner digest must be exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("planner evidence identity must contain between 1 and 512 bytes")]
    InvalidEvidenceId,
    #[error("protected obligation catalog must not be empty")]
    EmptyObligationCatalog,
    #[error("protected obligation catalog exceeds its hard item limit")]
    TooManyObligations,
    #[error("protected obligation statement is empty or exceeds its hard field limit")]
    InvalidObligationStatement,
    #[error("protected obligation digest does not bind its exact statement")]
    InvalidObligationDigest,
    #[error("protected obligation catalog exceeds its aggregate encoded-byte limit")]
    ObligationCatalogTooLarge,
    #[error("protected obligation {0} appears more than once")]
    DuplicateObligation(ObligationId),
    #[error("planner context catalog must not be empty")]
    EmptyContextCatalog,
    #[error("planner context catalog exceeds its hard item limit")]
    TooManyContextEvidenceIds,
    #[error("planner context catalog exceeds its aggregate encoded-byte limit")]
    ContextCatalogTooLarge,
    #[error("planner context evidence identity {0} appears more than once")]
    DuplicateContextEvidenceId(PlannerEvidenceId),
    #[error("planner policy limits are invalid")]
    InvalidPolicyLimits,
    #[error("planner value could not be encoded canonically: {0}")]
    Encoding(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedObligation {
    pub id: ObligationId,
    pub content_sha256: PlannerDigest,
    pub statement: String,
    pub required: bool,
}

impl ProtectedObligation {
    #[must_use]
    pub fn new(id: ObligationId, statement: impl Into<String>, required: bool) -> Self {
        let statement = statement.into();
        let content_sha256 = PlannerDigest::of_bytes(statement.as_bytes());
        Self {
            id,
            content_sha256,
            statement,
            required,
        }
    }
}

#[derive(Serialize)]
struct ObligationCatalogHashMaterial<'a> {
    acceptance_policy_sha256: &'a PlannerDigest,
    obligations: &'a BTreeMap<ObligationId, ProtectedObligation>,
}

/// Runtime-authored obligation and acceptance-policy snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedObligationCatalog {
    snapshot_sha256: PlannerDigest,
    acceptance_policy_sha256: PlannerDigest,
    obligations: BTreeMap<ObligationId, ProtectedObligation>,
}

impl ProtectedObligationCatalog {
    /// Builds a content-bound protected catalog.
    ///
    /// # Errors
    ///
    /// Rejects an empty catalog, duplicate identities, or encoding failure.
    pub fn new(
        acceptance_policy_sha256: PlannerDigest,
        obligations: impl IntoIterator<Item = ProtectedObligation>,
    ) -> Result<Self, PlannerContractError> {
        let mut by_id = BTreeMap::new();
        let mut aggregate_encoded_bytes = 256_usize;
        for obligation in obligations {
            if by_id.len() >= HARD_MAX_OBLIGATIONS {
                return Err(PlannerContractError::TooManyObligations);
            }
            if obligation.statement.trim().is_empty()
                || obligation.statement.len() > MAX_FIELD_BYTES
            {
                return Err(PlannerContractError::InvalidObligationStatement);
            }
            if obligation.content_sha256 != PlannerDigest::of_bytes(obligation.statement.as_bytes())
            {
                return Err(PlannerContractError::InvalidObligationDigest);
            }
            let encoded_len = serde_json::to_vec(&obligation)
                .map_err(|error| PlannerContractError::Encoding(error.to_string()))?
                .len()
                // Account conservatively for the map key, separators, and quotes.
                .saturating_add(80);
            aggregate_encoded_bytes = aggregate_encoded_bytes.saturating_add(encoded_len);
            if aggregate_encoded_bytes > HARD_MAX_OBLIGATION_CATALOG_ENCODED_BYTES {
                return Err(PlannerContractError::ObligationCatalogTooLarge);
            }
            if by_id.insert(obligation.id, obligation.clone()).is_some() {
                return Err(PlannerContractError::DuplicateObligation(obligation.id));
            }
        }
        if by_id.is_empty() {
            return Err(PlannerContractError::EmptyObligationCatalog);
        }
        let hash_material = ObligationCatalogHashMaterial {
            acceptance_policy_sha256: &acceptance_policy_sha256,
            obligations: &by_id,
        };
        if serde_json::to_vec(&hash_material)
            .map_err(|error| PlannerContractError::Encoding(error.to_string()))?
            .len()
            > HARD_MAX_OBLIGATION_CATALOG_ENCODED_BYTES
        {
            return Err(PlannerContractError::ObligationCatalogTooLarge);
        }
        let snapshot_sha256 = digest_of(&hash_material)?;
        Ok(Self {
            snapshot_sha256,
            acceptance_policy_sha256,
            obligations: by_id,
        })
    }

    #[must_use]
    pub const fn snapshot_sha256(&self) -> &PlannerDigest {
        &self.snapshot_sha256
    }

    #[must_use]
    pub const fn acceptance_policy_sha256(&self) -> &PlannerDigest {
        &self.acceptance_policy_sha256
    }

    #[must_use]
    pub const fn obligations(&self) -> &BTreeMap<ObligationId, ProtectedObligation> {
        &self.obligations
    }

    fn is_internally_valid(&self) -> bool {
        !self.obligations.is_empty()
            && self.obligations.len() <= HARD_MAX_OBLIGATIONS
            && self.obligations.values().all(|obligation| {
                !obligation.statement.trim().is_empty()
                    && obligation.statement.len() <= MAX_FIELD_BYTES
                    && obligation.content_sha256
                        == PlannerDigest::of_bytes(obligation.statement.as_bytes())
            })
            && obligation_catalog_encoded_len(&self.obligations)
                .is_some_and(|length| length <= HARD_MAX_OBLIGATION_CATALOG_ENCODED_BYTES)
            && digest_of(&ObligationCatalogHashMaterial {
                acceptance_policy_sha256: &self.acceptance_policy_sha256,
                obligations: &self.obligations,
            })
            .is_ok_and(|digest| digest == self.snapshot_sha256)
    }
}

fn obligation_catalog_encoded_len(
    obligations: &BTreeMap<ObligationId, ProtectedObligation>,
) -> Option<usize> {
    obligations
        .values()
        .try_fold(256_usize, |total, obligation| {
            let encoded = serde_json::to_vec(obligation).ok()?.len().checked_add(80)?;
            total.checked_add(encoded)
        })
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedObligationRef {
    pub id: ObligationId,
    pub content_sha256: PlannerDigest,
}

impl From<&ProtectedObligation> for ProtectedObligationRef {
    fn from(value: &ProtectedObligation) -> Self {
        Self {
            id: value.id,
            content_sha256: value.content_sha256.clone(),
        }
    }
}

#[derive(Serialize)]
struct PlannerContextHashMaterial<'a> {
    schema_version: u32,
    evidence_ids: &'a BTreeSet<PlannerEvidenceId>,
}

/// Content-bound evidence catalog compiled at the trusted context boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerContextCatalog {
    manifest_sha256: PlannerDigest,
    evidence_ids: BTreeSet<PlannerEvidenceId>,
}

impl PlannerContextCatalog {
    /// Builds a bounded canonical evidence manifest and derives its digest.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, over-count, or over-byte-limit manifests.
    pub fn new(
        evidence_ids: impl IntoIterator<Item = PlannerEvidenceId>,
    ) -> Result<Self, PlannerContractError> {
        let mut canonical = BTreeSet::new();
        let mut aggregate_encoded_bytes = 32_usize;
        for evidence_id in evidence_ids {
            if canonical.len() >= HARD_MAX_CONTEXT_EVIDENCE_IDS {
                return Err(PlannerContractError::TooManyContextEvidenceIds);
            }
            let encoded_len = serde_json::to_vec(&evidence_id)
                .map_err(|error| PlannerContractError::Encoding(error.to_string()))?
                .len()
                .saturating_add(1);
            aggregate_encoded_bytes = aggregate_encoded_bytes.saturating_add(encoded_len);
            if aggregate_encoded_bytes > HARD_MAX_CONTEXT_MANIFEST_ENCODED_BYTES {
                return Err(PlannerContractError::ContextCatalogTooLarge);
            }
            if !canonical.insert(evidence_id.clone()) {
                return Err(PlannerContractError::DuplicateContextEvidenceId(
                    evidence_id,
                ));
            }
        }
        if canonical.is_empty() {
            return Err(PlannerContractError::EmptyContextCatalog);
        }
        let hash_material = PlannerContextHashMaterial {
            schema_version: PLAN_SCHEMA_VERSION,
            evidence_ids: &canonical,
        };
        if serde_json::to_vec(&hash_material)
            .map_err(|error| PlannerContractError::Encoding(error.to_string()))?
            .len()
            > HARD_MAX_CONTEXT_MANIFEST_ENCODED_BYTES
        {
            return Err(PlannerContractError::ContextCatalogTooLarge);
        }
        let manifest_sha256 = digest_of(&hash_material)?;
        Ok(Self {
            manifest_sha256,
            evidence_ids: canonical,
        })
    }

    #[must_use]
    pub const fn manifest_sha256(&self) -> &PlannerDigest {
        &self.manifest_sha256
    }

    #[must_use]
    pub const fn evidence_ids(&self) -> &BTreeSet<PlannerEvidenceId> {
        &self.evidence_ids
    }

    fn is_internally_valid(&self) -> bool {
        !self.evidence_ids.is_empty()
            && self.evidence_ids.len() <= HARD_MAX_CONTEXT_EVIDENCE_IDS
            && serde_json::to_vec(&PlannerContextHashMaterial {
                schema_version: PLAN_SCHEMA_VERSION,
                evidence_ids: &self.evidence_ids,
            })
            .is_ok_and(|encoded| encoded.len() <= HARD_MAX_CONTEXT_MANIFEST_ENCODED_BYTES)
            && digest_of(&PlannerContextHashMaterial {
                schema_version: PLAN_SCHEMA_VERSION,
                evidence_ids: &self.evidence_ids,
            })
            .is_ok_and(|digest| digest == self.manifest_sha256)
    }
}

impl<'de> Deserialize<'de> for PlannerContextCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Repr {
            manifest_sha256: PlannerDigest,
            evidence_ids: Vec<PlannerEvidenceId>,
        }

        let repr = Repr::deserialize(deserializer)?;
        let catalog = Self::new(repr.evidence_ids).map_err(serde::de::Error::custom)?;
        if catalog.manifest_sha256 != repr.manifest_sha256 {
            return Err(serde::de::Error::custom(
                "planner context manifest digest does not match canonical evidence",
            ));
        }
        Ok(catalog)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerAccess {
    None,
    ReadOnly,
    WorkspaceWrite,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerLimits {
    pub max_work_orders: u32,
    pub max_verification_targets: u32,
    pub max_patch_operations: u32,
    pub max_dependencies_per_work_order: u32,
    pub max_delegations: u32,
    pub max_questions: u32,
    pub max_text_bytes: u64,
}

impl Default for PlannerLimits {
    fn default() -> Self {
        Self {
            max_work_orders: 32,
            max_verification_targets: 64,
            max_patch_operations: 64,
            max_dependencies_per_work_order: 16,
            max_delegations: 8,
            max_questions: 3,
            max_text_bytes: 256 * 1024,
        }
    }
}

#[derive(Serialize)]
struct PlannerPolicyHashMaterial<'a> {
    maximum_access: PlannerAccess,
    limits: &'a PlannerLimits,
}

/// Independently supplied mechanical policy for the first read-only slice.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerPolicy {
    policy_sha256: PlannerDigest,
    maximum_access: PlannerAccess,
    limits: PlannerLimits,
}

impl PlannerPolicy {
    /// Constructs the initial read-only policy.
    ///
    /// # Errors
    ///
    /// Rejects zero or hard-cap-exceeding limits.
    pub fn read_only(limits: PlannerLimits) -> Result<Self, PlannerContractError> {
        if !valid_limits(limits) {
            return Err(PlannerContractError::InvalidPolicyLimits);
        }
        let maximum_access = PlannerAccess::ReadOnly;
        let policy_sha256 = digest_of(&PlannerPolicyHashMaterial {
            maximum_access,
            limits: &limits,
        })?;
        Ok(Self {
            policy_sha256,
            maximum_access,
            limits,
        })
    }

    #[must_use]
    pub const fn policy_sha256(&self) -> &PlannerDigest {
        &self.policy_sha256
    }

    #[must_use]
    pub const fn maximum_access(&self) -> PlannerAccess {
        self.maximum_access
    }

    #[must_use]
    pub const fn limits(&self) -> PlannerLimits {
        self.limits
    }

    fn is_internally_valid(&self) -> bool {
        self.maximum_access == PlannerAccess::ReadOnly
            && valid_limits(self.limits)
            && digest_of(&PlannerPolicyHashMaterial {
                maximum_access: self.maximum_access,
                limits: &self.limits,
            })
            .is_ok_and(|digest| digest == self.policy_sha256)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LocalWorkOrderId(pub u32);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LocalVerificationTargetId(pub u32);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBasis {
    pub evidence_ids: BTreeSet<PlannerEvidenceId>,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewVerificationTarget {
    pub local_id: LocalVerificationTargetId,
    pub statement: String,
    pub obligations: BTreeSet<ProtectedObligationRef>,
    pub basis: DecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationTarget {
    pub id: VerificationTargetId,
    pub statement: String,
    pub obligations: BTreeSet<ProtectedObligationRef>,
    pub basis: DecisionBasis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedWorkOrderState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedWorkOrder {
    pub id: PlanWorkOrderId,
    pub revision: u32,
    pub objective: String,
    pub obligations: BTreeSet<ProtectedObligationRef>,
    pub dependencies: BTreeSet<PlanWorkOrderId>,
    pub verification_targets: BTreeSet<VerificationTargetId>,
    pub required_access: PlannerAccess,
    pub state: PlannedWorkOrderState,
    pub basis: DecisionBasis,
}

impl PlannedWorkOrder {
    /// Returns the exact optimistic-concurrency digest of this work order.
    ///
    /// # Errors
    ///
    /// Returns an error only when serialization fails.
    pub fn revision_sha256(&self) -> Result<PlannerDigest, PlannerContractError> {
        digest_of(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewWorkOrder {
    pub local_id: LocalWorkOrderId,
    pub objective: String,
    pub obligations: BTreeSet<ProtectedObligationRef>,
    pub existing_dependencies: BTreeSet<PlanWorkOrderId>,
    pub new_dependencies: BTreeSet<LocalWorkOrderId>,
    pub existing_verification_targets: BTreeSet<VerificationTargetId>,
    pub new_verification_targets: BTreeSet<LocalVerificationTargetId>,
    pub required_access: PlannerAccess,
    pub basis: DecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedWorkOrderRef {
    pub id: PlanWorkOrderId,
    pub revision_sha256: PlannerDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceWorkOrder {
    pub target: ProtectedWorkOrderRef,
    pub objective: String,
    pub obligations: BTreeSet<ProtectedObligationRef>,
    pub existing_dependencies: BTreeSet<PlanWorkOrderId>,
    pub new_dependencies: BTreeSet<LocalWorkOrderId>,
    pub existing_verification_targets: BTreeSet<VerificationTargetId>,
    pub new_verification_targets: BTreeSet<LocalVerificationTargetId>,
    pub required_access: PlannerAccess,
    pub basis: DecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelWorkOrder {
    pub target: ProtectedWorkOrderRef,
    pub basis: DecisionBasis,
}

/// Atomic semantic amendment. Authoritative obligation and acceptance-policy
/// mutations are impossible to express in this type.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPatch {
    pub strategy_summary: Option<String>,
    pub add_verification_targets: Vec<NewVerificationTarget>,
    pub add_work_orders: Vec<NewWorkOrder>,
    pub replace_work_orders: Vec<ReplaceWorkOrder>,
    pub cancel_work_orders: Vec<CancelWorkOrder>,
}

impl PlanPatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.strategy_summary.is_none()
            && self.add_verification_targets.is_empty()
            && self.add_work_orders.is_empty()
            && self.replace_work_orders.is_empty()
            && self.cancel_work_orders.is_empty()
    }

    fn operation_count(&self) -> usize {
        usize::from(self.strategy_summary.is_some())
            .saturating_add(self.add_verification_targets.len())
            .saturating_add(self.add_work_orders.len())
            .saturating_add(self.replace_work_orders.len())
            .saturating_add(self.cancel_work_orders.len())
    }
}

/// Immutable semantic plan projection rebuilt from accepted patches.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSnapshot {
    pub schema_version: u32,
    pub plan_id: PlanId,
    pub revision: u64,
    pub parent_plan_sha256: Option<PlannerDigest>,
    pub obligation_snapshot_sha256: PlannerDigest,
    pub acceptance_policy_sha256: PlannerDigest,
    pub strategy_summary: String,
    pub verification_targets: BTreeMap<VerificationTargetId, VerificationTarget>,
    pub work_orders: BTreeMap<PlanWorkOrderId, PlannedWorkOrder>,
}

impl PlanSnapshot {
    #[must_use]
    pub fn empty(plan_id: PlanId, obligations: &ProtectedObligationCatalog) -> Self {
        Self {
            schema_version: PLAN_SCHEMA_VERSION,
            plan_id,
            revision: 0,
            parent_plan_sha256: None,
            obligation_snapshot_sha256: obligations.snapshot_sha256.clone(),
            acceptance_policy_sha256: obligations.acceptance_policy_sha256.clone(),
            strategy_summary: String::new(),
            verification_targets: BTreeMap::new(),
            work_orders: BTreeMap::new(),
        }
    }

    /// Computes the canonical digest of the complete plan projection.
    ///
    /// # Errors
    ///
    /// Returns an error only when serialization fails.
    pub fn sha256(&self) -> Result<PlannerDigest, PlannerContractError> {
        digest_of(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerTurnBindings {
    pub plan_id: PlanId,
    pub base_revision: u64,
    pub base_plan_sha256: PlannerDigest,
    pub obligation_snapshot_sha256: PlannerDigest,
    pub acceptance_policy_sha256: PlannerDigest,
    pub context_manifest_sha256: PlannerDigest,
    pub planner_policy_sha256: PlannerDigest,
}

impl PlannerTurnBindings {
    /// Creates exact echo bindings for a planner invocation.
    ///
    /// # Errors
    ///
    /// Returns an error only when plan hashing fails.
    pub fn new(
        plan: &PlanSnapshot,
        obligations: &ProtectedObligationCatalog,
        context: &PlannerContextCatalog,
        policy: &PlannerPolicy,
    ) -> Result<Self, PlannerContractError> {
        Ok(Self {
            plan_id: plan.plan_id,
            base_revision: plan.revision,
            base_plan_sha256: plan.sha256()?,
            obligation_snapshot_sha256: obligations.snapshot_sha256.clone(),
            acceptance_policy_sha256: obligations.acceptance_policy_sha256.clone(),
            context_manifest_sha256: context.manifest_sha256().clone(),
            planner_policy_sha256: policy.policy_sha256.clone(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSelection {
    pub existing: BTreeSet<PlanWorkOrderId>,
    pub new: BTreeSet<LocalWorkOrderId>,
}

impl WorkSelection {
    fn is_empty(&self) -> bool {
        self.existing.is_empty() && self.new.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequest {
    pub work_orders: WorkSelection,
    pub basis: DecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationRequest {
    pub question: String,
    pub blocked_obligations: BTreeSet<ProtectedObligationRef>,
    pub basis: DecisionBasis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationKind {
    Authority,
    Budget,
    ModelCapability,
    HumanDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationRequest {
    pub kind: EscalationKind,
    pub request: String,
    pub blocked_obligations: BTreeSet<ProtectedObligationRef>,
    pub basis: DecisionBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinishClaim {
    pub obligation: ProtectedObligationRef,
    pub evidence_ids: BTreeSet<PlannerEvidenceId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerDirectiveKind {
    Execute,
    Delegate,
    Clarify,
    Escalate,
    Finish,
}

/// Fixed-shape directive for conservative structured-generation engines.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerDirective {
    pub kind: PlannerDirectiveKind,
    pub execute: WorkSelection,
    pub delegations: Vec<DelegationRequest>,
    pub clarifications: Vec<ClarificationRequest>,
    pub escalations: Vec<EscalationRequest>,
    pub finish_claims: Vec<FinishClaim>,
}

/// Internal revisions-and-patches domain value.
///
/// This is deliberately not the serde DTO of the initial
/// `root-planner-turn/1.0.0` prompt. A runtime adapter maps that prompt's
/// string-local plan into numeric local IDs, protected obligation references,
/// a [`PlanPatch`], and the fixed internal directive. Keeping the adapter at the
/// trust boundary prevents prompt evolution from mutating durable plan state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerTurnProposal {
    pub schema_version: u32,
    pub bindings: PlannerTurnBindings,
    pub patch: PlanPatch,
    pub directive: PlannerDirective,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolvedPlannerDirective {
    Execute {
        work_order_id: PlanWorkOrderId,
    },
    Delegate {
        work_order_ids: Vec<PlanWorkOrderId>,
    },
    Clarify {
        requests: Vec<ClarificationRequest>,
    },
    Escalate {
        requests: Vec<EscalationRequest>,
    },
    /// This is only a proposal for the independent completion gate.
    FinishPendingGate {
        claims: Vec<FinishClaim>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedPlannerTurn {
    pub plan: PlanSnapshot,
    pub plan_sha256: PlannerDigest,
    pub directive: ResolvedPlannerDirective,
}

/// Collect-all mechanical defects in a model-authored plan turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerViolation {
    UnsupportedSchemaVersion {
        actual: u32,
    },
    PolicySnapshotInvalid,
    ObligationCatalogInvalid,
    ContextCatalogInvalid,
    BasePlanInvalid,
    StalePlanBinding,
    ObligationSnapshotMismatch,
    AcceptancePolicyMismatch,
    ContextManifestMismatch,
    PlannerPolicyMismatch,
    PatchOperationLimitExceeded {
        maximum: u32,
        actual: usize,
    },
    WorkOrderLimitExceeded {
        maximum: u32,
        actual: usize,
    },
    VerificationTargetLimitExceeded {
        maximum: u32,
        actual: usize,
    },
    TextLimitExceeded {
        maximum: u64,
        actual: usize,
    },
    DirectiveEncodedLimitExceeded {
        maximum: usize,
    },
    DirectiveCollectionLimitExceeded {
        field: String,
        maximum: usize,
        actual: usize,
    },
    EmptyText {
        field: String,
    },
    FieldTooLarge {
        field: String,
        maximum: usize,
        actual: usize,
    },
    EmptyEvidence {
        field: String,
    },
    EvidenceLimitExceeded {
        field: String,
        maximum: usize,
        actual: usize,
    },
    UnknownEvidence {
        evidence_id: PlannerEvidenceId,
    },
    InvalidLocalWorkOrderId {
        id: LocalWorkOrderId,
    },
    InvalidLocalVerificationTargetId {
        id: LocalVerificationTargetId,
    },
    DuplicateLocalWorkOrderId {
        id: LocalWorkOrderId,
    },
    DuplicateLocalVerificationTargetId {
        id: LocalVerificationTargetId,
    },
    UnknownObligation {
        obligation_id: ObligationId,
    },
    ObligationDigestMismatch {
        obligation_id: ObligationId,
    },
    EmptyObligationSet {
        field: String,
    },
    UnknownWorkOrder {
        work_order_id: PlanWorkOrderId,
    },
    UnknownNewWorkOrder {
        local_id: LocalWorkOrderId,
    },
    StaleWorkOrder {
        work_order_id: PlanWorkOrderId,
    },
    WorkOrderOperationConflict {
        work_order_id: PlanWorkOrderId,
    },
    ImmutableWorkOrder {
        work_order_id: PlanWorkOrderId,
        state: PlannedWorkOrderState,
    },
    UnknownVerificationTarget {
        verification_target_id: VerificationTargetId,
    },
    UnknownNewVerificationTarget {
        local_id: LocalVerificationTargetId,
    },
    EmptyVerificationTargets {
        work_order_id: Option<PlanWorkOrderId>,
    },
    AccessExpansion {
        access: PlannerAccess,
    },
    DependencyLimitExceeded {
        maximum: u32,
        actual: usize,
    },
    DependencyOnCancelled {
        work_order_id: PlanWorkOrderId,
        dependency_id: PlanWorkOrderId,
    },
    DependencyCycle,
    RequiredObligationUncovered {
        obligation_id: ObligationId,
    },
    PlanRevisionOverflow,
    WorkOrderRevisionOverflow {
        work_order_id: PlanWorkOrderId,
    },
    DirectiveShapeMismatch {
        directive: PlannerDirectiveKind,
    },
    DirectiveTargetNotPending {
        work_order_id: PlanWorkOrderId,
    },
    DelegationLimitExceeded {
        maximum: u32,
        actual: usize,
    },
    ClarificationLimitExceeded {
        maximum: u32,
        actual: usize,
    },
    EscalationLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    FinishClaimLimitExceeded {
        maximum: usize,
        actual: usize,
    },
    FinishRequiresEmptyPatch,
    FinishMissingRequiredObligation {
        obligation_id: ObligationId,
    },
    DuplicateFinishClaim {
        obligation_id: ObligationId,
    },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("planner turn is invalid: {violations:?}")]
pub struct PlannerValidationError {
    pub violations: Vec<PlannerViolation>,
}

impl PlannerTurnProposal {
    /// Validates and atomically applies one model-authored turn.
    ///
    /// The input plan is never mutated. UUID allocation for accepted domain
    /// identities is local bookkeeping, not an external effect.
    ///
    /// # Errors
    ///
    /// Returns every safely collectable mechanical violation. Structural hard
    /// limits and stale trust bindings fail before graph traversal or cloning.
    #[allow(clippy::too_many_lines)]
    pub fn validate_and_apply(
        &self,
        base: &PlanSnapshot,
        obligations: &ProtectedObligationCatalog,
        context: &PlannerContextCatalog,
        policy: &PlannerPolicy,
    ) -> Result<ValidatedPlannerTurn, PlannerValidationError> {
        let structural = structural_violations(self, base, policy);
        if !structural.is_empty() {
            return Err(PlannerValidationError {
                violations: structural,
            });
        }

        let mut violations = binding_violations(self, base, obligations, context, policy);
        if !violations.is_empty() {
            return Err(PlannerValidationError { violations });
        }

        let mut next = base.clone();
        let old_digest = base.sha256().map_err(|_| PlannerValidationError {
            violations: vec![PlannerViolation::BasePlanInvalid],
        })?;
        let (work_ids, verification_ids) = allocate_patch_ids(base, &self.patch, &mut violations);
        apply_verification_targets(
            &mut next,
            &self.patch,
            &verification_ids,
            obligations,
            context,
            &mut violations,
        );
        apply_work_order_additions(
            &mut next,
            &self.patch,
            &work_ids,
            &verification_ids,
            obligations,
            context,
            policy,
            &mut violations,
        );
        apply_work_order_mutations(
            &mut next,
            &self.patch,
            &work_ids,
            &verification_ids,
            obligations,
            context,
            policy,
            &mut violations,
        );

        if let Some(summary) = &self.patch.strategy_summary {
            validate_text("patch.strategy_summary", summary, &mut violations);
            next.strategy_summary.clone_from(summary);
        }

        // The very first turn may discover that authoritative information or
        // authority is missing. Clarifying/escalating without inventing a work
        // order is valid, but execution, delegation, and completion never get
        // this exception to required-obligation coverage.
        let allow_initial_empty_pause = base.revision == 0
            && base.work_orders.is_empty()
            && self.patch.is_empty()
            && matches!(
                self.directive.kind,
                PlannerDirectiveKind::Clarify | PlannerDirectiveKind::Escalate
            );
        plan_invariant_violations(
            &next,
            obligations,
            policy,
            allow_initial_empty_pause,
            &mut violations,
        );
        let resolved_directive = resolve_directive(
            &self.directive,
            &self.patch,
            &next,
            &work_ids,
            obligations,
            context,
            policy,
            &mut violations,
        );
        if !violations.is_empty() {
            return Err(PlannerValidationError { violations });
        }
        let Some(resolved_directive) = resolved_directive else {
            return Err(PlannerValidationError {
                violations: vec![PlannerViolation::DirectiveShapeMismatch {
                    directive: self.directive.kind,
                }],
            });
        };

        if !self.patch.is_empty() {
            let Some(revision) = base.revision.checked_add(1) else {
                return Err(PlannerValidationError {
                    violations: vec![PlannerViolation::PlanRevisionOverflow],
                });
            };
            next.revision = revision;
            next.parent_plan_sha256 = Some(old_digest);
        }
        let plan_sha256 = next.sha256().map_err(|_| PlannerValidationError {
            violations: vec![PlannerViolation::BasePlanInvalid],
        })?;
        Ok(ValidatedPlannerTurn {
            plan: next,
            plan_sha256,
            directive: resolved_directive,
        })
    }
}

fn structural_violations(
    proposal: &PlannerTurnProposal,
    base: &PlanSnapshot,
    policy: &PlannerPolicy,
) -> Vec<PlannerViolation> {
    let mut violations = Vec::new();
    let mut hard_cardinality_exceeded = false;
    if !proposal.patch.is_empty() && base.revision.checked_add(1).is_none() {
        violations.push(PlannerViolation::PlanRevisionOverflow);
        hard_cardinality_exceeded = true;
    }
    let operations = proposal.patch.operation_count();
    if operations > HARD_MAX_PATCH_OPERATIONS
        || operations > usize::try_from(policy.limits.max_patch_operations).unwrap_or(usize::MAX)
    {
        violations.push(PlannerViolation::PatchOperationLimitExceeded {
            maximum: policy.limits.max_patch_operations,
            actual: operations,
        });
        hard_cardinality_exceeded |= operations > HARD_MAX_PATCH_OPERATIONS;
    }
    let work_orders = base
        .work_orders
        .len()
        .saturating_add(proposal.patch.add_work_orders.len());
    if work_orders > HARD_MAX_WORK_ORDERS
        || work_orders > usize::try_from(policy.limits.max_work_orders).unwrap_or(usize::MAX)
    {
        violations.push(PlannerViolation::WorkOrderLimitExceeded {
            maximum: policy.limits.max_work_orders,
            actual: work_orders,
        });
        hard_cardinality_exceeded |= work_orders > HARD_MAX_WORK_ORDERS;
    }
    let targets = base
        .verification_targets
        .len()
        .saturating_add(proposal.patch.add_verification_targets.len());
    if targets > HARD_MAX_VERIFICATION_TARGETS
        || targets > usize::try_from(policy.limits.max_verification_targets).unwrap_or(usize::MAX)
    {
        violations.push(PlannerViolation::VerificationTargetLimitExceeded {
            maximum: policy.limits.max_verification_targets,
            actual: targets,
        });
        hard_cardinality_exceeded |= targets > HARD_MAX_VERIFICATION_TARGETS;
    }
    if proposal.directive.delegations.len() > HARD_MAX_DELEGATIONS {
        violations.push(PlannerViolation::DelegationLimitExceeded {
            maximum: policy.limits.max_delegations,
            actual: proposal.directive.delegations.len(),
        });
        hard_cardinality_exceeded = true;
    }
    if proposal.directive.clarifications.len() > HARD_MAX_QUESTIONS {
        violations.push(PlannerViolation::ClarificationLimitExceeded {
            maximum: policy.limits.max_questions,
            actual: proposal.directive.clarifications.len(),
        });
        hard_cardinality_exceeded = true;
    }
    if proposal.directive.escalations.len() > HARD_MAX_ESCALATIONS {
        violations.push(PlannerViolation::EscalationLimitExceeded {
            maximum: HARD_MAX_ESCALATIONS,
            actual: proposal.directive.escalations.len(),
        });
        hard_cardinality_exceeded = true;
    }
    if proposal.directive.finish_claims.len() > HARD_MAX_FINISH_CLAIMS {
        violations.push(PlannerViolation::FinishClaimLimitExceeded {
            maximum: HARD_MAX_FINISH_CLAIMS,
            actual: proposal.directive.finish_claims.len(),
        });
        hard_cardinality_exceeded = true;
    }
    hard_cardinality_exceeded |=
        directive_collection_violations(&proposal.directive, &mut violations);
    if hard_cardinality_exceeded {
        return violations;
    }
    if directive_exceeds_encoded_limit(&proposal.directive) {
        violations.push(PlannerViolation::DirectiveEncodedLimitExceeded {
            maximum: HARD_MAX_DIRECTIVE_ENCODED_BYTES,
        });
        return violations;
    }
    let text_bytes = proposal_text_bytes(proposal);
    if text_bytes > HARD_MAX_TEXT_BYTES
        || u64::try_from(text_bytes).unwrap_or(u64::MAX) > policy.limits.max_text_bytes
    {
        violations.push(PlannerViolation::TextLimitExceeded {
            maximum: policy.limits.max_text_bytes,
            actual: text_bytes,
        });
    }
    violations
}

fn directive_collection_violations(
    directive: &PlannerDirective,
    violations: &mut Vec<PlannerViolation>,
) -> bool {
    fn check(
        field: &str,
        actual: usize,
        maximum: usize,
        violations: &mut Vec<PlannerViolation>,
    ) -> bool {
        if actual <= maximum {
            return false;
        }
        violations.push(PlannerViolation::DirectiveCollectionLimitExceeded {
            field: field.to_owned(),
            maximum,
            actual,
        });
        true
    }

    fn selection_len(selection: &WorkSelection) -> usize {
        selection.existing.len().saturating_add(selection.new.len())
    }

    let mut exceeded = check(
        "directive.execute",
        selection_len(&directive.execute),
        HARD_MAX_WORK_ORDERS,
        violations,
    );
    for (index, delegation) in directive.delegations.iter().enumerate() {
        exceeded |= check(
            &format!("directive.delegations[{index}].work_orders"),
            selection_len(&delegation.work_orders),
            HARD_MAX_WORK_ORDERS,
            violations,
        );
        exceeded |= check(
            &format!("directive.delegations[{index}].basis.evidence_ids"),
            delegation.basis.evidence_ids.len(),
            MAX_EVIDENCE_PER_BASIS,
            violations,
        );
    }
    for (index, clarification) in directive.clarifications.iter().enumerate() {
        exceeded |= check(
            &format!("directive.clarifications[{index}].blocked_obligations"),
            clarification.blocked_obligations.len(),
            HARD_MAX_OBLIGATIONS,
            violations,
        );
        exceeded |= check(
            &format!("directive.clarifications[{index}].basis.evidence_ids"),
            clarification.basis.evidence_ids.len(),
            MAX_EVIDENCE_PER_BASIS,
            violations,
        );
    }
    for (index, escalation) in directive.escalations.iter().enumerate() {
        exceeded |= check(
            &format!("directive.escalations[{index}].blocked_obligations"),
            escalation.blocked_obligations.len(),
            HARD_MAX_OBLIGATIONS,
            violations,
        );
        exceeded |= check(
            &format!("directive.escalations[{index}].basis.evidence_ids"),
            escalation.basis.evidence_ids.len(),
            MAX_EVIDENCE_PER_BASIS,
            violations,
        );
    }
    for (index, claim) in directive.finish_claims.iter().enumerate() {
        exceeded |= check(
            &format!("directive.finish_claims[{index}].evidence_ids"),
            claim.evidence_ids.len(),
            MAX_EVIDENCE_PER_BASIS,
            violations,
        );
    }
    exceeded
}

struct EncodedLimitWriter {
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl std::io::Write for EncodedLimitWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other("encoded byte limit exceeded"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("encoded byte limit exceeded"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn directive_exceeds_encoded_limit(directive: &PlannerDirective) -> bool {
    let mut writer = EncodedLimitWriter {
        written: 0,
        limit: HARD_MAX_DIRECTIVE_ENCODED_BYTES,
        exceeded: false,
    };
    serde_json::to_writer(&mut writer, directive).is_err() || writer.exceeded
}

fn binding_violations(
    proposal: &PlannerTurnProposal,
    base: &PlanSnapshot,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
) -> Vec<PlannerViolation> {
    let mut violations = Vec::new();
    if proposal.schema_version != PLAN_SCHEMA_VERSION {
        violations.push(PlannerViolation::UnsupportedSchemaVersion {
            actual: proposal.schema_version,
        });
    }
    if !policy.is_internally_valid() {
        violations.push(PlannerViolation::PolicySnapshotInvalid);
    }
    if !obligations.is_internally_valid() {
        violations.push(PlannerViolation::ObligationCatalogInvalid);
    }
    if !context.is_internally_valid() {
        violations.push(PlannerViolation::ContextCatalogInvalid);
    }
    let base_digest = base.sha256().ok();
    if base.schema_version != PLAN_SCHEMA_VERSION
        || base.obligation_snapshot_sha256 != obligations.snapshot_sha256
        || base.acceptance_policy_sha256 != obligations.acceptance_policy_sha256
    {
        violations.push(PlannerViolation::BasePlanInvalid);
    }
    if proposal.bindings.plan_id != base.plan_id
        || proposal.bindings.base_revision != base.revision
        || base_digest.as_ref() != Some(&proposal.bindings.base_plan_sha256)
    {
        violations.push(PlannerViolation::StalePlanBinding);
    }
    if proposal.bindings.obligation_snapshot_sha256 != obligations.snapshot_sha256 {
        violations.push(PlannerViolation::ObligationSnapshotMismatch);
    }
    if proposal.bindings.acceptance_policy_sha256 != obligations.acceptance_policy_sha256 {
        violations.push(PlannerViolation::AcceptancePolicyMismatch);
    }
    if proposal.bindings.context_manifest_sha256 != *context.manifest_sha256() {
        violations.push(PlannerViolation::ContextManifestMismatch);
    }
    if proposal.bindings.planner_policy_sha256 != policy.policy_sha256 {
        violations.push(PlannerViolation::PlannerPolicyMismatch);
    }
    if base.revision > 0 || !base.work_orders.is_empty() {
        plan_invariant_violations(base, obligations, policy, false, &mut violations);
    }
    violations
}

fn allocate_patch_ids(
    base: &PlanSnapshot,
    patch: &PlanPatch,
    violations: &mut Vec<PlannerViolation>,
) -> (
    BTreeMap<LocalWorkOrderId, PlanWorkOrderId>,
    BTreeMap<LocalVerificationTargetId, VerificationTargetId>,
) {
    let mut work_ids = BTreeMap::new();
    for work in &patch.add_work_orders {
        if work.local_id.0 == 0 {
            violations.push(PlannerViolation::InvalidLocalWorkOrderId { id: work.local_id });
        } else if work_ids
            .insert(
                work.local_id,
                PlanWorkOrderId::from_uuid(derived_patch_uuid(
                    b"birdcode.plan.work-order.v1",
                    base,
                    work.local_id.0,
                )),
            )
            .is_some()
        {
            violations.push(PlannerViolation::DuplicateLocalWorkOrderId { id: work.local_id });
        }
    }
    let mut verification_ids = BTreeMap::new();
    for target in &patch.add_verification_targets {
        if target.local_id.0 == 0 {
            violations.push(PlannerViolation::InvalidLocalVerificationTargetId {
                id: target.local_id,
            });
        } else if verification_ids
            .insert(
                target.local_id,
                VerificationTargetId::from_uuid(derived_patch_uuid(
                    b"birdcode.plan.verification-target.v1",
                    base,
                    target.local_id.0,
                )),
            )
            .is_some()
        {
            violations.push(PlannerViolation::DuplicateLocalVerificationTargetId {
                id: target.local_id,
            });
        }
    }
    (work_ids, verification_ids)
}

/// Derives stable domain identities for an accepted patch. Validation of an
/// already observed model response may be replayed after a crash, so allocating
/// identities from wall-clock time here would change the resulting plan hash.
/// The plan identity, next revision, local identity and type domain make this
/// deterministic without letting the model mint authoritative UUIDs.
fn derived_patch_uuid(domain: &[u8], base: &PlanSnapshot, local_id: u32) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(base.plan_id.as_uuid().as_bytes());
    // Structural validation rejects overflow before identity allocation. Keep
    // this function total for defensive direct reuse without wrapping IDs.
    let next_revision = base.revision.checked_add(1).unwrap_or(base.revision);
    hasher.update(next_revision.to_be_bytes());
    hasher.update(local_id.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 9562 UUIDv8 carries application-defined, hash-derived bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn apply_verification_targets(
    next: &mut PlanSnapshot,
    patch: &PlanPatch,
    ids: &BTreeMap<LocalVerificationTargetId, VerificationTargetId>,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    violations: &mut Vec<PlannerViolation>,
) {
    for target in &patch.add_verification_targets {
        validate_text(
            "verification_target.statement",
            &target.statement,
            violations,
        );
        validate_basis(
            "verification_target.basis",
            &target.basis,
            context,
            violations,
        );
        validate_obligation_refs(
            "verification_target.obligations",
            &target.obligations,
            obligations,
            violations,
        );
        if let Some(id) = ids.get(&target.local_id) {
            next.verification_targets.insert(
                *id,
                VerificationTarget {
                    id: *id,
                    statement: target.statement.clone(),
                    obligations: target.obligations.clone(),
                    basis: target.basis.clone(),
                },
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_work_order_additions(
    next: &mut PlanSnapshot,
    patch: &PlanPatch,
    work_ids: &BTreeMap<LocalWorkOrderId, PlanWorkOrderId>,
    verification_ids: &BTreeMap<LocalVerificationTargetId, VerificationTargetId>,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
    violations: &mut Vec<PlannerViolation>,
) {
    for work in &patch.add_work_orders {
        let Some(id) = work_ids.get(&work.local_id).copied() else {
            continue;
        };
        let dependencies = resolve_dependencies(
            &work.existing_dependencies,
            &work.new_dependencies,
            work_ids,
            next,
            violations,
        );
        let targets = resolve_verification_targets(
            &work.existing_verification_targets,
            &work.new_verification_targets,
            verification_ids,
            next,
            violations,
        );
        validate_work_order_fields(
            None,
            &work.objective,
            &work.obligations,
            &dependencies,
            &targets,
            work.required_access,
            &work.basis,
            obligations,
            context,
            policy,
            violations,
        );
        next.work_orders.insert(
            id,
            PlannedWorkOrder {
                id,
                revision: 1,
                objective: work.objective.clone(),
                obligations: work.obligations.clone(),
                dependencies,
                verification_targets: targets,
                required_access: work.required_access,
                state: PlannedWorkOrderState::Pending,
                basis: work.basis.clone(),
            },
        );
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn apply_work_order_mutations(
    next: &mut PlanSnapshot,
    patch: &PlanPatch,
    work_ids: &BTreeMap<LocalWorkOrderId, PlanWorkOrderId>,
    verification_ids: &BTreeMap<LocalVerificationTargetId, VerificationTargetId>,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
    violations: &mut Vec<PlannerViolation>,
) {
    let mut targets_seen = BTreeSet::new();
    for replacement in &patch.replace_work_orders {
        let id = replacement.target.id;
        if !targets_seen.insert(id) {
            violations.push(PlannerViolation::WorkOrderOperationConflict { work_order_id: id });
        }
        let Some(current) = next.work_orders.get(&id).cloned() else {
            violations.push(PlannerViolation::UnknownWorkOrder { work_order_id: id });
            continue;
        };
        if current.revision_sha256().ok().as_ref() != Some(&replacement.target.revision_sha256) {
            violations.push(PlannerViolation::StaleWorkOrder { work_order_id: id });
        }
        if !matches!(
            current.state,
            PlannedWorkOrderState::Pending | PlannedWorkOrderState::Failed
        ) {
            violations.push(PlannerViolation::ImmutableWorkOrder {
                work_order_id: id,
                state: current.state,
            });
        }
        let dependencies = resolve_dependencies(
            &replacement.existing_dependencies,
            &replacement.new_dependencies,
            work_ids,
            next,
            violations,
        );
        let verification_targets = resolve_verification_targets(
            &replacement.existing_verification_targets,
            &replacement.new_verification_targets,
            verification_ids,
            next,
            violations,
        );
        validate_work_order_fields(
            Some(id),
            &replacement.objective,
            &replacement.obligations,
            &dependencies,
            &verification_targets,
            replacement.required_access,
            &replacement.basis,
            obligations,
            context,
            policy,
            violations,
        );
        let revision = if let Some(revision) = current.revision.checked_add(1) {
            revision
        } else {
            violations.push(PlannerViolation::WorkOrderRevisionOverflow { work_order_id: id });
            current.revision
        };
        next.work_orders.insert(
            id,
            PlannedWorkOrder {
                id,
                revision,
                objective: replacement.objective.clone(),
                obligations: replacement.obligations.clone(),
                dependencies,
                verification_targets,
                required_access: replacement.required_access,
                state: PlannedWorkOrderState::Pending,
                basis: replacement.basis.clone(),
            },
        );
    }
    for cancellation in &patch.cancel_work_orders {
        let id = cancellation.target.id;
        if !targets_seen.insert(id) {
            violations.push(PlannerViolation::WorkOrderOperationConflict { work_order_id: id });
        }
        validate_basis(
            "cancel_work_order.basis",
            &cancellation.basis,
            context,
            violations,
        );
        let Some(current) = next.work_orders.get_mut(&id) else {
            violations.push(PlannerViolation::UnknownWorkOrder { work_order_id: id });
            continue;
        };
        if current.revision_sha256().ok().as_ref() != Some(&cancellation.target.revision_sha256) {
            violations.push(PlannerViolation::StaleWorkOrder { work_order_id: id });
        }
        if !matches!(
            current.state,
            PlannedWorkOrderState::Pending | PlannedWorkOrderState::Failed
        ) {
            violations.push(PlannerViolation::ImmutableWorkOrder {
                work_order_id: id,
                state: current.state,
            });
        }
        current.state = PlannedWorkOrderState::Cancelled;
        current.revision = if let Some(revision) = current.revision.checked_add(1) {
            revision
        } else {
            violations.push(PlannerViolation::WorkOrderRevisionOverflow { work_order_id: id });
            current.revision
        };
        current.basis = cancellation.basis.clone();
    }
}

fn resolve_dependencies(
    existing: &BTreeSet<PlanWorkOrderId>,
    new: &BTreeSet<LocalWorkOrderId>,
    allocated: &BTreeMap<LocalWorkOrderId, PlanWorkOrderId>,
    plan: &PlanSnapshot,
    violations: &mut Vec<PlannerViolation>,
) -> BTreeSet<PlanWorkOrderId> {
    let mut resolved = BTreeSet::new();
    for id in existing {
        if plan.work_orders.contains_key(id) {
            resolved.insert(*id);
        } else {
            violations.push(PlannerViolation::UnknownWorkOrder { work_order_id: *id });
        }
    }
    for local_id in new {
        if let Some(id) = allocated.get(local_id) {
            resolved.insert(*id);
        } else {
            violations.push(PlannerViolation::UnknownNewWorkOrder {
                local_id: *local_id,
            });
        }
    }
    resolved
}

fn resolve_verification_targets(
    existing: &BTreeSet<VerificationTargetId>,
    new: &BTreeSet<LocalVerificationTargetId>,
    allocated: &BTreeMap<LocalVerificationTargetId, VerificationTargetId>,
    plan: &PlanSnapshot,
    violations: &mut Vec<PlannerViolation>,
) -> BTreeSet<VerificationTargetId> {
    let mut resolved = BTreeSet::new();
    for id in existing {
        if plan.verification_targets.contains_key(id) {
            resolved.insert(*id);
        } else {
            violations.push(PlannerViolation::UnknownVerificationTarget {
                verification_target_id: *id,
            });
        }
    }
    for local_id in new {
        if let Some(id) = allocated.get(local_id) {
            resolved.insert(*id);
        } else {
            violations.push(PlannerViolation::UnknownNewVerificationTarget {
                local_id: *local_id,
            });
        }
    }
    resolved
}

#[allow(clippy::too_many_arguments)]
fn validate_work_order_fields(
    id: Option<PlanWorkOrderId>,
    objective: &str,
    obligations_refs: &BTreeSet<ProtectedObligationRef>,
    dependencies: &BTreeSet<PlanWorkOrderId>,
    verification_targets: &BTreeSet<VerificationTargetId>,
    access: PlannerAccess,
    basis: &DecisionBasis,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
    violations: &mut Vec<PlannerViolation>,
) {
    validate_text("work_order.objective", objective, violations);
    validate_basis("work_order.basis", basis, context, violations);
    validate_obligation_refs(
        "work_order.obligations",
        obligations_refs,
        obligations,
        violations,
    );
    if verification_targets.is_empty() {
        violations.push(PlannerViolation::EmptyVerificationTargets { work_order_id: id });
    }
    if dependencies.len() > HARD_MAX_DEPENDENCIES
        || dependencies.len()
            > usize::try_from(policy.limits.max_dependencies_per_work_order).unwrap_or(usize::MAX)
    {
        violations.push(PlannerViolation::DependencyLimitExceeded {
            maximum: policy.limits.max_dependencies_per_work_order,
            actual: dependencies.len(),
        });
    }
    if access > policy.maximum_access {
        violations.push(PlannerViolation::AccessExpansion { access });
    }
}

fn validate_text(field: &str, value: &str, violations: &mut Vec<PlannerViolation>) {
    if value.trim().is_empty() {
        violations.push(PlannerViolation::EmptyText {
            field: field.to_owned(),
        });
    }
    if value.len() > MAX_FIELD_BYTES {
        violations.push(PlannerViolation::FieldTooLarge {
            field: field.to_owned(),
            maximum: MAX_FIELD_BYTES,
            actual: value.len(),
        });
    }
}

fn validate_basis(
    field: &str,
    basis: &DecisionBasis,
    context: &PlannerContextCatalog,
    violations: &mut Vec<PlannerViolation>,
) {
    validate_text(&format!("{field}.rationale"), &basis.rationale, violations);
    if basis.evidence_ids.is_empty() {
        violations.push(PlannerViolation::EmptyEvidence {
            field: field.to_owned(),
        });
    }
    if basis.evidence_ids.len() > MAX_EVIDENCE_PER_BASIS {
        violations.push(PlannerViolation::EvidenceLimitExceeded {
            field: field.to_owned(),
            maximum: MAX_EVIDENCE_PER_BASIS,
            actual: basis.evidence_ids.len(),
        });
    }
    for evidence_id in &basis.evidence_ids {
        if !context.evidence_ids().contains(evidence_id) {
            violations.push(PlannerViolation::UnknownEvidence {
                evidence_id: evidence_id.clone(),
            });
        }
    }
}

fn validate_obligation_refs(
    field: &str,
    refs: &BTreeSet<ProtectedObligationRef>,
    catalog: &ProtectedObligationCatalog,
    violations: &mut Vec<PlannerViolation>,
) {
    if refs.is_empty() {
        violations.push(PlannerViolation::EmptyObligationSet {
            field: field.to_owned(),
        });
    }
    for obligation_ref in refs {
        let Some(obligation) = catalog.obligations.get(&obligation_ref.id) else {
            violations.push(PlannerViolation::UnknownObligation {
                obligation_id: obligation_ref.id,
            });
            continue;
        };
        if obligation.content_sha256 != obligation_ref.content_sha256 {
            violations.push(PlannerViolation::ObligationDigestMismatch {
                obligation_id: obligation_ref.id,
            });
        }
    }
}

fn plan_invariant_violations(
    plan: &PlanSnapshot,
    obligations: &ProtectedObligationCatalog,
    policy: &PlannerPolicy,
    allow_empty: bool,
    violations: &mut Vec<PlannerViolation>,
) {
    if plan.work_orders.len() > usize::try_from(policy.limits.max_work_orders).unwrap_or(usize::MAX)
    {
        violations.push(PlannerViolation::WorkOrderLimitExceeded {
            maximum: policy.limits.max_work_orders,
            actual: plan.work_orders.len(),
        });
    }
    if plan.verification_targets.len()
        > usize::try_from(policy.limits.max_verification_targets).unwrap_or(usize::MAX)
    {
        violations.push(PlannerViolation::VerificationTargetLimitExceeded {
            maximum: policy.limits.max_verification_targets,
            actual: plan.verification_targets.len(),
        });
    }
    for (id, work) in &plan.work_orders {
        if id != &work.id {
            violations.push(PlannerViolation::BasePlanInvalid);
        }
        if work.required_access > policy.maximum_access {
            violations.push(PlannerViolation::AccessExpansion {
                access: work.required_access,
            });
        }
        for dependency in &work.dependencies {
            match plan.work_orders.get(dependency) {
                None => violations.push(PlannerViolation::UnknownWorkOrder {
                    work_order_id: *dependency,
                }),
                Some(dependency_work)
                    if dependency_work.state == PlannedWorkOrderState::Cancelled =>
                {
                    violations.push(PlannerViolation::DependencyOnCancelled {
                        work_order_id: *id,
                        dependency_id: *dependency,
                    });
                }
                Some(_) => {}
            }
        }
        for target in &work.verification_targets {
            if !plan.verification_targets.contains_key(target) {
                violations.push(PlannerViolation::UnknownVerificationTarget {
                    verification_target_id: *target,
                });
            }
        }
        validate_obligation_refs(
            "plan.work_order.obligations",
            &work.obligations,
            obligations,
            violations,
        );
    }
    for (id, target) in &plan.verification_targets {
        if id != &target.id {
            violations.push(PlannerViolation::BasePlanInvalid);
        }
        validate_obligation_refs(
            "plan.verification_target.obligations",
            &target.obligations,
            obligations,
            violations,
        );
    }
    if dependency_graph_has_cycle(&plan.work_orders) {
        violations.push(PlannerViolation::DependencyCycle);
    }
    if !allow_empty || !plan.work_orders.is_empty() {
        for obligation in obligations
            .obligations
            .values()
            .filter(|item| item.required)
        {
            let covered = plan.work_orders.values().any(|work| {
                work.state != PlannedWorkOrderState::Cancelled
                    && work.obligations.iter().any(|item| item.id == obligation.id)
            });
            if !covered {
                violations.push(PlannerViolation::RequiredObligationUncovered {
                    obligation_id: obligation.id,
                });
            }
        }
    }
}

fn dependency_graph_has_cycle(work_orders: &BTreeMap<PlanWorkOrderId, PlannedWorkOrder>) -> bool {
    fn visit(
        id: PlanWorkOrderId,
        work_orders: &BTreeMap<PlanWorkOrderId, PlannedWorkOrder>,
        active: &mut BTreeSet<PlanWorkOrderId>,
        complete: &mut BTreeSet<PlanWorkOrderId>,
    ) -> bool {
        if complete.contains(&id) {
            return false;
        }
        if !active.insert(id) {
            return true;
        }
        if let Some(work) = work_orders.get(&id) {
            for dependency in &work.dependencies {
                if work_orders.contains_key(dependency)
                    && visit(*dependency, work_orders, active, complete)
                {
                    return true;
                }
            }
        }
        active.remove(&id);
        complete.insert(id);
        false
    }

    let mut active = BTreeSet::new();
    let mut complete = BTreeSet::new();
    work_orders
        .keys()
        .copied()
        .any(|id| visit(id, work_orders, &mut active, &mut complete))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn resolve_directive(
    directive: &PlannerDirective,
    patch: &PlanPatch,
    plan: &PlanSnapshot,
    local_work_ids: &BTreeMap<LocalWorkOrderId, PlanWorkOrderId>,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
    violations: &mut Vec<PlannerViolation>,
) -> Option<ResolvedPlannerDirective> {
    match directive.kind {
        PlannerDirectiveKind::Execute => {
            if !directive.delegations.is_empty()
                || !directive.clarifications.is_empty()
                || !directive.escalations.is_empty()
                || !directive.finish_claims.is_empty()
            {
                violations.push(PlannerViolation::DirectiveShapeMismatch {
                    directive: directive.kind,
                });
            }
            let selected =
                resolve_work_selection(&directive.execute, local_work_ids, plan, violations);
            if selected.len() == 1 {
                let id = selected[0];
                validate_pending_target(id, plan, violations);
                Some(ResolvedPlannerDirective::Execute { work_order_id: id })
            } else {
                violations.push(PlannerViolation::DirectiveShapeMismatch {
                    directive: directive.kind,
                });
                None
            }
        }
        PlannerDirectiveKind::Delegate => {
            if !directive.execute.is_empty()
                || !directive.clarifications.is_empty()
                || !directive.escalations.is_empty()
                || !directive.finish_claims.is_empty()
                || directive.delegations.is_empty()
            {
                violations.push(PlannerViolation::DirectiveShapeMismatch {
                    directive: directive.kind,
                });
            }
            if directive.delegations.len() > HARD_MAX_DELEGATIONS
                || directive.delegations.len()
                    > usize::try_from(policy.limits.max_delegations).unwrap_or(usize::MAX)
            {
                violations.push(PlannerViolation::DelegationLimitExceeded {
                    maximum: policy.limits.max_delegations,
                    actual: directive.delegations.len(),
                });
            }
            let mut selected = BTreeSet::new();
            for (index, delegation) in directive.delegations.iter().enumerate() {
                validate_basis(
                    &format!("directive.delegations[{index}].basis"),
                    &delegation.basis,
                    context,
                    violations,
                );
                let resolved = resolve_work_selection(
                    &delegation.work_orders,
                    local_work_ids,
                    plan,
                    violations,
                );
                if resolved.is_empty() {
                    violations.push(PlannerViolation::DirectiveShapeMismatch {
                        directive: directive.kind,
                    });
                }
                for id in resolved {
                    validate_pending_target(id, plan, violations);
                    if !selected.insert(id) {
                        violations.push(PlannerViolation::DirectiveShapeMismatch {
                            directive: directive.kind,
                        });
                    }
                }
            }
            Some(ResolvedPlannerDirective::Delegate {
                work_order_ids: selected.into_iter().collect(),
            })
        }
        PlannerDirectiveKind::Clarify => {
            if !directive.execute.is_empty()
                || !directive.delegations.is_empty()
                || !directive.escalations.is_empty()
                || !directive.finish_claims.is_empty()
                || directive.clarifications.is_empty()
            {
                violations.push(PlannerViolation::DirectiveShapeMismatch {
                    directive: directive.kind,
                });
            }
            if directive.clarifications.len() > HARD_MAX_QUESTIONS
                || directive.clarifications.len()
                    > usize::try_from(policy.limits.max_questions).unwrap_or(usize::MAX)
            {
                violations.push(PlannerViolation::ClarificationLimitExceeded {
                    maximum: policy.limits.max_questions,
                    actual: directive.clarifications.len(),
                });
            }
            for (index, clarification) in directive.clarifications.iter().enumerate() {
                validate_text(
                    &format!("directive.clarifications[{index}].question"),
                    &clarification.question,
                    violations,
                );
                validate_basis(
                    &format!("directive.clarifications[{index}].basis"),
                    &clarification.basis,
                    context,
                    violations,
                );
                validate_obligation_refs(
                    "directive.clarification.blocked_obligations",
                    &clarification.blocked_obligations,
                    obligations,
                    violations,
                );
            }
            Some(ResolvedPlannerDirective::Clarify {
                requests: directive.clarifications.clone(),
            })
        }
        PlannerDirectiveKind::Escalate => {
            if !directive.execute.is_empty()
                || !directive.delegations.is_empty()
                || !directive.clarifications.is_empty()
                || !directive.finish_claims.is_empty()
                || directive.escalations.is_empty()
            {
                violations.push(PlannerViolation::DirectiveShapeMismatch {
                    directive: directive.kind,
                });
            }
            for (index, escalation) in directive.escalations.iter().enumerate() {
                validate_text(
                    &format!("directive.escalations[{index}].request"),
                    &escalation.request,
                    violations,
                );
                validate_basis(
                    &format!("directive.escalations[{index}].basis"),
                    &escalation.basis,
                    context,
                    violations,
                );
                validate_obligation_refs(
                    "directive.escalation.blocked_obligations",
                    &escalation.blocked_obligations,
                    obligations,
                    violations,
                );
            }
            Some(ResolvedPlannerDirective::Escalate {
                requests: directive.escalations.clone(),
            })
        }
        PlannerDirectiveKind::Finish => {
            if !directive.execute.is_empty()
                || !directive.delegations.is_empty()
                || !directive.clarifications.is_empty()
                || !directive.escalations.is_empty()
                || directive.finish_claims.is_empty()
            {
                violations.push(PlannerViolation::DirectiveShapeMismatch {
                    directive: directive.kind,
                });
            }
            if !patch.is_empty() {
                violations.push(PlannerViolation::FinishRequiresEmptyPatch);
            }
            let mut claimed = BTreeSet::new();
            for claim in &directive.finish_claims {
                validate_single_obligation_ref(&claim.obligation, obligations, violations);
                validate_evidence_set(
                    "directive.finish_claims.evidence_ids",
                    &claim.evidence_ids,
                    context,
                    violations,
                );
                if !claimed.insert(claim.obligation.id) {
                    violations.push(PlannerViolation::DuplicateFinishClaim {
                        obligation_id: claim.obligation.id,
                    });
                }
            }
            for obligation in obligations
                .obligations
                .values()
                .filter(|item| item.required)
            {
                if !claimed.contains(&obligation.id) {
                    violations.push(PlannerViolation::FinishMissingRequiredObligation {
                        obligation_id: obligation.id,
                    });
                }
            }
            Some(ResolvedPlannerDirective::FinishPendingGate {
                claims: directive.finish_claims.clone(),
            })
        }
    }
}

fn resolve_work_selection(
    selection: &WorkSelection,
    local_ids: &BTreeMap<LocalWorkOrderId, PlanWorkOrderId>,
    plan: &PlanSnapshot,
    violations: &mut Vec<PlannerViolation>,
) -> Vec<PlanWorkOrderId> {
    let mut resolved = BTreeSet::new();
    for id in &selection.existing {
        if plan.work_orders.contains_key(id) {
            resolved.insert(*id);
        } else {
            violations.push(PlannerViolation::UnknownWorkOrder { work_order_id: *id });
        }
    }
    for local_id in &selection.new {
        if let Some(id) = local_ids.get(local_id) {
            resolved.insert(*id);
        } else {
            violations.push(PlannerViolation::UnknownNewWorkOrder {
                local_id: *local_id,
            });
        }
    }
    resolved.into_iter().collect()
}

fn validate_pending_target(
    id: PlanWorkOrderId,
    plan: &PlanSnapshot,
    violations: &mut Vec<PlannerViolation>,
) {
    if plan
        .work_orders
        .get(&id)
        .is_none_or(|work| work.state != PlannedWorkOrderState::Pending)
    {
        violations.push(PlannerViolation::DirectiveTargetNotPending { work_order_id: id });
    }
}

fn validate_single_obligation_ref(
    obligation_ref: &ProtectedObligationRef,
    catalog: &ProtectedObligationCatalog,
    violations: &mut Vec<PlannerViolation>,
) {
    let refs = BTreeSet::from([obligation_ref.clone()]);
    validate_obligation_refs("obligation_ref", &refs, catalog, violations);
}

fn validate_evidence_set(
    field: &str,
    evidence_ids: &BTreeSet<PlannerEvidenceId>,
    context: &PlannerContextCatalog,
    violations: &mut Vec<PlannerViolation>,
) {
    if evidence_ids.is_empty() {
        violations.push(PlannerViolation::EmptyEvidence {
            field: field.to_owned(),
        });
    }
    if evidence_ids.len() > MAX_EVIDENCE_PER_BASIS {
        violations.push(PlannerViolation::EvidenceLimitExceeded {
            field: field.to_owned(),
            maximum: MAX_EVIDENCE_PER_BASIS,
            actual: evidence_ids.len(),
        });
    }
    for evidence_id in evidence_ids {
        if !context.evidence_ids().contains(evidence_id) {
            violations.push(PlannerViolation::UnknownEvidence {
                evidence_id: evidence_id.clone(),
            });
        }
    }
}

fn proposal_text_bytes(proposal: &PlannerTurnProposal) -> usize {
    let mut total = proposal
        .patch
        .strategy_summary
        .as_ref()
        .map_or(0, String::len);
    for target in &proposal.patch.add_verification_targets {
        total = total
            .saturating_add(target.statement.len())
            .saturating_add(target.basis.rationale.len());
    }
    for work in &proposal.patch.add_work_orders {
        total = total
            .saturating_add(work.objective.len())
            .saturating_add(work.basis.rationale.len());
    }
    for work in &proposal.patch.replace_work_orders {
        total = total
            .saturating_add(work.objective.len())
            .saturating_add(work.basis.rationale.len());
    }
    for work in &proposal.patch.cancel_work_orders {
        total = total.saturating_add(work.basis.rationale.len());
    }
    for delegation in &proposal.directive.delegations {
        total = total.saturating_add(delegation.basis.rationale.len());
    }
    for clarification in &proposal.directive.clarifications {
        total = total
            .saturating_add(clarification.question.len())
            .saturating_add(clarification.basis.rationale.len());
    }
    for escalation in &proposal.directive.escalations {
        total = total
            .saturating_add(escalation.request.len())
            .saturating_add(escalation.basis.rationale.len());
    }
    total
}

/// Exact inference request and reservation acknowledged before backend work.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerAttemptPrepared {
    pub execution_id: PlannerExecutionId,
    pub attempt_id: PlannerAttemptId,
    pub parent_attempt_id: Option<PlannerAttemptId>,
    pub budget_reservation_id: BudgetReservationId,
    pub backend_id: BackendId,
    pub model_id: ModelId,
    pub max_output_tokens: u32,
    pub base_plan_sha256: PlannerDigest,
    pub obligation_snapshot_sha256: PlannerDigest,
    pub acceptance_policy_sha256: PlannerDigest,
    pub context_manifest_sha256: PlannerDigest,
    pub planner_policy_sha256: PlannerDigest,
    pub request_sha256: PlannerDigest,
    pub request: StructuredInferenceRequest,
    /// Exact authority snapshots required to replay the deterministic decision
    /// after a crash. Their independently repeated digests above make corrupt
    /// or substituted snapshots fail closed.
    pub base_plan: Box<PlanSnapshot>,
    pub obligations: Box<ProtectedObligationCatalog>,
    pub context: Box<PlannerContextCatalog>,
    pub policy: Box<PlannerPolicy>,
}

impl PlannerAttemptPrepared {
    fn sha256(&self) -> Result<PlannerDigest, PlannerContractError> {
        digest_of(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PlannerInferenceObservation {
    Response {
        response: Box<StructuredInferenceResponse>,
    },
    Error {
        error: BackendError,
    },
}

/// Backend outcome retained after a previously acknowledged preparation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerAttemptObserved {
    pub execution_id: PlannerExecutionId,
    pub attempt_id: PlannerAttemptId,
    pub prepared_sha256: PlannerDigest,
    pub observation: PlannerInferenceObservation,
}

impl PlannerAttemptObserved {
    fn sha256(&self) -> Result<PlannerDigest, PlannerContractError> {
        digest_of(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerResponseViolation {
    ModelIdentityMismatch,
    BackendIdentityMismatch,
    RawTextIsNotJson,
    RawTextValueMismatch,
    OutputTokenLimitExceeded { maximum: u64, actual: u64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerRejection {
    Backend,
    ResponseContract {
        violations: Vec<PlannerResponseViolation>,
    },
    OutputDecode {
        message: String,
    },
    PlanValidation {
        violations: Vec<PlannerViolation>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerAttemptAccepted {
    pub execution_id: PlannerExecutionId,
    pub attempt_id: PlannerAttemptId,
    pub observed_sha256: PlannerDigest,
    pub proposal_sha256: PlannerDigest,
    pub result: ValidatedPlannerTurn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerAttemptRejected {
    pub execution_id: PlannerExecutionId,
    pub attempt_id: PlannerAttemptId,
    pub observed_sha256: PlannerDigest,
    pub rejection: PlannerRejection,
}

/// Append-only planner lifecycle record.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum PlannerJournalRecord {
    Prepared(PlannerAttemptPrepared),
    Observed(PlannerAttemptObserved),
    Accepted(PlannerAttemptAccepted),
    Rejected(PlannerAttemptRejected),
}

impl PlannerJournalRecord {
    #[must_use]
    pub const fn attempt_id(&self) -> PlannerAttemptId {
        match self {
            Self::Prepared(record) => record.attempt_id,
            Self::Observed(record) => record.attempt_id,
            Self::Accepted(record) => record.attempt_id,
            Self::Rejected(record) => record.attempt_id,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct PlannerJournalError {
    pub message: String,
}

impl PlannerJournalError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Durability and budget-reservation boundary for planner attempts.
pub trait PlannerJournal: Send + Sync {
    /// Retains one transition according to the journal's durability contract.
    ///
    /// A `Prepared` acknowledgement must atomically reserve the declared token
    /// ceiling before returning. The executor will call no backend before it
    /// receives that acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error unless the transition is durably accepted.
    fn retain(&self, record: &PlannerJournalRecord) -> Result<(), PlannerJournalError>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum PlannerAttemptProjection {
    /// A crash may have happened before, during, or after the external call.
    /// No inference retry or plan application is safe until reconciliation.
    ReconciliationRequired {
        prepared: Box<PlannerAttemptPrepared>,
    },
    /// The external outcome exists; deterministic validation may be replayed
    /// without calling the model again.
    ObservedPendingDecision {
        prepared: Box<PlannerAttemptPrepared>,
        observed: Box<PlannerAttemptObserved>,
    },
    Accepted {
        prepared: Box<PlannerAttemptPrepared>,
        observed: Box<PlannerAttemptObserved>,
        accepted: Box<PlannerAttemptAccepted>,
    },
    Rejected {
        prepared: Box<PlannerAttemptPrepared>,
        observed: Box<PlannerAttemptObserved>,
        rejected: Box<PlannerAttemptRejected>,
    },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PlannerJournalProjection {
    pub attempts: BTreeMap<PlannerAttemptId, PlannerAttemptProjection>,
}

impl PlannerJournalProjection {
    /// Rebuilds attempt state without invoking a backend.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicate, out-of-order, or hash-unbound transitions.
    #[allow(clippy::too_many_lines)]
    pub fn replay(records: &[PlannerJournalRecord]) -> Result<Self, PlannerJournalError> {
        if records.len() > HARD_MAX_ACTIVE_JOURNAL_RECORDS {
            return Err(PlannerJournalError::new(
                "active planner journal exceeds its hard record limit; durable archival is required",
            ));
        }
        let mut attempts = BTreeMap::new();
        let mut reservations = BTreeSet::new();
        let mut executions = BTreeSet::new();
        for record in records {
            match record {
                PlannerJournalRecord::Prepared(prepared) => {
                    if !prepared_is_internally_valid(prepared)? {
                        return Err(PlannerJournalError::new(
                            "planner preparation does not bind its request and authority snapshots",
                        ));
                    }
                    if !reservations.insert(prepared.budget_reservation_id) {
                        return Err(PlannerJournalError::new(
                            "planner budget reservation is reused",
                        ));
                    }
                    // A new model call after any possible/observed outcome needs
                    // an explicit durable reconciliation/retry authorization.
                    // That record is deliberately not part of v1, so retries
                    // fail closed instead of treating parent_attempt_id as
                    // authority supplied by the caller.
                    if prepared.parent_attempt_id.is_some() {
                        return Err(PlannerJournalError::new(
                            "planner retry requires an explicit durable retry authorization record",
                        ));
                    }
                    if !executions.insert(prepared.execution_id) {
                        return Err(PlannerJournalError::new(
                            "planner execution may contain exactly one root preparation",
                        ));
                    }
                    if attempts
                        .insert(
                            prepared.attempt_id,
                            PlannerAttemptProjection::ReconciliationRequired {
                                prepared: Box::new(prepared.clone()),
                            },
                        )
                        .is_some()
                    {
                        return Err(PlannerJournalError::new("duplicate planner preparation"));
                    }
                }
                PlannerJournalRecord::Observed(observed) => {
                    let Some(state) = attempts.get_mut(&observed.attempt_id) else {
                        return Err(PlannerJournalError::new(
                            "planner observation has no preparation",
                        ));
                    };
                    let PlannerAttemptProjection::ReconciliationRequired { prepared } = state
                    else {
                        return Err(PlannerJournalError::new(
                            "planner observation is duplicated or out of order",
                        ));
                    };
                    if prepared.execution_id != observed.execution_id
                        || prepared
                            .sha256()
                            .map_err(|error| contract_journal_error(&error))?
                            != observed.prepared_sha256
                    {
                        return Err(PlannerJournalError::new(
                            "planner observation does not bind its preparation",
                        ));
                    }
                    *state = PlannerAttemptProjection::ObservedPendingDecision {
                        prepared: prepared.clone(),
                        observed: Box::new(observed.clone()),
                    };
                }
                PlannerJournalRecord::Accepted(accepted) => {
                    let Some(state) = attempts.get_mut(&accepted.attempt_id) else {
                        return Err(PlannerJournalError::new(
                            "planner acceptance has no observation",
                        ));
                    };
                    let PlannerAttemptProjection::ObservedPendingDecision { prepared, observed } =
                        state
                    else {
                        return Err(PlannerJournalError::new(
                            "planner acceptance is duplicated or out of order",
                        ));
                    };
                    if prepared.execution_id != accepted.execution_id
                        || observed
                            .sha256()
                            .map_err(|error| contract_journal_error(&error))?
                            != accepted.observed_sha256
                    {
                        return Err(PlannerJournalError::new(
                            "planner acceptance does not bind its observation",
                        ));
                    }
                    let ReplayedPlannerDecision::Accepted {
                        proposal_sha256,
                        result,
                    } = replay_planner_decision(prepared, observed)?
                    else {
                        return Err(PlannerJournalError::new(
                            "planner acceptance contradicts the observed deterministic decision",
                        ));
                    };
                    if accepted.proposal_sha256 != proposal_sha256
                        || &accepted.result != result.as_ref()
                    {
                        return Err(PlannerJournalError::new(
                            "planner acceptance contains a fabricated proposal or result",
                        ));
                    }
                    *state = PlannerAttemptProjection::Accepted {
                        prepared: prepared.clone(),
                        observed: observed.clone(),
                        accepted: Box::new(accepted.clone()),
                    };
                }
                PlannerJournalRecord::Rejected(rejected) => {
                    let Some(state) = attempts.get_mut(&rejected.attempt_id) else {
                        return Err(PlannerJournalError::new(
                            "planner rejection has no observation",
                        ));
                    };
                    let PlannerAttemptProjection::ObservedPendingDecision { prepared, observed } =
                        state
                    else {
                        return Err(PlannerJournalError::new(
                            "planner rejection is duplicated or out of order",
                        ));
                    };
                    if prepared.execution_id != rejected.execution_id
                        || observed
                            .sha256()
                            .map_err(|error| contract_journal_error(&error))?
                            != rejected.observed_sha256
                    {
                        return Err(PlannerJournalError::new(
                            "planner rejection does not bind its observation",
                        ));
                    }
                    let ReplayedPlannerDecision::Rejected(expected_rejection) =
                        replay_planner_decision(prepared, observed)?
                    else {
                        return Err(PlannerJournalError::new(
                            "planner rejection contradicts the observed deterministic decision",
                        ));
                    };
                    if rejected.rejection != expected_rejection {
                        return Err(PlannerJournalError::new(
                            "planner rejection does not match the observed deterministic decision",
                        ));
                    }
                    *state = PlannerAttemptProjection::Rejected {
                        prepared: prepared.clone(),
                        observed: observed.clone(),
                        rejected: Box::new(rejected.clone()),
                    };
                }
            }
        }
        Ok(Self { attempts })
    }
}

fn prepared_is_internally_valid(
    prepared: &PlannerAttemptPrepared,
) -> Result<bool, PlannerJournalError> {
    let request_sha256 =
        digest_of(&prepared.request).map_err(|error| contract_journal_error(&error))?;
    let base_plan_sha256 = prepared
        .base_plan
        .sha256()
        .map_err(|error| contract_journal_error(&error))?;
    Ok(prepared.request.model_id() == &prepared.model_id
        && prepared.request.max_output_tokens() == prepared.max_output_tokens
        && request_sha256 == prepared.request_sha256
        && base_plan_sha256 == prepared.base_plan_sha256
        && prepared.obligations.snapshot_sha256() == &prepared.obligation_snapshot_sha256
        && prepared.obligations.acceptance_policy_sha256() == &prepared.acceptance_policy_sha256
        && prepared.context.manifest_sha256() == &prepared.context_manifest_sha256
        && prepared.policy.policy_sha256() == &prepared.planner_policy_sha256
        && planner_setup_violations(
            &prepared.base_plan,
            &prepared.obligations,
            &prepared.context,
            &prepared.policy,
        )
        .is_empty())
}

enum ReplayedPlannerDecision {
    Accepted {
        proposal_sha256: PlannerDigest,
        result: Box<ValidatedPlannerTurn>,
    },
    Rejected(PlannerRejection),
}

fn replay_planner_decision(
    prepared: &PlannerAttemptPrepared,
    observed: &PlannerAttemptObserved,
) -> Result<ReplayedPlannerDecision, PlannerJournalError> {
    let PlannerInferenceObservation::Response { response } = &observed.observation else {
        return Ok(ReplayedPlannerDecision::Rejected(PlannerRejection::Backend));
    };
    let response_violations = planner_response_violations(
        response,
        &prepared.model_id,
        &prepared.backend_id,
        prepared.max_output_tokens,
    );
    if !response_violations.is_empty() {
        return Ok(ReplayedPlannerDecision::Rejected(
            PlannerRejection::ResponseContract {
                violations: response_violations,
            },
        ));
    }
    let proposal = match serde_json::from_value::<PlannerTurnProposal>(response.value.clone()) {
        Ok(proposal) => proposal,
        Err(error) => {
            return Ok(ReplayedPlannerDecision::Rejected(
                PlannerRejection::OutputDecode {
                    message: error.to_string(),
                },
            ));
        }
    };
    let proposal_sha256 = digest_of(&proposal).map_err(|error| contract_journal_error(&error))?;
    match proposal.validate_and_apply(
        &prepared.base_plan,
        &prepared.obligations,
        &prepared.context,
        &prepared.policy,
    ) {
        Ok(result) => Ok(ReplayedPlannerDecision::Accepted {
            proposal_sha256,
            result: Box::new(result),
        }),
        Err(error) => Ok(ReplayedPlannerDecision::Rejected(
            PlannerRejection::PlanValidation {
                violations: error.violations,
            },
        )),
    }
}

#[derive(Debug, Default)]
pub struct InMemoryPlannerJournal {
    records: Mutex<Vec<PlannerJournalRecord>>,
}

impl InMemoryPlannerJournal {
    /// Returns acknowledged records in order.
    ///
    /// # Errors
    ///
    /// Returns an error when the in-memory lock was poisoned.
    pub fn snapshot(&self) -> Result<Vec<PlannerJournalRecord>, PlannerJournalError> {
        self.records
            .lock()
            .map(|records| records.clone())
            .map_err(|_| PlannerJournalError::new("planner journal lock was poisoned"))
    }

    /// Rebuilds the current attempt projection.
    ///
    /// # Errors
    ///
    /// Returns an error for poisoned storage or an invalid event sequence.
    pub fn projection(&self) -> Result<PlannerJournalProjection, PlannerJournalError> {
        PlannerJournalProjection::replay(&self.snapshot()?)
    }
}

impl PlannerJournal for InMemoryPlannerJournal {
    fn retain(&self, record: &PlannerJournalRecord) -> Result<(), PlannerJournalError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PlannerJournalError::new("planner journal lock was poisoned"))?;
        let mut candidate = records.clone();
        candidate.push(record.clone());
        PlannerJournalProjection::replay(&candidate)?;
        records.push(record.clone());
        Ok(())
    }
}

/// Complete authoritative inputs for one planner inference attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannerExecutionRequest {
    pub execution_id: PlannerExecutionId,
    pub attempt_id: PlannerAttemptId,
    pub parent_attempt_id: Option<PlannerAttemptId>,
    pub budget_reservation_id: BudgetReservationId,
    pub inference: StructuredInferenceRequest,
    pub base_plan: PlanSnapshot,
    pub obligations: ProtectedObligationCatalog,
    pub context: PlannerContextCatalog,
    pub policy: PlannerPolicy,
}

impl PlannerExecutionRequest {
    #[must_use]
    pub fn new(
        inference: StructuredInferenceRequest,
        base_plan: PlanSnapshot,
        obligations: ProtectedObligationCatalog,
        context: PlannerContextCatalog,
        policy: PlannerPolicy,
    ) -> Self {
        Self {
            execution_id: PlannerExecutionId::new(),
            attempt_id: PlannerAttemptId::new(),
            parent_attempt_id: None,
            budget_reservation_id: BudgetReservationId::new(),
            inference,
            base_plan,
            obligations,
            context,
            policy,
        }
    }

    /// Records caller intent only. Journal v1 deliberately rejects parented
    /// preparations because no typed durable retry/reconciliation
    /// authorization record exists yet; this cannot authorize another call.
    #[must_use]
    pub const fn with_parent_attempt(mut self, parent_attempt_id: PlannerAttemptId) -> Self {
        self.parent_attempt_id = Some(parent_attempt_id);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PlannerExecutionStatus {
    Accepted { result: ValidatedPlannerTurn },
    Rejected { rejection: PlannerRejection },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerExecution {
    pub prepared: PlannerAttemptPrepared,
    pub observed: PlannerAttemptObserved,
    pub status: PlannerExecutionStatus,
}

#[derive(Debug, Error)]
pub enum PlannerExecutionError {
    #[error("planner setup is invalid: {violations:?}")]
    Setup { violations: Vec<PlannerViolation> },
    #[error("planner preparation was not acknowledged: {message}")]
    PreparationUnacknowledged { message: String },
    #[error(
        "planner outcome for attempt {attempt_id} was not acknowledged; reconciliation is required: {message}"
    )]
    ObservationUnacknowledged {
        attempt_id: PlannerAttemptId,
        message: String,
    },
    #[error(
        "planner decision for attempt {attempt_id} was not acknowledged; replay the observed outcome: {message}"
    )]
    DecisionUnacknowledged {
        attempt_id: PlannerAttemptId,
        message: String,
    },
    #[error("planner provenance encoding failed: {0}")]
    Encoding(String),
}

/// Runs one prepared, observed, and durably decided planner attempt.
pub struct PlannerExecutor<'a, B: ModelBackend + ?Sized, J: PlannerJournal + ?Sized> {
    backend: &'a B,
    journal: &'a J,
}

impl<'a, B, J> PlannerExecutor<'a, B, J>
where
    B: ModelBackend + ?Sized,
    J: PlannerJournal + ?Sized,
{
    #[must_use]
    pub const fn new(backend: &'a B, journal: &'a J) -> Self {
        Self { backend, journal }
    }

    /// Executes exactly one inference after durable preparation.
    ///
    /// # Errors
    ///
    /// Returns before inference for invalid authoritative inputs or failed
    /// preparation. Once the backend is called, a failed observation
    /// acknowledgement explicitly requires reconciliation and no plan is
    /// returned. Accepted and rejected decisions are also journal-gated.
    #[allow(clippy::too_many_lines)]
    pub async fn execute(
        &self,
        request: PlannerExecutionRequest,
    ) -> Result<PlannerExecution, PlannerExecutionError> {
        let setup_violations = planner_setup_violations(
            &request.base_plan,
            &request.obligations,
            &request.context,
            &request.policy,
        );
        if !setup_violations.is_empty() {
            return Err(PlannerExecutionError::Setup {
                violations: setup_violations,
            });
        }

        let base_plan_sha256 = request
            .base_plan
            .sha256()
            .map_err(|error| PlannerExecutionError::Encoding(error.to_string()))?;
        let request_sha256 = digest_of(&request.inference)
            .map_err(|error| PlannerExecutionError::Encoding(error.to_string()))?;
        let prepared = PlannerAttemptPrepared {
            execution_id: request.execution_id,
            attempt_id: request.attempt_id,
            parent_attempt_id: request.parent_attempt_id,
            budget_reservation_id: request.budget_reservation_id,
            backend_id: self.backend.backend_id().clone(),
            model_id: request.inference.model_id().clone(),
            max_output_tokens: request.inference.max_output_tokens(),
            base_plan_sha256,
            obligation_snapshot_sha256: request.obligations.snapshot_sha256.clone(),
            acceptance_policy_sha256: request.obligations.acceptance_policy_sha256.clone(),
            context_manifest_sha256: request.context.manifest_sha256().clone(),
            planner_policy_sha256: request.policy.policy_sha256.clone(),
            request_sha256,
            request: request.inference.clone(),
            base_plan: Box::new(request.base_plan.clone()),
            obligations: Box::new(request.obligations.clone()),
            context: Box::new(request.context.clone()),
            policy: Box::new(request.policy.clone()),
        };
        self.journal
            .retain(&PlannerJournalRecord::Prepared(prepared.clone()))
            .map_err(|error| PlannerExecutionError::PreparationUnacknowledged {
                message: error.message,
            })?;

        // Calling the backend itself may allocate or start work, so it occurs
        // strictly after the journal acknowledgement above, not merely after a
        // future is constructed.
        let backend_result = self.backend.infer_structured(request.inference).await;
        let observation = match backend_result {
            Ok(response) => PlannerInferenceObservation::Response {
                response: Box::new(response),
            },
            Err(error) => PlannerInferenceObservation::Error { error },
        };
        let prepared_sha256 = prepared
            .sha256()
            .map_err(|error| PlannerExecutionError::Encoding(error.to_string()))?;
        let observed = PlannerAttemptObserved {
            execution_id: request.execution_id,
            attempt_id: request.attempt_id,
            prepared_sha256,
            observation,
        };
        self.journal
            .retain(&PlannerJournalRecord::Observed(observed.clone()))
            .map_err(|error| PlannerExecutionError::ObservationUnacknowledged {
                attempt_id: request.attempt_id,
                message: error.message,
            })?;

        let observed_sha256 = observed
            .sha256()
            .map_err(|error| PlannerExecutionError::Encoding(error.to_string()))?;
        let PlannerInferenceObservation::Response { response } = &observed.observation else {
            return self.rejected_execution(
                prepared,
                observed,
                observed_sha256,
                PlannerRejection::Backend,
            );
        };

        let response_violations = planner_response_violations(
            response,
            &prepared.model_id,
            &prepared.backend_id,
            prepared.max_output_tokens,
        );
        if !response_violations.is_empty() {
            return self.rejected_execution(
                prepared,
                observed,
                observed_sha256,
                PlannerRejection::ResponseContract {
                    violations: response_violations,
                },
            );
        }

        let proposal = match serde_json::from_value::<PlannerTurnProposal>(response.value.clone()) {
            Ok(proposal) => proposal,
            Err(error) => {
                return self.rejected_execution(
                    prepared,
                    observed,
                    observed_sha256,
                    PlannerRejection::OutputDecode {
                        message: error.to_string(),
                    },
                );
            }
        };
        let proposal_sha256 = digest_of(&proposal)
            .map_err(|error| PlannerExecutionError::Encoding(error.to_string()))?;
        let result = match proposal.validate_and_apply(
            &request.base_plan,
            &request.obligations,
            &request.context,
            &request.policy,
        ) {
            Ok(result) => result,
            Err(error) => {
                return self.rejected_execution(
                    prepared,
                    observed,
                    observed_sha256,
                    PlannerRejection::PlanValidation {
                        violations: error.violations,
                    },
                );
            }
        };
        let accepted = PlannerAttemptAccepted {
            execution_id: request.execution_id,
            attempt_id: request.attempt_id,
            observed_sha256,
            proposal_sha256,
            result: result.clone(),
        };
        self.journal
            .retain(&PlannerJournalRecord::Accepted(accepted))
            .map_err(|error| PlannerExecutionError::DecisionUnacknowledged {
                attempt_id: request.attempt_id,
                message: error.message,
            })?;
        Ok(PlannerExecution {
            prepared,
            observed,
            status: PlannerExecutionStatus::Accepted { result },
        })
    }

    fn rejected_execution(
        &self,
        prepared: PlannerAttemptPrepared,
        observed: PlannerAttemptObserved,
        observed_sha256: PlannerDigest,
        rejection: PlannerRejection,
    ) -> Result<PlannerExecution, PlannerExecutionError> {
        let rejected = PlannerAttemptRejected {
            execution_id: prepared.execution_id,
            attempt_id: prepared.attempt_id,
            observed_sha256,
            rejection: rejection.clone(),
        };
        self.journal
            .retain(&PlannerJournalRecord::Rejected(rejected))
            .map_err(|error| PlannerExecutionError::DecisionUnacknowledged {
                attempt_id: prepared.attempt_id,
                message: error.message,
            })?;
        Ok(PlannerExecution {
            prepared,
            observed,
            status: PlannerExecutionStatus::Rejected { rejection },
        })
    }
}

fn planner_setup_violations(
    plan: &PlanSnapshot,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
) -> Vec<PlannerViolation> {
    let mut violations = Vec::new();
    if !policy.is_internally_valid() {
        violations.push(PlannerViolation::PolicySnapshotInvalid);
    }
    if !obligations.is_internally_valid() {
        violations.push(PlannerViolation::ObligationCatalogInvalid);
    }
    if !context.is_internally_valid() {
        violations.push(PlannerViolation::ContextCatalogInvalid);
    }
    if plan.schema_version != PLAN_SCHEMA_VERSION
        || plan.obligation_snapshot_sha256 != obligations.snapshot_sha256
        || plan.acceptance_policy_sha256 != obligations.acceptance_policy_sha256
    {
        violations.push(PlannerViolation::BasePlanInvalid);
    }
    if plan.revision > 0 || !plan.work_orders.is_empty() {
        plan_invariant_violations(plan, obligations, policy, false, &mut violations);
    }
    violations
}

fn planner_response_violations(
    response: &StructuredInferenceResponse,
    expected_model: &ModelId,
    expected_backend: &BackendId,
    max_output_tokens: u32,
) -> Vec<PlannerResponseViolation> {
    let mut violations = Vec::new();
    if &response.model_id != expected_model {
        violations.push(PlannerResponseViolation::ModelIdentityMismatch);
    }
    if &response.evidence.backend_id != expected_backend {
        violations.push(PlannerResponseViolation::BackendIdentityMismatch);
    }
    match serde_json::from_str::<serde_json::Value>(&response.raw_text) {
        Ok(value) if value != response.value => {
            violations.push(PlannerResponseViolation::RawTextValueMismatch);
        }
        Err(_) => violations.push(PlannerResponseViolation::RawTextIsNotJson),
        Ok(_) => {}
    }
    if let Some(actual) = response
        .usage
        .as_ref()
        .and_then(|usage| usage.output_tokens)
    {
        let maximum = u64::from(max_output_tokens);
        if actual > maximum {
            violations.push(PlannerResponseViolation::OutputTokenLimitExceeded { maximum, actual });
        }
    }
    violations
}

fn contract_journal_error(error: &PlannerContractError) -> PlannerJournalError {
    PlannerJournalError::new(error.to_string())
}

fn valid_limits(limits: PlannerLimits) -> bool {
    limits.max_work_orders > 0
        && usize::try_from(limits.max_work_orders).is_ok_and(|value| value <= HARD_MAX_WORK_ORDERS)
        && limits.max_verification_targets > 0
        && usize::try_from(limits.max_verification_targets)
            .is_ok_and(|value| value <= HARD_MAX_VERIFICATION_TARGETS)
        && limits.max_patch_operations > 0
        && usize::try_from(limits.max_patch_operations)
            .is_ok_and(|value| value <= HARD_MAX_PATCH_OPERATIONS)
        && limits.max_dependencies_per_work_order > 0
        && usize::try_from(limits.max_dependencies_per_work_order)
            .is_ok_and(|value| value <= HARD_MAX_DEPENDENCIES)
        && limits.max_delegations > 0
        && usize::try_from(limits.max_delegations).is_ok_and(|value| value <= HARD_MAX_DELEGATIONS)
        && limits.max_questions > 0
        && usize::try_from(limits.max_questions).is_ok_and(|value| value <= HARD_MAX_QUESTIONS)
        && limits.max_text_bytes > 0
        && limits.max_text_bytes <= HARD_MAX_TEXT_BYTES as u64
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn digest_of(value: &impl Serialize) -> Result<PlannerDigest, PlannerContractError> {
    serde_json::to_vec(value)
        .map(|bytes| PlannerDigest::of_bytes(&bytes))
        .map_err(|error| PlannerContractError::Encoding(error.to_string()))
}
