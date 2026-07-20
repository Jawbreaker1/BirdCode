//! Provider-neutral, schema-validated application prompt contracts.
//!
//! Prompt manifests are application data. Compilation keeps the immutable
//! policy separate from user, repository, tool, and external data; this crate
//! deliberately contains no local semantic classifier or heuristic fallback.

mod canonical;
mod compiler;
mod manifest;
mod plan_critic;
mod plan_repair;
mod root_planner;
mod router;

pub use compiler::{
    CanonicalJson, CompiledMessage, CompiledPrompt, DataProvenance, DataSection,
    ManifestProvenance, MessageContent, MessageProvenance, MessageRole, PromptInvocation,
    PromptLimits, RuntimeConstraint, SourceKind, TrustLevel,
};
pub use manifest::{
    MANIFEST_SCHEMA_JSON, PLAN_CRITIC_MANIFEST_JSON, PLAN_REPAIR_MANIFEST_JSON, PromptError,
    PromptId, PromptKey, PromptManifest, PromptRegistry, PromptRole, ROOT_PLANNER_MANIFEST_JSON,
    TASK_ROUTER_MANIFEST_JSON, TASK_ROUTER_MANIFEST_V1_0_0_JSON, TASK_ROUTER_MANIFEST_V1_1_0_JSON,
    TASK_ROUTER_MANIFEST_V1_1_1_JSON, TASK_ROUTER_MANIFEST_V1_1_2_JSON, builtin_registry,
    parse_manifest,
};
pub use plan_critic::{
    ObligationAssessment, ObligationAssessmentStatus,
    PLAN_CRITIC_POLICY_V1_MAX_EVIDENCE_REFERENCES, PLAN_CRITIC_POLICY_V1_MAX_FINDINGS,
    PlanCriticBindingField, PlanCriticBindings, PlanCriticFinding, PlanCriticFindingCategory,
    PlanCriticFindingSeverity, PlanCriticInvariantViolation, PlanCriticOutput, PlanCriticPolicy,
    PlanCriticPolicyMaterial, PlanCriticPolicyViolation, PlanCriticVerdict,
    derive_plan_critic_policy_v1, plan_critic_key, validate_plan_critic_output,
};
pub use plan_repair::{plan_repair_key, validate_plan_repair_output};
pub use root_planner::{
    ObligationReferenceSite, PlannerDigestField, ProposedVerificationTarget, ProtectedObligation,
    ProtectedObligationRef, ProtectedObligationViolation, RootPlannerDecisionEvidence,
    RootPlannerDirective, RootPlannerEscalationRequest, RootPlannerInvariantViolation,
    RootPlannerOutput, RootPlannerPolicy, RootPlannerPolicyViolation, RootPlannerRejectionClass,
    RootPlannerWorkOrder, VerificationKind, classify_root_planner_rejection, root_planner_key,
    validate_root_planner_output,
};
pub use router::{
    RequiredAccess, RouteAction, RouteEvidence, RouteStrategy, RouterInvariantViolation,
    SuggestedSubtask, TaskRouterOutput, task_router_key,
};
