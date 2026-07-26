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
mod planner_replanner;
mod planner_replanner_v2;
mod repository_explorer;
mod repository_reviewer;
mod root_planner;
mod router;

pub use compiler::{
    CanonicalJson, CompiledMessage, CompiledPrompt, DataProvenance, DataSection,
    ManifestProvenance, MessageContent, MessageProvenance, MessageRole, PromptInvocation,
    PromptLimits, RuntimeConstraint, SourceKind, TrustLevel,
};
pub use manifest::{
    MANIFEST_SCHEMA_JSON, PLAN_CRITIC_MANIFEST_JSON, PLAN_REPAIR_MANIFEST_JSON,
    PLANNER_REPLANNER_MANIFEST_JSON, PLANNER_REPLANNER_V2_MANIFEST_JSON, PromptError, PromptId,
    PromptKey, PromptManifest, PromptRegistry, PromptRole, REPOSITORY_EXPLORER_MANIFEST_JSON,
    REPOSITORY_REVIEWER_MANIFEST_JSON, ROOT_PLANNER_MANIFEST_JSON, TASK_ROUTER_MANIFEST_JSON,
    TASK_ROUTER_MANIFEST_V1_0_0_JSON, TASK_ROUTER_MANIFEST_V1_1_0_JSON,
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
pub use planner_replanner::{
    PlannerChildExecutionBinding, PlannerChildFindingConfidence, PlannerChildHandoff,
    PlannerChildHandoffEvidenceBinding, PlannerChildHandoffFinding,
    PlannerChildHandoffRecommendedFollowup, PlannerChildHandoffStatus, PlannerChildHandoffUnknown,
    PlannerEvidenceArtifactRef, PlannerEvidenceEntry, PlannerEvidenceEntryMaterial,
    PlannerEvidenceKind, PlannerEvidencePacket, PlannerEvidencePacketViolation,
    PlannerReplannerAccess, PlannerReplannerBindings, PlannerReplannerCancelWorkOrder,
    PlannerReplannerClarificationRequest, PlannerReplannerDecisionBasis,
    PlannerReplannerDelegationRequest, PlannerReplannerDirective, PlannerReplannerDirectiveKind,
    PlannerReplannerEscalationKind, PlannerReplannerEscalationRequest, PlannerReplannerFinishClaim,
    PlannerReplannerInvariantViolation, PlannerReplannerInvocationMaterial,
    PlannerReplannerLocalVerificationTargetId, PlannerReplannerLocalWorkOrderId,
    PlannerReplannerNewVerificationTarget, PlannerReplannerNewWorkOrder,
    PlannerReplannerObligationRef, PlannerReplannerOutput, PlannerReplannerPlanPatch,
    PlannerReplannerProtectedWorkOrderRef, PlannerReplannerReplaceWorkOrder,
    PlannerReplannerWorkSelection, planner_replanner_invocation, planner_replanner_key,
    validate_planner_replanner_invocation, validate_planner_replanner_output,
};
pub use planner_replanner_v2::{
    PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS, PlannerAcceptedRootPlanEvidenceV2,
    PlannerChildCancellationCauseV2, PlannerChildCancelledV2, PlannerChildFailedV2,
    PlannerChildFailureCauseV2, PlannerChildFailureKindV2, PlannerChildRetryDispositionV2,
    PlannerReplannerV2AuthoritativeParts, PlannerReplannerV2Bindings,
    PlannerReplannerV2ContextCatalog, PlannerReplannerV2ContextEvidenceBinding,
    PlannerReplannerV2EvidenceBinding, PlannerReplannerV2EvidenceDelta,
    PlannerReplannerV2EvidenceEntry, PlannerReplannerV2EvidenceKind,
    PlannerReplannerV2EvidenceMaterial, PlannerReplannerV2EvidencePacket,
    PlannerReplannerV2EvidenceViolation, PlannerReplannerV2InvariantViolation,
    PlannerReplannerV2InvocationMaterial, PlannerReplannerV2Output, PlannerReplannerV2PlanSnapshot,
    PlannerReplannerV2PlannedWorkOrder, PlannerReplannerV2PlannedWorkOrderState,
    PlannerReplannerV2Policy, PlannerReplannerV2PolicyLimits,
    PlannerReplannerV2ProtectedObligation, PlannerReplannerV2ProtectedObligationCatalog,
    PlannerReplannerV2Purpose, PlannerReplannerV2Reasoning, PlannerReplannerV2VerificationTarget,
    PlannerVerifiedChildHandoffV2, planner_replanner_v2_invocation, planner_replanner_v2_key,
    validate_planner_replanner_v2_invocation, validate_planner_replanner_v2_output,
};
pub use repository_explorer::{
    ExplorerArtifactBinding, ExplorerAuthority, ExplorerBindingField, ExplorerEvidenceRef,
    ExplorerFinding, ExplorerHandoffStatus, ExplorerObservationBinding, ExplorerToolGrant,
    ExplorerToolKind, RepositoryExplorerBindings, RepositoryExplorerBudget,
    RepositoryExplorerHandoff, RepositoryExplorerInvariantViolation, RepositoryExplorerNextAction,
    RepositoryExplorerObservation, RepositoryExplorerObservationData, RepositoryExplorerOutput,
    RepositoryExplorerPolicy, RepositoryExplorerPolicyMaterial, RepositoryExplorerPolicyViolation,
    repository_explorer_key, validate_repository_explorer_output,
};
pub use repository_reviewer::{
    REPOSITORY_REVIEW_CANDIDATE_ARTIFACTS_SECTION_V1, REPOSITORY_REVIEW_CONTRACT_VERSION_V1,
    REPOSITORY_REVIEW_MAX_EVIDENCE_REFERENCES_V1, REPOSITORY_REVIEW_MAX_FINDINGS_V1,
    REPOSITORY_REVIEW_MAX_REQUIREMENTS_V1, REPOSITORY_REVIEW_POLICY_CONSTRAINT_V1,
    REPOSITORY_REVIEW_PRODUCER_CLAIM_SECTION_V1, REPOSITORY_REVIEW_REQUIREMENTS_SECTION_V1,
    REPOSITORY_REVIEW_SOURCE_SECTION_V1, RepositoryReviewArtifactInputV1,
    RepositoryReviewBindingsV1, RepositoryReviewCandidateArtifactsInputV1,
    RepositoryReviewConfidenceV1, RepositoryReviewEvidenceBindingV1,
    RepositoryReviewEvidenceHandleV1, RepositoryReviewEvidenceRefV1,
    RepositoryReviewFindingCategoryV1, RepositoryReviewFindingSeverityV1,
    RepositoryReviewFindingV1, RepositoryReviewInputV1, RepositoryReviewInvariantViolationV1,
    RepositoryReviewLineSpanV1, RepositoryReviewMissingEvidenceV1, RepositoryReviewOutputV1,
    RepositoryReviewPathComponentV1, RepositoryReviewPathV1, RepositoryReviewPolicyMaterialV1,
    RepositoryReviewPolicyV1, RepositoryReviewPolicyViolationV1,
    RepositoryReviewProducerClaimInputV1, RepositoryReviewRequirementAssessmentV1,
    RepositoryReviewRequirementInputV1, RepositoryReviewRequirementKindV1,
    RepositoryReviewRequirementRefV1, RepositoryReviewRequirementStatusV1, RepositoryReviewScopeV1,
    RepositoryReviewSourceInputV1, RepositoryReviewVerdictV1, derive_repository_review_policy_v1,
    repository_review_invocation_v1, repository_review_requirement_sha256, repository_reviewer_key,
    validate_repository_review_output,
};
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
