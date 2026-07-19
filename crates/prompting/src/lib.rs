//! Provider-neutral, schema-validated application prompt contracts.
//!
//! Prompt manifests are application data. Compilation keeps the immutable
//! policy separate from user, repository, tool, and external data; this crate
//! deliberately contains no local semantic classifier or heuristic fallback.

mod canonical;
mod compiler;
mod manifest;
mod router;

pub use compiler::{
    CanonicalJson, CompiledMessage, CompiledPrompt, DataProvenance, DataSection,
    ManifestProvenance, MessageContent, MessageProvenance, MessageRole, PromptInvocation,
    PromptLimits, SourceKind, TrustLevel,
};
pub use manifest::{
    MANIFEST_SCHEMA_JSON, PromptError, PromptId, PromptKey, PromptManifest, PromptRegistry,
    PromptRole, TASK_ROUTER_MANIFEST_JSON, TASK_ROUTER_MANIFEST_V1_0_0_JSON,
    TASK_ROUTER_MANIFEST_V1_1_0_JSON, TASK_ROUTER_MANIFEST_V1_1_1_JSON,
    TASK_ROUTER_MANIFEST_V1_1_2_JSON, builtin_registry, parse_manifest,
};
pub use router::{
    RequiredAccess, RouteAction, RouteEvidence, RouteStrategy, RouterInvariantViolation,
    SuggestedSubtask, TaskRouterOutput, task_router_key,
};
