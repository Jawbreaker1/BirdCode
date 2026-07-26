mod args;
mod backend_config;
mod backend_registry;
mod json_lines;
mod model_call_scheduler;
pub mod model_policy;
mod recon;
mod recon_child;
mod repository_agent_prompt;
pub mod repository_agent_worker;
pub mod repository_candidate;
pub mod repository_candidate_head;
pub mod repository_candidate_resolver;
mod repository_implementation_prompt;
pub mod repository_implementation_worker;
pub mod repository_review_decision;
mod repository_reviewer_prompt;
mod repository_reviewer_repair_prompt;
pub mod repository_reviewer_worker;
mod server;
mod supervisor;
pub mod worktree_write_lane;
mod writable_agent_prompt;
pub mod writable_agent_step;

pub use args::{ArgsError, HELP, Options, ParseOutcome, parse};
pub use backend_config::{
    BACKEND_MANIFEST_SCHEMA_VERSION, BackendManifest, BackendManifestError,
    MAX_BACKEND_MANIFEST_BACKENDS, MAX_BACKEND_MANIFEST_BYTES,
};
pub use backend_registry::{
    BackendRegistry, BackendRegistryError, BackendRouteKey, BackendRouteKeyError,
};
pub use json_lines::{DEFAULT_MAX_FRAME_BYTES, FrameError, JsonLines};
pub use server::{serve, serve_with_supervisor};
pub use supervisor::{
    RunCompletion, RunSubmission, RunSupervisor, RunSupervisorConfig, RunSupervisorEvent,
    SupervisorCancelDisposition, SupervisorDiscoveryError, SupervisorShutdownError,
    SupervisorStartError, SupervisorSubmitError,
};
