//! Portable runtime orchestration for `BirdCode`.
//!
//! The runtime owns mechanical state transitions and durable local state. It
//! does not infer user intent or fabricate model output. Semantic decisions
//! will enter through explicit backend interfaces in later slices.

mod config;
mod critic;
mod planning;
mod repair;
mod runtime;

pub use config::RuntimePaths;
pub use critic::{
    CompiledPlanCriticRequest, MAX_PLAN_CRITIC_OUTPUT_TOKENS, PlanCriticCompileError,
    compile_plan_critic_request,
};
pub use planning::{
    CompiledRootPlanRequest, MAX_ROOT_PLANNER_OUTPUT_TOKENS, PlanRequestCompileError,
    compile_root_plan_request,
};
pub use repair::{
    CompiledPlanRepairRequest, MAX_PLAN_REPAIR_OUTPUT_TOKENS, PlanRepairCompileError,
    compile_plan_repair_request,
};
pub use runtime::{LocalRuntime, Repository, RepositoryError, RepositoryErrorKind, RuntimeError};
