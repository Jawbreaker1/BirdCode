//! Portable runtime orchestration for `BirdCode`.
//!
//! The runtime owns mechanical state transitions and durable local state. It
//! does not infer user intent or fabricate model output. Semantic decisions
//! will enter through explicit backend interfaces in later slices.

mod config;
mod planning;
mod runtime;

pub use config::RuntimePaths;
pub use planning::{
    CompiledRootPlanRequest, MAX_ROOT_PLANNER_OUTPUT_TOKENS, PlanRequestCompileError,
    compile_root_plan_request,
};
pub use runtime::{LocalRuntime, Repository, RepositoryError, RepositoryErrorKind, RuntimeError};
