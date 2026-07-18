//! Portable runtime orchestration for `BirdCode`.
//!
//! The runtime owns mechanical state transitions and durable local state. It
//! does not infer user intent or fabricate model output. Semantic decisions
//! will enter through explicit backend interfaces in later slices.

mod config;
mod runtime;

pub use config::RuntimePaths;
pub use runtime::{LocalRuntime, Repository, RepositoryError, RepositoryErrorKind, RuntimeError};
