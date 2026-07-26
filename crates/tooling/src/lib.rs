//! Broker-controlled, provider-neutral, read-only repository tools.
//!
//! Semantic agents decide *which* tool call to request. This crate enforces only
//! deterministic mechanics: exact grants, component-confined paths, hard
//! bounds, descriptor-relative reads, literal matching, provenance artifacts,
//! and typed outcomes.

mod broker;
mod model;

#[cfg(unix)]
mod unix;

pub use broker::{
    BrokerOpenError, RepositoryToolBroker, project_observed_event_v2, project_prepared_event_v2,
    project_unknown_event_v2, verify_terminal_output_v2,
};
pub use model::*;
