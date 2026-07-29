//! Store-owned child effect dispatch and public replay projection types.

mod model;
mod projection_types;

pub use model::{
    ChildModelDispatchHandoff, ChildModelDispatchPreparationOutcome, ChildModelPreparedEvidence,
};
pub use projection_types::ChildSuppliedResultProjection;
