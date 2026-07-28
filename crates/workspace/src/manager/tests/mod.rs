use super::*;
use crate::{
    ArtifactBoundaryError, CanonicalArtifactBoundary, CommandBoundaryError, RawCommandOutput,
};
use birdcode_protocol::{
    BackendKind, BackendSelection, CreateSessionRequest, IdempotentAppendOutcome,
    IdentifiedNewEvent, InputItem, NewEvent, PlanAcceptanceContract, Provenance,
    RepositoryMacOsDiskImageOperationV1, RepositorySnapshotCaptureClaimAdoptedV1,
    RepositorySnapshotCaptureClaimAdoptionId, Run, RunLimits, RunPurpose, RunSpec, RunState,
    Session,
};
use birdcode_store::{
    ParallelReconClaimRefreshAuthority, ParallelReconClaimRefreshOutcome,
    ParallelReconSnapshotClaimHandoffOutcomeV1, Store,
};
use chrono::Utc;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

mod capture_adoption;
mod claim_rebinding;
mod claim_validation;
mod manager_fixture;
mod snapshot_execution_safety;
mod snapshot_typestate_fixtures;
mod store_claim_harness;

use manager_fixture::*;
use snapshot_typestate_fixtures::*;
use store_claim_harness::*;
