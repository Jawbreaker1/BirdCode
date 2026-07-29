//! Product runtime for protocol-v7 parallel repository reconnaissance.
//!
//! This module owns only orchestration and external-effect ordering. Semantic
//! delegation and child actions remain typed model outputs; Store owns all
//! authoritative reconstruction and validation.

use crate::model_call_scheduler::ModelCallScheduler;
use crate::supervisor::{
    ModelCallSlotEnd, RunSupervisorConfig, SupervisorRunError, await_model_call_slot,
    deadline_elapsed, durable_cancellation_generation, ensure_durable_cancellation,
    protocol_backend_instance, renew_claim, run_deadline,
};
use birdcode_backends::{
    BackendInstanceIdentity, ModelBackend, ModelCatalog, ModelId, ModelLoadState,
    StructuredInferenceRequest,
};
use birdcode_orchestrator::planner::{
    ObligationId, PlanId, PlannerDigest, PlannerLimits, PlannerPolicy, ProtectedObligation,
    ProtectedObligationCatalog,
};
use birdcode_protocol::{
    BackendKind, BackendModelIdentity, ChildClaimAdoptionId, EventEnvelope, EventId, EventPayload,
    IdentifiedNewEvent, ModelLineage, ModelOutputBudgetV1, NewEvent,
    PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS, PARALLEL_RECONNAISSANCE_V1_CHILD_MAX_ATTEMPTS,
    PARALLEL_RECONNAISSANCE_V1_CHILD_MODEL_TURNS_PER_ATTEMPT,
    PARALLEL_RECONNAISSANCE_V1_DEFAULT_TOTAL_RESERVED_OUTPUT_TOKENS,
    PARALLEL_RECONNAISSANCE_V1_MAX_TOTAL_RESERVED_OUTPUT_TOKENS,
    PARALLEL_RECONNAISSANCE_V1_MIN_TOTAL_RESERVED_OUTPUT_TOKENS,
    PARALLEL_RECONNAISSANCE_V1_OUTPUT_TOKENS_PER_MODEL_TURN,
    PARALLEL_RECONNAISSANCE_V1_PLANNER_ATTEMPTS_PER_STAGE,
    PARALLEL_RECONNAISSANCE_V1_ROOT_PLANNING_WORST_CASE_OUTPUT_TOKENS, PlannerAcceptedDirectiveV1,
    PlannerDelegatedWorkOrderBindingV1, PlannerTurnId, PlannerTurnPurposeV1, Provenance,
    RepositorySnapshotCaptureClaimAdoptionId, Run, RunClaimId, RunId, RunState,
    RuntimeClockReading, RuntimeInstanceId, Sha256Digest, TokenReservation, TokenReservationId,
};
use birdcode_runtime::RuntimePaths;
use birdcode_store::{
    ParallelReconClaimRefreshAuthority, ParallelReconClaimRefreshOutcome,
    ParallelReconSnapshotClaimHandoffOutcomeV1, ParallelReconSnapshotClaimHandoffV1,
    ParallelReconSnapshotClaimHandoffViewV1, ParallelReconSnapshotRefreshStatus,
    PlannerTurnRecoveryState, PlannerV2FinalizationAuthority, PlannerV2FinalizationDisposition,
    PlannerV2NotDispatchedReason, PlannerV2ObservationAuthority, PlannerV2ObservedEvidence,
    PlannerV2PreparationAuthority, PlannerV2PreparedMaterial, PlannerV2UnknownAuthority,
    ReconRunProjection, RepositorySnapshotLifecycleProjection, Store,
};
use birdcode_workspace::{
    ActiveSnapshotLease, ClockBoundary, ClockBoundaryError, RetainedArtifact,
    SnapshotReleaseRequestV1, SnapshotRequestV1, WorkspaceManager, WorkspaceManagerConfig,
};
use chrono::Utc;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const WORKSPACE_PRODUCER: &str = "birdcode-daemon-recon-workspace/1";
const WORK_ORDER_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-work-order+json";
/// One adoption is reserved for an intentional ownership takeover and one
/// for the recovery refresh that re-establishes the normal heartbeat cadence.
/// Neither allowance is inferred from failure text or runtime diagnostics.
///
/// P0 before product enablement: Store's takeover admission must independently
/// enforce this exact two-adoption non-heartbeat ceiling. This preflight proves
/// the heartbeat share; it cannot by itself constrain a foreign runtime. Every
/// reconnaissance renewal path must also use Store's atomic refresh/coalescing
/// boundary so concurrent heartbeat waiters cannot spend the same interval's
/// budget more than once.
const PARALLEL_RECONNAISSANCE_V1_CLAIM_ADOPTION_TAKEOVER_RECOVERY_MARGIN: u32 = 2;

fn recon_claim_heartbeat_interval(claim_lease: Duration) -> Duration {
    (claim_lease / 3).max(Duration::from_millis(10))
}

/// Exact active model profile derived from provider discovery. The selected
/// loaded-instance context, rather than a model-name table or advertised
/// architecture maximum, is the authority for total input+output usage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReconModelProfile {
    backend_instance: BackendInstanceIdentity,
    model_id: ModelId,
    context_window_tokens: u64,
    parallel_capacity: u32,
}

impl ReconModelProfile {
    pub(crate) const fn context_window_tokens(&self) -> u64 {
        self.context_window_tokens
    }

    pub(crate) const fn parallel_capacity(&self) -> u32 {
        self.parallel_capacity
    }
}

/// Resolves one unambiguous loaded instance from typed discovery. An unloaded
/// descriptor, duplicate selected model, missing active-instance context, or
/// catalog/backend identity drift fails closed. `maximum_context_tokens` is
/// not substituted for the active LM Studio/Ollama instance setting.
pub(crate) fn resolve_recon_model_profile(
    catalog: &ModelCatalog,
    run: &Run,
    backend: &dyn ModelBackend,
) -> Result<ReconModelProfile, SupervisorRunError> {
    if &catalog.backend_id != backend.backend_id()
        || &catalog.backend_instance != backend.instance_identity()
        || catalog.backend_instance.validate_integrity().is_err()
    {
        return Err(SupervisorRunError::InvalidState(
            "recon discovery did not attest the configured backend instance".to_owned(),
        ));
    }
    let selected = run.spec.backend.model.as_deref().ok_or_else(|| {
        SupervisorRunError::InvalidState("recon run has no selected model".to_owned())
    })?;
    let mut descriptors = catalog.models.iter().filter(|descriptor| {
        descriptor.load_state == ModelLoadState::Loaded && descriptor.id.as_str() == selected
    });
    let descriptor = descriptors.next().ok_or_else(|| {
        SupervisorRunError::InvalidState(
            "recon selected model has no loaded discovery descriptor".to_owned(),
        )
    })?;
    if descriptors.next().is_some() {
        return Err(SupervisorRunError::InvalidState(
            "recon selected model is ambiguous in discovery".to_owned(),
        ));
    }
    let exact_instances = descriptor
        .loaded_instances
        .iter()
        .filter(|instance| instance.id == selected)
        .collect::<Vec<_>>();
    let active = match exact_instances.as_slice() {
        [active] => *active,
        [] if descriptor.loaded_instances.len() == 1 => &descriptor.loaded_instances[0],
        _ => {
            return Err(SupervisorRunError::InvalidState(
                "recon discovery does not identify one active loaded instance".to_owned(),
            ));
        }
    };
    let context_window_tokens = active.context_length.ok_or_else(|| {
        SupervisorRunError::InvalidState(
            "recon active model instance has no explicit context window".to_owned(),
        )
    })?;
    let parallel_capacity = active
        .parallel_capacity
        .filter(|capacity| *capacity > 0)
        .ok_or_else(|| {
            SupervisorRunError::InvalidState(
                "recon active model instance has no explicit positive parallel capacity".to_owned(),
            )
        })?;
    if context_window_tokens < PARALLEL_RECONNAISSANCE_V1_OUTPUT_TOKENS_PER_MODEL_TURN {
        return Err(SupervisorRunError::InvalidState(
            "recon active context window is smaller than one output slice".to_owned(),
        ));
    }
    Ok(ReconModelProfile {
        backend_instance: catalog.backend_instance.clone(),
        model_id: descriptor.id.clone(),
        context_window_tokens,
        parallel_capacity,
    })
}

/// Provider-neutral conservative input authority. A byte-level tokenizer can
/// require at most one base token per serialized UTF-8 byte; counting the
/// complete provider request also covers roles, schema and framing fields.
fn require_request_fits_context(
    request: &StructuredInferenceRequest,
    profile: &ReconModelProfile,
) -> Result<(), SupervisorRunError> {
    if request.model_id() != &profile.model_id {
        return Err(SupervisorRunError::InvalidState(
            "recon request model differs from its discovered profile".to_owned(),
        ));
    }
    let input_upper_bound = u64::try_from(
        serde_json::to_vec(request)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?
            .len(),
    )
    .map_err(|_| {
        SupervisorRunError::InvalidState("recon request size does not fit u64".to_owned())
    })?;
    let required = input_upper_bound
        .checked_add(u64::from(request.max_output_tokens()))
        .ok_or_else(|| {
            SupervisorRunError::InvalidState("recon request token authority overflowed".to_owned())
        })?;
    if required > profile.context_window_tokens {
        return Err(SupervisorRunError::InvalidState(format!(
            "recon request needs a conservative {required}-token context but discovery authorizes {}",
            profile.context_window_tokens
        )));
    }
    Ok(())
}

/// One process-local monotonic origin shared by every reconnaissance effect.
/// A reading is always tagged with the caller's exact claim runtime identity.
pub(crate) struct ReconRuntimeClock {
    origin: Instant,
    last_nanos: AtomicU64,
}

impl ReconRuntimeClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_nanos: AtomicU64::new(0),
        }
    }

    /// Returns the sole monotonic origin used by this daemon process. This is
    /// intentionally process-global: separate run tasks and both child tasks
    /// can never accidentally construct incomparable origins carrying the
    /// same runtime identity.
    pub(crate) fn process() -> Arc<Self> {
        static CLOCK: OnceLock<Arc<ReconRuntimeClock>> = OnceLock::new();
        Arc::clone(CLOCK.get_or_init(|| Arc::new(Self::new())))
    }

    pub(crate) fn reading(&self, runtime_instance_id: RuntimeInstanceId) -> RuntimeClockReading {
        let elapsed = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let monotonic_nanos = self
            .last_nanos
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |previous| {
                Some(elapsed.max(previous.saturating_add(1)))
            })
            .map_or(u64::MAX, |previous| elapsed.max(previous.saturating_add(1)));
        RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos,
            observed_at: Utc::now(),
        }
    }
}

impl ClockBoundary for ReconRuntimeClock {
    fn now(
        &self,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<RuntimeClockReading, ClockBoundaryError> {
        Ok(self.reading(runtime_instance_id))
    }
}

fn planner_contracts(
    run_id: RunId,
) -> Result<
    (
        birdcode_prompting::PlannerReplannerV2ProtectedObligationCatalog,
        birdcode_prompting::PlannerReplannerV2Policy,
    ),
    SupervisorRunError,
> {
    let acceptance_policy = PlannerDigest::of_bytes(
        b"birdcode.parallel-repository-reconnaissance.v1.acceptance-policy",
    );
    let obligation = ProtectedObligation::new(
        ObligationId::from_uuid(run_id.as_uuid()),
        "Produce evidence-backed repository reconnaissance from exactly two concurrent read-only child executions over one immutable snapshot.",
        true,
    );
    let catalog = ProtectedObligationCatalog::new(acceptance_policy, [obligation])
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let policy = PlannerPolicy::read_only(PlannerLimits {
        max_work_orders: 2,
        max_verification_targets: 8,
        max_patch_operations: 16,
        max_dependencies_per_work_order: 1,
        max_delegations: 2,
        max_questions: 2,
        max_text_bytes: 128 * 1024,
    })
    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let catalog = serde_json::from_value(serde_json::to_value(catalog).map_err(|error| {
        SupervisorRunError::Contract(format!("planner obligation encoding failed: {error}"))
    })?)
    .map_err(|error| {
        SupervisorRunError::Contract(format!("planner obligation projection failed: {error}"))
    })?;
    let policy = serde_json::from_value(serde_json::to_value(policy).map_err(|error| {
        SupervisorRunError::Contract(format!("planner policy encoding failed: {error}"))
    })?)
    .map_err(|error| {
        SupervisorRunError::Contract(format!("planner policy projection failed: {error}"))
    })?;
    Ok((catalog, policy))
}

fn planner_reasoning(
    run: &Run,
) -> Result<Option<birdcode_protocol::ChildModelReasoningSettingV1>, SupervisorRunError> {
    run.spec
        .backend
        .reasoning_effort
        .as_deref()
        .map(|value| match value {
            "off" => Ok(birdcode_protocol::ChildModelReasoningSettingV1::Off),
            "on" => Ok(birdcode_protocol::ChildModelReasoningSettingV1::On),
            "low" => Ok(birdcode_protocol::ChildModelReasoningSettingV1::Low),
            "medium" => Ok(birdcode_protocol::ChildModelReasoningSettingV1::Medium),
            "high" => Ok(birdcode_protocol::ChildModelReasoningSettingV1::High),
            _ => Err(SupervisorRunError::Contract(
                "recon planner reasoning setting is outside the closed provider vocabulary"
                    .to_owned(),
            )),
        })
        .transpose()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParallelWorkOrderSelection {
    pub directive_id: birdcode_protocol::PlannerDelegateDirectiveId,
    pub work_order: PlannerDelegatedWorkOrderBindingV1,
}

/// Returns the exact two unique work orders selected across all model-authored
/// delegation groups. Validation happens atomically before either child
/// authorization can be appended.
pub(crate) fn exact_parallel_pair(
    directive: &PlannerAcceptedDirectiveV1,
) -> Result<[ParallelWorkOrderSelection; 2], SupervisorRunError> {
    let PlannerAcceptedDirectiveV1::Delegate { delegations } = directive else {
        return Err(SupervisorRunError::InvalidState(
            "initial reconnaissance planner did not author Delegate".to_owned(),
        ));
    };
    let flattened =
        delegations
            .iter()
            .flat_map(|delegation| {
                delegation.work_orders.iter().cloned().map(|work_order| {
                    ParallelWorkOrderSelection {
                        directive_id: delegation.directive_id,
                        work_order,
                    }
                })
            })
            .collect::<Vec<_>>();
    let unique = flattened
        .iter()
        .map(|selection| selection.work_order.work_order_id.as_str())
        .collect::<BTreeSet<_>>();
    let [left, right] = flattened.as_slice() else {
        return Err(SupervisorRunError::InvalidState(
            "initial reconnaissance delegation must contain exactly two work orders".to_owned(),
        ));
    };
    if unique.len() != 2 {
        return Err(SupervisorRunError::InvalidState(
            "initial reconnaissance delegation repeats a work order across groups".to_owned(),
        ));
    }
    Ok([left.clone(), right.clone()])
}

/// Decodes both planner-authored work-order artifacts before any child
/// capability can be minted.  Store repeats the same checks authoritatively at
/// append time; this all-or-nothing preflight prevents a valid first child
/// from being authorized before a malformed second selection is discovered.
pub(crate) fn decode_exact_parallel_pair(
    store: &Store,
    pair: &[ParallelWorkOrderSelection; 2],
) -> Result<[birdcode_prompting::PlannerReplannerV2PlannedWorkOrder; 2], SupervisorRunError> {
    let decoded = pair
        .iter()
        .map(|selection| {
            let retained = store.get_artifact(&selection.work_order.work_order_artifact)?;
            let planned = serde_json::from_slice::<
                birdcode_prompting::PlannerReplannerV2PlannedWorkOrder,
            >(&retained)
            .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            let canonical = serde_json::to_vec(&planned)
                .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
            if canonical != retained
                || Sha256Digest::of_bytes(&retained) != selection.work_order.work_order_digest
                || selection.work_order.work_order_artifact.media_type != WORK_ORDER_MEDIA_TYPE
                || planned.id != selection.work_order.work_order_id
                || planned.revision != selection.work_order.revision
                || planned.required_access != birdcode_prompting::PlannerReplannerAccess::ReadOnly
                || planned.state
                    != birdcode_prompting::PlannerReplannerV2PlannedWorkOrderState::Pending
                || !planned.dependencies.is_empty()
            {
                return Err(SupervisorRunError::InvalidState(
                    "planner delegation is not an exact pending read-only work order".to_owned(),
                ));
            }
            Ok(planned)
        })
        .collect::<Result<Vec<_>, SupervisorRunError>>()?;
    decoded.try_into().map_err(|_| {
        SupervisorRunError::InvalidState(
            "parallel planner preflight did not produce exactly two documents".to_owned(),
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReconBudgetPartition {
    pub aggregate_output_tokens: u64,
    pub root_planning_output_tokens: u64,
    pub planner_calls_per_stage: u32,
    pub child_agents: u32,
    pub child_attempts_per_agent: u32,
    pub child_model_turns_per_attempt: u32,
    pub output_tokens_per_model_turn: u64,
}

impl ReconBudgetPartition {
    const fn planner_stage_output_tokens(self) -> u64 {
        self.planner_calls_per_stage as u64 * self.output_tokens_per_model_turn
    }

    const fn all_child_output_tokens(self) -> u64 {
        self.child_agents as u64
            * self.child_attempts_per_agent as u64
            * self.child_model_turns_per_attempt as u64
            * self.output_tokens_per_model_turn
    }

    pub(crate) const fn minimum_required_output_tokens(self) -> u64 {
        self.root_planning_output_tokens
            + (2 * self.planner_stage_output_tokens())
            + self.all_child_output_tokens()
    }

    const fn protected_after_planner_turn(self, purpose: PlannerTurnPurposeV1) -> u64 {
        match purpose {
            PlannerTurnPurposeV1::InitialDelegation => {
                self.planner_stage_output_tokens() + self.all_child_output_tokens()
            }
            PlannerTurnPurposeV1::EvidenceReplan => 0,
        }
    }

    fn planner_output_budget(self) -> ModelOutputBudgetV1 {
        ModelOutputBudgetV1 {
            max_total_reserved_output_tokens: self.aggregate_output_tokens,
            max_output_tokens_per_call: self.output_tokens_per_model_turn,
        }
    }
}

/// Validates the complete fixed product call shape before any reconnaissance
/// model, snapshot, tool, or child effect is allowed. `None` is a typed product
/// default, not permission to consume the one-million-token hard cap.
pub(crate) fn preflight_recon_budget(
    run: &Run,
) -> Result<ReconBudgetPartition, SupervisorRunError> {
    let aggregate_output_tokens = run
        .spec
        .limits
        .max_output_tokens
        .unwrap_or(PARALLEL_RECONNAISSANCE_V1_DEFAULT_TOTAL_RESERVED_OUTPUT_TOKENS);
    let partition = ReconBudgetPartition {
        aggregate_output_tokens,
        root_planning_output_tokens:
            PARALLEL_RECONNAISSANCE_V1_ROOT_PLANNING_WORST_CASE_OUTPUT_TOKENS,
        planner_calls_per_stage: PARALLEL_RECONNAISSANCE_V1_PLANNER_ATTEMPTS_PER_STAGE,
        child_agents: PARALLEL_RECONNAISSANCE_V1_CHILD_AGENTS,
        child_attempts_per_agent: PARALLEL_RECONNAISSANCE_V1_CHILD_MAX_ATTEMPTS,
        child_model_turns_per_attempt: PARALLEL_RECONNAISSANCE_V1_CHILD_MODEL_TURNS_PER_ATTEMPT,
        output_tokens_per_model_turn: PARALLEL_RECONNAISSANCE_V1_OUTPUT_TOKENS_PER_MODEL_TURN,
    };
    if partition.minimum_required_output_tokens()
        != PARALLEL_RECONNAISSANCE_V1_MIN_TOTAL_RESERVED_OUTPUT_TOKENS
        || aggregate_output_tokens < partition.minimum_required_output_tokens()
        || aggregate_output_tokens > PARALLEL_RECONNAISSANCE_V1_MAX_TOTAL_RESERVED_OUTPUT_TOKENS
    {
        return Err(SupervisorRunError::InvalidState(
            "recon aggregate output authority cannot fund the complete fixed v1 call shape"
                .to_owned(),
        ));
    }
    Ok(partition)
}

/// Mechanical proof that the run's complete wall-time authority can fit in
/// Store's bounded per-child claim-adoption history.
///
/// `heartbeat_interval` is deliberately identical to every reconnaissance
/// effect loop: one third of the claim lease, with a ten-millisecond floor.
/// The proof pessimistically assumes both children exist for the complete run
/// and therefore charges every possible heartbeat renewal to each child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReconClaimAdoptionBudget {
    pub heartbeat_interval: Duration,
    pub heartbeat_renewals: u32,
    pub takeover_recovery_margin: u32,
    pub required_adoptions_per_child: u32,
}

pub(crate) fn preflight_recon_claim_adoption_budget(
    run: &Run,
    claim_lease: Duration,
) -> Result<ReconClaimAdoptionBudget, SupervisorRunError> {
    if run.spec.purpose != birdcode_protocol::RunPurpose::ParallelRepositoryReconnaissanceV1 {
        return Err(SupervisorRunError::InvalidState(
            "claim-adoption preflight requires a parallel reconnaissance run".to_owned(),
        ));
    }
    let max_wall_time_seconds = run
        .spec
        .limits
        .max_wall_time_seconds
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| {
            SupervisorRunError::InvalidState(
                "parallel reconnaissance requires positive finite wall-time authority".to_owned(),
            )
        })?;
    let heartbeat_interval = recon_claim_heartbeat_interval(claim_lease);
    let heartbeat_nanos = heartbeat_interval.as_nanos();
    let wall_nanos = Duration::from_secs(max_wall_time_seconds).as_nanos();
    let heartbeat_renewals = wall_nanos.div_ceil(heartbeat_nanos);
    let required_adoptions_per_child = heartbeat_renewals
        .checked_add(u128::from(
            PARALLEL_RECONNAISSANCE_V1_CLAIM_ADOPTION_TAKEOVER_RECOVERY_MARGIN,
        ))
        .ok_or_else(|| {
            SupervisorRunError::InvalidState(
                "parallel reconnaissance claim-adoption calculation overflowed".to_owned(),
            )
        })?;
    if required_adoptions_per_child
        > u128::from(birdcode_store::PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD)
    {
        return Err(SupervisorRunError::InvalidState(
            "parallel reconnaissance wall-time and claim lease exceed the bounded per-child claim-adoption budget"
                .to_owned(),
        ));
    }
    Ok(ReconClaimAdoptionBudget {
        heartbeat_interval,
        heartbeat_renewals: u32::try_from(heartbeat_renewals).map_err(|_| {
            SupervisorRunError::InvalidState(
                "parallel reconnaissance heartbeat count overflowed".to_owned(),
            )
        })?,
        takeover_recovery_margin:
            PARALLEL_RECONNAISSANCE_V1_CLAIM_ADOPTION_TAKEOVER_RECOVERY_MARGIN,
        required_adoptions_per_child: u32::try_from(required_adoptions_per_child).map_err(
            |_| {
                SupervisorRunError::InvalidState(
                    "parallel reconnaissance claim-adoption count overflowed".to_owned(),
                )
            },
        )?,
    })
}

/// Counts exact durable pre-effect reservations.  This mirrors Store's
/// run-wide admission fence without trusting an in-memory call counter, so a
/// daemon restart cannot recreate already-consumed planner authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DurableReservationLedger {
    total_output_tokens: u64,
    initial_planner_turns: u32,
    evidence_replan_turns: u32,
}

fn durable_reservation_ledger(
    store: &Store,
    run_id: RunId,
) -> Result<DurableReservationLedger, SupervisorRunError> {
    let mut cursor = 0_u64;
    let mut ledger = DurableReservationLedger::default();
    loop {
        let page = store.events_for_run_after(run_id, cursor)?;
        for event in &page.events {
            let tokens = match &event.payload {
                EventPayload::PlannerInferencePrepared(prepared) => {
                    Some(prepared.token_reservation.max_output_tokens)
                }
                EventPayload::PlannerTurnPreparedV1(prepared) => {
                    let count = match prepared.purpose {
                        PlannerTurnPurposeV1::InitialDelegation => {
                            &mut ledger.initial_planner_turns
                        }
                        PlannerTurnPurposeV1::EvidenceReplan => &mut ledger.evidence_replan_turns,
                    };
                    *count = count.checked_add(1).ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "durable planner turn count overflowed".to_owned(),
                        )
                    })?;
                    Some(prepared.token_reservation.max_output_tokens)
                }
                EventPayload::ChildModelInferencePrepared(prepared) => {
                    Some(prepared.token_reservation.max_output_tokens)
                }
                EventPayload::ChildModelInferencePreparedV2(prepared) => {
                    Some(prepared.prepared.token_reservation.max_output_tokens)
                }
                _ => None,
            };
            if let Some(tokens) = tokens {
                ledger.total_output_tokens = ledger
                    .total_output_tokens
                    .checked_add(tokens)
                    .ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "durable model reservation total overflowed".to_owned(),
                        )
                    })?;
            }
        }
        cursor = page.next_sequence;
        if !page.has_more {
            return Ok(ledger);
        }
        if page.events.is_empty() {
            return Err(SupervisorRunError::InvalidState(
                "durable reservation scan made no progress".to_owned(),
            ));
        }
    }
}

fn prepare_planner_turn(
    paths: &RuntimePaths,
    run: &Run,
    purpose: PlannerTurnPurposeV1,
    model_profile: &ReconModelProfile,
    lineage: ModelLineage,
    clock: &ReconRuntimeClock,
) -> Result<PlannerV2PreparedMaterial, SupervisorRunError> {
    let (protected_obligation_catalog, planner_policy) = planner_contracts(run.id)?;
    let backend_model = BackendModelIdentity {
        backend_id: lineage.backend_id.clone(),
        kind: BackendKind::Model,
        model_id: lineage.model_id.clone(),
    };
    let mut store = Store::open(paths.database(), paths.artifacts())?;
    let projection = store
        .recon_run_projection(run.id)?
        .ok_or_else(|| SupervisorRunError::InvalidState("recon run is missing".to_owned()))?;
    let runtime_instance_id = projection
        .guard
        .latest_claim
        .as_ref()
        .ok_or_else(|| SupervisorRunError::InvalidState("recon run has no claim".to_owned()))?
        .claim
        .runtime_instance_id;
    let initial_plan_id = matches!(
        &projection.planner.next_action,
        birdcode_store::PlannerNextAction::ReadyToPrepare {
            purpose: PlannerTurnPurposeV1::InitialDelegation,
            base_plan: None,
        }
    )
    .then(|| PlanId::new().to_string());
    let partition = preflight_recon_budget(run)?;
    let output_budget = partition.planner_output_budget();
    let ledger = durable_reservation_ledger(&store, run.id)?;
    let stage_turns = match purpose {
        PlannerTurnPurposeV1::InitialDelegation => ledger.initial_planner_turns,
        PlannerTurnPurposeV1::EvidenceReplan => ledger.evidence_replan_turns,
    };
    if stage_turns >= partition.planner_calls_per_stage {
        return Err(SupervisorRunError::InvalidState(
            "recon planner stage exhausted its trusted retry pool".to_owned(),
        ));
    }
    let remaining = output_budget
        .max_total_reserved_output_tokens
        .checked_sub(ledger.total_output_tokens)
        .ok_or_else(|| {
            SupervisorRunError::InvalidState(
                "durable model reservations exceed run output authority".to_owned(),
            )
        })?;
    let required_now = partition
        .output_tokens_per_model_turn
        .checked_add(partition.protected_after_planner_turn(purpose))
        .ok_or_else(|| {
            SupervisorRunError::InvalidState("recon protected budget overflowed".to_owned())
        })?;
    if remaining < required_now {
        return Err(SupervisorRunError::InvalidState(
            "recon planner reservation would consume protected child or replan authority"
                .to_owned(),
        ));
    }
    let max_output_tokens = partition.output_tokens_per_model_turn;
    let authority = PlannerV2PreparationAuthority {
        event_id: EventId::new(),
        turn_id: PlannerTurnId::new(),
        initial_plan_id,
        protected_obligation_catalog,
        planner_policy,
        backend_instance: model_profile.backend_instance.clone(),
        backend_model,
        model_lineage: lineage,
        reasoning: planner_reasoning(run)?,
        token_reservation: TokenReservation {
            id: TokenReservationId::new(),
            reserved_tokens: model_profile.context_window_tokens,
            max_output_tokens,
        },
        output_budget,
        prepared_at: clock.reading(runtime_instance_id),
    };
    Ok(store.prepare_planner_v2_turn(run.id, authority)?.material)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PlannerTurnExecution {
    Accepted {
        event: EventEnvelope,
        accepted: birdcode_protocol::PlannerTurnAcceptedV1,
    },
    Rejected {
        event: EventEnvelope,
        reason: birdcode_protocol::PlannerTurnRejectionReasonV1,
    },
    Terminal {
        event: EventEnvelope,
        state: RunState,
    },
    /// The old Prepared boundary is durably terminal and Store authorizes a
    /// fresh attempt, but the current runtime/claim/scheduler must not launch
    /// it. A later supervisor pass resumes from `RetryPrepared`.
    DeferredRetry { event: EventEnvelope },
}

async fn recon_projection(
    paths: RuntimePaths,
    run_id: RunId,
) -> Result<ReconRunProjection, SupervisorRunError> {
    tokio::task::spawn_blocking(move || {
        Store::open(paths.database(), paths.artifacts())?
            .recon_run_projection(run_id)?
            .ok_or_else(|| SupervisorRunError::InvalidState("recon run is missing".to_owned()))
    })
    .await
    .map_err(|error| {
        SupervisorRunError::Background(format!("planner projection worker failed: {error}"))
    })?
}

/// Returns the runtime identity that owns the *current* durable claim.
///
/// A recovered Prepared/Observed boundary may have been created by an older
/// daemon process.  New runtime-clock readings must never be tagged with that
/// abandoned process identity: Store requires reconciliation/finalization to
/// use the latest claim while retaining the old boundary's own clock as
/// historical evidence.
fn current_claim_runtime_instance_id(
    projection: &ReconRunProjection,
) -> Result<RuntimeInstanceId, SupervisorRunError> {
    projection
        .guard
        .latest_claim
        .as_ref()
        .map(|claim| claim.claim.runtime_instance_id)
        .ok_or_else(|| {
            SupervisorRunError::InvalidState(
                "recon planner recovery has no current durable claim".to_owned(),
            )
        })
}

async fn prepare_planner_turn_async(
    paths: RuntimePaths,
    run: Run,
    purpose: PlannerTurnPurposeV1,
    model_profile: ReconModelProfile,
    lineage: ModelLineage,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerV2PreparedMaterial, SupervisorRunError> {
    tokio::task::spawn_blocking(move || {
        prepare_planner_turn(&paths, &run, purpose, &model_profile, lineage, &clock)
    })
    .await
    .map_err(|error| {
        SupervisorRunError::Background(format!("planner preparation worker failed: {error}"))
    })?
}

async fn observe_planner_turn(
    paths: RuntimePaths,
    run_id: RunId,
    authority: PlannerV2ObservationAuthority,
) -> Result<EventEnvelope, SupervisorRunError> {
    tokio::task::spawn_blocking(move || {
        Ok(Store::open(paths.database(), paths.artifacts())?
            .observe_planner_v2_turn(run_id, authority)?
            .event)
    })
    .await
    .map_err(|error| {
        SupervisorRunError::Background(format!("planner observation worker failed: {error}"))
    })?
}

async fn reconcile_planner_unknown(
    paths: RuntimePaths,
    run_id: RunId,
    authority: PlannerV2UnknownAuthority,
) -> Result<EventEnvelope, SupervisorRunError> {
    tokio::task::spawn_blocking(move || {
        Ok(Store::open(paths.database(), paths.artifacts())?
            .reconcile_planner_v2_turn_unknown(run_id, authority)?
            .event)
    })
    .await
    .map_err(|error| {
        SupervisorRunError::Background(format!("planner reconciliation worker failed: {error}"))
    })?
}

fn planner_execution_from_finalization(
    outcome: birdcode_store::PlannerV2FinalizationOutcome,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    match outcome.disposition {
        PlannerV2FinalizationDisposition::Accepted => {
            let EventPayload::PlannerTurnAcceptedV1(accepted) = &outcome.event.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner acceptance without an accepted event".to_owned(),
                ));
            };
            Ok(PlannerTurnExecution::Accepted {
                event: outcome.event.clone(),
                accepted: accepted.clone(),
            })
        }
        PlannerV2FinalizationDisposition::Rejected(reason) => {
            if !matches!(
                &outcome.event.payload,
                EventPayload::PlannerTurnRejectedV1(_)
            ) {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner rejection without a rejected event".to_owned(),
                ));
            }
            Ok(PlannerTurnExecution::Rejected {
                event: outcome.event,
                reason,
            })
        }
        PlannerV2FinalizationDisposition::RunFailed
        | PlannerV2FinalizationDisposition::RunCancelled => {
            let EventPayload::RunStateChanged { to, .. } = &outcome.event.payload else {
                return Err(SupervisorRunError::InvalidState(
                    "Store reported planner terminalization without a run-state event".to_owned(),
                ));
            };
            let expected = match outcome.disposition {
                PlannerV2FinalizationDisposition::RunFailed => RunState::Failed,
                PlannerV2FinalizationDisposition::RunCancelled => RunState::Cancelled,
                _ => unreachable!("terminal disposition was matched above"),
            };
            if *to != expected {
                return Err(SupervisorRunError::InvalidState(
                    "Store planner terminal disposition disagrees with run state".to_owned(),
                ));
            }
            let state = *to;
            Ok(PlannerTurnExecution::Terminal {
                event: outcome.event,
                state,
            })
        }
    }
}

async fn finalize_planner_turn(
    paths: RuntimePaths,
    run_id: RunId,
    runtime_instance_id: RuntimeInstanceId,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    tokio::task::spawn_blocking(move || {
        let outcome = Store::open(paths.database(), paths.artifacts())?.finalize_planner_v2_turn(
            run_id,
            PlannerV2FinalizationAuthority {
                event_id: EventId::new(),
                finalized_at: clock.reading(runtime_instance_id),
            },
        )?;
        planner_execution_from_finalization(outcome)
    })
    .await
    .map_err(|error| {
        SupervisorRunError::Background(format!("planner finalization worker failed: {error}"))
    })?
}

fn accepted_planner_recovery(
    event: &EventEnvelope,
    purpose: PlannerTurnPurposeV1,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    let EventPayload::PlannerTurnAcceptedV1(accepted) = &event.payload else {
        return Err(SupervisorRunError::InvalidState(
            "accepted planner recovery carries the wrong event".to_owned(),
        ));
    };
    if accepted.purpose != purpose {
        return Err(SupervisorRunError::InvalidState(
            "accepted planner turn has the wrong purpose".to_owned(),
        ));
    }
    Ok(PlannerTurnExecution::Accepted {
        event: event.clone(),
        accepted: accepted.clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannerRetryMode {
    Immediate,
    Deferred,
}

enum PlannerTerminalResolution {
    RetryNow,
    Execution(PlannerTurnExecution),
}

async fn resolve_planner_terminal_boundary(
    paths: RuntimePaths,
    run_id: RunId,
    terminal_event: EventEnvelope,
    runtime_instance_id: RuntimeInstanceId,
    retry_mode: PlannerRetryMode,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTerminalResolution, SupervisorRunError> {
    let projection = recon_projection(paths.clone(), run_id).await?;
    if matches!(
        projection.planner.next_action,
        birdcode_store::PlannerNextAction::RetryPrepared { .. }
    ) {
        return Ok(match retry_mode {
            PlannerRetryMode::Immediate => PlannerTerminalResolution::RetryNow,
            PlannerRetryMode::Deferred => {
                PlannerTerminalResolution::Execution(PlannerTurnExecution::DeferredRetry {
                    event: terminal_event,
                })
            }
        });
    }
    Ok(PlannerTerminalResolution::Execution(
        finalize_planner_turn(paths, run_id, runtime_instance_id, clock).await?,
    ))
}

async fn close_planner_not_dispatched(
    paths: RuntimePaths,
    run_id: RunId,
    prepared_event_id: EventId,
    runtime_instance_id: RuntimeInstanceId,
    reason: PlannerV2NotDispatchedReason,
    retry_mode: PlannerRetryMode,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTerminalResolution, SupervisorRunError> {
    let event = observe_planner_turn(
        paths.clone(),
        run_id,
        PlannerV2ObservationAuthority {
            event_id: EventId::new(),
            prepared_event_id,
            evidence: PlannerV2ObservedEvidence::NotDispatched { reason },
            observed_at: clock.reading(runtime_instance_id),
        },
    )
    .await?;
    resolve_planner_terminal_boundary(paths, run_id, event, runtime_instance_id, retry_mode, clock)
        .await
}

async fn close_planner_unknown(
    paths: RuntimePaths,
    run_id: RunId,
    prepared_event_id: EventId,
    runtime_instance_id: RuntimeInstanceId,
    boundary: birdcode_protocol::UnknownInferenceBoundary,
    retry_mode: PlannerRetryMode,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTerminalResolution, SupervisorRunError> {
    let event = reconcile_planner_unknown(
        paths.clone(),
        run_id,
        PlannerV2UnknownAuthority {
            event_id: EventId::new(),
            prepared_event_id,
            boundary,
            boundary_at: clock.reading(runtime_instance_id),
        },
    )
    .await?;
    resolve_planner_terminal_boundary(paths, run_id, event, runtime_instance_id, retry_mode, clock)
        .await
}

/// Executes or recovers one planner-v2 turn through Store's total Prepared,
/// Observed/Unknown and finalization APIs. A recovered Prepared is always
/// reconciled as restart-unknown; it is never redispatched.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn drive_planner_turn(
    paths: RuntimePaths,
    run: Run,
    purpose: PlannerTurnPurposeV1,
    backend: Arc<dyn ModelBackend>,
    scheduler: ModelCallScheduler,
    config: RunSupervisorConfig,
    lineage: ModelLineage,
    model_profile: ReconModelProfile,
    cancellation: tokio_util::sync::CancellationToken,
    shutdown: tokio_util::sync::CancellationToken,
    deadline: Option<chrono::DateTime<Utc>>,
    clock: Arc<ReconRuntimeClock>,
) -> Result<PlannerTurnExecution, SupervisorRunError> {
    if model_profile.backend_instance != *backend.instance_identity()
        || model_profile.model_id.as_str() != run.spec.backend.model.as_deref().unwrap_or_default()
        || scheduler.maximum_parallel_calls()
            > usize::try_from(model_profile.parallel_capacity()).unwrap_or(usize::MAX)
    {
        return Err(SupervisorRunError::InvalidState(
            "recon discovered model profile or provider parallel capacity drifted before planner preparation"
                .to_owned(),
        ));
    }

    loop {
        let projection = recon_projection(paths.clone(), run.id).await?;
        if matches!(
            projection.run_state,
            RunState::Completed | RunState::Failed | RunState::Cancelled
        ) {
            let event = projection
                .guard
                .terminal_state_event
                .clone()
                .ok_or_else(|| {
                    SupervisorRunError::InvalidState(
                        "terminal recon projection omitted its state event".to_owned(),
                    )
                })?;
            return Ok(PlannerTurnExecution::Terminal {
                event,
                state: projection.run_state,
            });
        }

        let material = match &projection.planner.next_action {
            birdcode_store::PlannerNextAction::ReadyToPrepare {
                purpose: projected, ..
            }
            | birdcode_store::PlannerNextAction::RetryPrepared {
                purpose: projected, ..
            } => {
                if *projected != purpose {
                    return Err(SupervisorRunError::InvalidState(
                        "Store authorized a different planner purpose".to_owned(),
                    ));
                }
                prepare_planner_turn_async(
                    paths.clone(),
                    run.clone(),
                    purpose,
                    model_profile.clone(),
                    lineage.clone(),
                    Arc::clone(&clock),
                )
                .await?
            }
            birdcode_store::PlannerNextAction::RecoverPrepared { .. } => {
                let PlannerTurnRecoveryState::Prepared { prepared_event } =
                    &projection.planner.recovery
                else {
                    return Err(SupervisorRunError::InvalidState(
                        "Store requested Prepared recovery without Prepared evidence".to_owned(),
                    ));
                };
                let EventPayload::PlannerTurnPreparedV1(_prepared) = &prepared_event.payload else {
                    return Err(SupervisorRunError::InvalidState(
                        "planner recovery lost its Prepared event".to_owned(),
                    ));
                };
                let runtime_instance_id = current_claim_runtime_instance_id(&projection)?;
                match close_planner_unknown(
                    paths.clone(),
                    run.id,
                    prepared_event.id,
                    runtime_instance_id,
                    birdcode_protocol::UnknownInferenceBoundary::Restart,
                    PlannerRetryMode::Immediate,
                    Arc::clone(&clock),
                )
                .await?
                {
                    PlannerTerminalResolution::RetryNow => continue,
                    PlannerTerminalResolution::Execution(execution) => return Ok(execution),
                }
            }
            birdcode_store::PlannerNextAction::ValidateObserved { .. }
            | birdcode_store::PlannerNextAction::FinalizeObservedFailure { .. }
            | birdcode_store::PlannerNextAction::ReconcileUnknown { .. } => {
                let prepared_event = match &projection.planner.recovery {
                    PlannerTurnRecoveryState::Observed { prepared_event, .. }
                    | PlannerTurnRecoveryState::Unknown { prepared_event, .. } => prepared_event,
                    _ => {
                        return Err(SupervisorRunError::InvalidState(
                            "Store requested planner finalization without terminal evidence"
                                .to_owned(),
                        ));
                    }
                };
                let EventPayload::PlannerTurnPreparedV1(_prepared) = &prepared_event.payload else {
                    return Err(SupervisorRunError::InvalidState(
                        "planner recovery lost its Prepared event".to_owned(),
                    ));
                };
                let runtime_instance_id = current_claim_runtime_instance_id(&projection)?;
                return finalize_planner_turn(paths, run.id, runtime_instance_id, clock).await;
            }
            birdcode_store::PlannerNextAction::ApplyAcceptedDirective { .. } => {
                let accepted = projection
                    .planner
                    .accepted_directive
                    .as_ref()
                    .ok_or_else(|| {
                        SupervisorRunError::InvalidState(
                            "Store requested an accepted directive without its event".to_owned(),
                        )
                    })?;
                return accepted_planner_recovery(&accepted.event, purpose);
            }
            birdcode_store::PlannerNextAction::ResolveRejectedTurn { .. } => {
                let PlannerTurnRecoveryState::Rejected { rejected_event, .. } =
                    &projection.planner.recovery
                else {
                    return Err(SupervisorRunError::InvalidState(
                        "Store requested rejected-turn resolution without its event".to_owned(),
                    ));
                };
                let EventPayload::PlannerTurnRejectedV1(rejected) = &rejected_event.payload else {
                    return Err(SupervisorRunError::InvalidState(
                        "rejected planner recovery carries the wrong event".to_owned(),
                    ));
                };
                if rejected.purpose != purpose {
                    return Err(SupervisorRunError::InvalidState(
                        "rejected planner turn has the wrong purpose".to_owned(),
                    ));
                }
                return Ok(PlannerTurnExecution::Rejected {
                    event: rejected_event.clone(),
                    reason: rejected.reason,
                });
            }
            birdcode_store::PlannerNextAction::Terminal { .. } => {
                return Err(SupervisorRunError::InvalidState(
                    "nonterminal recon projection exposed terminal planner action".to_owned(),
                ));
            }
            birdcode_store::PlannerNextAction::CancellationRequested { .. } => {
                ensure_durable_cancellation(paths.clone(), run.id, config.clone()).await?;
                let PlannerTurnRecoveryState::Prepared { prepared_event } =
                    &projection.planner.recovery
                else {
                    return Err(SupervisorRunError::InvalidState(
                        "planner cancellation has no Prepared boundary to close".to_owned(),
                    ));
                };
                let EventPayload::PlannerTurnPreparedV1(prepared) = &prepared_event.payload else {
                    return Err(SupervisorRunError::InvalidState(
                        "planner cancellation lost its Prepared event".to_owned(),
                    ));
                };
                let resolution = close_planner_not_dispatched(
                    paths.clone(),
                    run.id,
                    prepared_event.id,
                    prepared.claim_runtime_instance_id,
                    PlannerV2NotDispatchedReason::CancellationRequested,
                    PlannerRetryMode::Immediate,
                    Arc::clone(&clock),
                )
                .await?;
                match resolution {
                    PlannerTerminalResolution::RetryNow => continue,
                    PlannerTerminalResolution::Execution(execution) => return Ok(execution),
                }
            }
            birdcode_store::PlannerNextAction::AwaitRunClaim
            | birdcode_store::PlannerNextAction::AwaitAcceptedRootPlan
            | birdcode_store::PlannerNextAction::FinalizeCompletionGate { .. } => {
                return Err(SupervisorRunError::InvalidState(
                    "planner driver was called before Store authorized this phase".to_owned(),
                ));
            }
        };

        let EventPayload::PlannerTurnPreparedV1(prepared) = &material.prepared_event.payload else {
            return Err(SupervisorRunError::InvalidState(
                "Store returned non-planner Prepared material".to_owned(),
            ));
        };
        let prepared_event_id = material.prepared_event.id;
        let runtime_instance_id = prepared.claim_runtime_instance_id;
        let preflight_reason = if model_profile.model_id.as_str() != prepared.backend_model.model_id
            || prepared.token_reservation.reserved_tokens != model_profile.context_window_tokens
            || prepared.token_reservation.max_output_tokens
                != PARALLEL_RECONNAISSANCE_V1_OUTPUT_TOKENS_PER_MODEL_TURN
        {
            Some(PlannerV2NotDispatchedReason::ModelProfileDrift)
        } else if require_request_fits_context(material.request.inference(), &model_profile)
            .is_err()
        {
            Some(PlannerV2NotDispatchedReason::RequestContextExceeded)
        } else {
            None
        };
        if let Some(reason) = preflight_reason {
            return match close_planner_not_dispatched(
                paths.clone(),
                run.id,
                prepared_event_id,
                runtime_instance_id,
                reason,
                PlannerRetryMode::Immediate,
                clock,
            )
            .await?
            {
                PlannerTerminalResolution::RetryNow => Err(SupervisorRunError::InvalidState(
                    "Store retried a non-retryable planner preflight rejection".to_owned(),
                )),
                PlannerTerminalResolution::Execution(execution) => Ok(execution),
            };
        }

        let slot = await_model_call_slot(
            paths.clone(),
            run.id,
            &config,
            &scheduler,
            &cancellation,
            &shutdown,
            deadline,
        )
        .await?;
        let permit = match slot {
            ModelCallSlotEnd::Acquired(permit) => permit,
            ModelCallSlotEnd::Cancelled => {
                ensure_durable_cancellation(paths.clone(), run.id, config.clone()).await?;
                let resolution = close_planner_not_dispatched(
                    paths.clone(),
                    run.id,
                    prepared_event_id,
                    runtime_instance_id,
                    PlannerV2NotDispatchedReason::CancellationRequested,
                    PlannerRetryMode::Immediate,
                    Arc::clone(&clock),
                )
                .await?;
                match resolution {
                    PlannerTerminalResolution::RetryNow => continue,
                    PlannerTerminalResolution::Execution(execution) => return Ok(execution),
                }
            }
            ModelCallSlotEnd::Shutdown => {
                let resolution = close_planner_not_dispatched(
                    paths.clone(),
                    run.id,
                    prepared_event_id,
                    runtime_instance_id,
                    PlannerV2NotDispatchedReason::RuntimeShutdown,
                    PlannerRetryMode::Deferred,
                    Arc::clone(&clock),
                )
                .await?;
                match resolution {
                    PlannerTerminalResolution::RetryNow => continue,
                    PlannerTerminalResolution::Execution(execution) => return Ok(execution),
                }
            }
            ModelCallSlotEnd::Deadline => {
                let resolution = close_planner_not_dispatched(
                    paths.clone(),
                    run.id,
                    prepared_event_id,
                    runtime_instance_id,
                    PlannerV2NotDispatchedReason::DeadlineElapsed,
                    PlannerRetryMode::Immediate,
                    Arc::clone(&clock),
                )
                .await?;
                match resolution {
                    PlannerTerminalResolution::RetryNow => continue,
                    PlannerTerminalResolution::Execution(execution) => return Ok(execution),
                }
            }
            ModelCallSlotEnd::ClaimRenewalFailed(_) => {
                let resolution = close_planner_not_dispatched(
                    paths.clone(),
                    run.id,
                    prepared_event_id,
                    runtime_instance_id,
                    PlannerV2NotDispatchedReason::ClaimLost,
                    PlannerRetryMode::Deferred,
                    Arc::clone(&clock),
                )
                .await?;
                match resolution {
                    PlannerTerminalResolution::RetryNow => continue,
                    PlannerTerminalResolution::Execution(execution) => return Ok(execution),
                }
            }
            ModelCallSlotEnd::SchedulerClosed => {
                let resolution = close_planner_not_dispatched(
                    paths.clone(),
                    run.id,
                    prepared_event_id,
                    runtime_instance_id,
                    PlannerV2NotDispatchedReason::SchedulerClosed,
                    PlannerRetryMode::Deferred,
                    Arc::clone(&clock),
                )
                .await?;
                match resolution {
                    PlannerTerminalResolution::RetryNow => continue,
                    PlannerTerminalResolution::Execution(execution) => return Ok(execution),
                }
            }
        };

        let current_instance = protocol_backend_instance(backend.instance_identity())
            .map_err(SupervisorRunError::Contract)?;
        if current_instance != prepared.backend_instance
            || prepared.model_lineage.deployment_id
                != backend
                    .instance_identity()
                    .configured_deployment_id()
                    .as_str()
            || prepared.backend_model.backend_id != backend.backend_id().as_str()
            || material.request.inference().model_id().as_str() != prepared.backend_model.model_id
        {
            drop(permit);
            let reason = if material.request.inference().model_id().as_str()
                != prepared.backend_model.model_id
            {
                PlannerV2NotDispatchedReason::ModelProfileDrift
            } else {
                PlannerV2NotDispatchedReason::BackendInstanceDrift
            };
            return match close_planner_not_dispatched(
                paths.clone(),
                run.id,
                prepared_event_id,
                runtime_instance_id,
                reason,
                PlannerRetryMode::Immediate,
                clock,
            )
            .await?
            {
                PlannerTerminalResolution::RetryNow => Err(SupervisorRunError::InvalidState(
                    "Store retried a non-retryable backend-attestation rejection".to_owned(),
                )),
                PlannerTerminalResolution::Execution(execution) => Ok(execution),
            };
        }

        let inference = backend.infer_structured(material.request.inference().clone());
        tokio::pin!(inference);
        let heartbeat_interval = recon_claim_heartbeat_interval(config.claim_lease);
        enum EffectEnd {
            Observed(
                Result<
                    birdcode_backends::StructuredInferenceResponse,
                    birdcode_backends::BackendError,
                >,
            ),
            Unknown(birdcode_protocol::UnknownInferenceBoundary),
        }
        let effect = loop {
            let heartbeat = tokio::time::sleep(heartbeat_interval);
            tokio::pin!(heartbeat);
            let end = tokio::select! {
                biased;
                result = &mut inference => Some(EffectEnd::Observed(result)),
                () = cancellation.cancelled() => Some(EffectEnd::Unknown(
                    birdcode_protocol::UnknownInferenceBoundary::Cancelled,
                )),
                () = shutdown.cancelled() => Some(EffectEnd::Unknown(
                    birdcode_protocol::UnknownInferenceBoundary::Shutdown,
                )),
                () = crate::supervisor::wait_for_deadline(deadline) => Some(EffectEnd::Unknown(
                    birdcode_protocol::UnknownInferenceBoundary::Deadline,
                )),
                () = &mut heartbeat => None,
            };
            if let Some(end) = end {
                break end;
            }
            if renew_claim(paths.clone(), run.id, config.clone())
                .await
                .is_err()
            {
                break EffectEnd::Unknown(
                    birdcode_protocol::UnknownInferenceBoundary::ClaimRenewalFailed,
                );
            }
            if durable_cancellation_generation(paths.clone(), run.id, config.max_recovery_events)
                .await?
                > 0
            {
                break EffectEnd::Unknown(birdcode_protocol::UnknownInferenceBoundary::Cancelled);
            }
        };
        drop(permit);

        let resolution = match effect {
            EffectEnd::Observed(result) => {
                let evidence = match result {
                    Ok(response) => {
                        // Store retains malformed evidence and derives the
                        // non-retryable ProtocolViolation itself.
                        let _response_attested = response.model_id.as_str()
                            == prepared.backend_model.model_id
                            && backend
                                .instance_identity()
                                .matches_response_evidence(&response.evidence);
                        PlannerV2ObservedEvidence::Response(response)
                    }
                    Err(error) => PlannerV2ObservedEvidence::Error(error),
                };
                let event = observe_planner_turn(
                    paths.clone(),
                    run.id,
                    PlannerV2ObservationAuthority {
                        event_id: EventId::new(),
                        prepared_event_id,
                        evidence,
                        observed_at: clock.reading(runtime_instance_id),
                    },
                )
                .await?;
                resolve_planner_terminal_boundary(
                    paths.clone(),
                    run.id,
                    event,
                    runtime_instance_id,
                    PlannerRetryMode::Immediate,
                    Arc::clone(&clock),
                )
                .await?
            }
            EffectEnd::Unknown(boundary) => {
                if boundary == birdcode_protocol::UnknownInferenceBoundary::Cancelled {
                    ensure_durable_cancellation(paths.clone(), run.id, config.clone()).await?;
                }
                let retry_mode = match boundary {
                    birdcode_protocol::UnknownInferenceBoundary::Shutdown
                    | birdcode_protocol::UnknownInferenceBoundary::ClaimRenewalFailed => {
                        PlannerRetryMode::Deferred
                    }
                    _ => PlannerRetryMode::Immediate,
                };
                close_planner_unknown(
                    paths.clone(),
                    run.id,
                    prepared_event_id,
                    runtime_instance_id,
                    boundary,
                    retry_mode,
                    Arc::clone(&clock),
                )
                .await?
            }
        };
        match resolution {
            PlannerTerminalResolution::RetryNow => continue,
            PlannerTerminalResolution::Execution(execution) => return Ok(execution),
        }
    }
}

pub(crate) struct ManagedSnapshot {
    manager: WorkspaceManager,
    active: ActiveSnapshotLease,
    lease_event: EventEnvelope,
}

impl ManagedSnapshot {
    pub(crate) fn mount_path(&self) -> &Path {
        self.active.mount_path()
    }

    pub(crate) fn snapshot(&self) -> &birdcode_protocol::RepositorySnapshotBindingV1 {
        self.active.snapshot()
    }

    pub(crate) fn root(&self) -> &birdcode_protocol::RepositoryRootBindingV1 {
        self.active.root()
    }

    pub(crate) fn lease_event(&self) -> &EventEnvelope {
        &self.lease_event
    }
}

fn retain_exact(store: &Store, artifact: &RetainedArtifact) -> Result<(), SupervisorRunError> {
    let retained = store.put_artifact(&artifact.bytes, artifact.artifact.media_type.clone())?;
    if retained != artifact.artifact {
        return Err(SupervisorRunError::InvalidState(
            "workspace artifact changed at Store boundary".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedSnapshotClaimHandoff {
    PreCapture,
    ActiveLease,
}

struct RefreshedSnapshotClaimHandoff {
    claim_event: EventEnvelope,
    handoff: ParallelReconSnapshotClaimHandoffV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedSnapshotEffectPhase {
    Capture,
    Release,
}

fn snapshot_lifecycle_allows_effect(
    expected: ExpectedSnapshotEffectPhase,
    lifecycle: &RepositorySnapshotLifecycleProjection,
) -> bool {
    matches!(
        (expected, lifecycle),
        (
            ExpectedSnapshotEffectPhase::Capture,
            RepositorySnapshotLifecycleProjection::None
                | RepositorySnapshotLifecycleProjection::OpenCapture { .. }
        ) | (
            ExpectedSnapshotEffectPhase::Release,
            RepositorySnapshotLifecycleProjection::ActiveLease { .. }
        )
    )
}

fn release_parent_matches_active_lease(
    causal_parent_event_id: EventId,
    retained_lease_event: &EventEnvelope,
    handoff_view: ParallelReconSnapshotClaimHandoffViewV1<'_>,
) -> bool {
    match handoff_view {
        ParallelReconSnapshotClaimHandoffViewV1::ActiveLease { lease_event, .. } => {
            causal_parent_event_id == lease_event.id && retained_lease_event == lease_event
        }
        _ => false,
    }
}

/// Enters Store's one serializable claim-refresh transaction and moves the
/// resulting snapshot capability to the caller. This bridge is deliberately
/// limited to lifecycle boundaries at which no snapshot command is in flight.
fn refresh_snapshot_claim_handoff(
    store: &mut Store,
    run_id: RunId,
    config: &RunSupervisorConfig,
    clock: &ReconRuntimeClock,
    expected: ExpectedSnapshotClaimHandoff,
) -> Result<RefreshedSnapshotClaimHandoff, SupervisorRunError> {
    let refreshed_at = clock.reading(config.runtime_instance_id);
    let heartbeat = chrono::Duration::from_std(recon_claim_heartbeat_interval(config.claim_lease))
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let lease = chrono::Duration::from_std(config.claim_lease)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let outcome = store.refresh_parallel_recon_claim(
        run_id,
        ParallelReconClaimRefreshAuthority {
            actor_id: config.actor_id,
            runtime_instance_id: config.runtime_instance_id,
            renewal_claim_id: RunClaimId::new(),
            snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
            child_adoption_ids: [ChildClaimAdoptionId::new(), ChildClaimAdoptionId::new()],
            refreshed_at: refreshed_at.clone(),
            fresh_through: refreshed_at.observed_at + heartbeat,
            renewed_lease_expires_at: refreshed_at.observed_at + lease,
        },
    )?;

    let (claim, snapshot, snapshot_claim) = match outcome {
        ParallelReconClaimRefreshOutcome::CleanupInProgress { .. } => {
            return Err(SupervisorRunError::InvalidState(
                "snapshot claim authority is unavailable while cleanup is in progress".to_owned(),
            ));
        }
        ParallelReconClaimRefreshOutcome::Fresh {
            claim,
            nonterminal_work_orders,
            snapshot,
            snapshot_claim,
        } if nonterminal_work_orders.is_empty() => (claim, snapshot, snapshot_claim),
        ParallelReconClaimRefreshOutcome::Renewed {
            claim,
            snapshot,
            snapshot_claim,
            adoptions,
        } if adoptions.is_empty() => (claim, snapshot, snapshot_claim),
        ParallelReconClaimRefreshOutcome::Fresh { .. }
        | ParallelReconClaimRefreshOutcome::Renewed { .. } => {
            return Err(SupervisorRunError::InvalidState(
                "snapshot claim boundary found live child work that requires the serial control lane"
                    .to_owned(),
            ));
        }
        ParallelReconClaimRefreshOutcome::Cancelled { .. } => {
            return Err(SupervisorRunError::InvalidState(
                "snapshot claim boundary is cancelled".to_owned(),
            ));
        }
        ParallelReconClaimRefreshOutcome::Terminal { state } => {
            return Err(SupervisorRunError::InvalidState(format!(
                "snapshot claim boundary is terminal ({state:?})"
            )));
        }
        ParallelReconClaimRefreshOutcome::ForeignOwner { .. } => {
            return Err(SupervisorRunError::InvalidState(
                "snapshot claim boundary is owned by another runtime".to_owned(),
            ));
        }
    };
    let handoff = match snapshot_claim {
        ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(handoff) => handoff,
        ParallelReconSnapshotClaimHandoffOutcomeV1::NoSnapshotAuthority(reason) => {
            return Err(SupervisorRunError::InvalidState(format!(
                "Store withheld snapshot authority at the claim boundary ({reason:?})"
            )));
        }
    };
    let exact_view = match (expected, &snapshot, handoff.view()) {
        (
            ExpectedSnapshotClaimHandoff::PreCapture,
            ParallelReconSnapshotRefreshStatus::None,
            ParallelReconSnapshotClaimHandoffViewV1::PreCapture { current_claim, .. },
        ) => current_claim == &claim.event,
        (
            ExpectedSnapshotClaimHandoff::ActiveLease,
            ParallelReconSnapshotRefreshStatus::ActiveLease { lease_event_id },
            ParallelReconSnapshotClaimHandoffViewV1::ActiveLease {
                lease_event,
                current_claim,
                ..
            },
        ) => lease_event.id == *lease_event_id && current_claim == &claim.event,
        _ => false,
    };
    if !exact_view {
        return Err(SupervisorRunError::InvalidState(
            "Store returned a snapshot capability for the wrong lifecycle phase".to_owned(),
        ));
    }
    Ok(RefreshedSnapshotClaimHandoff {
        claim_event: claim.event,
        handoff,
    })
}

fn workspace_payload_matches_claim(payload: &EventPayload, claim_event: &EventEnvelope) -> bool {
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return false;
    };
    let fields_match = |issuer_actor_id,
                        claim_event_id,
                        claim_id,
                        claim_generation,
                        claim_runtime_instance_id,
                        cancellation_generation| {
        issuer_actor_id == claim_event.actor_id
            && claim_event_id == claim_event.id
            && claim_id == claim.claim_id
            && claim_generation == claim.claim_generation
            && claim_runtime_instance_id == claim.runtime_instance_id
            && cancellation_generation == claim.cancellation_generation
    };
    match payload {
        EventPayload::RepositoryWriterLeaseRevoked(value) => fields_match(
            value.issuer_actor_id,
            value.claim_event_id,
            value.claim_id,
            value.claim_generation,
            value.claim_runtime_instance_id,
            value.cancellation_generation,
        ),
        EventPayload::RepositorySnapshotLeaseIssued(value) => fields_match(
            value.issuer_actor_id,
            value.claim_event_id,
            value.claim_id,
            value.claim_generation,
            value.claim_runtime_instance_id,
            value.cancellation_generation,
        ),
        EventPayload::RepositorySnapshotLeaseReleased(value) => fields_match(
            value.issuer_actor_id,
            value.claim_event_id,
            value.claim_id,
            value.claim_generation,
            value.claim_runtime_instance_id,
            value.cancellation_generation,
        ),
        _ => false,
    }
}

fn append_workspace_event(
    store: &mut Store,
    event_id: EventId,
    run_id: RunId,
    causal_parent: EventId,
    payload: EventPayload,
    raw_artifact: birdcode_protocol::ArtifactRef,
) -> Result<EventEnvelope, SupervisorRunError> {
    let run = store
        .get_run(run_id)?
        .ok_or_else(|| SupervisorRunError::InvalidState("recon run is missing".to_owned()))?;
    let projection = store
        .recon_run_projection(run_id)?
        .ok_or_else(|| SupervisorRunError::InvalidState("recon run is missing".to_owned()))?;
    let current_claim = projection.guard.latest_claim.as_ref().ok_or_else(|| {
        SupervisorRunError::InvalidState("recon run has no live claim".to_owned())
    })?;
    let claim_parent_required = matches!(
        &payload,
        EventPayload::RepositoryWriterLeaseRevoked(_)
            | EventPayload::RepositorySnapshotLeaseIssued(_)
    );
    if projection.run_state != RunState::Running
        || projection.guard.cancellation_event.is_some()
        || !projection.guard.claim_matches_cancellation_generation
        || current_claim.claim.lease_expires_at <= Utc::now()
        || deadline_elapsed(run_deadline(&run)?)
        || !workspace_payload_matches_claim(&payload, &current_claim.event)
        || (claim_parent_required && causal_parent != current_claim.event.id)
    {
        return Err(SupervisorRunError::InvalidState(
            "workspace event intent is stale relative to Store's current claim".to_owned(),
        ));
    }
    let append = store.append_identified_event(IdentifiedNewEvent {
        event_id,
        event: NewEvent {
            session_id: projection.session_id,
            run_id: Some(projection.run_id),
            actor_id: current_claim.event.actor_id,
            causal_parent: Some(causal_parent),
            provenance: Provenance {
                producer: WORKSPACE_PRODUCER.to_owned(),
                backend: None,
                raw_artifact: Some(raw_artifact),
            },
            payload,
        },
    })?;
    Ok(match append {
        birdcode_protocol::IdempotentAppendOutcome::Appended { event }
        | birdcode_protocol::IdempotentAppendOutcome::AlreadyPresent { event } => event,
    })
}

/// Re-reads durable run authority at every workspace phase boundary. A stale
/// authority captured before `hdiutil` is never treated as proof that the next
/// external effect is still permitted.
fn require_snapshot_guard(
    paths: &RuntimePaths,
    run_id: RunId,
    expected_claim_event: &EventEnvelope,
    expected_phase: ExpectedSnapshotEffectPhase,
    stop: &tokio_util::sync::CancellationToken,
) -> Result<(), SupervisorRunError> {
    if stop.is_cancelled() {
        return Err(SupervisorRunError::Background(
            "snapshot lifecycle stopped at a safe phase boundary".to_owned(),
        ));
    }
    let store = Store::open(paths.database(), paths.artifacts())?;
    let run = store
        .get_run(run_id)?
        .ok_or_else(|| SupervisorRunError::InvalidState("recon run is missing".to_owned()))?;
    let projection = store
        .recon_run_projection(run_id)?
        .ok_or_else(|| SupervisorRunError::InvalidState("recon run is missing".to_owned()))?;
    let snapshot_lifecycle = store.repository_snapshot_lifecycle(run_id)?;
    let claim = projection
        .guard
        .latest_claim
        .as_ref()
        .ok_or_else(|| SupervisorRunError::InvalidState("recon run has no claim".to_owned()))?;
    let EventPayload::RunClaimed(expected_claim) = &expected_claim_event.payload else {
        return Err(SupervisorRunError::InvalidState(
            "snapshot guard did not retain a RunClaimed envelope".to_owned(),
        ));
    };
    if projection.run_state != RunState::Running
        || projection.guard.cancellation_event.is_some()
        || projection.guard.cancellation_generation != expected_claim.cancellation_generation
        || !projection.guard.claim_matches_cancellation_generation
        || expected_claim_event.run_id != Some(run_id)
        || claim.event != *expected_claim_event
        || claim.claim != *expected_claim
        || claim.claim.lease_expires_at <= Utc::now()
        || deadline_elapsed(run_deadline(&run)?)
        || !snapshot_lifecycle_allows_effect(expected_phase, &snapshot_lifecycle)
    {
        return Err(SupervisorRunError::InvalidState(
            "snapshot effect authority is no longer live".to_owned(),
        ));
    }
    Ok(())
}

fn require_capture_snapshot_guard(
    paths: &RuntimePaths,
    run_id: RunId,
    expected_claim_event: &EventEnvelope,
    stop: &tokio_util::sync::CancellationToken,
) -> Result<(), SupervisorRunError> {
    require_snapshot_guard(
        paths,
        run_id,
        expected_claim_event,
        ExpectedSnapshotEffectPhase::Capture,
        stop,
    )
}

fn require_release_snapshot_guard(
    paths: &RuntimePaths,
    run_id: RunId,
    expected_claim_event: &EventEnvelope,
    stop: &tokio_util::sync::CancellationToken,
) -> Result<(), SupervisorRunError> {
    require_snapshot_guard(
        paths,
        run_id,
        expected_claim_event,
        ExpectedSnapshotEffectPhase::Release,
        stop,
    )
}

/// Captures, mounts and durably commits one immutable repository snapshot.
/// Every returned workspace artifact is persisted in Store before the next
/// external command or event boundary is crossed.
fn acquire_snapshot_blocking(
    paths: &RuntimePaths,
    state_root: PathBuf,
    source_path: PathBuf,
    run_id: RunId,
    clock: Arc<ReconRuntimeClock>,
    config: &RunSupervisorConfig,
    stop: tokio_util::sync::CancellationToken,
) -> Result<ManagedSnapshot, SupervisorRunError> {
    let mut store = Store::open(paths.database(), paths.artifacts())?;
    if stop.is_cancelled() {
        return Err(SupervisorRunError::Background(
            "snapshot capture stopped before claim refresh".to_owned(),
        ));
    }
    let workspace_clock: Arc<dyn ClockBoundary> = clock.clone();
    let manager = WorkspaceManager::open_with_boundaries(
        WorkspaceManagerConfig::new(source_path, state_root.join(run_id.to_string())),
        Arc::new(birdcode_workspace::SystemCommandBoundary),
        Arc::new(birdcode_workspace::CanonicalArtifactBoundary),
        workspace_clock,
    )
    .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let recovery = manager
        .recovery_inspections()
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    if !recovery.is_empty() {
        let dispositions = recovery
            .iter()
            .map(|inspection| format!("{:?}", inspection.disposition))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(SupervisorRunError::InvalidState(format!(
            "workspace recovery is required before capture ({dispositions}); no snapshot effect was repeated"
        )));
    }
    if stop.is_cancelled() {
        return Err(SupervisorRunError::Background(
            "snapshot capture stopped before claim refresh".to_owned(),
        ));
    }
    let RefreshedSnapshotClaimHandoff {
        claim_event,
        handoff,
    } = refresh_snapshot_claim_handoff(
        &mut store,
        run_id,
        config,
        &clock,
        ExpectedSnapshotClaimHandoff::PreCapture,
    )?;
    let request = SnapshotRequestV1 {
        writer_revocation_event_id: EventId::new(),
        snapshot_lease_event_id: EventId::new(),
        snapshot_lease_id: birdcode_protocol::RepositorySnapshotLeaseId::new(),
        snapshot_id: format!("snapshot-{run_id}"),
        repository_root_id: format!("repository-{run_id}"),
        workspace_writer_lease_id: format!("writer-{}", EventId::new()),
    };
    let prepared = manager
        .prepare_snapshot(request, handoff)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_capture_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    let revoked = manager
        .revoke_writers(prepared)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_capture_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    retain_exact(&store, &revoked.evidence)?;
    retain_exact(&store, &revoked.source_manifest_artifact)?;
    let revoked_event = append_workspace_event(
        &mut store,
        revoked.event_id,
        run_id,
        claim_event.id,
        EventPayload::RepositoryWriterLeaseRevoked(revoked.payload.clone()),
        revoked.evidence.artifact.clone(),
    )?;
    let committed = manager
        .confirm_writer_revocation(revoked, &revoked_event)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;

    // `prepare_capture` fsyncs recovery authority before hdiutil can start.
    require_capture_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    let capture = manager
        .prepare_capture(committed)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    // The fsynced journal is not authority to execute later: re-read the
    // claim/cancellation/deadline guard immediately before `hdiutil create`.
    require_capture_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    let captured = manager
        .execute_capture(capture)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_capture_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    for artifact in [
        &captured.create_stdout,
        &captured.create_stderr,
        &captured.source_after_artifact,
    ] {
        retain_exact(&store, artifact)?;
    }
    let attach = manager
        .prepare_attach(captured)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_capture_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    let lease = manager
        .execute_attach(attach)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_capture_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    for artifact in [
        &lease.lease,
        &lease.attach_evidence,
        &lease.raw_attach_plist,
        &lease.attach_stderr,
        &lease.snapshot_manifest,
        &lease.mounted_content_manifest,
    ] {
        retain_exact(&store, artifact)?;
    }
    let lease_event = append_workspace_event(
        &mut store,
        lease.event_id,
        run_id,
        claim_event.id,
        EventPayload::RepositorySnapshotLeaseIssued(lease.payload.clone()),
        lease.lease.artifact.clone(),
    )?;
    let committed = manager
        .confirm_snapshot_lease(lease, &lease_event)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    let active = manager
        .activate_snapshot_lease(committed)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    Ok(ManagedSnapshot {
        manager,
        active,
        lease_event,
    })
}

/// Runs manifest traversal and every `hdiutil` effect on Tokio's blocking
/// pool.  The async supervisor never blocks a worker thread with filesystem or
/// subprocess work.
pub(crate) async fn acquire_snapshot(
    paths: RuntimePaths,
    state_root: PathBuf,
    source_path: PathBuf,
    run_id: RunId,
    clock: Arc<ReconRuntimeClock>,
    config: RunSupervisorConfig,
    cancellation: tokio_util::sync::CancellationToken,
    shutdown: tokio_util::sync::CancellationToken,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<ManagedSnapshot, SupervisorRunError> {
    let worker_paths = paths.clone();
    let stop = tokio_util::sync::CancellationToken::new();
    let worker_stop = stop.clone();
    let worker_config = config.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        acquire_snapshot_blocking(
            &worker_paths,
            state_root,
            source_path,
            run_id,
            clock,
            &worker_config,
            worker_stop,
        )
    });
    let heartbeat_interval = recon_claim_heartbeat_interval(config.claim_lease);
    let mut stop_error = None;
    loop {
        tokio::select! {
            result = &mut worker => {
                let result = result.map_err(|error| {
                    SupervisorRunError::Background(format!("snapshot worker failed to join: {error}"))
                })?;
                return match stop_error {
                    Some(error) => Err(error),
                    None => result,
                };
            }
            () = cancellation.cancelled(), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::Background(
                    "snapshot capture cancelled; recovery journal retained".to_owned(),
                ));
            }
            () = shutdown.cancelled(), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::Background(
                    "snapshot capture interrupted by shutdown; recovery journal retained".to_owned(),
                ));
            }
            () = crate::supervisor::wait_for_deadline(deadline), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::InvalidState(
                    "snapshot capture exceeded the run deadline; recovery journal retained".to_owned(),
                ));
            }
            () = tokio::time::sleep(heartbeat_interval), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::InvalidState(
                    "snapshot capture crossed its heartbeat boundary; recovery is required until the serial claim/effect lane is implemented"
                        .to_owned(),
                ));
            }
        }
    }
}

/// Detaches one committed snapshot and persists the exact release before local
/// image cleanup. The parent must be Store-derived by the caller.
fn release_snapshot_blocking(
    paths: &RuntimePaths,
    run_id: RunId,
    snapshot: ManagedSnapshot,
    causal_parent_event_id: EventId,
    config: &RunSupervisorConfig,
    clock: &ReconRuntimeClock,
    stop: tokio_util::sync::CancellationToken,
) -> Result<EventEnvelope, SupervisorRunError> {
    let mut store = Store::open(paths.database(), paths.artifacts())?;
    if stop.is_cancelled() {
        return Err(SupervisorRunError::Background(
            "snapshot release stopped before claim refresh".to_owned(),
        ));
    }
    let RefreshedSnapshotClaimHandoff {
        claim_event,
        handoff,
    } = refresh_snapshot_claim_handoff(
        &mut store,
        run_id,
        config,
        clock,
        ExpectedSnapshotClaimHandoff::ActiveLease,
    )?;
    let ManagedSnapshot {
        manager,
        active,
        lease_event,
    } = snapshot;
    let exact_release_parent =
        release_parent_matches_active_lease(causal_parent_event_id, &lease_event, handoff.view());
    if !exact_release_parent {
        return Err(SupervisorRunError::InvalidState(
            "snapshot release parent is not Store's exact active lease".to_owned(),
        ));
    }
    let active = manager
        .rebind_active_snapshot_release_claim(active, handoff)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_release_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    let prepared = manager
        .prepare_release(
            active,
            SnapshotReleaseRequestV1 {
                release_event_id: EventId::new(),
                causal_parent_event_id,
            },
        )
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_release_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    let released = manager
        .execute_release(prepared)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    require_release_snapshot_guard(paths, run_id, &claim_event, &stop)?;
    for artifact in [
        &released.release,
        &released.detach_stdout,
        &released.detach_stderr,
    ] {
        retain_exact(&store, artifact)?;
    }
    let event = append_workspace_event(
        &mut store,
        released.event_id,
        run_id,
        causal_parent_event_id,
        EventPayload::RepositorySnapshotLeaseReleased(released.payload.clone()),
        released.release.artifact.clone(),
    )?;
    manager
        .confirm_release(released, &event)
        .map_err(|error| SupervisorRunError::Contract(error.to_string()))?;
    Ok(event)
}

/// Runs detach, unmount verification and image cleanup outside Tokio's async
/// worker threads.
pub(crate) async fn release_snapshot(
    paths: RuntimePaths,
    run_id: RunId,
    snapshot: ManagedSnapshot,
    causal_parent_event_id: EventId,
    config: RunSupervisorConfig,
    cancellation: tokio_util::sync::CancellationToken,
    shutdown: tokio_util::sync::CancellationToken,
    deadline: Option<chrono::DateTime<Utc>>,
) -> Result<EventEnvelope, SupervisorRunError> {
    let worker_paths = paths.clone();
    let stop = tokio_util::sync::CancellationToken::new();
    let worker_stop = stop.clone();
    let worker_config = config.clone();
    let worker_clock = ReconRuntimeClock::process();
    let mut worker = tokio::task::spawn_blocking(move || {
        release_snapshot_blocking(
            &worker_paths,
            run_id,
            snapshot,
            causal_parent_event_id,
            &worker_config,
            &worker_clock,
            worker_stop,
        )
    });
    let heartbeat_interval = recon_claim_heartbeat_interval(config.claim_lease);
    let mut stop_error = None;
    loop {
        tokio::select! {
            result = &mut worker => {
                let result = result.map_err(|error| {
                    SupervisorRunError::Background(format!("snapshot release worker failed to join: {error}"))
                })?;
                return match stop_error {
                    Some(error) => Err(error),
                    None => result,
                };
            }
            () = cancellation.cancelled(), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::Background(
                    "snapshot release cancelled; recovery journal retained".to_owned(),
                ));
            }
            () = shutdown.cancelled(), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::Background(
                    "snapshot release interrupted by shutdown; recovery journal retained".to_owned(),
                ));
            }
            () = crate::supervisor::wait_for_deadline(deadline), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::InvalidState(
                    "snapshot release exceeded the run deadline; recovery journal retained".to_owned(),
                ));
            }
            () = tokio::time::sleep(heartbeat_interval), if stop_error.is_none() => {
                stop.cancel();
                stop_error = Some(SupervisorRunError::InvalidState(
                    "snapshot release crossed its heartbeat boundary; recovery is required until the serial claim/effect lane is implemented"
                        .to_owned(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use birdcode_backends::{
        CapabilityState, DiscoveryEvidence, HttpEvidence, LmStudioBackend, LmStudioConfig,
        LoadedInstance, ModelCapabilities, ModelDescriptor, ModelKind, NativeDiscoveryEvidence,
        NativeMatch,
    };
    use birdcode_protocol::{
        ArtifactRef, BackendSelection, InputItem, PlanAcceptanceContract,
        PlannerAcceptedDelegationV1, PlannerDelegateDirectiveId,
        RepositorySnapshotCaptureIdentityV1, RepositorySnapshotLeaseId,
        RepositoryWriterLeaseRevokedV1, RunClaimed, RunLimits, RunPurpose, RunSpec, SessionId,
    };
    use url::Url;

    fn budget_run(max_output_tokens: Option<u64>) -> Run {
        Run::new(RunSpec {
            session_id: SessionId::new(),
            purpose: RunPurpose::ParallelRepositoryReconnaissanceV1,
            plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
            backend: BackendSelection {
                backend_id: "lmstudio".to_owned(),
                kind: BackendKind::Model,
                model: Some("gemma-4-26b".to_owned()),
                reasoning_effort: None,
            },
            input: vec![InputItem::Text {
                text: "Kartlägg repositoryt med två agenter.".to_owned(),
            }],
            limits: RunLimits {
                max_output_tokens,
                max_wall_time_seconds: Some(600),
                max_subagents: 2,
            },
        })
    }

    fn work_order(id: &str) -> PlannerDelegatedWorkOrderBindingV1 {
        let bytes = id.as_bytes();
        let digest = Sha256Digest::of_bytes(bytes);
        PlannerDelegatedWorkOrderBindingV1 {
            work_order_id: id.to_owned(),
            revision: 1,
            work_order_digest: digest.clone(),
            work_order_artifact: ArtifactRef {
                sha256: digest.as_str().to_owned(),
                size_bytes: u64::try_from(bytes.len()).expect("test length fits"),
                media_type: WORK_ORDER_MEDIA_TYPE.to_owned(),
            },
        }
    }

    fn discovered_recon_catalog(parallel_capacity: Option<u32>) -> (LmStudioBackend, ModelCatalog) {
        let backend = LmStudioBackend::new(LmStudioConfig::new(
            Url::parse("http://127.0.0.1:1234").expect("test URL is valid"),
        ))
        .expect("test backend config is valid");
        let evidence = HttpEvidence {
            endpoint: "http://127.0.0.1:1234/v1/models".to_owned(),
            status: 200,
            response_body_sha256: "0".repeat(64),
            body: serde_json::json!({"data": [{"id": "gemma-4-26b"}]}),
        };
        let catalog = ModelCatalog {
            backend_id: backend.backend_id().clone(),
            backend_instance: backend.instance_identity().clone(),
            models: vec![ModelDescriptor {
                id: ModelId::new("gemma-4-26b").expect("test model id is valid"),
                kind: ModelKind::Language,
                display_name: Some("Gemma test".to_owned()),
                publisher: Some("google".to_owned()),
                architecture: Some("gemma4".to_owned()),
                load_state: ModelLoadState::Loaded,
                loaded_instances: vec![LoadedInstance {
                    id: "gemma-4-26b".to_owned(),
                    context_length: Some(32_000),
                    parallel_capacity,
                }],
                maximum_context_tokens: Some(262_144),
                quantization: None,
                capabilities: ModelCapabilities {
                    vision: CapabilityState::Supported,
                    trained_for_tool_use: CapabilityState::Supported,
                    reasoning: None,
                },
                native_match: NativeMatch::None,
            }],
            evidence: DiscoveryEvidence {
                openai: evidence.clone(),
                native: NativeDiscoveryEvidence::Available { response: evidence },
            },
        };
        (backend, catalog)
    }

    fn delegated(
        groups: Vec<Vec<PlannerDelegatedWorkOrderBindingV1>>,
    ) -> PlannerAcceptedDirectiveV1 {
        PlannerAcceptedDirectiveV1::Delegate {
            delegations: groups
                .into_iter()
                .enumerate()
                .map(|(index, work_orders)| PlannerAcceptedDelegationV1 {
                    directive_id: PlannerDelegateDirectiveId::new(),
                    source_delegation_index: u32::try_from(index).expect("test index fits"),
                    work_orders,
                })
                .collect(),
        }
    }

    fn claim_bound_writer_revocation(
        claim_event: &EventEnvelope,
    ) -> RepositoryWriterLeaseRevokedV1 {
        let EventPayload::RunClaimed(claim) = &claim_event.payload else {
            panic!("test claim envelope must contain RunClaimed");
        };
        let evidence_digest = Sha256Digest::of_bytes(b"writer evidence");
        RepositoryWriterLeaseRevokedV1 {
            issuer_actor_id: claim_event.actor_id,
            claim_event_id: claim_event.id,
            claim_id: claim.claim_id,
            claim_generation: claim.claim_generation,
            claim_runtime_instance_id: claim.runtime_instance_id,
            cancellation_generation: claim.cancellation_generation,
            capture: RepositorySnapshotCaptureIdentityV1 {
                snapshot_id: "snapshot-test".to_owned(),
                lease_id: RepositorySnapshotLeaseId::new(),
                snapshot_lease_event_id: EventId::new(),
            },
            evidence_artifact: ArtifactRef {
                sha256: evidence_digest.as_str().to_owned(),
                size_bytes: 15,
                media_type: "application/vnd.birdcode.repository-writer-lease-evidence+json"
                    .to_owned(),
            },
            evidence_digest,
        }
    }

    #[test]
    fn workspace_payload_requires_every_current_claim_identity_field() {
        let session_id = SessionId::new();
        let run_id = RunId::new();
        let actor_id = birdcode_protocol::ActorId::new();
        let claim = RunClaimed {
            claim_id: RunClaimId::new(),
            runtime_instance_id: RuntimeInstanceId::new(),
            claim_generation: 7,
            cancellation_generation: 3,
            lease_expires_at: Utc::now() + chrono::Duration::minutes(1),
        };
        let claim_event = EventEnvelope {
            id: EventId::new(),
            sequence: 2,
            session_id,
            run_id: Some(run_id),
            actor_id,
            causal_parent: None,
            occurred_at: Utc::now(),
            provenance: Provenance {
                producer: "daemon-d1-test".to_owned(),
                backend: None,
                raw_artifact: None,
            },
            payload: EventPayload::RunClaimed(claim),
        };
        let exact = claim_bound_writer_revocation(&claim_event);
        assert!(workspace_payload_matches_claim(
            &EventPayload::RepositoryWriterLeaseRevoked(exact.clone()),
            &claim_event,
        ));

        let mut substitutions = Vec::new();
        let mut changed = exact.clone();
        changed.issuer_actor_id = birdcode_protocol::ActorId::new();
        substitutions.push(changed);
        let mut changed = exact.clone();
        changed.claim_event_id = EventId::new();
        substitutions.push(changed);
        let mut changed = exact.clone();
        changed.claim_id = RunClaimId::new();
        substitutions.push(changed);
        let mut changed = exact.clone();
        changed.claim_generation += 1;
        substitutions.push(changed);
        let mut changed = exact.clone();
        changed.claim_runtime_instance_id = RuntimeInstanceId::new();
        substitutions.push(changed);
        let mut changed = exact;
        changed.cancellation_generation += 1;
        substitutions.push(changed);

        for substituted in substitutions {
            assert!(!workspace_payload_matches_claim(
                &EventPayload::RepositoryWriterLeaseRevoked(substituted),
                &claim_event,
            ));
        }
        assert!(!workspace_payload_matches_claim(
            &EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id: RuntimeInstanceId::new(),
                claim_generation: 1,
                cancellation_generation: 0,
                lease_expires_at: Utc::now(),
            }),
            &claim_event,
        ));
    }

    #[test]
    fn snapshot_effect_phase_matrix_rejects_cleanup_and_wrong_lifecycle() {
        let claim = RunClaimed {
            claim_id: RunClaimId::new(),
            runtime_instance_id: RuntimeInstanceId::new(),
            claim_generation: 1,
            cancellation_generation: 0,
            lease_expires_at: Utc::now() + chrono::Duration::minutes(1),
        };
        let event = EventEnvelope {
            id: EventId::new(),
            sequence: 1,
            session_id: SessionId::new(),
            run_id: Some(RunId::new()),
            actor_id: birdcode_protocol::ActorId::new(),
            causal_parent: None,
            occurred_at: Utc::now(),
            provenance: Provenance {
                producer: "daemon-d1-phase-test".to_owned(),
                backend: None,
                raw_artifact: None,
            },
            payload: EventPayload::RunClaimed(claim.clone()),
        };
        let open = RepositorySnapshotLifecycleProjection::OpenCapture {
            writer_revocation_event: event.clone(),
            latest_capture_event: event.clone(),
            active_claim: birdcode_store::DurableRunClaimProjection {
                event: event.clone(),
                claim,
            },
            adoption_count: 0,
        };
        let active = RepositorySnapshotLifecycleProjection::ActiveLease {
            writer_revocation_event: event.clone(),
            lease_event: event.clone(),
        };
        let mut substituted_lease = event.clone();
        substituted_lease.id = EventId::new();
        assert!(release_parent_matches_active_lease(
            event.id,
            &event,
            ParallelReconSnapshotClaimHandoffViewV1::ActiveLease {
                lease_event: &event,
                previous_claim: None,
                current_claim: &event,
            },
        ));
        assert!(!release_parent_matches_active_lease(
            EventId::new(),
            &event,
            ParallelReconSnapshotClaimHandoffViewV1::ActiveLease {
                lease_event: &event,
                previous_claim: None,
                current_claim: &event,
            },
        ));
        assert!(!release_parent_matches_active_lease(
            event.id,
            &substituted_lease,
            ParallelReconSnapshotClaimHandoffViewV1::ActiveLease {
                lease_event: &event,
                previous_claim: None,
                current_claim: &event,
            },
        ));
        assert!(!release_parent_matches_active_lease(
            event.id,
            &event,
            ParallelReconSnapshotClaimHandoffViewV1::PreCapture {
                previous_claim: None,
                current_claim: &event,
            },
        ));
        let cleanup = RepositorySnapshotLifecycleProjection::PendingCleanup {
            writer_revocation_event: event.clone(),
            target:
                birdcode_store::RepositorySnapshotCleanupTargetProjectionV1::CaptureAbandonment {
                    latest_capture_event: event.clone(),
                },
            latest_cleanup_grant_event: event,
            grant_count: 1,
        };

        assert!(snapshot_lifecycle_allows_effect(
            ExpectedSnapshotEffectPhase::Capture,
            &RepositorySnapshotLifecycleProjection::None,
        ));
        assert!(snapshot_lifecycle_allows_effect(
            ExpectedSnapshotEffectPhase::Capture,
            &open,
        ));
        assert!(!snapshot_lifecycle_allows_effect(
            ExpectedSnapshotEffectPhase::Release,
            &open,
        ));
        assert!(snapshot_lifecycle_allows_effect(
            ExpectedSnapshotEffectPhase::Release,
            &active,
        ));
        assert!(!snapshot_lifecycle_allows_effect(
            ExpectedSnapshotEffectPhase::Capture,
            &active,
        ));
        for phase in [
            ExpectedSnapshotEffectPhase::Capture,
            ExpectedSnapshotEffectPhase::Release,
        ] {
            assert!(!snapshot_lifecycle_allows_effect(phase, &cleanup));
        }
    }

    #[test]
    fn exact_parallel_pair_flattens_groups_before_authorizing() {
        let directive = delegated(vec![vec![work_order("left")], vec![work_order("right")]]);
        let pair = exact_parallel_pair(&directive).expect("exact pair is accepted");
        assert_eq!(pair[0].work_order.work_order_id, "left");
        assert_eq!(pair[1].work_order.work_order_id, "right");
        assert_ne!(pair[0].directive_id, pair[1].directive_id);
    }

    #[test]
    fn exact_parallel_pair_rejects_one_three_and_cross_group_duplicates() {
        for directive in [
            delegated(vec![vec![work_order("one")]]),
            delegated(vec![vec![
                work_order("one"),
                work_order("two"),
                work_order("three"),
            ]]),
            delegated(vec![vec![work_order("same")], vec![work_order("same")]]),
        ] {
            assert!(exact_parallel_pair(&directive).is_err());
        }
    }

    #[test]
    fn process_clock_is_strictly_monotonic_for_one_runtime() {
        let clock = ReconRuntimeClock::process();
        let runtime = RuntimeInstanceId::new();
        let first = clock.reading(runtime);
        let second = clock.reading(runtime);
        assert_eq!(first.runtime_instance_id, second.runtime_instance_id);
        assert!(first.monotonic_nanos != 0 && second.monotonic_nanos > first.monotonic_nanos);
    }

    #[test]
    fn recon_profile_requires_and_preserves_provider_parallel_capacity() {
        let run = budget_run(None);
        let (backend, catalog) = discovered_recon_catalog(Some(4));
        let profile = resolve_recon_model_profile(&catalog, &run, &backend)
            .expect("exact discovery capacity is accepted");
        assert_eq!(profile.context_window_tokens(), 32_000);
        assert_eq!(profile.parallel_capacity(), 4);

        let (backend, catalog) = discovered_recon_catalog(None);
        assert!(resolve_recon_model_profile(&catalog, &run, &backend).is_err());
        let (backend, catalog) = discovered_recon_catalog(Some(0));
        assert!(resolve_recon_model_profile(&catalog, &run, &backend).is_err());
    }

    #[test]
    fn trusted_budget_counts_the_complete_retryable_call_shape() {
        let partition = preflight_recon_budget(&budget_run(Some(
            PARALLEL_RECONNAISSANCE_V1_MIN_TOTAL_RESERVED_OUTPUT_TOKENS,
        )))
        .expect("the exact complete call shape is funded");
        let planner_calls = 2_u64 * u64::from(partition.planner_calls_per_stage);
        let child_calls = u64::from(partition.child_agents)
            * u64::from(partition.child_attempts_per_agent)
            * u64::from(partition.child_model_turns_per_attempt);

        assert_eq!(partition.root_planning_output_tokens, 40_960);
        assert_eq!(partition.output_tokens_per_model_turn, 8_192);
        assert_eq!(planner_calls, 4, "initial and replan each get one retry");
        assert_eq!(child_calls, 8, "both children get two complete attempts");
        assert_eq!(planner_calls + child_calls, 12);
        assert_eq!(partition.minimum_required_output_tokens(), 139_264);
        assert_eq!(
            partition.minimum_required_output_tokens(),
            PARALLEL_RECONNAISSANCE_V1_MIN_TOTAL_RESERVED_OUTPUT_TOKENS
        );
    }

    #[test]
    fn trusted_budget_defaults_to_complete_and_rejects_one_token_less() {
        let defaulted = preflight_recon_budget(&budget_run(None))
            .expect("omitted aggregate uses the complete product default");
        assert_eq!(
            defaulted.aggregate_output_tokens,
            PARALLEL_RECONNAISSANCE_V1_MIN_TOTAL_RESERVED_OUTPUT_TOKENS
        );
        assert!(
            preflight_recon_budget(&budget_run(Some(
                PARALLEL_RECONNAISSANCE_V1_MIN_TOTAL_RESERVED_OUTPUT_TOKENS - 1
            )))
            .is_err()
        );
    }

    #[test]
    fn claim_adoption_budget_accepts_the_default_600_second_run_and_60_second_lease() {
        let proof =
            preflight_recon_claim_adoption_budget(&budget_run(None), Duration::from_secs(60))
                .expect("the default finite run fits the durable adoption budget");

        assert_eq!(proof.heartbeat_interval, Duration::from_secs(20));
        assert_eq!(proof.heartbeat_renewals, 30);
        assert_eq!(proof.takeover_recovery_margin, 2);
        assert_eq!(proof.required_adoptions_per_child, 32);
    }

    #[test]
    fn claim_adoption_budget_requires_finite_wall_time_authority() {
        let mut run = budget_run(None);
        run.spec.limits.max_wall_time_seconds = None;

        assert!(preflight_recon_claim_adoption_budget(&run, Duration::from_secs(60)).is_err());
        run.spec.limits.max_wall_time_seconds = Some(0);
        assert!(preflight_recon_claim_adoption_budget(&run, Duration::from_secs(60)).is_err());
    }

    #[test]
    fn claim_adoption_budget_rejects_short_lease_when_heartbeats_exceed_the_store_budget() {
        let error =
            preflight_recon_claim_adoption_budget(&budget_run(None), Duration::from_millis(30))
                .expect_err(
                    "ten-millisecond heartbeats cannot cover 600 seconds within 256 adoptions",
                );

        assert!(matches!(error, SupervisorRunError::InvalidState(_)));
    }

    #[test]
    fn claim_adoption_budget_accepts_the_exact_boundary_and_rejects_boundary_plus_one() {
        let heartbeat_renewal_boundary =
            birdcode_store::PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD
                - PARALLEL_RECONNAISSANCE_V1_CLAIM_ADOPTION_TAKEOVER_RECOVERY_MARGIN;
        let mut boundary = budget_run(None);
        boundary.spec.limits.max_wall_time_seconds = Some(u64::from(heartbeat_renewal_boundary));
        let proof = preflight_recon_claim_adoption_budget(&boundary, Duration::from_secs(3))
            .expect("one-second heartbeats fit exactly at the adoption boundary");
        assert_eq!(proof.heartbeat_interval, Duration::from_secs(1));
        assert_eq!(proof.heartbeat_renewals, heartbeat_renewal_boundary);
        assert_eq!(
            proof.required_adoptions_per_child,
            birdcode_store::PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD
        );

        boundary.spec.limits.max_wall_time_seconds =
            Some(u64::from(heartbeat_renewal_boundary) + 1);
        assert!(preflight_recon_claim_adoption_budget(&boundary, Duration::from_secs(3)).is_err());
    }
}
