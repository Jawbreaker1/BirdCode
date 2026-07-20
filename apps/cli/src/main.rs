mod args;

use args::{Command, Options, PlanOptions};
use birdcode_client::{DaemonClient, DaemonLaunchOptions, resolve_daemon_path};
use birdcode_prompting::{PlanCriticOutput, PlanCriticVerdict};
use birdcode_protocol::{
    ArtifactChunk, ArtifactRef, BackendCatalog, BackendKind, BackendModelIdentity,
    BackendSelection, ClientCommand, CreateRunRequest, CreateSessionRequest, EventEnvelope,
    EventPage, EventPayload, HealthStatus, InputItem, MAX_ARTIFACT_CHUNK_BYTES,
    PlanAcceptanceContract, PlanCandidateBinding, PlanProposalAccepted, PlanProposalRejected,
    PlanSemanticReviewAccepted, PlanSemanticReviewRejected, PlanSemanticReviewRejectionDisposition,
    PlanSemanticReviewValidatedVerdict, PlanSemanticReviewValidationReceipt, PlannerInferenceError,
    PlannerInferenceErrorKind, PlannerInferenceObservation, PlannerInferenceOutcomeUnknown,
    RetryDisposition, RootPlanningFailed, RootPlanningFailurePhase, RootPlanningFailureReason,
    RootPlanningStageFailed, Run, RunId, RunLimits, RunPurpose, RunSpec, RunState,
    RuntimeCapability, ServerResult, SessionId, UnknownInferenceOutcomeReason,
};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const LM_STUDIO_BACKEND_ID: &str = "lmstudio";
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_CLI_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const PROPOSAL_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-proposal+json";
const VALIDATION_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-validation+json";
const ACCEPTED_PLAN_MEDIA_TYPE: &str = "application/vnd.birdcode.accepted-plan+json";
const CRITIQUE_MEDIA_TYPE: &str = "application/vnd.birdcode.plan-critique+json";
const SEMANTIC_REVIEW_RECEIPT_MEDIA_TYPE: &str =
    "application/vnd.birdcode.plan-semantic-review-receipt+json";

fn main() {
    if let Err(error) = run() {
        eprintln!("birdcode: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let options = args::parse(std::env::args_os().skip(1))?;
    if options.command == Command::Help {
        print_help();
        return Ok(());
    }

    let daemon = daemon_path(&options)?;
    let data_dir = data_dir(&options)?;
    let mut client = DaemonClient::spawn_with_launch_options(
        &daemon,
        &data_dir,
        DaemonLaunchOptions {
            model_policy: options.model_policy.clone(),
        },
    )?;
    let initialized = client.initialize("birdcode-cli", env!("CARGO_PKG_VERSION"))?;

    match &options.command {
        Command::Doctor => run_doctor(&mut client, &initialized)?,
        Command::SessionSmoke => run_session_smoke(&mut client)?,
        Command::Models => print_models(&mut client)?,
        Command::Plan(plan) => {
            require_planning_capability(&initialized.capabilities)?;
            run_plan(&mut client, plan)?;
        }
        Command::Help => unreachable!("help returns before starting the daemon"),
    }
    Ok(())
}

fn run_doctor(
    client: &mut DaemonClient,
    initialized: &birdcode_protocol::InitializeResult,
) -> Result<(), Box<dyn Error>> {
    let health = client.health()?;
    if health.status != HealthStatus::Ready {
        return Err(CliContractError::new("daemon reports degraded local storage").into());
    }
    println!(
        "BirdCode daemon {} is ready (protocol {}, {}/{})",
        initialized.server.version,
        initialized.protocol_version,
        health.platform,
        health.architecture
    );
    Ok(())
}

fn run_session_smoke(client: &mut DaemonClient) -> Result<(), Box<dyn Error>> {
    let workspace_root = std::env::current_dir()?;
    let result = client.call(ClientCommand::CreateSession(CreateSessionRequest {
        workspace_root: workspace_root.into(),
        title: Some("BirdCode CLI smoke – svenska / 日本語".to_owned()),
    }))?;
    let ServerResult::Session(created) = result else {
        return Err(
            CliContractError::new("daemon returned the wrong result for create_session").into(),
        );
    };
    let result = client.call(ClientCommand::GetSession {
        session_id: created.id,
    })?;
    let ServerResult::Session(loaded) = result else {
        return Err(
            CliContractError::new("daemon returned the wrong result for get_session").into(),
        );
    };
    if loaded != created {
        return Err(
            CliContractError::new("reloaded session differs from the created session").into(),
        );
    }
    println!("Session {} persisted and reloaded successfully", loaded.id);
    Ok(())
}

fn print_models(client: &mut DaemonClient) -> Result<(), Box<dyn Error>> {
    let catalog = client.discover_models()?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &catalog)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn require_planning_capability(
    capabilities: &birdcode_protocol::RuntimeCapabilities,
) -> Result<(), CliContractError> {
    if capabilities.supports(RuntimeCapability::DurableRootPlanning) {
        Ok(())
    } else {
        Err(CliContractError::new(
            "daemon does not advertise durable root planning; refusing to create a plan run",
        ))
    }
}

fn run_plan(client: &mut DaemonClient, options: &PlanOptions) -> Result<(), Box<dyn Error>> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&interrupted);
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))?;

    let catalog = client.discover_models()?;
    let resolved_model = resolve_exact_lmstudio_model(&catalog, &options.model)?;
    let workspace = resolve_workspace(options.workspace.as_deref())?;
    let session = create_session(client, workspace)?;
    let run_spec = RunSpec {
        session_id: session.id,
        purpose: RunPurpose::PlanOnly,
        plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
        backend: BackendSelection {
            backend_id: resolved_model.backend_id,
            kind: resolved_model.kind,
            model: Some(resolved_model.model_id),
            reasoning_effort: options
                .reasoning
                .map(|reasoning| reasoning.as_str().to_owned()),
        },
        input: vec![InputItem::Text {
            text: options.goal.clone(),
        }],
        limits: RunLimits {
            max_output_tokens: options.max_output_tokens,
            max_wall_time_seconds: options.max_wall_time_seconds,
            max_subagents: 0,
        },
    };
    let run_id = RunId::new();
    let created = client.create_run(&CreateRunRequest {
        run_id,
        spec: run_spec.clone(),
    })?;
    validate_run_identity(&created, run_id, &run_spec)?;

    let (terminal, outcome) =
        wait_for_terminal_plan(client, &created, interrupted.as_ref(), POLL_INTERVAL)?;
    finish_plan(client, terminal, outcome)?;
    Ok(())
}

fn resolve_workspace(explicit: Option<&Path>) -> Result<PathBuf, Box<dyn Error>> {
    let path = explicit.map_or_else(std::env::current_dir, |path| Ok(path.to_owned()))?;
    Ok(path.canonicalize()?)
}

fn create_session(
    client: &mut DaemonClient,
    workspace: PathBuf,
) -> Result<birdcode_protocol::Session, Box<dyn Error>> {
    let result = client.call(ClientCommand::CreateSession(CreateSessionRequest {
        workspace_root: workspace.into(),
        title: Some("BirdCode CLI root plan".to_owned()),
    }))?;
    match result {
        ServerResult::Session(session) => Ok(session),
        _ => {
            Err(CliContractError::new("daemon returned the wrong result for create_session").into())
        }
    }
}

fn resolve_exact_lmstudio_model(
    catalog: &BackendCatalog,
    requested_model_id: &str,
) -> Result<BackendModelIdentity, CliContractError> {
    let mut matches = catalog.models.iter().filter(|model| {
        model.identity.backend_id == LM_STUDIO_BACKEND_ID
            && model.identity.kind == BackendKind::Model
            && model.identity.model_id.as_bytes() == requested_model_id.as_bytes()
    });
    let selected = matches.next().ok_or_else(|| {
        CliContractError::new(format!(
            "LM Studio did not report an exact model id match for {requested_model_id:?}"
        ))
    })?;
    if matches.next().is_some() {
        return Err(CliContractError::new(format!(
            "LM Studio reported ambiguous duplicate entries for model id {requested_model_id:?}"
        )));
    }
    Ok(selected.identity.clone())
}

fn validate_run_identity(
    run: &Run,
    expected_id: RunId,
    expected_spec: &RunSpec,
) -> Result<(), CliContractError> {
    if run.id != expected_id {
        return Err(CliContractError::new(format!(
            "daemon returned run {} for requested run {expected_id}",
            run.id
        )));
    }
    if &run.spec != expected_spec {
        return Err(CliContractError::new(
            "daemon returned a run whose specification differs from the submitted plan run",
        ));
    }
    Ok(())
}

fn wait_for_terminal_plan(
    client: &mut DaemonClient,
    created: &Run,
    interrupted: &AtomicBool,
    poll_interval: Duration,
) -> Result<(RunState, PlanOutcome), Box<dyn Error>> {
    let mut cursor = 0_u64;
    let mut tracker = DecisionTracker::for_contract(created.spec.plan_acceptance)?;
    let mut cancellation_sent = false;

    loop {
        if interrupted.load(Ordering::SeqCst) && !cancellation_sent {
            let receipt = client.cancel_run(created.id)?;
            if receipt.run_id != created.id {
                return Err(CliContractError::new(
                    "daemon returned a cancellation receipt for a different run",
                )
                .into());
            }
            cancellation_sent = true;
        }

        cursor = drain_event_pages(
            client,
            created.spec.session_id,
            created.id,
            cursor,
            &mut tracker,
        )?;
        let current = client.get_run(created.id)?;
        validate_run_identity(&current, created.id, &created.spec)?;
        if is_terminal(current.state) {
            let _ = drain_event_pages(
                client,
                created.spec.session_id,
                created.id,
                cursor,
                &mut tracker,
            )?;
            return Ok((current.state, tracker.into_outcome(current.state)?));
        }
        thread::sleep(poll_interval);
    }
}

fn drain_event_pages(
    client: &mut DaemonClient,
    session_id: SessionId,
    run_id: RunId,
    mut cursor: u64,
    tracker: &mut DecisionTracker,
) -> Result<u64, Box<dyn Error>> {
    loop {
        let page = client.get_events(session_id, cursor)?;
        cursor = validate_and_observe_page(&page, session_id, run_id, cursor, tracker)?;
        if !tracker.last_page_had_more {
            return Ok(cursor);
        }
    }
}

fn validate_and_observe_page(
    page: &EventPage,
    session_id: SessionId,
    run_id: RunId,
    cursor: u64,
    tracker: &mut DecisionTracker,
) -> Result<u64, CliContractError> {
    if page.has_more && page.events.is_empty() {
        return Err(CliContractError::new(
            "event replay returned an empty non-terminal page",
        ));
    }
    let mut previous = cursor;
    for event in &page.events {
        if event.session_id != session_id {
            return Err(CliContractError::new(
                "event replay crossed the requested session boundary",
            ));
        }
        if event.sequence <= previous {
            return Err(CliContractError::new(
                "event replay sequence did not increase strictly",
            ));
        }
        previous = event.sequence;
        tracker.observe(event, run_id)?;
    }
    if page.next_sequence != previous {
        return Err(CliContractError::new(
            "event replay cursor does not equal the last observed sequence",
        ));
    }
    if page.has_more && page.next_sequence <= cursor {
        return Err(CliContractError::new(
            "event replay claimed more data without advancing its cursor",
        ));
    }
    tracker.last_page_had_more = page.has_more;
    Ok(page.next_sequence)
}

#[derive(Clone, Debug)]
enum PlanDecision {
    MechanicallyAccepted(PlanProposalAccepted),
    MechanicallyRejected(PlanProposalRejected),
    SemanticallyAccepted(PlanSemanticReviewAccepted),
    SemanticallyRejected(PlanSemanticReviewRejected),
}

#[derive(Clone, Debug)]
enum PreProposalFailure {
    Root(RootPlanningFailed),
    Stage(RootPlanningStageFailed),
    Inference(PlannerInferenceError),
    OutcomeUnknown(PlannerInferenceOutcomeUnknown),
}

#[derive(Clone, Debug)]
enum PlanOutcome {
    Decision {
        decision: PlanDecision,
        repair_reviews: Vec<PlanSemanticReviewRejected>,
    },
    PreProposalFailure {
        failure: PreProposalFailure,
        repair_reviews: Vec<PlanSemanticReviewRejected>,
    },
    Cancelled {
        repair_reviews: Vec<PlanSemanticReviewRejected>,
    },
}

struct DecisionTracker {
    acceptance_contract: PlanAcceptanceContract,
    decision: Option<PlanDecision>,
    pre_proposal_failure: Option<PreProposalFailure>,
    validated_candidates: Vec<PlanCandidateBinding>,
    repair_reviews: Vec<PlanSemanticReviewRejected>,
    repair_authorizations: u32,
    last_page_had_more: bool,
}

impl Default for DecisionTracker {
    fn default() -> Self {
        Self {
            acceptance_contract: PlanAcceptanceContract::LegacyMechanicalOnlyV4,
            decision: None,
            pre_proposal_failure: None,
            validated_candidates: Vec::new(),
            repair_reviews: Vec::new(),
            repair_authorizations: 0,
            last_page_had_more: false,
        }
    }
}

impl DecisionTracker {
    fn for_contract(acceptance_contract: PlanAcceptanceContract) -> Result<Self, CliContractError> {
        if acceptance_contract == PlanAcceptanceContract::NotApplicable {
            return Err(CliContractError::new(
                "plan tracker cannot use a not-applicable acceptance contract",
            ));
        }
        Ok(Self {
            acceptance_contract,
            ..Self::default()
        })
    }

    // Keep the closed event-to-state projection together so protocol variants
    // cannot disappear behind catch-all helpers during security review.
    #[allow(clippy::too_many_lines)]
    fn observe(&mut self, event: &EventEnvelope, run_id: RunId) -> Result<(), CliContractError> {
        if event.run_id != Some(run_id) {
            return Ok(());
        }
        let decision = match &event.payload {
            EventPayload::PlanProposalAccepted(accepted)
                if self.acceptance_contract == PlanAcceptanceContract::LegacyMechanicalOnlyV4 =>
            {
                Some(PlanDecision::MechanicallyAccepted(accepted.clone()))
            }
            EventPayload::PlanProposalAccepted(accepted) => {
                if self.decision.is_some() || self.pre_proposal_failure.is_some() {
                    return Err(CliContractError::new(
                        "validated candidate appears after terminal planning evidence",
                    ));
                }
                if self.validated_candidates.len() == 1 && self.repair_authorizations != 1 {
                    return Err(CliContractError::new(
                        "second validated candidate lacks the single repair authorization",
                    ));
                }
                if self.validated_candidates.len() >= 2 {
                    return Err(CliContractError::new(
                        "semantic plan run contains more than two validated candidates",
                    ));
                }
                if accepted.accepted_plan_digest.as_str().as_bytes()
                    != accepted.accepted_plan_artifact.sha256.as_bytes()
                    || accepted.accepted_plan_artifact.media_type != ACCEPTED_PLAN_MEDIA_TYPE
                {
                    return Err(CliContractError::new(
                        "validated candidate digest or media type contradicts its plan artifact",
                    ));
                }
                if let Some(previous) = self.validated_candidates.last()
                    && (accepted.previous_plan_revision != previous.plan_revision
                        || accepted.previous_plan_digest != previous.plan_digest)
                {
                    return Err(CliContractError::new(
                        "repaired candidate is not based on the previous validated candidate",
                    ));
                }
                self.validated_candidates.push(PlanCandidateBinding {
                    proposal_event_id: event.id,
                    plan_revision: accepted.accepted_plan_revision,
                    plan_digest: accepted.accepted_plan_digest.clone(),
                    plan_artifact: accepted.accepted_plan_artifact.clone(),
                });
                None
            }
            EventPayload::PlanProposalRejected(rejected) => {
                if self.acceptance_contract == PlanAcceptanceContract::IndependentSemanticReviewV1
                    && !matches!(
                        (self.validated_candidates.len(), self.repair_authorizations),
                        (0, 0) | (1, 1)
                    )
                {
                    return Err(CliContractError::new(
                        "mechanical rejection appears at an invalid semantic planning stage",
                    ));
                }
                Some(PlanDecision::MechanicallyRejected(rejected.clone()))
            }
            EventPayload::PlanSemanticReviewAccepted(accepted)
                if self.acceptance_contract
                    == PlanAcceptanceContract::IndependentSemanticReviewV1 =>
            {
                self.require_current_review_candidate(&accepted.candidate)?;
                self.require_terminal_review_position()?;
                Some(PlanDecision::SemanticallyAccepted(accepted.clone()))
            }
            EventPayload::PlanSemanticReviewRejected(rejected)
                if self.acceptance_contract
                    == PlanAcceptanceContract::IndependentSemanticReviewV1 =>
            {
                self.require_current_review_candidate(&rejected.candidate)?;
                if rejected.disposition
                    == PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
                {
                    if self.validated_candidates.len() != 1 || self.decision.is_some() {
                        return Err(CliContractError::new(
                            "repair authorization does not follow exactly one validated candidate",
                        ));
                    }
                    self.repair_authorizations = self.repair_authorizations.saturating_add(1);
                    if self.repair_authorizations > 1 {
                        return Err(CliContractError::new(
                            "semantic plan run contains more than one repair authorization",
                        ));
                    }
                    self.repair_reviews.push(rejected.clone());
                    None
                } else {
                    self.require_terminal_review_position()?;
                    Some(PlanDecision::SemanticallyRejected(rejected.clone()))
                }
            }
            EventPayload::PlanSemanticReviewAccepted(_)
            | EventPayload::PlanSemanticReviewRejected(_) => {
                return Err(CliContractError::new(
                    "semantic review event contradicts the run acceptance contract",
                ));
            }
            _ => None,
        };
        if let Some(decision) = decision {
            if self.decision.is_some() {
                return Err(CliContractError::new(
                    "run contains more than one terminal plan decision",
                ));
            }
            self.decision = Some(decision);
        }
        let failure = match &event.payload {
            EventPayload::RootPlanningFailed(failure) => {
                Some(PreProposalFailure::Root(failure.clone()))
            }
            EventPayload::RootPlanningStageFailed(failure) => {
                Some(PreProposalFailure::Stage(failure.clone()))
            }
            EventPayload::PlannerInferenceObserved(observed) => match &observed.outcome {
                PlannerInferenceObservation::Failed { error } => {
                    Some(PreProposalFailure::Inference(error.clone()))
                }
                PlannerInferenceObservation::Succeeded { .. } => None,
            },
            EventPayload::PlannerInferenceOutcomeUnknown(unknown) => {
                Some(PreProposalFailure::OutcomeUnknown(unknown.clone()))
            }
            _ => None,
        };
        if let Some(failure) = failure
            && self.pre_proposal_failure.replace(failure).is_some()
        {
            return Err(CliContractError::new(
                "run contains more than one typed pre-proposal terminal cause",
            ));
        }
        Ok(())
    }

    fn require_current_review_candidate(
        &self,
        candidate: &PlanCandidateBinding,
    ) -> Result<(), CliContractError> {
        if self.validated_candidates.last() == Some(candidate) {
            Ok(())
        } else {
            Err(CliContractError::new(
                "semantic review is not bound to the latest validated candidate event",
            ))
        }
    }

    fn require_terminal_review_position(&self) -> Result<(), CliContractError> {
        if matches!(
            (self.validated_candidates.len(), self.repair_authorizations),
            (1, 0) | (2, 1)
        ) {
            Ok(())
        } else {
            Err(CliContractError::new(
                "terminal semantic review appears at an invalid planning stage",
            ))
        }
    }

    fn into_outcome(self, terminal: RunState) -> Result<PlanOutcome, CliContractError> {
        if terminal == RunState::Cancelled {
            return Ok(PlanOutcome::Cancelled {
                repair_reviews: self.repair_reviews,
            });
        }
        if matches!(
            terminal,
            RunState::Queued | RunState::Running | RunState::Waiting
        ) {
            return Err(CliContractError::new(
                "non-terminal run was passed to terminal plan validation",
            ));
        }
        match (self.decision, self.pre_proposal_failure) {
            (Some(_), Some(_)) => Err(CliContractError::new(
                "terminal plan decision conflicts with a typed planning failure",
            )),
            (Some(decision), None)
                if (terminal == RunState::Completed && decision.is_accepting())
                    || (terminal == RunState::Failed && !decision.is_accepting()) =>
            {
                Ok(PlanOutcome::Decision {
                    decision,
                    repair_reviews: self.repair_reviews,
                })
            }
            (Some(_), None) => Err(CliContractError::new(
                "materialized run state contradicts its terminal plan decision",
            )),
            (None, Some(failure)) if terminal == RunState::Failed => {
                Ok(PlanOutcome::PreProposalFailure {
                    failure,
                    repair_reviews: self.repair_reviews,
                })
            }
            (None, Some(_)) => Err(CliContractError::new(
                "completed plan run contradicts its typed failure evidence",
            )),
            (None, None) if terminal == RunState::Completed => Err(CliContractError::new(
                "completed plan run has no typed semantic acceptance event",
            )),
            (None, None) => Err(CliContractError::new(
                "failed plan run has no typed terminal cause event",
            )),
        }
    }
}

impl PlanDecision {
    const fn is_accepting(&self) -> bool {
        matches!(
            self,
            Self::MechanicallyAccepted(_) | Self::SemanticallyAccepted(_)
        )
    }
}

const fn is_terminal(state: RunState) -> bool {
    matches!(
        state,
        RunState::Completed | RunState::Failed | RunState::Cancelled
    )
}

// Each terminal variant verifies its complete artifact set before producing
// output. Keeping those branches adjacent makes omissions auditable.
#[allow(clippy::too_many_lines)]
fn finish_plan(
    client: &mut DaemonClient,
    terminal: RunState,
    outcome: PlanOutcome,
) -> Result<(), Box<dyn Error>> {
    match outcome {
        PlanOutcome::Decision {
            decision: PlanDecision::MechanicallyAccepted(accepted),
            repair_reviews,
        } => {
            require_no_semantic_repair_reviews(&repair_reviews)?;
            let proposal = fetch_verified_json(
                client,
                &accepted.proposal_artifact,
                PROPOSAL_MEDIA_TYPE,
                "accepted proposal",
            )?;
            let plan = fetch_verified_json(
                client,
                &accepted.accepted_plan_artifact,
                ACCEPTED_PLAN_MEDIA_TYPE,
                "accepted plan",
            )?;
            let validation = fetch_verified_json(
                client,
                &accepted.validation_evidence_artifact,
                VALIDATION_MEDIA_TYPE,
                "accepted-plan validation",
            )?;
            if terminal != RunState::Completed || proposal.is_empty() || validation.is_empty() {
                return Err(CliContractError::new(
                    "accepted plan evidence contradicts the completed run state",
                )
                .into());
            }
            emit_plan_json(&plan)
        }
        PlanOutcome::Decision {
            decision: PlanDecision::MechanicallyRejected(rejected),
            repair_reviews,
        } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            let proposal = fetch_verified_json(
                client,
                &rejected.proposal_artifact,
                PROPOSAL_MEDIA_TYPE,
                "rejected proposal",
            )?;
            let validation = fetch_verified_json(
                client,
                &rejected.validation_evidence_artifact,
                VALIDATION_MEDIA_TYPE,
                "rejection validation",
            )?;
            if terminal != RunState::Failed || proposal.is_empty() || validation.is_empty() {
                return Err(CliContractError::new(
                    "rejected plan evidence contradicts the failed run state",
                )
                .into());
            }
            Err(CliContractError::new(format!(
                "root planner proposal was rejected by typed validation: {:?}",
                rejected.reason
            ))
            .into())
        }
        PlanOutcome::Decision {
            decision: PlanDecision::SemanticallyAccepted(accepted),
            repair_reviews,
        } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            if terminal != RunState::Completed
                || accepted.candidate.plan_digest.as_str().as_bytes()
                    != accepted.candidate.plan_artifact.sha256.as_bytes()
            {
                return Err(CliContractError::new(
                    "semantic acceptance contradicts the completed candidate binding",
                )
                .into());
            }
            let plan = fetch_verified_json(
                client,
                &accepted.candidate.plan_artifact,
                ACCEPTED_PLAN_MEDIA_TYPE,
                "semantically accepted plan",
            )?;
            let critique = fetch_verified_typed_review::<PlanCriticOutput>(
                client,
                &accepted.critique_artifact,
                CRITIQUE_MEDIA_TYPE,
                "semantic critique",
            )?;
            let receipt = fetch_verified_typed_review::<PlanSemanticReviewValidationReceipt>(
                client,
                &accepted.validation_evidence_artifact,
                SEMANTIC_REVIEW_RECEIPT_MEDIA_TYPE,
                "semantic-review receipt",
            )?;
            validate_cli_review_receipt_binding(
                accepted.inference_attempt_id,
                accepted.observed_event_id,
                &accepted.candidate,
                &accepted.critique_artifact,
                &receipt,
            )?;
            validate_cli_typed_critique_binding(&critique, &accepted.candidate, &receipt)?;
            let finding_ids = critique
                .findings
                .iter()
                .map(|finding| finding.finding_id.clone())
                .collect::<Vec<_>>();
            if critique.verdict != PlanCriticVerdict::Accept
                || receipt.verdict != PlanSemanticReviewValidatedVerdict::Accept
                || receipt.finding_ids != finding_ids
            {
                return Err(CliContractError::new(
                    "semantic acceptance contradicts its exact typed critique or validation receipt",
                )
                .into());
            }
            emit_plan_json(&plan)
        }
        PlanOutcome::Decision {
            decision: PlanDecision::SemanticallyRejected(rejected),
            repair_reviews,
        } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            if terminal != RunState::Failed {
                return Err(CliContractError::new(
                    "semantic rejection evidence contradicts the failed run state",
                )
                .into());
            }
            validate_cli_semantic_rejection(client, &rejected)?;
            Err(CliContractError::new(format!(
                "policy-separated semantic review rejected the root plan ({:?})",
                rejected.disposition
            ))
            .into())
        }
        PlanOutcome::PreProposalFailure {
            failure: PreProposalFailure::Root(failure),
            repair_reviews,
        } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            Err(CliContractError::new(format!(
                "root planning failed before inference (phase={}, reason={}, evidence_sha256={})",
                root_failure_phase_name(failure.phase),
                root_failure_reason_name(failure.reason),
                failure.evidence_artifact.sha256
            ))
            .into())
        }
        PlanOutcome::PreProposalFailure {
            failure: PreProposalFailure::Stage(failure),
            repair_reviews,
        } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            Err(CliContractError::new(format!(
                "root planning stage failed (stage={:?}, reason={:?}, evidence_sha256={})",
                failure.failed_stage, failure.reason, failure.evidence_artifact.sha256
            ))
            .into())
        }
        PlanOutcome::PreProposalFailure {
            failure: PreProposalFailure::Inference(error),
            repair_reviews,
        } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            Err(CliContractError::new(format!(
                "planner inference failed (kind={}, retry={})",
                inference_error_kind_name(error.kind),
                retry_disposition_name(error.retry)
            ))
            .into())
        }
        PlanOutcome::PreProposalFailure {
            failure: PreProposalFailure::OutcomeUnknown(unknown),
            repair_reviews,
        } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            Err(CliContractError::new(format!(
                "planner inference outcome is unknown (reason={}); fail-closed reconciliation evidence is required",
                unknown_outcome_reason_name(unknown.reason)
            ))
            .into())
        }
        PlanOutcome::Cancelled { repair_reviews } => {
            validate_cli_repair_review_chain(client, &repair_reviews)?;
            Err(CliContractError::new(
                "plan run was cancelled after its durable cancellation request",
            )
            .into())
        }
    }
}

fn emit_plan_json(plan: &[u8]) -> Result<(), Box<dyn Error>> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_all(plan)?;
    if !plan.ends_with(b"\n") {
        output.write_all(b"\n")?;
    }
    Ok(())
}

const fn root_failure_phase_name(phase: RootPlanningFailurePhase) -> &'static str {
    match phase {
        RootPlanningFailurePhase::Preflight => "preflight",
        RootPlanningFailurePhase::ModelDiscovery => "model_discovery",
        RootPlanningFailurePhase::PromptPreparation => "prompt_preparation",
    }
}

const fn root_failure_reason_name(reason: RootPlanningFailureReason) -> &'static str {
    match reason {
        RootPlanningFailureReason::InvalidWallDeadline => "invalid_wall_deadline",
        RootPlanningFailureReason::InvalidRunConfiguration => "invalid_run_configuration",
        RootPlanningFailureReason::BackendDiscoveryFailed => "backend_discovery_failed",
        RootPlanningFailureReason::DiscoveryTimedOut => "discovery_timed_out",
        RootPlanningFailureReason::InvalidDiscoveryCatalog => "invalid_discovery_catalog",
        RootPlanningFailureReason::SelectedModelUnavailable => "selected_model_unavailable",
        RootPlanningFailureReason::WallDeadlineExceeded => "wall_deadline_exceeded",
        RootPlanningFailureReason::PromptCompilationFailed => "prompt_compilation_failed",
        RootPlanningFailureReason::ArtifactPersistenceFailed => "artifact_persistence_failed",
        RootPlanningFailureReason::DurableStateConflict => "durable_state_conflict",
    }
}

const fn inference_error_kind_name(kind: PlannerInferenceErrorKind) -> &'static str {
    match kind {
        PlannerInferenceErrorKind::Transport => "transport",
        PlannerInferenceErrorKind::Timeout => "timeout",
        PlannerInferenceErrorKind::Authentication => "authentication",
        PlannerInferenceErrorKind::RateLimited => "rate_limited",
        PlannerInferenceErrorKind::ProviderRejected => "provider_rejected",
        PlannerInferenceErrorKind::ProtocolViolation => "protocol_violation",
        PlannerInferenceErrorKind::InvalidStructuredResponse => "invalid_structured_response",
        PlannerInferenceErrorKind::Cancelled => "cancelled",
    }
}

const fn retry_disposition_name(disposition: RetryDisposition) -> &'static str {
    match disposition {
        RetryDisposition::Never => "never",
        RetryDisposition::RequiresNewAttempt => "requires_new_attempt",
    }
}

const fn unknown_outcome_reason_name(reason: UnknownInferenceOutcomeReason) -> &'static str {
    match reason {
        UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation => {
            "runtime_restarted_before_observation"
        }
        UnknownInferenceOutcomeReason::ClaimExpiredBeforeObservation => {
            "claim_expired_before_observation"
        }
        UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate => {
            "evidence_commit_indeterminate"
        }
    }
}

fn fetch_verified_json(
    client: &mut DaemonClient,
    artifact: &ArtifactRef,
    expected_media_type: &str,
    label: &str,
) -> Result<Vec<u8>, CliContractError> {
    let bytes = fetch_verified_media(client, artifact, expected_media_type, label)?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|error| CliContractError::new(format!("{label} is not valid JSON: {error}")))?;
    Ok(bytes)
}

fn fetch_verified_media(
    client: &mut DaemonClient,
    artifact: &ArtifactRef,
    expected_media_type: &str,
    label: &str,
) -> Result<Vec<u8>, CliContractError> {
    if artifact.media_type != expected_media_type {
        return Err(CliContractError::new(format!(
            "{label} has media type {:?}; expected {expected_media_type:?}",
            artifact.media_type
        )));
    }
    let bytes = fetch_verified_artifact(artifact, |reference, offset, maximum| {
        client
            .get_artifact(reference, offset, maximum)
            .map_err(|error| error.to_string())
    })?;
    Ok(bytes)
}

fn fetch_verified_typed_review<T: serde::de::DeserializeOwned>(
    client: &mut DaemonClient,
    artifact: &ArtifactRef,
    expected_media_type: &str,
    label: &str,
) -> Result<T, CliContractError> {
    let bytes = fetch_verified_media(client, artifact, expected_media_type, label)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CliContractError::new(format!("{label} is not valid typed JSON: {error}")))
}

fn require_no_semantic_repair_reviews(
    repair_reviews: &[PlanSemanticReviewRejected],
) -> Result<(), CliContractError> {
    if repair_reviews.is_empty() {
        Ok(())
    } else {
        Err(CliContractError::new(
            "mechanical planning outcome contains semantic repair-review evidence",
        ))
    }
}

fn validate_cli_repair_review_chain(
    client: &mut DaemonClient,
    repair_reviews: &[PlanSemanticReviewRejected],
) -> Result<(), CliContractError> {
    if repair_reviews.len() > 1 {
        return Err(CliContractError::new(
            "semantic planning outcome contains more than one repair review",
        ));
    }
    for review in repair_reviews {
        if review.disposition != PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized {
            return Err(CliContractError::new(
                "semantic repair-review chain contains a non-repair disposition",
            ));
        }
        validate_cli_semantic_rejection(client, review)?;
    }
    Ok(())
}

fn validate_cli_semantic_rejection(
    client: &mut DaemonClient,
    review: &PlanSemanticReviewRejected,
) -> Result<(), CliContractError> {
    let critique_bytes = fetch_verified_media(
        client,
        &review.critique_artifact,
        CRITIQUE_MEDIA_TYPE,
        "semantic rejection critique",
    )?;
    let receipt = fetch_verified_typed_review::<PlanSemanticReviewValidationReceipt>(
        client,
        &review.validation_evidence_artifact,
        SEMANTIC_REVIEW_RECEIPT_MEDIA_TYPE,
        "semantic-rejection receipt",
    )?;
    validate_cli_semantic_rejection_evidence(review, &critique_bytes, &receipt)
}

fn validate_cli_semantic_rejection_evidence(
    review: &PlanSemanticReviewRejected,
    critique_bytes: &[u8],
    receipt: &PlanSemanticReviewValidationReceipt,
) -> Result<(), CliContractError> {
    validate_cli_review_receipt_binding(
        review.inference_attempt_id,
        review.observed_event_id,
        &review.candidate,
        &review.critique_artifact,
        receipt,
    )?;
    match review.disposition {
        PlanSemanticReviewRejectionDisposition::ReviewContractInvalid => {
            if !review.required_finding_ids.is_empty()
                || !receipt.finding_ids.is_empty()
                || receipt.verdict != PlanSemanticReviewValidatedVerdict::ContractInvalid
            {
                return Err(CliContractError::new(
                    "review-contract rejection requires empty findings and a contract-invalid receipt",
                ));
            }
        }
        PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
        | PlanSemanticReviewRejectionDisposition::TerminalReject => {
            let event_findings_match = match review.disposition {
                PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized => {
                    !review.required_finding_ids.is_empty()
                        && receipt.finding_ids == review.required_finding_ids
                }
                PlanSemanticReviewRejectionDisposition::TerminalReject => {
                    review.required_finding_ids.is_empty()
                }
                PlanSemanticReviewRejectionDisposition::ReviewContractInvalid => {
                    unreachable!("contract-invalid disposition is handled above")
                }
            };
            if !event_findings_match {
                return Err(CliContractError::new(
                    "semantic rejection event findings contradict its disposition or receipt",
                ));
            }
            let critique =
                serde_json::from_slice::<PlanCriticOutput>(critique_bytes).map_err(|error| {
                    CliContractError::new(format!(
                        "semantic rejection critique is not typed critic JSON: {error}"
                    ))
                })?;
            validate_cli_typed_critique_binding(&critique, &review.candidate, receipt)?;
            let expected_verdict = validated_cli_critic_verdict(critique.verdict);
            if receipt.verdict != expected_verdict
                || receipt.verdict == PlanSemanticReviewValidatedVerdict::Accept
                || (review.disposition
                    == PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized
                    && receipt.verdict != PlanSemanticReviewValidatedVerdict::Revise)
            {
                return Err(CliContractError::new(
                    "semantic rejection disposition contradicts its typed verdict",
                ));
            }
            let finding_ids = critique
                .findings
                .iter()
                .map(|finding| finding.finding_id.clone())
                .collect::<Vec<_>>();
            if receipt.finding_ids != finding_ids {
                return Err(CliContractError::new(
                    "semantic rejection receipt differs from the exact critique findings",
                ));
            }
        }
    }
    Ok(())
}

fn validate_cli_review_receipt_binding(
    inference_attempt_id: birdcode_protocol::InferenceAttemptId,
    observed_event_id: birdcode_protocol::EventId,
    candidate: &PlanCandidateBinding,
    critique_artifact: &ArtifactRef,
    receipt: &PlanSemanticReviewValidationReceipt,
) -> Result<(), CliContractError> {
    if receipt.schema_version != 1
        || receipt.inference_attempt_id != inference_attempt_id
        || receipt.observed_event_id != observed_event_id
        || &receipt.candidate != candidate
        || receipt.critique_sha256.as_str().as_bytes() != critique_artifact.sha256.as_bytes()
    {
        return Err(CliContractError::new(
            "semantic-review receipt is not bound to the exact event, candidate, and critique",
        ));
    }
    Ok(())
}

fn validate_cli_typed_critique_binding(
    critique: &PlanCriticOutput,
    candidate: &PlanCandidateBinding,
    receipt: &PlanSemanticReviewValidationReceipt,
) -> Result<(), CliContractError> {
    if critique.schema_version != 1
        || critique.bindings.candidate_plan_sha256.as_bytes()
            != candidate.plan_digest.as_str().as_bytes()
        || critique.bindings.critic_policy_sha256.as_bytes()
            != receipt.critic_policy_sha256.as_str().as_bytes()
    {
        return Err(CliContractError::new(
            "typed semantic critique is not bound to the exact candidate and critic policy",
        ));
    }
    Ok(())
}

const fn validated_cli_critic_verdict(
    verdict: PlanCriticVerdict,
) -> PlanSemanticReviewValidatedVerdict {
    match verdict {
        PlanCriticVerdict::Accept => PlanSemanticReviewValidatedVerdict::Accept,
        PlanCriticVerdict::Revise => PlanSemanticReviewValidatedVerdict::Revise,
        PlanCriticVerdict::Clarify => PlanSemanticReviewValidatedVerdict::Clarify,
        PlanCriticVerdict::Escalate => PlanSemanticReviewValidatedVerdict::Escalate,
    }
}

fn fetch_verified_artifact(
    artifact: &ArtifactRef,
    mut read: impl FnMut(ArtifactRef, u64, u32) -> Result<ArtifactChunk, String>,
) -> Result<Vec<u8>, CliContractError> {
    if artifact.size_bytes > MAX_CLI_ARTIFACT_BYTES {
        return Err(CliContractError::new(format!(
            "artifact {} declares {} bytes; CLI limit is {MAX_CLI_ARTIFACT_BYTES}",
            artifact.sha256, artifact.size_bytes
        )));
    }
    let capacity = usize::try_from(artifact.size_bytes)
        .map_err(|_| CliContractError::new("artifact size does not fit this platform"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut offset = 0_u64;
    loop {
        let chunk = read(artifact.clone(), offset, MAX_ARTIFACT_CHUNK_BYTES)
            .map_err(CliContractError::new)?;
        if chunk.artifact() != artifact || chunk.offset() != offset {
            return Err(CliContractError::new(
                "artifact page is not bound to the requested reference and cursor",
            ));
        }
        let next_offset = chunk.next_offset();
        let eof = chunk.eof();
        bytes.extend_from_slice(chunk.data());
        if eof {
            if next_offset != artifact.size_bytes {
                return Err(CliContractError::new(
                    "artifact page reached EOF at the wrong declared size",
                ));
            }
            break;
        }
        if next_offset <= offset {
            return Err(CliContractError::new("artifact pagination did not advance"));
        }
        offset = next_offset;
    }
    if u64::try_from(bytes.len()).ok() != Some(artifact.size_bytes) {
        return Err(CliContractError::new(
            "assembled artifact length differs from its reference",
        ));
    }
    let actual_sha256 = sha256_hex(&bytes);
    if actual_sha256.as_bytes() != artifact.sha256.as_bytes() {
        return Err(CliContractError::new(format!(
            "assembled artifact SHA-256 {actual_sha256} differs from reference {}",
            artifact.sha256
        )));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn daemon_path(options: &Options) -> Result<PathBuf, Box<dyn Error>> {
    Ok(resolve_daemon_path(options.daemon.as_deref())?)
}

fn data_dir(options: &Options) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = &options.data_dir {
        return Ok(path.clone());
    }
    if let Some(path) = std::env::var_os("BIRDCODE_DATA_DIR") {
        return Ok(path.into());
    }
    Ok(std::env::current_dir()?.join(".birdcode"))
}

fn print_help() {
    println!(concat!(
        "BirdCode CLI\n\n",
        "Usage:\n",
        "  birdcode doctor [--daemon PATH] [--data-dir PATH]\n",
        "  birdcode session-smoke [--daemon PATH] [--data-dir PATH]\n",
        "  birdcode models [--daemon PATH] [--data-dir PATH]\n",
        "  birdcode plan --model ID --goal TEXT --model-policy PATH [--workspace PATH] \\\n",
        "    [--max-output-tokens N] [--max-wall-time-seconds N] \\\n",
        "    [--reasoning off|low|medium|high] \\\n",
        "    [--daemon PATH] [--data-dir PATH]\n\n",
        "Plan output is emitted only after policy-separated semantic acceptance. Model ids\n",
        "are exact, case-sensitive values from `birdcode models`; BirdCode never guesses\n",
        "one. The strict policy file pins producer/critic lineages and stage budgets.\n\n",
        "BIRDCODE_DAEMON and BIRDCODE_DATA_DIR provide equivalent defaults."
    ));
}

#[derive(Debug)]
struct CliContractError(String);

impl CliContractError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CliContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CliContractError {}

#[cfg(test)]
mod tests {
    use super::{
        ACCEPTED_PLAN_MEDIA_TYPE, DecisionTracker, LM_STUDIO_BACKEND_ID, PlanDecision, PlanOutcome,
        PreProposalFailure, fetch_verified_artifact, resolve_exact_lmstudio_model, sha256_hex,
        validate_cli_review_receipt_binding, validate_cli_semantic_rejection_evidence,
        validate_cli_typed_critique_binding,
    };
    use birdcode_protocol::{
        ActorId, ArtifactChunk, ArtifactRef, BackendCatalog, BackendKind, BackendModelIdentity,
        DiscoveredModel, EventEnvelope, EventId, EventPayload, PlanAcceptanceContract,
        PlanCandidateBinding, PlanProposalAccepted, PlanProposalId, PlanProposalRejected,
        PlanProposalRejectionReason, PlanSemanticReviewAccepted, PlanSemanticReviewId,
        PlanSemanticReviewRejected, PlanSemanticReviewRejectionDisposition,
        PlanSemanticReviewValidatedVerdict, PlanSemanticReviewValidationReceipt,
        PlannerInferenceError, PlannerInferenceErrorKind, Provenance, RetryDisposition, RunId,
        RunState, SessionId, Sha256Digest,
    };

    fn catalog(models: &[DiscoveredModel]) -> BackendCatalog {
        serde_json::from_value(serde_json::json!({
            "discovered_at": "2026-07-19T12:00:00Z",
            "models": models,
        }))
        .expect("catalog fixture should decode")
    }

    fn artifact(bytes: &[u8], media_type: &str) -> ArtifactRef {
        ArtifactRef {
            sha256: sha256_hex(bytes),
            size_bytes: u64::try_from(bytes.len()).expect("fixture length should fit u64"),
            media_type: media_type.to_owned(),
        }
    }

    #[test]
    fn exact_lmstudio_model_selection_never_normalizes_or_guesses() {
        let exact = DiscoveredModel {
            identity: BackendModelIdentity {
                backend_id: LM_STUDIO_BACKEND_ID.to_owned(),
                kind: BackendKind::Model,
                model_id: "Gemma/モデル-26B".to_owned(),
            },
            display_name: None,
            context_window_tokens: None,
            max_output_tokens: None,
        };
        let other_backend = DiscoveredModel {
            identity: BackendModelIdentity {
                backend_id: "ollama".to_owned(),
                kind: BackendKind::Model,
                model_id: exact.identity.model_id.clone(),
            },
            display_name: None,
            context_window_tokens: None,
            max_output_tokens: None,
        };
        let catalog = catalog(&[other_backend, exact.clone()]);

        assert_eq!(
            resolve_exact_lmstudio_model(&catalog, "Gemma/モデル-26B")
                .expect("exact identity should resolve"),
            exact.identity
        );
        assert!(
            resolve_exact_lmstudio_model(&catalog, "gemma/モデル-26b").is_err(),
            "case changes must not be silently normalized"
        );
    }

    #[test]
    fn duplicate_exact_model_identity_is_ambiguous() {
        let model = DiscoveredModel {
            identity: BackendModelIdentity {
                backend_id: LM_STUDIO_BACKEND_ID.to_owned(),
                kind: BackendKind::Model,
                model_id: "same".to_owned(),
            },
            display_name: None,
            context_window_tokens: None,
            max_output_tokens: None,
        };
        let catalog = catalog(&[model.clone(), model]);
        let error = resolve_exact_lmstudio_model(&catalog, "same")
            .expect_err("duplicate identities must fail closed");
        assert!(error.to_string().contains("ambiguous duplicate"));
    }

    #[test]
    fn artifact_reader_paginates_and_verifies_length_and_digest() {
        let bytes = "{\"unicode\":\"svenska / 日本語\",\"plan\":[1,2,3]}".as_bytes();
        let reference = artifact(bytes, ACCEPTED_PLAN_MEDIA_TYPE);
        let mut calls = 0_usize;
        let loaded = fetch_verified_artifact(&reference, |requested, offset, _| {
            calls += 1;
            let start = usize::try_from(offset).map_err(|error| error.to_string())?;
            let end = (start + 7).min(bytes.len());
            ArtifactChunk::new(
                requested,
                offset,
                bytes[start..end].to_vec(),
                end == bytes.len(),
            )
            .map_err(|error| error.to_string())
        })
        .expect("valid pages should assemble");

        assert_eq!(loaded, bytes);
        assert!(calls > 1, "fixture should exercise pagination");
    }

    #[test]
    fn artifact_reader_rejects_content_that_does_not_match_reference_hash() {
        let expected = b"{\"plan\":true}";
        let reference = artifact(expected, ACCEPTED_PLAN_MEDIA_TYPE);
        let forged = b"{\"plan\":fals}";
        assert_eq!(forged.len(), expected.len());
        let error = fetch_verified_artifact(&reference, |requested, offset, _| {
            ArtifactChunk::new(requested, offset, forged.to_vec(), true)
                .map_err(|error| error.to_string())
        })
        .expect_err("same-length forged bytes must fail hashing");
        assert!(error.to_string().contains("SHA-256"));
    }

    #[test]
    fn semantic_receipt_must_bind_the_exact_candidate_and_critique() {
        let plan_artifact = artifact(b"{}", ACCEPTED_PLAN_MEDIA_TYPE);
        let plan_digest = Sha256Digest::parse(plan_artifact.sha256.clone())
            .expect("plan digest should be canonical");
        let critique_artifact = artifact(b"{}", super::CRITIQUE_MEDIA_TYPE);
        let critique_digest = Sha256Digest::parse(critique_artifact.sha256.clone())
            .expect("critique digest should be canonical");
        let candidate = PlanCandidateBinding {
            proposal_event_id: EventId::new(),
            plan_revision: 2,
            plan_digest,
            plan_artifact,
        };
        let inference_attempt_id = birdcode_protocol::InferenceAttemptId::new();
        let observed_event_id = EventId::new();
        let bound_digest =
            || Sha256Digest::parse("d".repeat(64)).expect("receipt digest should be canonical");
        let mut receipt = PlanSemanticReviewValidationReceipt {
            schema_version: 1,
            inference_attempt_id,
            observed_event_id,
            candidate: candidate.clone(),
            prompt_manifest_sha256: bound_digest(),
            prompt_artifact_sha256: bound_digest(),
            request_artifact_sha256: bound_digest(),
            normalized_evidence_sha256: bound_digest(),
            critic_policy_sha256: bound_digest(),
            critique_sha256: critique_digest,
            verdict: PlanSemanticReviewValidatedVerdict::Accept,
            finding_ids: Vec::new(),
        };

        validate_cli_review_receipt_binding(
            inference_attempt_id,
            observed_event_id,
            &candidate,
            &critique_artifact,
            &receipt,
        )
        .expect("exact receipt should validate");
        receipt.candidate.plan_revision += 1;
        assert!(
            validate_cli_review_receipt_binding(
                inference_attempt_id,
                observed_event_id,
                &candidate,
                &critique_artifact,
                &receipt,
            )
            .is_err()
        );
    }

    #[test]
    fn semantic_critique_must_bind_the_exact_candidate_and_critic_policy() {
        let plan_artifact = artifact(b"{}", ACCEPTED_PLAN_MEDIA_TYPE);
        let plan_digest = Sha256Digest::parse(plan_artifact.sha256.clone())
            .expect("plan digest should be canonical");
        let candidate = PlanCandidateBinding {
            proposal_event_id: EventId::new(),
            plan_revision: 1,
            plan_digest: plan_digest.clone(),
            plan_artifact,
        };
        let critic_policy_sha256 =
            Sha256Digest::parse("d".repeat(64)).expect("policy digest should be canonical");
        let receipt = PlanSemanticReviewValidationReceipt {
            schema_version: 1,
            inference_attempt_id: birdcode_protocol::InferenceAttemptId::new(),
            observed_event_id: EventId::new(),
            candidate: candidate.clone(),
            prompt_manifest_sha256: critic_policy_sha256.clone(),
            prompt_artifact_sha256: critic_policy_sha256.clone(),
            request_artifact_sha256: critic_policy_sha256.clone(),
            normalized_evidence_sha256: critic_policy_sha256.clone(),
            critic_policy_sha256: critic_policy_sha256.clone(),
            critique_sha256: critic_policy_sha256,
            verdict: PlanSemanticReviewValidatedVerdict::Accept,
            finding_ids: Vec::new(),
        };
        let mut critique =
            serde_json::from_value::<birdcode_prompting::PlanCriticOutput>(serde_json::json!({
                "schema_version": 1,
                "bindings": {
                    "root_snapshot_sha256": "a".repeat(64),
                    "planner_policy_sha256": "b".repeat(64),
                    "context_manifest_sha256": "c".repeat(64),
                    "candidate_plan_sha256": plan_digest.as_str(),
                    "critic_policy_sha256": "d".repeat(64)
                },
                "verdict": "accept",
                "summary": "Bound acceptance",
                "obligation_assessments": [],
                "findings": [],
                "clarification_questions": [],
                "escalation_requests": [],
                "decision_evidence": []
            }))
            .expect("typed critique fixture should decode");

        validate_cli_typed_critique_binding(&critique, &candidate, &receipt)
            .expect("exact critique binding should validate");
        critique.bindings.critic_policy_sha256 = "e".repeat(64);
        assert!(validate_cli_typed_critique_binding(&critique, &candidate, &receipt).is_err());
    }

    #[test]
    fn repair_review_evidence_requires_exact_typed_critique_receipt_and_findings() {
        let plan_artifact = artifact(b"{}", ACCEPTED_PLAN_MEDIA_TYPE);
        let plan_digest = Sha256Digest::parse(plan_artifact.sha256.clone())
            .expect("plan digest should be canonical");
        let candidate = PlanCandidateBinding {
            proposal_event_id: EventId::new(),
            plan_revision: 1,
            plan_digest: plan_digest.clone(),
            plan_artifact,
        };
        let critique_bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "bindings": {
                "root_snapshot_sha256": "a".repeat(64),
                "planner_policy_sha256": "b".repeat(64),
                "context_manifest_sha256": "c".repeat(64),
                "candidate_plan_sha256": plan_digest.as_str(),
                "critic_policy_sha256": "d".repeat(64)
            },
            "verdict": "revise",
            "summary": "Repair is required",
            "obligation_assessments": [],
            "findings": [{
                "finding_id": "finding-1",
                "severity": "major",
                "category": "verification",
                "statement": "Verification is incomplete",
                "source_sections": [],
                "affected_work_order_ids": [],
                "required_change": "Add an executable verification target"
            }],
            "clarification_questions": [],
            "escalation_requests": [],
            "decision_evidence": []
        }))
        .expect("critique fixture should encode");
        let critique_artifact = artifact(&critique_bytes, super::CRITIQUE_MEDIA_TYPE);
        let critique_digest = Sha256Digest::parse(critique_artifact.sha256.clone())
            .expect("critique digest should be canonical");
        let inference_attempt_id = birdcode_protocol::InferenceAttemptId::new();
        let observed_event_id = EventId::new();
        let policy_digest =
            Sha256Digest::parse("d".repeat(64)).expect("policy digest should be canonical");
        let review = PlanSemanticReviewRejected {
            review_id: PlanSemanticReviewId::new(),
            inference_attempt_id,
            observed_event_id,
            candidate: candidate.clone(),
            critique_artifact,
            validation_evidence_artifact: artifact(
                b"{}",
                super::SEMANTIC_REVIEW_RECEIPT_MEDIA_TYPE,
            ),
            disposition: PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized,
            required_finding_ids: vec!["finding-1".to_owned()],
        };
        let mut receipt = PlanSemanticReviewValidationReceipt {
            schema_version: 1,
            inference_attempt_id,
            observed_event_id,
            candidate,
            prompt_manifest_sha256: policy_digest.clone(),
            prompt_artifact_sha256: policy_digest.clone(),
            request_artifact_sha256: policy_digest.clone(),
            normalized_evidence_sha256: policy_digest.clone(),
            critic_policy_sha256: policy_digest,
            critique_sha256: critique_digest,
            verdict: PlanSemanticReviewValidatedVerdict::Revise,
            finding_ids: vec!["finding-1".to_owned()],
        };

        validate_cli_semantic_rejection_evidence(&review, &critique_bytes, &receipt)
            .expect("exact repair review evidence should validate");

        let mut terminal_review = review.clone();
        terminal_review.disposition = PlanSemanticReviewRejectionDisposition::TerminalReject;
        terminal_review.required_finding_ids.clear();
        validate_cli_semantic_rejection_evidence(&terminal_review, &critique_bytes, &receipt)
            .expect("terminal revise keeps critique findings in the receipt, not the event");
        terminal_review.required_finding_ids = vec!["finding-1".to_owned()];
        assert!(
            validate_cli_semantic_rejection_evidence(&terminal_review, &critique_bytes, &receipt,)
                .is_err()
        );

        receipt.verdict = PlanSemanticReviewValidatedVerdict::Accept;
        assert!(
            validate_cli_semantic_rejection_evidence(&review, &critique_bytes, &receipt).is_err()
        );
    }

    #[test]
    fn decision_tracker_rejects_ambiguous_terminal_decisions() {
        let session_id = SessionId::new();
        let run_id = RunId::new();
        let artifact = artifact(b"{}", ACCEPTED_PLAN_MEDIA_TYPE);
        let digest = Sha256Digest::parse(sha256_hex(b"base")).expect("digest should be valid");
        let accepted = PlanProposalAccepted {
            proposal_id: PlanProposalId::new(),
            inference_attempt_id: birdcode_protocol::InferenceAttemptId::new(),
            observed_event_id: EventId::new(),
            proposal_artifact: artifact.clone(),
            previous_plan_revision: 0,
            previous_plan_digest: digest.clone(),
            accepted_plan_revision: 1,
            accepted_plan_digest: digest,
            accepted_plan_artifact: artifact.clone(),
            validation_evidence_artifact: artifact,
        };
        let event = |sequence| EventEnvelope {
            id: EventId::new(),
            sequence,
            session_id,
            run_id: Some(run_id),
            actor_id: ActorId::new(),
            causal_parent: None,
            occurred_at: serde_json::from_value(serde_json::json!("2026-07-19T12:00:00Z"))
                .expect("event time should decode"),
            provenance: Provenance {
                producer: "test".to_owned(),
                backend: None,
                raw_artifact: None,
            },
            payload: EventPayload::PlanProposalAccepted(accepted.clone()),
        };
        let mut tracker = DecisionTracker::default();
        tracker
            .observe(&event(1), run_id)
            .expect("first decision should be retained");
        let error = tracker
            .observe(&event(2), run_id)
            .expect_err("a second decision must be rejected");
        assert!(error.to_string().contains("more than one"));
        assert!(matches!(
            tracker.decision,
            Some(PlanDecision::MechanicallyAccepted(_))
        ));
    }

    #[test]
    fn semantic_tracker_treats_two_candidates_and_repair_authorization_as_nonterminal() {
        let session_id = SessionId::new();
        let run_id = RunId::new();
        let plan_artifact = artifact(b"{}", ACCEPTED_PLAN_MEDIA_TYPE);
        let plan_digest = Sha256Digest::parse(plan_artifact.sha256.clone())
            .expect("plan artifact digest should be canonical");
        let evidence = artifact(b"{\"evidence\":true}", "application/json");
        let proposal = |revision: u64| PlanProposalAccepted {
            proposal_id: PlanProposalId::new(),
            inference_attempt_id: birdcode_protocol::InferenceAttemptId::new(),
            observed_event_id: EventId::new(),
            proposal_artifact: evidence.clone(),
            previous_plan_revision: revision.saturating_sub(1),
            previous_plan_digest: plan_digest.clone(),
            accepted_plan_revision: revision,
            accepted_plan_digest: plan_digest.clone(),
            accepted_plan_artifact: plan_artifact.clone(),
            validation_evidence_artifact: evidence.clone(),
        };
        let event = |sequence, payload| EventEnvelope {
            id: EventId::new(),
            sequence,
            session_id,
            run_id: Some(run_id),
            actor_id: ActorId::new(),
            causal_parent: None,
            occurred_at: serde_json::from_value(serde_json::json!("2026-07-19T12:00:00Z"))
                .expect("event time should decode"),
            provenance: Provenance {
                producer: "test".to_owned(),
                backend: None,
                raw_artifact: None,
            },
            payload,
        };
        let mut tracker =
            DecisionTracker::for_contract(PlanAcceptanceContract::IndependentSemanticReviewV1)
                .expect("semantic contract should be trackable");
        let initial_candidate_event = event(1, EventPayload::PlanProposalAccepted(proposal(1)));
        let initial_candidate = PlanCandidateBinding {
            proposal_event_id: initial_candidate_event.id,
            plan_revision: 1,
            plan_digest: plan_digest.clone(),
            plan_artifact: plan_artifact.clone(),
        };
        tracker
            .observe(&initial_candidate_event, run_id)
            .expect("initial candidate is not terminal");
        tracker
            .observe(
                &event(
                    2,
                    EventPayload::PlanSemanticReviewRejected(PlanSemanticReviewRejected {
                        review_id: PlanSemanticReviewId::new(),
                        inference_attempt_id: birdcode_protocol::InferenceAttemptId::new(),
                        observed_event_id: EventId::new(),
                        candidate: initial_candidate,
                        critique_artifact: evidence.clone(),
                        validation_evidence_artifact: evidence.clone(),
                        disposition: PlanSemanticReviewRejectionDisposition::RepairOnceAuthorized,
                        required_finding_ids: vec!["finding-1".to_owned()],
                    }),
                ),
                run_id,
            )
            .expect("one repair authorization is not terminal");
        let repaired_candidate_event = event(3, EventPayload::PlanProposalAccepted(proposal(2)));
        let repaired_candidate = PlanCandidateBinding {
            proposal_event_id: repaired_candidate_event.id,
            plan_revision: 2,
            plan_digest,
            plan_artifact,
        };
        tracker
            .observe(&repaired_candidate_event, run_id)
            .expect("repaired candidate is not terminal");
        tracker
            .observe(
                &event(
                    4,
                    EventPayload::PlanSemanticReviewAccepted(PlanSemanticReviewAccepted {
                        review_id: PlanSemanticReviewId::new(),
                        inference_attempt_id: birdcode_protocol::InferenceAttemptId::new(),
                        observed_event_id: EventId::new(),
                        candidate: repaired_candidate,
                        critique_artifact: evidence.clone(),
                        validation_evidence_artifact: evidence,
                    }),
                ),
                run_id,
            )
            .expect("final semantic acceptance is terminal");

        assert!(matches!(
            tracker
                .into_outcome(RunState::Completed)
                .expect("completed semantic run should project"),
            PlanOutcome::Decision {
                decision: PlanDecision::SemanticallyAccepted(_),
                repair_reviews,
            } if repair_reviews.len() == 1
        ));
    }

    #[test]
    fn failed_run_projects_a_typed_inference_failure_without_parsing_messages() {
        let tracker = DecisionTracker {
            pre_proposal_failure: Some(PreProposalFailure::Inference(PlannerInferenceError {
                kind: PlannerInferenceErrorKind::Authentication,
                retry: RetryDisposition::Never,
            })),
            ..DecisionTracker::default()
        };

        let outcome = tracker
            .into_outcome(RunState::Failed)
            .expect("typed cause should explain the failed run");

        assert!(matches!(
            outcome,
            PlanOutcome::PreProposalFailure {
                failure: PreProposalFailure::Inference(PlannerInferenceError {
                    kind: PlannerInferenceErrorKind::Authentication,
                    retry: RetryDisposition::Never,
                }),
                repair_reviews,
            } if repair_reviews.is_empty()
        ));
    }

    #[test]
    fn cancellation_dominates_both_typed_plan_decisions() {
        let proposal_artifact = artifact(b"{}", ACCEPTED_PLAN_MEDIA_TYPE);
        let base_digest =
            Sha256Digest::parse(sha256_hex(b"base")).expect("base digest should be valid");
        let inference_attempt_id = birdcode_protocol::InferenceAttemptId::new();
        let observed_event_id = EventId::new();
        let decisions = [
            PlanDecision::MechanicallyAccepted(PlanProposalAccepted {
                proposal_id: PlanProposalId::new(),
                inference_attempt_id,
                observed_event_id,
                proposal_artifact: proposal_artifact.clone(),
                previous_plan_revision: 0,
                previous_plan_digest: base_digest.clone(),
                accepted_plan_revision: 1,
                accepted_plan_digest: Sha256Digest::parse(proposal_artifact.sha256.clone())
                    .expect("artifact digest should be canonical"),
                accepted_plan_artifact: proposal_artifact.clone(),
                validation_evidence_artifact: proposal_artifact.clone(),
            }),
            PlanDecision::MechanicallyRejected(PlanProposalRejected {
                proposal_id: PlanProposalId::new(),
                inference_attempt_id,
                observed_event_id,
                proposal_artifact: proposal_artifact.clone(),
                base_plan_revision: 0,
                base_plan_digest: base_digest,
                reason: PlanProposalRejectionReason::InvalidSchema,
                validation_evidence_artifact: proposal_artifact,
            }),
        ];

        for decision in decisions {
            let outcome = DecisionTracker {
                decision: Some(decision),
                ..DecisionTracker::default()
            }
            .into_outcome(RunState::Cancelled)
            .expect("durable cancellation should dominate an earlier typed decision");
            assert!(matches!(
                outcome,
                PlanOutcome::Cancelled { repair_reviews } if repair_reviews.is_empty()
            ));
        }
    }

    #[test]
    fn failed_run_without_typed_terminal_evidence_fails_closed() {
        let error = DecisionTracker::default()
            .into_outcome(RunState::Failed)
            .expect_err("generic failed state is not enough evidence");

        assert_eq!(
            error.to_string(),
            "failed plan run has no typed terminal cause event"
        );
    }
}
