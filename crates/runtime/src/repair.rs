use birdcode_backends::{
    ContractError, Message as BackendMessage, MessageRole as BackendMessageRole, ModelId,
    ReasoningSetting, StructuredInferenceRequest, StructuredOutputSpec,
};
use birdcode_prompting::{
    CompiledMessage, CompiledPrompt, DataProvenance, DataSection, MessageContent,
    MessageRole as PromptMessageRole, PlanCriticInvariantViolation, PlanCriticOutput,
    PlanCriticPolicy, PlanCriticVerdict, PromptError, PromptInvocation, PromptLimits,
    RootPlannerInvariantViolation, RootPlannerOutput, RootPlannerPolicy, RuntimeConstraint,
    SourceKind, TrustLevel, builtin_registry, plan_repair_key, validate_plan_critic_output,
    validate_root_planner_output,
};
pub use birdcode_protocol::ROOT_PLANNING_POLICY_V1_REPAIR_MAX_OUTPUT_TOKENS as MAX_PLAN_REPAIR_OUTPUT_TOKENS;
use birdcode_protocol::{
    BackendKind, EventId, InputItem, Run, RunPurpose, Session, Sha256Digest, Sha256DigestError,
    WorkspacePath,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

const REPAIR_OUTPUT_SCHEMA_NAME: &str = "birdcode_root_plan_repair_v1";
const MISSING_SELECTED_MODEL_MESSAGE: &str = "repair requires an exact selected producer model";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Fully bound request material for the single authorized repair attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledPlanRepairRequest {
    pub prompt_invocation: PromptInvocation,
    pub compiled_prompt: CompiledPrompt,
    pub inference_request: StructuredInferenceRequest,
    pub candidate_plan_sha256: Sha256Digest,
    pub critique_sha256: Sha256Digest,
    pub repair_assignment_sha256: Sha256Digest,
    pub repair_context_manifest_sha256: Sha256Digest,
    pub prompt_manifest_sha256: Sha256Digest,
    pub request_sha256: Sha256Digest,
    pub triggering_review_event_id: EventId,
    pub required_finding_ids: Vec<String>,
}

#[derive(Debug)]
pub enum PlanRepairCompileError {
    UnsupportedPurpose {
        actual: RunPurpose,
    },
    UnsupportedBackendKind {
        actual: BackendKind,
    },
    SessionMismatch {
        session_id: String,
        run_session_id: String,
    },
    EmptyInput,
    BlankTextInput {
        index: usize,
    },
    UnsupportedArtifactInput {
        index: usize,
    },
    BlankBackendId,
    MissingSelectedModel,
    BlankSelectedModel,
    BlankRepairModel,
    RepairModelSelectionMismatch {
        selected: String,
        resolved: String,
    },
    SubagentsNotAuthorized {
        requested: u32,
    },
    ZeroMaxOutputTokens,
    MaxOutputTokensExceedCompilerCeiling {
        requested: u32,
        maximum: u32,
    },
    MaxOutputTokensExceedRunLimit {
        requested: u32,
        maximum: u64,
    },
    CandidatePlanDigestMismatch {
        expected: String,
        actual: String,
    },
    CritiqueDigestMismatch {
        expected: String,
        actual: String,
    },
    CriticRootPolicyMismatch,
    CriticCandidateMismatch {
        expected: String,
        actual: String,
    },
    CriticVerdictNotRevisable {
        actual: PlanCriticVerdict,
    },
    RequiredFindingIdsMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    RootPlannerCandidate(Vec<RootPlannerInvariantViolation>),
    CriticOutput(Vec<PlanCriticInvariantViolation>),
    Serialization {
        target: &'static str,
        message: String,
    },
    Prompt(PromptError),
    BackendContract(ContractError),
    Digest(Sha256DigestError),
}

impl fmt::Display for PlanRepairCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPurpose { actual } => {
                write!(
                    formatter,
                    "run purpose {actual:?} does not support plan repair"
                )
            }
            Self::UnsupportedBackendKind { actual } => {
                write!(
                    formatter,
                    "backend kind {actual:?} does not support plan repair"
                )
            }
            Self::SessionMismatch {
                session_id,
                run_session_id,
            } => write!(
                formatter,
                "session {session_id} does not own run session {run_session_id}"
            ),
            Self::EmptyInput => formatter.write_str("plan repair requires the original run input"),
            Self::BlankTextInput { index } => {
                write!(formatter, "text input at index {index} must not be blank")
            }
            Self::UnsupportedArtifactInput { index } => write!(
                formatter,
                "artifact input at index {index} cannot be bound without reading its content"
            ),
            Self::BlankBackendId => formatter.write_str("repair backend id must not be blank"),
            Self::MissingSelectedModel => formatter.write_str(MISSING_SELECTED_MODEL_MESSAGE),
            Self::BlankSelectedModel => {
                formatter.write_str("selected repair model must not be blank")
            }
            Self::BlankRepairModel => {
                formatter.write_str("resolved repair model must not be blank")
            }
            Self::RepairModelSelectionMismatch { selected, resolved } => write!(
                formatter,
                "resolved repair model {resolved} differs from selected producer model {selected}"
            ),
            Self::SubagentsNotAuthorized { requested } => write!(
                formatter,
                "read-only plan repair cannot exercise {requested} subagent grants"
            ),
            Self::ZeroMaxOutputTokens => {
                formatter.write_str("repair max_output_tokens must be greater than zero")
            }
            Self::MaxOutputTokensExceedCompilerCeiling { requested, maximum } => write!(
                formatter,
                "repair max_output_tokens {requested} exceeds compiler ceiling {maximum}"
            ),
            Self::MaxOutputTokensExceedRunLimit { requested, maximum } => write!(
                formatter,
                "repair max_output_tokens {requested} exceeds run limit {maximum}"
            ),
            Self::CandidatePlanDigestMismatch { expected, actual } => write!(
                formatter,
                "candidate artifact digest {actual} does not match exact candidate bytes {expected}"
            ),
            Self::CritiqueDigestMismatch { expected, actual } => write!(
                formatter,
                "critique artifact digest {actual} does not match exact critique bytes {expected}"
            ),
            Self::CriticRootPolicyMismatch => formatter.write_str(
                "committed critic policy is not bound to the original root planner policy",
            ),
            Self::CriticCandidateMismatch { expected, actual } => write!(
                formatter,
                "critic policy candidate {actual} does not match repair candidate {expected}"
            ),
            Self::CriticVerdictNotRevisable { actual } => write!(
                formatter,
                "critic verdict {actual:?} cannot authorize the single repair"
            ),
            Self::RequiredFindingIdsMismatch { expected, actual } => write!(
                formatter,
                "repair finding ids {actual:?} do not exactly match committed findings {expected:?}"
            ),
            Self::RootPlannerCandidate(violations) => {
                write!(
                    formatter,
                    "candidate violates root bindings: {violations:?}"
                )
            }
            Self::CriticOutput(violations) => {
                write!(
                    formatter,
                    "critique violates critic bindings: {violations:?}"
                )
            }
            Self::Serialization { target, message } => {
                write!(formatter, "could not serialize {target}: {message}")
            }
            Self::Prompt(error) => write!(formatter, "could not compile repair prompt: {error}"),
            Self::BackendContract(error) => {
                write!(formatter, "could not construct repair request: {error}")
            }
            Self::Digest(error) => write!(formatter, "could not construct digest: {error}"),
        }
    }
}

impl std::error::Error for PlanRepairCompileError {}

impl From<PromptError> for PlanRepairCompileError {
    fn from(error: PromptError) -> Self {
        Self::Prompt(error)
    }
}

impl From<ContractError> for PlanRepairCompileError {
    fn from(error: ContractError) -> Self {
        Self::BackendContract(error)
    }
}

impl From<Sha256DigestError> for PlanRepairCompileError {
    fn from(error: Sha256DigestError) -> Self {
        Self::Digest(error)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RunInputPayload<'a> {
    session_id: String,
    run_id: String,
    input: &'a [InputItem],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryIdentityPayload<'a> {
    workspace_identity: String,
    workspace_path: &'a WorkspacePath,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidatePlanPayload<'a> {
    candidate_plan_sha256: &'a str,
    candidate: &'a RootPlannerOutput,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CommittedCritiquePayload<'a> {
    critique_sha256: &'a str,
    critique: &'a PlanCriticOutput,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RepairAssignment<'a> {
    schema_version: u32,
    triggering_review_event_id: String,
    candidate_plan_sha256: &'a str,
    critique_sha256: &'a str,
    critic_policy_sha256: &'a str,
    required_finding_ids: &'a [String],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ContextManifest<'a> {
    schema_version: u32,
    sections: &'a [DataSection],
}

/// Compiles the only authorized repair as a complete replacement root plan.
///
/// The candidate and committed critique are exact, hash-bound data. Their
/// prose never selects a runtime branch. Eligibility, lineage, call count,
/// and the durable repair authorization remain supervisor/store concerns.
///
/// # Errors
///
/// Returns a typed mechanical error for stale bytes, forged bindings, a
/// non-revisable verdict, altered finding IDs, invalid limits, or downstream
/// prompt/backend contract failures.
#[allow(
    clippy::too_many_arguments,
    reason = "the compatibility entry point preserves explicit hash-bound repair authority inputs"
)]
pub fn compile_plan_repair_request(
    session: &Session,
    run: &Run,
    root_policy: &RootPlannerPolicy,
    candidate: &RootPlannerOutput,
    candidate_plan_sha256: &Sha256Digest,
    critic_policy: &PlanCriticPolicy,
    critique: &PlanCriticOutput,
    critique_sha256: &Sha256Digest,
    triggering_review_event_id: EventId,
    required_finding_ids: &[String],
    resolved_repair_model_id: ModelId,
    max_output_tokens: u32,
    reasoning: Option<ReasoningSetting>,
) -> Result<CompiledPlanRepairRequest, PlanRepairCompileError> {
    validate_inputs(session, run, &resolved_repair_model_id, max_output_tokens)?;

    let root_sections = build_root_sections(session, run)?;
    let root_invocation = invocation_with_policy(&root_sections, "planner_policy", root_policy)?;
    let candidate_value = to_json_value(candidate, "root plan candidate")?;
    validate_root_planner_output(&candidate_value, &root_invocation)
        .map_err(PlanRepairCompileError::RootPlannerCandidate)?;
    validate_exact_bytes(
        candidate,
        candidate_plan_sha256,
        "root plan candidate artifact",
        |expected, actual| PlanRepairCompileError::CandidatePlanDigestMismatch { expected, actual },
    )?;

    validate_critic_policy_binding(root_policy, candidate_plan_sha256, critic_policy)?;
    let critic_sections = build_critic_sections(session, run, candidate, candidate_plan_sha256)?;
    let critic_invocation =
        invocation_with_policy(&critic_sections, "critic_policy", critic_policy)?;
    let critique_value = to_json_value(critique, "committed critique")?;
    validate_plan_critic_output(&critique_value, &critic_invocation)
        .map_err(PlanRepairCompileError::CriticOutput)?;
    validate_exact_bytes(
        critique,
        critique_sha256,
        "committed critique artifact",
        |expected, actual| PlanRepairCompileError::CritiqueDigestMismatch { expected, actual },
    )?;
    if critique.verdict != PlanCriticVerdict::Revise {
        return Err(PlanRepairCompileError::CriticVerdictNotRevisable {
            actual: critique.verdict,
        });
    }
    let expected_finding_ids = critique
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    if expected_finding_ids != required_finding_ids {
        return Err(PlanRepairCompileError::RequiredFindingIdsMismatch {
            expected: expected_finding_ids,
            actual: required_finding_ids.to_vec(),
        });
    }

    let assignment = RepairAssignment {
        schema_version: 1,
        triggering_review_event_id: triggering_review_event_id.to_string(),
        candidate_plan_sha256: candidate_plan_sha256.as_str(),
        critique_sha256: critique_sha256.as_str(),
        critic_policy_sha256: &critic_policy.critic_policy_sha256,
        required_finding_ids,
    };
    let repair_assignment_sha256 = canonical_sha256(&assignment, "repair assignment")?;
    let sections = build_repair_sections(
        session,
        run,
        candidate,
        candidate_plan_sha256,
        critique,
        critique_sha256,
        triggering_review_event_id,
        &assignment,
    )?;
    let repair_context_manifest_sha256 = canonical_sha256(
        &ContextManifest {
            schema_version: 1,
            sections: &sections,
        },
        "repair context manifest",
    )?;
    let prompt_invocation = invocation_with_policy(&sections, "planner_policy", root_policy)?;
    let registry = builtin_registry()?;
    let compiled_prompt = registry.compile(&plan_repair_key(), &prompt_invocation)?;
    let prompt_manifest_sha256 =
        Sha256Digest::parse(compiled_prompt.manifest.content_sha256.clone())?;
    let inference_request = build_inference_request(
        &compiled_prompt,
        resolved_repair_model_id,
        max_output_tokens,
        reasoning,
    )?;
    let request_sha256 = canonical_sha256(&inference_request, "repair inference request")?;

    Ok(CompiledPlanRepairRequest {
        prompt_invocation,
        compiled_prompt,
        inference_request,
        candidate_plan_sha256: candidate_plan_sha256.clone(),
        critique_sha256: critique_sha256.clone(),
        repair_assignment_sha256,
        repair_context_manifest_sha256,
        prompt_manifest_sha256,
        request_sha256,
        triggering_review_event_id,
        required_finding_ids: required_finding_ids.to_vec(),
    })
}

fn validate_critic_policy_binding(
    root_policy: &RootPlannerPolicy,
    candidate_plan_sha256: &Sha256Digest,
    critic_policy: &PlanCriticPolicy,
) -> Result<(), PlanRepairCompileError> {
    if critic_policy.root_snapshot_sha256 != root_policy.root_snapshot_sha256
        || critic_policy.planner_policy_sha256 != root_policy.planner_policy_sha256
        || critic_policy.context_manifest_sha256 != root_policy.context_manifest_sha256
        || critic_policy.obligations != root_policy.obligations
    {
        return Err(PlanRepairCompileError::CriticRootPolicyMismatch);
    }
    if critic_policy.candidate_plan_sha256 != candidate_plan_sha256.as_str() {
        return Err(PlanRepairCompileError::CriticCandidateMismatch {
            expected: candidate_plan_sha256.as_str().to_owned(),
            actual: critic_policy.candidate_plan_sha256.clone(),
        });
    }
    Ok(())
}

fn validate_inputs(
    session: &Session,
    run: &Run,
    repair_model: &ModelId,
    max_output_tokens: u32,
) -> Result<(), PlanRepairCompileError> {
    if run.spec.purpose != RunPurpose::PlanOnly {
        return Err(PlanRepairCompileError::UnsupportedPurpose {
            actual: run.spec.purpose,
        });
    }
    if run.spec.backend.kind != BackendKind::Model {
        return Err(PlanRepairCompileError::UnsupportedBackendKind {
            actual: run.spec.backend.kind,
        });
    }
    if run.spec.session_id != session.id {
        return Err(PlanRepairCompileError::SessionMismatch {
            session_id: session.id.to_string(),
            run_session_id: run.spec.session_id.to_string(),
        });
    }
    if run.spec.input.is_empty() {
        return Err(PlanRepairCompileError::EmptyInput);
    }
    for (index, item) in run.spec.input.iter().enumerate() {
        match item {
            InputItem::Text { text } if text.trim().is_empty() => {
                return Err(PlanRepairCompileError::BlankTextInput { index });
            }
            InputItem::Text { .. } => {}
            InputItem::Artifact { .. } => {
                return Err(PlanRepairCompileError::UnsupportedArtifactInput { index });
            }
        }
    }
    if run.spec.backend.backend_id.trim().is_empty() {
        return Err(PlanRepairCompileError::BlankBackendId);
    }
    let selected_model = run
        .spec
        .backend
        .model
        .as_deref()
        .ok_or(PlanRepairCompileError::MissingSelectedModel)?;
    if selected_model.trim().is_empty() {
        return Err(PlanRepairCompileError::BlankSelectedModel);
    }
    if repair_model.as_str().trim().is_empty() {
        return Err(PlanRepairCompileError::BlankRepairModel);
    }
    if selected_model.as_bytes() != repair_model.as_str().as_bytes() {
        return Err(PlanRepairCompileError::RepairModelSelectionMismatch {
            selected: selected_model.to_owned(),
            resolved: repair_model.as_str().to_owned(),
        });
    }
    if run.spec.limits.max_subagents != 0 {
        return Err(PlanRepairCompileError::SubagentsNotAuthorized {
            requested: run.spec.limits.max_subagents,
        });
    }
    if max_output_tokens == 0 {
        return Err(PlanRepairCompileError::ZeroMaxOutputTokens);
    }
    if max_output_tokens > MAX_PLAN_REPAIR_OUTPUT_TOKENS {
        return Err(
            PlanRepairCompileError::MaxOutputTokensExceedCompilerCeiling {
                requested: max_output_tokens,
                maximum: MAX_PLAN_REPAIR_OUTPUT_TOKENS,
            },
        );
    }
    if let Some(maximum) = run.spec.limits.max_output_tokens
        && u64::from(max_output_tokens) > maximum
    {
        return Err(PlanRepairCompileError::MaxOutputTokensExceedRunLimit {
            requested: max_output_tokens,
            maximum,
        });
    }
    Ok(())
}

fn invocation_with_policy<T: Serialize>(
    sections: &[DataSection],
    name: &str,
    policy: &T,
) -> Result<PromptInvocation, PlanRepairCompileError> {
    Ok(PromptInvocation::with_runtime_constraints(
        sections.to_vec(),
        PromptLimits::new(0),
        vec![RuntimeConstraint {
            name: name.to_owned(),
            payload: to_json_value(policy, "repair runtime policy")?,
        }],
    ))
}

fn build_root_sections(
    session: &Session,
    run: &Run,
) -> Result<Vec<DataSection>, PlanRepairCompileError> {
    Ok(vec![
        run_input_section(session, run)?,
        repository_identity_section(session)?,
    ])
}

fn build_critic_sections(
    session: &Session,
    run: &Run,
    candidate: &RootPlannerOutput,
    candidate_plan_sha256: &Sha256Digest,
) -> Result<Vec<DataSection>, PlanRepairCompileError> {
    let mut sections = build_root_sections(session, run)?;
    sections.push(candidate_section(run, candidate, candidate_plan_sha256)?);
    Ok(sections)
}

#[allow(clippy::too_many_arguments)]
fn build_repair_sections(
    session: &Session,
    run: &Run,
    candidate: &RootPlannerOutput,
    candidate_plan_sha256: &Sha256Digest,
    critique: &PlanCriticOutput,
    critique_sha256: &Sha256Digest,
    triggering_review_event_id: EventId,
    assignment: &RepairAssignment<'_>,
) -> Result<Vec<DataSection>, PlanRepairCompileError> {
    let mut sections = build_critic_sections(session, run, candidate, candidate_plan_sha256)?;
    sections.push(DataSection {
        name: "committed_critique".to_owned(),
        trust: TrustLevel::Tool,
        provenance: DataProvenance {
            source_kind: SourceKind::Tool,
            source_id: format!("event:{triggering_review_event_id}:critique"),
            artifact_sha256: Some(critique_sha256.as_str().to_owned()),
            event_id: Some(triggering_review_event_id.to_string()),
        },
        payload: to_json_value(
            &CommittedCritiquePayload {
                critique_sha256: critique_sha256.as_str(),
                critique,
            },
            "committed critique section",
        )?,
    });
    sections.push(DataSection {
        name: "repair_assignment".to_owned(),
        trust: TrustLevel::Tool,
        provenance: DataProvenance {
            source_kind: SourceKind::Tool,
            source_id: format!("event:{triggering_review_event_id}:repair-assignment"),
            artifact_sha256: None,
            event_id: Some(triggering_review_event_id.to_string()),
        },
        payload: to_json_value(assignment, "repair assignment section")?,
    });
    Ok(sections)
}

fn run_input_section(session: &Session, run: &Run) -> Result<DataSection, PlanRepairCompileError> {
    Ok(DataSection {
        name: "run_input".to_owned(),
        trust: TrustLevel::User,
        provenance: DataProvenance {
            source_kind: SourceKind::User,
            source_id: format!("run:{}:input", run.id),
            artifact_sha256: None,
            event_id: None,
        },
        payload: to_json_value(
            &RunInputPayload {
                session_id: session.id.to_string(),
                run_id: run.id.to_string(),
                input: &run.spec.input,
            },
            "repair run input section",
        )?,
    })
}

fn repository_identity_section(session: &Session) -> Result<DataSection, PlanRepairCompileError> {
    Ok(DataSection {
        name: "repository_identity".to_owned(),
        trust: TrustLevel::Repository,
        provenance: DataProvenance {
            source_kind: SourceKind::Repository,
            source_id: format!("session:{}:workspace", session.id),
            artifact_sha256: None,
            event_id: None,
        },
        payload: to_json_value(
            &RepositoryIdentityPayload {
                workspace_identity: session.id.to_string(),
                workspace_path: &session.workspace_root,
            },
            "repair repository identity section",
        )?,
    })
}

fn candidate_section(
    run: &Run,
    candidate: &RootPlannerOutput,
    candidate_plan_sha256: &Sha256Digest,
) -> Result<DataSection, PlanRepairCompileError> {
    Ok(DataSection {
        name: "candidate_plan".to_owned(),
        trust: TrustLevel::Tool,
        provenance: DataProvenance {
            source_kind: SourceKind::Tool,
            source_id: format!("run:{}:plan-candidate", run.id),
            artifact_sha256: Some(candidate_plan_sha256.as_str().to_owned()),
            event_id: None,
        },
        payload: to_json_value(
            &CandidatePlanPayload {
                candidate_plan_sha256: candidate_plan_sha256.as_str(),
                candidate,
            },
            "repair candidate section",
        )?,
    })
}

fn build_inference_request(
    compiled_prompt: &CompiledPrompt,
    model_id: ModelId,
    max_output_tokens: u32,
    reasoning: Option<ReasoningSetting>,
) -> Result<StructuredInferenceRequest, PlanRepairCompileError> {
    let messages = compiled_prompt
        .messages
        .iter()
        .map(compile_backend_message)
        .collect::<Result<Vec<_>, _>>()?;
    let output = StructuredOutputSpec::new_with_generation_schema(
        REPAIR_OUTPUT_SCHEMA_NAME,
        compiled_prompt.output_schema.clone(),
        compiled_prompt.generation_schema.clone(),
    )?;
    let mut request =
        StructuredInferenceRequest::new(model_id, messages, output, max_output_tokens)?;
    if let Some(reasoning) = reasoning {
        request = request.with_reasoning(reasoning);
    }
    Ok(request)
}

fn compile_backend_message(
    message: &CompiledMessage,
) -> Result<BackendMessage, PlanRepairCompileError> {
    let role = match message.role {
        PromptMessageRole::System => BackendMessageRole::System,
        PromptMessageRole::User => BackendMessageRole::User,
    };
    let content =
        match &message.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Json(value) => value.to_compact_string().map_err(|error| {
                PlanRepairCompileError::Serialization {
                    target: "compiled repair message",
                    message: error.to_string(),
                }
            })?,
        };
    Ok(BackendMessage::new(role, content))
}

fn validate_exact_bytes<T: Serialize>(
    value: &T,
    actual: &Sha256Digest,
    target: &'static str,
    mismatch: impl FnOnce(String, String) -> PlanRepairCompileError,
) -> Result<(), PlanRepairCompileError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| PlanRepairCompileError::Serialization {
            target,
            message: error.to_string(),
        })?;
    let expected = bytes_sha256(&bytes)?;
    if &expected != actual {
        return Err(mismatch(
            expected.as_str().to_owned(),
            actual.as_str().to_owned(),
        ));
    }
    Ok(())
}

fn to_json_value<T: Serialize>(
    value: &T,
    target: &'static str,
) -> Result<Value, PlanRepairCompileError> {
    serde_json::to_value(value).map_err(|error| PlanRepairCompileError::Serialization {
        target,
        message: error.to_string(),
    })
}

fn canonical_sha256<T: Serialize>(
    value: &T,
    target: &'static str,
) -> Result<Sha256Digest, PlanRepairCompileError> {
    let value = to_json_value(value, target)?;
    let mut encoded = String::new();
    encode_canonical_value(&value, &mut encoded)
        .map_err(|message| PlanRepairCompileError::Serialization { target, message })?;
    bytes_sha256(encoded.as_bytes())
}

fn bytes_sha256(bytes: &[u8]) -> Result<Sha256Digest, PlanRepairCompileError> {
    let digest = Sha256::digest(bytes);
    let mut hexadecimal = String::with_capacity(Sha256Digest::HEX_LENGTH);
    for byte in digest {
        hexadecimal.push(char::from(HEX[usize::from(byte >> 4)]));
        hexadecimal.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(Sha256Digest::parse(hexadecimal)?)
}

fn encode_canonical_value(value: &Value, output: &mut String) -> Result<(), String> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(|error| error.to_string())?);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                encode_canonical_value(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(|error| error.to_string())?);
                output.push(':');
                encode_canonical_value(&values[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}
