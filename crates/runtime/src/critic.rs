use birdcode_backends::{
    ContractError, Message as BackendMessage, MessageRole as BackendMessageRole, ModelId,
    ReasoningSetting, StructuredInferenceRequest, StructuredOutputSpec,
};
use birdcode_prompting::{
    CompiledMessage, CompiledPrompt, DataProvenance, DataSection, MessageContent,
    MessageRole as PromptMessageRole, PlanCriticPolicy, PlanCriticPolicyViolation, PromptError,
    PromptInvocation, PromptLimits, RootPlannerInvariantViolation, RootPlannerOutput,
    RootPlannerPolicy, RuntimeConstraint, SourceKind, TrustLevel, builtin_registry,
    derive_plan_critic_policy_v1, plan_critic_key, validate_root_planner_output,
};
pub use birdcode_protocol::ROOT_PLANNING_POLICY_V1_INITIAL_REVIEW_MAX_OUTPUT_TOKENS as MAX_PLAN_CRITIC_OUTPUT_TOKENS;
use birdcode_protocol::{
    InputItem, Run, RunPurpose, Session, Sha256Digest, Sha256DigestError, WorkspacePath,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

const CRITIC_OUTPUT_SCHEMA_NAME: &str = "birdcode_plan_semantic_critic_v1";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Fully bound request material for one read-only semantic review.
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledPlanCriticRequest {
    pub critic_policy: PlanCriticPolicy,
    pub prompt_invocation: PromptInvocation,
    pub compiled_prompt: CompiledPrompt,
    pub inference_request: StructuredInferenceRequest,
    pub candidate_plan_sha256: Sha256Digest,
    pub critic_context_manifest_sha256: Sha256Digest,
    pub critic_policy_sha256: Sha256Digest,
    pub prompt_manifest_sha256: Sha256Digest,
    pub request_sha256: Sha256Digest,
}

#[derive(Debug)]
pub enum PlanCriticCompileError {
    UnsupportedPurpose {
        actual: RunPurpose,
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
    BlankReviewerModel,
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
    RootPlannerCandidate(Vec<RootPlannerInvariantViolation>),
    CriticPolicy(Vec<PlanCriticPolicyViolation>),
    Serialization {
        target: &'static str,
        message: String,
    },
    Prompt(PromptError),
    BackendContract(ContractError),
    Digest(Sha256DigestError),
}

impl fmt::Display for PlanCriticCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPurpose { actual } => {
                write!(
                    formatter,
                    "run purpose {actual:?} is not supported by the plan critic"
                )
            }
            Self::SessionMismatch {
                session_id,
                run_session_id,
            } => write!(
                formatter,
                "session {session_id} does not own run session {run_session_id}"
            ),
            Self::EmptyInput => formatter.write_str("a semantic critic requires root input"),
            Self::BlankTextInput { index } => {
                write!(formatter, "text input at index {index} must not be blank")
            }
            Self::UnsupportedArtifactInput { index } => write!(
                formatter,
                "artifact input at index {index} cannot be bound without reading its content"
            ),
            Self::BlankReviewerModel => {
                formatter.write_str("the resolved reviewer model must not be blank")
            }
            Self::ZeroMaxOutputTokens => {
                formatter.write_str("critic max_output_tokens must be greater than zero")
            }
            Self::MaxOutputTokensExceedCompilerCeiling { requested, maximum } => write!(
                formatter,
                "critic max_output_tokens {requested} exceeds compiler ceiling {maximum}"
            ),
            Self::MaxOutputTokensExceedRunLimit { requested, maximum } => write!(
                formatter,
                "critic max_output_tokens {requested} exceeds run limit {maximum}"
            ),
            Self::CandidatePlanDigestMismatch { expected, actual } => write!(
                formatter,
                "candidate plan artifact digest {actual} does not match exact candidate bytes {expected}"
            ),
            Self::RootPlannerCandidate(violations) => {
                write!(
                    formatter,
                    "candidate plan violates root bindings: {violations:?}"
                )
            }
            Self::CriticPolicy(violations) => {
                write!(formatter, "critic policy is invalid: {violations:?}")
            }
            Self::Serialization { target, message } => {
                write!(formatter, "could not serialize {target}: {message}")
            }
            Self::Prompt(error) => write!(formatter, "could not compile critic prompt: {error}"),
            Self::BackendContract(error) => {
                write!(
                    formatter,
                    "could not construct critic inference request: {error}"
                )
            }
            Self::Digest(error) => write!(formatter, "could not construct digest: {error}"),
        }
    }
}

impl std::error::Error for PlanCriticCompileError {}

impl From<PromptError> for PlanCriticCompileError {
    fn from(error: PromptError) -> Self {
        Self::Prompt(error)
    }
}

impl From<ContractError> for PlanCriticCompileError {
    fn from(error: ContractError) -> Self {
        Self::BackendContract(error)
    }
}

impl From<Sha256DigestError> for PlanCriticCompileError {
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
struct ContextManifest<'a> {
    schema_version: u32,
    sections: &'a [DataSection],
}

/// Compiles a model-identity-blinded, read-only semantic assessment of one
/// exact root plan.
///
/// Reviewer lineage eligibility is deliberately not inferred here. The daemon
/// must select a reviewer allowed by its trusted policy before calling this
/// pure compiler. The current LM Studio adapter reports an exact model ID; it
/// does not attest the operator-declared deployment or independence domain.
/// Candidate text never influences the runtime branch or model.
///
/// # Errors
///
/// Returns a typed mechanical error for malformed authority, stale candidate
/// bindings, digest mismatch, invalid limits, or prompt/backend contracts.
#[allow(
    clippy::too_many_arguments,
    reason = "this stable public compiler API keeps independently typed authority and evidence bindings explicit"
)]
pub fn compile_plan_critic_request(
    session: &Session,
    run: &Run,
    root_policy: &RootPlannerPolicy,
    candidate: &RootPlannerOutput,
    candidate_plan_sha256: &Sha256Digest,
    resolved_reviewer_model_id: ModelId,
    max_output_tokens: u32,
    reasoning: Option<ReasoningSetting>,
) -> Result<CompiledPlanCriticRequest, PlanCriticCompileError> {
    validate_inputs(session, run, &resolved_reviewer_model_id, max_output_tokens)?;
    let root_sections = build_root_sections(session, run)?;
    let root_invocation = PromptInvocation::with_runtime_constraints(
        root_sections,
        PromptLimits::new(0),
        vec![RuntimeConstraint {
            name: "planner_policy".to_owned(),
            payload: to_json_value(root_policy, "root planner policy")?,
        }],
    );
    let candidate_value = to_json_value(candidate, "root plan candidate")?;
    validate_root_planner_output(&candidate_value, &root_invocation)
        .map_err(PlanCriticCompileError::RootPlannerCandidate)?;

    let candidate_bytes =
        serde_json::to_vec(candidate).map_err(|error| PlanCriticCompileError::Serialization {
            target: "root plan candidate artifact",
            message: error.to_string(),
        })?;
    let expected_candidate_sha256 = bytes_sha256(&candidate_bytes)?;
    if &expected_candidate_sha256 != candidate_plan_sha256 {
        return Err(PlanCriticCompileError::CandidatePlanDigestMismatch {
            expected: expected_candidate_sha256.as_str().to_owned(),
            actual: candidate_plan_sha256.as_str().to_owned(),
        });
    }

    let critic_policy =
        derive_plan_critic_policy_v1(root_policy, candidate, candidate_plan_sha256.as_str())
            .map_err(PlanCriticCompileError::CriticPolicy)?;
    let sections = build_critic_sections(session, run, candidate, candidate_plan_sha256)?;
    let critic_context_manifest_sha256 = canonical_sha256(
        &ContextManifest {
            schema_version: 1,
            sections: &sections,
        },
        "critic context manifest",
    )?;
    let prompt_invocation = PromptInvocation::with_runtime_constraints(
        sections,
        PromptLimits::new(0),
        vec![RuntimeConstraint {
            name: "critic_policy".to_owned(),
            payload: to_json_value(&critic_policy, "critic policy")?,
        }],
    );
    let registry = builtin_registry()?;
    let compiled_prompt = registry.compile(&plan_critic_key(), &prompt_invocation)?;
    let prompt_manifest_sha256 =
        Sha256Digest::parse(compiled_prompt.manifest.content_sha256.clone())?;
    let inference_request = build_inference_request(
        &compiled_prompt,
        resolved_reviewer_model_id,
        max_output_tokens,
        reasoning,
    )?;
    let request_sha256 = canonical_sha256(&inference_request, "critic inference request")?;
    let critic_policy_sha256 = Sha256Digest::parse(critic_policy.critic_policy_sha256.clone())?;

    Ok(CompiledPlanCriticRequest {
        critic_policy,
        prompt_invocation,
        compiled_prompt,
        inference_request,
        candidate_plan_sha256: candidate_plan_sha256.clone(),
        critic_context_manifest_sha256,
        critic_policy_sha256,
        prompt_manifest_sha256,
        request_sha256,
    })
}

fn validate_inputs(
    session: &Session,
    run: &Run,
    reviewer_model: &ModelId,
    max_output_tokens: u32,
) -> Result<(), PlanCriticCompileError> {
    if run.spec.purpose != RunPurpose::PlanOnly {
        return Err(PlanCriticCompileError::UnsupportedPurpose {
            actual: run.spec.purpose,
        });
    }
    if run.spec.session_id != session.id {
        return Err(PlanCriticCompileError::SessionMismatch {
            session_id: session.id.to_string(),
            run_session_id: run.spec.session_id.to_string(),
        });
    }
    if run.spec.input.is_empty() {
        return Err(PlanCriticCompileError::EmptyInput);
    }
    for (index, item) in run.spec.input.iter().enumerate() {
        match item {
            InputItem::Text { text } if text.trim().is_empty() => {
                return Err(PlanCriticCompileError::BlankTextInput { index });
            }
            InputItem::Text { .. } => {}
            InputItem::Artifact { .. } => {
                return Err(PlanCriticCompileError::UnsupportedArtifactInput { index });
            }
        }
    }
    if reviewer_model.as_str().trim().is_empty() {
        return Err(PlanCriticCompileError::BlankReviewerModel);
    }
    if max_output_tokens == 0 {
        return Err(PlanCriticCompileError::ZeroMaxOutputTokens);
    }
    if max_output_tokens > MAX_PLAN_CRITIC_OUTPUT_TOKENS {
        return Err(
            PlanCriticCompileError::MaxOutputTokensExceedCompilerCeiling {
                requested: max_output_tokens,
                maximum: MAX_PLAN_CRITIC_OUTPUT_TOKENS,
            },
        );
    }
    if let Some(maximum) = run.spec.limits.max_output_tokens
        && u64::from(max_output_tokens) > maximum
    {
        return Err(PlanCriticCompileError::MaxOutputTokensExceedRunLimit {
            requested: max_output_tokens,
            maximum,
        });
    }
    Ok(())
}

fn build_root_sections(
    session: &Session,
    run: &Run,
) -> Result<Vec<DataSection>, PlanCriticCompileError> {
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
) -> Result<Vec<DataSection>, PlanCriticCompileError> {
    Ok(vec![
        run_input_section(session, run)?,
        repository_identity_section(session)?,
        DataSection {
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
                "candidate plan section",
            )?,
        },
    ])
}

fn run_input_section(session: &Session, run: &Run) -> Result<DataSection, PlanCriticCompileError> {
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
            "critic run input section",
        )?,
    })
}

fn repository_identity_section(session: &Session) -> Result<DataSection, PlanCriticCompileError> {
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
            "critic repository identity section",
        )?,
    })
}

fn build_inference_request(
    compiled_prompt: &CompiledPrompt,
    model_id: ModelId,
    max_output_tokens: u32,
    reasoning: Option<ReasoningSetting>,
) -> Result<StructuredInferenceRequest, PlanCriticCompileError> {
    let messages = compiled_prompt
        .messages
        .iter()
        .map(compile_backend_message)
        .collect::<Result<Vec<_>, _>>()?;
    let output = StructuredOutputSpec::new_with_generation_schema(
        CRITIC_OUTPUT_SCHEMA_NAME,
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
) -> Result<BackendMessage, PlanCriticCompileError> {
    let role = match message.role {
        PromptMessageRole::System => BackendMessageRole::System,
        PromptMessageRole::User => BackendMessageRole::User,
    };
    let content =
        match &message.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Json(value) => value.to_compact_string().map_err(|error| {
                PlanCriticCompileError::Serialization {
                    target: "compiled critic message",
                    message: error.to_string(),
                }
            })?,
        };
    Ok(BackendMessage::new(role, content))
}

fn to_json_value<T: Serialize>(
    value: &T,
    target: &'static str,
) -> Result<Value, PlanCriticCompileError> {
    serde_json::to_value(value).map_err(|error| PlanCriticCompileError::Serialization {
        target,
        message: error.to_string(),
    })
}

fn canonical_sha256<T: Serialize>(
    value: &T,
    target: &'static str,
) -> Result<Sha256Digest, PlanCriticCompileError> {
    let value = to_json_value(value, target)?;
    let mut encoded = String::new();
    encode_canonical_value(&value, &mut encoded)
        .map_err(|message| PlanCriticCompileError::Serialization { target, message })?;
    bytes_sha256(encoded.as_bytes())
}

fn bytes_sha256(bytes: &[u8]) -> Result<Sha256Digest, PlanCriticCompileError> {
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
