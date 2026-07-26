//! Adapter between the stable planner/replanner prompt DTO and durable plan domain.

use crate::planner::{
    PlanSnapshot, PlannerContextCatalog, PlannerContractError, PlannerDigest, PlannerPolicy,
    PlannerTurnBindings, PlannerTurnProposal, PlannerValidationError, ProtectedObligationCatalog,
    ValidatedPlannerTurn,
};
use birdcode_backends::{
    BackendId, BackendInstanceIdentity, BackendInstanceIdentityError, ContractError, Message,
    MessageRole as BackendMessageRole, ModelId, ReasoningSetting, StructuredInferenceRequest,
    StructuredOutputSpec,
};
use birdcode_prompting::{
    CompiledMessage, CompiledPrompt, MessageContent, MessageRole,
    PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS, PlannerEvidencePacket, PlannerReplannerBindings,
    PlannerReplannerInvariantViolation, PlannerReplannerInvocationMaterial, PromptError,
    PromptInvocation, builtin_registry, planner_replanner_invocation, planner_replanner_key,
    validate_planner_replanner_invocation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const OUTPUT_SCHEMA_NAME: &str = "planner_replanner_turn";
const INFERENCE_POLICY_SCHEMA_VERSION: u32 = 2;

#[derive(Serialize)]
struct PlannerReplannerInferencePolicyHashMaterial<'a> {
    schema_version: u32,
    backend_instance: &'a BackendInstanceIdentity,
    model_id: &'a ModelId,
    reasoning: Option<ReasoningSetting>,
    max_output_tokens: u32,
}

/// Trusted runtime configuration for one planner inference class.
///
/// This policy is constructed independently of any prepared prompt candidate.
/// Backend identity and every model-controlled request option are exact; an
/// executor or replay caller must supply the expected policy out of band.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerReplannerInferencePolicy {
    backend_instance: BackendInstanceIdentity,
    model_id: ModelId,
    reasoning: Option<ReasoningSetting>,
    max_output_tokens: u32,
    policy_sha256: PlannerDigest,
}

impl PlannerReplannerInferencePolicy {
    /// Creates and content-addresses an exact trusted inference policy.
    ///
    /// # Errors
    ///
    /// Rejects a zero or product-contract-exceeding token ceiling, or an
    /// encoding failure.
    pub fn new(
        backend_instance: BackendInstanceIdentity,
        model_id: ModelId,
        reasoning: Option<ReasoningSetting>,
        max_output_tokens: u32,
    ) -> Result<Self, PlannerReplannerInferencePolicyError> {
        if max_output_tokens == 0 {
            return Err(PlannerReplannerInferencePolicyError::ZeroOutputTokens);
        }
        if max_output_tokens > PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS {
            return Err(PlannerReplannerInferencePolicyError::OutputTokensTooLarge {
                requested: max_output_tokens,
                maximum: PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS,
            });
        }
        backend_instance.validate_integrity()?;
        let policy_sha256 =
            inference_policy_digest(&backend_instance, &model_id, reasoning, max_output_tokens)?;
        Ok(Self {
            backend_instance,
            model_id,
            reasoning,
            max_output_tokens,
            policy_sha256,
        })
    }

    #[must_use]
    pub const fn backend_id(&self) -> &BackendId {
        self.backend_instance.backend_id()
    }

    #[must_use]
    pub const fn backend_instance(&self) -> &BackendInstanceIdentity {
        &self.backend_instance
    }

    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        &self.model_id
    }

    #[must_use]
    pub const fn reasoning(&self) -> Option<ReasoningSetting> {
        self.reasoning
    }

    #[must_use]
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    #[must_use]
    pub const fn policy_sha256(&self) -> &PlannerDigest {
        &self.policy_sha256
    }

    /// Re-derives the content address for defense in depth at runtime edges.
    ///
    /// # Errors
    ///
    /// Rejects any mechanically invalid or hash-substituted policy.
    pub fn validate_integrity(&self) -> Result<(), PlannerReplannerInferencePolicyError> {
        if self.max_output_tokens == 0 {
            return Err(PlannerReplannerInferencePolicyError::ZeroOutputTokens);
        }
        if self.max_output_tokens > PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS {
            return Err(PlannerReplannerInferencePolicyError::OutputTokensTooLarge {
                requested: self.max_output_tokens,
                maximum: PLANNER_REPLANNER_V2_MAX_OUTPUT_TOKENS,
            });
        }
        self.backend_instance.validate_integrity()?;
        let expected = inference_policy_digest(
            &self.backend_instance,
            &self.model_id,
            self.reasoning,
            self.max_output_tokens,
        )?;
        if expected == self.policy_sha256 {
            Ok(())
        } else {
            Err(PlannerReplannerInferencePolicyError::DigestMismatch)
        }
    }
}

impl<'de> Deserialize<'de> for PlannerReplannerInferencePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Repr {
            backend_instance: BackendInstanceIdentity,
            model_id: ModelId,
            reasoning: Option<ReasoningSetting>,
            max_output_tokens: u32,
            policy_sha256: PlannerDigest,
        }

        let repr = Repr::deserialize(deserializer)?;
        let policy = Self::new(
            repr.backend_instance,
            repr.model_id,
            repr.reasoning,
            repr.max_output_tokens,
        )
        .map_err(serde::de::Error::custom)?;
        if policy.policy_sha256 != repr.policy_sha256 {
            return Err(serde::de::Error::custom(
                PlannerReplannerInferencePolicyError::DigestMismatch,
            ));
        }
        Ok(policy)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PlannerReplannerInferencePolicyError {
    #[error(transparent)]
    BackendInstance(#[from] BackendInstanceIdentityError),
    #[error("planner/replanner inference token ceiling must be positive")]
    ZeroOutputTokens,
    #[error(
        "planner/replanner inference token ceiling {requested} exceeds product maximum {maximum}"
    )]
    OutputTokensTooLarge { requested: u32, maximum: u32 },
    #[error("planner/replanner inference policy digest does not bind its exact content")]
    DigestMismatch,
    #[error("planner/replanner inference policy could not be encoded: {0}")]
    Encoding(String),
}

fn inference_policy_digest(
    backend_instance: &BackendInstanceIdentity,
    model_id: &ModelId,
    reasoning: Option<ReasoningSetting>,
    max_output_tokens: u32,
) -> Result<PlannerDigest, PlannerReplannerInferencePolicyError> {
    let encoded = serde_json::to_vec(&PlannerReplannerInferencePolicyHashMaterial {
        schema_version: INFERENCE_POLICY_SCHEMA_VERSION,
        backend_instance,
        model_id,
        reasoning,
        max_output_tokens,
    })
    .map_err(|error| PlannerReplannerInferencePolicyError::Encoding(error.to_string()))?;
    Ok(PlannerDigest::of_bytes(&encoded))
}

/// Exact provider-neutral artifacts prepared for one planner/replanner call.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPlannerReplannerRequest {
    inference_policy_sha256: PlannerDigest,
    invocation: PromptInvocation,
    compiled_prompt: CompiledPrompt,
    evidence_packet: PlannerEvidencePacket,
    inference: StructuredInferenceRequest,
}

impl PreparedPlannerReplannerRequest {
    #[must_use]
    pub const fn inference_policy_sha256(&self) -> &PlannerDigest {
        &self.inference_policy_sha256
    }

    #[must_use]
    pub const fn invocation(&self) -> &PromptInvocation {
        &self.invocation
    }

    #[must_use]
    pub const fn compiled_prompt(&self) -> &CompiledPrompt {
        &self.compiled_prompt
    }

    #[must_use]
    pub const fn evidence_packet(&self) -> &PlannerEvidencePacket {
        &self.evidence_packet
    }

    #[must_use]
    pub const fn inference(&self) -> &StructuredInferenceRequest {
        &self.inference
    }

    /// Rebuilds the bundled prompt and backend request from authoritative
    /// inputs, then requires byte-equivalent typed state.
    ///
    /// # Errors
    ///
    /// Rejects any substituted prompt, invocation, evidence packet, schema,
    /// message, model, reasoning value, or token ceiling.
    pub fn validate_against(
        &self,
        base_plan: &PlanSnapshot,
        obligations: &ProtectedObligationCatalog,
        context: &PlannerContextCatalog,
        policy: &PlannerPolicy,
        inference_policy: &PlannerReplannerInferencePolicy,
    ) -> Result<(), PlannerReplannerSetupError> {
        inference_policy.validate_integrity()?;
        let expected = PlannerReplannerRequestBuilder::new(inference_policy.clone()).build(
            base_plan,
            obligations,
            context,
            policy,
            &self.evidence_packet,
        )?;
        if self == &expected {
            Ok(())
        } else {
            Err(PlannerReplannerSetupError::AttestationMismatch)
        }
    }
}

/// Builds one immutable planner/replanner inference request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerReplannerRequestBuilder {
    inference_policy: PlannerReplannerInferencePolicy,
}

impl PlannerReplannerRequestBuilder {
    #[must_use]
    pub const fn new(inference_policy: PlannerReplannerInferencePolicy) -> Self {
        Self { inference_policy }
    }

    /// Serializes the exact authoritative domain inputs and compiles the
    /// bundled immutable prompt before constructing the backend request.
    ///
    /// # Errors
    ///
    /// Fails for invalid domain bindings, serialization, prompt compilation,
    /// or backend request constraints. It performs no inference.
    pub fn build(
        &self,
        base_plan: &PlanSnapshot,
        obligations: &ProtectedObligationCatalog,
        context: &PlannerContextCatalog,
        policy: &PlannerPolicy,
        evidence_packet: &PlannerEvidencePacket,
    ) -> Result<PreparedPlannerReplannerRequest, PlannerReplannerSetupError> {
        self.inference_policy.validate_integrity()?;
        let bindings = PlannerTurnBindings::new(base_plan, obligations, context, policy)?;
        let prompt_bindings = prompt_bindings(&bindings);
        let invocation = planner_replanner_invocation(PlannerReplannerInvocationMaterial {
            base_plan: serde_json::to_value(base_plan)?,
            protected_obligation_catalog: serde_json::to_value(obligations)?,
            planner_context_catalog: serde_json::to_value(context)?,
            evidence_packet: evidence_packet.clone(),
            planner_policy: serde_json::to_value(policy)?,
            bindings: prompt_bindings,
        });
        validate_planner_replanner_invocation(&invocation)
            .map_err(|violations| PlannerReplannerSetupError::Invocation { violations })?;
        let registry = builtin_registry()?;
        let compiled_prompt = registry.compile(&planner_replanner_key(), &invocation)?;
        let messages = compiled_prompt
            .messages
            .iter()
            .map(backend_message)
            .collect::<Result<Vec<_>, _>>()?;
        let output = StructuredOutputSpec::new_with_generation_schema(
            OUTPUT_SCHEMA_NAME,
            compiled_prompt.output_schema.clone(),
            compiled_prompt.generation_schema.clone(),
        )?;
        let mut inference = StructuredInferenceRequest::new(
            self.inference_policy.model_id.clone(),
            messages,
            output,
            self.inference_policy.max_output_tokens,
        )?;
        if let Some(reasoning) = self.inference_policy.reasoning {
            inference = inference.with_reasoning(reasoning);
        }
        Ok(PreparedPlannerReplannerRequest {
            inference_policy_sha256: self.inference_policy.policy_sha256.clone(),
            invocation,
            compiled_prompt,
            evidence_packet: evidence_packet.clone(),
            inference,
        })
    }
}

/// Validates one model value against the immutable prompt and then delegates
/// every plan semantic/state invariant to the authoritative domain method.
///
/// # Errors
///
/// Returns a prompt-boundary, DTO-decode, or durable-plan validation error.
pub fn validate_and_apply_planner_replanner_output(
    prepared: &PreparedPlannerReplannerRequest,
    value: &Value,
    base_plan: &PlanSnapshot,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
    inference_policy: &PlannerReplannerInferencePolicy,
) -> Result<ValidatedPlannerTurn, PlannerReplannerApplyError> {
    decode_and_apply_planner_replanner_output(
        prepared,
        value,
        base_plan,
        obligations,
        context,
        policy,
        inference_policy,
    )
    .map(|(_, result)| result)
}

/// Returns the exact decoded proposal together with its authoritative result.
///
/// # Errors
///
/// Applies the same prompt and durable-domain checks as
/// [`validate_and_apply_planner_replanner_output`].
pub fn decode_and_apply_planner_replanner_output(
    prepared: &PreparedPlannerReplannerRequest,
    value: &Value,
    base_plan: &PlanSnapshot,
    obligations: &ProtectedObligationCatalog,
    context: &PlannerContextCatalog,
    policy: &PlannerPolicy,
    inference_policy: &PlannerReplannerInferencePolicy,
) -> Result<(PlannerTurnProposal, ValidatedPlannerTurn), PlannerReplannerApplyError> {
    prepared.validate_against(base_plan, obligations, context, policy, inference_policy)?;
    let registry = builtin_registry()?;
    registry.validate_output(&prepared.compiled_prompt, &prepared.invocation, value)?;
    let proposal = serde_json::from_value::<PlannerTurnProposal>(value.clone())?;
    let result = proposal
        .validate_and_apply(base_plan, obligations, context, policy)
        .map_err(PlannerReplannerApplyError::Plan)?;
    Ok((proposal, result))
}

#[derive(Debug, Error)]
pub enum PlannerReplannerSetupError {
    #[error(transparent)]
    PlannerContract(#[from] PlannerContractError),
    #[error(transparent)]
    Prompt(#[from] PromptError),
    #[error(transparent)]
    BackendContract(#[from] ContractError),
    #[error(transparent)]
    InferencePolicy(#[from] PlannerReplannerInferencePolicyError),
    #[error("planner/replanner domain value could not be serialized: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("planner/replanner invocation is invalid: {violations:?}")]
    Invocation {
        violations: Vec<PlannerReplannerInvariantViolation>,
    },
    #[error("planner/replanner compiled request does not match authoritative inputs")]
    AttestationMismatch,
}

#[derive(Debug, Error)]
pub enum PlannerReplannerApplyError {
    #[error(transparent)]
    Setup(#[from] PlannerReplannerSetupError),
    #[error(transparent)]
    Prompt(#[from] PromptError),
    #[error("planner/replanner output could not be decoded into the durable domain: {0}")]
    OutputDecode(#[from] serde_json::Error),
    #[error(transparent)]
    Plan(PlannerValidationError),
}

fn prompt_bindings(bindings: &PlannerTurnBindings) -> PlannerReplannerBindings {
    PlannerReplannerBindings {
        plan_id: bindings.plan_id.to_string(),
        base_revision: bindings.base_revision,
        base_plan_sha256: bindings.base_plan_sha256.to_string(),
        obligation_snapshot_sha256: bindings.obligation_snapshot_sha256.to_string(),
        acceptance_policy_sha256: bindings.acceptance_policy_sha256.to_string(),
        context_manifest_sha256: bindings.context_manifest_sha256.to_string(),
        planner_policy_sha256: bindings.planner_policy_sha256.to_string(),
    }
}

fn backend_message(message: &CompiledMessage) -> Result<Message, serde_json::Error> {
    let role = match message.role {
        MessageRole::System => BackendMessageRole::System,
        MessageRole::User => BackendMessageRole::User,
    };
    let content = match &message.content {
        MessageContent::Text(value) => value.clone(),
        MessageContent::Json(value) => value.to_compact_string()?,
    };
    Ok(Message::new(role, content))
}
