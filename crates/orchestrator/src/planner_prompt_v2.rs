//! Single request/replay adapter for the versioned planner/replanner v2 wire.
//!
//! Prompting owns the semantic prompt contract. The planner domain owns the
//! authoritative state transition. This module is the only place that joins
//! those contracts to a backend [`StructuredInferenceRequest`], so live
//! execution and durable replay cannot drift through duplicated schema names,
//! message conversion, or inference options.

use crate::planner::{
    LocalWorkOrderId, PlanSnapshot, PlanWorkOrderId, PlannerContextCatalog, PlannerPolicy,
    PlannerTurnProposal, PlannerValidationError, ProtectedObligationCatalog, ValidatedPlannerTurn,
};
use crate::planner_prompt::{
    PlannerReplannerInferencePolicy, PlannerReplannerInferencePolicyError,
};
use birdcode_backends::{
    ContractError, Message, MessageRole as BackendMessageRole, ReasoningSetting,
    StructuredInferenceRequest, StructuredOutputSpec,
};
use birdcode_prompting::{
    CompiledMessage, CompiledPrompt, MessageContent, MessageRole, PlannerReplannerDecisionBasis,
    PlannerReplannerV2Bindings, PlannerReplannerV2InvariantViolation,
    PlannerReplannerV2InvocationMaterial, PlannerReplannerV2Output, PlannerReplannerV2Reasoning,
    PromptError, PromptInvocation, builtin_registry, planner_replanner_v2_invocation,
    planner_replanner_v2_key,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

const OUTPUT_SCHEMA_NAME: &str = "birdcode_planner_replanner_v2_turn";

/// Exact trusted inputs for one v2 planner request.
///
/// The semantic material includes the independently reconstructed plan,
/// obligations, context, evidence, delta, policy, and request echo bindings.
/// The separate inference policy is runtime authority for backend, model,
/// reasoning, and token ceiling; the builder requires both views to agree.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannerReplannerV2BuildInput {
    material: PlannerReplannerV2InvocationMaterial,
    inference_policy: PlannerReplannerInferencePolicy,
}

impl PlannerReplannerV2BuildInput {
    #[must_use]
    pub const fn new(
        material: PlannerReplannerV2InvocationMaterial,
        inference_policy: PlannerReplannerInferencePolicy,
    ) -> Self {
        Self {
            material,
            inference_policy,
        }
    }

    #[must_use]
    pub const fn material(&self) -> &PlannerReplannerV2InvocationMaterial {
        &self.material
    }

    #[must_use]
    pub const fn inference_policy(&self) -> &PlannerReplannerInferencePolicy {
        &self.inference_policy
    }
}

/// Provider-neutral request artifacts retained before inference.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPlannerReplannerV2Request {
    inference_policy_sha256: crate::planner::PlannerDigest,
    invocation: PromptInvocation,
    compiled_prompt: CompiledPrompt,
    inference: StructuredInferenceRequest,
}

impl PreparedPlannerReplannerV2Request {
    #[must_use]
    pub const fn inference_policy_sha256(&self) -> &crate::planner::PlannerDigest {
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
    pub const fn inference(&self) -> &StructuredInferenceRequest {
        &self.inference
    }

    /// Rebuilds every prepared value from independently supplied authority.
    ///
    /// # Errors
    ///
    /// Rejects any substituted policy, invocation, compiled message, output
    /// schema, model option, or request field.
    pub fn validate_against(
        &self,
        input: &PlannerReplannerV2BuildInput,
    ) -> Result<(), PlannerReplannerV2SetupError> {
        let expected = PlannerReplannerV2RequestBuilder::build(input)?;
        if self == &expected {
            Ok(())
        } else {
            Err(PlannerReplannerV2SetupError::AttestationMismatch)
        }
    }
}

/// Stateless owner of the frozen v2 backend request construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlannerReplannerV2RequestBuilder;

impl PlannerReplannerV2RequestBuilder {
    /// Compiles the exact semantic invocation and backend request without
    /// performing inference.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid prompt material, inference-policy drift,
    /// prompt compilation failure, or backend request constraints.
    pub fn build(
        input: &PlannerReplannerV2BuildInput,
    ) -> Result<PreparedPlannerReplannerV2Request, PlannerReplannerV2SetupError> {
        input.inference_policy.validate_integrity()?;
        validate_inference_bindings(&input.material.bindings, &input.inference_policy)?;

        let invocation = planner_replanner_v2_invocation(&input.material)
            .map_err(|violations| PlannerReplannerV2SetupError::Invocation { violations })?;
        let registry = builtin_registry()?;
        let compiled_prompt = registry.compile(&planner_replanner_v2_key(), &invocation)?;
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
            input.inference_policy.model_id().clone(),
            messages,
            output,
            input.inference_policy.max_output_tokens(),
        )?;
        if let Some(reasoning) = input.inference_policy.reasoning() {
            inference = inference.with_reasoning(reasoning);
        }

        Ok(PreparedPlannerReplannerV2Request {
            inference_policy_sha256: input.inference_policy.policy_sha256().clone(),
            invocation,
            compiled_prompt,
            inference,
        })
    }
}

/// Accepted v2 provenance together with the authoritative planner transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPlannerReplannerV2Turn {
    pub proposal: PlannerTurnProposal,
    pub validated: ValidatedPlannerTurn,
    pub source_schema_version: u32,
    pub turn_basis: PlannerReplannerDecisionBasis,
    pub request_bindings: PlannerReplannerV2Bindings,
    local_work_order_ids: BTreeMap<LocalWorkOrderId, PlanWorkOrderId>,
}

impl ValidatedPlannerReplannerV2Turn {
    /// Returns the exact local-to-authoritative work-order allocation produced
    /// by the same domain validation pass as [`Self::validated`].
    #[must_use]
    pub const fn local_work_order_ids(&self) -> &BTreeMap<LocalWorkOrderId, PlanWorkOrderId> {
        &self.local_work_order_ids
    }
}

/// Revalidates one typed model output against the exact prepared request and
/// applies it through the authoritative planner domain.
///
/// # Errors
///
/// Returns a typed request-attestation, prompt-boundary, domain-projection, or
/// plan-transition error. No semantic field is repaired or inferred here.
pub fn decode_and_apply_planner_replanner_v2_output(
    prepared: &PreparedPlannerReplannerV2Request,
    value: &Value,
    input: &PlannerReplannerV2BuildInput,
) -> Result<ValidatedPlannerReplannerV2Turn, PlannerReplannerV2ApplyError> {
    prepared.validate_against(input)?;
    let output = serde_json::from_value::<PlannerReplannerV2Output>(value.clone())
        .map_err(PlannerReplannerV2ApplyError::OutputDecode)?;
    let parts = output
        .into_authoritative_parts(prepared.invocation())
        .map_err(|violations| PlannerReplannerV2ApplyError::OutputInvariant { violations })?;
    let proposal: PlannerTurnProposal = project_domain(&parts.proposal, "proposal")?;
    let base_plan: PlanSnapshot = project_domain(&input.material.base_plan, "base_plan")?;
    let obligations: ProtectedObligationCatalog = project_domain(
        &input.material.protected_obligation_catalog,
        "protected_obligation_catalog",
    )?;
    let context: PlannerContextCatalog = project_domain(
        &input.material.planner_context_catalog,
        "planner_context_catalog",
    )?;
    let policy: PlannerPolicy = project_domain(&input.material.planner_policy, "planner_policy")?;
    let applied = proposal
        .validate_and_apply_with_allocations(&base_plan, &obligations, &context, &policy)
        .map_err(PlannerReplannerV2ApplyError::Plan)?;

    Ok(ValidatedPlannerReplannerV2Turn {
        proposal,
        validated: applied.validated,
        source_schema_version: parts.source_schema_version,
        turn_basis: parts.turn_basis,
        request_bindings: parts.request_bindings,
        local_work_order_ids: applied.local_work_order_ids,
    })
}

#[derive(Debug, Error)]
pub enum PlannerReplannerV2SetupError {
    #[error(transparent)]
    Prompt(#[from] PromptError),
    #[error(transparent)]
    BackendContract(#[from] ContractError),
    #[error(transparent)]
    InferencePolicy(#[from] PlannerReplannerInferencePolicyError),
    #[error("planner/replanner v2 backend message could not be encoded: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("planner/replanner v2 invocation is invalid: {violations:?}")]
    Invocation {
        violations: Vec<PlannerReplannerV2InvariantViolation>,
    },
    #[error("planner/replanner v2 inference binding does not match trusted field {field}")]
    InferenceBindingMismatch { field: &'static str },
    #[error("planner/replanner v2 compiled request does not match authoritative inputs")]
    AttestationMismatch,
}

#[derive(Debug, Error)]
pub enum PlannerReplannerV2ApplyError {
    #[error(transparent)]
    Setup(#[from] PlannerReplannerV2SetupError),
    #[error("planner/replanner v2 output could not be decoded: {0}")]
    OutputDecode(serde_json::Error),
    #[error("planner/replanner v2 output violates the prompt contract: {violations:?}")]
    OutputInvariant {
        violations: Vec<PlannerReplannerV2InvariantViolation>,
    },
    #[error("planner/replanner v2 {field} is not isomorphic to the planner domain: {source}")]
    DomainProjection {
        field: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Plan(PlannerValidationError),
}

fn validate_inference_bindings(
    bindings: &PlannerReplannerV2Bindings,
    policy: &PlannerReplannerInferencePolicy,
) -> Result<(), PlannerReplannerV2SetupError> {
    for (field, matches) in [
        (
            "backend_id",
            bindings.backend_id == policy.backend_id().as_str(),
        ),
        (
            "backend_configured_deployment_id",
            bindings.backend_configured_deployment_id
                == policy
                    .backend_instance()
                    .configured_deployment_id()
                    .as_str(),
        ),
        (
            "backend_endpoint_origin",
            bindings.backend_endpoint_origin
                == policy.backend_instance().endpoint_origin().as_str(),
        ),
        (
            "backend_instance_sha256",
            bindings.backend_instance_sha256
                == policy.backend_instance().identity_sha256().as_str(),
        ),
        ("model_id", bindings.model_id == policy.model_id().as_str()),
        (
            "reasoning",
            bindings.reasoning == policy.reasoning().map(prompt_reasoning),
        ),
        (
            "max_output_tokens",
            bindings.max_output_tokens == policy.max_output_tokens(),
        ),
    ] {
        if !matches {
            return Err(PlannerReplannerV2SetupError::InferenceBindingMismatch { field });
        }
    }
    Ok(())
}

const fn prompt_reasoning(reasoning: ReasoningSetting) -> PlannerReplannerV2Reasoning {
    match reasoning {
        ReasoningSetting::Off => PlannerReplannerV2Reasoning::Off,
        ReasoningSetting::On => PlannerReplannerV2Reasoning::On,
        ReasoningSetting::Low => PlannerReplannerV2Reasoning::Low,
        ReasoningSetting::Medium => PlannerReplannerV2Reasoning::Medium,
        ReasoningSetting::High => PlannerReplannerV2Reasoning::High,
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

fn project_domain<T, U>(value: &T, field: &'static str) -> Result<U, PlannerReplannerV2ApplyError>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let value = serde_json::to_value(value)
        .map_err(|source| PlannerReplannerV2ApplyError::DomainProjection { field, source })?;
    serde_json::from_value(value)
        .map_err(|source| PlannerReplannerV2ApplyError::DomainProjection { field, source })
}
