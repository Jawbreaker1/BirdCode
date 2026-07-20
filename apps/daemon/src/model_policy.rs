use birdcode_prompting::{
    PromptError, PromptKey, PromptRegistry, builtin_registry, plan_critic_key, plan_repair_key,
    root_planner_key,
};
use birdcode_protocol::{
    ModelLineage, ROOT_PLANNING_POLICY_V1_FINAL_REVIEW_MAX_OUTPUT_TOKENS,
    ROOT_PLANNING_POLICY_V1_INITIAL_PLAN_MAX_OUTPUT_TOKENS,
    ROOT_PLANNING_POLICY_V1_INITIAL_REVIEW_MAX_OUTPUT_TOKENS,
    ROOT_PLANNING_POLICY_V1_REPAIR_MAX_OUTPUT_TOKENS, RootPlanningExecutionPolicy,
    RootPlanningPromptContracts, RootPlanningStageBudgets, Sha256Digest, Sha256DigestError,
};
pub use birdcode_protocol::{
    ROOT_PLANNING_POLICY_V1_MAX_MODEL_CALLS as ROOT_PLANNING_MAX_MODEL_CALLS,
    ROOT_PLANNING_POLICY_V1_MAX_REPAIRS as ROOT_PLANNING_MAX_REPAIRS,
    ROOT_PLANNING_POLICY_V1_MAX_REVIEW_ROUNDS as ROOT_PLANNING_MAX_REVIEW_ROUNDS,
    ROOT_PLANNING_POLICY_V1_SCHEMA_VERSION as ROOT_PLANNING_POLICY_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::fmt;

const MAX_LINEAGE_IDENTIFIER_BYTES: usize = 512;
const PRODUCER_LINEAGE_PATHS: LineagePaths = LineagePaths {
    backend: "producer.backend_id",
    model: "producer.model_id",
    deployment: "producer.deployment_id",
    independence_domain: "producer.independence_domain_id",
};
const CRITIC_LINEAGE_PATHS: LineagePaths = LineagePaths {
    backend: "critic.backend_id",
    model: "critic.model_id",
    deployment: "critic.deployment_id",
    independence_domain: "critic.independence_domain_id",
};

#[derive(Clone, Copy)]
struct LineagePaths {
    backend: &'static str,
    model: &'static str,
    deployment: &'static str,
    independence_domain: &'static str,
}

/// Strict daemon-owned configuration for enhanced root planning.
///
/// Prompt digests are deliberately absent. They are derived from `BirdCode`'s
/// bundled prompt registry when this configuration is compiled, so a config
/// file cannot substitute a different planning, critic, or repair contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRootPlanningPolicyConfig {
    pub schema_version: u32,
    pub producer: ModelLineage,
    pub critic: ModelLineage,
    pub max_model_calls: u32,
    pub max_repairs: u32,
    pub max_review_rounds: u32,
    pub stage_budgets: RootPlanningStageBudgets,
}

impl TrustedRootPlanningPolicyConfig {
    /// Decodes a strict JSON policy configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, duplicate or unknown fields, and
    /// values that do not match the typed configuration shape.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, ModelPolicyError> {
        serde_json::from_slice(bytes).map_err(ModelPolicyError::InvalidJson)
    }

    /// Validates trusted model lineage and closed execution limits, then binds
    /// the exact bundled prompt-manifest digests.
    ///
    /// # Errors
    ///
    /// Returns an error unless the policy is the fixed four-call, two-review,
    /// one-repair protocol with executable nonzero stage budgets and mutually
    /// independent producer and critic identities.
    pub fn compile(&self) -> Result<RootPlanningExecutionPolicy, ModelPolicyError> {
        validate_closed_value(
            "schema_version",
            ROOT_PLANNING_POLICY_SCHEMA_VERSION,
            self.schema_version,
        )?;
        validate_closed_value(
            "max_model_calls",
            ROOT_PLANNING_MAX_MODEL_CALLS,
            self.max_model_calls,
        )?;
        validate_closed_value("max_repairs", ROOT_PLANNING_MAX_REPAIRS, self.max_repairs)?;
        validate_closed_value(
            "max_review_rounds",
            ROOT_PLANNING_MAX_REVIEW_ROUNDS,
            self.max_review_rounds,
        )?;

        validate_lineage(PRODUCER_LINEAGE_PATHS, &self.producer)?;
        validate_lineage(CRITIC_LINEAGE_PATHS, &self.critic)?;
        validate_independence(&self.producer, &self.critic)?;
        validate_stage_budgets(&self.stage_budgets)?;

        let registry = builtin_registry().map_err(ModelPolicyError::PromptRegistry)?;
        let prompt_contracts = RootPlanningPromptContracts {
            initial_plan_manifest_sha256: manifest_sha256(&registry, root_planner_key())?,
            critic_manifest_sha256: manifest_sha256(&registry, plan_critic_key())?,
            repair_manifest_sha256: manifest_sha256(&registry, plan_repair_key())?,
        };

        Ok(RootPlanningExecutionPolicy {
            schema_version: self.schema_version,
            producer: self.producer.clone(),
            critic: self.critic.clone(),
            max_model_calls: self.max_model_calls,
            max_repairs: self.max_repairs,
            max_review_rounds: self.max_review_rounds,
            stage_budgets: self.stage_budgets.clone(),
            prompt_contracts,
        })
    }
}

/// Parses and compiles a strict daemon policy without accepting configurable
/// prompt-manifest identities.
///
/// # Errors
///
/// Returns any strict JSON, lineage, budget, closed-limit, or bundled-prompt
/// validation error.
pub fn compile_root_planning_policy_json(
    bytes: &[u8],
) -> Result<RootPlanningExecutionPolicy, ModelPolicyError> {
    TrustedRootPlanningPolicyConfig::from_json_slice(bytes)?.compile()
}

#[derive(Debug)]
pub enum ModelPolicyError {
    InvalidJson(serde_json::Error),
    ClosedValueMismatch {
        field: &'static str,
        expected: u32,
        actual: u32,
    },
    InvalidCanonicalIdentifier {
        field: &'static str,
        maximum_bytes: usize,
    },
    LineageNotIndependent {
        field: &'static str,
    },
    ZeroStageBudget {
        field: &'static str,
    },
    StageBudgetExceedsCompilerLimit {
        field: &'static str,
        maximum: u64,
        actual: u64,
    },
    TotalStageBudgetOverflow,
    PromptRegistry(PromptError),
    MissingBuiltinPrompt(PromptKey),
    InvalidManifestDigest {
        prompt: PromptKey,
        source: Sha256DigestError,
    },
}

impl fmt::Display for ModelPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(error) => write!(formatter, "invalid model-policy JSON: {error}"),
            Self::ClosedValueMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "model-policy field {field} must be {expected}, got {actual}"
            ),
            Self::InvalidCanonicalIdentifier {
                field,
                maximum_bytes,
            } => write!(
                formatter,
                "model-policy identifier {field} must be nonblank, canonically trimmed, and at most {maximum_bytes} bytes"
            ),
            Self::LineageNotIndependent { field } => write!(
                formatter,
                "producer and critic must have distinct {field} values"
            ),
            Self::ZeroStageBudget { field } => {
                write!(
                    formatter,
                    "model-policy stage budget {field} must be nonzero"
                )
            }
            Self::StageBudgetExceedsCompilerLimit {
                field,
                maximum,
                actual,
            } => write!(
                formatter,
                "model-policy stage budget {field} exceeds compiler limit {maximum}: got {actual}"
            ),
            Self::TotalStageBudgetOverflow => {
                formatter.write_str("model-policy total stage budget overflows u64")
            }
            Self::PromptRegistry(error) => {
                write!(formatter, "bundled prompt registry is invalid: {error}")
            }
            Self::MissingBuiltinPrompt(prompt) => {
                write!(formatter, "required bundled prompt is missing: {prompt}")
            }
            Self::InvalidManifestDigest { prompt, source } => write!(
                formatter,
                "bundled prompt {prompt} produced a noncanonical SHA-256 digest: {source}"
            ),
        }
    }
}

impl std::error::Error for ModelPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidJson(error) => Some(error),
            Self::PromptRegistry(error) => Some(error),
            Self::InvalidManifestDigest { source, .. } => Some(source),
            Self::ClosedValueMismatch { .. }
            | Self::InvalidCanonicalIdentifier { .. }
            | Self::LineageNotIndependent { .. }
            | Self::ZeroStageBudget { .. }
            | Self::StageBudgetExceedsCompilerLimit { .. }
            | Self::TotalStageBudgetOverflow
            | Self::MissingBuiltinPrompt(_) => None,
        }
    }
}

fn validate_closed_value(
    field: &'static str,
    expected: u32,
    actual: u32,
) -> Result<(), ModelPolicyError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ModelPolicyError::ClosedValueMismatch {
            field,
            expected,
            actual,
        })
    }
}

fn validate_lineage(paths: LineagePaths, lineage: &ModelLineage) -> Result<(), ModelPolicyError> {
    validate_identifier(paths.backend, &lineage.backend_id)?;
    validate_identifier(paths.model, &lineage.model_id)?;
    validate_identifier(paths.deployment, &lineage.deployment_id)?;
    validate_identifier(paths.independence_domain, &lineage.independence_domain_id)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ModelPolicyError> {
    if value.is_empty() || value.trim() != value || value.len() > MAX_LINEAGE_IDENTIFIER_BYTES {
        return Err(ModelPolicyError::InvalidCanonicalIdentifier {
            field,
            maximum_bytes: MAX_LINEAGE_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

fn validate_independence(
    producer: &ModelLineage,
    critic: &ModelLineage,
) -> Result<(), ModelPolicyError> {
    for (field, producer_value, critic_value) in [
        ("model_id", &producer.model_id, &critic.model_id),
        (
            "deployment_id",
            &producer.deployment_id,
            &critic.deployment_id,
        ),
        (
            "independence_domain_id",
            &producer.independence_domain_id,
            &critic.independence_domain_id,
        ),
    ] {
        if producer_value == critic_value {
            return Err(ModelPolicyError::LineageNotIndependent { field });
        }
    }
    Ok(())
}

fn validate_stage_budgets(budgets: &RootPlanningStageBudgets) -> Result<(), ModelPolicyError> {
    let stages = [
        (
            "initial_plan_output_tokens",
            budgets.initial_plan_output_tokens,
            u64::from(ROOT_PLANNING_POLICY_V1_INITIAL_PLAN_MAX_OUTPUT_TOKENS),
        ),
        (
            "initial_review_output_tokens",
            budgets.initial_review_output_tokens,
            u64::from(ROOT_PLANNING_POLICY_V1_INITIAL_REVIEW_MAX_OUTPUT_TOKENS),
        ),
        (
            "repair_output_tokens",
            budgets.repair_output_tokens,
            u64::from(ROOT_PLANNING_POLICY_V1_REPAIR_MAX_OUTPUT_TOKENS),
        ),
        (
            "final_review_output_tokens",
            budgets.final_review_output_tokens,
            u64::from(ROOT_PLANNING_POLICY_V1_FINAL_REVIEW_MAX_OUTPUT_TOKENS),
        ),
    ];
    stages
        .iter()
        .map(|(_, value, _)| *value)
        .try_fold(0_u64, u64::checked_add)
        .ok_or(ModelPolicyError::TotalStageBudgetOverflow)?;
    for (field, actual, maximum) in stages {
        if actual == 0 {
            return Err(ModelPolicyError::ZeroStageBudget { field });
        }
        if actual > maximum {
            return Err(ModelPolicyError::StageBudgetExceedsCompilerLimit {
                field,
                maximum,
                actual,
            });
        }
    }
    Ok(())
}

fn manifest_sha256(
    registry: &PromptRegistry,
    key: PromptKey,
) -> Result<Sha256Digest, ModelPolicyError> {
    let manifest = registry
        .get(&key)
        .ok_or_else(|| ModelPolicyError::MissingBuiltinPrompt(key.clone()))?;
    let digest = manifest
        .content_sha256()
        .map_err(ModelPolicyError::PromptRegistry)?;
    Sha256Digest::parse(digest).map_err(|source| ModelPolicyError::InvalidManifestDigest {
        prompt: key,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn lineage(
        backend_id: &str,
        model_id: &str,
        deployment_id: &str,
        independence_domain_id: &str,
    ) -> ModelLineage {
        ModelLineage {
            backend_id: backend_id.to_owned(),
            model_id: model_id.to_owned(),
            deployment_id: deployment_id.to_owned(),
            independence_domain_id: independence_domain_id.to_owned(),
        }
    }

    fn valid_config() -> TrustedRootPlanningPolicyConfig {
        TrustedRootPlanningPolicyConfig {
            schema_version: ROOT_PLANNING_POLICY_SCHEMA_VERSION,
            producer: lineage(
                "lmstudio",
                "producer-model-exact",
                "producer-deployment-1",
                "producer-domain",
            ),
            critic: lineage(
                "lmstudio",
                "critic-model-exact",
                "critic-deployment-1",
                "critic-domain",
            ),
            max_model_calls: ROOT_PLANNING_MAX_MODEL_CALLS,
            max_repairs: ROOT_PLANNING_MAX_REPAIRS,
            max_review_rounds: ROOT_PLANNING_MAX_REVIEW_ROUNDS,
            stage_budgets: RootPlanningStageBudgets {
                initial_plan_output_tokens: 4_096,
                initial_review_output_tokens: 2_048,
                repair_output_tokens: 4_096,
                final_review_output_tokens: 2_048,
            },
        }
    }

    #[test]
    fn checked_in_example_policy_remains_strictly_compilable() {
        let config = TrustedRootPlanningPolicyConfig::from_json_slice(include_bytes!(
            "../../../examples/root-planning-policy.json"
        ))
        .expect("checked-in example policy should remain strict JSON");

        config
            .compile()
            .expect("checked-in example policy should remain mechanically valid");
    }

    fn expected_manifest_digest(key: &PromptKey) -> Sha256Digest {
        let registry = builtin_registry().expect("bundled registry should validate");
        let manifest = registry.get(key).expect("bundled prompt should exist");
        Sha256Digest::parse(
            manifest
                .content_sha256()
                .expect("bundled manifest should hash"),
        )
        .expect("bundled manifest hash should be canonical")
    }

    #[test]
    fn valid_config_compiles_with_digests_from_the_builtin_registry() {
        let config = valid_config();
        let json = serde_json::to_vec(&config).expect("config should serialize");
        let policy = compile_root_planning_policy_json(&json).expect("config should compile");

        assert_eq!(policy.schema_version, ROOT_PLANNING_POLICY_SCHEMA_VERSION);
        assert_eq!(policy.producer, config.producer);
        assert_eq!(policy.critic, config.critic);
        assert_eq!(policy.stage_budgets, config.stage_budgets);
        assert_eq!(
            policy.prompt_contracts.initial_plan_manifest_sha256,
            expected_manifest_digest(&root_planner_key())
        );
        assert_eq!(
            policy.prompt_contracts.critic_manifest_sha256,
            expected_manifest_digest(&plan_critic_key())
        );
        assert_eq!(
            policy.prompt_contracts.repair_manifest_sha256,
            expected_manifest_digest(&plan_repair_key())
        );
    }

    #[test]
    fn same_lineage_dimensions_fail_closed() {
        let base = valid_config();
        let mut same_model = base.clone();
        same_model
            .critic
            .model_id
            .clone_from(&same_model.producer.model_id);
        let mut same_deployment = base.clone();
        same_deployment
            .critic
            .deployment_id
            .clone_from(&same_deployment.producer.deployment_id);
        let mut same_domain = base;
        same_domain
            .critic
            .independence_domain_id
            .clone_from(&same_domain.producer.independence_domain_id);

        for (expected_field, config) in [
            ("model_id", same_model),
            ("deployment_id", same_deployment),
            ("independence_domain_id", same_domain),
        ] {
            assert!(matches!(
                config.compile(),
                Err(ModelPolicyError::LineageNotIndependent { field })
                    if field == expected_field
            ));
        }
    }

    #[test]
    fn zero_stage_budget_fails_closed() {
        let mut config = valid_config();
        config.stage_budgets.repair_output_tokens = 0;

        assert!(matches!(
            config.compile(),
            Err(ModelPolicyError::ZeroStageBudget {
                field: "repair_output_tokens"
            })
        ));
    }

    #[test]
    fn overflowing_and_unexecutable_stage_budgets_fail_closed() {
        let mut overflowing = valid_config();
        overflowing.stage_budgets.initial_plan_output_tokens = u64::MAX;
        assert!(matches!(
            overflowing.compile(),
            Err(ModelPolicyError::TotalStageBudgetOverflow)
        ));

        let mut above_compiler_limit = valid_config();
        above_compiler_limit
            .stage_budgets
            .initial_review_output_tokens =
            u64::from(ROOT_PLANNING_POLICY_V1_INITIAL_REVIEW_MAX_OUTPUT_TOKENS) + 1;
        assert!(matches!(
            above_compiler_limit.compile(),
            Err(ModelPolicyError::StageBudgetExceedsCompilerLimit {
                field: "initial_review_output_tokens",
                ..
            })
        ));
    }

    #[test]
    fn tampered_closed_limits_fail_closed() {
        let base = valid_config();
        let mut wrong_schema = base.clone();
        wrong_schema.schema_version += 1;
        let mut extra_call = base.clone();
        extra_call.max_model_calls += 1;
        let mut extra_repair = base.clone();
        extra_repair.max_repairs += 1;
        let mut missing_review = base;
        missing_review.max_review_rounds -= 1;

        for (expected_field, config) in [
            ("schema_version", wrong_schema),
            ("max_model_calls", extra_call),
            ("max_repairs", extra_repair),
            ("max_review_rounds", missing_review),
        ] {
            assert!(matches!(
                config.compile(),
                Err(ModelPolicyError::ClosedValueMismatch { field, .. })
                    if field == expected_field
            ));
        }
    }

    #[test]
    fn prompt_contracts_cannot_be_injected_through_json() {
        let mut value = serde_json::to_value(valid_config()).expect("config should serialize");
        let Value::Object(object) = &mut value else {
            panic!("config must serialize as an object");
        };
        object.insert(
            "prompt_contracts".to_owned(),
            serde_json::json!({"initial_plan_manifest_sha256": "untrusted"}),
        );
        let bytes = serde_json::to_vec(&value).expect("test JSON should serialize");

        assert!(matches!(
            TrustedRootPlanningPolicyConfig::from_json_slice(&bytes),
            Err(ModelPolicyError::InvalidJson(_))
        ));
    }

    #[test]
    fn noncanonical_lineage_identifier_fails_closed() {
        let mut config = valid_config();
        config.critic.deployment_id = " critic-deployment-1".to_owned();

        assert!(matches!(
            config.compile(),
            Err(ModelPolicyError::InvalidCanonicalIdentifier {
                field: "critic.deployment_id",
                ..
            })
        ));
    }
}
