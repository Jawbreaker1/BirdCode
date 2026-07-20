use crate::compiler::PromptInvocation;
use crate::root_planner::{RootPlannerInvariantViolation, validate_root_planner_output};
use crate::{PromptId, PromptKey};
use semver::Version;
use serde_json::Value;

const PLAN_REPAIR_ID: &str = "birdcode.root-plan-repair";

/// Returns the immutable key of the bundled bounded repair prompt.
///
/// # Panics
///
/// Panics only if the compile-time identifier is invalid.
#[must_use]
pub fn plan_repair_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(PLAN_REPAIR_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 0, 0),
    )
}

pub(crate) fn is_plan_repair_key(key: &PromptKey) -> bool {
    key == &plan_repair_key()
}

/// Validates a repair as a complete replacement root plan against the
/// original immutable planner policy.
///
/// The triggering critique remains evidence, not authority. Mechanical
/// validation therefore reuses the exact root-plan contract; a later
/// independent critic decides whether the replacement addressed the meaning
/// of the findings.
///
/// # Errors
///
/// Returns the root-plan binding and shape violations without interpreting
/// natural-language fields.
pub fn validate_plan_repair_output(
    value: &Value,
    invocation: &PromptInvocation,
) -> Result<(), Vec<RootPlannerInvariantViolation>> {
    let mut root_invocation = invocation.clone();
    root_invocation
        .sections
        .retain(|section| matches!(section.name.as_str(), "run_input" | "repository_identity"));
    validate_root_planner_output(value, &root_invocation)
}
