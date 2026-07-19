use crate::compiler::{PromptInvocation, TrustLevel};
use crate::{PromptError, PromptId, PromptKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const TASK_ROUTER_ID: &str = "birdcode.semantic-task-router";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Clarify,
    Answer,
    Inspect,
    Change,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStrategy {
    Direct,
    Delegate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredAccess {
    None,
    ReadOnly,
    WorkspaceWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteEvidence {
    pub section: String,
    pub basis: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuggestedSubtask {
    pub id: String,
    pub objective: String,
    pub required_access: RequiredAccess,
    pub acceptance_criteria: Vec<String>,
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRouterOutput {
    pub action: RouteAction,
    pub strategy: RouteStrategy,
    pub required_access: RequiredAccess,
    pub confidence: f64,
    pub evidence: Vec<RouteEvidence>,
    pub clarification_questions: Vec<String>,
    pub suggested_subtasks: Vec<SuggestedSubtask>,
}

/// A machine-readable failure of the semantic router's local contract.
///
/// These variants are deliberately independent of rendered error text. An
/// orchestrator may use the exact variant to decide whether a bounded repair
/// is safe, while retaining every simultaneous violation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterInvariantViolation {
    TooManySuggestedSubtasks {
        maximum: u32,
        actual: u32,
    },
    RequiredAccessMismatch {
        action: RouteAction,
        expected: RequiredAccess,
        actual: RequiredAccess,
    },
    DelegateForUnsupportedAction {
        action: RouteAction,
    },
    ClarificationQuestionPresenceMismatch {
        action: RouteAction,
    },
    SuggestedSubtaskPresenceMismatch {
        strategy: RouteStrategy,
    },
    BlankEvidenceField {
        index: u32,
    },
    UnknownEvidenceSection {
        index: u32,
        section: String,
    },
    DuplicateEvidenceSection {
        section: String,
        occurrences: u32,
    },
    UserSectionCount {
        actual: u32,
    },
    UserEvidenceCitationCount {
        section: String,
        actual: u32,
    },
    BlankClarificationQuestion {
        index: u32,
    },
    SubtaskAccessExceedsRoute {
        index: u32,
        id: String,
    },
    BlankSubtaskId {
        index: u32,
    },
    BlankSubtaskObjective {
        index: u32,
        id: String,
    },
    BlankAcceptanceCriterion {
        subtask_index: u32,
        criterion_index: u32,
        id: String,
    },
    BlankDependency {
        subtask_index: u32,
        dependency_index: u32,
        id: String,
    },
    DuplicateSubtaskId {
        id: String,
        occurrences: u32,
    },
    SelfDependency {
        id: String,
    },
    UnknownDependency {
        id: String,
        dependency: String,
    },
    DependencyCycle,
}

/// Returns the stable key of the latest bundled semantic task router.
///
/// # Panics
///
/// Panics only if the compile-time constant identifier or version is invalid.
#[must_use]
pub fn task_router_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(TASK_ROUTER_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 1, 3),
    )
}

pub(crate) fn is_task_router_key(key: &PromptKey) -> bool {
    key.id.as_str() == TASK_ROUTER_ID
}

pub(crate) fn validate_router_output(
    value: &Value,
    invocation: &PromptInvocation,
    prompt_version: &Version,
) -> Result<(), PromptError> {
    let output = serde_json::from_value::<TaskRouterOutput>(value.clone())?;
    let violations = router_invariant_violations(&output, invocation, prompt_version);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(PromptError::OutputInvariant(violations))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one collect-all pass keeps simultaneous router violations visible to repair policy"
)]
fn router_invariant_violations(
    output: &TaskRouterOutput,
    invocation: &PromptInvocation,
    prompt_version: &Version,
) -> Vec<RouterInvariantViolation> {
    let mut violations = Vec::new();
    if u64::try_from(output.suggested_subtasks.len()).unwrap_or(u64::MAX)
        > u64::from(invocation.limits.max_suggested_subtasks)
    {
        violations.push(RouterInvariantViolation::TooManySuggestedSubtasks {
            maximum: invocation.limits.max_suggested_subtasks,
            actual: wire_u32(output.suggested_subtasks.len()),
        });
    }
    collect_route_axis_violations(output, &mut violations);
    let sections = invocation
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect::<BTreeSet<_>>();
    for (index, evidence) in output.evidence.iter().enumerate() {
        if evidence.section.trim().is_empty() || evidence.basis.trim().is_empty() {
            violations.push(RouterInvariantViolation::BlankEvidenceField {
                index: wire_u32(index),
            });
        }
        if !sections.contains(evidence.section.as_str()) {
            violations.push(RouterInvariantViolation::UnknownEvidenceSection {
                index: wire_u32(index),
                section: evidence.section.clone(),
            });
        }
    }
    if prompt_version >= &Version::new(1, 1, 1) {
        collect_minimal_evidence_violations(output, invocation, &mut violations);
    }
    for (index, question) in output.clarification_questions.iter().enumerate() {
        if question.trim().is_empty() {
            violations.push(RouterInvariantViolation::BlankClarificationQuestion {
                index: wire_u32(index),
            });
        }
    }

    let mut tasks = BTreeMap::<&str, &SuggestedSubtask>::new();
    let mut task_id_counts = BTreeMap::<&str, usize>::new();
    for (index, task) in output.suggested_subtasks.iter().enumerate() {
        if task.required_access > output.required_access {
            violations.push(RouterInvariantViolation::SubtaskAccessExceedsRoute {
                index: wire_u32(index),
                id: task.id.clone(),
            });
        }
        if task.id.trim().is_empty() {
            violations.push(RouterInvariantViolation::BlankSubtaskId {
                index: wire_u32(index),
            });
        }
        if task.objective.trim().is_empty() {
            violations.push(RouterInvariantViolation::BlankSubtaskObjective {
                index: wire_u32(index),
                id: task.id.clone(),
            });
        }
        for (criterion_index, criterion) in task.acceptance_criteria.iter().enumerate() {
            if criterion.trim().is_empty() {
                violations.push(RouterInvariantViolation::BlankAcceptanceCriterion {
                    subtask_index: wire_u32(index),
                    criterion_index: wire_u32(criterion_index),
                    id: task.id.clone(),
                });
            }
        }
        for (dependency_index, dependency) in task.depends_on.iter().enumerate() {
            if dependency.trim().is_empty() {
                violations.push(RouterInvariantViolation::BlankDependency {
                    subtask_index: wire_u32(index),
                    dependency_index: wire_u32(dependency_index),
                    id: task.id.clone(),
                });
            }
        }
        *task_id_counts.entry(task.id.as_str()).or_default() += 1;
        tasks.entry(task.id.as_str()).or_insert(task);
    }
    for (id, occurrences) in task_id_counts {
        if occurrences > 1 {
            violations.push(RouterInvariantViolation::DuplicateSubtaskId {
                id: id.to_owned(),
                occurrences: wire_u32(occurrences),
            });
        }
    }
    for task in &output.suggested_subtasks {
        for dependency in &task.depends_on {
            if dependency == &task.id {
                violations.push(RouterInvariantViolation::SelfDependency {
                    id: task.id.clone(),
                });
            } else if !tasks.contains_key(dependency.as_str()) {
                violations.push(RouterInvariantViolation::UnknownDependency {
                    id: task.id.clone(),
                    dependency: dependency.clone(),
                });
            }
        }
    }
    if dependency_graph_has_cycle(&tasks) {
        violations.push(RouterInvariantViolation::DependencyCycle);
    }
    violations
}

fn collect_minimal_evidence_violations(
    output: &TaskRouterOutput,
    invocation: &PromptInvocation,
    violations: &mut Vec<RouterInvariantViolation>,
) {
    let mut citation_counts = BTreeMap::<&str, usize>::new();
    for evidence in &output.evidence {
        *citation_counts
            .entry(evidence.section.as_str())
            .or_default() += 1;
    }
    let mut emitted_duplicates = BTreeSet::new();
    for evidence in &output.evidence {
        let occurrences = citation_counts[evidence.section.as_str()];
        if occurrences > 1 && emitted_duplicates.insert(evidence.section.as_str()) {
            violations.push(RouterInvariantViolation::DuplicateEvidenceSection {
                section: evidence.section.clone(),
                occurrences: wire_u32(occurrences),
            });
        }
    }

    let user_sections = invocation
        .sections
        .iter()
        .filter(|section| section.trust == TrustLevel::User)
        .collect::<Vec<_>>();
    if user_sections.len() == 1 {
        let user_section = user_sections[0];
        let actual = citation_counts
            .get(user_section.name.as_str())
            .copied()
            .unwrap_or_default();
        // More than one citation is represented canonically by the typed
        // duplicate-section violation above. Emitting a second violation for
        // the same defect would incorrectly make an evidence-only repair look
        // non-repairable.
        if actual == 0 {
            violations.push(RouterInvariantViolation::UserEvidenceCitationCount {
                section: user_section.name.clone(),
                actual: wire_u32(actual),
            });
        }
    } else {
        violations.push(RouterInvariantViolation::UserSectionCount {
            actual: wire_u32(user_sections.len()),
        });
    }
}

fn collect_route_axis_violations(
    output: &TaskRouterOutput,
    violations: &mut Vec<RouterInvariantViolation>,
) {
    let expected_access = match output.action {
        RouteAction::Clarify | RouteAction::Answer => RequiredAccess::None,
        RouteAction::Inspect => RequiredAccess::ReadOnly,
        RouteAction::Change => RequiredAccess::WorkspaceWrite,
    };
    if output.required_access != expected_access {
        violations.push(RouterInvariantViolation::RequiredAccessMismatch {
            action: output.action,
            expected: expected_access,
            actual: output.required_access,
        });
    }
    if output.strategy == RouteStrategy::Delegate
        && !matches!(output.action, RouteAction::Inspect | RouteAction::Change)
    {
        violations.push(RouterInvariantViolation::DelegateForUnsupportedAction {
            action: output.action,
        });
    }
    if output.clarification_questions.is_empty() == (output.action == RouteAction::Clarify) {
        violations.push(
            RouterInvariantViolation::ClarificationQuestionPresenceMismatch {
                action: output.action,
            },
        );
    }
    if output.suggested_subtasks.is_empty() == (output.strategy == RouteStrategy::Delegate) {
        violations.push(RouterInvariantViolation::SuggestedSubtaskPresenceMismatch {
            strategy: output.strategy,
        });
    }
}

fn dependency_graph_has_cycle(tasks: &BTreeMap<&str, &SuggestedSubtask>) -> bool {
    fn visit<'a>(
        id: &'a str,
        tasks: &BTreeMap<&'a str, &'a SuggestedSubtask>,
        active: &mut BTreeSet<&'a str>,
        complete: &mut BTreeSet<&'a str>,
    ) -> bool {
        if complete.contains(id) {
            return false;
        }
        if !active.insert(id) {
            return true;
        }
        for dependency in &tasks[id].depends_on {
            if tasks.contains_key(dependency.as_str()) && visit(dependency, tasks, active, complete)
            {
                return true;
            }
        }
        active.remove(id);
        complete.insert(id);
        false
    }

    let mut active = BTreeSet::new();
    let mut complete = BTreeSet::new();
    for id in tasks.keys().copied() {
        if visit(id, tasks, &mut active, &mut complete) {
            return true;
        }
    }
    false
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
