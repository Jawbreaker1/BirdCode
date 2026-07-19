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

/// Returns the stable key of the latest bundled semantic task router.
///
/// # Panics
///
/// Panics only if the compile-time constant identifier or version is invalid.
#[must_use]
pub fn task_router_key() -> PromptKey {
    PromptKey::new(
        PromptId::new(TASK_ROUTER_ID).expect("bundled prompt identifier must be valid"),
        Version::new(1, 1, 1),
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
    let subtask_limit =
        usize::try_from(invocation.limits.max_suggested_subtasks).map_err(|_| {
            PromptError::OutputInvariant(
                "subtask limit cannot be represented on this platform".into(),
            )
        })?;
    if output.suggested_subtasks.len() > subtask_limit {
        return Err(PromptError::OutputInvariant(format!(
            "suggested_subtasks exceeds invocation limit {}",
            invocation.limits.max_suggested_subtasks
        )));
    }
    validate_route_axes(&output)?;
    let sections = invocation
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect::<BTreeSet<_>>();
    for evidence in &output.evidence {
        if evidence.section.trim().is_empty() || evidence.basis.trim().is_empty() {
            return Err(PromptError::OutputInvariant(
                "evidence fields must contain non-whitespace text".to_owned(),
            ));
        }
        if !sections.contains(evidence.section.as_str()) {
            return Err(PromptError::OutputInvariant(format!(
                "evidence references unknown input section {}",
                evidence.section
            )));
        }
    }
    if prompt_version >= &Version::new(1, 1, 1) {
        validate_minimal_evidence(&output, invocation)?;
    }
    if output
        .clarification_questions
        .iter()
        .any(|question| question.trim().is_empty())
    {
        return Err(PromptError::OutputInvariant(
            "clarification questions must contain non-whitespace text".to_owned(),
        ));
    }

    let mut tasks = BTreeMap::new();
    for task in &output.suggested_subtasks {
        if task.required_access > output.required_access {
            return Err(PromptError::OutputInvariant(format!(
                "subtask {} requires broader access than its parent route",
                task.id
            )));
        }
        if task.id.trim().is_empty()
            || task.objective.trim().is_empty()
            || task
                .acceptance_criteria
                .iter()
                .any(|criterion| criterion.trim().is_empty())
            || task
                .depends_on
                .iter()
                .any(|dependency| dependency.trim().is_empty())
        {
            return Err(PromptError::OutputInvariant(format!(
                "subtask {} contains a blank field",
                task.id
            )));
        }
        if tasks.insert(task.id.as_str(), task).is_some() {
            return Err(PromptError::OutputInvariant(format!(
                "subtask id {} is duplicated",
                task.id
            )));
        }
    }
    for task in &output.suggested_subtasks {
        for dependency in &task.depends_on {
            if dependency == &task.id {
                return Err(PromptError::OutputInvariant(format!(
                    "subtask {} depends on itself",
                    task.id
                )));
            }
            if !tasks.contains_key(dependency.as_str()) {
                return Err(PromptError::OutputInvariant(format!(
                    "subtask {} references unknown dependency {dependency}",
                    task.id
                )));
            }
        }
    }
    ensure_acyclic(&tasks)
}

fn validate_minimal_evidence(
    output: &TaskRouterOutput,
    invocation: &PromptInvocation,
) -> Result<(), PromptError> {
    let mut citation_counts = BTreeMap::<&str, usize>::new();
    for evidence in &output.evidence {
        let count = citation_counts
            .entry(evidence.section.as_str())
            .or_default();
        *count += 1;
        if *count > 1 {
            return Err(PromptError::OutputInvariant(format!(
                "evidence section {} is cited more than once",
                evidence.section
            )));
        }
    }

    let mut user_sections = invocation
        .sections
        .iter()
        .filter(|section| section.trust == TrustLevel::User);
    let user_section = user_sections.next().ok_or_else(|| {
        PromptError::OutputInvariant(
            "router invocation must contain exactly one user-trusted section".to_owned(),
        )
    })?;
    if user_sections.next().is_some() {
        return Err(PromptError::OutputInvariant(
            "router invocation must contain exactly one user-trusted section".to_owned(),
        ));
    }
    if citation_counts.get(user_section.name.as_str()).copied() != Some(1) {
        return Err(PromptError::OutputInvariant(format!(
            "the user-trusted section {} must be cited exactly once",
            user_section.name
        )));
    }
    Ok(())
}

fn validate_route_axes(output: &TaskRouterOutput) -> Result<(), PromptError> {
    let expected_access = match output.action {
        RouteAction::Clarify | RouteAction::Answer => RequiredAccess::None,
        RouteAction::Inspect => RequiredAccess::ReadOnly,
        RouteAction::Change => RequiredAccess::WorkspaceWrite,
    };
    if output.required_access != expected_access {
        return Err(PromptError::OutputInvariant(format!(
            "required_access must be {expected_access:?} for action {:?}",
            output.action
        )));
    }
    if output.strategy == RouteStrategy::Delegate
        && !matches!(output.action, RouteAction::Inspect | RouteAction::Change)
    {
        return Err(PromptError::OutputInvariant(
            "delegate strategy is allowed only for inspect or change".to_owned(),
        ));
    }
    if output.clarification_questions.is_empty() == (output.action == RouteAction::Clarify) {
        return Err(PromptError::OutputInvariant(
            "clarification_questions must be non-empty exactly when action is clarify".to_owned(),
        ));
    }
    if output.suggested_subtasks.is_empty() == (output.strategy == RouteStrategy::Delegate) {
        return Err(PromptError::OutputInvariant(
            "suggested_subtasks must be non-empty exactly when strategy is delegate".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_acyclic(tasks: &BTreeMap<&str, &SuggestedSubtask>) -> Result<(), PromptError> {
    fn visit<'a>(
        id: &'a str,
        tasks: &BTreeMap<&'a str, &'a SuggestedSubtask>,
        active: &mut BTreeSet<&'a str>,
        complete: &mut BTreeSet<&'a str>,
    ) -> Result<(), PromptError> {
        if complete.contains(id) {
            return Ok(());
        }
        if !active.insert(id) {
            return Err(PromptError::OutputInvariant(format!(
                "subtask dependency graph contains a cycle at {id}"
            )));
        }
        for dependency in &tasks[id].depends_on {
            visit(dependency, tasks, active, complete)?;
        }
        active.remove(id);
        complete.insert(id);
        Ok(())
    }

    let mut active = BTreeSet::new();
    let mut complete = BTreeSet::new();
    for id in tasks.keys().copied() {
        visit(id, tasks, &mut active, &mut complete)?;
    }
    Ok(())
}
