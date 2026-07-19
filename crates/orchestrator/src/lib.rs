//! Provider-neutral orchestration primitives for `BirdCode` agent decisions.
//!
//! The first production slice is a semantic task-router executor with one
//! narrowly typed repair opportunity. It never repairs semantic route fields:
//! only duplicate evidence bases may be consolidated, at most once.

mod actor_graph;
pub mod planner;

pub use actor_graph::{
    ActorGraph, ActorGraphExecutionError, ActorGraphExecutor, ActorGraphLimits, ActorGraphOutcome,
    ActorGraphPolicy, ActorGraphRun, ActorGraphValidationError, ActorGraphViolation,
    ActorId as GraphActorId, AgentAssignment, AgentBudget, AgentCleanupFuture, AgentCompletion,
    AgentDispatch, AgentFailure, AgentFailureKind, AgentFailureViolation, AgentFuture, AgentWorker,
    AttemptId as AgentAttemptId, AttemptObservation, CandidateGroupId, CapabilityId,
    CleanupReceipt, DispatchAttestation, ExecutionId, Handoff, HandoffId, HandoffOutcome,
    HandoffViolation, InMemorySchedulerJournal, ModelLineage, ModelProfileId, PermissionGrant,
    RoleId, SchedulerEvent, SchedulerEventId, SchedulerJournal, SchedulerJournalError,
    SchedulerRecord, TimedOutAttempt, Usage, ValidatedActorGraph, WorkOrder, WorkOrderFailure,
    WorkOrderId, WorkspaceAccess, WorkspaceGrant, WorkspaceLeaseId, WorkspaceLeasePolicy,
};

use birdcode_backends::{
    BackendError, ContractError, Message, MessageRole as BackendMessageRole, ModelBackend, ModelId,
    ReasoningSetting, StructuredInferenceRequest, StructuredInferenceResponse,
    StructuredOutputSpec,
};
use birdcode_prompting::{
    CompiledMessage, CompiledPrompt, DataProvenance, DataSection, ManifestProvenance,
    MessageContent, MessageRole, PromptError, PromptInvocation, PromptKey, PromptLimits,
    PromptRegistry, RouteEvidence, RouterInvariantViolation, SourceKind, TaskRouterOutput,
    TrustLevel, builtin_registry, parse_manifest, task_router_key,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// Immutable evidence-repair prompt embedded from repository data.
pub const ROUTER_REPAIR_MANIFEST_JSON: &str =
    include_str!("../../../prompts/semantic-task-router-repair/1.0.0/manifest.json");

const DEFAULT_REPAIR_MAX_OUTPUT_TOKENS: u32 = 768;
const REPAIR_INPUT_SECTION: &str = "duplicate_evidence_groups";
const SEMANTIC_TASK_ROUTER_ID: &str = "birdcode.semantic-task-router";

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a globally unique UUID v7 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an explicit UUID for durable replay or resume.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the wrapped UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(RouterExecutionId);
uuid_id!(RouterAttemptId);

/// Configuration for one semantic router execution.
#[derive(Clone, Debug)]
pub struct RouterExecutionRequest {
    pub execution_id: RouterExecutionId,
    pub router_key: PromptKey,
    pub model_id: ModelId,
    pub invocation: PromptInvocation,
    pub max_output_tokens: u32,
    pub repair_max_output_tokens: u32,
    pub reasoning: Option<ReasoningSetting>,
}

impl RouterExecutionRequest {
    /// Uses the latest bundled router and a bounded default repair budget.
    #[must_use]
    pub fn new(model_id: ModelId, invocation: PromptInvocation, max_output_tokens: u32) -> Self {
        Self {
            execution_id: RouterExecutionId::new(),
            router_key: task_router_key(),
            model_id,
            invocation,
            max_output_tokens,
            repair_max_output_tokens: DEFAULT_REPAIR_MAX_OUTPUT_TOKENS,
            reasoning: None,
        }
    }

    /// Uses an existing durable execution identity for reproduction or resume.
    #[must_use]
    pub const fn with_execution_id(mut self, execution_id: RouterExecutionId) -> Self {
        self.execution_id = execution_id;
        self
    }

    /// Applies the same provider reasoning setting to the initial and repair calls.
    #[must_use]
    pub const fn with_reasoning(mut self, reasoning: ReasoningSetting) -> Self {
        self.reasoning = Some(reasoning);
        self
    }

    /// Overrides the repair call's independent output-token ceiling.
    #[must_use]
    pub const fn with_repair_max_output_tokens(mut self, maximum: u32) -> Self {
        self.repair_max_output_tokens = maximum;
        self
    }
}

/// Which bounded inference attempt is being retained.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAttemptPhase {
    Initial,
    EvidenceRepair,
}

/// Complete backend result retained for one inference attempt.
///
/// A successful response contains the backend's exact assistant `raw_text` and
/// parsed provider envelope evidence. The current backend contract does not
/// claim to retain wire-exact successful response bytes.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RetainedInferenceAttempt {
    Response {
        response: Box<StructuredInferenceResponse>,
    },
    Error {
        error: BackendError,
    },
}

/// Causal request provenance and backend outcome for one bounded attempt.
///
/// `compiled_prompt` can contain sensitive user and repository data. Journal
/// implementations must protect it accordingly. Every record carries globally
/// unique execution and attempt identities. Repair records causally bind to the
/// exact initial attempt and assistant text.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RetainedInferenceRecord {
    pub execution_id: RouterExecutionId,
    pub attempt_id: RouterAttemptId,
    pub parent_attempt_id: Option<RouterAttemptId>,
    pub phase: RouterAttemptPhase,
    pub compiled_prompt: CompiledPrompt,
    pub requested_model_id: ModelId,
    pub reasoning: Option<ReasoningSetting>,
    pub max_output_tokens: u32,
    pub parent_candidate_raw_text_sha256: Option<String>,
    pub attempt: RetainedInferenceAttempt,
}

/// Failure returned by an attempt journal.
#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("{message}")]
pub struct AttemptJournalError {
    pub message: String,
}

impl AttemptJournalError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Persistence boundary invoked before validation can trigger another call or acceptance.
///
/// Implementations choose the durability level. A failed acknowledgement makes
/// the executor fail closed.
pub trait AttemptJournal: Send + Sync {
    /// Retains one complete attempt before orchestration proceeds.
    ///
    /// # Errors
    ///
    /// Returns an error when the record was not accepted according to the
    /// implementation's declared retention contract.
    fn retain(&self, record: &RetainedInferenceRecord) -> Result<(), AttemptJournalError>;
}

/// Explicitly in-memory journal for tests and callers that do not yet supply durable storage.
#[derive(Debug, Default)]
pub struct InMemoryAttemptJournal {
    records: Mutex<Vec<RetainedInferenceRecord>>,
}

impl InMemoryAttemptJournal {
    /// Returns a cloned snapshot of retained attempts.
    ///
    /// # Errors
    ///
    /// Returns an error if another thread poisoned the in-memory lock.
    pub fn snapshot(&self) -> Result<Vec<RetainedInferenceRecord>, AttemptJournalError> {
        self.records
            .lock()
            .map(|records| records.clone())
            .map_err(|_| AttemptJournalError::new("in-memory attempt journal lock was poisoned"))
    }
}

impl AttemptJournal for InMemoryAttemptJournal {
    fn retain(&self, record: &RetainedInferenceRecord) -> Result<(), AttemptJournalError> {
        self.records
            .lock()
            .map_err(|_| AttemptJournalError::new("in-memory attempt journal lock was poisoned"))?
            .push(record.clone());
        Ok(())
    }
}

/// A locally validated semantic route, with first-pass and repaired outcomes distinct.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RouterExecutionStatus {
    AcceptedFirstPass { output: TaskRouterOutput },
    AcceptedAfterEvidenceRepair { output: TaskRouterOutput },
    Rejected { failure: RouterExecutionFailure },
}

/// Typed reason why an execution failed closed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterExecutionFailure {
    InitialBackend,
    InitialResponseContract {
        violations: Vec<InferenceResponseContractViolation>,
    },
    InitialOutputContract {
        message: String,
    },
    NonRepairableInvariants {
        violations: Vec<RouterInvariantViolation>,
    },
    RepairPreparation {
        message: String,
    },
    RepairBackend,
    RepairResponseContract {
        violations: Vec<InferenceResponseContractViolation>,
    },
    RepairOutputContract {
        message: String,
    },
    InvalidRepairPatch {
        violations: Vec<EvidenceRepairPatchViolation>,
    },
    RepairedOutputContract {
        message: String,
    },
    Journal {
        phase: RouterAttemptPhase,
        message: String,
    },
}

/// Machine-readable inconsistency in a nominally successful backend response.
///
/// Exact identifiers and assistant content remain available in the retained
/// attempt. They are deliberately not duplicated into violations or error
/// messages, which keeps this contract useful without widening disclosure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InferenceResponseContractViolation {
    ModelIdentityMismatch,
    BackendIdentityMismatch,
    RawTextIsNotJson,
    RawTextValueMismatch,
    OutputTokenLimitExceeded { maximum: u64, actual: u64 },
}

/// Machine-readable defect in a model-produced evidence patch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceRepairPatchViolation {
    ReplacementCount {
        expected: u32,
        actual: u32,
    },
    BlankBasis {
        index: u32,
        section: String,
    },
    UnexpectedSection {
        index: u32,
        section: String,
    },
    WrongSectionOrder {
        index: u32,
        expected: String,
        actual: String,
    },
    MissingSection {
        section: String,
    },
    DuplicateSection {
        section: String,
        occurrences: u32,
    },
}

/// Complete in-memory execution record returned to the caller.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RouterExecution {
    pub router_manifest: ManifestProvenance,
    pub repair_manifest: Option<ManifestProvenance>,
    pub initial: RetainedInferenceRecord,
    pub repair: Option<RetainedInferenceRecord>,
    pub status: RouterExecutionStatus,
}

/// Errors that prevent a safe initial inference request from being constructed.
#[derive(Debug, Error)]
pub enum RouterSetupError {
    #[error("prompt {0} is not a semantic task-router prompt")]
    UnsupportedRouterPrompt(PromptKey),
    #[error("prompt {0} is not an exact bundled semantic task-router manifest")]
    UnbundledRouterManifest(PromptKey),
    #[error(transparent)]
    Prompt(#[from] PromptError),
    #[error(transparent)]
    BackendContract(#[from] ContractError),
    #[error("compiled prompt message could not be encoded: {0}")]
    MessageEncoding(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRepairPatch {
    replacements: Vec<RouteEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DuplicateEvidenceGroup {
    section: String,
    bases: Vec<String>,
}

/// Executes a semantic router through a provider-neutral backend.
pub struct RouterExecutor<'a, B: ModelBackend + ?Sized> {
    backend: &'a B,
    router_registry: &'a PromptRegistry,
    bundled_router_registry: PromptRegistry,
    journal: &'a dyn AttemptJournal,
    repair_registry: PromptRegistry,
    repair_key: PromptKey,
}

impl<'a, B: ModelBackend + ?Sized> RouterExecutor<'a, B> {
    /// Parses the immutable repair manifest and creates an executor.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundled repair manifest is invalid.
    pub fn new(
        backend: &'a B,
        router_registry: &'a PromptRegistry,
        journal: &'a dyn AttemptJournal,
    ) -> Result<Self, RouterSetupError> {
        let manifest = parse_manifest(ROUTER_REPAIR_MANIFEST_JSON.as_bytes())?;
        let repair_key = manifest.key();
        let repair_registry = PromptRegistry::new([manifest])?;
        let bundled_router_registry = builtin_registry()?;
        Ok(Self {
            backend,
            router_registry,
            bundled_router_registry,
            journal,
            repair_registry,
            repair_key,
        })
    }

    /// Runs at most one initial call and one evidence-only repair call.
    ///
    /// # Errors
    ///
    /// Returns a setup error only when the initial prompt or backend request
    /// cannot be constructed. Once inference begins, every outcome is retained
    /// in [`RouterExecution`] and failures are represented as rejected status.
    #[allow(
        clippy::too_many_lines,
        reason = "every retained first-call failure stage stays explicit and fail-closed"
    )]
    pub async fn execute(
        &self,
        request: RouterExecutionRequest,
    ) -> Result<RouterExecution, RouterSetupError> {
        if request.router_key.id.as_str() != SEMANTIC_TASK_ROUTER_ID {
            return Err(RouterSetupError::UnsupportedRouterPrompt(
                request.router_key,
            ));
        }
        let selected_manifest = self
            .router_registry
            .get(&request.router_key)
            .ok_or_else(|| PromptError::PromptNotFound(request.router_key.clone()))?;
        let Some(bundled_manifest) = self.bundled_router_registry.get(&request.router_key) else {
            return Err(RouterSetupError::UnbundledRouterManifest(
                request.router_key,
            ));
        };
        let bundled_provenance = ManifestProvenance {
            prompt: request.router_key.clone(),
            content_sha256: bundled_manifest.content_sha256()?,
        };
        if selected_manifest != bundled_manifest
            || selected_manifest.content_sha256()? != bundled_provenance.content_sha256
        {
            return Err(RouterSetupError::UnbundledRouterManifest(
                request.router_key,
            ));
        }
        let compiled = self
            .router_registry
            .compile(&request.router_key, &request.invocation)?;
        if compiled.manifest != bundled_provenance {
            return Err(RouterSetupError::UnbundledRouterManifest(
                request.router_key,
            ));
        }
        let backend_request = structured_request(
            request.model_id.clone(),
            &compiled,
            request.max_output_tokens,
            request.reasoning,
            "task_router_output",
        )?;
        let router_manifest = compiled.manifest.clone();
        let initial = RetainedInferenceRecord {
            execution_id: request.execution_id,
            attempt_id: RouterAttemptId::new(),
            parent_attempt_id: None,
            phase: RouterAttemptPhase::Initial,
            compiled_prompt: compiled.clone(),
            requested_model_id: request.model_id.clone(),
            reasoning: request.reasoning,
            max_output_tokens: request.max_output_tokens,
            parent_candidate_raw_text_sha256: None,
            attempt: retained_attempt(self.backend.infer_structured(backend_request).await),
        };
        if let Err(error) = self.journal.retain(&initial) {
            return Ok(execution(
                router_manifest,
                None,
                initial,
                None,
                RouterExecutionFailure::Journal {
                    phase: RouterAttemptPhase::Initial,
                    message: error.message,
                },
            ));
        }
        let RetainedInferenceAttempt::Response {
            response: initial_response,
        } = &initial.attempt
        else {
            return Ok(execution(
                router_manifest,
                None,
                initial,
                None,
                RouterExecutionFailure::InitialBackend,
            ));
        };
        let response_violations = inference_response_contract_violations(
            initial_response,
            &request.model_id,
            self.backend.backend_id(),
            request.max_output_tokens,
        );
        if !response_violations.is_empty() {
            return Ok(execution(
                router_manifest,
                None,
                initial,
                None,
                RouterExecutionFailure::InitialResponseContract {
                    violations: response_violations,
                },
            ));
        }

        match self.router_registry.validate_output(
            &compiled,
            &request.invocation,
            &initial_response.value,
        ) {
            Ok(()) => {
                let output = match serde_json::from_value::<TaskRouterOutput>(
                    initial_response.value.clone(),
                ) {
                    Ok(output) => output,
                    Err(error) => {
                        return Ok(execution(
                            router_manifest,
                            None,
                            initial,
                            None,
                            RouterExecutionFailure::InitialOutputContract {
                                message: error.to_string(),
                            },
                        ));
                    }
                };
                Ok(RouterExecution {
                    router_manifest,
                    repair_manifest: None,
                    initial,
                    repair: None,
                    status: RouterExecutionStatus::AcceptedFirstPass { output },
                })
            }
            Err(PromptError::OutputInvariant(violations))
                if repairable_duplicate_violations(&violations) =>
            {
                Ok(self
                    .repair_duplicate_evidence(
                        request,
                        compiled,
                        router_manifest,
                        initial,
                        violations,
                    )
                    .await)
            }
            Err(PromptError::OutputInvariant(violations)) => Ok(execution(
                router_manifest,
                None,
                initial,
                None,
                RouterExecutionFailure::NonRepairableInvariants { violations },
            )),
            Err(error) => Ok(execution(
                router_manifest,
                None,
                initial,
                None,
                RouterExecutionFailure::InitialOutputContract {
                    message: error.to_string(),
                },
            )),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the single bounded repair path retains each failure before proceeding"
    )]
    async fn repair_duplicate_evidence(
        &self,
        request: RouterExecutionRequest,
        compiled: CompiledPrompt,
        router_manifest: ManifestProvenance,
        initial: RetainedInferenceRecord,
        violations: Vec<RouterInvariantViolation>,
    ) -> RouterExecution {
        let initial_response = match &initial.attempt {
            RetainedInferenceAttempt::Response { response } => response,
            RetainedInferenceAttempt::Error { .. } => unreachable!("repair follows a response"),
        };
        let candidate =
            match serde_json::from_value::<TaskRouterOutput>(initial_response.value.clone()) {
                Ok(candidate) => candidate,
                Err(error) => {
                    return execution(
                        router_manifest,
                        None,
                        initial,
                        None,
                        RouterExecutionFailure::RepairPreparation {
                            message: error.to_string(),
                        },
                    );
                }
            };
        let duplicate_sections =
            duplicate_sections_in_first_occurrence_order(&candidate, &violations);
        let parent_candidate_raw_text_sha256 = sha256_hex(initial_response.raw_text.as_bytes());
        let repair_invocation = repair_invocation(
            &candidate,
            &duplicate_sections,
            &format!("router-candidate-raw-text-sha256:{parent_candidate_raw_text_sha256}"),
        );
        let repair_compiled = match self
            .repair_registry
            .compile(&self.repair_key, &repair_invocation)
        {
            Ok(value) => value,
            Err(error) => {
                return execution(
                    router_manifest,
                    None,
                    initial,
                    None,
                    RouterExecutionFailure::RepairPreparation {
                        message: error.to_string(),
                    },
                );
            }
        };
        let repair_manifest = repair_compiled.manifest.clone();
        let repair_request = match structured_request(
            request.model_id.clone(),
            &repair_compiled,
            request.repair_max_output_tokens,
            request.reasoning,
            "task_router_evidence_repair",
        ) {
            Ok(value) => value,
            Err(error) => {
                return execution(
                    router_manifest,
                    Some(repair_manifest),
                    initial,
                    None,
                    RouterExecutionFailure::RepairPreparation {
                        message: error.to_string(),
                    },
                );
            }
        };
        let repair = RetainedInferenceRecord {
            execution_id: request.execution_id,
            attempt_id: RouterAttemptId::new(),
            parent_attempt_id: Some(initial.attempt_id),
            phase: RouterAttemptPhase::EvidenceRepair,
            compiled_prompt: repair_compiled.clone(),
            requested_model_id: request.model_id,
            reasoning: request.reasoning,
            max_output_tokens: request.repair_max_output_tokens,
            parent_candidate_raw_text_sha256: Some(parent_candidate_raw_text_sha256),
            attempt: retained_attempt(self.backend.infer_structured(repair_request).await),
        };
        if let Err(error) = self.journal.retain(&repair) {
            return execution(
                router_manifest,
                Some(repair_manifest),
                initial,
                Some(repair),
                RouterExecutionFailure::Journal {
                    phase: RouterAttemptPhase::EvidenceRepair,
                    message: error.message,
                },
            );
        }
        let RetainedInferenceAttempt::Response {
            response: repair_response,
        } = &repair.attempt
        else {
            return execution(
                router_manifest,
                Some(repair_manifest),
                initial,
                Some(repair),
                RouterExecutionFailure::RepairBackend,
            );
        };
        let response_violations = inference_response_contract_violations(
            repair_response,
            &repair.requested_model_id,
            self.backend.backend_id(),
            repair.max_output_tokens,
        );
        if !response_violations.is_empty() {
            return execution(
                router_manifest,
                Some(repair_manifest),
                initial,
                Some(repair),
                RouterExecutionFailure::RepairResponseContract {
                    violations: response_violations,
                },
            );
        }
        if let Err(error) = self.repair_registry.validate_output(
            &repair_compiled,
            &repair_invocation,
            &repair_response.value,
        ) {
            return execution(
                router_manifest,
                Some(repair_manifest),
                initial,
                Some(repair),
                RouterExecutionFailure::RepairOutputContract {
                    message: error.to_string(),
                },
            );
        }
        let patch =
            match serde_json::from_value::<EvidenceRepairPatch>(repair_response.value.clone()) {
                Ok(value) => value,
                Err(error) => {
                    return execution(
                        router_manifest,
                        Some(repair_manifest),
                        initial,
                        Some(repair),
                        RouterExecutionFailure::RepairOutputContract {
                            message: error.to_string(),
                        },
                    );
                }
            };
        let patch_violations = validate_patch(&patch, &duplicate_sections);
        if !patch_violations.is_empty() {
            return execution(
                router_manifest,
                Some(repair_manifest),
                initial,
                Some(repair),
                RouterExecutionFailure::InvalidRepairPatch {
                    violations: patch_violations,
                },
            );
        }
        let repaired_output = apply_patch(candidate, patch, &duplicate_sections);
        let repaired_value = match serde_json::to_value(&repaired_output) {
            Ok(value) => value,
            Err(error) => {
                return execution(
                    router_manifest,
                    Some(repair_manifest),
                    initial,
                    Some(repair),
                    RouterExecutionFailure::RepairedOutputContract {
                        message: error.to_string(),
                    },
                );
            }
        };
        if let Err(error) =
            self.router_registry
                .validate_output(&compiled, &request.invocation, &repaired_value)
        {
            return execution(
                router_manifest,
                Some(repair_manifest),
                initial,
                Some(repair),
                RouterExecutionFailure::RepairedOutputContract {
                    message: error.to_string(),
                },
            );
        }
        RouterExecution {
            router_manifest,
            repair_manifest: Some(repair_manifest),
            initial,
            repair: Some(repair),
            status: RouterExecutionStatus::AcceptedAfterEvidenceRepair {
                output: repaired_output,
            },
        }
    }
}

fn retained_attempt(
    result: Result<StructuredInferenceResponse, BackendError>,
) -> RetainedInferenceAttempt {
    match result {
        Ok(response) => RetainedInferenceAttempt::Response {
            response: Box::new(response),
        },
        Err(error) => RetainedInferenceAttempt::Error { error },
    }
}

fn inference_response_contract_violations(
    response: &StructuredInferenceResponse,
    requested_model_id: &ModelId,
    expected_backend_id: &birdcode_backends::BackendId,
    max_output_tokens: u32,
) -> Vec<InferenceResponseContractViolation> {
    let mut violations = Vec::new();
    if &response.model_id != requested_model_id {
        violations.push(InferenceResponseContractViolation::ModelIdentityMismatch);
    }
    if &response.evidence.backend_id != expected_backend_id {
        violations.push(InferenceResponseContractViolation::BackendIdentityMismatch);
    }
    match serde_json::from_str::<serde_json::Value>(&response.raw_text) {
        Ok(decoded) if decoded != response.value => {
            violations.push(InferenceResponseContractViolation::RawTextValueMismatch);
        }
        Err(_) => violations.push(InferenceResponseContractViolation::RawTextIsNotJson),
        Ok(_) => {}
    }
    if let Some(actual) = response
        .usage
        .as_ref()
        .and_then(|usage| usage.output_tokens)
    {
        let maximum = u64::from(max_output_tokens);
        if actual > maximum {
            violations.push(
                InferenceResponseContractViolation::OutputTokenLimitExceeded { maximum, actual },
            );
        }
    }
    violations
}

fn structured_request(
    model_id: ModelId,
    compiled: &CompiledPrompt,
    max_output_tokens: u32,
    reasoning: Option<ReasoningSetting>,
    schema_name: &str,
) -> Result<StructuredInferenceRequest, RouterSetupError> {
    let messages = compiled
        .messages
        .iter()
        .map(backend_message)
        .collect::<Result<Vec<_>, _>>()?;
    let output = StructuredOutputSpec::new_with_generation_schema(
        schema_name,
        compiled.output_schema.clone(),
        compiled.generation_schema.clone(),
    )?;
    let mut request =
        StructuredInferenceRequest::new(model_id, messages, output, max_output_tokens)?;
    if let Some(reasoning) = reasoning {
        request = request.with_reasoning(reasoning);
    }
    Ok(request)
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

fn repairable_duplicate_violations(violations: &[RouterInvariantViolation]) -> bool {
    !violations.is_empty()
        && violations.iter().all(|violation| {
            matches!(
                violation,
                RouterInvariantViolation::DuplicateEvidenceSection { .. }
            )
        })
}

fn duplicate_sections_in_first_occurrence_order(
    candidate: &TaskRouterOutput,
    violations: &[RouterInvariantViolation],
) -> Vec<String> {
    let duplicate_names = violations
        .iter()
        .filter_map(|violation| match violation {
            RouterInvariantViolation::DuplicateEvidenceSection { section, .. } => {
                Some(section.as_str())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    candidate
        .evidence
        .iter()
        .filter(|evidence| duplicate_names.contains(evidence.section.as_str()))
        .filter(|evidence| seen.insert(evidence.section.as_str()))
        .map(|evidence| evidence.section.clone())
        .collect()
}

fn repair_invocation(
    candidate: &TaskRouterOutput,
    duplicate_sections: &[String],
    source_id: &str,
) -> PromptInvocation {
    let groups = duplicate_sections
        .iter()
        .map(|section| DuplicateEvidenceGroup {
            section: section.clone(),
            bases: candidate
                .evidence
                .iter()
                .filter(|evidence| &evidence.section == section)
                .map(|evidence| evidence.basis.clone())
                .collect(),
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({ "duplicate_groups": groups });
    PromptInvocation::with_limits(
        vec![DataSection {
            name: REPAIR_INPUT_SECTION.to_owned(),
            trust: TrustLevel::UntrustedExternal,
            provenance: DataProvenance {
                source_kind: SourceKind::External,
                source_id: source_id.to_owned(),
                artifact_sha256: None,
                event_id: None,
            },
            payload,
        }],
        PromptLimits::new(0),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn validate_patch(
    patch: &EvidenceRepairPatch,
    expected_sections: &[String],
) -> Vec<EvidenceRepairPatchViolation> {
    let mut violations = Vec::new();
    if patch.replacements.len() != expected_sections.len() {
        violations.push(EvidenceRepairPatchViolation::ReplacementCount {
            expected: wire_u32(expected_sections.len()),
            actual: wire_u32(patch.replacements.len()),
        });
    }
    let expected_set = expected_sections
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut counts = BTreeMap::<&str, usize>::new();
    for (index, replacement) in patch.replacements.iter().enumerate() {
        *counts.entry(replacement.section.as_str()).or_default() += 1;
        if replacement.basis.trim().is_empty() {
            violations.push(EvidenceRepairPatchViolation::BlankBasis {
                index: wire_u32(index),
                section: replacement.section.clone(),
            });
        }
        if !expected_set.contains(replacement.section.as_str()) {
            violations.push(EvidenceRepairPatchViolation::UnexpectedSection {
                index: wire_u32(index),
                section: replacement.section.clone(),
            });
        } else if expected_sections.get(index) != Some(&replacement.section) {
            violations.push(EvidenceRepairPatchViolation::WrongSectionOrder {
                index: wire_u32(index),
                expected: expected_sections.get(index).cloned().unwrap_or_default(),
                actual: replacement.section.clone(),
            });
        }
    }
    for section in expected_sections {
        if !counts.contains_key(section.as_str()) {
            violations.push(EvidenceRepairPatchViolation::MissingSection {
                section: section.clone(),
            });
        }
    }
    for (section, occurrences) in counts {
        if occurrences > 1 {
            violations.push(EvidenceRepairPatchViolation::DuplicateSection {
                section: section.to_owned(),
                occurrences: wire_u32(occurrences),
            });
        }
    }
    violations
}

fn apply_patch(
    mut candidate: TaskRouterOutput,
    patch: EvidenceRepairPatch,
    duplicate_sections: &[String],
) -> TaskRouterOutput {
    let replacements = patch
        .replacements
        .into_iter()
        .map(|replacement| (replacement.section.clone(), replacement))
        .collect::<BTreeMap<_, _>>();
    let duplicates = duplicate_sections.iter().collect::<BTreeSet<_>>();
    let mut emitted = BTreeSet::new();
    candidate.evidence = candidate
        .evidence
        .into_iter()
        .filter_map(|evidence| {
            if !duplicates.contains(&evidence.section) {
                return Some(evidence);
            }
            emitted
                .insert(evidence.section.clone())
                .then(|| replacements[&evidence.section].clone())
        })
        .collect();
    candidate
}

fn execution(
    router_manifest: ManifestProvenance,
    repair_manifest: Option<ManifestProvenance>,
    initial: RetainedInferenceRecord,
    repair: Option<RetainedInferenceRecord>,
    failure: RouterExecutionFailure,
) -> RouterExecution {
    RouterExecution {
        router_manifest,
        repair_manifest,
        initial,
        repair,
        status: RouterExecutionStatus::Rejected { failure },
    }
}

fn wire_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
