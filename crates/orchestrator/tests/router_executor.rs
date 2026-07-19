use birdcode_backends::{
    BackendError, BackendErrorKind, BackendFuture, BackendId, BackendOperation, InferenceEvidence,
    MessageRole as BackendMessageRole, ModelBackend, ModelCatalog, ModelId,
    StructuredInferenceRequest, StructuredInferenceResponse,
};
use birdcode_orchestrator::{
    AttemptJournal, AttemptJournalError, EvidenceRepairPatchViolation, InMemoryAttemptJournal,
    ROUTER_REPAIR_MANIFEST_JSON, RetainedInferenceAttempt, RouterAttemptPhase,
    RouterExecutionFailure, RouterExecutionRequest, RouterExecutionStatus, RouterExecutor,
    RouterSetupError,
};
use birdcode_prompting::{
    DataProvenance, DataSection, MessageContent, MessageRole, PromptInvocation,
    RouterInvariantViolation, SourceKind, TaskRouterOutput, TrustLevel, builtin_registry,
    parse_manifest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FakeBackend {
    id: BackendId,
    replies: Mutex<VecDeque<Result<StructuredInferenceResponse, BackendError>>>,
    requests: Mutex<Vec<StructuredInferenceRequest>>,
    calls: AtomicUsize,
}

impl FakeBackend {
    fn new(replies: Vec<Result<StructuredInferenceResponse, BackendError>>) -> Self {
        Self {
            id: backend_id(),
            replies: Mutex::new(replies.into()),
            requests: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<StructuredInferenceRequest> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl ModelBackend for FakeBackend {
    fn backend_id(&self) -> &BackendId {
        &self.id
    }

    fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
        Box::pin(async { panic!("router executor must not perform model discovery") })
    }

    fn infer_structured(
        &self,
        request: StructuredInferenceRequest,
    ) -> BackendFuture<'_, StructuredInferenceResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().expect("request lock").push(request);
        Box::pin(async {
            self.replies
                .lock()
                .expect("reply lock")
                .pop_front()
                .expect("the executor made more than two configured inference calls")
        })
    }
}

fn backend_id() -> BackendId {
    BackendId::new("fake").expect("valid backend id")
}

fn model_id() -> ModelId {
    ModelId::new("fake/router-model").expect("valid model id")
}

fn response(value: Value) -> StructuredInferenceResponse {
    StructuredInferenceResponse {
        model_id: model_id(),
        raw_text: serde_json::to_string(&value).expect("response serializes"),
        value,
        finish_reason: Some("stop".to_owned()),
        usage: None,
        evidence: InferenceEvidence {
            backend_id: backend_id(),
            endpoint: "fake://structured-inference".to_owned(),
            status: 200,
            completion_id: Some("completion-1".to_owned()),
            raw_response: json!({"provider_envelope": "retained"}),
        },
    }
}

fn backend_failure() -> BackendError {
    BackendError {
        backend_id: backend_id(),
        operation: BackendOperation::StructuredInference,
        kind: BackendErrorKind::Transport,
        message: "simulated repair transport failure".to_owned(),
        evidence: None,
    }
}

fn section(
    name: &str,
    trust: TrustLevel,
    source_kind: SourceKind,
    source_id: &str,
    payload: Value,
) -> DataSection {
    DataSection {
        name: name.to_owned(),
        trust,
        provenance: DataProvenance {
            source_kind,
            source_id: source_id.to_owned(),
            artifact_sha256: None,
            event_id: None,
        },
        payload,
    }
}

fn invocation() -> PromptInvocation {
    PromptInvocation::new(vec![
        section(
            "request",
            TrustLevel::User,
            SourceKind::User,
            "turn-sensitive-42",
            json!({"request": "Implement the private billing change."}),
        ),
        section(
            "repository",
            TrustLevel::Repository,
            SourceKind::Repository,
            "repo-sensitive-7",
            json!({"private_file": "src/billing.rs"}),
        ),
        section(
            "tool_observation",
            TrustLevel::Tool,
            SourceKind::Tool,
            "tool-sensitive-3",
            json!({"compiler": "clean"}),
        ),
    ])
}

fn valid_output() -> Value {
    json!({
        "action": "change",
        "strategy": "direct",
        "required_access": "workspace_write",
        "confidence": 0.91,
        "evidence": [
            {"section": "request", "basis": "The user requests an implementation."},
            {"section": "repository", "basis": "The repository identifies the target."},
            {"section": "tool_observation", "basis": "The current compiler state informs the change."}
        ],
        "clarification_questions": [],
        "suggested_subtasks": []
    })
}

fn duplicate_output() -> Value {
    json!({
        "action": "change",
        "strategy": "direct",
        "required_access": "workspace_write",
        "confidence": 0.91,
        "evidence": [
            {"section": "repository", "basis": "The target is in the billing module."},
            {"section": "request", "basis": "The user asks for implementation."},
            {"section": "repository", "basis": "The repository identifies the concrete file."},
            {"section": "tool_observation", "basis": "The compiler was clean before the change."},
            {"section": "request", "basis": "The requested outcome requires workspace writes."}
        ],
        "clarification_questions": [],
        "suggested_subtasks": []
    })
}

fn repair_patch() -> Value {
    json!({
        "replacements": [
            {"section": "repository", "basis": "The repository identifies the billing module and concrete target file."},
            {"section": "request", "basis": "The user requests an implementation whose outcome requires workspace writes."}
        ]
    })
}

fn request() -> RouterExecutionRequest {
    RouterExecutionRequest::new(model_id(), invocation(), 2_048)
}

#[tokio::test]
async fn first_pass_success_is_retained_without_repair() {
    let backend = FakeBackend::new(vec![Ok(response(valid_output()))]);
    let registry = builtin_registry().expect("registry");
    let journal = InMemoryAttemptJournal::default();
    let execution = RouterExecutor::new(&backend, &registry, &journal)
        .expect("executor")
        .execute(request())
        .await
        .expect("execution setup");

    assert!(matches!(
        execution.status,
        RouterExecutionStatus::AcceptedFirstPass { .. }
    ));
    assert!(execution.repair.is_none());
    assert_eq!(backend.call_count(), 1);
    let records = journal.snapshot().expect("journal snapshot");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].phase, RouterAttemptPhase::Initial);
    assert!(records[0].parent_candidate_raw_text_sha256.is_none());
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end test cross-checks semantic locking, provenance, redaction, and call bounds"
)]
async fn two_duplicate_groups_are_repaired_in_one_call_with_semantics_locked() {
    let initial_value = duplicate_output();
    let initial_typed: TaskRouterOutput =
        serde_json::from_value(initial_value.clone()).expect("typed initial output");
    let initial_raw_text = serde_json::to_string(&initial_value).expect("initial serializes");
    let backend = FakeBackend::new(vec![
        Ok(response(initial_value)),
        Ok(response(repair_patch())),
    ]);
    let registry = builtin_registry().expect("registry");
    let journal = InMemoryAttemptJournal::default();
    let execution = RouterExecutor::new(&backend, &registry, &journal)
        .expect("executor")
        .execute(request())
        .await
        .expect("execution setup");

    let output = match &execution.status {
        RouterExecutionStatus::AcceptedAfterEvidenceRepair { output } => output,
        other => panic!("unexpected status: {other:?}"),
    };
    assert_eq!(output.action, initial_typed.action);
    assert_eq!(output.strategy, initial_typed.strategy);
    assert_eq!(output.required_access, initial_typed.required_access);
    assert_eq!(
        output.confidence.to_bits(),
        initial_typed.confidence.to_bits()
    );
    assert_eq!(
        output.clarification_questions,
        initial_typed.clarification_questions
    );
    assert_eq!(output.suggested_subtasks, initial_typed.suggested_subtasks);
    assert_eq!(
        output
            .evidence
            .iter()
            .map(|item| item.section.as_str())
            .collect::<Vec<_>>(),
        vec!["repository", "request", "tool_observation"]
    );
    assert_eq!(
        output.evidence[2], initial_typed.evidence[3],
        "non-duplicate evidence must be preserved byte-for-struct"
    );
    assert_eq!(backend.call_count(), 2);

    let records = journal.snapshot().expect("journal snapshot");
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].phase, RouterAttemptPhase::EvidenceRepair);
    let expected_parent = format!("{:x}", Sha256::digest(initial_raw_text.as_bytes()));
    assert_eq!(
        records[1].parent_candidate_raw_text_sha256.as_deref(),
        Some(expected_parent.as_str())
    );
    assert_eq!(records[1].requested_model_id, model_id());
    assert_eq!(records[1].max_output_tokens, 768);

    let repair_compiled = &records[1].compiled_prompt;
    assert!(
        repair_compiled
            .messages
            .iter()
            .all(|message| matches!(message.role, MessageRole::System | MessageRole::User))
    );
    let repair_data = repair_compiled
        .messages
        .last()
        .expect("repair data message");
    assert_eq!(repair_data.role, MessageRole::User);
    assert_eq!(repair_data.trust, TrustLevel::UntrustedExternal);
    let MessageContent::Json(repair_json) = &repair_data.content else {
        panic!("repair data must be canonical JSON")
    };
    let repair_json = repair_json.value();
    assert_eq!(repair_json["trust"], "untrusted_external");
    assert_eq!(repair_json["provenance"]["source_kind"], "external");
    let source_id = repair_json["provenance"]["source_id"]
        .as_str()
        .expect("source id");
    assert_eq!(
        source_id,
        format!("router-candidate-raw-text-sha256:{expected_parent}")
    );
    let encoded_repair = repair_json.to_string();
    for forbidden in [
        "Implement the private billing change",
        "src/billing.rs",
        "turn-sensitive-42",
        "repo-sensitive-7",
        "tool-sensitive-3",
        "expected_action",
        "case_id",
        "eval",
    ] {
        assert!(!encoded_repair.contains(forbidden), "leaked {forbidden}");
    }

    let requests = backend.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].messages().iter().all(|message| matches!(
        message.role,
        BackendMessageRole::System | BackendMessageRole::User
    )));
    assert!(!requests[1].messages().iter().any(|message| matches!(
        message.role,
        BackendMessageRole::Assistant | BackendMessageRole::Developer
    )));
}

#[tokio::test]
async fn missing_extra_and_blank_patch_entries_all_fail_closed() {
    let invalid_patches = [
        json!({"replacements": [
            {"section": "repository", "basis": "Consolidated repository basis."}
        ]}),
        json!({"replacements": [
            {"section": "repository", "basis": "Consolidated repository basis."},
            {"section": "request", "basis": "Consolidated request basis."},
            {"section": "invented", "basis": "Unexpected basis."}
        ]}),
        json!({"replacements": [
            {"section": "repository", "basis": "   "},
            {"section": "request", "basis": "Consolidated request basis."}
        ]}),
        json!({"replacements": [
            {"section": "request", "basis": "Consolidated request basis."},
            {"section": "repository", "basis": "Consolidated repository basis."}
        ]}),
        json!({"replacements": [
            {"section": "repository", "basis": "First repository basis."},
            {"section": "repository", "basis": "Second repository basis."}
        ]}),
    ];

    for invalid_patch in invalid_patches {
        let backend = FakeBackend::new(vec![
            Ok(response(duplicate_output())),
            Ok(response(invalid_patch)),
        ]);
        let registry = builtin_registry().expect("registry");
        let journal = InMemoryAttemptJournal::default();
        let execution = RouterExecutor::new(&backend, &registry, &journal)
            .expect("executor")
            .execute(request())
            .await
            .expect("execution setup");
        assert!(matches!(
            execution.status,
            RouterExecutionStatus::Rejected {
                failure: RouterExecutionFailure::InvalidRepairPatch { .. }
            }
        ));
        assert_eq!(backend.call_count(), 2);
        assert_eq!(journal.snapshot().expect("journal snapshot").len(), 2);
    }
}

#[tokio::test]
async fn a_patch_cannot_smuggle_semantic_field_changes() {
    let backend = FakeBackend::new(vec![
        Ok(response(duplicate_output())),
        Ok(response(json!({
            "replacements": [
                {"section": "repository", "basis": "Consolidated repository basis."},
                {"section": "request", "basis": "Consolidated request basis."}
            ],
            "action": "answer"
        }))),
    ]);
    let registry = builtin_registry().expect("registry");
    let journal = InMemoryAttemptJournal::default();
    let execution = RouterExecutor::new(&backend, &registry, &journal)
        .expect("executor")
        .execute(request())
        .await
        .expect("execution setup");
    assert!(matches!(
        execution.status,
        RouterExecutionStatus::Rejected {
            failure: RouterExecutionFailure::RepairOutputContract { .. }
        }
    ));
    assert_eq!(backend.call_count(), 2);
}

#[tokio::test]
async fn a_simultaneous_noneligible_invariant_prevents_any_retry() {
    let mut candidate = duplicate_output();
    candidate["evidence"][3]["basis"] = json!("   ");
    let backend = FakeBackend::new(vec![Ok(response(candidate))]);
    let registry = builtin_registry().expect("registry");
    let journal = InMemoryAttemptJournal::default();
    let execution = RouterExecutor::new(&backend, &registry, &journal)
        .expect("executor")
        .execute(request())
        .await
        .expect("execution setup");
    let RouterExecutionStatus::Rejected {
        failure: RouterExecutionFailure::NonRepairableInvariants { violations },
    } = execution.status
    else {
        panic!("candidate must be rejected without repair")
    };
    assert!(violations.iter().any(|violation| matches!(
        violation,
        RouterInvariantViolation::DuplicateEvidenceSection { .. }
    )));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        RouterInvariantViolation::BlankEvidenceField { .. }
    )));
    assert_eq!(backend.call_count(), 1);
    assert!(execution.repair.is_none());
}

#[tokio::test]
async fn repair_backend_failure_is_retained_and_never_retried() {
    let backend = FakeBackend::new(vec![
        Ok(response(duplicate_output())),
        Err(backend_failure()),
    ]);
    let registry = builtin_registry().expect("registry");
    let journal = InMemoryAttemptJournal::default();
    let execution = RouterExecutor::new(&backend, &registry, &journal)
        .expect("executor")
        .execute(request())
        .await
        .expect("execution setup");
    assert!(matches!(
        execution.status,
        RouterExecutionStatus::Rejected {
            failure: RouterExecutionFailure::RepairBackend
        }
    ));
    assert!(matches!(
        execution.repair.as_ref().map(|record| &record.attempt),
        Some(RetainedInferenceAttempt::Error { error })
            if error.message == "simulated repair transport failure"
    ));
    assert_eq!(backend.call_count(), 2);
    assert_eq!(journal.snapshot().expect("journal snapshot").len(), 2);
}

#[tokio::test]
async fn a_non_router_prompt_key_is_rejected_before_inference() {
    let backend = FakeBackend::new(Vec::new());
    let registry = builtin_registry().expect("registry");
    let journal = InMemoryAttemptJournal::default();
    let executor = RouterExecutor::new(&backend, &registry, &journal).expect("executor");
    let mut request = request();
    request.router_key = parse_manifest(ROUTER_REPAIR_MANIFEST_JSON.as_bytes())
        .expect("repair manifest")
        .key();
    let error = executor
        .execute(request)
        .await
        .expect_err("non-router prompt must fail before inference");
    assert!(matches!(
        error,
        RouterSetupError::UnsupportedRouterPrompt(_)
    ));
    assert_eq!(backend.call_count(), 0);
    assert!(journal.snapshot().expect("journal snapshot").is_empty());
}

struct RejectRepairJournal {
    retained: AtomicUsize,
}

struct RejectInitialJournal;

impl AttemptJournal for RejectInitialJournal {
    fn retain(
        &self,
        record: &birdcode_orchestrator::RetainedInferenceRecord,
    ) -> Result<(), AttemptJournalError> {
        assert_eq!(record.phase, RouterAttemptPhase::Initial);
        Err(AttemptJournalError::new("initial persistence failed"))
    }
}

#[tokio::test]
async fn initial_journal_failure_stops_before_any_repair_call() {
    let backend = FakeBackend::new(vec![Ok(response(duplicate_output()))]);
    let registry = builtin_registry().expect("registry");
    let execution = RouterExecutor::new(&backend, &registry, &RejectInitialJournal)
        .expect("executor")
        .execute(request())
        .await
        .expect("execution setup");
    assert!(matches!(
        execution.status,
        RouterExecutionStatus::Rejected {
            failure: RouterExecutionFailure::Journal {
                phase: RouterAttemptPhase::Initial,
                ..
            }
        }
    ));
    assert_eq!(backend.call_count(), 1);
    assert!(execution.repair.is_none());
}

impl AttemptJournal for RejectRepairJournal {
    fn retain(
        &self,
        record: &birdcode_orchestrator::RetainedInferenceRecord,
    ) -> Result<(), AttemptJournalError> {
        self.retained.fetch_add(1, Ordering::SeqCst);
        if record.phase == RouterAttemptPhase::EvidenceRepair {
            Err(AttemptJournalError::new("repair persistence failed"))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn repair_journal_failure_rejects_before_patch_acceptance() {
    let backend = FakeBackend::new(vec![
        Ok(response(duplicate_output())),
        Ok(response(repair_patch())),
    ]);
    let registry = builtin_registry().expect("registry");
    let journal = RejectRepairJournal {
        retained: AtomicUsize::new(0),
    };
    let execution = RouterExecutor::new(&backend, &registry, &journal)
        .expect("executor")
        .execute(request())
        .await
        .expect("execution setup");
    assert!(matches!(
        execution.status,
        RouterExecutionStatus::Rejected {
            failure: RouterExecutionFailure::Journal {
                phase: RouterAttemptPhase::EvidenceRepair,
                ..
            }
        }
    ));
    assert_eq!(backend.call_count(), 2);
    assert_eq!(journal.retained.load(Ordering::SeqCst), 2);
}

#[test]
fn public_patch_violation_wire_fields_are_fixed_width() {
    let value = serde_json::to_value(EvidenceRepairPatchViolation::ReplacementCount {
        expected: 2,
        actual: 3,
    })
    .expect("violation serializes");
    assert_eq!(
        value,
        json!({"kind": "replacement_count", "expected": 2, "actual": 3})
    );
}

#[test]
fn repair_manifest_version_requires_an_explicit_hash_update() {
    let manifest = parse_manifest(ROUTER_REPAIR_MANIFEST_JSON.as_bytes()).expect("repair manifest");
    assert_eq!(manifest.version.to_string(), "1.0.0");
    assert_eq!(
        manifest.content_sha256().expect("manifest hash"),
        "f02df09a4699da154070ae0eea5b95ffcf69d526245b14c9c8b5e44030acf3a5"
    );
}
