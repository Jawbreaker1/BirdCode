use super::*;
use crate::{
    ChildModelDispatchPreparationOutcome, ChildRecoveryState,
    ChildRepositoryExplorerObservationAuthority, ChildRepositoryExplorerObservedEvidence,
    ChildRepositoryExplorerPreparationAuthority, ChildToolDispatchRecovery,
    backend_instance_from_protocol_identity,
    tests::{
        ExactPairFixture, default_exact_pair_fixture,
        parallel_recon_bootstrap::bootstrap_default_exact_pair,
    },
};
use birdcode_backends::{
    BackendId, InferenceEvidence, ModelId, StructuredInferenceResponse, TokenUsage,
};
use birdcode_protocol::{
    ActorId, CancellationRequestId, CancellationRequested, ChildActionV1, ChildLocalPlanSnapshotV1,
    ChildLocalPlanStepIdV1, ChildLocalPlanStepStatusV1, ChildLocalPlanStepV1, ChildModelCallId,
    ChildModelInferencePreparedV2, ChildModelStructuredResponseV1, CreateSessionRequest,
    EventPayload, ModelRepositoryPathV1, REPOSITORY_TOOL_CANONICAL_PARAMETERS_V2_MEDIA_TYPE,
    REPOSITORY_TOOL_PREPARED_RECEIPT_V2_MEDIA_TYPE, RepositoryBrokerClockV1,
    RepositoryBrokerEpochActivatedV1, RepositoryToolPreparedReceiptV2, RunClaimId, RunClaimed,
    RunState, RuntimeInstanceId, Session, Sha256Digest, TokenReservation, TokenReservationId,
};
use chrono::Utc;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicU64, Ordering},
};

pub(crate) fn clock(
    runtime_instance_id: RuntimeInstanceId,
    monotonic_nanos: u64,
) -> RuntimeClockReading {
    RuntimeClockReading {
        runtime_instance_id,
        monotonic_nanos,
        observed_at: Utc::now(),
    }
}

pub(crate) fn provenance() -> Provenance {
    Provenance {
        producer: "child-tool-dispatch-fixture".to_owned(),
        backend: None,
        raw_artifact: None,
    }
}

fn receipt_authority_for(
    authority: &ChildRepositoryAuthorityV1,
) -> RepositoryToolReceiptAuthorityV2 {
    RepositoryToolReceiptAuthorityV2 {
        policy_id: authority.policy_id.clone(),
        policy_artifact: authority.policy_artifact.clone(),
        policy_digest: authority.policy_digest.clone(),
        snapshot: authority.snapshot.clone(),
        root: authority.root.clone(),
        broker_bounds: authority.broker_bounds,
        tool_grants: authority.tool_grants.clone(),
    }
}

fn retained(media_type: &str, bytes: Vec<u8>) -> RetainedArtifactV2 {
    let digest = Sha256Digest::of_bytes(&bytes);
    RetainedArtifactV2 {
        artifact: ArtifactRef {
            sha256: digest.as_str().to_owned(),
            size_bytes: u64::try_from(bytes.len()).expect("fixture bytes fit u64"),
            media_type: media_type.to_owned(),
        },
        bytes,
    }
}

fn artifact_file_count(root: &std::path::Path) -> usize {
    std::fs::read_dir(root)
        .expect("fixture artifact root reads")
        .map(|entry| entry.expect("fixture artifact entry reads").path())
        .map(|path| {
            if path.is_dir() {
                artifact_file_count(&path)
            } else {
                1
            }
        })
        .sum()
}

struct MockPreparer {
    authority: RepositoryToolReceiptAuthorityV2,
    epoch: RepositoryBrokerEpochStateV1,
    calls: Arc<AtomicU64>,
    corrupt_parameters: bool,
}

impl RepositoryToolPreparer for MockPreparer {
    fn authority(&self) -> &RepositoryToolReceiptAuthorityV2 {
        &self.authority
    }

    fn epoch(&self) -> &RepositoryBrokerEpochStateV1 {
        &self.epoch
    }

    fn prepare(
        &self,
        input: RepositoryToolPrepareInputV2,
    ) -> Result<PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2> {
        let sequence = self
            .calls
            .fetch_add(1, Ordering::SeqCst)
            .checked_add(1)
            .expect("fixture sequence fits");
        let parameter_bytes =
            serde_json::to_vec(&input.parameters).expect("fixture parameters encode");
        let mut canonical_parameters = retained(
            REPOSITORY_TOOL_CANONICAL_PARAMETERS_V2_MEDIA_TYPE,
            parameter_bytes,
        );
        let authorization = birdcode_protocol::evaluate_repository_tool_authorization_v1(
            &self.authority.broker_bounds,
            &self.authority.tool_grants,
            &input.parameters,
            canonical_parameters.artifact.size_bytes,
            sequence,
        );
        let receipt = RepositoryToolPreparedReceiptV2 {
            schema_version: REPOSITORY_BROKER_CONTRACT_VERSION,
            binding: input.parameters.binding.clone(),
            tool_call_id: input.parameters.tool_call_id,
            tool_ordinal: input.parameters.tool_ordinal,
            action_binding: input.parameters.action_binding.clone(),
            operation: input.parameters.operation.clone(),
            authority: self.authority.clone(),
            canonical_parameters_artifact: canonical_parameters.artifact.clone(),
            canonical_parameters_digest: Sha256Digest::of_bytes(&canonical_parameters.bytes),
            authorization,
            broker_call_sequence: sequence,
            broker_prepared_at: RepositoryBrokerClockV1 {
                broker_instance_id: self.epoch.active_broker_instance_id,
                monotonic_nanos: sequence.saturating_mul(100),
            },
            runtime_prepared_at: input.runtime_prepared_at,
        };
        let prepared_receipt = retained(
            REPOSITORY_TOOL_PREPARED_RECEIPT_V2_MEDIA_TYPE,
            serde_json::to_vec(&receipt).expect("fixture receipt encodes"),
        );
        if self.corrupt_parameters {
            canonical_parameters.bytes.push(b'x');
        }
        Ok(PreparedRepositoryToolCallV2 {
            receipt,
            canonical_parameters,
            prepared_receipt,
        })
    }
}

pub(crate) fn mock_lane(
    authority: RepositoryToolReceiptAuthorityV2,
    epoch: RepositoryBrokerEpochStateV1,
    corrupt_parameters: bool,
) -> (ChildRepositoryToolLane, Arc<AtomicU64>) {
    let calls = Arc::new(AtomicU64::new(0));
    let lane = ChildRepositoryToolLane::from_preparer(Box::new(MockPreparer {
        authority,
        epoch,
        calls: Arc::clone(&calls),
        corrupt_parameters,
    }));
    (lane, calls)
}

pub(crate) struct ReadyToolFixture {
    pub(crate) fixture: ExactPairFixture,
    pub(crate) work_order_id: ChildWorkOrderId,
    other_work_order_id: ChildWorkOrderId,
    pub(crate) tail_event_id: EventId,
    pub(crate) epoch: RepositoryBrokerEpochStateV1,
    pub(crate) receipt_authority: RepositoryToolReceiptAuthorityV2,
}

fn model_response(
    spec: &birdcode_protocol::ChildWorkOrderSpec,
    prepared: &ChildModelInferencePreparedV2,
) -> StructuredInferenceResponse {
    let step_id = ChildLocalPlanStepIdV1("inspect-root".to_owned());
    let normalized = ChildModelStructuredResponseV1 {
        contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
        plan: ChildLocalPlanSnapshotV1 {
            contract_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            binding: prepared.prepared.binding.clone(),
            plan_id: prepared.prepared.local_plan_id,
            revision: 1,
            previous_plan_digest: None,
            objective: spec.objective.clone(),
            steps: vec![ChildLocalPlanStepV1 {
                step_id: step_id.clone(),
                objective: "Inspect the immutable repository root".to_owned(),
                status: ChildLocalPlanStepStatusV1::InProgress,
            }],
            active_step_id: Some(step_id),
            assumptions: Vec::new(),
            unknowns: Vec::new(),
        },
        action: ChildActionV1::RepositoryTree {
            tool_grant_id: spec.repository_authority.tool_grants[0].tool_grant_id(),
            path: ModelRepositoryPathV1::default(),
            max_depth: 1,
            max_entries: 16,
        },
    };
    let value = serde_json::to_value(&normalized).expect("typed response encodes");
    let backend_instance = backend_instance_from_protocol_identity(
        prepared
            .prepared
            .backend_instance
            .as_ref()
            .expect("fixture Prepared has exact backend instance"),
    )
    .expect("fixture backend identity converts");
    StructuredInferenceResponse {
        model_id: ModelId::new(spec.resolved_model.model_id.clone())
            .expect("fixture model id is valid"),
        raw_text: serde_json::to_string(&value).expect("typed response text encodes"),
        value,
        finish_reason: Some("stop".to_owned()),
        usage: Some(TokenUsage {
            input_tokens: Some(200),
            output_tokens: Some(100),
            total_tokens: Some(300),
        }),
        evidence: InferenceEvidence {
            backend_id: BackendId::new(spec.resolved_model.backend_id.clone())
                .expect("fixture backend id is valid"),
            backend_instance: Some(backend_instance),
            endpoint: "http://127.0.0.1:19001/v1/chat/completions".to_owned(),
            status: 200,
            completion_id: Some("child-tool-dispatch-success".to_owned()),
            response_body_sha256: Some("9".repeat(Sha256Digest::HEX_LENGTH)),
            raw_response: serde_json::json!({"complete": true}),
        },
    }
}

pub(crate) fn ready_tool_fixture() -> ReadyToolFixture {
    let mut fixture = default_exact_pair_fixture();
    let bootstrap = bootstrap_default_exact_pair(&mut fixture);
    let child = bootstrap.children[0].projection.clone();
    let other_work_order_id = bootstrap.children[1].projection.spec.work_order_id;
    let epoch = RepositoryBrokerEpochStateV1 {
        active_broker_instance_id: RepositoryBrokerInstanceId::new(),
        closed_broker_instance_ids: Vec::new(),
    };
    fixture
        .store
        .append_event(NewEvent {
            session_id: fixture.run.spec.session_id,
            run_id: Some(fixture.run.id),
            actor_id: fixture.actor_id,
            causal_parent: Some(bootstrap.children[1].started_event.id),
            provenance: provenance(),
            payload: EventPayload::RepositoryBrokerEpochActivatedV1(
                RepositoryBrokerEpochActivatedV1 {
                    previous_active_broker_instance_id: None,
                    state: epoch.clone(),
                    activated_at: clock(fixture.runtime_instance_id, 32),
                },
            ),
        })
        .expect("fixture broker epoch activates");
    let model_authority = ChildRepositoryExplorerPreparationAuthority {
        event_id: EventId::new(),
        model_call_id: ChildModelCallId::new(),
        token_reservation: TokenReservation {
            id: TokenReservationId::new(),
            reserved_tokens: 1_048_576,
            max_output_tokens: 1_024,
        },
        prepared_at: clock(fixture.runtime_instance_id, 40),
    };
    let prepared = fixture
        .store
        .prepare_child_repository_explorer_dispatch(
            fixture.run.id,
            child.spec.work_order_id,
            model_authority,
        )
        .expect("model preparation commits");
    let (prepared_event, dispatch) = match prepared {
        ChildModelDispatchPreparationOutcome::Appended { evidence, dispatch } => {
            (evidence.prepared_event, dispatch)
        }
        ChildModelDispatchPreparationOutcome::AlreadyPresent { .. } => {
            panic!("fixture model preparation is fresh")
        }
    };
    drop(dispatch.into_backend_request());
    let EventPayload::ChildModelInferencePreparedV2(prepared) = &prepared_event.payload else {
        panic!("fixture Prepared remains typed")
    };
    let observed = fixture
        .store
        .observe_child_repository_explorer_turn(
            fixture.run.id,
            ChildRepositoryExplorerObservationAuthority {
                event_id: EventId::new(),
                prepared_event_id: prepared_event.id,
                evidence: ChildRepositoryExplorerObservedEvidence::Response(model_response(
                    &child.spec,
                    prepared,
                )),
                finished_at: clock(fixture.runtime_instance_id, 50),
            },
        )
        .expect("model observation commits");
    assert!(matches!(
        fixture
            .store
            .child_work_order_projection(fixture.run.id, child.spec.work_order_id)
            .expect("child replays")
            .expect("child exists")
            .recovery,
        ChildRecoveryState::ReadyForTool
    ));
    assert_eq!(observed.event.causal_parent, Some(prepared_event.id));
    ReadyToolFixture {
        fixture,
        work_order_id: child.spec.work_order_id,
        other_work_order_id,
        tail_event_id: observed.event.id,
        epoch,
        receipt_authority: receipt_authority_for(&child.spec.repository_authority),
    }
}

pub(crate) fn tool_authority(
    runtime_instance_id: RuntimeInstanceId,
) -> ChildRepositoryExplorerToolPreparationAuthority {
    ChildRepositoryExplorerToolPreparationAuthority {
        event_id: EventId::new(),
        action_id: ChildValidatedActionId::new(),
        tool_call_id: ChildToolCallId::new(),
        prepared_at: clock(runtime_instance_id, 60),
    }
}

#[test]
fn fresh_prepare_issues_one_affine_handoff_while_replay_and_recovery_are_evidence_only() {
    fn assert_send_static<T: Send + 'static>() {}

    assert_send_static::<ChildToolDispatchHandoff>();
    assert_eq!(
        std::mem::size_of::<ChildToolDispatchHandoff>(),
        std::mem::size_of::<usize>()
    );
    let mut ready = ready_tool_fixture();
    let (lane, calls) = mock_lane(ready.receipt_authority.clone(), ready.epoch.clone(), false);
    let authority = tool_authority(ready.fixture.runtime_instance_id);
    let first = ready
        .fixture
        .store
        .prepare_child_repository_explorer_tool_dispatch(
            ready.fixture.run.id,
            ready.work_order_id,
            authority.clone(),
            &lane,
        )
        .expect("fresh tool preparation commits");
    let (evidence, dispatch) = match first {
        ChildToolDispatchPreparationOutcome::Appended { evidence, dispatch } => {
            (evidence, dispatch)
        }
        ChildToolDispatchPreparationOutcome::AlreadyPresent { .. } => {
            panic!("fresh preparation owns the sole handoff")
        }
    };
    assert_eq!(evidence.prepared_event.id, authority.event_id);
    assert_eq!(dispatch.prepared_event(), &evidence.prepared_event);
    assert_eq!(
        dispatch.broker_instance_id(),
        ready.epoch.active_broker_instance_id
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let poisoned_lane = lane.clone();
    assert!(
        std::thread::spawn(move || {
            let mut state = poisoned_lane
                .inner
                .publication
                .lock()
                .expect("fixture lane starts available");
            *state = ToolLaneState::Tainted;
            panic!("fixture simulates a poisoned tainted lane");
        })
        .join()
        .is_err()
    );
    assert!(!lane.is_healthy());

    let replay = ready
        .fixture
        .store
        .prepare_child_repository_explorer_tool_dispatch(
            ready.fixture.run.id,
            ready.work_order_id,
            authority,
            &lane,
        )
        .expect("exact replay validates");
    let ChildToolDispatchPreparationOutcome::AlreadyPresent {
        evidence: replay_evidence,
    } = replay
    else {
        panic!("exact replay never recreates dispatch authority")
    };
    assert_eq!(replay_evidence, evidence);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        ready
            .fixture
            .store
            .recover_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
            )
            .expect("pending tool recovery validates"),
        Some(ChildToolDispatchRecovery {
            prepared: evidence.clone(),
            started: None,
        })
    );
    let reopened = Store::open(&ready.fixture.database, &ready.fixture.artifacts)
        .expect("recovery Store reopens");
    assert_eq!(
        reopened
            .recover_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
            )
            .expect("reopened recovery validates"),
        Some(ChildToolDispatchRecovery {
            prepared: evidence,
            started: None,
        })
    );
}

#[test]
fn exact_event_identity_rejects_runtime_authority_substitution_before_broker_prepare() {
    let mut ready = ready_tool_fixture();
    let (lane, calls) = mock_lane(ready.receipt_authority.clone(), ready.epoch.clone(), false);
    let authority = tool_authority(ready.fixture.runtime_instance_id);
    let _fresh = ready
        .fixture
        .store
        .prepare_child_repository_explorer_tool_dispatch(
            ready.fixture.run.id,
            ready.work_order_id,
            authority.clone(),
            &lane,
        )
        .expect("fresh tool preparation commits");
    let mut changed_action = authority.clone();
    changed_action.action_id = ChildValidatedActionId::new();
    let mut changed_call = authority.clone();
    changed_call.tool_call_id = ChildToolCallId::new();
    let mut changed_clock = authority.clone();
    changed_clock.prepared_at.monotonic_nanos += 1;

    for (work_order_id, changed) in [
        (ready.work_order_id, changed_action),
        (ready.work_order_id, changed_call),
        (ready.work_order_id, changed_clock),
        (ready.other_work_order_id, authority),
    ] {
        assert!(matches!(
            ready
                .fixture
                .store
                .prepare_child_repository_explorer_tool_dispatch(
                    ready.fixture.run.id,
                    work_order_id,
                    changed,
                    &lane,
                ),
            Err(ChildToolDispatchError::Store(
                StoreError::IdentifiedEventConflict
            ))
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(lane.is_healthy());
}

#[test]
fn mismatched_broker_authority_is_rejected_without_mutating_the_broker() {
    let mut ready = ready_tool_fixture();
    let mut wrong = ready.receipt_authority.clone();
    wrong.policy_id.push_str("-substituted");
    let (lane, calls) = mock_lane(wrong, ready.epoch.clone(), false);
    let authority = tool_authority(ready.fixture.runtime_instance_id);
    let artifact_count = artifact_file_count(&ready.fixture.artifacts);

    assert!(matches!(
        ready
            .fixture
            .store
            .prepare_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
                authority,
                &lane,
            ),
        Err(ChildToolDispatchError::Store(StoreError::InvalidStateEvent))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        artifact_file_count(&ready.fixture.artifacts),
        artifact_count,
        "pre-Prepare rejection must not retain orphan action material"
    );
    assert!(lane.is_healthy());
}

#[test]
fn mismatched_broker_epoch_is_rejected_without_mutating_the_broker() {
    let mut ready = ready_tool_fixture();
    let wrong_epoch = RepositoryBrokerEpochStateV1 {
        active_broker_instance_id: RepositoryBrokerInstanceId::new(),
        closed_broker_instance_ids: vec![ready.epoch.active_broker_instance_id],
    };
    let (lane, calls) = mock_lane(ready.receipt_authority.clone(), wrong_epoch, false);

    assert!(matches!(
        ready
            .fixture
            .store
            .prepare_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
                tool_authority(ready.fixture.runtime_instance_id),
                &lane,
            ),
        Err(ChildToolDispatchError::Store(StoreError::InvalidStateEvent))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(lane.is_healthy());
}

#[test]
fn cancellation_is_rejected_before_broker_prepare() {
    let mut ready = ready_tool_fixture();
    ready
        .fixture
        .store
        .append_event(NewEvent {
            session_id: ready.fixture.run.spec.session_id,
            run_id: Some(ready.fixture.run.id),
            actor_id: ready.fixture.actor_id,
            causal_parent: Some(ready.tail_event_id),
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: CancellationRequestId::new(),
                cancellation_generation: 1,
            }),
        })
        .expect("cancellation persists");
    let (lane, calls) = mock_lane(ready.receipt_authority.clone(), ready.epoch.clone(), false);

    assert!(matches!(
        ready
            .fixture
            .store
            .prepare_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
                tool_authority(ready.fixture.runtime_instance_id),
                &lane,
            ),
        Err(ChildToolDispatchError::Store(StoreError::InvalidStateEvent))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(lane.is_healthy());
}

#[test]
fn broker_epoch_uuid_cannot_be_activated_in_a_second_run() {
    let mut ready = ready_tool_fixture();
    let actor_id = ActorId::new();
    let runtime_instance_id = RuntimeInstanceId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: std::path::PathBuf::from("/tmp/birdcode-second-epoch-run").into(),
        title: Some("duplicate broker epoch".to_owned()),
    });
    let session_created = ready
        .fixture
        .store
        .create_session(
            &session,
            NewEvent {
                session_id: session.id,
                run_id: None,
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::SessionCreated {
                    session: session.clone(),
                },
            },
        )
        .expect("second session persists");
    let mut run_spec = ready.fixture.run.spec.clone();
    run_spec.session_id = session.id;
    let run = birdcode_protocol::Run::new(run_spec);
    let run_created = ready
        .fixture
        .store
        .create_run(
            &run,
            NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(session_created.id),
                provenance: provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            },
        )
        .expect("second run persists");
    let claim = ready
        .fixture
        .store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(run_created.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id,
                claim_generation: 1,
                cancellation_generation: 0,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        })
        .expect("second run claim persists");
    let running = ready
        .fixture
        .store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(claim.id),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        })
        .expect("second run starts");

    assert!(matches!(
        ready.fixture.store.append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(running.id),
            provenance: provenance(),
            payload: EventPayload::RepositoryBrokerEpochActivatedV1(
                RepositoryBrokerEpochActivatedV1 {
                    previous_active_broker_instance_id: None,
                    state: ready.epoch.clone(),
                    activated_at: clock(runtime_instance_id, 1),
                },
            ),
        }),
        Err(StoreError::InvalidStateEvent)
    ));
}

#[test]
fn post_prepare_artifact_failure_taints_lane_and_never_issues_handoff() {
    let mut ready = ready_tool_fixture();
    let (lane, calls) = mock_lane(ready.receipt_authority.clone(), ready.epoch.clone(), true);
    let authority = tool_authority(ready.fixture.runtime_instance_id);
    assert!(matches!(
        ready
            .fixture
            .store
            .prepare_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
                authority.clone(),
                &lane,
            ),
        Err(ChildToolDispatchError::Store(StoreError::InvalidStateEvent))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!lane.is_healthy());
    assert_eq!(
        ready
            .fixture
            .store
            .recover_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
            )
            .expect("failed publication leaves no pending effect"),
        None
    );
    assert!(matches!(
        ready
            .fixture
            .store
            .prepare_child_repository_explorer_tool_dispatch(
                ready.fixture.run.id,
                ready.work_order_id,
                authority,
                &lane,
            ),
        Err(ChildToolDispatchError::LaneRequiresReconciliation)
    ));
}

#[test]
fn concurrent_exact_writers_issue_exactly_one_dispatch_handoff() {
    let ready = ready_tool_fixture();
    let (lane, calls) = mock_lane(ready.receipt_authority.clone(), ready.epoch.clone(), false);
    let authority = tool_authority(ready.fixture.runtime_instance_id);
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let database = ready.fixture.database.clone();
            let artifacts = ready.fixture.artifacts.clone();
            let lane = lane.clone();
            let authority = authority.clone();
            let barrier = Arc::clone(&barrier);
            let run_id = ready.fixture.run.id;
            let work_order_id = ready.work_order_id;
            std::thread::spawn(move || {
                let mut store = Store::open(database, artifacts).expect("Store opens");
                barrier.wait();
                store
                    .prepare_child_repository_explorer_tool_dispatch(
                        run_id,
                        work_order_id,
                        authority,
                        &lane,
                    )
                    .map(|outcome| {
                        matches!(
                            outcome,
                            ChildToolDispatchPreparationOutcome::Appended { .. }
                        )
                    })
            })
        })
        .collect::<Vec<_>>();
    let fresh = handles
        .into_iter()
        .map(|handle| handle.join().expect("prepare thread joins"))
        .collect::<Result<Vec<_>, _>>()
        .expect("both exact preparations converge");

    assert_eq!(fresh.iter().filter(|fresh| **fresh).count(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
