use super::*;
use birdcode_protocol::{
    ActorId, ArtifactRef, BackendKind, BackendSelection, CancellationRequestId,
    CancellationRequested, CreateSessionRequest, IdempotentAppendOutcome, InputItem, NewEvent,
    PlanAcceptanceContract, PlannerAcceptedDelegationV1, PlannerBasePlanBindingV1,
    PlannerDelegateDirectiveId, PlannerDelegatedWorkOrderBindingV1, PlannerPromptDecisionBasisV1,
    PlannerPromptDirectiveKindV1, PlannerPromptDirectiveV1, PlannerPromptPlanPatchV1,
    PlannerPromptV2AcceptedOutputV1, PlannerPromptV2OutputBindingsV1, PlannerTurnAcceptedV1,
    PlannerTurnId, PlannerTurnRejectedV1, PlannerTurnRejectionReasonV1, Provenance, Run,
    RunClaimId, RunClaimed, RunLimits, RunPurpose, RunSpec, RuntimeClockReading, Session,
    Sha256Digest, TokenReservationId,
};
use birdcode_store::{
    DurableRunClaimProjection, PlannerRunProjection, PlannerV2FinalizationOutcome,
    ReconRunGuardProjection,
};
use chrono::Utc;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn artifact(label: &str) -> ArtifactRef {
    let digest = Sha256Digest::of_bytes(label.as_bytes());
    ArtifactRef {
        sha256: digest.as_str().to_owned(),
        size_bytes: u64::try_from(label.len()).expect("fixture length fits"),
        media_type: "application/json".to_owned(),
    }
}

fn provenance() -> Provenance {
    Provenance {
        producer: "planner-terminal-test".to_owned(),
        backend: None,
        raw_artifact: None,
    }
}

fn envelope(
    session_id: birdcode_protocol::SessionId,
    run_id: RunId,
    payload: EventPayload,
) -> EventEnvelope {
    EventEnvelope {
        id: EventId::new(),
        sequence: 7,
        session_id,
        run_id: Some(run_id),
        actor_id: ActorId::new(),
        causal_parent: None,
        occurred_at: Utc::now(),
        provenance: provenance(),
        payload,
    }
}

fn base_plan() -> PlannerBasePlanBindingV1 {
    PlannerBasePlanBindingV1 {
        accepted_event_id: EventId::new(),
        revision: 1,
        digest: Sha256Digest::of_bytes(b"base-plan"),
        artifact: artifact("base-plan"),
    }
}

fn accepted_directive() -> PlannerAcceptedDirectiveV1 {
    PlannerAcceptedDirectiveV1::Delegate {
        delegations: vec![PlannerAcceptedDelegationV1 {
            directive_id: PlannerDelegateDirectiveId::new(),
            source_delegation_index: 0,
            work_orders: vec![PlannerDelegatedWorkOrderBindingV1 {
                work_order_id: "inspect-src".to_owned(),
                revision: 1,
                work_order_artifact: artifact("inspect-src"),
                work_order_digest: Sha256Digest::of_bytes(b"inspect-src"),
            }],
        }],
    }
}

fn accepted_projection(
    session_id: birdcode_protocol::SessionId,
    run_id: RunId,
    purpose: PlannerTurnPurposeV1,
    directive: PlannerAcceptedDirectiveV1,
) -> PlannerAcceptedDirectiveProjection {
    let binding_digest = Sha256Digest::of_bytes(b"binding");
    let accepted_output = PlannerPromptV2AcceptedOutputV1 {
        schema_version: 1,
        bindings: PlannerPromptV2OutputBindingsV1 {
            purpose,
            prompt_id: "planner-replanner-v2".to_owned(),
            prompt_version: "2".to_owned(),
            prompt_manifest_sha256: binding_digest.clone(),
            plan_id: "plan-1".to_owned(),
            base_revision: 1,
            base_plan_sha256: binding_digest.clone(),
            obligation_snapshot_sha256: binding_digest.clone(),
            acceptance_policy_sha256: binding_digest.clone(),
            context_manifest_sha256: binding_digest.clone(),
            planner_policy_sha256: binding_digest.clone(),
            evidence_packet_sha256: binding_digest.clone(),
            previous_evidence_packet_sha256: None,
            evidence_delta_sha256: binding_digest.clone(),
            backend_id: "lmstudio".to_owned(),
            backend_configured_deployment_id: "local".to_owned(),
            backend_endpoint_origin: "http://127.0.0.1:1234".to_owned(),
            backend_instance_sha256: binding_digest.clone(),
            model_id: "gemma-4-26b".to_owned(),
            reasoning: None,
            budget_reservation_id: TokenReservationId::new(),
            max_output_tokens: 256,
        },
        turn_basis: PlannerPromptDecisionBasisV1 {
            evidence_ids: BTreeSet::new(),
            rationale: "typed fixture".to_owned(),
        },
        patch: PlannerPromptPlanPatchV1::default(),
        directive: PlannerPromptDirectiveV1 {
            kind: PlannerPromptDirectiveKindV1::Delegate,
            execute: Default::default(),
            delegations: Vec::new(),
            clarifications: Vec::new(),
            escalations: Vec::new(),
            finish_claims: Vec::new(),
        },
    };
    let accepted_digest = Sha256Digest::of_bytes(b"accepted-output");
    let accepted = PlannerTurnAcceptedV1 {
        turn_id: PlannerTurnId::new(),
        purpose,
        prepared_event_id: EventId::new(),
        observed_event_id: EventId::new(),
        base_plan: base_plan(),
        resulting_plan: base_plan(),
        accepted_prompt_output_artifact: artifact("accepted-output"),
        accepted_prompt_output_digest: accepted_digest,
        accepted_prompt_output: accepted_output,
        resolved_directive: directive,
        validation_evidence_artifact: artifact("accepted-validation"),
        validation_evidence_digest: Sha256Digest::of_bytes(b"accepted-validation"),
        accepted_at: RuntimeClockReading {
            runtime_instance_id: RuntimeInstanceId::new(),
            monotonic_nanos: 10,
            observed_at: Utc::now(),
        },
    };
    PlannerAcceptedDirectiveProjection {
        event: envelope(
            session_id,
            run_id,
            EventPayload::PlannerTurnAcceptedV1(accepted.clone()),
        ),
        accepted,
    }
}

fn rejected_event(
    session_id: birdcode_protocol::SessionId,
    run_id: RunId,
    purpose: PlannerTurnPurposeV1,
    reason: PlannerTurnRejectionReasonV1,
) -> EventEnvelope {
    envelope(
        session_id,
        run_id,
        EventPayload::PlannerTurnRejectedV1(PlannerTurnRejectedV1 {
            turn_id: PlannerTurnId::new(),
            purpose,
            prepared_event_id: EventId::new(),
            observed_event_id: EventId::new(),
            base_plan: base_plan(),
            rejected_output_artifact: artifact("rejected-output"),
            rejected_output_digest: Sha256Digest::of_bytes(b"rejected-output"),
            reason,
            validation_evidence_artifact: artifact("rejected-validation"),
            validation_evidence_digest: Sha256Digest::of_bytes(b"rejected-validation"),
            rejected_at: RuntimeClockReading {
                runtime_instance_id: RuntimeInstanceId::new(),
                monotonic_nanos: 11,
                observed_at: Utc::now(),
            },
        }),
    )
}

fn finalization_outcome(
    event: EventEnvelope,
    disposition: PlannerV2FinalizationDisposition,
) -> PlannerV2FinalizationOutcome {
    PlannerV2FinalizationOutcome {
        append: IdempotentAppendOutcome::AlreadyPresent {
            event: event.clone(),
        },
        event,
        disposition,
    }
}

#[test]
fn accepted_finalization_reprojects_then_adapter_replays_and_rejects_substitution() {
    let session_id = birdcode_protocol::SessionId::new();
    let run_id = RunId::new();
    let purpose = PlannerTurnPurposeV1::InitialDelegation;
    let evidence = accepted_projection(session_id, run_id, purpose, accepted_directive());
    assert!(matches!(
        planner_resolution_from_finalization(finalization_outcome(
            evidence.event.clone(),
            PlannerV2FinalizationDisposition::Accepted,
        ))
        .expect("accepted finalization is structurally valid"),
        PlannerFinalizationResolution::Reproject
    ));
    let action = PlannerNextAction::ApplyAcceptedDirective {
        accepted_event_id: evidence.event.id,
        directive: evidence.accepted.resolved_directive.clone(),
    };

    let first = accepted_planner_recovery(&action, &evidence, purpose).expect("exact accepted");
    let replay = accepted_planner_recovery(&action, &evidence, purpose).expect("accepted replay");
    assert_eq!(first, replay);

    let sibling = PlannerNextAction::ApplyAcceptedDirective {
        accepted_event_id: EventId::new(),
        directive: evidence.accepted.resolved_directive.clone(),
    };
    assert!(accepted_planner_recovery(&sibling, &evidence, purpose).is_err());

    let mut nested_substitution = evidence.accepted.resolved_directive.clone();
    let PlannerAcceptedDirectiveV1::Delegate { delegations } = &mut nested_substitution else {
        panic!("fixture directive is Delegate");
    };
    delegations[0].work_orders[0].revision += 1;
    let substituted_action = PlannerNextAction::ApplyAcceptedDirective {
        accepted_event_id: evidence.event.id,
        directive: nested_substitution,
    };
    assert!(accepted_planner_recovery(&substituted_action, &evidence, purpose).is_err());
    assert!(
        accepted_planner_recovery(&PlannerNextAction::AwaitRunClaim, &evidence, purpose).is_err()
    );

    let mut substituted_mirror = evidence.clone();
    substituted_mirror.accepted.resolved_directive = PlannerAcceptedDirectiveV1::Delegate {
        delegations: Vec::new(),
    };
    assert!(accepted_planner_recovery(&action, &substituted_mirror, purpose).is_err());
}

#[test]
fn rejected_finalization_reprojects_then_adapter_replays_and_rejects_substitution() {
    let session_id = birdcode_protocol::SessionId::new();
    let run_id = RunId::new();
    let purpose = PlannerTurnPurposeV1::EvidenceReplan;
    let reason = PlannerTurnRejectionReasonV1::BindingMismatch;
    let event = rejected_event(session_id, run_id, purpose, reason);
    assert!(matches!(
        planner_resolution_from_finalization(finalization_outcome(
            event.clone(),
            PlannerV2FinalizationDisposition::Rejected(reason),
        ))
        .expect("rejected finalization is structurally valid"),
        PlannerFinalizationResolution::Reproject
    ));
    assert!(
        planner_resolution_from_finalization(finalization_outcome(
            event.clone(),
            PlannerV2FinalizationDisposition::Rejected(
                PlannerTurnRejectionReasonV1::DirectiveInvalid,
            ),
        ))
        .is_err()
    );
    let action = PlannerNextAction::ResolveRejectedTurn {
        rejected_event_id: event.id,
        reason,
    };

    let first = rejected_planner_recovery(&action, &event, purpose).expect("exact rejected");
    let replay = rejected_planner_recovery(&action, &event, purpose).expect("rejected replay");
    assert_eq!(first, replay);
    assert!(
        rejected_planner_recovery(
            &PlannerNextAction::ResolveRejectedTurn {
                rejected_event_id: EventId::new(),
                reason,
            },
            &event,
            purpose,
        )
        .is_err()
    );
    assert!(
        rejected_planner_recovery(
            &PlannerNextAction::ResolveRejectedTurn {
                rejected_event_id: event.id,
                reason: PlannerTurnRejectionReasonV1::DirectiveInvalid,
            },
            &event,
            purpose,
        )
        .is_err()
    );
    assert!(rejected_planner_recovery(&PlannerNextAction::AwaitRunClaim, &event, purpose).is_err());
}

#[test]
fn run_terminal_finalization_returns_direct_execution_and_rejects_state_substitution() {
    let session_id = birdcode_protocol::SessionId::new();
    let run_id = RunId::new();
    for (state, disposition) in [
        (
            RunState::Failed,
            PlannerV2FinalizationDisposition::RunFailed,
        ),
        (
            RunState::Cancelled,
            PlannerV2FinalizationDisposition::RunCancelled,
        ),
    ] {
        let event = envelope(
            session_id,
            run_id,
            EventPayload::RunStateChanged {
                from: RunState::Running,
                to: state,
            },
        );
        let resolution =
            planner_resolution_from_finalization(finalization_outcome(event.clone(), disposition))
                .expect("matching terminal finalization");
        let PlannerFinalizationResolution::Execution(PlannerTurnExecution::Terminal {
            event: resolved,
            state: resolved_state,
        }) = resolution
        else {
            panic!("run-terminal outcome must execute directly");
        };
        assert_eq!(resolved, event);
        assert_eq!(resolved_state, state);
    }

    let wrong_state = envelope(
        session_id,
        run_id,
        EventPayload::RunStateChanged {
            from: RunState::Running,
            to: RunState::Failed,
        },
    );
    assert!(
        planner_resolution_from_finalization(finalization_outcome(
            wrong_state,
            PlannerV2FinalizationDisposition::RunCancelled,
        ))
        .is_err()
    );
}

async fn assert_post_decision_cancellation_is_terminal_and_replay_safe(rejected: bool) {
    let directory = tempfile::tempdir().expect("temporary runtime");
    let paths = RuntimePaths::new(directory.path().join("state"));
    paths.prepare().expect("runtime paths prepare");
    let mut store = Store::open(paths.database(), paths.artifacts()).expect("Store opens");
    let config = RunSupervisorConfig::default();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/planner-terminal-race").into(),
        title: Some("planner terminal race".to_owned()),
    });
    let session_created = store
        .create_session(
            &session,
            NewEvent {
                session_id: session.id,
                run_id: None,
                actor_id: config.actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::SessionCreated {
                    session: session.clone(),
                },
            },
        )
        .expect("session commits");
    let run = Run::new(RunSpec {
        session_id: session.id,
        purpose: RunPurpose::ParallelRepositoryReconnaissanceV1,
        plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
        backend: BackendSelection {
            backend_id: "lmstudio".to_owned(),
            kind: BackendKind::Model,
            model: Some("gemma-4-26b".to_owned()),
            reasoning_effort: None,
        },
        input: vec![InputItem::Text {
            text: "Inspect repository".to_owned(),
        }],
        limits: RunLimits {
            max_output_tokens: Some(32_768),
            max_wall_time_seconds: Some(600),
            max_subagents: 2,
        },
    });
    let created = store
        .create_run(
            &run,
            NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id: config.actor_id,
                causal_parent: Some(session_created.id),
                provenance: provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            },
        )
        .expect("run commits");
    let claim = RunClaimed {
        claim_id: RunClaimId::new(),
        runtime_instance_id: config.runtime_instance_id,
        claim_generation: 1,
        cancellation_generation: 0,
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
    };
    let claim_event = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: Some(created.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(claim.clone()),
        })
        .expect("claim commits");
    let running = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: Some(claim_event.id),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        })
        .expect("run starts");
    let cancellation = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id: config.actor_id,
            causal_parent: Some(running.id),
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: CancellationRequestId::new(),
                cancellation_generation: 1,
            }),
        })
        .expect("cancellation commits");

    let purpose = PlannerTurnPurposeV1::InitialDelegation;
    let accepted = accepted_projection(session.id, run.id, purpose, accepted_directive());
    let rejected_event = rejected_event(
        session.id,
        run.id,
        purpose,
        PlannerTurnRejectionReasonV1::BindingMismatch,
    );
    let recovery = if rejected {
        PlannerTurnRecoveryState::Rejected {
            prepared_event: rejected_event.clone(),
            observed_event: rejected_event.clone(),
            rejected_event,
        }
    } else {
        PlannerTurnRecoveryState::Accepted {
            prepared_event: accepted.event.clone(),
            observed_event: accepted.event.clone(),
            accepted_event: accepted.event.clone(),
        }
    };
    let projection = ReconRunProjection {
        session_id: session.id,
        run_id: run.id,
        run_state: RunState::Running,
        last_event: cancellation.clone(),
        guard: ReconRunGuardProjection {
            latest_claim: Some(DurableRunClaimProjection {
                event: claim_event,
                claim,
            }),
            cancellation_event: Some(cancellation.clone()),
            cancellation_generation: 1,
            claim_matches_cancellation_generation: false,
            terminal_state_event: None,
        },
        planner: PlannerRunProjection {
            accepted_root_plan: None,
            current_base_plan: None,
            latest_accepted_plan: None,
            latest_evidence: None,
            accepted_directive: (!rejected).then_some(accepted),
            recovery,
            next_action: PlannerNextAction::CancellationRequested {
                cancellation_event_id: cancellation.id,
                cancellation_generation: 1,
            },
            prepared_turn_count: 1,
        },
        completion_gate: None,
    };
    let before = store
        .events_for_run_after(run.id, 0)
        .expect("history reads")
        .events
        .len();
    drop(store);

    for expected_growth in [1, 1] {
        assert!(matches!(
            resolve_planner_cancellation(
                paths.clone(),
                run.id,
                &projection,
                &config,
                Arc::new(ReconRuntimeClock::new()),
            )
            .await
            .expect("post-decision cancellation resolves"),
            PlannerTerminalResolution::Reproject
        ));
        let store = Store::open(paths.database(), paths.artifacts()).expect("Store reopens");
        assert_eq!(
            store
                .get_run(run.id)
                .expect("run reads")
                .expect("run exists")
                .state,
            RunState::Cancelled,
        );
        let after = store
            .events_for_run_after(run.id, 0)
            .expect("history replays")
            .events
            .len();
        assert_eq!(after, before + expected_growth);
    }
}

#[tokio::test]
async fn cancellation_after_accepted_or_rejected_decision_terminalizes_once() {
    assert_post_decision_cancellation_is_terminal_and_replay_safe(false).await;
    assert_post_decision_cancellation_is_terminal_and_replay_safe(true).await;
}
