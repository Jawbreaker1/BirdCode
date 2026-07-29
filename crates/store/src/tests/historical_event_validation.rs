use super::*;

#[test]
fn historical_claim_validation_uses_candidate_time_not_reopen_time() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/historical-claim-time").into(),
        title: None,
    });
    let session_created = store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let run = run_for(&session);
    let run_created = store
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
        .expect("run should persist");
    let lease_expires_at = run_created.occurred_at + chrono::Duration::nanoseconds(1);
    assert!(lease_expires_at < Utc::now());

    let artifact_root = store.artifact_root.clone();
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("transaction should begin");
    let mut historical = preallocate_event_envelope(
        &transaction,
        NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(run_created.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id: RuntimeInstanceId::new(),
                claim_generation: 1,
                cancellation_generation: 0,
                lease_expires_at,
            }),
        },
    )
    .expect("historical envelope should preallocate");
    historical.occurred_at = run_created.occurred_at;
    validate_generic_event(
        &transaction,
        &historical,
        &artifact_root,
        EventAdmission::PublicAppend,
    )
    .expect("a claim live at its durable candidate time remains historically valid");

    let mut at_expiry = historical;
    at_expiry.occurred_at = lease_expires_at;
    assert!(matches!(
        validate_generic_event(
            &transaction,
            &at_expiry,
            &artifact_root,
            EventAdmission::PublicAppend,
        ),
        Err(StoreError::InvalidStateEvent)
    ));
    transaction
        .rollback()
        .expect("historical validation should not mutate the store");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "three durable claims make the exclusive historical horizon explicit"
)]
fn historical_claim_lookup_ignores_claims_after_the_candidate_horizon() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let runtime_instance_id = RuntimeInstanceId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/claim-prefix-replay").into(),
        title: None,
    });
    let session_created = store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let run = run_for(&session);
    let run_created = store
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
        .expect("run should persist");
    let first_claim = store
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
        .expect("first claim should persist");
    let running = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(first_claim.id),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        })
        .expect("run should start");
    let second_claim = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(running.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id,
                claim_generation: 2,
                cancellation_generation: 0,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        })
        .expect("second claim should persist");
    let historical_candidate = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(second_claim.id),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "historical claim horizon".to_owned(),
                }],
            },
        })
        .expect("historical candidate position should persist");
    let third_claim = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(historical_candidate.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id,
                claim_generation: 3,
                cancellation_generation: 0,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        })
        .expect("later claim should persist");

    let historical = latest_claim_for_run_before(
        &store.connection,
        session.id,
        run.id,
        historical_candidate.sequence,
    )
    .expect("historical claim lookup should succeed")
    .expect("a historical claim should exist");
    assert_eq!(historical.id, second_claim.id);
    assert_eq!(
        latest_claim_for_run(&store.connection, session.id, run.id)
            .expect("latest claim lookup should succeed")
            .expect("latest claim should exist")
            .id,
        third_claim.id
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the adversarial future record and historical terminal remain fully explicit"
)]
fn historical_cancellation_cause_ignores_later_cancellation_records() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/cancellation-prefix-replay").into(),
        title: None,
    });
    let session_created = store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let run = run_for(&session);
    let run_created = store
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
        .expect("run should persist");
    let request_id = birdcode_protocol::CancellationRequestId::new();
    let cancellation = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(run_created.id),
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: request_id,
                cancellation_generation: 1,
            }),
        })
        .expect("first cancellation should persist");
    let historical_terminal_position = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(cancellation.id),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "historical terminal position".to_owned(),
                }],
            },
        })
        .expect("historical terminal position should persist");

    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("transaction should begin");
    let later = preallocate_event_envelope(
        &transaction,
        NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(historical_terminal_position.id),
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: birdcode_protocol::CancellationRequestId::new(),
                cancellation_generation: 2,
            }),
        },
    )
    .expect("later raw fixture should preallocate");
    insert_event_in_transaction(&transaction, &later)
        .expect("later adversarial cancellation fixture should insert");
    transaction.commit().expect("fixture should commit");

    let historical_terminal = EventEnvelope {
        id: EventId::new(),
        sequence: historical_terminal_position.sequence,
        session_id: session.id,
        run_id: Some(run.id),
        actor_id,
        causal_parent: Some(cancellation.id),
        occurred_at: historical_terminal_position.occurred_at,
        provenance: provenance(),
        payload: EventPayload::BackendEvent {
            event_type: "historical-child-terminal-fixture".to_owned(),
            data: serde_json::json!({}),
        },
    };
    validate_child_cancellation_cause(
        &store.connection,
        &historical_terminal,
        &ChildCancellationCauseV1 {
            request_event_id: cancellation.id,
            request_id,
            cancellation_generation: 1,
        },
    )
    .expect("a later cancellation must not invalidate the historical cause");
    assert_eq!(
        latest_cancellation_generation_before(
            &store.connection,
            session.id,
            run.id,
            historical_terminal.sequence,
        )
        .expect("historical cancellation generation should read"),
        1
    );
    assert_eq!(
        latest_cancellation_generation(&store.connection, session.id, run.id)
            .expect("latest cancellation generation should read"),
        2
    );
}

#[test]
fn generic_event_routing_has_only_explicit_mechanical_pass_throughs() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/closed-event-routing").into(),
        title: None,
    });
    let creation = store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let raw = store
        .put_artifact(b"{}", "application/json")
        .expect("raw backend artifact should persist");
    let before = store.events_after(session.id, 0).unwrap().events.len();

    assert!(matches!(
        store.append_event(session_event(&session, actor_id)),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        store.append_event(NewEvent {
            session_id: session.id,
            run_id: None,
            actor_id,
            causal_parent: Some(creation.id),
            provenance: Provenance {
                producer: "closed-routing-test".to_owned(),
                backend: None,
                raw_artifact: Some(raw.clone()),
            },
            payload: EventPayload::BackendEvent {
                event_type: "must-remain-run-scoped".to_owned(),
                data: serde_json::json!({}),
            },
        }),
        Err(StoreError::InvalidStateEvent)
    ));
    store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: None,
            actor_id,
            causal_parent: Some(creation.id),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "explicit mechanical input".to_owned(),
                }],
            },
        })
        .expect("explicit user input pass-through should remain valid");
    store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: None,
            actor_id,
            causal_parent: None,
            provenance: provenance(),
            payload: EventPayload::ArtifactStored { artifact: raw },
        })
        .expect("explicit artifact pass-through should remain valid");
    assert_eq!(
        store.events_after(session.id, 0).unwrap().events.len(),
        before + 2
    );
}

#[test]
fn child_replay_bounds_reject_the_prospective_overflow_before_insertion() {
    assert_eq!(
        PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD, 256,
        "claim refresh has an explicit product budget independent of attempts"
    );
    assert_eq!(
        PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_TAKEOVERS_PER_CHILD, 2,
        "ownership recovery has a separate bounded takeover margin"
    );
    const {
        assert!(
            PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD
                > CHILD_RECONNAISSANCE_MAX_ATTEMPTS
        );
    }
    assert_eq!(
        MAX_CHILD_REPLAY_EVENTS,
        1 + PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD
            + CHILD_RECONNAISSANCE_MAX_ATTEMPTS
                * (3 + 2 * CHILD_RECONNAISSANCE_MAX_MODEL_CALLS_PER_ATTEMPT
                    + 3 * CHILD_RECONNAISSANCE_MAX_TOOL_CALLS_PER_ATTEMPT)
    );
    assert!(
        validate_child_replay_admission(MAX_CHILD_REPLAY_EVENTS as usize - 1, 0, 0, None,).is_ok()
    );
    assert!(matches!(
        validate_child_replay_admission(MAX_CHILD_REPLAY_EVENTS as usize, 0, 0, None),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        validate_child_replay_admission(
            MAX_CHILD_REPLAY_EVENTS as usize - 1,
            PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_ADOPTIONS_PER_CHILD as usize,
            0,
            Some(ChildClaimAdoptionKindV1::Renewal),
        ),
        Err(StoreError::InvalidStateEvent)
    ));
    assert!(matches!(
        validate_child_replay_admission(
            MAX_CHILD_REPLAY_EVENTS as usize - 1,
            PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_TAKEOVERS_PER_CHILD as usize,
            PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_TAKEOVERS_PER_CHILD as usize,
            Some(ChildClaimAdoptionKindV1::Takeover),
        ),
        Err(StoreError::InvalidStateEvent)
    ));
    validate_child_replay_admission(
        MAX_CHILD_REPLAY_EVENTS as usize - 1,
        PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_TAKEOVERS_PER_CHILD as usize,
        PARALLEL_RECONNAISSANCE_V1_MAX_CLAIM_TAKEOVERS_PER_CHILD as usize,
        Some(ChildClaimAdoptionKindV1::Renewal),
    )
    .expect("takeover exhaustion must not consume the independent renewal budget");
}

#[test]
fn raw_insert_or_replace_cannot_rewrite_an_existing_event_id() {
    let (_directory, store, original) = store_with_session_event();
    let recursive_triggers = store
        .connection
        .pragma_query_value(None, "recursive_triggers", |row| row.get::<_, bool>(0))
        .expect("recursive_triggers should read");
    assert!(!recursive_triggers);

    let error = store
        .connection
        .execute(
            "INSERT OR REPLACE INTO events (
                 id, session_id, run_id, causal_parent, sequence, value_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                original.id.to_string(),
                original.session_id.to_string(),
                Option::<String>::None,
                Option::<String>::None,
                original.sequence + 1,
                serde_json::to_string(&original).expect("event should encode")
            ],
        )
        .expect_err("existing event id must not be replaceable");
    assert_append_only_abort(error);
    assert_eq!(
        store
            .events_after(original.session_id, 0)
            .expect("history should remain readable")
            .events,
        vec![original]
    );
}

#[test]
fn raw_insert_or_replace_cannot_rewrite_a_session_sequence() {
    let (_directory, store, original) = store_with_session_event();
    let replacement_id = EventId::new();

    let error = store
        .connection
        .execute(
            "INSERT OR REPLACE INTO events (
                 id, session_id, run_id, causal_parent, sequence, value_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                replacement_id.to_string(),
                original.session_id.to_string(),
                Option::<String>::None,
                Option::<String>::None,
                original.sequence,
                serde_json::to_string(&original).expect("event should encode")
            ],
        )
        .expect_err("existing session sequence must not be replaceable");
    assert_append_only_abort(error);
    assert_eq!(
        store
            .events_after(original.session_id, 0)
            .expect("history should remain readable")
            .events,
        vec![original]
    );
}
