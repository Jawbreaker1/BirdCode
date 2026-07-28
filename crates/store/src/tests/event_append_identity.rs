use super::*;

#[test]
fn appends_events_in_order_without_rewriting_history() {
    let (_directory, mut store) = test_store();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/example").into(),
        title: Some("Flerspråkig session".to_owned()),
    });
    let actor_id = ActorId::new();
    store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist with its event");

    for text in ["första", "第二"] {
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: None,
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::UserInput {
                    items: vec![birdcode_protocol::InputItem::Text {
                        text: text.to_owned(),
                    }],
                },
            })
            .expect("event should append");
    }

    let events = store
        .events_after(session.id, 0)
        .expect("events should load");
    assert_eq!(
        events
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

fn identified_user_input(
    event_id: EventId,
    session_id: SessionId,
    actor_id: ActorId,
    parent: Option<EventId>,
    text: &str,
) -> IdentifiedNewEvent {
    IdentifiedNewEvent {
        event_id,
        event: NewEvent {
            session_id,
            run_id: None,
            actor_id,
            causal_parent: parent,
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: text.to_owned(),
                }],
            },
        },
    }
}

#[test]
fn identified_append_is_exactly_idempotent_and_survives_reopen() {
    let (directory, mut store, session_created) = store_with_session_event();
    let event_id = EventId::new();
    let identified = identified_user_input(
        event_id,
        session_created.session_id,
        ActorId::new(),
        Some(session_created.id),
        "durable retry 世界",
    );
    let appended = store
        .append_identified_event(identified.clone())
        .expect("first identified append should commit");
    let IdempotentAppendOutcome::Appended { event: committed } = appended else {
        panic!("first append must not be reported as a replay");
    };
    assert_eq!(committed.id, event_id);
    let replayed = store
        .append_identified_event(identified.clone())
        .expect("same-connection retry should be idempotent");
    assert_eq!(
        replayed,
        IdempotentAppendOutcome::AlreadyPresent {
            event: committed.clone(),
        }
    );
    drop(store);

    let mut reopened = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("store should reopen");
    assert_eq!(
        reopened
            .append_identified_event(identified)
            .expect("retry after reopen should be idempotent"),
        IdempotentAppendOutcome::AlreadyPresent { event: committed }
    );
}

#[test]
fn identified_append_rejects_every_caller_field_substitution() {
    let (_directory, mut store, session_created) = store_with_session_event();
    let event_id = EventId::new();
    let identified = identified_user_input(
        event_id,
        session_created.session_id,
        ActorId::new(),
        Some(session_created.id),
        "original",
    );
    store
        .append_identified_event(identified.clone())
        .expect("fixture event should commit");

    let mut substitutions = Vec::new();
    let mut actor = identified.clone();
    actor.event.actor_id = ActorId::new();
    substitutions.push(actor);
    let mut provenance = identified.clone();
    provenance.event.provenance.producer = "substituted".to_owned();
    substitutions.push(provenance);
    let mut payload = identified.clone();
    payload.event.payload = EventPayload::UserInput {
        items: vec![InputItem::Text {
            text: "changed".to_owned(),
        }],
    };
    substitutions.push(payload);
    let mut parent = identified.clone();
    parent.event.causal_parent = None;
    substitutions.push(parent);
    let mut run = identified.clone();
    run.event.run_id = Some(RunId::new());
    substitutions.push(run);

    for substituted in substitutions {
        assert!(matches!(
            store.append_identified_event(substituted),
            Err(StoreError::IdentifiedEventConflict)
        ));
    }
    assert_eq!(
        store
            .events_after(session_created.session_id, 0)
            .expect("history should remain readable")
            .events
            .len(),
        2
    );
}

#[test]
fn concurrent_identified_retries_commit_exactly_one_event() {
    let (directory, store, session_created) = store_with_session_event();
    let database = directory.path().join("state.sqlite3");
    let artifacts = directory.path().join("artifacts");
    let identified = identified_user_input(
        EventId::new(),
        session_created.session_id,
        ActorId::new(),
        Some(session_created.id),
        "concurrent retry",
    );
    drop(store);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let barrier = std::sync::Arc::clone(&barrier);
            let database = database.clone();
            let artifacts = artifacts.clone();
            let identified = identified.clone();
            std::thread::spawn(move || {
                let mut store =
                    Store::open(database, artifacts).expect("concurrent store should open");
                barrier.wait();
                store
                    .append_identified_event(identified)
                    .expect("concurrent retry should converge")
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().expect("retry thread should not panic"))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, IdempotentAppendOutcome::Appended { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| { matches!(outcome, IdempotentAppendOutcome::AlreadyPresent { .. }) })
            .count(),
        1
    );
    let committed = outcomes
        .iter()
        .map(|outcome| match outcome {
            IdempotentAppendOutcome::Appended { event }
            | IdempotentAppendOutcome::AlreadyPresent { event } => event,
        })
        .collect::<Vec<_>>();
    assert_eq!(committed[0], committed[1]);

    let reopened = Store::open(database, artifacts).expect("store should reopen");
    assert_eq!(
        reopened
            .events_after(session_created.session_id, 0)
            .expect("history should load")
            .events
            .iter()
            .filter(|event| event.id == identified.event_id)
            .count(),
        1
    );
}

#[test]
fn failed_identified_append_rolls_back_event_and_identity_projection() {
    let (_directory, mut store) = test_store();
    let event_id = EventId::new();
    let identified = identified_user_input(
        event_id,
        SessionId::new(),
        ActorId::new(),
        None,
        "missing session",
    );
    assert!(store.append_identified_event(identified).is_err());
    let event_count: u64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE id = ?1",
            [event_id.to_string()],
            |row| row.get(0),
        )
        .expect("event count should read");
    let projection_count: u64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_identity_projection WHERE event_id = ?1",
            [event_id.to_string()],
            |row| row.get(0),
        )
        .expect("projection count should read");
    assert_eq!((event_count, projection_count), (0, 0));
}

#[test]
fn preallocated_envelopes_are_validated_and_inserted_without_metadata_substitution() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/exact-event-envelope").into(),
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

    let artifact_root = store.artifact_root.clone();
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("transaction should begin");
    let claim = preallocate_event_envelope(
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
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        },
    )
    .expect("claim envelope should preallocate");
    apply_exact_event_envelope(&transaction, &artifact_root, &claim)
        .expect("preallocated claim should validate and insert exactly");

    let running = preallocate_event_envelope(
        &transaction,
        NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(claim.id),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        },
    )
    .expect("state envelope should preallocate");
    apply_exact_event_envelope(&transaction, &artifact_root, &running)
        .expect("the exact preallocated claim id must authorize its state event");

    for expected in [&claim, &running] {
        let stored = transaction
            .query_row(
                "SELECT value_json FROM events WHERE id = ?1",
                [expected.id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .and_then(|json| {
                serde_json::from_str::<EventEnvelope>(&json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .expect("stored envelope should decode");
        assert_eq!(&stored, expected);
    }
    transaction.commit().expect("exact envelopes should commit");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the exact-envelope regression keeps insertion and all identity failures explicit"
)]
fn exact_apply_preserves_stored_metadata_and_rejects_gaps_or_missing_parents() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/exact-replay-envelope").into(),
        title: None,
    });
    let run = run_for(&session);
    let session_created = EventEnvelope {
        id: EventId::new(),
        sequence: 1,
        session_id: session.id,
        run_id: None,
        actor_id,
        causal_parent: None,
        occurred_at: DateTime::parse_from_rfc3339("2026-01-02T03:04:05.123456789Z")
            .expect("fixed replay time should parse")
            .with_timezone(&Utc),
        provenance: provenance(),
        payload: EventPayload::SessionCreated {
            session: session.clone(),
        },
    };
    let run_created = EventEnvelope {
        id: EventId::new(),
        sequence: 2,
        session_id: session.id,
        run_id: Some(run.id),
        actor_id,
        causal_parent: Some(session_created.id),
        occurred_at: session_created.occurred_at + chrono::Duration::seconds(1),
        provenance: provenance(),
        payload: EventPayload::RunCreated { run: run.clone() },
    };
    let exact = EventEnvelope {
        id: EventId::new(),
        sequence: run_created.sequence + 1,
        session_id: session.id,
        run_id: Some(run.id),
        actor_id,
        causal_parent: Some(run_created.id),
        occurred_at: run_created.occurred_at,
        provenance: provenance(),
        payload: EventPayload::UserInput {
            items: vec![InputItem::Text {
                text: "historical exact envelope".to_owned(),
            }],
        },
    };
    let artifact_root = store.artifact_root.clone();
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("transaction should begin");
    apply_exact_event_envelope(&transaction, &artifact_root, &session_created)
        .expect("the exact historical session should apply without allocation");
    apply_exact_event_envelope(&transaction, &artifact_root, &run_created)
        .expect("the exact historical run should apply without allocation");
    apply_exact_event_envelope(&transaction, &artifact_root, &exact)
        .expect("an exact historical envelope should apply without allocation");
    for expected in [&session_created, &run_created, &exact] {
        let stored = transaction
            .query_row(
                "SELECT value_json FROM events WHERE id = ?1",
                [expected.id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .and_then(|json| {
                serde_json::from_str::<EventEnvelope>(&json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .expect("the exact envelope should decode");
        assert_eq!(&stored, expected);
    }

    let duplicate_run = run_for(&session);
    let duplicate_id = EventEnvelope {
        id: exact.id,
        sequence: exact.sequence + 1,
        session_id: session.id,
        run_id: Some(duplicate_run.id),
        actor_id,
        causal_parent: Some(exact.id),
        occurred_at: exact.occurred_at + chrono::Duration::seconds(1),
        provenance: provenance(),
        payload: EventPayload::RunCreated {
            run: duplicate_run.clone(),
        },
    };
    assert!(matches!(
        apply_exact_event_envelope(&transaction, &artifact_root, &duplicate_id),
        Err(StoreError::InvalidStateEvent)
    ));
    let materialized_duplicate_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM runs WHERE id = ?1",
            [duplicate_run.id.to_string()],
            |row| row.get::<_, u64>(0),
        )
        .expect("materialized duplicate count should read");
    let projected_duplicate_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM run_state_projection WHERE run_id = ?1",
            [duplicate_run.id.to_string()],
            |row| row.get::<_, u64>(0),
        )
        .expect("projected duplicate count should read");
    assert_eq!(materialized_duplicate_count, 0);
    assert_eq!(projected_duplicate_count, 0);

    let mut duplicate_sequence = exact.clone();
    duplicate_sequence.id = EventId::new();
    assert!(matches!(
        apply_exact_event_envelope(&transaction, &artifact_root, &duplicate_sequence),
        Err(StoreError::InvalidStateEvent)
    ));

    let mut gap = exact.clone();
    gap.id = EventId::new();
    gap.sequence = exact.sequence + 2;
    gap.causal_parent = Some(exact.id);
    assert!(matches!(
        apply_exact_event_envelope(&transaction, &artifact_root, &gap),
        Err(StoreError::InvalidStateEvent)
    ));

    let mut missing_parent = exact.clone();
    missing_parent.id = EventId::new();
    missing_parent.sequence = exact.sequence + 1;
    missing_parent.causal_parent = Some(EventId::new());
    assert!(matches!(
        apply_exact_event_envelope(&transaction, &artifact_root, &missing_parent),
        Err(StoreError::InvalidStateEvent)
    ));
    let event_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM events WHERE session_id = ?1",
            [session.id.to_string()],
            |row| row.get::<_, u64>(0),
        )
        .expect("event count should read");
    assert_eq!(event_count, exact.sequence);
    transaction.commit().expect("exact envelope should commit");
}
