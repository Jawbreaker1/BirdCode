use super::*;

#[test]
fn v1_migration_preserves_interleaved_run_creation_parented_to_user_input() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let database = directory.path().join("legacy-interleaved.sqlite3");
    let (session, _run, creation_ids) = create_legacy_database(&database, true);
    let (session_event_id, run_event_id) = creation_ids.expect("legacy events should exist");
    let user_input_id = EventId::new();
    let user_input = EventEnvelope {
        id: user_input_id,
        sequence: 2,
        session_id: session.id,
        run_id: None,
        actor_id: ActorId::new(),
        causal_parent: Some(session_event_id),
        occurred_at: Utc::now(),
        provenance: provenance(),
        payload: EventPayload::UserInput {
            items: vec![InputItem::Text {
                text: "planera först".to_owned(),
            }],
        },
    };
    let connection = Connection::open(&database).expect("legacy database should reopen");
    let run_json = connection
        .query_row(
            "SELECT value_json FROM events WHERE id = ?1",
            [run_event_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .expect("legacy run creation should read");
    let mut run_json = serde_json::from_str::<serde_json::Value>(&run_json)
        .expect("legacy run creation should parse");
    run_json["sequence"] = serde_json::json!(3);
    run_json["causal_parent"] = serde_json::json!(user_input_id);
    connection
        .execute(
            "UPDATE events SET sequence = 3, value_json = ?1 WHERE id = ?2",
            params![run_json.to_string(), run_event_id.to_string()],
        )
        .expect("legacy run creation should move after user input");
    connection
        .execute(
            "INSERT INTO events (id, session_id, run_id, sequence, value_json)
             VALUES (?1, ?2, NULL, 2, ?3)",
            params![
                user_input_id.to_string(),
                session.id.to_string(),
                serde_json::to_string(&user_input).expect("user input should encode")
            ],
        )
        .expect("interleaved user input should insert");
    drop(connection);

    let store = Store::open(&database, directory.path().join("artifacts"))
        .expect("interleaved legacy history should migrate");
    let events = store
        .events_after(session.id, 0)
        .expect("migrated history should replay")
        .events;
    assert_eq!(
        events.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![session_event_id, user_input_id, run_event_id]
    );
    assert_eq!(events[2].causal_parent, Some(user_input_id));
    assert_eq!(events[2].sequence, 3);
}

#[test]
fn mixed_legacy_history_places_synthesized_run_before_dependent_events() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let database = directory.path().join("legacy.sqlite3");
    let (session, run, creation_ids) = create_legacy_database(&database, true);
    let (session_event_id, run_event_id) = creation_ids.expect("legacy events should exist");
    let dependent_id = EventId::new();
    let dependent = EventEnvelope {
        id: dependent_id,
        sequence: 2,
        session_id: session.id,
        run_id: Some(run.id),
        actor_id: ActorId::new(),
        causal_parent: Some(session_event_id),
        occurred_at: Utc::now(),
        provenance: provenance(),
        payload: EventPayload::UserInput {
            items: vec![InputItem::Text {
                text: "bevarad".to_owned(),
            }],
        },
    };
    let connection = Connection::open(&database).expect("legacy database should reopen");
    connection
        .execute(
            "DELETE FROM events WHERE id = ?1",
            [run_event_id.to_string()],
        )
        .expect("legacy run creation should be removed");
    connection
        .execute(
            "INSERT INTO events (id, session_id, run_id, sequence, value_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                dependent.id.to_string(),
                session.id.to_string(),
                run.id.to_string(),
                dependent.sequence,
                serde_json::to_string(&dependent).expect("dependent event should encode")
            ],
        )
        .expect("dependent legacy event should insert");
    drop(connection);

    let store = Store::open(&database, directory.path().join("artifacts"))
        .expect("mixed legacy history should migrate");
    let events = store
        .events_after(session.id, 0)
        .expect("migrated events should replay");
    assert_eq!(events.events.len(), 3);
    assert_eq!(events.events[0].id, session_event_id);
    assert!(matches!(
        events.events[0].payload,
        EventPayload::SessionCreated { .. }
    ));
    assert!(matches!(
        events.events[1].payload,
        EventPayload::RunCreated { .. }
    ));
    assert_eq!(
        events.events[1].provenance.producer,
        "birdcode-store-migration/v1-to-v2"
    );
    assert_eq!(events.events[2].id, dependent_id);
    assert!(matches!(
        events.events[2].payload,
        EventPayload::UserInput { .. }
    ));
    assert_eq!(
        events
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one regression covers late, missing, and non-causal v1 creation histories"
)]
fn v1_creation_and_causal_order_is_fail_closed_but_missing_creation_is_synthesized() {
    let late_directory = TempDir::new().expect("temporary directory should be created");
    let late_database = late_directory.path().join("late-run-created.sqlite3");
    let (late_session, late_run, creation_ids) = create_legacy_database(&late_database, true);
    let (late_session_event_id, late_run_event_id) =
        creation_ids.expect("legacy creation events should exist");
    let late_connection = Connection::open(&late_database).expect("legacy database should open");
    let late_run_json = late_connection
        .query_row(
            "SELECT value_json FROM events WHERE id = ?1",
            [late_run_event_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .expect("legacy run event should read");
    let mut late_run_json = serde_json::from_str::<serde_json::Value>(&late_run_json)
        .expect("legacy run event should decode");
    late_run_json["sequence"] = serde_json::json!(3);
    late_connection
        .execute(
            "UPDATE events SET sequence = 3, value_json = ?1 WHERE id = ?2",
            params![late_run_json.to_string(), late_run_event_id.to_string()],
        )
        .expect("run creation should move after its dependency");
    let late_dependency = EventEnvelope {
        id: EventId::new(),
        sequence: 2,
        session_id: late_session.id,
        run_id: Some(late_run.id),
        actor_id: ActorId::new(),
        causal_parent: Some(late_session_event_id),
        occurred_at: Utc::now(),
        provenance: provenance(),
        payload: EventPayload::UserInput {
            items: vec![InputItem::Text {
                text: "dependency before creation".to_owned(),
            }],
        },
    };
    late_connection
        .execute(
            "INSERT INTO events (id, session_id, run_id, sequence, value_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                late_dependency.id.to_string(),
                late_dependency.session_id.to_string(),
                late_dependency.run_id.map(|id| id.to_string()),
                late_dependency.sequence,
                serde_json::to_string(&late_dependency).unwrap()
            ],
        )
        .expect("late-creation dependency should insert");
    drop(late_connection);
    assert!(matches!(
        Store::open(
            &late_database,
            late_directory.path().join("late-run-artifacts")
        ),
        Err(StoreError::IncompatibleSchema { found: 1, .. })
    ));

    let missing_directory = TempDir::new().expect("temporary directory should be created");
    let missing_database = missing_directory.path().join("missing-run-created.sqlite3");
    let (missing_session, missing_run, creation_ids) =
        create_legacy_database(&missing_database, true);
    let (missing_session_event_id, missing_run_event_id) =
        creation_ids.expect("legacy creation events should exist");
    let missing_connection =
        Connection::open(&missing_database).expect("legacy database should open");
    missing_connection
        .execute(
            "DELETE FROM events WHERE id = ?1",
            [missing_run_event_id.to_string()],
        )
        .expect("run creation should be removed");
    let transition = EventEnvelope {
        id: EventId::new(),
        sequence: 2,
        session_id: missing_session.id,
        run_id: Some(missing_run.id),
        actor_id: ActorId::new(),
        causal_parent: Some(missing_session_event_id),
        occurred_at: Utc::now(),
        provenance: provenance(),
        payload: EventPayload::RunStateChanged {
            from: RunState::Queued,
            to: RunState::Running,
        },
    };
    missing_connection
        .execute(
            "INSERT INTO events (id, session_id, run_id, sequence, value_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                transition.id.to_string(),
                transition.session_id.to_string(),
                transition.run_id.map(|id| id.to_string()),
                transition.sequence,
                serde_json::to_string(&transition).unwrap()
            ],
        )
        .expect("transition without creation should insert");
    drop(missing_connection);
    let migrated = Store::open(
        &missing_database,
        missing_directory.path().join("missing-run-artifacts"),
    )
    .expect("missing run creation should be synthesized before the transition");
    assert_eq!(
        migrated.get_run(missing_run.id).unwrap().unwrap().state,
        RunState::Running
    );
    let events = migrated.events_after(missing_session.id, 0).unwrap().events;
    assert!(matches!(events[1].payload, EventPayload::RunCreated { .. }));
    assert_eq!(events[2].id, transition.id);

    let causal_directory = TempDir::new().expect("temporary directory should be created");
    let causal_database = causal_directory.path().join("self-parent.sqlite3");
    let (causal_session, _, _) = create_legacy_database(&causal_database, true);
    let causal_connection =
        Connection::open(&causal_database).expect("legacy database should open");
    let self_parent_id = EventId::new();
    let self_parent = EventEnvelope {
        id: self_parent_id,
        sequence: 3,
        session_id: causal_session.id,
        run_id: None,
        actor_id: ActorId::new(),
        causal_parent: Some(self_parent_id),
        occurred_at: Utc::now(),
        provenance: provenance(),
        payload: EventPayload::UserInput {
            items: vec![InputItem::Text {
                text: "self-parent".to_owned(),
            }],
        },
    };
    causal_connection
        .execute(
            "INSERT INTO events (id, session_id, run_id, sequence, value_json)
             VALUES (?1, ?2, NULL, ?3, ?4)",
            params![
                self_parent.id.to_string(),
                self_parent.session_id.to_string(),
                self_parent.sequence,
                serde_json::to_string(&self_parent).unwrap()
            ],
        )
        .expect("self-parent fixture should insert");
    drop(causal_connection);
    assert!(matches!(
        Store::open(
            &causal_database,
            causal_directory.path().join("self-parent-artifacts")
        ),
        Err(StoreError::IncompatibleSchema { found: 1, .. })
    ));
}
