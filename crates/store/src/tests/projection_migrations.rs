use super::*;

#[test]
fn oversized_v3_event_is_rejected_without_empty_cursor_loop_or_large_read() {
    let (directory, store, original) = store_with_session_event();
    drop_current_projection_objects(&store.connection);
    store
        .connection
        .execute_batch(
            "DROP TRIGGER events_reject_oversized_insert;
             DROP TABLE runtime_health_canary;
             PRAGMA user_version = 3;",
        )
        .expect("test database should be restored to canonical v3");
    store
        .connection
        .execute(
            "INSERT INTO events (
                 id, session_id, run_id, causal_parent, sequence, value_json
             ) VALUES (?1, ?2, NULL, NULL, ?3, ?4)",
            params![
                EventId::new().to_string(),
                original.session_id.to_string(),
                original.sequence + 1,
                "x".repeat(MAX_INLINE_EVENT_BYTES + 1),
            ],
        )
        .expect("legacy oversized fixture should insert");

    assert!(matches!(
        store.events_after(original.session_id, original.sequence),
        Err(StoreError::EventTooLarge)
    ));
    drop(store);
    assert!(matches!(
        Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        ),
        Err(StoreError::IncompatibleSchema { found: 5, .. })
    ));
    let connection = Connection::open(directory.path().join("state.sqlite3"))
        .expect("checkpointed oversized fixture should reopen");
    assert!(table_exists(&connection, "store_upgrade_progress").unwrap());
}

#[test]
fn run_state_query_uses_the_canonical_non_unique_sequence_index() {
    let (_directory, store) = test_store();
    let index_sql = store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'index' AND name = 'events_by_run_sequence'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("run sequence index should exist");
    assert_eq!(
        normalize_sql(&index_sql),
        normalize_sql(EVENT_RUN_SEQUENCE_INDEX_SQL)
    );
    let is_unique = store
        .connection
        .query_row(
            "SELECT \"unique\" FROM pragma_index_list('events')
             WHERE name = 'events_by_run_sequence'",
            [],
            |row| row.get::<_, bool>(0),
        )
        .expect("index metadata should exist");
    assert!(!is_unique);

    let mut statement = store
        .connection
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT value_json FROM events
             WHERE run_id = ?1 ORDER BY sequence ASC",
        )
        .expect("query plan should prepare");
    let details = statement
        .query_map([RunId::new().to_string()], |row| row.get::<_, String>(3))
        .expect("query plan should execute")
        .collect::<Result<Vec<_>, _>>()
        .expect("query plan should collect");
    assert!(
        details
            .iter()
            .any(|detail| detail.contains("USING INDEX events_by_run_sequence")),
        "unexpected query plan: {details:?}"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one regression covers projection writes, bounded reads, plans, and migration"
)]
fn schema_v7_materializes_state_and_get_run_never_scans_event_history() {
    let (directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/projected-run").into(),
        title: None,
    });
    store
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
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            },
        )
        .expect("run should persist");
    let claim = store
        .append_event(NewEvent {
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
        })
        .expect("run claim should persist");
    store
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
        .expect("state transition should atomically update projection");
    for index in 0..=EVENT_PAGE_SIZE {
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::UserInput {
                    items: vec![InputItem::Text {
                        text: format!("history {index}"),
                    }],
                },
            })
            .expect("long history should append");
    }
    assert_eq!(
        store.get_run(run.id).unwrap().unwrap().state,
        RunState::Running
    );
    let projected = store
        .connection
        .query_row(
            "SELECT state, state_sequence FROM run_state_projection WHERE run_id = ?1",
            [run.id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
        )
        .expect("projection should read");
    assert_eq!(projected, ("running".to_owned(), 4));

    let plan = {
        let mut statement = store
            .connection
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT runs.value_json, run_state_projection.state
                 FROM runs
                 JOIN run_state_projection
                   ON run_state_projection.run_id = runs.id
                  AND run_state_projection.session_id = runs.session_id
                 WHERE runs.id = ?1",
            )
            .expect("projection query should prepare");
        statement
            .query_map([run.id.to_string()], |row| row.get::<_, String>(3))
            .expect("query plan should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("query plan should collect")
    };
    assert!(plan.iter().all(|detail| !detail.contains("events")));
    assert!(plan.iter().all(|detail| !detail.contains("SCAN runs")));

    rewrite_plan_acceptance_as_protocol_v4(&store);
    drop_current_projection_objects(&store.connection);
    store
        .connection
        .execute_batch("PRAGMA user_version = 6;")
        .expect("fixture should downgrade to schema v6");
    drop(store);
    let migrated = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("schema v6 should rebuild its state projection");
    assert_eq!(
        migrated.get_run(run.id).unwrap().unwrap().state,
        RunState::Running
    );
    assert_eq!(
        schema_version(&migrated.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture exercises two independent crash checkpoints across every upgrade phase"
)]
fn schema_v6_upgrade_resumes_mid_replay_and_mid_projection() {
    let (directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/resumable-v6-upgrade").into(),
        title: None,
    });
    store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let mut runs = Vec::new();
    let mut first_run_created = None;
    for _ in 0..=MIGRATION_ROW_BATCH_SIZE {
        let run = run_for(&session);
        let created = store
            .create_run(
                &run,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: None,
                    provenance: provenance(),
                    payload: EventPayload::RunCreated { run: run.clone() },
                },
            )
            .expect("run should persist");
        first_run_created.get_or_insert(created.id);
        runs.push(run);
    }
    let claim = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(runs[0].id),
            actor_id,
            causal_parent: first_run_created,
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id: RuntimeInstanceId::new(),
                claim_generation: 1,
                cancellation_generation: 0,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        })
        .expect("run claim should persist");
    store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(runs[0].id),
            actor_id,
            causal_parent: Some(claim.id),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        })
        .expect("state transition should persist");
    rewrite_plan_acceptance_as_protocol_v4(&store);
    drop_current_projection_objects(&store.connection);
    store
        .connection
        .execute_batch("PRAGMA user_version = 6;")
        .expect("fixture should become schema v6");
    drop(store);

    let database = directory.path().join("state.sqlite3");
    let artifacts = directory.path().join("artifacts");
    let mut connection = Connection::open(&database).expect("schema v6 should open");
    connection
        .pragma_update(None, "foreign_keys", true)
        .expect("foreign keys should enable");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("upgrade should begin");
    begin_store_upgrade(&transaction, PATH_WIRE_SCHEMA_VERSION)
        .expect("upgrade journal should initialize");
    transaction.commit().expect("upgrade journal should commit");

    loop {
        let progress = read_store_upgrade_progress(&connection).unwrap();
        if progress.phase == "replay_events" && progress.cursor_sequence > 0 {
            assert!(progress.cursor_sequence < 67);
            break;
        }
        resume_store_upgrade_batch(&mut connection, &artifacts)
            .expect("bounded replay batch should advance");
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM store_upgrade_replay_runs",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap(),
        MIGRATION_ROW_BATCH_SIZE + 1
    );
    drop(connection);

    let mut connection = Connection::open(&database).expect("checkpoint should reopen");
    connection
        .pragma_update(None, "foreign_keys", true)
        .expect("foreign keys should enable after restart");
    loop {
        let progress = read_store_upgrade_progress(&connection).unwrap();
        if progress.phase == "project_runs" {
            break;
        }
        resume_store_upgrade_batch(&mut connection, &artifacts)
            .expect("replay should resume from its event cursor");
    }
    resume_store_upgrade_batch(&mut connection, &artifacts)
        .expect("one bounded projection batch should commit");
    let progress = read_store_upgrade_progress(&connection).unwrap();
    assert_eq!(progress.phase, "project_runs");
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM run_state_projection", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        MIGRATION_ROW_BATCH_SIZE
    );
    drop(connection);

    let resumed = Store::open(&database, &artifacts)
        .expect("Store must return only after projection and schema finalize");
    assert!(!table_exists(&resumed.connection, "store_upgrade_progress").unwrap());
    assert_eq!(
        schema_version(&resumed.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        resumed.get_run(runs[0].id).unwrap().unwrap().state,
        RunState::Running
    );
    for run in &runs[1..] {
        assert_eq!(
            resumed.get_run(run.id).unwrap().unwrap().state,
            RunState::Queued
        );
    }
}

#[test]
fn replay_validation_uses_partial_invalid_indexes_instead_of_full_scans() {
    let connection = Connection::open_in_memory().expect("in-memory database should open");
    connection
        .execute_batch(STORE_UPGRADE_CONTROL_SQL)
        .expect("upgrade scratch schema should initialize");
    for (query, expected_index) in [
        (
            "SELECT id FROM store_upgrade_replay_sessions
             WHERE creation_count != 1 LIMIT 1",
            "store_upgrade_sessions_invalid_creation",
        ),
        (
            "SELECT id FROM store_upgrade_replay_runs
             WHERE creation_count != 1 LIMIT 1",
            "store_upgrade_runs_invalid_creation",
        ),
        (
            "SELECT id FROM store_upgrade_replay_runs
             WHERE state_sequence < 1 LIMIT 1",
            "store_upgrade_runs_without_state_sequence",
        ),
    ] {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
            .expect("validation plan should prepare");
        let details = statement
            .query_map([], |row| row.get::<_, String>(3))
            .expect("validation plan should execute")
            .collect::<Result<Vec<_>, _>>()
            .expect("validation plan should collect");
        assert!(
            details.iter().any(|detail| detail.contains(expected_index)),
            "expected {expected_index} in query plan: {details:?}"
        );
    }
}

#[test]
fn schema_v5_and_v6_upgrades_reject_run_dependencies_before_creation() {
    for source_version in [HEALTH_CANARY_SCHEMA_VERSION, PATH_WIRE_SCHEMA_VERSION] {
        let directory = TempDir::new().expect("temporary directory should be created");
        let database = directory
            .path()
            .join(format!("late-run-v{source_version}.sqlite3"));
        let artifacts = directory
            .path()
            .join(format!("late-run-v{source_version}-artifacts"));
        let mut store = Store::open(&database, &artifacts).expect("store should open");
        let actor_id = ActorId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/late-run-creation").into(),
            title: None,
        });
        let session_event = store
            .create_session(&session, session_event(&session, actor_id))
            .expect("session should persist");
        let run = run_for(&session);
        let mut run_event = store
            .create_run(
                &run,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(session_event.id),
                    provenance: provenance(),
                    payload: EventPayload::RunCreated { run: run.clone() },
                },
            )
            .expect("run should persist");

        drop_current_projection_objects(&store.connection);
        store
            .connection
            .execute_batch(
                "DROP TRIGGER events_are_immutable_on_update;
                 DROP TRIGGER events_are_immutable_on_delete;",
            )
            .expect("fixture should suspend event immutability");
        run_event.sequence = 3;
        store
            .connection
            .execute(
                "UPDATE events SET sequence = ?1, value_json = ?2 WHERE id = ?3",
                params![
                    run_event.sequence,
                    serde_json::to_string(&run_event).unwrap(),
                    run_event.id.to_string()
                ],
            )
            .expect("run creation should move after its dependency");
        store
            .connection
            .execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)
            .expect("fixture should restore event immutability");
        let transition = EventEnvelope {
            id: EventId::new(),
            sequence: 2,
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(session_event.id),
            occurred_at: Utc::now(),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        };
        store
            .connection
            .execute(
                "INSERT INTO events (
                     id, session_id, run_id, causal_parent, sequence, value_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    transition.id.to_string(),
                    transition.session_id.to_string(),
                    transition.run_id.map(|id| id.to_string()),
                    transition.causal_parent.map(|id| id.to_string()),
                    transition.sequence,
                    serde_json::to_string(&transition).unwrap()
                ],
            )
            .expect("late-creation transition fixture should insert");
        store
            .connection
            .pragma_update(None, "user_version", source_version)
            .expect("source version should set");
        drop(store);

        assert!(matches!(
            Store::open(&database, &artifacts),
            Err(StoreError::IncompatibleSchema { found, .. }) if found == source_version
        ));
        let connection = Connection::open(&database).expect("failed upgrade should reopen");
        assert!(table_exists(&connection, "store_upgrade_progress").unwrap());
        assert_eq!(schema_version(&connection).unwrap(), source_version);
    }
}

#[test]
fn v5_path_migration_reaches_rows_beyond_its_internal_batch() {
    let (directory, mut store) = test_store();
    let mut last = None;
    for index in 0..=MIGRATION_ROW_BATCH_SIZE {
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from(format!("/tmp/batched-{index}")).into(),
            title: None,
        });
        let event = store
            .create_session(&session, session_event(&session, ActorId::new()))
            .expect("batched session should persist");
        last = Some((session, event));
    }
    let (last_session, last_event) = last.expect("fixture should create sessions");
    rewrite_workspace_paths_as_protocol_v1(&store, &last_session, &last_event);
    downgrade_store_to_schema(&store, HEALTH_CANARY_SCHEMA_VERSION);
    drop(store);

    let migrated = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("batched schema-v5 paths should migrate");
    assert_eq!(
        migrated
            .get_session(last_session.id)
            .expect("last migrated session should load"),
        Some(last_session.clone())
    );
    assert_workspace_paths_are_canonical(&migrated, last_session.id, last_event.id);
}

#[test]
fn concurrent_open_serializes_fresh_initialization_and_v1_migration() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let fresh_database = directory.path().join("fresh.sqlite3");
    let fresh_artifacts = directory.path().join("fresh-artifacts");
    assert_two_concurrent_opens(&fresh_database, &fresh_artifacts);
    let fresh =
        Store::open(&fresh_database, &fresh_artifacts).expect("initialized store should reopen");
    assert_eq!(
        schema_version(&fresh.connection).expect("fresh version should read"),
        CURRENT_SCHEMA_VERSION
    );
    drop(fresh);

    let legacy_database = directory.path().join("legacy-concurrent.sqlite3");
    let legacy_artifacts = directory.path().join("legacy-concurrent-artifacts");
    let (session, run, _) = create_legacy_database(&legacy_database, false);
    assert_two_concurrent_opens(&legacy_database, &legacy_artifacts);
    let migrated = Store::open(&legacy_database, &legacy_artifacts)
        .expect("concurrently migrated store should reopen");
    assert_eq!(
        schema_version(&migrated.connection).expect("migrated version should read"),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        migrated
            .get_session(session.id)
            .expect("session should load after concurrent migration"),
        Some(session)
    );
    assert_eq!(
        migrated
            .get_run(run.id)
            .expect("run should load after concurrent migration"),
        Some(run.clone())
    );
    assert_eq!(
        migrated
            .events_after(run.spec.session_id, 0)
            .expect("migrated history should replay")
            .events
            .len(),
        2
    );
}

#[test]
fn concurrent_open_serializes_the_checkpointed_v6_upgrade() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let database = directory.path().join("v6-concurrent.sqlite3");
    let artifacts = directory.path().join("v6-concurrent-artifacts");
    let mut store = Store::open(&database, &artifacts).expect("current store should open");
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/concurrent-v6").into(),
        title: None,
    });
    let actor_id = ActorId::new();
    store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let mut runs = Vec::new();
    for _ in 0..=(MIGRATION_ROW_BATCH_SIZE * 4) {
        let run = run_for(&session);
        store
            .create_run(
                &run,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: None,
                    provenance: provenance(),
                    payload: EventPayload::RunCreated { run: run.clone() },
                },
            )
            .expect("run should persist");
        runs.push(run);
    }
    rewrite_plan_acceptance_as_protocol_v4(&store);
    for run in &mut runs {
        run.spec.plan_acceptance = PlanAcceptanceContract::LegacyMechanicalOnlyV4;
    }
    drop_current_projection_objects(&store.connection);
    store
        .connection
        .execute_batch("PRAGMA user_version = 6;")
        .expect("fixture should become schema v6");
    drop(store);

    assert_two_concurrent_opens(&database, &artifacts);
    let upgraded = Store::open(&database, &artifacts).expect("upgraded store should reopen");
    assert_eq!(
        schema_version(&upgraded.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    for run in runs {
        assert_eq!(upgraded.get_run(run.id).unwrap(), Some(run));
    }
}

#[test]
fn canonicalizes_legacy_creation_payloads_and_preserves_causality() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let database = directory.path().join("legacy.sqlite3");
    let (session, run, creation_ids) = create_legacy_database(&database, true);
    let (session_event_id, run_event_id) = creation_ids.expect("legacy events should exist");
    let store = Store::open(&database, directory.path().join("artifacts"))
        .expect("legacy database should migrate");

    let events = store
        .events_after(session.id, 0)
        .expect("canonical events should replay");
    assert_eq!(events.events.len(), 2);
    assert_eq!(events.events[0].id, session_event_id);
    assert_eq!(events.events[1].id, run_event_id);
    assert_eq!(events.events[1].causal_parent, Some(session_event_id));
    assert!(matches!(
        &events.events[0].payload,
        EventPayload::SessionCreated { session: value } if value == &session
    ));
    assert!(matches!(
        &events.events[1].payload,
        EventPayload::RunCreated { run: value } if value == &run
    ));
}
