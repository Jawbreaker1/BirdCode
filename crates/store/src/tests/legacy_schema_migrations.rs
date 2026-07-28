use super::*;

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the migration regression also proves new writes require a durable live claim"
)]
fn migrates_materialized_v1_state_into_self_contained_creation_events() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let database = directory.path().join("legacy.sqlite3");
    let (session, run, _) = create_legacy_database(&database, false);
    let mut store = Store::open(&database, directory.path().join("artifacts"))
        .expect("legacy database should migrate");

    let events = store
        .events_after(session.id, 0)
        .expect("migrated events should replay");
    assert_eq!(events.events.len(), 2);
    assert_eq!(events.events[0].sequence, 1);
    assert_eq!(events.events[1].sequence, 2);
    assert_eq!(
        events.events[0].provenance.producer,
        "birdcode-store-migration/v1-to-v2"
    );
    assert!(matches!(
        &events.events[0].payload,
        EventPayload::SessionCreated { session: value } if value == &session
    ));
    assert!(matches!(
        &events.events[1].payload,
        EventPayload::RunCreated { run: value } if value == &run
    ));
    assert_workspace_paths_are_canonical(&store, session.id, events.events[0].id);
    let stored_json: Vec<String> = {
        let mut statement = store
            .connection
            .prepare("SELECT value_json FROM events ORDER BY sequence")
            .expect("event query should prepare");
        statement
            .query_map([], |row| row.get(0))
            .expect("events should query")
            .collect::<Result<_, _>>()
            .expect("events should collect")
    };
    assert!(
        stored_json
            .iter()
            .all(|json| serde_json::from_str::<EventEnvelope>(json).is_ok())
    );

    let actor_id = ActorId::new();
    let claim = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(events.events[1].id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id: RuntimeInstanceId::new(),
                claim_generation: 1,
                cancellation_generation: 0,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        })
        .expect("claim should append after migration");
    let running = store
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
        .expect("append should continue after migration");
    assert_eq!(running.sequence, 4);
    assert_eq!(
        store
            .get_run(run.id)
            .expect("run projection should load")
            .expect("run should exist")
            .state,
        RunState::Running
    );

    let next_session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/after-migration").into(),
        title: None,
    });
    let actor_id = ActorId::new();
    store
        .create_session(&next_session, session_event(&next_session, actor_id))
        .expect("session creation should continue after migration");
    let next_run = run_for(&next_session);
    store
        .create_run(
            &next_run,
            NewEvent {
                session_id: next_session.id,
                run_id: Some(next_run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::RunCreated {
                    run: next_run.clone(),
                },
            },
        )
        .expect("run creation should continue after migration");
    assert_eq!(
        schema_version(&store.connection).expect("schema version should read"),
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn interrupted_v1_migration_resumes_from_committed_progress_before_serving() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let database = directory.path().join("legacy-resume.sqlite3");
    let (session, run, _) = create_legacy_database(&database, false);
    let artifacts = directory.path().join("artifacts");
    prepare_private_directory(&artifacts).expect("artifact root should be ready");

    let mut connection = Connection::open(&database).expect("legacy database should open");
    connection
        .pragma_update(None, "foreign_keys", true)
        .expect("foreign keys should enable");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("migration should start");
    begin_legacy_migration(&transaction, LEGACY_SCHEMA_VERSION, false)
        .expect("migration journal should initialize");
    transaction
        .commit()
        .expect("migration start should persist");
    resume_legacy_migration_batch(&mut connection, &artifacts)
        .expect("one bounded batch should commit");
    let progress = read_legacy_migration_progress(&connection)
        .expect("committed progress should survive interruption");
    assert_eq!(progress.phase, "copy_sessions");
    assert!(progress.cursor_rowid > 0);
    assert_eq!(
        schema_version(&connection).expect("source version should remain visible"),
        LEGACY_SCHEMA_VERSION
    );
    assert!(table_exists(&connection, "sessions_schema_v1").unwrap());
    drop(connection);

    let store = Store::open(&database, &artifacts)
        .expect("next open should resume and finish before returning");
    assert_eq!(store.get_session(session.id).unwrap(), Some(session));
    assert_eq!(store.get_run(run.id).unwrap(), Some(run));
    assert!(!table_exists(&store.connection, "store_migration_progress").unwrap());
    assert!(!table_exists(&store.connection, "sessions_schema_v1").unwrap());
    assert_eq!(
        schema_version(&store.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn schema_v7_history_is_physically_labeled_without_claiming_semantic_review() {
    let (directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/v7-acceptance").into(),
        title: None,
    });
    let session_created = store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let plan_run = run_for(&session);
    let plan_created = store
        .create_run(
            &plan_run,
            NewEvent {
                session_id: session.id,
                run_id: Some(plan_run.id),
                actor_id,
                causal_parent: Some(session_created.id),
                provenance: provenance(),
                payload: EventPayload::RunCreated {
                    run: plan_run.clone(),
                },
            },
        )
        .expect("plan run should persist");
    let mut execute_run = run_for(&session);
    execute_run.spec.purpose = RunPurpose::Execute;
    execute_run.spec.plan_acceptance = PlanAcceptanceContract::NotApplicable;
    store
        .create_run(
            &execute_run,
            NewEvent {
                session_id: session.id,
                run_id: Some(execute_run.id),
                actor_id,
                causal_parent: Some(plan_created.id),
                provenance: provenance(),
                payload: EventPayload::RunCreated {
                    run: execute_run.clone(),
                },
            },
        )
        .expect("execute history fixture should persist");

    rewrite_plan_acceptance_as_protocol_v4(&store);
    store
        .connection
        .pragma_update(None, "user_version", RUN_STATE_PROJECTION_SCHEMA_VERSION)
        .expect("fixture should become schema v7");
    drop(store);

    let reopened = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("schema v7 should migrate");
    assert_eq!(
        schema_version(&reopened.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    let migrated_plan = reopened.get_run(plan_run.id).unwrap().unwrap();
    assert_eq!(
        migrated_plan.spec.plan_acceptance,
        PlanAcceptanceContract::LegacyMechanicalOnlyV4
    );
    let migrated_execute = reopened.get_run(execute_run.id).unwrap().unwrap();
    assert_eq!(
        migrated_execute.spec.plan_acceptance,
        PlanAcceptanceContract::NotApplicable
    );
    let creation = reopened
        .events_for_run_after(plan_run.id, 0)
        .unwrap()
        .events
        .into_iter()
        .find(|event| matches!(event.payload, EventPayload::RunCreated { .. }))
        .expect("migrated creation should exist");
    assert!(matches!(
        creation.payload,
        EventPayload::RunCreated { run } if run == migrated_plan
    ));
    let stored_run = reopened
        .connection
        .query_row(
            "SELECT value_json FROM runs WHERE id = ?1",
            [plan_run.id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stored_run)
            .unwrap()
            .pointer("/spec/plan_acceptance"),
        Some(&serde_json::json!("legacy_mechanical_only_v4"))
    );
}

#[test]
fn interrupted_schema_v7_acceptance_migration_resumes_before_serving() {
    let (directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/v7-acceptance-resume").into(),
        title: None,
    });
    store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
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
    rewrite_plan_acceptance_as_protocol_v4(&store);
    store
        .connection
        .pragma_update(None, "user_version", RUN_STATE_PROJECTION_SCHEMA_VERSION)
        .expect("fixture should become schema v7");
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("upgrade should begin");
    begin_store_upgrade(&transaction, RUN_STATE_PROJECTION_SCHEMA_VERSION)
        .expect("upgrade journal should initialize");
    transaction.commit().expect("upgrade journal should commit");
    let artifacts = directory.path().join("artifacts");
    resume_store_upgrade_batch(&mut store.connection, &artifacts)
        .expect("one bounded run batch should commit");
    let progress = read_store_upgrade_progress(&store.connection).unwrap();
    assert_eq!(progress.phase, "acceptance_runs");
    assert!(progress.cursor_rowid > 0);
    assert_eq!(
        schema_version(&store.connection).unwrap(),
        RUN_STATE_PROJECTION_SCHEMA_VERSION
    );
    drop(store);

    let reopened = Store::open(directory.path().join("state.sqlite3"), &artifacts)
        .expect("next open should resume and finish");
    assert_eq!(
        schema_version(&reopened.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        reopened
            .get_run(run.id)
            .unwrap()
            .unwrap()
            .spec
            .plan_acceptance,
        PlanAcceptanceContract::LegacyMechanicalOnlyV4
    );
    assert!(!table_exists(&reopened.connection, "store_upgrade_progress").unwrap());
}

#[test]
fn concurrent_open_serializes_schema_v7_acceptance_migration() {
    let (directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/v7-acceptance-concurrent").into(),
        title: None,
    });
    store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
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
    rewrite_plan_acceptance_as_protocol_v4(&store);
    store
        .connection
        .pragma_update(None, "user_version", RUN_STATE_PROJECTION_SCHEMA_VERSION)
        .expect("fixture should become schema v7");
    drop(store);

    let database = directory.path().join("state.sqlite3");
    let artifacts = directory.path().join("artifacts");
    assert_two_concurrent_opens(&database, &artifacts);
    let reopened = Store::open(&database, &artifacts).expect("migrated store should reopen");
    assert_eq!(
        schema_version(&reopened.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        reopened
            .get_run(run.id)
            .unwrap()
            .unwrap()
            .spec
            .plan_acceptance,
        PlanAcceptanceContract::LegacyMechanicalOnlyV4
    );
}

#[test]
fn new_legacy_plan_run_is_rejected_without_partial_writes() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/reject-new-legacy").into(),
        title: None,
    });
    let session_created = store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let mut run = run_for(&session);
    run.spec.plan_acceptance = PlanAcceptanceContract::LegacyMechanicalOnlyV4;
    let before = store.events_after(session.id, 0).unwrap().events;
    assert!(matches!(
        store.create_run(
            &run,
            NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(session_created.id),
                provenance: provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            }
        ),
        Err(StoreError::InvalidStateEvent)
    ));
    assert_eq!(store.get_run(run.id).unwrap(), None);
    assert_eq!(store.events_after(session.id, 0).unwrap().events, before);
}

#[test]
fn migrates_v2_integrity_objects_without_rewriting_history() {
    let (directory, store, original) = store_with_session_event();
    drop_current_projection_objects(&store.connection);
    store
        .connection
        .execute_batch(
            "DROP TRIGGER events_reject_conflicting_insert;
             DROP TRIGGER events_reject_oversized_insert;
             DROP INDEX events_by_run_sequence;
             DROP TABLE runtime_health_canary;
             PRAGMA user_version = 2;",
        )
        .expect("test database should be restored to canonical v2");
    drop(store);

    let migrated = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("v2 database should migrate");
    assert_eq!(
        schema_version(&migrated.connection).expect("schema version should read"),
        CURRENT_SCHEMA_VERSION
    );
    validate_current_schema(&migrated.connection).expect("v6 schema should be canonical");
    assert_eq!(
        migrated
            .events_after(original.session_id, 0)
            .expect("migrated history should remain readable")
            .events,
        vec![original]
    );
}

#[test]
fn migrates_v3_event_size_guard_without_rewriting_history() {
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
    drop(store);

    let migrated = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("v3 database should migrate");
    assert_eq!(
        schema_version(&migrated.connection).expect("schema version should read"),
        CURRENT_SCHEMA_VERSION
    );
    validate_current_schema(&migrated.connection).expect("v6 schema should be canonical");
    assert_eq!(
        migrated
            .events_after(original.session_id, 0)
            .expect("migrated history should remain readable")
            .events,
        vec![original]
    );
}

#[test]
fn migrates_v4_durable_health_canary_without_rewriting_history() {
    let (directory, store, original) = store_with_session_event();
    drop_current_projection_objects(&store.connection);
    store
        .connection
        .execute_batch(
            "DROP TABLE runtime_health_canary;
             PRAGMA user_version = 4;",
        )
        .expect("test database should be restored to canonical v4");
    drop(store);

    let migrated = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("v4 database should migrate");
    assert_eq!(
        schema_version(&migrated.connection).expect("schema version should read"),
        CURRENT_SCHEMA_VERSION
    );
    validate_current_schema(&migrated.connection).expect("v6 schema should be canonical");
    assert_eq!(
        migrated
            .events_after(original.session_id, 0)
            .expect("migrated history should remain readable")
            .events,
        vec![original]
    );
}

#[test]
fn migrates_protocol_v1_workspace_paths_from_schemas_v2_through_v5() {
    for source_version in IMMUTABLE_SCHEMA_VERSION..=HEALTH_CANARY_SCHEMA_VERSION {
        let (directory, store, original) = store_with_session_event();
        let session = match &original.payload {
            EventPayload::SessionCreated { session } => session.clone(),
            other => panic!("expected session creation event, got {other:?}"),
        };
        rewrite_workspace_paths_as_protocol_v1(&store, &session, &original);
        downgrade_store_to_schema(&store, source_version);
        drop(store);

        let migrated = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .unwrap_or_else(|error| {
            panic!("schema v{source_version} path migration should succeed: {error}")
        });
        assert_eq!(
            schema_version(&migrated.connection).expect("schema version should read"),
            CURRENT_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .get_session(session.id)
                .expect("migrated session should load"),
            Some(session.clone())
        );
        assert_eq!(
            migrated
                .events_after(original.session_id, 0)
                .expect("migrated history should replay")
                .events,
            vec![original.clone()]
        );
        assert_workspace_paths_are_canonical(&migrated, session.id, original.id);
        validate_current_schema(&migrated.connection)
            .expect("migrated v6 schema should restore every integrity object");
    }
}

#[test]
fn v5_path_migration_preserves_mixed_legacy_and_current_rows() {
    let (directory, mut store, legacy_event) = store_with_session_event();
    let legacy_session = match &legacy_event.payload {
        EventPayload::SessionCreated { session } => session.clone(),
        other => panic!("expected session creation event, got {other:?}"),
    };
    rewrite_workspace_paths_as_protocol_v1(&store, &legacy_session, &legacy_event);

    let current_session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/already-current").into(),
        title: Some("Canonical path row".to_owned()),
    });
    let current_event = store
        .create_session(
            &current_session,
            session_event(&current_session, ActorId::new()),
        )
        .expect("current session should persist");
    downgrade_store_to_schema(&store, HEALTH_CANARY_SCHEMA_VERSION);
    drop(store);

    let migrated = Store::open(
        directory.path().join("state.sqlite3"),
        directory.path().join("artifacts"),
    )
    .expect("mixed schema-v5 paths should migrate");
    assert_eq!(
        migrated
            .events_after(legacy_session.id, 0)
            .expect("legacy session history should replay")
            .events,
        vec![legacy_event.clone()]
    );
    assert_eq!(
        migrated
            .events_after(current_session.id, 0)
            .expect("current session history should replay")
            .events,
        vec![current_event.clone()]
    );
    assert_workspace_paths_are_canonical(&migrated, legacy_session.id, legacy_event.id);
    assert_workspace_paths_are_canonical(&migrated, current_session.id, current_event.id);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression proves fail-closed checkpoint inspection, repair, and resume"
)]
fn malformed_v5_path_upgrade_is_checkpointed_fail_closed_and_repairable() {
    let (directory, store, original) = store_with_session_event();
    let session = match &original.payload {
        EventPayload::SessionCreated { session } => session.clone(),
        other => panic!("expected session creation event, got {other:?}"),
    };
    rewrite_workspace_paths_as_protocol_v1(&store, &session, &original);

    let mut event_json = store
        .connection
        .query_row(
            "SELECT value_json FROM events WHERE id = ?1",
            [original.id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .and_then(|json| {
            serde_json::from_str::<serde_json::Value>(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .expect("fixture event JSON should read");
    *event_json
        .pointer_mut("/payload/data/session/workspace_root")
        .expect("session creation event should contain its workspace path") = serde_json::json!({
        "wire_version": WORKSPACE_PATH_WIRE_VERSION + 1,
        "representation": {
            "encoding": "unix_bytes",
            "bytes": [47, 116, 109, 112],
        },
    });
    let transaction = store
        .connection
        .unchecked_transaction()
        .expect("fixture transaction should begin");
    transaction
        .execute_batch(
            "DROP TRIGGER events_are_immutable_on_update;
             DROP TRIGGER events_are_immutable_on_delete;",
        )
        .expect("fixture should suspend event immutability");
    assert_eq!(
        transaction
            .execute(
                "UPDATE events SET value_json = ?1 WHERE id = ?2",
                params![event_json.to_string(), original.id.to_string()],
            )
            .expect("malformed fixture event should update"),
        1
    );
    transaction
        .execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)
        .expect("fixture should restore event immutability");
    transaction.commit().expect("fixture should commit");
    downgrade_store_to_schema(&store, HEALTH_CANARY_SCHEMA_VERSION);
    drop(store);

    let database = directory.path().join("state.sqlite3");
    assert!(matches!(
        Store::open(&database, directory.path().join("artifacts")),
        Err(StoreError::IncompatibleSchema { found: 5, .. })
    ));

    let connection = Connection::open(&database).expect("checkpointed database should open");
    assert_eq!(
        schema_version(&connection).expect("source schema version should remain visible"),
        HEALTH_CANARY_SCHEMA_VERSION
    );
    let progress = read_store_upgrade_progress(&connection)
        .expect("failed upgrade must retain durable progress");
    assert_eq!(progress.phase, "path_events");
    let session_json = connection
        .query_row(
            "SELECT value_json FROM sessions WHERE id = ?1",
            [session.id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .expect("checkpointed materialized session should read");
    let session_value = serde_json::from_str::<serde_json::Value>(&session_json)
        .expect("checkpointed materialized session should parse");
    assert!(session_value["workspace_root"].is_object());
    let immutable_triggers: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'trigger'
               AND name IN (
                   'events_are_immutable_on_update',
                   'events_are_immutable_on_delete'
               )",
            [],
            |row| row.get(0),
        )
        .expect("immutability trigger state should read");
    assert_eq!(immutable_triggers, 0);

    connection
        .execute(
            "UPDATE events SET value_json = ?1 WHERE id = ?2",
            params![
                serde_json::to_string(&original).expect("original event should encode"),
                original.id.to_string()
            ],
        )
        .expect("operator repair should replace only the malformed staged row");
    drop(connection);
    let resumed = Store::open(&database, directory.path().join("artifacts"))
        .expect("repaired upgrade should resume from its path-event checkpoint");
    assert_eq!(
        schema_version(&resumed.connection).unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert!(!table_exists(&resumed.connection, "store_upgrade_progress").unwrap());
    assert_eq!(
        resumed.events_after(session.id, 0).unwrap().events,
        vec![original]
    );
}
