use super::*;

#[test]
fn rejects_incompatible_or_tampered_current_schemas() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let future = directory.path().join("future.sqlite3");
    Connection::open(&future)
        .expect("future database should open")
        .pragma_update(None, "user_version", 99_i64)
        .expect("future version should set");
    let error = Store::open(&future, directory.path().join("future-artifacts"))
        .err()
        .expect("future schema should be rejected");
    assert!(matches!(error, StoreError::IncompatibleSchema { .. }));
    assert!(!error.is_retryable());

    let current = directory.path().join("current.sqlite3");
    drop(
        Store::open(&current, directory.path().join("current-artifacts"))
            .expect("current store should open"),
    );
    Connection::open(&current)
        .expect("current database should reopen")
        .execute_batch(
            "DROP TRIGGER events_reject_conflicting_insert;
             CREATE TRIGGER events_reject_conflicting_insert
             BEFORE INSERT ON events
             WHEN EXISTS (SELECT 1 FROM events WHERE id = NEW.id) BEGIN
                 SELECT RAISE(ABORT, 'events are append-only');
             END;",
        )
        .expect("test should weaken conflict trigger");
    assert!(matches!(
        Store::open(&current, directory.path().join("current-artifacts")),
        Err(StoreError::IncompatibleSchema { .. })
    ));

    let altered_index = directory.path().join("altered-index.sqlite3");
    drop(
        Store::open(
            &altered_index,
            directory.path().join("altered-index-artifacts"),
        )
        .expect("current store should open"),
    );
    Connection::open(&altered_index)
        .expect("current database should reopen")
        .execute_batch(
            "DROP INDEX events_by_run_sequence;
             CREATE INDEX events_by_run_sequence ON events(run_id);",
        )
        .expect("test should weaken query index");
    assert!(matches!(
        Store::open(
            &altered_index,
            directory.path().join("altered-index-artifacts")
        ),
        Err(StoreError::IncompatibleSchema { .. })
    ));

    let extra_unique = directory.path().join("extra-unique.sqlite3");
    drop(
        Store::open(
            &extra_unique,
            directory.path().join("extra-unique-artifacts"),
        )
        .expect("current store should open"),
    );
    Connection::open(&extra_unique)
        .expect("current database should reopen")
        .execute_batch("CREATE UNIQUE INDEX one_run_per_session ON runs(session_id);")
        .expect("extra unique index should install");
    assert!(matches!(
        Store::open(
            &extra_unique,
            directory.path().join("extra-unique-artifacts")
        ),
        Err(StoreError::IncompatibleSchema { .. })
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one regression restores every schema mutation before testing projection integrity"
)]
fn health_rejects_closed_world_schema_drift_and_projection_integrity_tampering() {
    let (_directory, mut store) = test_store();

    for (install, remove) in [
        (
            "CREATE UNIQUE INDEX one_run_per_session ON runs(session_id);",
            "DROP INDEX one_run_per_session;",
        ),
        (
            "CREATE TRIGGER block_runs BEFORE INSERT ON runs BEGIN
                 SELECT RAISE(ABORT, 'blocked');
             END;",
            "DROP TRIGGER block_runs;",
        ),
        (
            "CREATE VIEW leaked_sessions AS SELECT * FROM sessions;",
            "DROP VIEW leaked_sessions;",
        ),
        (
            "CREATE TABLE unexpected_state (id INTEGER PRIMARY KEY);",
            "DROP TABLE unexpected_state;",
        ),
    ] {
        store
            .connection
            .execute_batch(install)
            .expect("unexpected schema object should install for the fixture");
        store.last_durable_health_probe.set(None);
        assert!(matches!(
            store.health_probe(),
            Err(StoreError::IncompatibleSchema { .. })
        ));
        store
            .connection
            .execute_batch(remove)
            .expect("unexpected schema object should be removable");
        store.last_durable_health_probe.set(None);
        store
            .health_probe()
            .expect("restored canonical schema should become healthy");
    }

    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/projection-integrity").into(),
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

    store
        .connection
        .pragma_update(None, "foreign_keys", false)
        .expect("fixture should disable foreign keys");
    assert!(matches!(
        store.connection.execute(
            "UPDATE run_state_projection SET session_id = ?1 WHERE run_id = ?2",
            params![SessionId::new().to_string(), run.id.to_string()],
        ),
        Err(rusqlite::Error::SqliteFailure(_, _))
    ));
    store
        .connection
        .pragma_update(None, "foreign_keys", true)
        .expect("fixture should restore foreign keys");
    assert!(matches!(
        store.connection.execute(
            "DELETE FROM run_state_projection WHERE run_id = ?1",
            [run.id.to_string()],
        ),
        Err(rusqlite::Error::SqliteFailure(_, _))
    ));
    assert_eq!(store.get_run(run.id).unwrap(), Some(run));

    store
        .connection
        .execute(
            "UPDATE run_state_projection_health
             SET projected_runs = projected_runs + 1 WHERE id = 1",
            [],
        )
        .expect("counter mismatch fixture should apply");
    store.last_durable_health_probe.set(None);
    assert!(matches!(
        store.health_probe(),
        Err(StoreError::IncompatibleSchema { .. })
    ));
    store
        .connection
        .execute(
            "UPDATE run_state_projection_health
             SET projected_runs = projected_runs - 1 WHERE id = 1",
            [],
        )
        .expect("counter fixture should repair");
    store.last_durable_health_probe.set(None);
    store
        .health_probe()
        .expect("repaired projection counters should be healthy");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one adversarial flow covers state, parent, claim, and actor authority"
)]
fn generic_append_rejects_creation_events_and_invalid_state_transitions() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/invariants").into(),
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

    for payload in [
        EventPayload::SessionCreated {
            session: session.clone(),
        },
        EventPayload::RunCreated { run: run.clone() },
        EventPayload::RunStateChanged {
            from: RunState::Waiting,
            to: RunState::Running,
        },
    ] {
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload,
            }),
            Err(StoreError::InvalidStateEvent)
        ));
    }
    assert!(matches!(
        store.append_event(NewEvent {
            session_id: session.id,
            run_id: None,
            actor_id,
            causal_parent: None,
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        }),
        Err(StoreError::InvalidStateEvent)
    ));

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
        .expect("claim should append before a running transition");
    assert!(matches!(
        store.append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id: ActorId::new(),
            causal_parent: Some(claim.id),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        }),
        Err(StoreError::InvalidStateEvent)
    ));
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
        .expect("the live claim owner should start the run");
    assert_eq!(
        store
            .get_run(run.id)
            .expect("run should load")
            .expect("run should exist")
            .state,
        RunState::Running
    );
}

#[test]
fn aggregate_artifact_budget_is_rejected_without_mutating_history_or_projection() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/artifact-budget").into(),
        title: None,
    });
    store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let mut run = run_for(&session);
    run.spec.input = (0..=MAX_EVENT_ARTIFACT_REFS)
        .map(|index| {
            let bytes = format!("distinct artifact {index}");
            let artifact = store
                .put_artifact(bytes.as_bytes(), "application/octet-stream")
                .expect("fixture artifact should persist");
            InputItem::Artifact { artifact }
        })
        .collect();
    assert!(matches!(
        store.create_run(
            &run,
            NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            }
        ),
        Err(StoreError::ArtifactReferenceBudget)
    ));
    assert_eq!(store.get_run(run.id).unwrap(), None);
    assert_eq!(store.events_after(session.id, 0).unwrap().events.len(), 1);
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT materialized_runs, projected_runs
                 FROM run_state_projection_health WHERE id = 1",
                [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
            )
            .unwrap(),
        (0, 0)
    );

    let mut byte_run = run_for(&session);
    byte_run.spec.input = (0..3)
        .map(|index| {
            let bytes = format!("oversized reference fixture {index}");
            let mut artifact = store
                .put_artifact(bytes.as_bytes(), "application/octet-stream")
                .expect("fixture artifact should persist");
            artifact.size_bytes = MAX_ARTIFACT_BYTES;
            InputItem::Artifact { artifact }
        })
        .collect();
    assert!(matches!(
        store.create_run(
            &byte_run,
            NewEvent {
                session_id: session.id,
                run_id: Some(byte_run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::RunCreated {
                    run: byte_run.clone()
                },
            }
        ),
        Err(StoreError::ArtifactReferenceBudget)
    ));
    assert_eq!(store.events_after(session.id, 0).unwrap().events.len(), 1);
}

#[test]
fn rejects_dangling_typed_artifact_references_before_immutable_writes() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/artifact-invariants").into(),
        title: None,
    });
    store
        .create_session(&session, session_event(&session, actor_id))
        .expect("session should persist");
    let missing = ArtifactRef {
        sha256: "00".repeat(32),
        size_bytes: 1,
        media_type: "application/octet-stream".to_owned(),
    };
    let mut run = run_for(&session);
    run.spec.input = vec![InputItem::Artifact {
        artifact: missing.clone(),
    }];
    let error = store
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
        .expect_err("dangling run input should be rejected");
    assert!(!error.is_retryable());
    assert!(
        store
            .get_run(run.id)
            .expect("run lookup should succeed")
            .is_none()
    );

    for payload in [
        EventPayload::UserInput {
            items: vec![InputItem::Artifact {
                artifact: missing.clone(),
            }],
        },
        EventPayload::ArtifactStored {
            artifact: missing.clone(),
        },
    ] {
        assert!(
            store
                .append_event(NewEvent {
                    session_id: session.id,
                    run_id: None,
                    actor_id,
                    causal_parent: None,
                    provenance: provenance(),
                    payload,
                })
                .is_err()
        );
    }
    assert!(
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: None,
                actor_id,
                causal_parent: None,
                provenance: Provenance {
                    producer: "test".to_owned(),
                    backend: None,
                    raw_artifact: Some(missing),
                },
                payload: EventPayload::UserInput { items: Vec::new() },
            })
            .is_err()
    );
    assert_eq!(
        store
            .events_after(session.id, 0)
            .expect("history should remain readable")
            .events
            .len(),
        1
    );
}

#[test]
fn backend_events_require_an_existing_hash_verified_raw_artifact() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/backend-raw-invariant").into(),
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
    let payload = EventPayload::BackendEvent {
        event_type: "model.delta".to_owned(),
        data: serde_json::json!({ "text": "hej 世界" }),
    };

    assert!(matches!(
        store.append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: None,
            provenance: provenance(),
            payload: payload.clone(),
        }),
        Err(StoreError::InvalidStateEvent)
    ));

    let dangling = ArtifactRef {
        sha256: "ab".repeat(32),
        size_bytes: 4,
        media_type: "application/json".to_owned(),
    };
    assert!(matches!(
        store.append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: None,
            provenance: Provenance {
                producer: "test".to_owned(),
                backend: None,
                raw_artifact: Some(dangling),
            },
            payload: payload.clone(),
        }),
        Err(StoreError::Io(_))
    ));

    let raw = store
        .put_artifact(
            r#"{"choices":[{"delta":{"content":"hej 世界"}}]}"#.as_bytes(),
            "application/json",
        )
        .expect("exact raw backend response should persist");
    let accepted = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: None,
            provenance: Provenance {
                producer: "test".to_owned(),
                backend: None,
                raw_artifact: Some(raw.clone()),
            },
            payload,
        })
        .expect("verified raw backend response should authorize normalized event");
    assert_eq!(accepted.provenance.raw_artifact, Some(raw));
    assert_eq!(
        store.events_after(session.id, 0).unwrap().events.len(),
        3,
        "rejected attempts must not mutate immutable history"
    );
}

#[test]
fn migration_rejects_dangling_materialized_artifact_inputs() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let database = directory.path().join("legacy.sqlite3");
    let (_session, mut run, _) = create_legacy_database(&database, false);
    run.spec.input = vec![InputItem::Artifact {
        artifact: ArtifactRef {
            sha256: "11".repeat(32),
            size_bytes: 7,
            media_type: "application/octet-stream".to_owned(),
        },
    }];
    Connection::open(&database)
        .expect("legacy database should reopen")
        .execute(
            "UPDATE runs SET value_json = ?1 WHERE id = ?2",
            rusqlite::params![
                serde_json::to_string(&run).expect("run should encode"),
                run.id.to_string()
            ],
        )
        .expect("legacy projection should update");

    let error = Store::open(&database, directory.path().join("artifacts"))
        .err()
        .expect("dangling legacy reference should block migration");
    assert!(matches!(error, StoreError::IncompatibleSchema { .. }));
    assert!(!error.is_retryable());
}

#[test]
fn artifacts_are_content_addressed_and_round_trip() {
    let (_directory, store) = test_store();
    let bytes = "Hej, 世界".as_bytes();
    let first = store
        .put_artifact(bytes, "text/plain; charset=utf-8")
        .expect("artifact should persist");
    let second = store
        .put_artifact(bytes, "text/plain; charset=utf-8")
        .expect("same artifact should deduplicate");

    assert_eq!(first.sha256, second.sha256);
    assert_eq!(
        store.get_artifact(&first).expect("artifact should load"),
        bytes
    );
}
