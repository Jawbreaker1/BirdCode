use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[cfg(unix)]
#[test]
fn state_directories_database_and_artifacts_are_private() {
    let parent = TempDir::new().expect("temporary parent should exist");
    let parent_mode = fs::metadata(parent.path()).unwrap().permissions().mode() & 0o777;
    let state = parent.path().join("state");
    let database = state.join("birdcode.sqlite3");
    let artifacts = state.join("artifacts");
    let store = Store::open(&database, &artifacts).expect("private store should open");
    let artifact = store
        .put_artifact(b"private", "application/octet-stream")
        .expect("private artifact should persist");
    let artifact_path = store.artifact_path(&artifact.sha256).unwrap();

    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&artifacts).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(artifact_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&artifact_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            assert_eq!(
                fs::metadata(sidecar).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    assert_eq!(
        fs::metadata(parent.path()).unwrap().permissions().mode() & 0o777,
        parent_mode
    );
}

#[cfg(unix)]
#[test]
fn opening_store_does_not_chmod_existing_user_selected_directories() {
    let parent = TempDir::new().expect("temporary parent should exist");
    let state = parent.path().join("shared-state-parent");
    let artifacts = state.join("existing-artifacts");
    fs::create_dir_all(&artifacts).expect("fixture directories should be created");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755))
        .expect("state fixture permissions should be applied");
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o755))
        .expect("artifact fixture permissions should be applied");

    let database = state.join("birdcode.sqlite3");
    let store = Store::open(&database, &artifacts).expect("store should open");
    let artifact = store
        .put_artifact(b"private content", "application/octet-stream")
        .expect("artifact should persist");

    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(&artifacts).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(store.artifact_path(&artifact.sha256).unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn opening_store_rejects_shared_writable_existing_state_directory() {
    let parent = TempDir::new().expect("temporary parent should exist");
    let state = parent.path().join("shared-writable");
    fs::create_dir(&state).expect("fixture state should be created");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o777))
        .expect("fixture permissions should be applied");

    let error = Store::open(state.join("birdcode.sqlite3"), state.join("artifacts"))
        .err()
        .expect("shared-writable state must be rejected");
    assert!(matches!(
        error,
        StoreError::Io(ref source) if source.kind() == io::ErrorKind::PermissionDenied
    ));
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o777
    );
    assert!(!state.join("birdcode.sqlite3").exists());
}

#[test]
fn health_probe_rolls_back_authoritative_probe_and_periodically_commits_canary() {
    let (directory, store) = test_store();
    let artifact_root = directory.path().join("artifacts");
    let entries_before = fs::read_dir(&artifact_root)
        .expect("artifact root should list")
        .count();
    store
        .health_probe()
        .expect("writable store should be healthy");
    assert_eq!(
        fs::read_dir(&artifact_root)
            .expect("artifact root should list after canary")
            .count(),
        entries_before,
        "artifact canary must leave no residue"
    );
    let sessions = store
        .connection
        .query_row("SELECT COUNT(*) FROM sessions", [], |row| {
            row.get::<_, u64>(0)
        })
        .expect("session count should read");
    assert_eq!(sessions, 0);
    let generation = || {
        store
            .connection
            .query_row(
                "SELECT generation FROM runtime_health_canary WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("health generation should read")
    };
    assert_eq!(generation(), 1);

    store
        .health_probe()
        .expect("cached durable probe should remain healthy");
    assert_eq!(generation(), 1);
    store.last_durable_health_probe.set(None);
    store
        .health_probe()
        .expect("forced durable probe should commit");
    assert_eq!(generation(), 2);

    store
        .connection
        .pragma_update(None, "query_only", true)
        .expect("fixture should become read-only");
    assert!(matches!(store.health_probe(), Err(StoreError::Database(_))));
}

#[test]
fn health_probe_detects_corrupt_artifact_root_and_altered_schema_objects() {
    let (directory, store) = test_store();
    let artifact_root = directory.path().join("artifacts");
    let saved_root = directory.path().join("artifacts-saved");
    fs::rename(&artifact_root, &saved_root).expect("artifact root should move");
    fs::write(&artifact_root, b"not a directory").expect("corrupt root fixture should write");
    store.last_durable_health_probe.set(None);
    assert!(matches!(store.health_probe(), Err(StoreError::Io(_))));
    fs::remove_file(&artifact_root).expect("corrupt root fixture should remove");
    fs::rename(&saved_root, &artifact_root).expect("artifact root should restore");

    store
        .connection
        .execute_batch("DROP TABLE run_state_projection;")
        .expect("projection fixture should be removed");
    store.last_durable_health_probe.set(None);
    assert!(matches!(
        store.health_probe(),
        Err(StoreError::IncompatibleSchema { .. })
    ));
}

#[cfg(unix)]
#[test]
fn health_probe_detects_unwritable_artifact_root() {
    let (directory, store) = test_store();
    let artifact_root = directory.path().join("artifacts");
    fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o500))
        .expect("artifact root should become read-only");
    store.last_durable_health_probe.set(None);
    let result = store.health_probe();
    fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700))
        .expect("artifact root permissions should restore");
    assert!(matches!(result, Err(StoreError::Io(_))));
}

#[test]
fn rejects_corrupted_content_addressed_artifacts() {
    let (_directory, store) = test_store();
    let artifact = store
        .put_artifact(b"trusted bytes", "application/octet-stream")
        .expect("artifact should persist");
    let path = store
        .artifact_path(&artifact.sha256)
        .expect("hash should map to a path");
    fs::write(path, b"tampered").expect("test should corrupt artifact");

    assert!(matches!(
        store.get_artifact(&artifact),
        Err(StoreError::ArtifactIntegrity)
    ));
    assert!(matches!(
        store.put_artifact(b"trusted bytes", "application/octet-stream"),
        Err(StoreError::ArtifactIntegrity)
    ));
}

#[test]
fn rejects_oversized_artifact_files_before_allocating_their_contents() {
    let (_directory, store) = test_store();
    let artifact = store
        .put_artifact(b"small", "application/octet-stream")
        .expect("fixture artifact should persist");
    let path = store.artifact_path(&artifact.sha256).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("artifact should reopen")
        .set_len(MAX_ARTIFACT_BYTES + 1)
        .expect("sparse oversized fixture should be created");

    assert!(matches!(
        store.get_artifact(&artifact),
        Err(StoreError::ArtifactTooLarge)
    ));
}

#[test]
fn rejects_cross_session_run_and_causal_references() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let first = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/first").into(),
        title: None,
    });
    let second = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/second").into(),
        title: None,
    });
    let first_event = store
        .create_session(&first, session_event(&first, actor_id))
        .expect("first session should persist");
    store
        .create_session(&second, session_event(&second, actor_id))
        .expect("second session should persist");
    let run = Run::new(RunSpec {
        session_id: second.id,
        purpose: RunPurpose::PlanOnly,
        plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
        backend: BackendSelection {
            backend_id: "test".to_owned(),
            kind: BackendKind::Model,
            model: None,
            reasoning_effort: None,
        },
        input: vec![InputItem::Text {
            text: "test".to_owned(),
        }],
        limits: RunLimits::default(),
    });
    store
        .create_run(
            &run,
            NewEvent {
                session_id: second.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::RunCreated { run: run.clone() },
            },
        )
        .expect("run should persist");

    for invalid in [
        NewEvent {
            session_id: first.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: None,
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "cross-session run".to_owned(),
                }],
            },
        },
        NewEvent {
            session_id: second.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(first_event.id),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "cross-session parent".to_owned(),
                }],
            },
        },
    ] {
        let result = store.append_event(invalid);
        assert!(
            matches!(result, Err(StoreError::InvalidStateEvent)),
            "cross-session reference produced {result:?}"
        );
    }
}

#[test]
fn authoritative_event_reads_are_bounded_and_resumable() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/paginated").into(),
        title: Some("Lång session".to_owned()),
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

    for index in 0..EVENT_PAGE_SIZE + 5 {
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::UserInput {
                    items: vec![InputItem::Text {
                        text: format!("page {index}"),
                    }],
                },
            })
            .expect("event should append");
    }

    let first = store
        .events_after(session.id, 0)
        .expect("first page should load");
    assert_eq!(first.events.len(), EVENT_PAGE_SIZE as usize);
    assert!(first.has_more);
    assert_eq!(first.next_sequence, u64::from(EVENT_PAGE_SIZE));
    assert!(first.encoded_bytes <= EVENT_PAGE_BYTES);
    assert_eq!(first.events.first().map(|event| event.sequence), Some(1));
    assert_eq!(
        first.events.last().map(|event| event.sequence),
        Some(u64::from(EVENT_PAGE_SIZE))
    );

    let second = store
        .events_after(session.id, first.next_sequence)
        .expect("second page should load");
    assert_eq!(second.events.len(), 7);
    assert!(!second.has_more);
    assert_eq!(second.next_sequence, u64::from(EVENT_PAGE_SIZE) + 7);
    assert!(second.encoded_bytes <= EVENT_PAGE_BYTES);
    assert_eq!(
        second.events.first().map(|event| event.sequence),
        Some(u64::from(EVENT_PAGE_SIZE) + 1)
    );
    assert_eq!(
        second.events.last().map(|event| event.sequence),
        Some(u64::from(EVENT_PAGE_SIZE) + 7)
    );
}

#[test]
fn authoritative_event_reads_respect_the_encoded_byte_budget() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/byte-paginated").into(),
        title: Some("Byte-bounded session".to_owned()),
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

    for index in 0..12 {
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: None,
                provenance: provenance(),
                payload: EventPayload::UserInput {
                    items: vec![InputItem::Text {
                        text: format!("{index}:{}", "x".repeat(100_000)),
                    }],
                },
            })
            .expect("bounded event should append");
    }

    let first = store
        .events_after(session.id, 0)
        .expect("first byte-bounded page should load");
    assert!(first.has_more);
    assert!(first.events.len() < EVENT_PAGE_SIZE as usize);
    assert!(first.encoded_bytes <= EVENT_PAGE_BYTES);

    let mut cursor = 0_u64;
    let mut total = 0_usize;
    loop {
        let page = store
            .events_after(session.id, cursor)
            .expect("byte-bounded page should load");
        assert!(!page.events.is_empty());
        assert!(page.encoded_bytes <= EVENT_PAGE_BYTES);
        assert_eq!(
            page.events.first().map(|event| event.sequence),
            Some(cursor + 1)
        );
        assert_eq!(
            page.events.last().map(|event| event.sequence),
            Some(page.next_sequence)
        );
        total += page.events.len();
        cursor = page.next_sequence;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(total, 14);
    assert_eq!(cursor, 14);
}

#[test]
fn oversized_inline_event_is_rejected_without_mutating_history() {
    let (_directory, mut store) = test_store();
    let actor_id = ActorId::new();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/oversized-event").into(),
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

    let error = store
        .append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: None,
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "x".repeat(MAX_INLINE_EVENT_BYTES),
                }],
            },
        })
        .expect_err("oversized inline event must be rejected");
    assert!(matches!(error, StoreError::EventTooLarge));

    let page = store
        .events_after(session.id, 0)
        .expect("existing history should remain readable");
    assert_eq!(page.events.len(), 2);
    assert!(!page.has_more);
    assert_eq!(page.next_sequence, 2);
}
