use super::{
    ActorId, CURRENT_TABLES_SQL, Connection, EventEnvelope, EventId, EventPayload,
    IMMUTABLE_SCHEMA_VERSION, LEGACY_MIGRATION_CONTROL_SQL, MAX_INLINE_EVENT_BYTES_U64,
    MAX_MIGRATION_METADATA_BYTES, MIGRATION_EVENT_BATCH_SIZE, MIGRATION_ROW_BATCH_SIZE,
    OptionalExtension, Path, PathBuf, Provenance, RunState, SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL,
    Session, StoreError, Transaction, TransactionBehavior, WorkspacePath, decode_canonical_event,
    decode_legacy_event, decode_pre_v8_stored_run, decode_stored_run, encode_inline_event,
    encode_run_state, ensure_column_names, expected_table_names, incompatible,
    insert_pre_v8_run_spec_fields, known_tables, params, table_exists, valid_run_transition,
    validate_input_artifacts, validate_typed_artifact_refs,
};

#[derive(Debug)]
pub(super) struct LegacyMigrationProgress {
    pub(super) source_version: i64,
    pub(super) has_causal_parent: bool,
    pub(super) phase: String,
    pub(super) cursor_rowid: i64,
    pub(super) cursor_session_id: Option<String>,
    pub(super) cursor_sequence: u64,
}

pub(super) fn begin_legacy_migration(
    transaction: &Transaction<'_>,
    found: i64,
    has_causal_parent: bool,
) -> Result<(), StoreError> {
    validate_legacy_shape(transaction, found, has_causal_parent)?;
    transaction.execute_batch(
        "DROP TRIGGER IF EXISTS events_are_immutable_on_update;
         DROP TRIGGER IF EXISTS events_are_immutable_on_delete;
         ALTER TABLE events RENAME TO events_schema_v1;
         ALTER TABLE runs RENAME TO runs_schema_v1;
         ALTER TABLE sessions RENAME TO sessions_schema_v1;",
    )?;
    transaction.execute_batch(CURRENT_TABLES_SQL)?;
    transaction.execute_batch(LEGACY_MIGRATION_CONTROL_SQL)?;
    transaction.execute(
        "UPDATE store_migration_progress
         SET source_version = ?1, has_causal_parent = ?2 WHERE id = 1",
        params![found, has_causal_parent],
    )?;
    Ok(())
}

pub(super) fn resume_legacy_migration_batch(
    connection: &mut Connection,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !table_exists(&transaction, "store_migration_progress")? {
        transaction.commit()?;
        return Ok(());
    }
    let progress = read_legacy_migration_progress(&transaction)?;
    match progress.phase.as_str() {
        "copy_sessions" => copy_legacy_session_batch(&transaction, &progress)?,
        "copy_runs" => copy_legacy_run_batch(&transaction, &progress)?,
        "scan_events" => scan_legacy_event_batch(&transaction, &progress)?,
        "emit_events" => emit_legacy_event_batch(&transaction, &progress, artifact_root)?,
        "synthesize_sessions" => synthesize_orphan_session_batch(&transaction, &progress)?,
        "synthesize_runs" => {
            synthesize_orphan_run_batch(&transaction, &progress, artifact_root)?;
        }
        "validate" => {
            validate_legacy_migration_inventory(&transaction, progress.source_version)?;
            set_legacy_migration_phase(&transaction, "finalize")?;
        }
        "finalize" => finalize_legacy_migration(&transaction, progress.source_version)?,
        other => {
            return Err(incompatible(
                progress.source_version,
                format!("legacy migration has unknown phase {other}"),
            ));
        }
    }
    transaction.commit()?;
    Ok(())
}

pub(super) fn read_legacy_migration_progress(
    connection: &Connection,
) -> Result<LegacyMigrationProgress, StoreError> {
    connection
        .query_row(
            "SELECT source_version, has_causal_parent, phase, cursor_rowid,
                    cursor_session_id, cursor_sequence
             FROM store_migration_progress WHERE id = 1",
            [],
            |row| {
                Ok(LegacyMigrationProgress {
                    source_version: row.get(0)?,
                    has_causal_parent: row.get(1)?,
                    phase: row.get(2)?,
                    cursor_rowid: row.get(3)?,
                    cursor_session_id: row.get(4)?,
                    cursor_sequence: row.get(5)?,
                })
            },
        )
        .map_err(StoreError::from)
}

fn set_legacy_migration_phase(connection: &Connection, phase: &str) -> Result<(), StoreError> {
    let changed = connection.execute(
        "UPDATE store_migration_progress
         SET phase = ?1, cursor_rowid = 0, cursor_session_id = NULL,
             cursor_sequence = 0
         WHERE id = 1",
        [phase],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn advance_legacy_row_cursor(
    connection: &Connection,
    phase: &str,
    rowid: i64,
    processed: usize,
) -> Result<(), StoreError> {
    let changed = connection.execute(
        "UPDATE store_migration_progress
         SET cursor_rowid = ?1, processed_rows = processed_rows + ?2
         WHERE id = 1 AND phase = ?3",
        params![rowid, u64::try_from(processed).unwrap_or(u64::MAX), phase],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

type LegacyMetadataRow = (i64, String, String, u64);

pub(super) fn bounded_legacy_metadata_rows(
    connection: &Connection,
    table: &str,
    after_rowid: i64,
) -> Result<Vec<LegacyMetadataRow>, StoreError> {
    let query = format!(
        "SELECT rowid, id,
                CASE WHEN length(CAST(value_json AS BLOB)) <= ?1 THEN value_json END,
                length(CAST(value_json AS BLOB))
         FROM {table} WHERE rowid > ?2 ORDER BY rowid LIMIT ?3"
    );
    let mut statement = connection.prepare(&query)?;
    statement
        .query_map(
            params![
                MAX_MIGRATION_METADATA_BYTES,
                after_rowid,
                MIGRATION_ROW_BATCH_SIZE
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    row.get::<_, u64>(3)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn copy_legacy_session_batch(
    transaction: &Transaction<'_>,
    progress: &LegacyMigrationProgress,
) -> Result<(), StoreError> {
    let rows =
        bounded_legacy_metadata_rows(transaction, "sessions_schema_v1", progress.cursor_rowid)?;
    if rows.is_empty() {
        return set_legacy_migration_phase(transaction, "copy_runs");
    }
    for (_, id, json, bytes) in &rows {
        if *bytes > MAX_MIGRATION_METADATA_BYTES {
            return Err(incompatible(
                progress.source_version,
                format!("materialized session {id} exceeds the migration metadata limit"),
            ));
        }
        let mut value = serde_json::from_str::<serde_json::Value>(json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized session {id} contains invalid JSON: {error}"),
            )
        })?;
        canonicalize_workspace_root(
            &mut value,
            "/workspace_root",
            progress.source_version,
            &format!("materialized session {id}"),
            true,
        )?;
        let session = serde_json::from_value::<Session>(value).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized session {id} is invalid: {error}"),
            )
        })?;
        if session.id.to_string() != *id {
            return Err(incompatible(
                progress.source_version,
                format!("materialized session {id} contradicts its primary key"),
            ));
        }
        transaction.execute(
            "INSERT INTO sessions (id, value_json) VALUES (?1, ?2)",
            params![id, serde_json::to_string(&session)?],
        )?;
        transaction.execute(
            "INSERT INTO migration_v1_session_inventory (session_id) VALUES (?1)",
            [id],
        )?;
    }
    advance_legacy_row_cursor(
        transaction,
        "copy_sessions",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

fn copy_legacy_run_batch(
    transaction: &Transaction<'_>,
    progress: &LegacyMigrationProgress,
) -> Result<(), StoreError> {
    let rows = bounded_legacy_metadata_rows(transaction, "runs_schema_v1", progress.cursor_rowid)?;
    if rows.is_empty() {
        return set_legacy_migration_phase(transaction, "scan_events");
    }
    for (_, id, json, bytes) in &rows {
        if *bytes > MAX_MIGRATION_METADATA_BYTES {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} exceeds the migration metadata limit"),
            ));
        }
        let session_id = transaction.query_row(
            "SELECT session_id FROM runs_schema_v1 WHERE id = ?1",
            [id],
            |row| row.get::<_, String>(0),
        )?;
        let run = decode_pre_v8_stored_run(json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized run {id} is invalid: {error}"),
            )
        })?;
        if run.id.to_string() != *id || run.spec.session_id.to_string() != session_id {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} contradicts its keys"),
            ));
        }
        transaction.execute(
            "INSERT INTO runs (id, session_id, value_json) VALUES (?1, ?2, ?3)",
            params![id, session_id, serde_json::to_string(&run)?],
        )?;
        transaction.execute(
            "INSERT INTO migration_v1_run_inventory (run_id, session_id, state)
             VALUES (?1, ?2, ?3)",
            params![id, session_id, encode_run_state(run.state)],
        )?;
    }
    advance_legacy_row_cursor(
        transaction,
        "copy_runs",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

type LegacySourceEventRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    u64,
    u64,
    Option<String>,
);

#[allow(
    clippy::too_many_lines,
    reason = "the bounded legacy decoder keeps all column and payload invariants together"
)]
fn scan_legacy_event_batch(
    transaction: &Transaction<'_>,
    progress: &LegacyMigrationProgress,
) -> Result<(), StoreError> {
    let causal_parent = if progress.has_causal_parent {
        "causal_parent"
    } else {
        "NULL"
    };
    let query = format!(
        "SELECT rowid, id, session_id, run_id, {causal_parent}, sequence,
                length(CAST(value_json AS BLOB)),
                CASE WHEN length(CAST(value_json AS BLOB)) <= ?1
                     THEN value_json END
         FROM events_schema_v1 WHERE rowid > ?2 ORDER BY rowid LIMIT ?3"
    );
    let rows = {
        let mut statement = transaction.prepare(&query)?;
        statement
            .query_map(
                params![
                    MAX_INLINE_EVENT_BYTES_U64,
                    progress.cursor_rowid,
                    MIGRATION_ROW_BATCH_SIZE
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, u64>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )?
            .collect::<Result<Vec<LegacySourceEventRow>, _>>()?
    };
    if rows.is_empty() {
        return set_legacy_migration_phase(transaction, "emit_events");
    }

    for (rowid, id, session_id, run_id, scalar_parent, sequence, bytes, raw_json) in &rows {
        if *bytes > MAX_INLINE_EVENT_BYTES_U64 {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} exceeds the inline event size limit"),
            ));
        }
        let raw_json = raw_json.as_deref().ok_or_else(|| {
            incompatible(
                progress.source_version,
                format!("event {id} could not be read within its size limit"),
            )
        })?;
        let mut value = serde_json::from_str::<serde_json::Value>(raw_json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("event {id} contains invalid JSON: {error}"),
            )
        })?;
        canonicalize_workspace_root(
            &mut value,
            "/payload/data/session/workspace_root",
            progress.source_version,
            &format!("event {id}"),
            false,
        )?;
        let json_parent =
            optional_json_string(&value, "causal_parent", progress.source_version, id)?;
        let causal_parent = match json_parent {
            JsonStringPresence::Missing => scalar_parent.clone(),
            JsonStringPresence::Present(value) => {
                if progress.has_causal_parent && value != *scalar_parent {
                    return Err(incompatible(
                        progress.source_version,
                        format!("event {id} has contradictory causal parent representations"),
                    ));
                }
                value
            }
        };
        value
            .as_object_mut()
            .ok_or_else(|| {
                incompatible(
                    progress.source_version,
                    format!("event {id} is not a JSON object"),
                )
            })?
            .insert(
                "causal_parent".to_owned(),
                causal_parent
                    .as_ref()
                    .map_or(serde_json::Value::Null, |parent| {
                        serde_json::Value::String(parent.clone())
                    }),
            );
        let normalized = serde_json::to_string(&value)?;
        let envelope = decode_legacy_event(transaction, &normalized).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("event {id} cannot be upgraded to the current protocol: {error}"),
            )
        })?;
        if envelope.id.to_string() != *id
            || envelope.session_id.to_string() != *session_id
            || envelope.run_id.map(|value| value.to_string()) != *run_id
            || envelope.causal_parent.map(|value| value.to_string()) != causal_parent
            || envelope.sequence != *sequence
        {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} columns contradict its canonical envelope"),
            ));
        }
        validate_legacy_payload_semantics(transaction, &value, &envelope, progress.source_version)?;
        match &envelope.payload {
            EventPayload::SessionCreated { session } => {
                let materialized = transaction
                    .query_row(
                        "SELECT value_json FROM sessions WHERE id = ?1",
                        [session_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                let materialized = materialized
                    .as_deref()
                    .map(serde_json::from_str::<Session>)
                    .transpose()?;
                if envelope.run_id.is_some() || materialized.as_ref() != Some(session) {
                    return Err(incompatible(
                        progress.source_version,
                        format!("session creation event {id} contradicts materialized state"),
                    ));
                }
                transaction.execute(
                    "UPDATE migration_v1_session_inventory
                     SET creation_count = creation_count + 1 WHERE session_id = ?1",
                    [session_id],
                )?;
            }
            EventPayload::RunCreated { run } => {
                let Some(run_id) = run_id.as_ref() else {
                    return Err(incompatible(
                        progress.source_version,
                        format!("run creation event {id} has no run_id"),
                    ));
                };
                let materialized = transaction
                    .query_row(
                        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
                        params![run_id, session_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                let materialized = materialized.as_deref().map(decode_stored_run).transpose()?;
                if materialized.as_ref() != Some(run) {
                    return Err(incompatible(
                        progress.source_version,
                        format!("run creation event {id} contradicts materialized state"),
                    ));
                }
                transaction.execute(
                    "UPDATE migration_v1_run_inventory
                     SET creation_count = creation_count + 1 WHERE run_id = ?1",
                    [run_id],
                )?;
            }
            _ => {}
        }
        transaction.execute(
            "INSERT INTO migration_v1_events (
                 source_rowid, id, session_id, run_id, causal_parent,
                 source_sequence, value_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                rowid,
                id,
                session_id,
                run_id,
                causal_parent,
                sequence,
                encode_inline_event(&envelope)?
            ],
        )?;
    }
    advance_legacy_row_cursor(
        transaction,
        "scan_events",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

type StagedLegacyEventRow = (String, String, Option<String>, u64, String);

#[allow(
    clippy::too_many_lines,
    reason = "one bounded emit step keeps creation, causal, state, and artifact invariants atomic"
)]
fn emit_legacy_event_batch(
    transaction: &Transaction<'_>,
    progress: &LegacyMigrationProgress,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let cursor_session = progress.cursor_session_id.as_deref().unwrap_or("");
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT id, session_id, run_id, source_sequence, value_json
             FROM migration_v1_events
             WHERE session_id > ?1
                OR (session_id = ?1 AND source_sequence > ?2)
             ORDER BY session_id, source_sequence LIMIT ?3",
        )?;
        statement
            .query_map(
                params![
                    cursor_session,
                    progress.cursor_sequence,
                    MIGRATION_EVENT_BATCH_SIZE
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )?
            .collect::<Result<Vec<StagedLegacyEventRow>, _>>()?
    };
    if rows.is_empty() {
        return set_legacy_migration_phase(transaction, "synthesize_sessions");
    }

    for (_, session_id, run_id, _, value_json) in &rows {
        let mut event = decode_canonical_event(value_json)?;
        validate_typed_artifact_refs(artifact_root, &event.provenance, &event.payload)?;
        let is_session_creation = matches!(&event.payload, EventPayload::SessionCreated { .. });
        let is_run_creation = matches!(&event.payload, EventPayload::RunCreated { .. });
        if !is_session_creation {
            synthesize_session_before_first_dependency(
                transaction,
                session_id,
                progress.source_version,
            )?;
        }
        if let Some(run_id) = run_id
            && !is_run_creation
        {
            synthesize_run_before_first_dependency(
                transaction,
                session_id,
                run_id,
                progress.source_version,
                artifact_root,
            )?;
        }
        event.sequence = next_migrated_sequence(transaction, session_id)?;
        if let Some(parent_id) = event.causal_parent {
            let parent_sequence = transaction
                .query_row(
                    "SELECT sequence FROM events WHERE id = ?1 AND session_id = ?2",
                    params![parent_id.to_string(), session_id],
                    |row| row.get::<_, u64>(0),
                )
                .optional()?;
            if parent_sequence.is_none_or(|parent_sequence| parent_sequence >= event.sequence) {
                return Err(incompatible(
                    progress.source_version,
                    format!(
                        "event {} has a missing or non-prior causal parent",
                        event.id
                    ),
                ));
            }
        }
        match &event.payload {
            EventPayload::SessionCreated { .. } => {
                if event.run_id.is_some()
                    || transaction.execute(
                        "UPDATE migration_v1_session_inventory
                         SET creation_seen = 1
                         WHERE session_id = ?1 AND creation_count = 1
                           AND synthesized = 0 AND creation_seen = 0",
                        [session_id],
                    )? != 1
                {
                    return Err(incompatible(
                        progress.source_version,
                        format!(
                            "session creation event {} is duplicated or follows a dependency",
                            event.id
                        ),
                    ));
                }
            }
            EventPayload::RunCreated { run } => {
                let run_id = run_id.as_deref().ok_or_else(|| {
                    incompatible(
                        progress.source_version,
                        format!("run creation event {} has no run_id", event.id),
                    )
                })?;
                if run.state != RunState::Queued
                    || transaction.execute(
                        "UPDATE migration_v1_run_inventory
                         SET creation_seen = 1, state = 'queued', state_sequence = ?1
                         WHERE run_id = ?2 AND session_id = ?3
                           AND creation_count = 1 AND synthesized = 0
                           AND creation_seen = 0 AND state = 'queued'",
                        params![event.sequence, run_id, session_id],
                    )? != 1
                {
                    return Err(incompatible(
                        progress.source_version,
                        format!(
                            "run creation event {} is non-queued, duplicated, or follows a dependency",
                            event.id
                        ),
                    ));
                }
            }
            EventPayload::RunStateChanged { from, to } => {
                let run_id = run_id.as_deref().ok_or(StoreError::InvalidStateEvent)?;
                if !valid_run_transition(*from, *to)
                    || transaction.execute(
                        "UPDATE migration_v1_run_inventory
                         SET state = ?1, state_sequence = ?2
                         WHERE run_id = ?3 AND session_id = ?4 AND state = ?5
                           AND creation_seen = 1 AND state_sequence < ?2",
                        params![
                            encode_run_state(*to),
                            event.sequence,
                            run_id,
                            session_id,
                            encode_run_state(*from)
                        ],
                    )? != 1
                {
                    return Err(incompatible(
                        progress.source_version,
                        format!("event {} is not a valid state transition", event.id),
                    ));
                }
            }
            EventPayload::BackendEvent { .. } if run_id.is_none() => {
                return Err(incompatible(
                    progress.source_version,
                    format!("backend event {} has no run_id", event.id),
                ));
            }
            _ => {}
        }
        insert_migrated_event(transaction, &event, progress.source_version)?;
    }
    let last = rows.last().expect("non-empty migration batch");
    let changed = transaction.execute(
        "UPDATE store_migration_progress
         SET cursor_session_id = ?1, cursor_sequence = ?2,
             processed_rows = processed_rows + ?3
         WHERE id = 1 AND phase = 'emit_events'",
        params![
            last.1,
            last.3,
            u64::try_from(rows.len()).unwrap_or(u64::MAX)
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn next_migrated_sequence(connection: &Connection, session_id: &str) -> Result<u64, StoreError> {
    let current = connection.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM events WHERE session_id = ?1",
        [session_id],
        |row| row.get::<_, u64>(0),
    )?;
    current.checked_add(1).ok_or(StoreError::SequenceOverflow)
}

fn last_migrated_event_id(
    connection: &Connection,
    session_id: &str,
) -> Result<Option<EventId>, StoreError> {
    let value = connection
        .query_row(
            "SELECT id FROM events WHERE session_id = ?1 ORDER BY sequence DESC LIMIT 1",
            [session_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    value
        .map(|id| serde_json::from_value::<EventId>(serde_json::Value::String(id)))
        .transpose()
        .map_err(StoreError::from)
}

fn migration_provenance() -> Provenance {
    Provenance {
        producer: "birdcode-store-migration/v1-to-v2".to_owned(),
        backend: None,
        raw_artifact: None,
    }
}

fn synthesize_session_before_first_dependency(
    transaction: &Transaction<'_>,
    session_id: &str,
    found: i64,
) -> Result<(), StoreError> {
    let inventory = transaction
        .query_row(
            "SELECT creation_count, synthesized, creation_seen
             FROM migration_v1_session_inventory WHERE session_id = ?1",
            [session_id],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| incompatible(found, format!("unknown migrated session {session_id}")))?;
    if inventory.2 {
        return Ok(());
    }
    if inventory.0 != 0 || inventory.1 {
        return Err(incompatible(
            found,
            format!("session {session_id} has a creation event after a dependent event"),
        ));
    }
    let json = transaction.query_row(
        "SELECT value_json FROM sessions WHERE id = ?1",
        [session_id],
        |row| row.get::<_, String>(0),
    )?;
    let session = serde_json::from_str::<Session>(&json)?;
    let event = EventEnvelope {
        id: EventId::new(),
        sequence: next_migrated_sequence(transaction, session_id)?,
        session_id: session.id,
        run_id: None,
        actor_id: ActorId::new(),
        causal_parent: last_migrated_event_id(transaction, session_id)?,
        occurred_at: session.created_at,
        provenance: migration_provenance(),
        payload: EventPayload::SessionCreated { session },
    };
    insert_migrated_event(transaction, &event, found)?;
    let changed = transaction.execute(
        "UPDATE migration_v1_session_inventory
         SET synthesized = 1, creation_seen = 1
         WHERE session_id = ?1 AND creation_count = 0
           AND synthesized = 0 AND creation_seen = 0",
        [session_id],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn synthesize_run_before_first_dependency(
    transaction: &Transaction<'_>,
    session_id: &str,
    run_id: &str,
    found: i64,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let inventory = transaction
        .query_row(
            "SELECT session_id, creation_count, synthesized, creation_seen
             FROM migration_v1_run_inventory WHERE run_id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| incompatible(found, format!("unknown migrated run {run_id}")))?;
    if inventory.0 != session_id {
        return Err(incompatible(
            found,
            format!("run {run_id} belongs to a different session"),
        ));
    }
    if inventory.3 {
        return Ok(());
    }
    if inventory.1 != 0 || inventory.2 {
        return Err(incompatible(
            found,
            format!("run {run_id} has a creation event after a dependent event"),
        ));
    }
    let json = transaction.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id, session_id],
        |row| row.get::<_, String>(0),
    )?;
    let run = decode_pre_v8_stored_run(&json)?;
    if run.state != RunState::Queued {
        return Err(incompatible(
            found,
            format!("run {run_id} does not have canonical queued creation state"),
        ));
    }
    validate_input_artifacts(artifact_root, &run.spec.input).map_err(|error| {
        incompatible(
            found,
            format!("run {run_id} references an unavailable artifact: {error}"),
        )
    })?;
    let event = EventEnvelope {
        id: EventId::new(),
        sequence: next_migrated_sequence(transaction, session_id)?,
        session_id: run.spec.session_id,
        run_id: Some(run.id),
        actor_id: ActorId::new(),
        causal_parent: last_migrated_event_id(transaction, session_id)?,
        occurred_at: run.created_at,
        provenance: migration_provenance(),
        payload: EventPayload::RunCreated { run },
    };
    insert_migrated_event(transaction, &event, found)?;
    let changed = transaction.execute(
        "UPDATE migration_v1_run_inventory
         SET synthesized = 1, creation_seen = 1, state_sequence = ?1
         WHERE run_id = ?2 AND creation_count = 0
           AND synthesized = 0 AND creation_seen = 0",
        params![event.sequence, run_id],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn synthesize_orphan_session_batch(
    transaction: &Transaction<'_>,
    progress: &LegacyMigrationProgress,
) -> Result<(), StoreError> {
    let session_ids = {
        let mut statement = transaction.prepare(
            "SELECT session_id FROM migration_v1_session_inventory
             WHERE creation_count = 0 AND synthesized = 0
             ORDER BY session_id LIMIT ?1",
        )?;
        statement
            .query_map([MIGRATION_ROW_BATCH_SIZE], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    if session_ids.is_empty() {
        return set_legacy_migration_phase(transaction, "synthesize_runs");
    }
    for session_id in &session_ids {
        synthesize_session_before_first_dependency(
            transaction,
            session_id,
            progress.source_version,
        )?;
    }
    Ok(())
}

fn synthesize_orphan_run_batch(
    transaction: &Transaction<'_>,
    progress: &LegacyMigrationProgress,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let runs = {
        let mut statement = transaction.prepare(
            "SELECT run_id, session_id FROM migration_v1_run_inventory
             WHERE creation_count = 0 AND synthesized = 0
             ORDER BY session_id, run_id LIMIT ?1",
        )?;
        statement
            .query_map([MIGRATION_EVENT_BATCH_SIZE], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if runs.is_empty() {
        return set_legacy_migration_phase(transaction, "validate");
    }
    for (run_id, session_id) in &runs {
        synthesize_run_before_first_dependency(
            transaction,
            session_id,
            run_id,
            progress.source_version,
            artifact_root,
        )?;
    }
    Ok(())
}

fn validate_legacy_migration_inventory(
    connection: &Connection,
    found: i64,
) -> Result<(), StoreError> {
    for (table, id_column, entity) in [
        ("migration_v1_session_inventory", "session_id", "session"),
        ("migration_v1_run_inventory", "run_id", "run"),
    ] {
        let query = format!(
            "SELECT {id_column}, creation_count, synthesized, creation_seen FROM {table}
             WHERE creation_count + synthesized != 1 OR creation_seen != 1 LIMIT 1"
        );
        if let Some((id, count, synthesized, creation_seen)) = connection
            .query_row(&query, [], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, u32>(3)?,
                ))
            })
            .optional()?
        {
            return Err(incompatible(
                found,
                format!(
                    "{entity} {id} has {count} source and {synthesized} synthesized creation events; creation_seen={creation_seen}"
                ),
            ));
        }
    }
    Ok(())
}

fn finalize_legacy_migration(transaction: &Transaction<'_>, _found: i64) -> Result<(), StoreError> {
    // Every target row was inserted with foreign_keys enabled, and causal
    // parents were inserted before their dependents. A final full-table
    // foreign_key_check would only repeat those bounded per-row checks while
    // holding the migration write lock.
    transaction.execute_batch(
        "DROP TABLE events_schema_v1;
         DROP TABLE runs_schema_v1;
         DROP TABLE sessions_schema_v1;
         DROP TABLE migration_v1_events;
         DROP TABLE migration_v1_run_inventory;
         DROP TABLE migration_v1_session_inventory;
         DROP TABLE store_migration_progress;",
    )?;
    transaction.execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)?;
    transaction.pragma_update(None, "user_version", IMMUTABLE_SCHEMA_VERSION)?;
    Ok(())
}
pub(super) fn canonicalize_workspace_root(
    value: &mut serde_json::Value,
    pointer: &str,
    found: i64,
    context: &str,
    required: bool,
) -> Result<bool, StoreError> {
    let Some(workspace_root) = value.pointer_mut(pointer) else {
        if required {
            return Err(incompatible(
                found,
                format!("{context} has no workspace_root"),
            ));
        }
        return Ok(false);
    };
    let serde_json::Value::String(legacy) = workspace_root else {
        return Ok(false);
    };
    let canonical = WorkspacePath::from(PathBuf::from(legacy.as_str()));
    *workspace_root = serde_json::to_value(canonical).map_err(|error| {
        incompatible(
            found,
            format!("{context} workspace_root could not be canonicalized: {error}"),
        )
    })?;
    Ok(true)
}

fn insert_migrated_event(
    transaction: &Transaction<'_>,
    event: &EventEnvelope,
    found: i64,
) -> Result<(), StoreError> {
    let value_json = match encode_inline_event(event) {
        Ok(value) => value,
        Err(StoreError::EventTooLarge) => {
            return Err(incompatible(
                found,
                format!("event {} exceeds the inline event size limit", event.id),
            ));
        }
        Err(error) => return Err(error),
    };
    transaction
        .execute(
            "INSERT INTO events (
                 id, session_id, run_id, causal_parent, sequence, value_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.id.to_string(),
                event.session_id.to_string(),
                event.run_id.map(|value| value.to_string()),
                event.causal_parent.map(|value| value.to_string()),
                event.sequence,
                value_json
            ],
        )
        .map_err(|error| {
            incompatible(
                found,
                format!("event rows violate current integrity rules: {error}"),
            )
        })?;
    Ok(())
}

enum JsonStringPresence {
    Missing,
    Present(Option<String>),
}

fn optional_json_string(
    value: &serde_json::Value,
    key: &str,
    found: i64,
    event_id: &str,
) -> Result<JsonStringPresence, StoreError> {
    match value.get(key) {
        None => Ok(JsonStringPresence::Missing),
        Some(serde_json::Value::Null) => Ok(JsonStringPresence::Present(None)),
        Some(serde_json::Value::String(value)) => {
            Ok(JsonStringPresence::Present(Some(value.clone())))
        }
        Some(_) => Err(incompatible(
            found,
            format!("event {event_id} has a non-string {key}"),
        )),
    }
}

fn validate_legacy_payload_semantics(
    connection: &Connection,
    raw: &serde_json::Value,
    envelope: &EventEnvelope,
    found: i64,
) -> Result<(), StoreError> {
    let Some(legacy_spec) = raw.pointer("/payload/data/spec") else {
        return Ok(());
    };
    if raw
        .pointer("/payload/type")
        .and_then(serde_json::Value::as_str)
        != Some("run_created")
    {
        return Ok(());
    }
    let run_id = envelope
        .run_id
        .ok_or_else(|| incompatible(found, "legacy run_created event has no associated run"))?;
    let run_json = connection.query_row(
        "SELECT value_json FROM runs WHERE id = ?1",
        [run_id.to_string()],
        |row| row.get::<_, String>(0),
    )?;
    let run = decode_pre_v8_stored_run(&run_json).map_err(|error| {
        incompatible(
            found,
            format!("materialized run {run_id} is invalid: {error}"),
        )
    })?;
    let mut normalized_legacy_spec = legacy_spec.clone();
    insert_pre_v8_run_spec_fields(&mut normalized_legacy_spec, "")?;
    if normalized_legacy_spec != serde_json::to_value(run.spec)? {
        return Err(incompatible(
            found,
            format!("legacy run_created event contradicts materialized run {run_id}"),
        ));
    }
    Ok(())
}

fn validate_legacy_shape(
    connection: &Connection,
    found: i64,
    has_causal_parent: bool,
) -> Result<(), StoreError> {
    if known_tables(connection)? != expected_table_names() {
        return Err(incompatible(
            found,
            "legacy database has an incomplete table set",
        ));
    }
    ensure_column_names(connection, "sessions", &["id", "value_json"], found)?;
    ensure_column_names(
        connection,
        "runs",
        &["id", "session_id", "value_json"],
        found,
    )?;
    let event_columns = if has_causal_parent {
        vec![
            "id",
            "session_id",
            "run_id",
            "causal_parent",
            "sequence",
            "value_json",
        ]
    } else {
        vec!["id", "session_id", "run_id", "sequence", "value_json"]
    };
    ensure_column_names(connection, "events", &event_columns, found)
}
