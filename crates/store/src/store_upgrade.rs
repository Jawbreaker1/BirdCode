use super::legacy_migration::{bounded_legacy_metadata_rows, canonicalize_workspace_root};
use super::{
    CHILD_RECONNAISSANCE_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION, Connection, EventEnvelope,
    EventPayload, HEALTH_CANARY_SCHEMA_VERSION, MAX_INLINE_EVENT_BYTES_U64,
    MAX_MIGRATION_METADATA_BYTES, MIGRATION_EVENT_BATCH_SIZE, MIGRATION_ROW_BATCH_SIZE,
    OptionalExtension, PATH_WIRE_SCHEMA_VERSION, Path, PlanAcceptanceContract,
    RUN_STATE_PROJECTION_HEALTH_SQL, RUN_STATE_PROJECTION_INTEGRITY_TRIGGERS_SQL,
    RUN_STATE_PROJECTION_SCHEMA_VERSION, RUN_STATE_PROJECTION_SQL,
    RUN_STATE_PROJECTION_TRIGGERS_SQL, Run, RunPurpose, RunState,
    SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL, STORE_UPGRADE_CONTROL_SQL, Session, StoreError,
    Transaction, TransactionBehavior, decode_canonical_event, decode_pre_v8_canonical_event,
    decode_pre_v8_stored_event_value, decode_pre_v8_stored_run, decode_run_state,
    decode_stored_run, encode_inline_event, encode_run_state, incompatible,
    insert_pre_v8_run_spec_fields, params, table_exists, valid_run_transition,
    validate_current_schema, validate_health_canary, validate_run_state_projection,
    validate_schema, validate_typed_artifact_refs,
};

#[derive(Debug)]
pub(super) struct StoreUpgradeProgress {
    pub(super) source_version: i64,
    pub(super) phase: String,
    pub(super) cursor_rowid: i64,
    pub(super) cursor_session_id: Option<String>,
    pub(super) cursor_sequence: u64,
}

pub(super) fn create_run_state_projection_objects(
    connection: &Connection,
) -> Result<(), StoreError> {
    connection.execute_batch(RUN_STATE_PROJECTION_SQL)?;
    connection.execute_batch(RUN_STATE_PROJECTION_HEALTH_SQL)?;
    connection.execute_batch(RUN_STATE_PROJECTION_INTEGRITY_TRIGGERS_SQL)?;
    Ok(())
}

pub(super) fn begin_store_upgrade(
    transaction: &Transaction<'_>,
    source_version: i64,
) -> Result<(), StoreError> {
    validate_schema(transaction, source_version, true, true)?;
    validate_health_canary(transaction, source_version)?;
    let has_projection = table_exists(transaction, "run_state_projection")?;
    if has_projection != (source_version >= RUN_STATE_PROJECTION_SCHEMA_VERSION) {
        let qualifier = if has_projection {
            "unexpectedly contains"
        } else {
            "is missing"
        };
        return Err(incompatible(
            source_version,
            format!("schema v{source_version} {qualifier} run_state_projection"),
        ));
    }
    transaction.execute_batch(STORE_UPGRADE_CONTROL_SQL)?;
    let phase = if source_version == HEALTH_CANARY_SCHEMA_VERSION {
        transaction.execute_batch(
            "DROP TRIGGER events_are_immutable_on_update;
             DROP TRIGGER events_are_immutable_on_delete;",
        )?;
        "path_sessions"
    } else if source_version == PATH_WIRE_SCHEMA_VERSION {
        create_run_state_projection_objects(transaction)?;
        "replay_sessions"
    } else if source_version == RUN_STATE_PROJECTION_SCHEMA_VERSION {
        validate_run_state_projection(transaction, source_version)?;
        transaction.execute_batch(
            "DROP TRIGGER events_are_immutable_on_update;
             DROP TRIGGER events_are_immutable_on_delete;",
        )?;
        "acceptance_runs"
    } else {
        return Err(incompatible(
            source_version,
            "durable upgrade can only start from schema v5, v6, or v7",
        ));
    };
    transaction.execute(
        "INSERT INTO store_upgrade_progress (
             id, source_version, phase, cursor_rowid, cursor_session_id,
             cursor_sequence, processed_rows
         ) VALUES (1, ?1, ?2, 0, NULL, 0, 0)",
        params![source_version, phase],
    )?;
    Ok(())
}

pub(super) fn resume_store_upgrade_batch(
    connection: &mut Connection,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !table_exists(&transaction, "store_upgrade_progress")? {
        transaction.commit()?;
        return Ok(());
    }
    let progress = read_store_upgrade_progress(&transaction)?;
    match progress.phase.as_str() {
        "path_sessions" => upgrade_path_session_batch(&transaction, &progress)?,
        "path_events" => upgrade_path_event_batch(&transaction, &progress)?,
        "replay_sessions" => upgrade_replay_session_batch(&transaction, &progress)?,
        "replay_runs" => upgrade_replay_run_batch(&transaction, &progress)?,
        "replay_events" => {
            upgrade_replay_event_batch(&transaction, &progress, artifact_root)?;
        }
        "replay_validate" => {
            validate_upgrade_replay(&transaction, progress.source_version)?;
            set_store_upgrade_phase(&transaction, "project_runs")?;
        }
        "project_runs" => upgrade_project_run_batch(&transaction, &progress)?,
        "acceptance_runs" => upgrade_acceptance_run_batch(&transaction, &progress)?,
        "acceptance_events" => upgrade_acceptance_event_batch(&transaction, &progress)?,
        "acceptance_validate_runs" => {
            validate_acceptance_run_batch(&transaction, &progress)?;
        }
        "finalize" => finalize_store_upgrade(&transaction, progress.source_version)?,
        other => {
            return Err(incompatible(
                progress.source_version,
                format!("store upgrade has unknown phase {other}"),
            ));
        }
    }
    transaction.commit()?;
    Ok(())
}

pub(super) fn read_store_upgrade_progress(
    connection: &Connection,
) -> Result<StoreUpgradeProgress, StoreError> {
    connection
        .query_row(
            "SELECT source_version, phase, cursor_rowid,
                    cursor_session_id, cursor_sequence
             FROM store_upgrade_progress WHERE id = 1",
            [],
            |row| {
                Ok(StoreUpgradeProgress {
                    source_version: row.get(0)?,
                    phase: row.get(1)?,
                    cursor_rowid: row.get(2)?,
                    cursor_session_id: row.get(3)?,
                    cursor_sequence: row.get(4)?,
                })
            },
        )
        .map_err(StoreError::from)
}

fn set_store_upgrade_phase(connection: &Connection, phase: &str) -> Result<(), StoreError> {
    if connection.execute(
        "UPDATE store_upgrade_progress
         SET phase = ?1, cursor_rowid = 0, cursor_session_id = NULL,
             cursor_sequence = 0
         WHERE id = 1",
        [phase],
    )? != 1
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn advance_store_upgrade_row_cursor(
    connection: &Connection,
    phase: &str,
    rowid: i64,
    processed: usize,
) -> Result<(), StoreError> {
    if connection.execute(
        "UPDATE store_upgrade_progress
         SET cursor_rowid = ?1, processed_rows = processed_rows + ?2
         WHERE id = 1 AND phase = ?3",
        params![rowid, u64::try_from(processed).unwrap_or(u64::MAX), phase],
    )? != 1
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn upgrade_path_session_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let rows = bounded_legacy_metadata_rows(transaction, "sessions", progress.cursor_rowid)?;
    if rows.is_empty() {
        return set_store_upgrade_phase(transaction, "path_events");
    }
    for (rowid, id, json, bytes) in &rows {
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
        let normalized = serde_json::to_string(&session)?;
        if normalized != *json
            && transaction.execute(
                "UPDATE sessions SET value_json = ?1
                 WHERE rowid = ?2 AND id = ?3 AND value_json = ?4",
                params![normalized, rowid, id, json],
            )? != 1
        {
            return Err(incompatible(
                progress.source_version,
                format!("materialized session {id} changed during migration"),
            ));
        }
    }
    advance_store_upgrade_row_cursor(
        transaction,
        "path_sessions",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

fn upgrade_path_event_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let rows = bounded_event_json_rows(
        transaction,
        "events",
        progress.source_version,
        true,
        Some(progress.cursor_rowid),
    )?;
    if rows.is_empty() {
        create_run_state_projection_objects(transaction)?;
        return set_store_upgrade_phase(transaction, "replay_sessions");
    }
    for (rowid, id, session_id, run_id, causal_parent, sequence, json) in &rows {
        let mut value = serde_json::from_str::<serde_json::Value>(json).map_err(|error| {
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
        let event = decode_pre_v8_stored_event_value(value).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("event {id} is invalid after path migration: {error}"),
            )
        })?;
        if event.id.to_string() != *id
            || event.session_id.to_string() != *session_id
            || event.run_id.map(|value| value.to_string()) != *run_id
            || event.causal_parent.map(|value| value.to_string()) != *causal_parent
            || event.sequence != *sequence
        {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} columns contradict its canonical envelope"),
            ));
        }
        let normalized = encode_inline_event(&event).map_err(|error| match error {
            StoreError::EventTooLarge => incompatible(
                progress.source_version,
                format!("event {id} exceeds the inline event size limit after path migration"),
            ),
            other => other,
        })?;
        if normalized != *json
            && transaction.execute(
                "UPDATE events SET value_json = ?1
                 WHERE rowid = ?2 AND id = ?3 AND value_json = ?4",
                params![normalized, rowid, id, json],
            )? != 1
        {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} changed during migration"),
            ));
        }
    }
    advance_store_upgrade_row_cursor(
        transaction,
        "path_events",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

fn upgrade_replay_session_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let rows = bounded_legacy_metadata_rows(transaction, "sessions", progress.cursor_rowid)?;
    if rows.is_empty() {
        return set_store_upgrade_phase(transaction, "replay_runs");
    }
    for (_, id, json, bytes) in &rows {
        if *bytes > MAX_MIGRATION_METADATA_BYTES {
            return Err(incompatible(
                progress.source_version,
                format!("materialized session {id} exceeds the replay metadata limit"),
            ));
        }
        let session = serde_json::from_str::<Session>(json).map_err(|error| {
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
            "INSERT INTO store_upgrade_replay_sessions (id) VALUES (?1)",
            [id],
        )?;
    }
    advance_store_upgrade_row_cursor(
        transaction,
        "replay_sessions",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

fn upgrade_replay_run_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let rows = bounded_legacy_metadata_rows(transaction, "runs", progress.cursor_rowid)?;
    if rows.is_empty() {
        return set_store_upgrade_phase(transaction, "replay_events");
    }
    for (_, id, json, bytes) in &rows {
        if *bytes > MAX_MIGRATION_METADATA_BYTES {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} exceeds the replay metadata limit"),
            ));
        }
        let session_id =
            transaction.query_row("SELECT session_id FROM runs WHERE id = ?1", [id], |row| {
                row.get::<_, String>(0)
            })?;
        let run = decode_pre_v8_stored_run(json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized run {id} is invalid: {error}"),
            )
        })?;
        let session_exists = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM store_upgrade_replay_sessions WHERE id = ?1
             )",
            [&session_id],
            |row| row.get::<_, bool>(0),
        )?;
        if run.id.to_string() != *id
            || run.spec.session_id.to_string() != session_id
            || run.state != RunState::Queued
            || !session_exists
        {
            return Err(incompatible(
                progress.source_version,
                format!(
                    "materialized run {id} contradicts its keys, session, or queued creation state"
                ),
            ));
        }
        transaction.execute(
            "INSERT INTO store_upgrade_replay_runs (
                 id, session_id, state
             ) VALUES (?1, ?2, ?3)",
            params![id, session_id, encode_run_state(run.state)],
        )?;
    }
    if transaction.execute(
        "UPDATE run_state_projection_health
         SET materialized_runs = materialized_runs + ?1 WHERE id = 1",
        [u64::try_from(rows.len()).unwrap_or(u64::MAX)],
    )? != 1
    {
        return Err(StoreError::InvalidStateEvent);
    }
    advance_store_upgrade_row_cursor(
        transaction,
        "replay_runs",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "bounded replay keeps canonical columns, artifacts, creations, and transitions together"
)]
fn upgrade_replay_event_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    let cursor_session = progress.cursor_session_id.as_deref().unwrap_or("");
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT id, session_id, run_id, causal_parent, sequence,
                    length(CAST(value_json AS BLOB)),
                    CASE WHEN length(CAST(value_json AS BLOB)) <= ?1
                         THEN value_json END
             FROM events
             WHERE session_id > ?2
                OR (session_id = ?2 AND sequence > ?3)
             ORDER BY session_id, sequence LIMIT ?4",
        )?;
        statement
            .query_map(
                params![
                    MAX_INLINE_EVENT_BYTES_U64,
                    cursor_session,
                    progress.cursor_sequence,
                    MIGRATION_EVENT_BATCH_SIZE
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let Some(last) = rows.last().map(|row| (row.1.clone(), row.4)) else {
        return set_store_upgrade_phase(transaction, "replay_validate");
    };
    for (id, session_id, run_id, causal_parent, sequence, bytes, json) in &rows {
        if *bytes > MAX_INLINE_EVENT_BYTES_U64 {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} exceeds the inline event size limit"),
            ));
        }
        let event = decode_pre_v8_canonical_event(json.as_deref().ok_or_else(|| {
            incompatible(
                progress.source_version,
                format!("event {id} could not be read within its size limit"),
            )
        })?)
        .map_err(|error| {
            incompatible(
                progress.source_version,
                format!("event {id} is not replayable: {error}"),
            )
        })?;
        if event.id.to_string() != *id
            || event.session_id.to_string() != *session_id
            || event.run_id.map(|value| value.to_string()) != *run_id
            || event.causal_parent.map(|value| value.to_string()) != *causal_parent
            || event.sequence != *sequence
        {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} columns contradict its canonical envelope"),
            ));
        }
        if let Some(parent_id) = causal_parent {
            let parent_sequence = transaction
                .query_row(
                    "SELECT sequence FROM events WHERE id = ?1 AND session_id = ?2",
                    params![parent_id, session_id],
                    |row| row.get::<_, u64>(0),
                )
                .optional()?;
            if parent_sequence.is_none_or(|parent_sequence| parent_sequence >= *sequence) {
                return Err(incompatible(
                    progress.source_version,
                    format!("event {id} has a missing or non-prior causal parent"),
                ));
            }
        }
        let session_creation_count = transaction
            .query_row(
                "SELECT creation_count FROM store_upgrade_replay_sessions WHERE id = ?1",
                [session_id],
                |row| row.get::<_, u32>(0),
            )
            .optional()?
            .ok_or_else(|| {
                incompatible(
                    progress.source_version,
                    format!("event {id} belongs to an unknown session"),
                )
            })?;
        let is_session_creation = matches!(&event.payload, EventPayload::SessionCreated { .. });
        let is_run_creation = matches!(&event.payload, EventPayload::RunCreated { .. });
        if !is_session_creation && session_creation_count != 1 {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} precedes its session creation event"),
            ));
        }
        if let Some(run_id) = run_id
            && !is_run_creation
        {
            let run_creation_count = transaction
                .query_row(
                    "SELECT creation_count FROM store_upgrade_replay_runs
                     WHERE id = ?1 AND session_id = ?2",
                    params![run_id, session_id],
                    |row| row.get::<_, u32>(0),
                )
                .optional()?;
            if run_creation_count != Some(1) {
                return Err(incompatible(
                    progress.source_version,
                    format!("run-scoped event {id} precedes its run creation event"),
                ));
            }
        }
        validate_typed_artifact_refs(artifact_root, &event.provenance, &event.payload).map_err(
            |error| {
                incompatible(
                    progress.source_version,
                    format!("event {id} references invalid durable artifacts: {error}"),
                )
            },
        )?;
        match event.payload {
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
                if event.run_id.is_some()
                    || materialized.as_ref() != Some(&session)
                    || transaction.execute(
                        "UPDATE store_upgrade_replay_sessions
                         SET creation_count = 1
                         WHERE id = ?1 AND creation_count = 0",
                        [session_id],
                    )? != 1
                {
                    return Err(incompatible(
                        progress.source_version,
                        format!("session creation event {id} contradicts materialized state"),
                    ));
                }
            }
            EventPayload::RunCreated { run } => {
                let run_id = run_id.as_ref().ok_or_else(|| {
                    incompatible(
                        progress.source_version,
                        format!("run creation event {id} has no run_id"),
                    )
                })?;
                let materialized = transaction
                    .query_row(
                        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
                        params![run_id, session_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                let materialized = materialized
                    .as_deref()
                    .map(decode_pre_v8_stored_run)
                    .transpose()?;
                if run.state != RunState::Queued
                    || materialized.as_ref() != Some(&run)
                    || transaction.execute(
                        "UPDATE store_upgrade_replay_runs
                         SET creation_count = 1, state = 'queued', state_sequence = ?1
                         WHERE id = ?2 AND session_id = ?3
                           AND creation_count = 0 AND state = 'queued'
                           AND state_sequence = 0",
                        params![sequence, run_id, session_id],
                    )? != 1
                {
                    return Err(incompatible(
                        progress.source_version,
                        format!("run creation event {id} contradicts materialized state"),
                    ));
                }
            }
            EventPayload::RunStateChanged { from, to } => {
                let run_id = run_id.as_ref().ok_or_else(|| {
                    incompatible(
                        progress.source_version,
                        format!("state event {id} has no run_id"),
                    )
                })?;
                if !valid_run_transition(from, to)
                    || transaction.execute(
                        "UPDATE store_upgrade_replay_runs
                         SET state = ?1, state_sequence = ?2
                         WHERE id = ?3 AND session_id = ?4 AND state = ?5
                           AND creation_count = 1 AND state_sequence < ?2",
                        params![
                            encode_run_state(to),
                            sequence,
                            run_id,
                            session_id,
                            encode_run_state(from)
                        ],
                    )? != 1
                {
                    return Err(incompatible(
                        progress.source_version,
                        format!("state event {id} is not a valid transition"),
                    ));
                }
            }
            EventPayload::BackendEvent { .. } if run_id.is_none() => {
                return Err(incompatible(
                    progress.source_version,
                    format!("backend event {id} has no run_id"),
                ));
            }
            _ => {}
        }
    }
    if transaction.execute(
        "UPDATE store_upgrade_progress
         SET cursor_session_id = ?1, cursor_sequence = ?2,
             processed_rows = processed_rows + ?3
         WHERE id = 1 AND phase = 'replay_events'",
        params![
            last.0,
            last.1,
            u64::try_from(rows.len()).unwrap_or(u64::MAX)
        ],
    )? != 1
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn validate_upgrade_replay(connection: &Connection, found: i64) -> Result<(), StoreError> {
    for (table, entity) in [
        ("store_upgrade_replay_sessions", "session"),
        ("store_upgrade_replay_runs", "run"),
    ] {
        let query = format!(
            "SELECT id, creation_count FROM {table}
             WHERE creation_count != 1 LIMIT 1"
        );
        if let Some((id, count)) = connection
            .query_row(&query, [], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
            })
            .optional()?
        {
            return Err(incompatible(
                found,
                format!("{entity} {id} has {count} creation events; expected one"),
            ));
        }
    }
    let missing_sequence = connection
        .query_row(
            "SELECT id FROM store_upgrade_replay_runs
             WHERE state_sequence < 1 LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(id) = missing_sequence {
        return Err(incompatible(
            found,
            format!("run {id} has no authoritative state sequence"),
        ));
    }
    Ok(())
}

fn upgrade_project_run_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let after_id = progress.cursor_session_id.as_deref().unwrap_or("");
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT id, session_id, state, state_sequence
             FROM store_upgrade_replay_runs
             WHERE id > ?1 ORDER BY id LIMIT ?2",
        )?;
        statement
            .query_map(params![after_id, MIGRATION_ROW_BATCH_SIZE], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let Some(last_id) = rows.last().map(|row| row.0.clone()) else {
        return set_store_upgrade_phase(transaction, "finalize");
    };
    for (id, session_id, state, state_sequence) in &rows {
        decode_run_state(state)?;
        transaction.execute(
            "INSERT INTO run_state_projection (
                 run_id, session_id, state, state_sequence
             ) VALUES (?1, ?2, ?3, ?4)",
            params![id, session_id, state, state_sequence],
        )?;
    }
    if transaction.execute(
        "UPDATE store_upgrade_progress
         SET cursor_session_id = ?1, processed_rows = processed_rows + ?2
         WHERE id = 1 AND phase = 'project_runs'",
        params![last_id, u64::try_from(rows.len()).unwrap_or(u64::MAX)],
    )? != 1
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn upgrade_acceptance_run_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let rows = bounded_legacy_metadata_rows(transaction, "runs", progress.cursor_rowid)?;
    if rows.is_empty() {
        return set_store_upgrade_phase(transaction, "acceptance_events");
    }
    for (rowid, id, json, bytes) in &rows {
        if *bytes > MAX_MIGRATION_METADATA_BYTES {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} exceeds the acceptance migration limit"),
            ));
        }
        let mut value = serde_json::from_str::<serde_json::Value>(json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized run {id} contains invalid JSON: {error}"),
            )
        })?;
        insert_pre_v8_run_spec_fields(&mut value, "/spec").map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized run {id} has an invalid historical contract: {error}"),
            )
        })?;
        let run = serde_json::from_value::<Run>(value).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized run {id} is invalid: {error}"),
            )
        })?;
        let session_id = transaction.query_row(
            "SELECT session_id FROM runs WHERE rowid = ?1 AND id = ?2",
            params![rowid, id],
            |row| row.get::<_, String>(0),
        )?;
        if run.id.to_string() != *id
            || run.spec.session_id.to_string() != session_id
            || run.state != RunState::Queued
            || !historical_run_acceptance_contract_is_valid(&run)
        {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} contradicts its historical identity or contract"),
            ));
        }
        let normalized = serde_json::to_string(&run)?;
        if normalized != *json
            && transaction.execute(
                "UPDATE runs SET value_json = ?1
                 WHERE rowid = ?2 AND id = ?3 AND value_json = ?4",
                params![normalized, rowid, id, json],
            )? != 1
        {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} changed during acceptance migration"),
            ));
        }
    }
    advance_store_upgrade_row_cursor(
        transaction,
        "acceptance_runs",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

fn upgrade_acceptance_event_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let rows = bounded_event_json_rows(
        transaction,
        "events",
        progress.source_version,
        true,
        Some(progress.cursor_rowid),
    )?;
    if rows.is_empty() {
        return set_store_upgrade_phase(transaction, "acceptance_validate_runs");
    }
    for (rowid, id, session_id, run_id, causal_parent, sequence, json) in &rows {
        let mut value = serde_json::from_str::<serde_json::Value>(json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("event {id} contains invalid JSON: {error}"),
            )
        })?;
        insert_pre_v8_run_spec_fields(&mut value, "/payload/data/run/spec").map_err(|error| {
            incompatible(
                progress.source_version,
                format!("event {id} has an invalid historical contract: {error}"),
            )
        })?;
        let event = serde_json::from_value::<EventEnvelope>(value).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("event {id} is invalid: {error}"),
            )
        })?;
        if event.id.to_string() != *id
            || event.session_id.to_string() != *session_id
            || event.run_id.map(|value| value.to_string()) != *run_id
            || event.causal_parent.map(|value| value.to_string()) != *causal_parent
            || event.sequence != *sequence
            || matches!(
                &event.payload,
                EventPayload::RunCreated { run }
                    if !historical_run_acceptance_contract_is_valid(run)
            )
        {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} contradicts its historical columns or contract"),
            ));
        }
        let normalized = encode_inline_event(&event).map_err(|error| match error {
            StoreError::EventTooLarge => incompatible(
                progress.source_version,
                format!("event {id} exceeds the inline limit after acceptance migration"),
            ),
            other => other,
        })?;
        if normalized != *json
            && transaction.execute(
                "UPDATE events SET value_json = ?1
                 WHERE rowid = ?2 AND id = ?3 AND value_json = ?4",
                params![normalized, rowid, id, json],
            )? != 1
        {
            return Err(incompatible(
                progress.source_version,
                format!("event {id} changed during acceptance migration"),
            ));
        }
    }
    advance_store_upgrade_row_cursor(
        transaction,
        "acceptance_events",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

fn validate_acceptance_run_batch(
    transaction: &Transaction<'_>,
    progress: &StoreUpgradeProgress,
) -> Result<(), StoreError> {
    let rows = bounded_legacy_metadata_rows(transaction, "runs", progress.cursor_rowid)?;
    if rows.is_empty() {
        return set_store_upgrade_phase(transaction, "finalize");
    }
    for (_, id, json, bytes) in &rows {
        if *bytes > MAX_MIGRATION_METADATA_BYTES {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} exceeds the acceptance validation limit"),
            ));
        }
        let run = decode_stored_run(json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("materialized run {id} is not protocol-v5 canonical: {error}"),
            )
        })?;
        if run.id.to_string() != *id
            || run.state != RunState::Queued
            || !historical_run_acceptance_contract_is_valid(&run)
        {
            return Err(incompatible(
                progress.source_version,
                format!("materialized run {id} has an invalid migrated contract"),
            ));
        }
        let creation_rows = {
            let mut statement = transaction.prepare(
                "SELECT id, sequence, value_json FROM events
                 WHERE run_id = ?1 AND session_id = ?2
                   AND json_extract(value_json, '$.payload.type') = 'run_created'
                 ORDER BY sequence LIMIT 2",
            )?;
            statement
                .query_map(params![id, run.spec.session_id.to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let [(event_id, sequence, event_json)] = creation_rows.as_slice() else {
            return Err(incompatible(
                progress.source_version,
                format!("run {id} does not have exactly one canonical creation event"),
            ));
        };
        let creation = decode_canonical_event(event_json).map_err(|error| {
            incompatible(
                progress.source_version,
                format!("run {id} creation event is not protocol-v5 canonical: {error}"),
            )
        })?;
        if creation.id.to_string() != *event_id
            || creation.sequence != *sequence
            || creation.session_id != run.spec.session_id
            || creation.run_id != Some(run.id)
            || !matches!(creation.payload, EventPayload::RunCreated { run: created } if created == run)
        {
            return Err(incompatible(
                progress.source_version,
                format!("run {id} creation event contradicts materialized state"),
            ));
        }
    }
    advance_store_upgrade_row_cursor(
        transaction,
        "acceptance_validate_runs",
        rows.last().map_or(progress.cursor_rowid, |row| row.0),
        rows.len(),
    )
}

const fn historical_run_acceptance_contract_is_valid(run: &Run) -> bool {
    matches!(
        (run.spec.purpose, run.spec.plan_acceptance),
        (
            RunPurpose::PlanOnly,
            PlanAcceptanceContract::LegacyMechanicalOnlyV4
        ) | (RunPurpose::Execute, PlanAcceptanceContract::NotApplicable)
    )
}

fn finalize_store_upgrade(
    transaction: &Transaction<'_>,
    source_version: i64,
) -> Result<(), StoreError> {
    // Replay validates every source relationship with indexed point lookups;
    // projection rows are then inserted with foreign_keys enabled. Avoid a
    // second unbounded foreign_key_check while the final write lock is held.
    if matches!(
        source_version,
        HEALTH_CANARY_SCHEMA_VERSION | RUN_STATE_PROJECTION_SCHEMA_VERSION
    ) {
        transaction.execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)?;
    }
    if source_version < RUN_STATE_PROJECTION_SCHEMA_VERSION {
        transaction.execute_batch(RUN_STATE_PROJECTION_TRIGGERS_SQL)?;
    }
    transaction.execute_batch(
        "DROP TABLE store_upgrade_replay_runs;
         DROP TABLE store_upgrade_replay_sessions;
         DROP TABLE store_upgrade_progress;",
    )?;
    let target_version = if source_version < RUN_STATE_PROJECTION_SCHEMA_VERSION {
        RUN_STATE_PROJECTION_SCHEMA_VERSION
    } else {
        CHILD_RECONNAISSANCE_SCHEMA_VERSION
    };
    transaction.pragma_update(None, "user_version", target_version)?;
    if target_version == CURRENT_SCHEMA_VERSION {
        validate_current_schema(transaction)?;
    } else {
        validate_schema(transaction, target_version, true, true)?;
        validate_health_canary(transaction, target_version)?;
        validate_run_state_projection(transaction, target_version)?;
    }
    Ok(())
}

type StoredEventJsonRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    u64,
    String,
);

fn bounded_event_json_rows(
    transaction: &Transaction<'_>,
    table: &str,
    found: i64,
    has_causal_parent: bool,
    after_rowid: Option<i64>,
) -> Result<Vec<StoredEventJsonRow>, StoreError> {
    let causal_parent = if has_causal_parent {
        "causal_parent"
    } else {
        "NULL"
    };
    let query = format!(
        "SELECT rowid, id, session_id, run_id, {causal_parent},
                sequence, length(CAST(value_json AS BLOB)),
                CASE WHEN length(CAST(value_json AS BLOB)) <= ?1 THEN value_json END
         FROM {table}
         WHERE (?2 IS NULL OR rowid > ?2)
         ORDER BY rowid LIMIT ?3"
    );
    let mut statement = transaction.prepare(&query)?;
    let rows = statement.query_map(
        params![
            MAX_INLINE_EVENT_BYTES_U64,
            after_rowid,
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
    )?;
    let mut result = Vec::new();
    for row in rows {
        let (rowid, id, session_id, run_id, causal_parent, sequence, encoded_bytes, json) = row?;
        if encoded_bytes > MAX_INLINE_EVENT_BYTES_U64 {
            return Err(incompatible(
                found,
                format!("event {id} exceeds the inline event size limit"),
            ));
        }
        let json = json.ok_or_else(|| {
            incompatible(
                found,
                format!("event {id} could not be read within its size limit"),
            )
        })?;
        result.push((rowid, id, session_id, run_id, causal_parent, sequence, json));
    }
    Ok(result)
}
