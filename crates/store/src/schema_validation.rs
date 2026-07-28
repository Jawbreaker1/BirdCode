//! Canonical `SQLite` schema and integrity validation.

use super::{
    AGENT_RUNTIME_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION, EVENT_RUN_SEQUENCE_INDEX_SQL,
    HEALTH_CANARY_SCHEMA_VERSION, RUN_STATE_PROJECTION_SCHEMA_VERSION, StoreError, ensure_columns,
    expected_table_names, foreign_keys, has_foreign_key, incompatible, known_tables, normalize_sql,
    projection_validation::{validate_event_identity_projection, validate_run_state_projection},
    schema_version, table_exists, unique_indexes, user_schema_object_names,
};
use rusqlite::Connection;
use std::collections::BTreeMap;

pub(super) fn validate_current_schema(connection: &Connection) -> Result<(), StoreError> {
    validate_schema(connection, CURRENT_SCHEMA_VERSION, true, true)?;
    validate_health_canary(connection, CURRENT_SCHEMA_VERSION)?;
    validate_run_state_projection(connection, CURRENT_SCHEMA_VERSION)?;
    validate_event_identity_projection(connection, CURRENT_SCHEMA_VERSION)
}

pub(super) fn validate_schema(
    connection: &Connection,
    expected_version: i64,
    has_v3_integrity_objects: bool,
    has_event_size_guard: bool,
) -> Result<(), StoreError> {
    let found = schema_version(connection)?;
    if found != expected_version {
        return Err(incompatible(
            found,
            format!("expected canonical schema version {expected_version}"),
        ));
    }
    if known_tables(connection)? != expected_table_names() {
        return Err(incompatible(
            found,
            "current schema has an incomplete table set",
        ));
    }

    ensure_columns(
        connection,
        "sessions",
        &[("id", "TEXT", true, 1), ("value_json", "TEXT", true, 0)],
        found,
    )?;
    ensure_columns(
        connection,
        "runs",
        &[
            ("id", "TEXT", true, 1),
            ("session_id", "TEXT", true, 0),
            ("value_json", "TEXT", true, 0),
        ],
        found,
    )?;
    ensure_columns(
        connection,
        "events",
        &[
            ("id", "TEXT", true, 1),
            ("session_id", "TEXT", true, 0),
            ("run_id", "TEXT", false, 0),
            ("causal_parent", "TEXT", false, 0),
            ("sequence", "INTEGER", true, 0),
            ("value_json", "TEXT", true, 0),
        ],
        found,
    )?;
    validate_core_table_definitions(connection, found)?;
    validate_user_table_and_view_set(connection, found, expected_version)?;

    for (table, expected) in [
        ("runs", vec![vec!["id", "session_id"]]),
        (
            "events",
            vec![vec!["id", "session_id"], vec!["session_id", "sequence"]],
        ),
    ] {
        let indexes = unique_indexes(connection, table)?;
        for columns in expected {
            if !indexes.iter().any(|value| value == &columns) {
                return Err(incompatible(
                    found,
                    format!("{table} is missing UNIQUE({})", columns.join(", ")),
                ));
            }
        }
    }

    let run_keys = foreign_keys(connection, "runs")?;
    if !has_foreign_key(&run_keys, "sessions", &[("session_id", "id")]) {
        return Err(incompatible(
            found,
            "runs is missing its session foreign key",
        ));
    }
    let event_keys = foreign_keys(connection, "events")?;
    for (target, columns, description) in [
        ("sessions", vec![("session_id", "id")], "session"),
        (
            "runs",
            vec![("run_id", "id"), ("session_id", "session_id")],
            "session-scoped run",
        ),
        (
            "events",
            vec![("causal_parent", "id"), ("session_id", "session_id")],
            "session-scoped causal parent",
        ),
    ] {
        if !has_foreign_key(&event_keys, target, &columns) {
            return Err(incompatible(
                found,
                format!("events is missing its {description} foreign key"),
            ));
        }
    }

    validate_immutability_triggers(
        connection,
        found,
        has_v3_integrity_objects,
        has_event_size_guard,
        expected_version >= RUN_STATE_PROJECTION_SCHEMA_VERSION,
        expected_version >= AGENT_RUNTIME_SCHEMA_VERSION,
    )?;
    validate_explicit_indexes(connection, found, has_v3_integrity_objects)?;
    Ok(())
}

fn validate_core_table_definitions(connection: &Connection, found: i64) -> Result<(), StoreError> {
    let expected = [
        (
            "sessions",
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY NOT NULL,
                value_json TEXT NOT NULL
            )",
        ),
        (
            "runs",
            "CREATE TABLE runs (
                id TEXT PRIMARY KEY NOT NULL,
                session_id TEXT NOT NULL,
                value_json TEXT NOT NULL,
                UNIQUE(id, session_id),
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )",
        ),
        (
            "events",
            "CREATE TABLE events (
                id TEXT PRIMARY KEY NOT NULL,
                session_id TEXT NOT NULL,
                run_id TEXT,
                causal_parent TEXT,
                sequence INTEGER NOT NULL,
                value_json TEXT NOT NULL,
                UNIQUE(id, session_id),
                UNIQUE(session_id, sequence),
                FOREIGN KEY(session_id) REFERENCES sessions(id),
                FOREIGN KEY(run_id, session_id) REFERENCES runs(id, session_id),
                FOREIGN KEY(causal_parent, session_id) REFERENCES events(id, session_id)
            )",
        ),
    ];
    for (table, expected_sql) in expected {
        let actual = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, String>(0),
        )?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(incompatible(
                found,
                format!("{table} table definition is altered"),
            ));
        }
    }
    Ok(())
}

fn validate_user_table_and_view_set(
    connection: &Connection,
    found: i64,
    expected_version: i64,
) -> Result<(), StoreError> {
    let mut expected_tables = expected_table_names();
    if expected_version >= HEALTH_CANARY_SCHEMA_VERSION {
        expected_tables.insert("runtime_health_canary".to_owned());
    }
    if expected_version >= RUN_STATE_PROJECTION_SCHEMA_VERSION {
        expected_tables.insert("run_state_projection".to_owned());
        expected_tables.insert("run_state_projection_health".to_owned());
    }
    if expected_version >= AGENT_RUNTIME_SCHEMA_VERSION {
        expected_tables.insert("event_identity_projection".to_owned());
    }
    let actual_tables = user_schema_object_names(connection, "table")?;
    if actual_tables != expected_tables {
        return Err(incompatible(
            found,
            format!("unexpected user table set: {actual_tables:?}"),
        ));
    }
    let views = user_schema_object_names(connection, "view")?;
    if !views.is_empty() {
        return Err(incompatible(
            found,
            format!("unexpected views in durable schema: {views:?}"),
        ));
    }
    Ok(())
}

pub(super) fn validate_health_canary(
    connection: &Connection,
    found: i64,
) -> Result<(), StoreError> {
    if !table_exists(connection, "runtime_health_canary")? {
        return Err(incompatible(
            found,
            "runtime health canary table is missing",
        ));
    }
    ensure_columns(
        connection,
        "runtime_health_canary",
        &[
            ("id", "INTEGER", true, 1),
            ("generation", "INTEGER", true, 0),
        ],
        found,
    )?;
    let table_sql = connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type = 'table' AND name = 'runtime_health_canary'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let expected_sql = "CREATE TABLE runtime_health_canary (
        id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
        generation INTEGER NOT NULL
    )";
    if normalize_sql(&table_sql) != normalize_sql(expected_sql) {
        return Err(incompatible(
            found,
            "runtime health canary table definition is altered",
        ));
    }
    let rows = {
        let mut statement =
            connection.prepare("SELECT id, generation FROM runtime_health_canary")?;
        statement
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?
    };
    if !matches!(rows.as_slice(), [(1, generation)] if *generation >= 0) {
        return Err(incompatible(
            found,
            "runtime health canary must contain exactly one valid row",
        ));
    }
    Ok(())
}

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_lines,
    reason = "exact trigger SQL validation is intentionally colocated and auditable"
)]
fn validate_immutability_triggers(
    connection: &Connection,
    version: i64,
    has_insert_conflict_guard: bool,
    has_event_size_guard: bool,
    has_run_state_projection: bool,
    has_event_identity_projection: bool,
) -> Result<(), StoreError> {
    let mut statement = connection
        .prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' ORDER BY name")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let actual = rows.collect::<Result<BTreeMap<_, _>, _>>()?;
    let expected = [
        (
            "events_are_immutable_on_update",
            "CREATE TRIGGER events_are_immutable_on_update
             BEFORE UPDATE ON events BEGIN
                 SELECT RAISE(ABORT, 'events are immutable');
             END",
        ),
        (
            "events_are_immutable_on_delete",
            "CREATE TRIGGER events_are_immutable_on_delete
             BEFORE DELETE ON events BEGIN
                 SELECT RAISE(ABORT, 'events are immutable');
             END",
        ),
        (
            "events_reject_conflicting_insert",
            "CREATE TRIGGER events_reject_conflicting_insert
             BEFORE INSERT ON events
             WHEN EXISTS (
                 SELECT 1 FROM events
                 WHERE id = NEW.id
                    OR (session_id = NEW.session_id AND sequence = NEW.sequence)
             ) BEGIN
                 SELECT RAISE(ABORT, 'events are append-only');
             END",
        ),
        (
            "events_reject_oversized_insert",
            "CREATE TRIGGER events_reject_oversized_insert
             BEFORE INSERT ON events
             WHEN length(CAST(NEW.value_json AS BLOB)) > 262144 BEGIN
                 SELECT RAISE(ABORT, 'event exceeds inline size limit');
             END",
        ),
        (
            "events_project_run_creation_after_insert",
            "CREATE TRIGGER events_project_run_creation_after_insert
             AFTER INSERT ON events
             WHEN json_extract(NEW.value_json, '$.payload.type') = 'run_created'
             BEGIN
                 SELECT CASE
                     WHEN json_extract(NEW.value_json, '$.payload.data.run.state') != 'queued'
                     THEN RAISE(ABORT, 'run creation state must be queued')
                 END;
                 INSERT INTO run_state_projection (
                     run_id, session_id, state, state_sequence
                 ) VALUES (
                     NEW.run_id,
                     NEW.session_id,
                     json_extract(NEW.value_json, '$.payload.data.run.state'),
                     NEW.sequence
                 );
             END",
        ),
        (
            "events_project_run_state_after_insert",
            "CREATE TRIGGER events_project_run_state_after_insert
             AFTER INSERT ON events
             WHEN json_extract(NEW.value_json, '$.payload.type') = 'run_state_changed'
             BEGIN
                 UPDATE run_state_projection
                 SET state = json_extract(NEW.value_json, '$.payload.data.to'),
                     state_sequence = NEW.sequence
                 WHERE run_id = NEW.run_id
                   AND session_id = NEW.session_id
                   AND state = json_extract(NEW.value_json, '$.payload.data.from')
                   AND state_sequence < NEW.sequence
                   AND (
                       (
                           json_extract(NEW.value_json, '$.payload.data.from')
                               IN ('queued', 'waiting')
                           AND json_extract(NEW.value_json, '$.payload.data.to')
                               IN ('running', 'failed', 'cancelled')
                       ) OR (
                           json_extract(NEW.value_json, '$.payload.data.from') = 'running'
                           AND json_extract(NEW.value_json, '$.payload.data.to')
                               IN ('waiting', 'completed', 'failed', 'cancelled')
                       )
                   );
                 SELECT CASE WHEN changes() != 1
                     THEN RAISE(ABORT, 'invalid run state transition')
                 END;
             END",
        ),
        (
            "runs_reject_identity_update",
            "CREATE TRIGGER runs_reject_identity_update
             BEFORE UPDATE OF id, session_id ON runs BEGIN
                 SELECT RAISE(ABORT, 'run identity is immutable');
             END",
        ),
        (
            "runs_reject_delete",
            "CREATE TRIGGER runs_reject_delete
             BEFORE DELETE ON runs BEGIN
                 SELECT RAISE(ABORT, 'runs are immutable');
             END",
        ),
        (
            "runs_track_projection_health_after_insert",
            "CREATE TRIGGER runs_track_projection_health_after_insert
             AFTER INSERT ON runs BEGIN
                 UPDATE run_state_projection_health
                 SET materialized_runs = materialized_runs + 1 WHERE id = 1;
                 SELECT CASE WHEN changes() != 1
                     THEN RAISE(ABORT, 'run projection health row is missing')
                 END;
             END",
        ),
        (
            "run_state_projection_validate_before_insert",
            "CREATE TRIGGER run_state_projection_validate_before_insert
             BEFORE INSERT ON run_state_projection
             WHEN NOT EXISTS (
                 SELECT 1 FROM events
                 WHERE events.run_id = NEW.run_id
                   AND events.session_id = NEW.session_id
                   AND events.sequence = NEW.state_sequence
                   AND (
                       (
                           json_extract(events.value_json, '$.payload.type') = 'run_created'
                           AND NEW.state = 'queued'
                       ) OR (
                           json_extract(events.value_json, '$.payload.type') = 'run_state_changed'
                           AND json_extract(events.value_json, '$.payload.data.to') = NEW.state
                       )
                   )
             ) BEGIN
                 SELECT RAISE(ABORT, 'run projection has no authoritative event');
             END",
        ),
        (
            "run_state_projection_validate_before_update",
            "CREATE TRIGGER run_state_projection_validate_before_update
             BEFORE UPDATE ON run_state_projection
             WHEN NEW.run_id != OLD.run_id
               OR NEW.session_id != OLD.session_id
               OR NEW.state_sequence <= OLD.state_sequence
               OR NOT EXISTS (
                   SELECT 1 FROM events
                   WHERE events.run_id = NEW.run_id
                     AND events.session_id = NEW.session_id
                     AND events.sequence = NEW.state_sequence
                     AND json_extract(events.value_json, '$.payload.type') = 'run_state_changed'
                     AND json_extract(events.value_json, '$.payload.data.from') = OLD.state
                     AND json_extract(events.value_json, '$.payload.data.to') = NEW.state
               )
             BEGIN
                 SELECT RAISE(ABORT, 'run projection update is not authoritative');
             END",
        ),
        (
            "run_state_projection_reject_delete",
            "CREATE TRIGGER run_state_projection_reject_delete
             BEFORE DELETE ON run_state_projection BEGIN
                 SELECT RAISE(ABORT, 'run projections are immutable');
             END",
        ),
        (
            "run_state_projection_track_health_after_insert",
            "CREATE TRIGGER run_state_projection_track_health_after_insert
             AFTER INSERT ON run_state_projection BEGIN
                 UPDATE run_state_projection_health
                 SET projected_runs = projected_runs + 1 WHERE id = 1;
                 SELECT CASE WHEN changes() != 1
                     THEN RAISE(ABORT, 'run projection health row is missing')
                 END;
             END",
        ),
        (
            "events_project_identity_after_insert",
            "CREATE TRIGGER events_project_identity_after_insert
             AFTER INSERT ON events BEGIN
                 INSERT INTO event_identity_projection (event_id, session_id, sequence)
                 VALUES (NEW.id, NEW.session_id, NEW.sequence);
             END",
        ),
        (
            "event_identity_projection_reject_update",
            "CREATE TRIGGER event_identity_projection_reject_update
             BEFORE UPDATE ON event_identity_projection BEGIN
                 SELECT RAISE(ABORT, 'event identity projections are immutable');
             END",
        ),
        (
            "event_identity_projection_reject_delete",
            "CREATE TRIGGER event_identity_projection_reject_delete
             BEFORE DELETE ON event_identity_projection BEGIN
                 SELECT RAISE(ABORT, 'event identity projections are immutable');
             END",
        ),
    ];
    let expected = if has_event_identity_projection {
        &expected[..16]
    } else if has_run_state_projection {
        &expected[..13]
    } else if has_event_size_guard {
        &expected[..4]
    } else if has_insert_conflict_guard {
        &expected[..3]
    } else {
        &expected[..2]
    };
    for &(name, sql) in expected {
        if actual.get(name).map(|value| normalize_sql(value)) != Some(normalize_sql(sql)) {
            return Err(incompatible(
                version,
                format!("missing or altered append-only trigger {name}"),
            ));
        }
    }
    if actual.len() != expected.len() {
        return Err(incompatible(
            version,
            "unexpected triggers are attached to the event log",
        ));
    }
    Ok(())
}

fn validate_explicit_indexes(
    connection: &Connection,
    version: i64,
    expected: bool,
) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT name, tbl_name, sql FROM sqlite_schema
         WHERE type = 'index' AND sql IS NOT NULL ORDER BY name",
    )?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
            ))
        })?
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let canonical = expected.then(|| {
        BTreeMap::from([(
            "events_by_run_sequence".to_owned(),
            ("events".to_owned(), EVENT_RUN_SEQUENCE_INDEX_SQL.to_owned()),
        )])
    });
    let matches = match canonical {
        Some(canonical) => {
            actual.len() == canonical.len()
                && canonical.iter().all(|(name, (table, sql))| {
                    actual.get(name).is_some_and(|(actual_table, actual_sql)| {
                        actual_table == table && normalize_sql(actual_sql) == normalize_sql(sql)
                    })
                })
        }
        None => actual.is_empty(),
    };
    if !matches {
        return Err(incompatible(
            version,
            "explicit index set differs from the canonical schema",
        ));
    }
    Ok(())
}
