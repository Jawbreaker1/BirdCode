//! SQLite projection schema and integrity validation.

use super::{
    EVENT_IDENTITY_PROJECTION_SQL, RUN_STATE_PROJECTION_SQL, StoreError, ensure_columns,
    foreign_keys, has_foreign_key, incompatible, normalize_sql, table_exists, unique_indexes,
};
use rusqlite::Connection;

pub(super) fn validate_event_identity_projection(
    connection: &Connection,
    found: i64,
) -> Result<(), StoreError> {
    if !table_exists(connection, "event_identity_projection")? {
        return Err(incompatible(
            found,
            "event identity projection table is missing",
        ));
    }
    ensure_columns(
        connection,
        "event_identity_projection",
        &[
            ("event_id", "TEXT", true, 1),
            ("session_id", "TEXT", true, 0),
            ("sequence", "INTEGER", true, 0),
        ],
        found,
    )?;
    let definition = connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type = 'table' AND name = 'event_identity_projection'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    if normalize_sql(&definition) != normalize_sql(EVENT_IDENTITY_PROJECTION_SQL) {
        return Err(incompatible(
            found,
            "event identity projection table definition is altered",
        ));
    }
    let keys = foreign_keys(connection, "event_identity_projection")?;
    if !has_foreign_key(
        &keys,
        "events",
        &[("event_id", "id"), ("session_id", "session_id")],
    ) {
        return Err(incompatible(
            found,
            "event identity projection is missing its event foreign key",
        ));
    }
    let indexes = unique_indexes(connection, "event_identity_projection")?;
    for expected in [
        vec!["event_id", "session_id"],
        vec!["session_id", "sequence"],
    ] {
        if !indexes.iter().any(|actual| actual == &expected) {
            return Err(incompatible(
                found,
                "event identity projection is missing a canonical unique key",
            ));
        }
    }
    let mismatch = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM events
             LEFT JOIN event_identity_projection AS projection
               ON projection.event_id = events.id
              AND projection.session_id = events.session_id
              AND projection.sequence = events.sequence
             WHERE projection.event_id IS NULL
             UNION ALL
             SELECT 1 FROM event_identity_projection AS projection
             LEFT JOIN events
               ON events.id = projection.event_id
              AND events.session_id = projection.session_id
              AND events.sequence = projection.sequence
             WHERE events.id IS NULL
         )",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if mismatch {
        return Err(incompatible(
            found,
            "event identity projection does not exactly cover the event log",
        ));
    }
    Ok(())
}

pub(super) fn validate_run_state_projection(
    connection: &Connection,
    found: i64,
) -> Result<(), StoreError> {
    if !table_exists(connection, "run_state_projection")? {
        return Err(incompatible(found, "run state projection table is missing"));
    }
    ensure_columns(
        connection,
        "run_state_projection",
        &[
            ("run_id", "TEXT", true, 1),
            ("session_id", "TEXT", true, 0),
            ("state", "TEXT", true, 0),
            ("state_sequence", "INTEGER", true, 0),
        ],
        found,
    )?;
    let definition = connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type = 'table' AND name = 'run_state_projection'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    if normalize_sql(&definition) != normalize_sql(RUN_STATE_PROJECTION_SQL) {
        return Err(incompatible(
            found,
            "run state projection table definition is altered",
        ));
    }
    let keys = foreign_keys(connection, "run_state_projection")?;
    if !has_foreign_key(
        &keys,
        "runs",
        &[("run_id", "id"), ("session_id", "session_id")],
    ) {
        return Err(incompatible(
            found,
            "run state projection is missing its run foreign key",
        ));
    }
    validate_projection_health(connection, found)
}

fn validate_projection_health(connection: &Connection, found: i64) -> Result<(), StoreError> {
    if !table_exists(connection, "run_state_projection_health")? {
        return Err(incompatible(
            found,
            "run state projection health table is missing",
        ));
    }
    ensure_columns(
        connection,
        "run_state_projection_health",
        &[
            ("id", "INTEGER", true, 1),
            ("materialized_runs", "INTEGER", true, 0),
            ("projected_runs", "INTEGER", true, 0),
        ],
        found,
    )?;
    let definition = connection.query_row(
        "SELECT sql FROM sqlite_schema
         WHERE type = 'table' AND name = 'run_state_projection_health'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let expected = "CREATE TABLE run_state_projection_health (
        id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
        materialized_runs INTEGER NOT NULL CHECK(materialized_runs >= 0),
        projected_runs INTEGER NOT NULL CHECK(projected_runs >= 0)
    )";
    if normalize_sql(&definition) != normalize_sql(expected) {
        return Err(incompatible(
            found,
            "run state projection health table definition is altered",
        ));
    }
    let rows = {
        let mut statement = connection.prepare(
            "SELECT id, materialized_runs, projected_runs
             FROM run_state_projection_health",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if !matches!(rows.as_slice(), [(1, materialized, projected)] if materialized == projected) {
        return Err(incompatible(
            found,
            "run state projection does not cover exactly the materialized runs",
        ));
    }
    Ok(())
}
