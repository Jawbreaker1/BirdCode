//! Shared SQLite schema introspection for migrations and integrity validation.

use super::{StoreError, incompatible};
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn user_schema_object_names(
    connection: &Connection,
    object_type: &str,
) -> Result<BTreeSet<String>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = ?1 AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    statement
        .query_map([object_type], |row| row.get::<_, String>(0))?
        .collect::<Result<_, _>>()
        .map_err(StoreError::from)
}

pub(super) fn schema_version(connection: &Connection) -> Result<i64, StoreError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(StoreError::from)
}

pub(super) fn expected_table_names() -> BTreeSet<String> {
    ["events", "runs", "sessions"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub(super) fn table_exists(connection: &Connection, table: &str) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(StoreError::from)
}

pub(super) fn known_tables(connection: &Connection) -> Result<BTreeSet<String>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name IN ('sessions', 'runs', 'events')",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<_, _>>().map_err(StoreError::from)
}

pub(super) fn table_columns(
    connection: &Connection,
    table: &str,
) -> Result<BTreeMap<String, (String, bool, i64)>, StoreError> {
    let mut statement = connection
        .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1) ORDER BY cid")?;
    let rows = statement.query_map([table], |row| {
        Ok((
            row.get::<_, String>(0)?,
            (
                row.get::<_, String>(1)?.to_ascii_uppercase(),
                row.get::<_, bool>(2)?,
                row.get::<_, i64>(3)?,
            ),
        ))
    })?;
    rows.collect::<Result<_, _>>().map_err(StoreError::from)
}

pub(super) fn ensure_column_names(
    connection: &Connection,
    table: &str,
    expected: &[&str],
    version: i64,
) -> Result<(), StoreError> {
    let actual = table_columns(connection, table)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(incompatible(
            version,
            format!("unexpected columns in {table}: {actual:?}"),
        ))
    }
}

pub(super) fn ensure_columns(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str, bool, i64)],
    version: i64,
) -> Result<(), StoreError> {
    let actual = table_columns(connection, table)?;
    let expected = expected
        .iter()
        .map(|(name, kind, not_null, primary_key)| {
            (
                (*name).to_owned(),
                ((*kind).to_owned(), *not_null, *primary_key),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual == expected {
        Ok(())
    } else {
        Err(incompatible(
            version,
            format!("{table} does not match the canonical column definition"),
        ))
    }
}

pub(super) fn unique_indexes(
    connection: &Connection,
    table: &str,
) -> Result<Vec<Vec<String>>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT indexes.name, columns.seqno, columns.name
         FROM pragma_index_list(?1) AS indexes
         JOIN pragma_index_info(indexes.name) AS columns
         WHERE indexes.\"unique\" = 1
         ORDER BY indexes.name, columns.seqno",
    )?;
    let rows = statement.query_map([table], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(2)?))
    })?;
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for row in rows {
        let (name, column) = row?;
        grouped.entry(name).or_default().push(column);
    }
    Ok(grouped.into_values().collect())
}

pub(super) type ForeignKeys = BTreeMap<i64, (String, Vec<(String, String)>)>;

pub(super) fn foreign_keys(
    connection: &Connection,
    table: &str,
) -> Result<ForeignKeys, StoreError> {
    let mut statement = connection.prepare(
        "SELECT id, \"table\", \"from\", \"to\"
         FROM pragma_foreign_key_list(?1) ORDER BY id, seq",
    )?;
    let rows = statement.query_map([table], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut grouped = ForeignKeys::new();
    for row in rows {
        let (id, target, from, to) = row?;
        let entry = grouped.entry(id).or_insert_with(|| (target, Vec::new()));
        entry.1.push((from, to));
    }
    Ok(grouped)
}

pub(super) fn has_foreign_key(keys: &ForeignKeys, target: &str, columns: &[(&str, &str)]) -> bool {
    let expected = columns
        .iter()
        .map(|(from, to)| ((*from).to_owned(), (*to).to_owned()))
        .collect::<BTreeSet<_>>();
    keys.values().any(|(actual_target, actual_columns)| {
        actual_target == target
            && actual_columns.iter().cloned().collect::<BTreeSet<_>>() == expected
    })
}

pub(super) fn normalize_sql(sql: &str) -> String {
    sql.trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}
