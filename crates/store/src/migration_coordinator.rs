use super::legacy_migration::{begin_legacy_migration, resume_legacy_migration_batch};
use super::store_upgrade::{
    begin_store_upgrade, create_run_state_projection_objects, resume_store_upgrade_batch,
};
use super::{
    CHILD_RECONNAISSANCE_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION, CURRENT_TABLES_SQL, Connection,
    EVENT_IDENTITY_PROJECTION_SQL, EVENT_IDENTITY_PROJECTION_TRIGGERS_SQL,
    EVENT_INSERT_CONFLICT_GUARD_SQL, EVENT_RUN_SEQUENCE_INDEX_SQL, EVENT_SIZE_GUARD_SQL,
    EVENT_SIZE_SCHEMA_VERSION, HEALTH_CANARY_SCHEMA_VERSION, HEALTH_CANARY_SQL,
    IMMUTABLE_SCHEMA_VERSION, INDEXED_SCHEMA_VERSION, LEGACY_SCHEMA_VERSION,
    PATH_WIRE_SCHEMA_VERSION, Path, RUN_STATE_PROJECTION_SCHEMA_VERSION,
    RUN_STATE_PROJECTION_TRIGGERS_SQL, SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL,
    SEMANTIC_REVIEW_SCHEMA_VERSION, StoreError, Transaction, TransactionBehavior,
    expected_table_names, incompatible, known_tables, schema_version, table_columns, table_exists,
    validate_current_schema, validate_event_identity_projection, validate_health_canary,
    validate_run_state_projection, validate_schema,
};

#[allow(
    clippy::too_many_lines,
    reason = "the schema state machine keeps every atomic upgrade branch visible in one loop"
)]
pub(super) fn initialize_or_migrate_schema(
    connection: &mut Connection,
    artifact_root: &Path,
) -> Result<(), StoreError> {
    // Migrations use SQLite-backed staging and a committed progress cursor.
    // `Store` is not constructed until the marker is gone and the complete
    // target schema validates, so partially migrated state is never served.
    loop {
        if table_exists(connection, "store_migration_progress")? {
            resume_legacy_migration_batch(connection, artifact_root)?;
            std::thread::yield_now();
            continue;
        }
        if table_exists(connection, "store_upgrade_progress")? {
            resume_store_upgrade_batch(connection, artifact_root)?;
            std::thread::yield_now();
            continue;
        }

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Another opener may have created a durable migration marker while
        // this connection waited for the immediate transaction lock.
        if table_exists(&transaction, "store_migration_progress")?
            || table_exists(&transaction, "store_upgrade_progress")?
        {
            transaction.commit()?;
            continue;
        }
        let found = schema_version(&transaction)?;
        match found {
            CURRENT_SCHEMA_VERSION => {}
            CHILD_RECONNAISSANCE_SCHEMA_VERSION => {
                migrate_v9_schema_to_v10(&transaction)?;
                transaction.commit()?;
                continue;
            }
            SEMANTIC_REVIEW_SCHEMA_VERSION => {
                migrate_v8_schema_to_v9(&transaction)?;
                transaction.commit()?;
                continue;
            }
            RUN_STATE_PROJECTION_SCHEMA_VERSION => {
                begin_store_upgrade(&transaction, RUN_STATE_PROJECTION_SCHEMA_VERSION)?;
                transaction.commit()?;
                continue;
            }
            PATH_WIRE_SCHEMA_VERSION => {
                begin_store_upgrade(&transaction, PATH_WIRE_SCHEMA_VERSION)?;
                transaction.commit()?;
                continue;
            }
            HEALTH_CANARY_SCHEMA_VERSION => {
                begin_store_upgrade(&transaction, HEALTH_CANARY_SCHEMA_VERSION)?;
                transaction.commit()?;
                continue;
            }
            EVENT_SIZE_SCHEMA_VERSION => {
                migrate_v4_schema_to_v5(&transaction)?;
                transaction.commit()?;
                continue;
            }
            INDEXED_SCHEMA_VERSION => {
                migrate_v3_schema_to_v4(&transaction)?;
                transaction.commit()?;
                continue;
            }
            IMMUTABLE_SCHEMA_VERSION => {
                migrate_v2_schema_to_v3(&transaction)?;
                transaction.commit()?;
                continue;
            }
            LEGACY_SCHEMA_VERSION => {
                begin_legacy_migration(&transaction, found, false)?;
                transaction.commit()?;
                continue;
            }
            0 => {
                let existing = known_tables(&transaction)?;
                if existing.is_empty() {
                    transaction.execute_batch(CURRENT_TABLES_SQL)?;
                    transaction.execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)?;
                    transaction.execute_batch(EVENT_INSERT_CONFLICT_GUARD_SQL)?;
                    transaction.execute_batch(EVENT_RUN_SEQUENCE_INDEX_SQL)?;
                    transaction.execute_batch(EVENT_SIZE_GUARD_SQL)?;
                    transaction.execute_batch(HEALTH_CANARY_SQL)?;
                    create_run_state_projection_objects(&transaction)?;
                    transaction.execute_batch(RUN_STATE_PROJECTION_TRIGGERS_SQL)?;
                    transaction.execute_batch(EVENT_IDENTITY_PROJECTION_SQL)?;
                    transaction.execute_batch(EVENT_IDENTITY_PROJECTION_TRIGGERS_SQL)?;
                    transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
                } else if existing == expected_table_names() {
                    let has_causal_parent =
                        table_columns(&transaction, "events")?.contains_key("causal_parent");
                    begin_legacy_migration(&transaction, found, has_causal_parent)?;
                    transaction.commit()?;
                    continue;
                } else {
                    return Err(incompatible(
                        found,
                        format!("incomplete BirdCode table set: {existing:?}"),
                    ));
                }
            }
            _ => {
                return Err(incompatible(
                    found,
                    "only schema versions 1 through 9 can be migrated automatically",
                ));
            }
        }
        validate_current_schema(&transaction)?;
        transaction.commit()?;
        return Ok(());
    }
}

/// Schema v9 changes the closed durable event vocabulary but not the `SQLite`
/// object layout. A v8 database cannot legitimately contain v9 child events,
/// so validating the complete v8 shape before advancing `user_version` is a
/// sufficient, atomic migration.
fn migrate_v8_schema_to_v9(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_schema(transaction, SEMANTIC_REVIEW_SCHEMA_VERSION, true, true)?;
    validate_health_canary(transaction, SEMANTIC_REVIEW_SCHEMA_VERSION)?;
    validate_run_state_projection(transaction, SEMANTIC_REVIEW_SCHEMA_VERSION)?;
    transaction.pragma_update(None, "user_version", CHILD_RECONNAISSANCE_SCHEMA_VERSION)?;
    Ok(())
}

/// Schema v10 adds a durable event-identity projection used by caller-chosen
/// idempotency keys. Existing canonical envelopes are backfilled atomically;
/// the projection is then maintained and made immutable by triggers.
fn migrate_v9_schema_to_v10(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_schema(transaction, CHILD_RECONNAISSANCE_SCHEMA_VERSION, true, true)?;
    validate_health_canary(transaction, CHILD_RECONNAISSANCE_SCHEMA_VERSION)?;
    validate_run_state_projection(transaction, CHILD_RECONNAISSANCE_SCHEMA_VERSION)?;
    transaction.execute_batch(EVENT_IDENTITY_PROJECTION_SQL)?;
    transaction.execute(
        "INSERT INTO event_identity_projection (event_id, session_id, sequence)
         SELECT id, session_id, sequence FROM events ORDER BY session_id, sequence",
        [],
    )?;
    transaction.execute_batch(EVENT_IDENTITY_PROJECTION_TRIGGERS_SQL)?;
    transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    validate_event_identity_projection(transaction, CURRENT_SCHEMA_VERSION)?;
    Ok(())
}
fn migrate_v2_schema_to_v3(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_schema(transaction, IMMUTABLE_SCHEMA_VERSION, false, false)?;
    transaction.execute_batch(EVENT_INSERT_CONFLICT_GUARD_SQL)?;
    transaction.execute_batch(EVENT_RUN_SEQUENCE_INDEX_SQL)?;
    transaction.pragma_update(None, "user_version", INDEXED_SCHEMA_VERSION)?;
    Ok(())
}

fn migrate_v3_schema_to_v4(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_schema(transaction, INDEXED_SCHEMA_VERSION, true, false)?;
    // Existing rows are decoded through the durable, cursor-based v5/v6
    // replay before Store::open can return. Avoid an uncheckpointed O(N)
    // pre-scan here; the guard below protects every new row immediately.
    transaction.execute_batch(EVENT_SIZE_GUARD_SQL)?;
    transaction.pragma_update(None, "user_version", EVENT_SIZE_SCHEMA_VERSION)?;
    Ok(())
}

fn migrate_v4_schema_to_v5(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_schema(transaction, EVENT_SIZE_SCHEMA_VERSION, true, true)?;
    if table_exists(transaction, "runtime_health_canary")? {
        return Err(incompatible(
            EVENT_SIZE_SCHEMA_VERSION,
            "schema v4 unexpectedly contains runtime_health_canary",
        ));
    }
    transaction.execute_batch(HEALTH_CANARY_SQL)?;
    transaction.pragma_update(None, "user_version", HEALTH_CANARY_SCHEMA_VERSION)?;
    Ok(())
}
