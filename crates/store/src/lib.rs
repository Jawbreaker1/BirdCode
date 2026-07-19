//! Durable append-only storage for `BirdCode` sessions, runs, events, and artifacts.

use birdcode_protocol::{
    ActorId, ArtifactRef, EventEnvelope, EventId, EventPayload, InferenceAttemptId, InputItem,
    NewEvent, PlanProposalRejectionReason, Provenance, RetryDisposition, RootPlanningFailed,
    RootPlanningFailurePhase, RootPlanningFailureReason, Run, RunId, RunPurpose, RunState, Session,
    SessionId, Sha256Digest, WorkspacePath,
};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use thiserror::Error;

const HEX: &[u8; 16] = b"0123456789abcdef";
const LEGACY_SCHEMA_VERSION: i64 = 1;
const IMMUTABLE_SCHEMA_VERSION: i64 = 2;
const INDEXED_SCHEMA_VERSION: i64 = 3;
const EVENT_SIZE_SCHEMA_VERSION: i64 = 4;
const HEALTH_CANARY_SCHEMA_VERSION: i64 = 5;
const PATH_WIRE_SCHEMA_VERSION: i64 = 6;
const CURRENT_SCHEMA_VERSION: i64 = 7;

const CURRENT_TABLES_SQL: &str = "
    CREATE TABLE sessions (
        id TEXT PRIMARY KEY NOT NULL,
        value_json TEXT NOT NULL
    );
    CREATE TABLE runs (
        id TEXT PRIMARY KEY NOT NULL,
        session_id TEXT NOT NULL,
        value_json TEXT NOT NULL,
        UNIQUE(id, session_id),
        FOREIGN KEY(session_id) REFERENCES sessions(id)
    );
    CREATE TABLE events (
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
    );";

const SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL: &str = "
    CREATE TRIGGER events_are_immutable_on_update
    BEFORE UPDATE ON events BEGIN
        SELECT RAISE(ABORT, 'events are immutable');
    END;
    CREATE TRIGGER events_are_immutable_on_delete
    BEFORE DELETE ON events BEGIN
        SELECT RAISE(ABORT, 'events are immutable');
    END;";

const EVENT_INSERT_CONFLICT_GUARD_SQL: &str = "
    CREATE TRIGGER events_reject_conflicting_insert
    BEFORE INSERT ON events
    WHEN EXISTS (
        SELECT 1 FROM events
        WHERE id = NEW.id
           OR (session_id = NEW.session_id AND sequence = NEW.sequence)
    ) BEGIN
        SELECT RAISE(ABORT, 'events are append-only');
    END;";

const EVENT_RUN_SEQUENCE_INDEX_SQL: &str =
    "CREATE INDEX events_by_run_sequence ON events(run_id, sequence);";

const EVENT_SIZE_GUARD_SQL: &str = "
    CREATE TRIGGER events_reject_oversized_insert
    BEFORE INSERT ON events
    WHEN length(CAST(NEW.value_json AS BLOB)) > 262144 BEGIN
        SELECT RAISE(ABORT, 'event exceeds inline size limit');
    END;";

const HEALTH_CANARY_SQL: &str = "
    CREATE TABLE runtime_health_canary (
        id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
        generation INTEGER NOT NULL
    );
    INSERT INTO runtime_health_canary (id, generation) VALUES (1, 0);";

const RUN_STATE_PROJECTION_SQL: &str = "
    CREATE TABLE run_state_projection (
        run_id TEXT PRIMARY KEY NOT NULL,
        session_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK(
            state IN ('queued', 'running', 'waiting', 'completed', 'failed', 'cancelled')
        ),
        state_sequence INTEGER NOT NULL CHECK(state_sequence >= 1),
        UNIQUE(run_id, session_id),
        FOREIGN KEY(run_id, session_id) REFERENCES runs(id, session_id)
    );";

const RUN_STATE_PROJECTION_HEALTH_SQL: &str = "
    CREATE TABLE run_state_projection_health (
        id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
        materialized_runs INTEGER NOT NULL CHECK(materialized_runs >= 0),
        projected_runs INTEGER NOT NULL CHECK(projected_runs >= 0)
    );
    INSERT INTO run_state_projection_health (
        id, materialized_runs, projected_runs
    ) VALUES (1, 0, 0);";

const RUN_STATE_PROJECTION_INTEGRITY_TRIGGERS_SQL: &str = "
    CREATE TRIGGER runs_reject_identity_update
    BEFORE UPDATE OF id, session_id ON runs BEGIN
        SELECT RAISE(ABORT, 'run identity is immutable');
    END;
    CREATE TRIGGER runs_reject_delete
    BEFORE DELETE ON runs BEGIN
        SELECT RAISE(ABORT, 'runs are immutable');
    END;
    CREATE TRIGGER runs_track_projection_health_after_insert
    AFTER INSERT ON runs BEGIN
        UPDATE run_state_projection_health
        SET materialized_runs = materialized_runs + 1 WHERE id = 1;
        SELECT CASE WHEN changes() != 1
            THEN RAISE(ABORT, 'run projection health row is missing')
        END;
    END;
    CREATE TRIGGER run_state_projection_validate_before_insert
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
    END;
    CREATE TRIGGER run_state_projection_validate_before_update
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
    END;
    CREATE TRIGGER run_state_projection_reject_delete
    BEFORE DELETE ON run_state_projection BEGIN
        SELECT RAISE(ABORT, 'run projections are immutable');
    END;
    CREATE TRIGGER run_state_projection_track_health_after_insert
    AFTER INSERT ON run_state_projection BEGIN
        UPDATE run_state_projection_health
        SET projected_runs = projected_runs + 1 WHERE id = 1;
        SELECT CASE WHEN changes() != 1
            THEN RAISE(ABORT, 'run projection health row is missing')
        END;
    END;";

const RUN_STATE_PROJECTION_TRIGGERS_SQL: &str = "
    CREATE TRIGGER events_project_run_creation_after_insert
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
    END;
    CREATE TRIGGER events_project_run_state_after_insert
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
    END;";

const LEGACY_MIGRATION_CONTROL_SQL: &str = "
    CREATE TABLE store_migration_progress (
        id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
        source_version INTEGER NOT NULL,
        target_version INTEGER NOT NULL,
        has_causal_parent INTEGER NOT NULL CHECK(has_causal_parent IN (0, 1)),
        phase TEXT NOT NULL,
        cursor_rowid INTEGER NOT NULL,
        cursor_session_id TEXT,
        cursor_sequence INTEGER NOT NULL,
        processed_rows INTEGER NOT NULL
    );
    INSERT INTO store_migration_progress (
        id, source_version, target_version, has_causal_parent, phase, cursor_rowid,
        cursor_session_id, cursor_sequence, processed_rows
    ) VALUES (1, 1, 2, 0, 'copy_sessions', 0, NULL, 0, 0);
    CREATE TABLE migration_v1_events (
        source_rowid INTEGER PRIMARY KEY NOT NULL,
        id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        run_id TEXT,
        causal_parent TEXT,
        source_sequence INTEGER NOT NULL,
        value_json TEXT NOT NULL,
        UNIQUE(session_id, source_sequence)
    );
    CREATE TABLE migration_v1_session_inventory (
        session_id TEXT PRIMARY KEY NOT NULL,
        creation_count INTEGER NOT NULL DEFAULT 0,
        synthesized INTEGER NOT NULL DEFAULT 0 CHECK(synthesized IN (0, 1)),
        creation_seen INTEGER NOT NULL DEFAULT 0 CHECK(creation_seen IN (0, 1))
    );
    CREATE TABLE migration_v1_run_inventory (
        run_id TEXT PRIMARY KEY NOT NULL,
        session_id TEXT NOT NULL,
        state TEXT NOT NULL,
        state_sequence INTEGER NOT NULL DEFAULT 0,
        creation_count INTEGER NOT NULL DEFAULT 0,
        synthesized INTEGER NOT NULL DEFAULT 0 CHECK(synthesized IN (0, 1)),
        creation_seen INTEGER NOT NULL DEFAULT 0 CHECK(creation_seen IN (0, 1))
    );
    CREATE INDEX migration_v1_sessions_invalid_creation
        ON migration_v1_session_inventory(session_id)
        WHERE creation_count + synthesized != 1 OR creation_seen != 1;
    CREATE INDEX migration_v1_runs_invalid_creation
        ON migration_v1_run_inventory(run_id)
        WHERE creation_count + synthesized != 1 OR creation_seen != 1;
    CREATE INDEX migration_v1_sessions_without_creation
        ON migration_v1_session_inventory(session_id)
        WHERE creation_count = 0 AND synthesized = 0;
    CREATE INDEX migration_v1_runs_without_creation
        ON migration_v1_run_inventory(session_id, run_id)
        WHERE creation_count = 0 AND synthesized = 0;";

const STORE_UPGRADE_CONTROL_SQL: &str = "
    CREATE TABLE store_upgrade_progress (
        id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
        source_version INTEGER NOT NULL,
        phase TEXT NOT NULL,
        cursor_rowid INTEGER NOT NULL,
        cursor_session_id TEXT,
        cursor_sequence INTEGER NOT NULL,
        processed_rows INTEGER NOT NULL
    );
    CREATE TABLE store_upgrade_replay_sessions (
        id TEXT PRIMARY KEY NOT NULL,
        creation_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE store_upgrade_replay_runs (
        id TEXT PRIMARY KEY NOT NULL,
        session_id TEXT NOT NULL,
        state TEXT NOT NULL,
        state_sequence INTEGER NOT NULL DEFAULT 0,
        creation_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX store_upgrade_sessions_invalid_creation
        ON store_upgrade_replay_sessions(id) WHERE creation_count != 1;
    CREATE INDEX store_upgrade_runs_invalid_creation
        ON store_upgrade_replay_runs(id) WHERE creation_count != 1;
    CREATE INDEX store_upgrade_runs_without_state_sequence
        ON store_upgrade_replay_runs(id) WHERE state_sequence < 1;";

const DURABLE_HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(60);
const MIGRATION_ROW_BATCH_SIZE: u32 = 64;
const MIGRATION_EVENT_BATCH_SIZE: u32 = 1;
const MAX_MIGRATION_METADATA_BYTES: u64 = 1024 * 1024;
const ARTIFACT_HEALTH_CANARY_BYTES: &[u8] = b"birdcode-artifact-health-canary-v1";
const MAX_EVENT_ARTIFACT_REFS: u32 = 32;
const MAX_EVENT_REFERENCED_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

/// Schema version understood and emitted by this crate.
pub const SCHEMA_VERSION: i64 = CURRENT_SCHEMA_VERSION;

/// Maximum number of authoritative events returned by one sequential read.
/// Callers follow [`EventPage::has_more`] and continue from
/// [`EventPage::next_sequence`] to consume long sessions.
pub const EVENT_PAGE_SIZE: u32 = 512;

/// Maximum encoded event JSON retained in one sequential page.
pub const EVENT_PAGE_BYTES: usize = 1024 * 1024;

/// Maximum nonterminal runs returned in one deterministic recovery page.
pub const RUN_RECOVERY_PAGE_SIZE: u32 = 256;

/// Inline event payload ceiling. Larger backend data must be stored as a
/// content-addressed artifact and referenced from the event.
pub const MAX_INLINE_EVENT_BYTES: usize = 256 * 1024;
const MAX_INLINE_EVENT_BYTES_U64: u64 = 256 * 1024;

/// Maximum size of one content-addressed artifact accepted by this store.
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    pub events: Vec<EventEnvelope>,
    pub next_sequence: u64,
    pub has_more: bool,
    pub encoded_bytes: usize,
}

/// A bounded, deterministic page of materialized nonterminal runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRecoveryPage {
    pub runs: Vec<Run>,
    /// Exclusive run-id cursor for the next page.
    pub next_run_id: Option<RunId>,
    pub has_more: bool,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("stored JSON could not be encoded or decoded: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("artifact reference contains an invalid SHA-256 digest")]
    InvalidArtifactHash,
    #[error("artifact is too large to represent in the canonical protocol")]
    ArtifactTooLarge,
    #[error("event exceeds the aggregate artifact reference or byte budget")]
    ArtifactReferenceBudget,
    #[error("artifact content does not match its content-addressed reference")]
    ArtifactIntegrity,
    #[error("event sequence overflowed")]
    SequenceOverflow,
    #[error("inline event exceeds the durable event size limit; store large data as an artifact")]
    EventTooLarge,
    #[error("materialized state and authoritative event disagree")]
    InvalidStateEvent,
    #[error(
        "database schema version {found} is incompatible with supported version {supported}: {reason}"
    )]
    IncompatibleSchema {
        found: i64,
        supported: i64,
        reason: String,
    },
}

impl StoreError {
    /// Reports a transactional uniqueness or integrity conflict. Callers must
    /// re-read authoritative state before deciding whether an operation was
    /// an idempotent replay or a genuinely conflicting request.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::Database(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation
        )
    }

    /// Reports whether retrying the same operation can plausibly succeed
    /// without changing the database or input.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Database(rusqlite::Error::SqliteFailure(error, _)) => matches!(
                error.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ),
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            _ => false,
        }
    }
}

pub struct Store {
    connection: Connection,
    artifact_root: PathBuf,
    last_durable_health_probe: Cell<Option<Instant>>,
}

impl Store {
    /// Opens or creates the local database and artifact directory.
    ///
    /// # Errors
    ///
    /// Returns an error when directories cannot be created, `SQLite` cannot be
    /// opened, or the schema cannot be initialized.
    pub fn open(
        database: impl AsRef<Path>,
        artifact_root: impl Into<PathBuf>,
    ) -> Result<Self, StoreError> {
        let database = database.as_ref();
        if let Some(parent) = database.parent() {
            let parent_existed = parent.exists();
            fs::create_dir_all(parent)?;
            validate_real_directory(parent)?;
            if parent_existed {
                reject_shared_writable_directory(parent)?;
            } else {
                set_private_directory_permissions(parent)?;
            }
        }
        let artifact_root = artifact_root.into();
        prepare_private_directory(&artifact_root)?;

        if database.exists() {
            set_private_file_permissions(database)?;
        }
        let mut connection = Connection::open(database)?;
        set_private_file_permissions(database)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        initialize_or_migrate_schema(&mut connection, &artifact_root)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        secure_sqlite_family(database)?;

        Ok(Self {
            connection,
            artifact_root,
            last_durable_health_probe: Cell::new(None),
        })
    }

    /// Verifies that authoritative state is writable with a rolled-back
    /// canary. Periodically it also validates every schema object, commits a
    /// bounded non-authoritative database canary, and creates, fsyncs, reads,
    /// hashes, and removes a bounded artifact-root canary.
    ///
    /// # Errors
    ///
    /// Returns an error when the database is unavailable, read-only, busy, or
    /// no longer matches the initialized schema.
    pub fn health_probe(&self) -> Result<(), StoreError> {
        let schema_version = schema_version(&self.connection)?;
        if schema_version != CURRENT_SCHEMA_VERSION {
            return Err(incompatible(
                schema_version,
                "schema version changed after the store was opened",
            ));
        }
        let transaction = self.connection.unchecked_transaction()?;
        let canary = SessionId::new().to_string();
        transaction.execute(
            "INSERT INTO sessions (id, value_json) VALUES (?1, ?2)",
            params![canary, "{\"health_probe\":true}"],
        )?;
        transaction.rollback()?;

        let durable_probe_due = self
            .last_durable_health_probe
            .get()
            .is_none_or(|last| last.elapsed() >= DURABLE_HEALTH_PROBE_INTERVAL);
        if durable_probe_due {
            validate_current_schema(&self.connection)?;
            let transaction = self.connection.unchecked_transaction()?;
            let changed = transaction.execute(
                "UPDATE runtime_health_canary
                 SET generation = CASE
                     WHEN generation = 9223372036854775807 THEN 0
                     ELSE generation + 1
                 END
                 WHERE id = 1",
                [],
            )?;
            if changed != 1 {
                return Err(StoreError::InvalidStateEvent);
            }
            transaction.commit()?;
            probe_artifact_root(&self.artifact_root)?;
            self.last_durable_health_probe.set(Some(Instant::now()));
        }
        Ok(())
    }

    /// Atomically inserts session metadata and its authoritative creation event.
    ///
    /// # Errors
    ///
    /// Returns an error when the event does not describe the same session, or
    /// when serialization or the database transaction fails.
    pub fn create_session(
        &mut self,
        session: &Session,
        event: NewEvent,
    ) -> Result<EventEnvelope, StoreError> {
        if event.session_id != session.id
            || event.run_id.is_some()
            || !matches!(
                &event.payload,
                EventPayload::SessionCreated { session: value } if value == session
            )
        {
            return Err(StoreError::InvalidStateEvent);
        }
        validate_typed_artifact_refs(&self.artifact_root, &event.provenance, &event.payload)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO sessions (id, value_json) VALUES (?1, ?2)",
            params![session.id.to_string(), serde_json::to_string(session)?],
        )?;
        let envelope = append_event_in_transaction(&transaction, event)?;
        transaction.commit()?;
        Ok(envelope)
    }

    /// Loads a session by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the query or stored JSON decoding fails.
    pub fn get_session(&self, id: SessionId) -> Result<Option<Session>, StoreError> {
        read_json(
            &self.connection,
            "SELECT value_json FROM sessions WHERE id = ?1",
            id.to_string(),
        )
    }

    /// Atomically inserts run metadata and its authoritative creation event.
    ///
    /// # Errors
    ///
    /// Returns an error when the event does not describe the same run, or when
    /// serialization, referential integrity, or the transaction fails.
    pub fn create_run(&mut self, run: &Run, event: NewEvent) -> Result<EventEnvelope, StoreError> {
        if event.session_id != run.spec.session_id
            || event.run_id != Some(run.id)
            || run.state != RunState::Queued
            || !matches!(
                &event.payload,
                EventPayload::RunCreated { run: value } if value == run
            )
        {
            return Err(StoreError::InvalidStateEvent);
        }
        validate_typed_artifact_refs(&self.artifact_root, &event.provenance, &event.payload)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO runs (id, session_id, value_json) VALUES (?1, ?2, ?3)",
            params![
                run.id.to_string(),
                run.spec.session_id.to_string(),
                serde_json::to_string(run)?
            ],
        )?;
        let envelope = append_event_in_transaction(&transaction, event)?;
        transaction.commit()?;
        Ok(envelope)
    }

    /// Loads a run by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the query or stored JSON decoding fails.
    pub fn get_run(&self, id: RunId) -> Result<Option<Run>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT runs.value_json, run_state_projection.state
                 FROM runs
                 LEFT JOIN run_state_projection
                   ON run_state_projection.run_id = runs.id
                  AND run_state_projection.session_id = runs.session_id
                 WHERE runs.id = ?1",
                [id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        let Some((json, state)) = row else {
            return Ok(None);
        };
        let state = state.ok_or(StoreError::InvalidStateEvent)?;
        let mut run = decode_stored_run(&json)?;
        run.state = decode_run_state(&state)?;
        Ok(Some(run))
    }

    /// Appends one event and assigns its sequence transactionally.
    ///
    /// # Errors
    ///
    /// Returns an error when the session or run does not exist, serialization
    /// fails, the sequence overflows, or the transaction cannot commit.
    pub fn append_event(&mut self, event: NewEvent) -> Result<EventEnvelope, StoreError> {
        validate_typed_artifact_refs(&self.artifact_root, &event.provenance, &event.payload)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_generic_event(&transaction, &event)?;
        let envelope = append_event_in_transaction(&transaction, event)?;
        transaction.commit()?;
        Ok(envelope)
    }

    /// Loads one count- and byte-bounded page of a session's events after the
    /// supplied sequence in causal order. Continue from
    /// [`EventPage::next_sequence`] while [`EventPage::has_more`] is true.
    ///
    /// # Errors
    ///
    /// Returns an error when the query or stored JSON decoding fails.
    pub fn events_after(
        &self,
        session_id: SessionId,
        sequence: u64,
    ) -> Result<EventPage, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence,
                    length(CAST(value_json AS BLOB)),
                    CASE WHEN length(CAST(value_json AS BLOB)) <= ?4
                         THEN value_json END
             FROM events
             WHERE session_id = ?1 AND sequence > ?2
             ORDER BY sequence ASC
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                session_id.to_string(),
                sequence,
                u64::from(EVENT_PAGE_SIZE) + 1,
                MAX_INLINE_EVENT_BYTES_U64
            ],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        let mut events = Vec::with_capacity(EVENT_PAGE_SIZE as usize);
        let mut encoded_bytes = 0_usize;
        let mut has_more = false;
        for row in rows {
            let (stored_sequence, stored_bytes, json) = row?;
            if stored_bytes > MAX_INLINE_EVENT_BYTES_U64 {
                return Err(StoreError::EventTooLarge);
            }
            let json = json.ok_or(StoreError::InvalidStateEvent)?;
            if events.len() == EVENT_PAGE_SIZE as usize
                || encoded_bytes.saturating_add(json.len()) > EVENT_PAGE_BYTES
            {
                has_more = true;
                break;
            }
            let event = decode_canonical_event(&json)?;
            if event.sequence != stored_sequence {
                return Err(StoreError::InvalidStateEvent);
            }
            encoded_bytes += json.len();
            events.push(event);
        }
        let next_sequence = events.last().map_or(sequence, |event| event.sequence);
        Ok(EventPage {
            events,
            next_sequence,
            has_more,
            encoded_bytes,
        })
    }

    /// Loads a count- and byte-bounded page of events for exactly one run.
    /// Sequence cursors retain their session-global values, so causal and
    /// provenance ordering is identical to [`Self::events_after`] without a
    /// supervisor scanning unrelated runs in the same session.
    ///
    /// # Errors
    ///
    /// Returns an error when the run is unknown, a stored event is oversized,
    /// or canonical event decoding fails.
    pub fn events_for_run_after(
        &self,
        run_id: RunId,
        sequence: u64,
    ) -> Result<EventPage, StoreError> {
        let session_id = self
            .connection
            .query_row(
                "SELECT session_id FROM runs WHERE id = ?1",
                [run_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(StoreError::InvalidStateEvent)?;
        let mut statement = self.connection.prepare(
            "SELECT sequence,
                    length(CAST(value_json AS BLOB)),
                    CASE WHEN length(CAST(value_json AS BLOB)) <= ?5
                         THEN value_json END
             FROM events
             WHERE session_id = ?1 AND run_id = ?2 AND sequence > ?3
             ORDER BY sequence ASC
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                session_id,
                run_id.to_string(),
                sequence,
                u64::from(EVENT_PAGE_SIZE) + 1,
                MAX_INLINE_EVENT_BYTES_U64
            ],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        let mut events = Vec::with_capacity(EVENT_PAGE_SIZE as usize);
        let mut encoded_bytes = 0_usize;
        let mut has_more = false;
        for row in rows {
            let (stored_sequence, stored_bytes, json) = row?;
            if stored_bytes > MAX_INLINE_EVENT_BYTES_U64 {
                return Err(StoreError::EventTooLarge);
            }
            let json = json.ok_or(StoreError::InvalidStateEvent)?;
            if events.len() == EVENT_PAGE_SIZE as usize
                || encoded_bytes.saturating_add(json.len()) > EVENT_PAGE_BYTES
            {
                has_more = true;
                break;
            }
            let event = decode_canonical_event(&json)?;
            if event.sequence != stored_sequence
                || event.run_id != Some(run_id)
                || event.session_id.to_string() != session_id
            {
                return Err(StoreError::InvalidStateEvent);
            }
            encoded_bytes += json.len();
            events.push(event);
        }
        let next_sequence = events.last().map_or(sequence, |event| event.sequence);
        Ok(EventPage {
            events,
            next_sequence,
            has_more,
            encoded_bytes,
        })
    }

    /// Loads one deterministic recovery page of queued, running, or waiting
    /// runs. Continue with [`RunRecoveryPage::next_run_id`] while `has_more`.
    ///
    /// # Errors
    ///
    /// Returns an error when projection state or persisted run JSON is invalid.
    pub fn nonterminal_runs(
        &self,
        after_run_id: Option<RunId>,
    ) -> Result<RunRecoveryPage, StoreError> {
        let after = after_run_id.map(|id| id.to_string()).unwrap_or_default();
        let mut statement = self.connection.prepare(
            "SELECT runs.id, runs.value_json, run_state_projection.state
             FROM run_state_projection
             JOIN runs
               ON runs.id = run_state_projection.run_id
              AND runs.session_id = run_state_projection.session_id
             WHERE run_state_projection.state IN ('queued', 'running', 'waiting')
               AND runs.id > ?1
             ORDER BY runs.id ASC
             LIMIT ?2",
        )?;
        let rows = statement
            .query_map(
                params![after, u64::from(RUN_RECOVERY_PAGE_SIZE) + 1],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > RUN_RECOVERY_PAGE_SIZE as usize;
        let mut runs = Vec::with_capacity(rows.len().min(RUN_RECOVERY_PAGE_SIZE as usize));
        for (id, json, state) in rows.into_iter().take(RUN_RECOVERY_PAGE_SIZE as usize) {
            let mut run = decode_stored_run(&json)?;
            if run.id.to_string() != id {
                return Err(StoreError::InvalidStateEvent);
            }
            run.state = decode_run_state(&state)?;
            if !matches!(
                run.state,
                RunState::Queued | RunState::Running | RunState::Waiting
            ) {
                return Err(StoreError::InvalidStateEvent);
            }
            runs.push(run);
        }
        Ok(RunRecoveryPage {
            next_run_id: runs.last().map(|run| run.id),
            runs,
            has_more,
        })
    }

    /// Stores bytes by SHA-256 digest without overwriting an existing artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when directories or the durable artifact file cannot
    /// be created.
    pub fn put_artifact(
        &self,
        bytes: &[u8],
        media_type: impl Into<String>,
    ) -> Result<ArtifactRef, StoreError> {
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| StoreError::ArtifactTooLarge)?;
        if size_bytes > MAX_ARTIFACT_BYTES {
            return Err(StoreError::ArtifactTooLarge);
        }
        let hash = sha256_hex(bytes);
        let path = self.artifact_path(&hash)?;
        let parent = path.parent().ok_or(StoreError::InvalidArtifactHash)?;
        prepare_private_directory(parent)?;
        if !path.exists() {
            let mut temporary = NamedTempFile::new_in(parent)?;
            temporary.write_all(bytes)?;
            temporary.as_file_mut().sync_all()?;
            match temporary.persist_noclobber(&path) {
                Ok(_) => {
                    sync_directory(parent)?;
                    if parent != self.artifact_root {
                        sync_directory(&self.artifact_root)?;
                    }
                }
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(StoreError::Io(error.error)),
            }
        }
        set_private_file_permissions(&path)?;
        let artifact = ArtifactRef {
            sha256: hash,
            size_bytes,
            media_type: media_type.into(),
        };
        read_verified_artifact(&path, &artifact)?;
        Ok(artifact)
    }

    /// Loads bytes referenced by a validated artifact digest.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid digest or unreadable artifact file.
    pub fn get_artifact(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        let path = self.artifact_path(&artifact.sha256)?;
        read_verified_artifact(&path, artifact)
    }

    fn artifact_path(&self, hash: &str) -> Result<PathBuf, StoreError> {
        artifact_path_at(&self.artifact_root, hash)
    }
}

fn initialize_or_migrate_schema(
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
                    "only schema versions 1 through 6 can be migrated automatically",
                ));
            }
        }
        validate_current_schema(&transaction)?;
        transaction.commit()?;
        return Ok(());
    }
}

#[derive(Debug)]
struct LegacyMigrationProgress {
    source_version: i64,
    has_causal_parent: bool,
    phase: String,
    cursor_rowid: i64,
    cursor_session_id: Option<String>,
    cursor_sequence: u64,
}

fn begin_legacy_migration(
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

fn resume_legacy_migration_batch(
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

fn read_legacy_migration_progress(
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

fn bounded_legacy_metadata_rows(
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
        let run = decode_stored_run(json).map_err(|error| {
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
    let run = decode_stored_run(&json)?;
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

#[derive(Debug)]
struct StoreUpgradeProgress {
    source_version: i64,
    phase: String,
    cursor_rowid: i64,
    cursor_session_id: Option<String>,
    cursor_sequence: u64,
}

fn create_run_state_projection_objects(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(RUN_STATE_PROJECTION_SQL)?;
    connection.execute_batch(RUN_STATE_PROJECTION_HEALTH_SQL)?;
    connection.execute_batch(RUN_STATE_PROJECTION_INTEGRITY_TRIGGERS_SQL)?;
    Ok(())
}

fn begin_store_upgrade(
    transaction: &Transaction<'_>,
    source_version: i64,
) -> Result<(), StoreError> {
    validate_schema(transaction, source_version, true, true)?;
    validate_health_canary(transaction, source_version)?;
    if table_exists(transaction, "run_state_projection")? {
        return Err(incompatible(
            source_version,
            format!("schema v{source_version} unexpectedly contains run_state_projection"),
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
    } else {
        return Err(incompatible(
            source_version,
            "durable upgrade can only start from schema v5 or v6",
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

fn resume_store_upgrade_batch(
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

fn read_store_upgrade_progress(
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
        let event = decode_stored_event_value(value).map_err(|error| {
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
        let run = decode_stored_run(json).map_err(|error| {
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
        let event = decode_canonical_event(json.as_deref().ok_or_else(|| {
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
                let materialized = materialized.as_deref().map(decode_stored_run).transpose()?;
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

fn finalize_store_upgrade(
    transaction: &Transaction<'_>,
    source_version: i64,
) -> Result<(), StoreError> {
    // Replay validates every source relationship with indexed point lookups;
    // projection rows are then inserted with foreign_keys enabled. Avoid a
    // second unbounded foreign_key_check while the final write lock is held.
    if source_version == HEALTH_CANARY_SCHEMA_VERSION {
        transaction.execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)?;
    }
    transaction.execute_batch(RUN_STATE_PROJECTION_TRIGGERS_SQL)?;
    transaction.execute_batch(
        "DROP TABLE store_upgrade_replay_runs;
         DROP TABLE store_upgrade_replay_sessions;
         DROP TABLE store_upgrade_progress;",
    )?;
    transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    validate_current_schema(transaction)?;
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

fn canonicalize_workspace_root(
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
    let run = decode_stored_run(&run_json).map_err(|error| {
        incompatible(
            found,
            format!("materialized run {run_id} is invalid: {error}"),
        )
    })?;
    if legacy_spec != &serde_json::to_value(run.spec)? {
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

fn validate_current_schema(connection: &Connection) -> Result<(), StoreError> {
    validate_schema(connection, CURRENT_SCHEMA_VERSION, true, true)?;
    validate_health_canary(connection, CURRENT_SCHEMA_VERSION)?;
    validate_run_state_projection(connection, CURRENT_SCHEMA_VERSION)
}

fn validate_run_state_projection(connection: &Connection, found: i64) -> Result<(), StoreError> {
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

fn validate_schema(
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
        expected_version == CURRENT_SCHEMA_VERSION,
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
    if expected_version == CURRENT_SCHEMA_VERSION {
        expected_tables.insert("run_state_projection".to_owned());
        expected_tables.insert("run_state_projection_health".to_owned());
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

fn user_schema_object_names(
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

fn schema_version(connection: &Connection) -> Result<i64, StoreError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(StoreError::from)
}

fn expected_table_names() -> BTreeSet<String> {
    ["events", "runs", "sessions"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, StoreError> {
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

fn validate_health_canary(connection: &Connection, found: i64) -> Result<(), StoreError> {
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

fn known_tables(connection: &Connection) -> Result<BTreeSet<String>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name IN ('sessions', 'runs', 'events')",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<_, _>>().map_err(StoreError::from)
}

fn table_columns(
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

fn ensure_column_names(
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

fn ensure_columns(
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

fn unique_indexes(connection: &Connection, table: &str) -> Result<Vec<Vec<String>>, StoreError> {
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

type ForeignKeys = BTreeMap<i64, (String, Vec<(String, String)>)>;

fn foreign_keys(connection: &Connection, table: &str) -> Result<ForeignKeys, StoreError> {
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

fn has_foreign_key(keys: &ForeignKeys, target: &str, columns: &[(&str, &str)]) -> bool {
    let expected = columns
        .iter()
        .map(|(from, to)| ((*from).to_owned(), (*to).to_owned()))
        .collect::<BTreeSet<_>>();
    keys.values().any(|(actual_target, actual_columns)| {
        actual_target == target
            && actual_columns.iter().cloned().collect::<BTreeSet<_>>() == expected
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "exact trigger SQL validation is intentionally colocated and auditable"
)]
fn validate_immutability_triggers(
    connection: &Connection,
    version: i64,
    has_insert_conflict_guard: bool,
    has_event_size_guard: bool,
    has_run_state_projection: bool,
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
    ];
    let expected = if has_run_state_projection {
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

fn normalize_sql(sql: &str) -> String {
    sql.trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

fn incompatible(found: i64, reason: impl Into<String>) -> StoreError {
    StoreError::IncompatibleSchema {
        found,
        supported: CURRENT_SCHEMA_VERSION,
        reason: reason.into(),
    }
}

fn validate_generic_event(
    transaction: &Transaction<'_>,
    event: &NewEvent,
) -> Result<(), StoreError> {
    validate_root_planning_failure_fence(transaction, event)?;
    match &event.payload {
        EventPayload::SessionCreated { .. } | EventPayload::RunCreated { .. } => {
            Err(StoreError::InvalidStateEvent)
        }
        EventPayload::RunStateChanged { from, to } => {
            validate_run_state_change(transaction, event, *from, *to)
        }
        EventPayload::RunClaimed(claim) => validate_run_claim(transaction, event, claim),
        EventPayload::CancellationRequested(cancellation) => {
            validate_cancellation(transaction, event, cancellation)
        }
        EventPayload::RootPlanningFailed(failure) => {
            validate_root_planning_failed(transaction, event, failure)
        }
        EventPayload::PlannerInferencePrepared(prepared) => {
            validate_planner_inference_prepared(transaction, event, prepared)
        }
        EventPayload::PlannerInferenceObserved(observed) => {
            validate_planner_inference_observed(transaction, event, observed)
        }
        EventPayload::PlannerInferenceOutcomeUnknown(unknown) => {
            validate_planner_inference_unknown(transaction, event, unknown)
        }
        EventPayload::ReadOperationPrepared(prepared) => {
            validate_read_operation_prepared(transaction, event, prepared)
        }
        EventPayload::ReadOperationObserved(observed) => {
            validate_read_operation_observed(transaction, event, observed)
        }
        EventPayload::PlanProposalRejected(rejected) => {
            validate_plan_proposal_rejected(transaction, event, rejected)
        }
        EventPayload::PlanProposalAccepted(accepted) => {
            validate_plan_proposal_accepted(transaction, event, accepted)
        }
        EventPayload::BackendEvent { .. } if event.run_id.is_none() => {
            Err(StoreError::InvalidStateEvent)
        }
        _ => Ok(()),
    }
}

fn validate_root_planning_failure_fence(
    transaction: &Transaction<'_>,
    event: &NewEvent,
) -> Result<(), StoreError> {
    let Some(run_id) = event.run_id else {
        return Ok(());
    };
    if root_planning_failure_count(transaction, event.session_id, run_id)? == 0 {
        return Ok(());
    }
    if matches!(
        event.payload,
        EventPayload::RunClaimed(_)
            | EventPayload::CancellationRequested(_)
            | EventPayload::RunStateChanged { .. }
    ) {
        Ok(())
    } else {
        Err(StoreError::InvalidStateEvent)
    }
}

fn planner_run_id(event: &NewEvent) -> Result<RunId, StoreError> {
    event.run_id.ok_or(StoreError::InvalidStateEvent)
}

fn current_run_state(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<RunState, StoreError> {
    let state = transaction
        .query_row(
            "SELECT state FROM run_state_projection
             WHERE run_id = ?1 AND session_id = ?2",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    decode_run_state(&state)
}

fn require_nonterminal_run(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    run_id: RunId,
) -> Result<RunState, StoreError> {
    let state = current_run_state(transaction, event.session_id, run_id)?;
    if is_terminal_run_state(state) {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(state)
}

fn require_running_run(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    run_id: RunId,
) -> Result<(), StoreError> {
    if current_run_state(transaction, event.session_id, run_id)? != RunState::Running {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn latest_run_event(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<EventEnvelope, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
             ORDER BY sequence DESC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    decode_canonical_event(&json)
}

fn require_latest_run_parent(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    run_id: RunId,
) -> Result<(), StoreError> {
    let latest = latest_run_event(transaction, event.session_id, run_id)?;
    if event.causal_parent != Some(latest.id) {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn event_by_id_for_run(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    event_id: EventId,
) -> Result<EventEnvelope, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE id = ?1 AND run_id = ?2 AND session_id = ?3",
            params![
                event_id.to_string(),
                run_id.to_string(),
                session_id.to_string()
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    decode_canonical_event(&json)
}

fn event_count_by_json_identity(
    transaction: &Transaction<'_>,
    event_type: &str,
    json_path: &str,
    identity: &str,
) -> Result<u64, StoreError> {
    let query = format!(
        "SELECT COUNT(*) FROM events
         WHERE json_extract(value_json, '$.payload.type') = ?1
           AND json_extract(value_json, '{json_path}') = ?2"
    );
    transaction
        .query_row(&query, params![event_type, identity], |row| row.get(0))
        .map_err(StoreError::from)
}

fn latest_claim_for_run(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<EventEnvelope>, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'run_claimed'
             ORDER BY sequence DESC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    json.as_deref().map(decode_canonical_event).transpose()
}

fn latest_cancellation_generation(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COALESCE(MAX(CAST(
                 json_extract(value_json, '$.payload.data.cancellation_generation') AS INTEGER
             )), 0)
             FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'cancellation_requested'",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn require_active_claim_owner(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    run_id: RunId,
) -> Result<EventEnvelope, StoreError> {
    let claim_event = latest_claim_for_run(transaction, event.session_id, run_id)?
        .ok_or(StoreError::InvalidStateEvent)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if claim_event.actor_id != event.actor_id || claim.lease_expires_at <= Utc::now() {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(claim_event)
}

fn require_current_claim_owner(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    run_id: RunId,
    cancellation_generation: u64,
) -> Result<EventEnvelope, StoreError> {
    let claim_event = require_active_claim_owner(transaction, event, run_id)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let latest_cancellation =
        latest_cancellation_generation(transaction, event.session_id, run_id)?;
    if claim.cancellation_generation != cancellation_generation
        || latest_cancellation != cancellation_generation
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(claim_event)
}

fn require_latest_claim_owner(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    run_id: RunId,
) -> Result<EventEnvelope, StoreError> {
    let claim_event = require_active_claim_owner(transaction, event, run_id)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let cancellation_generation =
        latest_cancellation_generation(transaction, event.session_id, run_id)?;
    if claim.cancellation_generation != cancellation_generation {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(claim_event)
}

fn validate_run_state_change(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    from: RunState,
    to: RunState,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    if current_run_state(transaction, event.session_id, run_id)? != from
        || !valid_run_transition(from, to)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_latest_run_parent(transaction, event, run_id)?;
    let latest = latest_run_event(transaction, event.session_id, run_id)?;
    let cancellation_generation =
        latest_cancellation_generation(transaction, event.session_id, run_id)?;
    if cancellation_generation > 0 && to != RunState::Cancelled {
        return Err(StoreError::InvalidStateEvent);
    }

    if root_planning_failure_count(transaction, event.session_id, run_id)? != 0 {
        let latest_non_claim = latest_non_claim_event(transaction, event.session_id, run_id)?;
        match latest_non_claim.payload {
            EventPayload::RootPlanningFailed(_) if to != RunState::Failed => {
                return Err(StoreError::InvalidStateEvent);
            }
            EventPayload::CancellationRequested(_) if to != RunState::Cancelled => {
                return Err(StoreError::InvalidStateEvent);
            }
            EventPayload::RootPlanningFailed(_) | EventPayload::CancellationRequested(_) => {}
            _ => return Err(StoreError::InvalidStateEvent),
        }
    }

    match (from, to) {
        (RunState::Queued | RunState::Waiting, RunState::Cancelled) => {
            if !matches!(latest.payload, EventPayload::CancellationRequested(_)) {
                return Err(StoreError::InvalidStateEvent);
            }
            // The durable request, rather than an ephemeral runtime actor,
            // authorizes terminalization. This lets a replacement runtime
            // finish a cancellation after a crash while the latest-parent
            // and current-state checks above still close stale histories.
        }
        (RunState::Queued | RunState::Waiting, RunState::Running) => {
            if !matches!(latest.payload, EventPayload::RunClaimed(_)) {
                return Err(StoreError::InvalidStateEvent);
            }
            require_latest_claim_owner(transaction, event, run_id)?;
        }
        (RunState::Running, RunState::Cancelled) => {
            if cancellation_generation == 0 {
                return Err(StoreError::InvalidStateEvent);
            }
            // An already-running provider call may observe cancellation after
            // its claim was issued. The still-live owner may terminate it
            // without first manufacturing a renewal solely to copy the new
            // cancellation generation into the claim.
            require_active_claim_owner(transaction, event, run_id)?;
        }
        _ => {
            require_latest_claim_owner(transaction, event, run_id)?;
        }
    }
    Ok(())
}

fn validate_run_claim(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    claim: &birdcode_protocol::RunClaimed,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    let run_state = require_nonterminal_run(transaction, event, run_id)?;
    require_latest_run_parent(transaction, event, run_id)?;
    if claim.claim_generation == 0
        || claim.lease_expires_at <= Utc::now()
        || event_count_by_json_identity(
            transaction,
            "run_claimed",
            "$.payload.data.claim_id",
            &claim.claim_id.to_string(),
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let expected_cancellation =
        latest_cancellation_generation(transaction, event.session_id, run_id)?;
    if claim.cancellation_generation != expected_cancellation {
        return Err(StoreError::InvalidStateEvent);
    }
    if expected_cancellation > 0 && matches!(run_state, RunState::Queued | RunState::Waiting) {
        // Inactive runs are cancelled directly by the runtime. Refusing a new
        // claim after the durable request prevents a claim/terminal-state race.
        return Err(StoreError::InvalidStateEvent);
    }
    let previous = latest_claim_for_run(transaction, event.session_id, run_id)?;
    let expected_generation = previous
        .as_ref()
        .and_then(|envelope| match &envelope.payload {
            EventPayload::RunClaimed(previous) => previous.claim_generation.checked_add(1),
            _ => None,
        })
        .unwrap_or(1);
    if claim.claim_generation != expected_generation {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(previous_event) = previous {
        let EventPayload::RunClaimed(previous_claim) = previous_event.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        if previous_claim.lease_expires_at > Utc::now()
            && (previous_claim.runtime_instance_id != claim.runtime_instance_id
                || previous_event.actor_id != event.actor_id)
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    let conflicting_runtime_owner = transaction.query_row(
        "SELECT COUNT(*) FROM events
         WHERE json_extract(value_json, '$.payload.type') = 'run_claimed'
           AND json_extract(value_json, '$.payload.data.runtime_instance_id') = ?1
           AND json_extract(value_json, '$.actor_id') != ?2",
        params![
            claim.runtime_instance_id.to_string(),
            event.actor_id.to_string()
        ],
        |row| row.get::<_, u64>(0),
    )?;
    if conflicting_runtime_owner != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn validate_cancellation(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    cancellation: &birdcode_protocol::CancellationRequested,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_nonterminal_run(transaction, event, run_id)?;
    require_latest_run_parent(transaction, event, run_id)?;
    if cancellation.cancellation_generation != 1
        || latest_cancellation_generation(transaction, event.session_id, run_id)? != 0
        || event_count_by_json_identity(
            transaction,
            "cancellation_requested",
            "$.payload.data.cancellation_request_id",
            &cancellation.cancellation_request_id.to_string(),
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn root_planning_failure_count(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'root_planning_failed'",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn latest_non_claim_event(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<EventEnvelope, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') != 'run_claimed'
             ORDER BY sequence DESC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    decode_canonical_event(&json)
}

fn validate_root_planning_failed(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    failure: &RootPlanningFailed,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    require_latest_run_parent(transaction, event, run_id)?;
    if failure.cancellation_generation != 0
        || root_planning_failure_count(transaction, event.session_id, run_id)? != 0
        || !valid_root_planning_failure_classification(failure.phase, failure.reason)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let inference_count = transaction.query_row(
        "SELECT COUNT(*) FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, u64>(0),
    )?;
    if inference_count != 0 {
        return Err(StoreError::InvalidStateEvent);
    }

    let claim_event =
        require_current_claim_owner(transaction, event, run_id, failure.cancellation_generation)?;
    let EventPayload::RunClaimed(claim) = &claim_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if failure.claim_event_id != claim_event.id
        || failure.claim_id != claim.claim_id
        || event.provenance.raw_artifact.as_ref() != Some(&failure.evidence_artifact)
    {
        return Err(StoreError::InvalidStateEvent);
    }

    let run_json = transaction.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?;
    let run = decode_stored_run(&run_json)?;
    if run.spec.purpose != RunPurpose::PlanOnly
        || event.provenance.backend.as_ref() != Some(&run.spec.backend)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

const fn valid_root_planning_failure_classification(
    phase: RootPlanningFailurePhase,
    reason: RootPlanningFailureReason,
) -> bool {
    matches!(
        (phase, reason),
        (
            RootPlanningFailurePhase::Preflight,
            RootPlanningFailureReason::InvalidWallDeadline
                | RootPlanningFailureReason::InvalidRunConfiguration
                | RootPlanningFailureReason::WallDeadlineExceeded
        ) | (
            RootPlanningFailurePhase::ModelDiscovery,
            RootPlanningFailureReason::InvalidRunConfiguration
                | RootPlanningFailureReason::BackendDiscoveryFailed
                | RootPlanningFailureReason::DiscoveryTimedOut
                | RootPlanningFailureReason::InvalidDiscoveryCatalog
                | RootPlanningFailureReason::SelectedModelUnavailable
                | RootPlanningFailureReason::WallDeadlineExceeded
        ) | (
            RootPlanningFailurePhase::PromptPreparation,
            RootPlanningFailureReason::InvalidRunConfiguration
                | RootPlanningFailureReason::WallDeadlineExceeded
                | RootPlanningFailureReason::PromptCompilationFailed
                | RootPlanningFailureReason::DurableStateConflict
        )
    )
}

fn prepared_inference_for_attempt(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    attempt_id: InferenceAttemptId,
) -> Result<EventEnvelope, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
               AND json_extract(value_json, '$.payload.data.attempt_id') = ?3
             ORDER BY sequence ASC LIMIT 1",
            params![
                run_id.to_string(),
                session_id.to_string(),
                attempt_id.to_string()
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    decode_canonical_event(&json)
}

fn current_plan_base(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<(u64, Sha256Digest)>, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'plan_proposal_accepted'
             ORDER BY sequence DESC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let event = decode_canonical_event(&json)?;
    let EventPayload::PlanProposalAccepted(accepted) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(Some((
        accepted.accepted_plan_revision,
        accepted.accepted_plan_digest,
    )))
}

fn genesis_plan_digest(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<Sha256Digest>, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
             ORDER BY sequence ASC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let event = decode_canonical_event(&json)?;
    let EventPayload::PlannerInferencePrepared(prepared) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if prepared.plan_revision != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(Some(prepared.plan_digest))
}

fn first_prepared_inference(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<birdcode_protocol::PlannerInferencePrepared>, StoreError> {
    let json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
             ORDER BY sequence ASC LIMIT 1",
            params![run_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let event = decode_canonical_event(&json)?;
    let EventPayload::PlannerInferencePrepared(prepared) = event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    Ok(Some(prepared))
}

fn require_current_plan_base(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    revision: u64,
    digest: &Sha256Digest,
    allow_first_genesis: bool,
) -> Result<(), StoreError> {
    if let Some((current_revision, current_digest)) =
        current_plan_base(transaction, session_id, run_id)?
    {
        if current_revision != revision || &current_digest != digest {
            return Err(StoreError::InvalidStateEvent);
        }
        return Ok(());
    }
    if revision != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    match genesis_plan_digest(transaction, session_id, run_id)? {
        Some(genesis) if &genesis == digest => Ok(()),
        None if allow_first_genesis => Ok(()),
        _ => Err(StoreError::InvalidStateEvent),
    }
}

fn parent_attempt_is_terminal(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    parent_attempt_id: InferenceAttemptId,
) -> Result<bool, StoreError> {
    let parent =
        prepared_inference_for_attempt(transaction, session_id, run_id, parent_attempt_id)?;
    let terminal_json = transaction
        .query_row(
            "SELECT value_json FROM events
             WHERE run_id = ?1 AND session_id = ?2 AND sequence > ?3
               AND (
                    (json_extract(value_json, '$.payload.type') = 'planner_inference_outcome_unknown'
                     AND json_extract(value_json, '$.payload.data.attempt_id') = ?4)
                 OR (json_extract(value_json, '$.payload.type') IN
                        ('plan_proposal_accepted', 'plan_proposal_rejected')
                     AND json_extract(value_json, '$.payload.data.inference_attempt_id') = ?4)
                 OR (json_extract(value_json, '$.payload.type') = 'planner_inference_observed'
                     AND json_extract(value_json, '$.payload.data.attempt_id') = ?4)
               )
             ORDER BY sequence DESC LIMIT 1",
            params![
                run_id.to_string(),
                session_id.to_string(),
                parent.sequence,
                parent_attempt_id.to_string()
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(json) = terminal_json else {
        return Ok(false);
    };
    let terminal = decode_canonical_event(&json)?;
    match terminal.payload {
        EventPayload::PlannerInferenceOutcomeUnknown(_)
        | EventPayload::PlanProposalAccepted(_)
        | EventPayload::PlanProposalRejected(_) => Ok(true),
        EventPayload::PlannerInferenceObserved(observed) => Ok(matches!(
            observed.outcome,
            birdcode_protocol::PlannerInferenceObservation::Failed {
                error: birdcode_protocol::PlannerInferenceError {
                    retry: RetryDisposition::RequiresNewAttempt,
                    ..
                }
            }
        )),
        _ => Err(StoreError::InvalidStateEvent),
    }
}

fn validate_planner_inference_prepared(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    prepared: &birdcode_protocol::PlannerInferencePrepared,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    if latest_cancellation_generation(transaction, event.session_id, run_id)? != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    require_latest_run_parent(transaction, event, run_id)?;
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    if prepared.token_reservation.reserved_tokens == 0
        || prepared.token_reservation.max_output_tokens == 0
        || prepared.token_reservation.reserved_tokens < prepared.token_reservation.max_output_tokens
        || event_count_by_json_identity(
            transaction,
            "planner_inference_prepared",
            "$.payload.data.attempt_id",
            &prepared.attempt_id.to_string(),
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "planner_inference_prepared",
            "$.payload.data.token_reservation.id",
            &prepared.token_reservation.id.to_string(),
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if prepared.parent_attempt_id.is_none()
        && prepared_attempts_for_plan(
            transaction,
            event.session_id,
            run_id,
            prepared.plan_revision,
            &prepared.plan_digest,
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(parent_attempt_id) = prepared.parent_attempt_id
        && (parent_attempt_id == prepared.attempt_id
            || !parent_attempt_is_terminal(
                transaction,
                event.session_id,
                run_id,
                parent_attempt_id,
            )?)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(first) = first_prepared_inference(transaction, event.session_id, run_id)?
        && (first.obligation_snapshot_digest != prepared.obligation_snapshot_digest
            || first.acceptance_policy_digest != prepared.acceptance_policy_digest
            || first.planner_policy_digest != prepared.planner_policy_digest)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_current_plan_base(
        transaction,
        event.session_id,
        run_id,
        prepared.plan_revision,
        &prepared.plan_digest,
        true,
    )?;
    let run_json = transaction.query_row(
        "SELECT value_json FROM runs WHERE id = ?1 AND session_id = ?2",
        params![run_id.to_string(), event.session_id.to_string()],
        |row| row.get::<_, String>(0),
    )?;
    let run = decode_stored_run(&run_json)?;
    if run.spec.purpose != RunPurpose::PlanOnly
        || run.spec.backend.backend_id != prepared.backend_model.backend_id
        || run.spec.backend.kind != prepared.backend_model.kind
        || run
            .spec
            .backend
            .model
            .as_ref()
            .is_some_and(|model| model != &prepared.backend_model.model_id)
        || run
            .spec
            .limits
            .max_output_tokens
            .is_some_and(|limit| prepared.token_reservation.max_output_tokens > limit)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some(limit) = run.spec.limits.max_output_tokens {
        let already_reserved =
            reserved_output_tokens_for_run(transaction, event.session_id, run_id)?;
        if already_reserved
            .checked_add(prepared.token_reservation.max_output_tokens)
            .ok_or(StoreError::InvalidStateEvent)?
            > limit
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    Ok(())
}

fn prepared_attempts_for_plan(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    plan_revision: u64,
    plan_digest: &Sha256Digest,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
               AND json_extract(value_json, '$.payload.data.plan_revision') = ?3
               AND json_extract(value_json, '$.payload.data.plan_digest') = ?4",
            params![
                run_id.to_string(),
                session_id.to_string(),
                plan_revision,
                plan_digest.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn reserved_output_tokens_for_run(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
) -> Result<u64, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'planner_inference_prepared'
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(params![run_id.to_string(), session_id.to_string()], |row| {
        row.get::<_, String>(0)
    })?;
    let mut reserved = 0_u64;
    for row in rows {
        let envelope = decode_canonical_event(&row?)?;
        let EventPayload::PlannerInferencePrepared(prepared) = envelope.payload else {
            return Err(StoreError::InvalidStateEvent);
        };
        reserved = reserved
            .checked_add(prepared.token_reservation.max_output_tokens)
            .ok_or(StoreError::InvalidStateEvent)?;
    }
    Ok(reserved)
}

fn inference_terminal_count(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    attempt_id: InferenceAttemptId,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') IN
                   ('planner_inference_observed', 'planner_inference_outcome_unknown')
               AND json_extract(value_json, '$.payload.data.attempt_id') = ?3",
            params![
                run_id.to_string(),
                session_id.to_string(),
                attempt_id.to_string()
            ],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn validate_planner_inference_observed(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    observed: &birdcode_protocol::PlannerInferenceObserved,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let prepared_event = event_by_id_for_run(
        transaction,
        event.session_id,
        run_id,
        observed.prepared_event_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if event.causal_parent != Some(prepared_event.id)
        || event.actor_id != prepared_event.actor_id
        || observed.attempt_id != prepared.attempt_id
        || observed.token_reservation_id != prepared.token_reservation.id
        || inference_terminal_count(transaction, event.session_id, run_id, observed.attempt_id)?
            != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_active_claim_owner(transaction, event, run_id)?;
    if let birdcode_protocol::PlannerInferenceObservation::Succeeded {
        reported_backend_model,
        token_usage,
    } = &observed.outcome
        && (reported_backend_model != &prepared.backend_model
            || token_usage.output_tokens > prepared.token_reservation.max_output_tokens
            || token_usage.total_tokens > prepared.token_reservation.reserved_tokens
            || token_usage.total_tokens
                != token_usage
                    .input_tokens
                    .checked_add(token_usage.output_tokens)
                    .ok_or(StoreError::InvalidStateEvent)?
            || token_usage
                .cached_input_tokens
                .is_some_and(|cached| cached > token_usage.input_tokens))
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn validate_planner_inference_unknown(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    unknown: &birdcode_protocol::PlannerInferenceOutcomeUnknown,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let prepared_event = event_by_id_for_run(
        transaction,
        event.session_id,
        run_id,
        unknown.prepared_event_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    require_current_claim_owner(transaction, event, run_id, unknown.cancellation_generation)?;
    if event.causal_parent != Some(prepared_event.id)
        || unknown.attempt_id != prepared.attempt_id
        || unknown.token_reservation_id != prepared.token_reservation.id
        || inference_terminal_count(transaction, event.session_id, run_id, unknown.attempt_id)? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn validate_read_operation_prepared(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    prepared: &birdcode_protocol::ReadOperationPrepared,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    if latest_cancellation_generation(transaction, event.session_id, run_id)? != 0 {
        return Err(StoreError::InvalidStateEvent);
    }
    require_latest_run_parent(transaction, event, run_id)?;
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    if event_count_by_json_identity(
        transaction,
        "read_operation_prepared",
        "$.payload.data.operation_id",
        &prepared.operation_id.to_string(),
    )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_current_plan_base(
        transaction,
        event.session_id,
        run_id,
        prepared.plan_revision,
        &prepared.plan_digest,
        false,
    )
}

fn validate_read_operation_observed(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    observed: &birdcode_protocol::ReadOperationObserved,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    let prepared_event = event_by_id_for_run(
        transaction,
        event.session_id,
        run_id,
        observed.prepared_event_id,
    )?;
    let EventPayload::ReadOperationPrepared(prepared) = &prepared_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    let existing = transaction.query_row(
        "SELECT COUNT(*) FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'read_operation_observed'
           AND json_extract(value_json, '$.payload.data.operation_id') = ?3",
        params![
            run_id.to_string(),
            event.session_id.to_string(),
            observed.operation_id.to_string()
        ],
        |row| row.get::<_, u64>(0),
    )?;
    if event.causal_parent != Some(prepared_event.id)
        || event.actor_id != prepared_event.actor_id
        || observed.operation_id != prepared.operation_id
        || existing != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    require_active_claim_owner(transaction, event, run_id)?;
    Ok(())
}

fn successful_observed_for_decision(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    run_id: RunId,
    observed_event_id: EventId,
    attempt_id: InferenceAttemptId,
) -> Result<EventEnvelope, StoreError> {
    let observed_event =
        event_by_id_for_run(transaction, event.session_id, run_id, observed_event_id)?;
    let EventPayload::PlannerInferenceObserved(observed) = &observed_event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if event.causal_parent != Some(observed_event.id)
        || observed.attempt_id != attempt_id
        || !matches!(
            observed.outcome,
            birdcode_protocol::PlannerInferenceObservation::Succeeded { .. }
        )
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(observed_event)
}

fn plan_decision_count(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    run_id: RunId,
    attempt_id: InferenceAttemptId,
) -> Result<u64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE run_id = ?1 AND session_id = ?2
               AND json_extract(value_json, '$.payload.type') IN
                   ('plan_proposal_accepted', 'plan_proposal_rejected')
               AND json_extract(value_json, '$.payload.data.inference_attempt_id') = ?3",
            params![
                run_id.to_string(),
                session_id.to_string(),
                attempt_id.to_string()
            ],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn validate_plan_proposal_rejected(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    rejected: &birdcode_protocol::PlanProposalRejected,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    successful_observed_for_decision(
        transaction,
        event,
        run_id,
        rejected.observed_event_id,
        rejected.inference_attempt_id,
    )?;
    let prepared = prepared_inference_for_attempt(
        transaction,
        event.session_id,
        run_id,
        rejected.inference_attempt_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = prepared.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    if rejected.base_plan_revision != prepared.plan_revision
        || rejected.base_plan_digest != prepared.plan_digest
        || plan_decision_count(
            transaction,
            event.session_id,
            run_id,
            rejected.inference_attempt_id,
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_rejected",
            "$.payload.data.proposal_id",
            &rejected.proposal_id.to_string(),
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_accepted",
            "$.payload.data.proposal_id",
            &rejected.proposal_id.to_string(),
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let current = current_plan_base(transaction, event.session_id, run_id)?
        .unwrap_or((0, prepared.plan_digest.clone()));
    let reason_matches_cas = match rejected.reason {
        PlanProposalRejectionReason::StaleBaseRevision => current.0 != rejected.base_plan_revision,
        PlanProposalRejectionReason::StaleBaseDigest => {
            current.0 == rejected.base_plan_revision && current.1 != rejected.base_plan_digest
        }
        _ => current.0 == rejected.base_plan_revision && current.1 == rejected.base_plan_digest,
    };
    if !reason_matches_cas {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn validate_plan_proposal_accepted(
    transaction: &Transaction<'_>,
    event: &NewEvent,
    accepted: &birdcode_protocol::PlanProposalAccepted,
) -> Result<(), StoreError> {
    let run_id = planner_run_id(event)?;
    require_running_run(transaction, event, run_id)?;
    successful_observed_for_decision(
        transaction,
        event,
        run_id,
        accepted.observed_event_id,
        accepted.inference_attempt_id,
    )?;
    let prepared = prepared_inference_for_attempt(
        transaction,
        event.session_id,
        run_id,
        accepted.inference_attempt_id,
    )?;
    let EventPayload::PlannerInferencePrepared(prepared) = prepared.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    require_current_claim_owner(transaction, event, run_id, prepared.cancellation_generation)?;
    let current = current_plan_base(transaction, event.session_id, run_id)?
        .unwrap_or((0, prepared.plan_digest.clone()));
    if accepted.previous_plan_revision != prepared.plan_revision
        || accepted.previous_plan_digest != prepared.plan_digest
        || current.0 != accepted.previous_plan_revision
        || current.1 != accepted.previous_plan_digest
        || accepted.accepted_plan_revision
            != accepted
                .previous_plan_revision
                .checked_add(1)
                .ok_or(StoreError::InvalidStateEvent)?
        || accepted.accepted_plan_digest.as_str() != accepted.accepted_plan_artifact.sha256.as_str()
        || plan_decision_count(
            transaction,
            event.session_id,
            run_id,
            accepted.inference_attempt_id,
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_rejected",
            "$.payload.data.proposal_id",
            &accepted.proposal_id.to_string(),
        )? != 0
        || event_count_by_json_identity(
            transaction,
            "plan_proposal_accepted",
            "$.payload.data.proposal_id",
            &accepted.proposal_id.to_string(),
        )? != 0
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn encode_run_state(state: RunState) -> &'static str {
    match state {
        RunState::Queued => "queued",
        RunState::Running => "running",
        RunState::Waiting => "waiting",
        RunState::Completed => "completed",
        RunState::Failed => "failed",
        RunState::Cancelled => "cancelled",
    }
}

fn decode_run_state(value: &str) -> Result<RunState, StoreError> {
    match value {
        "queued" => Ok(RunState::Queued),
        "running" => Ok(RunState::Running),
        "waiting" => Ok(RunState::Waiting),
        "completed" => Ok(RunState::Completed),
        "failed" => Ok(RunState::Failed),
        "cancelled" => Ok(RunState::Cancelled),
        _ => Err(StoreError::InvalidStateEvent),
    }
}

const fn valid_run_transition(from: RunState, to: RunState) -> bool {
    matches!(
        (from, to),
        (
            RunState::Queued | RunState::Waiting,
            RunState::Running | RunState::Failed | RunState::Cancelled
        ) | (
            RunState::Running,
            RunState::Waiting | RunState::Completed | RunState::Failed | RunState::Cancelled
        )
    )
}

const fn is_terminal_run_state(state: RunState) -> bool {
    matches!(
        state,
        RunState::Completed | RunState::Failed | RunState::Cancelled
    )
}

fn decode_canonical_event(json: &str) -> Result<EventEnvelope, StoreError> {
    let value = serde_json::from_str::<serde_json::Value>(json)?;
    decode_stored_event_value(value)
}

fn decode_legacy_event(connection: &Connection, json: &str) -> Result<EventEnvelope, StoreError> {
    let mut value = serde_json::from_str::<serde_json::Value>(json)?;
    if let Some(object) = value.as_object_mut() {
        object
            .entry("causal_parent")
            .or_insert(serde_json::Value::Null);
    }
    upgrade_legacy_creation_payload(connection, &mut value)?;
    decode_stored_event_value(value)
}

/// Protocol v2 persisted runs predate `RunPurpose`. Store replay upgrades only
/// that missing historical field to `Execute`; the protocol's v3 serde types
/// remain strict and continue rejecting wire requests without `purpose`.
fn decode_stored_run(json: &str) -> Result<Run, StoreError> {
    let mut value = serde_json::from_str::<serde_json::Value>(json)?;
    insert_legacy_execute_purpose(&mut value, "/spec")?;
    serde_json::from_value(value).map_err(StoreError::from)
}

fn decode_stored_event_value(mut value: serde_json::Value) -> Result<EventEnvelope, StoreError> {
    insert_legacy_execute_purpose(&mut value, "/payload/data/run/spec")?;
    serde_json::from_value(value).map_err(StoreError::from)
}

fn insert_legacy_execute_purpose(
    value: &mut serde_json::Value,
    spec_pointer: &str,
) -> Result<(), StoreError> {
    let Some(spec) = value.pointer_mut(spec_pointer) else {
        return Ok(());
    };
    let spec = spec.as_object_mut().ok_or(StoreError::InvalidStateEvent)?;
    spec.entry("purpose")
        .or_insert_with(|| serde_json::Value::String("execute".to_owned()));
    Ok(())
}

fn validate_typed_artifact_refs(
    artifact_root: &Path,
    provenance: &Provenance,
    payload: &EventPayload,
) -> Result<(), StoreError> {
    if matches!(payload, EventPayload::BackendEvent { .. }) && provenance.raw_artifact.is_none() {
        return Err(StoreError::InvalidStateEvent);
    }
    let mut cost = ArtifactValidationCost::default();
    if let Some(artifact) = &provenance.raw_artifact {
        cost.add(artifact)?;
    }
    match payload {
        EventPayload::UserInput { items } => cost.add_inputs(items)?,
        EventPayload::RunCreated { run } => cost.add_inputs(&run.spec.input)?,
        EventPayload::ArtifactStored { artifact } => cost.add(artifact)?,
        EventPayload::PlannerInferencePrepared(prepared) => {
            cost.add(&prepared.prompt_artifact)?;
            cost.add(&prepared.request_artifact)?;
        }
        EventPayload::RootPlanningFailed(failure) => {
            cost.add(&failure.evidence_artifact)?;
        }
        EventPayload::PlannerInferenceObserved(observed) => {
            cost.add(&observed.normalized_complete_evidence_artifact)?;
        }
        EventPayload::ReadOperationPrepared(prepared) => {
            cost.add(&prepared.request_artifact)?;
        }
        EventPayload::ReadOperationObserved(observed) => {
            cost.add(&observed.normalized_complete_evidence_artifact)?;
        }
        EventPayload::PlanProposalRejected(rejected) => {
            cost.add(&rejected.proposal_artifact)?;
            cost.add(&rejected.validation_evidence_artifact)?;
        }
        EventPayload::PlanProposalAccepted(accepted) => {
            cost.add(&accepted.proposal_artifact)?;
            cost.add(&accepted.accepted_plan_artifact)?;
            cost.add(&accepted.validation_evidence_artifact)?;
        }
        _ => {}
    }
    cost.enforce_event_limit()?;

    if let Some(artifact) = &provenance.raw_artifact {
        verify_artifact_at_root(artifact_root, artifact)?;
    }
    match payload {
        EventPayload::UserInput { items } => verify_input_artifacts(artifact_root, items),
        EventPayload::RunCreated { run } => verify_input_artifacts(artifact_root, &run.spec.input),
        EventPayload::ArtifactStored { artifact } => {
            verify_artifact_at_root(artifact_root, artifact)
        }
        EventPayload::PlannerInferencePrepared(prepared) => {
            verify_artifact_at_root(artifact_root, &prepared.prompt_artifact)?;
            verify_artifact_at_root(artifact_root, &prepared.request_artifact)
        }
        EventPayload::RootPlanningFailed(failure) => {
            verify_artifact_at_root(artifact_root, &failure.evidence_artifact)
        }
        EventPayload::PlannerInferenceObserved(observed) => verify_artifact_at_root(
            artifact_root,
            &observed.normalized_complete_evidence_artifact,
        ),
        EventPayload::ReadOperationPrepared(prepared) => {
            verify_artifact_at_root(artifact_root, &prepared.request_artifact)
        }
        EventPayload::ReadOperationObserved(observed) => verify_artifact_at_root(
            artifact_root,
            &observed.normalized_complete_evidence_artifact,
        ),
        EventPayload::PlanProposalRejected(rejected) => {
            verify_artifact_at_root(artifact_root, &rejected.proposal_artifact)?;
            verify_artifact_at_root(artifact_root, &rejected.validation_evidence_artifact)
        }
        EventPayload::PlanProposalAccepted(accepted) => {
            verify_artifact_at_root(artifact_root, &accepted.proposal_artifact)?;
            verify_artifact_at_root(artifact_root, &accepted.accepted_plan_artifact)?;
            verify_artifact_at_root(artifact_root, &accepted.validation_evidence_artifact)
        }
        _ => Ok(()),
    }
}

fn validate_input_artifacts(artifact_root: &Path, items: &[InputItem]) -> Result<(), StoreError> {
    let mut cost = ArtifactValidationCost::default();
    cost.add_inputs(items)?;
    cost.enforce_event_limit()?;
    verify_input_artifacts(artifact_root, items)
}

fn verify_input_artifacts(artifact_root: &Path, items: &[InputItem]) -> Result<(), StoreError> {
    for item in items {
        if let InputItem::Artifact { artifact } = item {
            verify_artifact_at_root(artifact_root, artifact)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct ArtifactValidationCost {
    references: u32,
    bytes: u64,
}

impl ArtifactValidationCost {
    fn add(&mut self, artifact: &ArtifactRef) -> Result<(), StoreError> {
        self.references = self
            .references
            .checked_add(1)
            .ok_or(StoreError::ArtifactReferenceBudget)?;
        self.bytes = self
            .bytes
            .checked_add(artifact.size_bytes)
            .ok_or(StoreError::ArtifactReferenceBudget)?;
        Ok(())
    }

    fn add_inputs(&mut self, items: &[InputItem]) -> Result<(), StoreError> {
        for item in items {
            if let InputItem::Artifact { artifact } = item {
                self.add(artifact)?;
            }
        }
        Ok(())
    }

    fn enforce_event_limit(&self) -> Result<(), StoreError> {
        if self.references > MAX_EVENT_ARTIFACT_REFS
            || self.bytes > MAX_EVENT_REFERENCED_ARTIFACT_BYTES
        {
            Err(StoreError::ArtifactReferenceBudget)
        } else {
            Ok(())
        }
    }
}

fn verify_artifact_at_root(artifact_root: &Path, artifact: &ArtifactRef) -> Result<(), StoreError> {
    read_verified_artifact(
        &artifact_path_at(artifact_root, &artifact.sha256)?,
        artifact,
    )
    .map(|_| ())
}

fn artifact_path_at(artifact_root: &Path, hash: &str) -> Result<PathBuf, StoreError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::InvalidArtifactHash);
    }
    Ok(artifact_root.join(&hash[..2]).join(hash))
}

fn upgrade_legacy_creation_payload(
    connection: &Connection,
    envelope: &mut serde_json::Value,
) -> Result<(), StoreError> {
    let payload_type = envelope
        .pointer("/payload/type")
        .and_then(serde_json::Value::as_str);
    let requires_session = payload_type == Some("session_created")
        && envelope.pointer("/payload/data/session").is_none();
    let requires_run =
        payload_type == Some("run_created") && envelope.pointer("/payload/data/run").is_none();
    if !requires_session && !requires_run {
        return Ok(());
    }

    let (column, table) = if requires_session {
        ("session_id", "sessions")
    } else {
        ("run_id", "runs")
    };
    let id = envelope
        .get(column)
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::InvalidStateEvent)?;
    let query = if table == "sessions" {
        "SELECT value_json FROM sessions WHERE id = ?1"
    } else {
        "SELECT value_json FROM runs WHERE id = ?1"
    };
    let materialized = connection
        .query_row(query, [id], |row| row.get::<_, String>(0))
        .optional()?
        .ok_or(StoreError::InvalidStateEvent)?;
    let materialized = serde_json::from_str::<serde_json::Value>(&materialized)?;
    let payload = envelope
        .get_mut("payload")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(StoreError::InvalidStateEvent)?;
    payload.insert(
        "data".to_owned(),
        if requires_session {
            serde_json::json!({ "session": materialized })
        } else {
            serde_json::json!({ "run": materialized })
        },
    );
    Ok(())
}

fn probe_artifact_root(artifact_root: &Path) -> Result<(), StoreError> {
    validate_real_directory(artifact_root)?;
    reject_shared_writable_directory(artifact_root)?;
    let path = artifact_root.join(format!(".birdcode-health-{}", EventId::new()));
    let expected_hash = sha256_hex(ARTIFACT_HEALTH_CANARY_BYTES);
    let probe = (|| -> Result<(), StoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(ARTIFACT_HEALTH_CANARY_BYTES)?;
        file.sync_all()?;
        sync_directory(artifact_root)?;
        drop(file);

        let mut file = OpenOptions::new().read(true).open(&path)?;
        let mut bytes = Vec::with_capacity(ARTIFACT_HEALTH_CANARY_BYTES.len() + 1);
        Read::by_ref(&mut file)
            .take(u64::try_from(ARTIFACT_HEALTH_CANARY_BYTES.len()).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut bytes)?;
        if bytes != ARTIFACT_HEALTH_CANARY_BYTES || sha256_hex(&bytes) != expected_hash {
            return Err(StoreError::ArtifactIntegrity);
        }
        Ok(())
    })();

    let cleanup = match fs::remove_file(&path) {
        Ok(()) => sync_directory(artifact_root).map_err(StoreError::from),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StoreError::Io(error)),
    };
    match (probe, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), result) => result,
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    // Windows does not expose a portable std API for opening a directory as a
    // flushable handle. File contents are still fsynced before the atomic move.
    Ok(())
}

fn prepare_private_directory(path: &Path) -> io::Result<()> {
    let existed = path.exists();
    fs::create_dir_all(path)?;
    validate_real_directory(path)?;
    if existed {
        reject_shared_writable_directory(path)?;
    } else {
        set_private_directory_permissions(path)?;
    }
    Ok(())
}

fn reject_shared_writable_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if fs::metadata(path)?.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "state directory is writable by group or others: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    validate_real_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn validate_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("state path is not a real directory: {}", path.display()),
        ));
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("state path is not a real file: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn secure_sqlite_family(database: &Path) -> io::Result<()> {
    set_private_file_permissions(database)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            set_private_file_permissions(&sidecar)?;
        }
    }
    Ok(())
}

fn append_event_in_transaction(
    transaction: &Transaction<'_>,
    event: NewEvent,
) -> Result<EventEnvelope, StoreError> {
    let current: u64 = transaction.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM events WHERE session_id = ?1",
        [event.session_id.to_string()],
        |row| row.get(0),
    )?;
    let sequence = current.checked_add(1).ok_or(StoreError::SequenceOverflow)?;
    let envelope = EventEnvelope {
        id: EventId::new(),
        sequence,
        session_id: event.session_id,
        run_id: event.run_id,
        actor_id: event.actor_id,
        causal_parent: event.causal_parent,
        occurred_at: Utc::now(),
        provenance: event.provenance,
        payload: event.payload,
    };
    let value_json = encode_inline_event(&envelope)?;
    transaction.execute(
        "INSERT INTO events (
             id, session_id, run_id, causal_parent, sequence, value_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            envelope.id.to_string(),
            envelope.session_id.to_string(),
            envelope.run_id.map(|id| id.to_string()),
            envelope.causal_parent.map(|id| id.to_string()),
            envelope.sequence,
            value_json
        ],
    )?;
    Ok(envelope)
}

fn encode_inline_event(event: &EventEnvelope) -> Result<String, StoreError> {
    let mut encoded = CappedEventJson::new(MAX_INLINE_EVENT_BYTES);
    let result = serde_json::to_writer(&mut encoded, event);
    if encoded.overflowed {
        return Err(StoreError::EventTooLarge);
    }
    result?;
    Ok(String::from_utf8(encoded.bytes).expect("serde_json always emits valid UTF-8"))
}

struct CappedEventJson {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl CappedEventJson {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }
}

impl Write for CappedEventJson {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > self.limit {
            self.overflowed = true;
            return Err(io::Error::other(
                "serialized event exceeded its inline size limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn verify_artifact(artifact: &ArtifactRef, bytes: &[u8]) -> Result<(), StoreError> {
    let size = u64::try_from(bytes.len()).map_err(|_| StoreError::ArtifactTooLarge)?;
    if size != artifact.size_bytes || sha256_hex(bytes) != artifact.sha256 {
        return Err(StoreError::ArtifactIntegrity);
    }
    Ok(())
}

fn read_verified_artifact(path: &Path, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
    if artifact.size_bytes > MAX_ARTIFACT_BYTES {
        return Err(StoreError::ArtifactTooLarge);
    }
    set_private_file_permissions(path)?;
    let file = fs::File::open(path)?;
    let actual_size = file.metadata()?.len();
    if actual_size > MAX_ARTIFACT_BYTES {
        return Err(StoreError::ArtifactTooLarge);
    }
    if actual_size != artifact.size_bytes {
        return Err(StoreError::ArtifactIntegrity);
    }
    let capacity = usize::try_from(actual_size).map_err(|_| StoreError::ArtifactTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_ARTIFACT_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |size| size > MAX_ARTIFACT_BYTES) {
        return Err(StoreError::ArtifactTooLarge);
    }
    verify_artifact(artifact, &bytes)?;
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hash = String::with_capacity(64);
    for byte in digest {
        hash.push(char::from(HEX[usize::from(byte >> 4)]));
        hash.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hash
}

fn read_json<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    query: &str,
    id: String,
) -> Result<Option<T>, StoreError> {
    let value = connection
        .query_row(query, [id], |row| row.get::<_, String>(0))
        .optional()?;
    value
        .map(|json| serde_json::from_str(&json))
        .transpose()
        .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use birdcode_protocol::{
        ActorId, BackendKind, BackendModelIdentity, BackendSelection, CancellationRequested,
        CreateSessionRequest, EventPayload, InferenceAttemptId, InputItem, PlanProposalAccepted,
        PlanProposalId, PlanProposalRejected, PlannerInferenceObservation,
        PlannerInferenceObserved, PlannerInferenceOutcomeUnknown, PlannerInferencePrepared,
        Provenance, ReadOperation, ReadOperationId, ReadOperationObservation,
        ReadOperationObserved, ReadOperationPrepared, RunClaimId, RunClaimed, RunLimits,
        RunPurpose, RunSpec, RuntimeInstanceId, TokenReservation, TokenReservationId, TokenUsage,
        UnknownInferenceOutcomeReason, WORKSPACE_PATH_WIRE_VERSION,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    fn assert_two_concurrent_opens(database: &Path, artifacts: &Path) {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                let database = database.to_path_buf();
                let artifacts = artifacts.to_path_buf();
                std::thread::spawn(move || {
                    barrier.wait();
                    Store::open(database, artifacts)
                        .map(drop)
                        .map_err(|error| error.to_string())
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle
                .join()
                .expect("concurrent opener should not panic")
                .expect("concurrent store open should succeed");
        }
    }

    fn test_store() -> (TempDir, Store) {
        let directory = TempDir::new().expect("temporary directory should be created");
        let store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("store should open");
        (directory, store)
    }

    fn store_with_session_event() -> (TempDir, Store, EventEnvelope) {
        let (directory, mut store) = test_store();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/append-only").into(),
            title: Some("Append-only regression".to_owned()),
        });
        let event = store
            .create_session(&session, session_event(&session, ActorId::new()))
            .expect("session event should persist");
        (directory, store, event)
    }

    fn assert_append_only_abort(error: rusqlite::Error) {
        match error {
            rusqlite::Error::SqliteFailure(code, Some(message)) => {
                assert_eq!(code.code, rusqlite::ErrorCode::ConstraintViolation);
                assert_eq!(message, "events are append-only");
            }
            other => panic!("expected append-only trigger failure, got {other:?}"),
        }
    }

    fn provenance() -> Provenance {
        Provenance {
            producer: "test".to_owned(),
            backend: None,
            raw_artifact: None,
        }
    }

    fn session_event(session: &Session, actor_id: ActorId) -> NewEvent {
        NewEvent {
            session_id: session.id,
            run_id: None,
            actor_id,
            causal_parent: None,
            provenance: provenance(),
            payload: EventPayload::SessionCreated {
                session: session.clone(),
            },
        }
    }

    fn run_for(session: &Session) -> Run {
        Run::new(RunSpec {
            session_id: session.id,
            purpose: RunPurpose::PlanOnly,
            backend: BackendSelection {
                backend_id: "test".to_owned(),
                kind: BackendKind::Model,
                model: None,
                reasoning_effort: None,
            },
            input: vec![InputItem::Text {
                text: "migrera säkert 世界".to_owned(),
            }],
            limits: RunLimits::default(),
        })
    }

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(byte.to_string().repeat(Sha256Digest::HEX_LENGTH))
            .expect("fixture digest should be canonical")
    }

    fn fixture_artifact(store: &Store, label: &str) -> ArtifactRef {
        store
            .put_artifact(label.as_bytes(), "application/json")
            .expect("fixture artifact should persist")
    }

    #[allow(
        clippy::type_complexity,
        reason = "the tuple makes planner store fixtures explicit in adversarial tests"
    )]
    fn planner_store() -> (
        TempDir,
        Store,
        Session,
        Run,
        ActorId,
        RuntimeInstanceId,
        EventEnvelope,
        ArtifactRef,
        Sha256Digest,
    ) {
        planner_store_with_output_limit(None)
    }

    #[allow(
        clippy::type_complexity,
        reason = "the tuple makes planner store fixtures explicit in adversarial tests"
    )]
    fn planner_store_with_output_limit(
        max_output_tokens: Option<u64>,
    ) -> (
        TempDir,
        Store,
        Session,
        Run,
        ActorId,
        RuntimeInstanceId,
        EventEnvelope,
        ArtifactRef,
        Sha256Digest,
    ) {
        let (directory, mut store) = test_store();
        let actor_id = ActorId::new();
        let runtime_instance_id = RuntimeInstanceId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/planner-store").into(),
            title: Some("Durable planner".to_owned()),
        });
        let session_created = store
            .create_session(&session, session_event(&session, actor_id))
            .expect("session should persist");
        let mut run = run_for(&session);
        run.spec.limits.max_output_tokens = max_output_tokens;
        let run_created = store
            .create_run(
                &run,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(session_created.id),
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
                    runtime_instance_id,
                    claim_generation: 1,
                    cancellation_generation: 0,
                    lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
                }),
            })
            .expect("claim should persist");
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
            .expect("the live claim should start the planner run");
        let artifact = fixture_artifact(&store, "planner-fixture-artifact");
        let genesis_digest = digest('a');
        (
            directory,
            store,
            session,
            run,
            actor_id,
            runtime_instance_id,
            running,
            artifact,
            genesis_digest,
        )
    }

    fn prepared_payload(
        attempt_id: InferenceAttemptId,
        reservation_id: TokenReservationId,
        parent_attempt_id: Option<InferenceAttemptId>,
        artifact: &ArtifactRef,
        plan_revision: u64,
        plan_digest: Sha256Digest,
        cancellation_generation: u64,
    ) -> PlannerInferencePrepared {
        PlannerInferencePrepared {
            attempt_id,
            parent_attempt_id,
            backend_model: BackendModelIdentity {
                backend_id: "test".to_owned(),
                kind: BackendKind::Model,
                model_id: "gemma-fixture".to_owned(),
            },
            prompt_artifact: artifact.clone(),
            prompt_manifest_digest: digest('b'),
            request_artifact: artifact.clone(),
            token_reservation: TokenReservation {
                id: reservation_id,
                reserved_tokens: 128,
                max_output_tokens: 64,
            },
            plan_revision,
            plan_digest,
            obligation_snapshot_digest: digest('c'),
            acceptance_policy_digest: digest('d'),
            context_manifest_digest: digest('e'),
            planner_policy_digest: digest('f'),
            cancellation_generation,
        }
    }

    fn append_prepared(
        store: &mut Store,
        session: &Session,
        run: &Run,
        actor_id: ActorId,
        causal_parent: EventId,
        payload: PlannerInferencePrepared,
    ) -> EventEnvelope {
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(causal_parent),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(payload),
            })
            .expect("prepared inference should persist")
    }

    fn append_success_observation(
        store: &mut Store,
        session: &Session,
        run: &Run,
        actor_id: ActorId,
        prepared_event: &EventEnvelope,
        artifact: &ArtifactRef,
    ) -> EventEnvelope {
        let EventPayload::PlannerInferencePrepared(prepared) = &prepared_event.payload else {
            panic!("fixture must be a prepared inference")
        };
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(prepared_event.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                    attempt_id: prepared.attempt_id,
                    token_reservation_id: prepared.token_reservation.id,
                    prepared_event_id: prepared_event.id,
                    normalized_complete_evidence_artifact: artifact.clone(),
                    outcome: PlannerInferenceObservation::Succeeded {
                        reported_backend_model: prepared.backend_model.clone(),
                        token_usage: TokenUsage {
                            input_tokens: 20,
                            output_tokens: 30,
                            total_tokens: 50,
                            cached_input_tokens: Some(5),
                        },
                    },
                }),
            })
            .expect("observed inference should persist")
    }

    fn legacy_workspace_root_text(session: &Session) -> String {
        session
            .workspace_root
            .to_native()
            .expect("test workspace path should match the native platform")
            .to_str()
            .expect("protocol-v1 PathBuf JSON only represented Unicode paths")
            .to_owned()
    }

    fn legacy_session_json(session: &Session) -> serde_json::Value {
        let mut value = serde_json::to_value(session).expect("session should encode");
        value["workspace_root"] = serde_json::Value::String(legacy_workspace_root_text(session));
        value
    }

    fn rewrite_workspace_paths_as_protocol_v1(
        store: &Store,
        session: &Session,
        event: &EventEnvelope,
    ) {
        let legacy_root = serde_json::Value::String(legacy_workspace_root_text(session));
        let session_json = legacy_session_json(session).to_string();
        let mut event_json =
            serde_json::to_value(event).expect("session creation event should encode");
        *event_json
            .pointer_mut("/payload/data/session/workspace_root")
            .expect("session creation event should contain its workspace path") = legacy_root;

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
                    "UPDATE sessions SET value_json = ?1 WHERE id = ?2",
                    params![session_json, session.id.to_string()],
                )
                .expect("legacy materialized session should update"),
            1
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE events SET value_json = ?1 WHERE id = ?2",
                    params![event_json.to_string(), event.id.to_string()],
                )
                .expect("legacy session creation event should update"),
            1
        );
        transaction
            .execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)
            .expect("fixture should restore event immutability");
        transaction.commit().expect("fixture should commit");
    }

    fn drop_current_projection_objects(connection: &Connection) {
        connection
            .execute_batch(
                "DROP TRIGGER events_project_run_creation_after_insert;
                 DROP TRIGGER events_project_run_state_after_insert;
                 DROP TRIGGER runs_reject_identity_update;
                 DROP TRIGGER runs_reject_delete;
                 DROP TRIGGER runs_track_projection_health_after_insert;
                 DROP TABLE run_state_projection;
                 DROP TABLE run_state_projection_health;",
            )
            .expect("fixture should remove current projection objects");
    }

    fn downgrade_store_to_schema(store: &Store, version: i64) {
        drop_current_projection_objects(&store.connection);
        match version {
            IMMUTABLE_SCHEMA_VERSION => store
                .connection
                .execute_batch(
                    "DROP TRIGGER events_reject_conflicting_insert;
                     DROP TRIGGER events_reject_oversized_insert;
                     DROP INDEX events_by_run_sequence;
                     DROP TABLE runtime_health_canary;
                     PRAGMA user_version = 2;",
                )
                .expect("fixture should become schema v2"),
            INDEXED_SCHEMA_VERSION => store
                .connection
                .execute_batch(
                    "DROP TRIGGER events_reject_oversized_insert;
                     DROP TABLE runtime_health_canary;
                     PRAGMA user_version = 3;",
                )
                .expect("fixture should become schema v3"),
            EVENT_SIZE_SCHEMA_VERSION => store
                .connection
                .execute_batch(
                    "DROP TABLE runtime_health_canary;
                     PRAGMA user_version = 4;",
                )
                .expect("fixture should become schema v4"),
            HEALTH_CANARY_SCHEMA_VERSION => store
                .connection
                .execute_batch("PRAGMA user_version = 5;")
                .expect("fixture should become schema v5"),
            other => panic!("unsupported fixture schema {other}"),
        }
    }

    fn assert_workspace_paths_are_canonical(
        store: &Store,
        session_id: SessionId,
        event_id: EventId,
    ) {
        let session_json = store
            .connection
            .query_row(
                "SELECT value_json FROM sessions WHERE id = ?1",
                [session_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .expect("materialized session JSON should read");
        let session_value = serde_json::from_str::<serde_json::Value>(&session_json)
            .expect("materialized session JSON should parse");
        assert_eq!(
            session_value.pointer("/workspace_root/wire_version"),
            Some(&serde_json::json!(WORKSPACE_PATH_WIRE_VERSION))
        );
        #[cfg(unix)]
        assert_eq!(
            session_value.pointer("/workspace_root/representation/encoding"),
            Some(&serde_json::json!("unix_bytes"))
        );
        #[cfg(windows)]
        assert_eq!(
            session_value.pointer("/workspace_root/representation/encoding"),
            Some(&serde_json::json!("windows_utf16"))
        );
        serde_json::from_str::<Session>(&session_json)
            .expect("materialized session should use the canonical path wire format");

        let event_json = store
            .connection
            .query_row(
                "SELECT value_json FROM events WHERE id = ?1",
                [event_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .expect("session creation event JSON should read");
        let event_value = serde_json::from_str::<serde_json::Value>(&event_json)
            .expect("session creation event JSON should parse");
        assert_eq!(
            event_value.pointer("/payload/data/session/workspace_root/wire_version"),
            Some(&serde_json::json!(WORKSPACE_PATH_WIRE_VERSION))
        );
        #[cfg(unix)]
        assert_eq!(
            event_value.pointer("/payload/data/session/workspace_root/representation/encoding"),
            Some(&serde_json::json!("unix_bytes"))
        );
        #[cfg(windows)]
        assert_eq!(
            event_value.pointer("/payload/data/session/workspace_root/representation/encoding"),
            Some(&serde_json::json!("windows_utf16"))
        );
        serde_json::from_str::<EventEnvelope>(&event_json)
            .expect("session creation event should use the canonical path wire format");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture mirrors the complete legacy schema and wire shapes"
    )]
    fn create_legacy_database(
        path: &Path,
        include_legacy_creation_events: bool,
    ) -> (Session, Run, Option<(EventId, EventId)>) {
        let connection = Connection::open(path).expect("legacy database should open");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE sessions (
                     id TEXT PRIMARY KEY NOT NULL,
                     value_json TEXT NOT NULL
                 );
                 CREATE TABLE runs (
                     id TEXT PRIMARY KEY NOT NULL,
                     session_id TEXT NOT NULL,
                     value_json TEXT NOT NULL,
                     FOREIGN KEY(session_id) REFERENCES sessions(id)
                 );
                 CREATE TABLE events (
                     id TEXT PRIMARY KEY NOT NULL,
                     session_id TEXT NOT NULL,
                     run_id TEXT,
                     sequence INTEGER NOT NULL,
                     value_json TEXT NOT NULL,
                     UNIQUE(session_id, sequence),
                     FOREIGN KEY(session_id) REFERENCES sessions(id),
                     FOREIGN KEY(run_id) REFERENCES runs(id)
                 );
                 PRAGMA user_version = 1;",
            )
            .expect("legacy schema should be created");
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/legacy").into(),
            title: Some("Äldre session".to_owned()),
        });
        let run = run_for(&session);
        let legacy_session = legacy_session_json(&session);
        connection
            .execute(
                "INSERT INTO sessions (id, value_json) VALUES (?1, ?2)",
                rusqlite::params![session.id.to_string(), legacy_session.to_string()],
            )
            .expect("legacy session should insert");
        connection
            .execute(
                "INSERT INTO runs (id, session_id, value_json) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    run.id.to_string(),
                    session.id.to_string(),
                    serde_json::to_string(&run).expect("run should encode")
                ],
            )
            .expect("legacy run should insert");

        let creation_ids = include_legacy_creation_events.then(|| {
            let session_event_id = EventId::new();
            let run_event_id = EventId::new();
            let actor_id = ActorId::new();
            let session_json = serde_json::json!({
                "id": session_event_id,
                "sequence": 1,
                "session_id": session.id,
                "run_id": null,
                "actor_id": actor_id,
                "occurred_at": session.created_at,
                "provenance": provenance(),
                "payload": { "type": "session_created" }
            });
            let run_json = serde_json::json!({
                "id": run_event_id,
                "sequence": 2,
                "session_id": session.id,
                "run_id": run.id,
                "actor_id": actor_id,
                "causal_parent": session_event_id,
                "occurred_at": run.created_at,
                "provenance": provenance(),
                "payload": {
                    "type": "run_created",
                    "data": { "spec": run.spec }
                }
            });
            for (id, run_id, sequence, json) in [
                (session_event_id, None, 1_u64, session_json),
                (run_event_id, Some(run.id), 2_u64, run_json),
            ] {
                connection
                    .execute(
                        "INSERT INTO events (
                             id, session_id, run_id, sequence, value_json
                         ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            id.to_string(),
                            session.id.to_string(),
                            run_id.map(|value| value.to_string()),
                            sequence,
                            json.to_string()
                        ],
                    )
                    .expect("legacy event should insert");
            }
            (session_event_id, run_event_id)
        });
        (session, run, creation_ids)
    }

    #[test]
    fn appends_events_in_order_without_rewriting_history() {
        let (_directory, mut store) = test_store();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/example").into(),
            title: Some("Flerspråkig session".to_owned()),
        });
        let actor_id = ActorId::new();
        store
            .create_session(&session, session_event(&session, actor_id))
            .expect("session should persist with its event");

        for text in ["första", "第二"] {
            store
                .append_event(NewEvent {
                    session_id: session.id,
                    run_id: None,
                    actor_id,
                    causal_parent: None,
                    provenance: provenance(),
                    payload: EventPayload::UserInput {
                        items: vec![birdcode_protocol::InputItem::Text {
                            text: text.to_owned(),
                        }],
                    },
                })
                .expect("event should append");
        }

        let events = store
            .events_after(session.id, 0)
            .expect("events should load");
        assert_eq!(
            events
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn raw_insert_or_replace_cannot_rewrite_an_existing_event_id() {
        let (_directory, store, original) = store_with_session_event();
        let recursive_triggers = store
            .connection
            .pragma_query_value(None, "recursive_triggers", |row| row.get::<_, bool>(0))
            .expect("recursive_triggers should read");
        assert!(!recursive_triggers);

        let error = store
            .connection
            .execute(
                "INSERT OR REPLACE INTO events (
                     id, session_id, run_id, causal_parent, sequence, value_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    original.id.to_string(),
                    original.session_id.to_string(),
                    Option::<String>::None,
                    Option::<String>::None,
                    original.sequence + 1,
                    serde_json::to_string(&original).expect("event should encode")
                ],
            )
            .expect_err("existing event id must not be replaceable");
        assert_append_only_abort(error);
        assert_eq!(
            store
                .events_after(original.session_id, 0)
                .expect("history should remain readable")
                .events,
            vec![original]
        );
    }

    #[test]
    fn raw_insert_or_replace_cannot_rewrite_a_session_sequence() {
        let (_directory, store, original) = store_with_session_event();
        let replacement_id = EventId::new();

        let error = store
            .connection
            .execute(
                "INSERT OR REPLACE INTO events (
                     id, session_id, run_id, causal_parent, sequence, value_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    replacement_id.to_string(),
                    original.session_id.to_string(),
                    Option::<String>::None,
                    Option::<String>::None,
                    original.sequence,
                    serde_json::to_string(&original).expect("event should encode")
                ],
            )
            .expect_err("existing session sequence must not be replaceable");
        assert_append_only_abort(error);
        assert_eq!(
            store
                .events_after(original.session_id, 0)
                .expect("history should remain readable")
                .events,
            vec![original]
        );
    }

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
        let fresh = Store::open(&fresh_database, &fresh_artifacts)
            .expect("initialized store should reopen");
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

    #[test]
    fn v1_migration_preserves_interleaved_run_creation_parented_to_user_input() {
        let directory = TempDir::new().expect("temporary directory should be created");
        let database = directory.path().join("legacy-interleaved.sqlite3");
        let (session, _run, creation_ids) = create_legacy_database(&database, true);
        let (session_event_id, run_event_id) = creation_ids.expect("legacy events should exist");
        let user_input_id = EventId::new();
        let user_input = EventEnvelope {
            id: user_input_id,
            sequence: 2,
            session_id: session.id,
            run_id: None,
            actor_id: ActorId::new(),
            causal_parent: Some(session_event_id),
            occurred_at: Utc::now(),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "planera först".to_owned(),
                }],
            },
        };
        let connection = Connection::open(&database).expect("legacy database should reopen");
        let run_json = connection
            .query_row(
                "SELECT value_json FROM events WHERE id = ?1",
                [run_event_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .expect("legacy run creation should read");
        let mut run_json = serde_json::from_str::<serde_json::Value>(&run_json)
            .expect("legacy run creation should parse");
        run_json["sequence"] = serde_json::json!(3);
        run_json["causal_parent"] = serde_json::json!(user_input_id);
        connection
            .execute(
                "UPDATE events SET sequence = 3, value_json = ?1 WHERE id = ?2",
                params![run_json.to_string(), run_event_id.to_string()],
            )
            .expect("legacy run creation should move after user input");
        connection
            .execute(
                "INSERT INTO events (id, session_id, run_id, sequence, value_json)
                 VALUES (?1, ?2, NULL, 2, ?3)",
                params![
                    user_input_id.to_string(),
                    session.id.to_string(),
                    serde_json::to_string(&user_input).expect("user input should encode")
                ],
            )
            .expect("interleaved user input should insert");
        drop(connection);

        let store = Store::open(&database, directory.path().join("artifacts"))
            .expect("interleaved legacy history should migrate");
        let events = store
            .events_after(session.id, 0)
            .expect("migrated history should replay")
            .events;
        assert_eq!(
            events.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![session_event_id, user_input_id, run_event_id]
        );
        assert_eq!(events[2].causal_parent, Some(user_input_id));
        assert_eq!(events[2].sequence, 3);
    }

    #[test]
    fn mixed_legacy_history_places_synthesized_run_before_dependent_events() {
        let directory = TempDir::new().expect("temporary directory should be created");
        let database = directory.path().join("legacy.sqlite3");
        let (session, run, creation_ids) = create_legacy_database(&database, true);
        let (session_event_id, run_event_id) = creation_ids.expect("legacy events should exist");
        let dependent_id = EventId::new();
        let dependent = EventEnvelope {
            id: dependent_id,
            sequence: 2,
            session_id: session.id,
            run_id: Some(run.id),
            actor_id: ActorId::new(),
            causal_parent: Some(session_event_id),
            occurred_at: Utc::now(),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "bevarad".to_owned(),
                }],
            },
        };
        let connection = Connection::open(&database).expect("legacy database should reopen");
        connection
            .execute(
                "DELETE FROM events WHERE id = ?1",
                [run_event_id.to_string()],
            )
            .expect("legacy run creation should be removed");
        connection
            .execute(
                "INSERT INTO events (id, session_id, run_id, sequence, value_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    dependent.id.to_string(),
                    session.id.to_string(),
                    run.id.to_string(),
                    dependent.sequence,
                    serde_json::to_string(&dependent).expect("dependent event should encode")
                ],
            )
            .expect("dependent legacy event should insert");
        drop(connection);

        let store = Store::open(&database, directory.path().join("artifacts"))
            .expect("mixed legacy history should migrate");
        let events = store
            .events_after(session.id, 0)
            .expect("migrated events should replay");
        assert_eq!(events.events.len(), 3);
        assert_eq!(events.events[0].id, session_event_id);
        assert!(matches!(
            events.events[0].payload,
            EventPayload::SessionCreated { .. }
        ));
        assert!(matches!(
            events.events[1].payload,
            EventPayload::RunCreated { .. }
        ));
        assert_eq!(
            events.events[1].provenance.producer,
            "birdcode-store-migration/v1-to-v2"
        );
        assert_eq!(events.events[2].id, dependent_id);
        assert!(matches!(
            events.events[2].payload,
            EventPayload::UserInput { .. }
        ));
        assert_eq!(
            events
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one regression covers late, missing, and non-causal v1 creation histories"
    )]
    fn v1_creation_and_causal_order_is_fail_closed_but_missing_creation_is_synthesized() {
        let late_directory = TempDir::new().expect("temporary directory should be created");
        let late_database = late_directory.path().join("late-run-created.sqlite3");
        let (late_session, late_run, creation_ids) = create_legacy_database(&late_database, true);
        let (late_session_event_id, late_run_event_id) =
            creation_ids.expect("legacy creation events should exist");
        let late_connection =
            Connection::open(&late_database).expect("legacy database should open");
        let late_run_json = late_connection
            .query_row(
                "SELECT value_json FROM events WHERE id = ?1",
                [late_run_event_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .expect("legacy run event should read");
        let mut late_run_json = serde_json::from_str::<serde_json::Value>(&late_run_json)
            .expect("legacy run event should decode");
        late_run_json["sequence"] = serde_json::json!(3);
        late_connection
            .execute(
                "UPDATE events SET sequence = 3, value_json = ?1 WHERE id = ?2",
                params![late_run_json.to_string(), late_run_event_id.to_string()],
            )
            .expect("run creation should move after its dependency");
        let late_dependency = EventEnvelope {
            id: EventId::new(),
            sequence: 2,
            session_id: late_session.id,
            run_id: Some(late_run.id),
            actor_id: ActorId::new(),
            causal_parent: Some(late_session_event_id),
            occurred_at: Utc::now(),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "dependency before creation".to_owned(),
                }],
            },
        };
        late_connection
            .execute(
                "INSERT INTO events (id, session_id, run_id, sequence, value_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    late_dependency.id.to_string(),
                    late_dependency.session_id.to_string(),
                    late_dependency.run_id.map(|id| id.to_string()),
                    late_dependency.sequence,
                    serde_json::to_string(&late_dependency).unwrap()
                ],
            )
            .expect("late-creation dependency should insert");
        drop(late_connection);
        assert!(matches!(
            Store::open(
                &late_database,
                late_directory.path().join("late-run-artifacts")
            ),
            Err(StoreError::IncompatibleSchema { found: 1, .. })
        ));

        let missing_directory = TempDir::new().expect("temporary directory should be created");
        let missing_database = missing_directory.path().join("missing-run-created.sqlite3");
        let (missing_session, missing_run, creation_ids) =
            create_legacy_database(&missing_database, true);
        let (missing_session_event_id, missing_run_event_id) =
            creation_ids.expect("legacy creation events should exist");
        let missing_connection =
            Connection::open(&missing_database).expect("legacy database should open");
        missing_connection
            .execute(
                "DELETE FROM events WHERE id = ?1",
                [missing_run_event_id.to_string()],
            )
            .expect("run creation should be removed");
        let transition = EventEnvelope {
            id: EventId::new(),
            sequence: 2,
            session_id: missing_session.id,
            run_id: Some(missing_run.id),
            actor_id: ActorId::new(),
            causal_parent: Some(missing_session_event_id),
            occurred_at: Utc::now(),
            provenance: provenance(),
            payload: EventPayload::RunStateChanged {
                from: RunState::Queued,
                to: RunState::Running,
            },
        };
        missing_connection
            .execute(
                "INSERT INTO events (id, session_id, run_id, sequence, value_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    transition.id.to_string(),
                    transition.session_id.to_string(),
                    transition.run_id.map(|id| id.to_string()),
                    transition.sequence,
                    serde_json::to_string(&transition).unwrap()
                ],
            )
            .expect("transition without creation should insert");
        drop(missing_connection);
        let migrated = Store::open(
            &missing_database,
            missing_directory.path().join("missing-run-artifacts"),
        )
        .expect("missing run creation should be synthesized before the transition");
        assert_eq!(
            migrated.get_run(missing_run.id).unwrap().unwrap().state,
            RunState::Running
        );
        let events = migrated.events_after(missing_session.id, 0).unwrap().events;
        assert!(matches!(events[1].payload, EventPayload::RunCreated { .. }));
        assert_eq!(events[2].id, transition.id);

        let causal_directory = TempDir::new().expect("temporary directory should be created");
        let causal_database = causal_directory.path().join("self-parent.sqlite3");
        let (causal_session, _, _) = create_legacy_database(&causal_database, true);
        let causal_connection =
            Connection::open(&causal_database).expect("legacy database should open");
        let self_parent_id = EventId::new();
        let self_parent = EventEnvelope {
            id: self_parent_id,
            sequence: 3,
            session_id: causal_session.id,
            run_id: None,
            actor_id: ActorId::new(),
            causal_parent: Some(self_parent_id),
            occurred_at: Utc::now(),
            provenance: provenance(),
            payload: EventPayload::UserInput {
                items: vec![InputItem::Text {
                    text: "self-parent".to_owned(),
                }],
            },
        };
        causal_connection
            .execute(
                "INSERT INTO events (id, session_id, run_id, sequence, value_json)
                 VALUES (?1, ?2, NULL, ?3, ?4)",
                params![
                    self_parent.id.to_string(),
                    self_parent.session_id.to_string(),
                    self_parent.sequence,
                    serde_json::to_string(&self_parent).unwrap()
                ],
            )
            .expect("self-parent fixture should insert");
        drop(causal_connection);
        assert!(matches!(
            Store::open(
                &causal_database,
                causal_directory.path().join("self-parent-artifacts")
            ),
            Err(StoreError::IncompatibleSchema { found: 1, .. })
        ));
    }

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
        let artifact = store
            .put_artifact(b"small reusable artifact", "application/octet-stream")
            .expect("fixture artifact should persist");
        let mut run = run_for(&session);
        run.spec.input = (0..=MAX_EVENT_ARTIFACT_REFS)
            .map(|_| InputItem::Artifact {
                artifact: artifact.clone(),
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

        let mut oversized_reference = artifact;
        oversized_reference.size_bytes = MAX_ARTIFACT_BYTES;
        let mut byte_run = run_for(&session);
        byte_run.spec.input = (0..3)
            .map(|_| InputItem::Artifact {
                artifact: oversized_reference.clone(),
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
            assert!(matches!(
                store.append_event(invalid),
                Err(StoreError::Database(_))
            ));
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

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial flow proves the complete pre-inference failure fence"
    )]
    fn root_planning_failure_binds_exact_claim_cause_artifact_and_failed_transition() {
        let (_directory, mut store, session, run, actor_id, runtime_id, running, artifact, genesis) =
            planner_store();
        let events = store
            .events_for_run_after(run.id, 0)
            .expect("planner history should replay")
            .events;
        let claim_event = events
            .iter()
            .find(|event| matches!(event.payload, EventPayload::RunClaimed(_)))
            .expect("planner fixture should contain its exact claim");
        let EventPayload::RunClaimed(claim) = &claim_event.payload else {
            panic!("claim event should retain its typed payload")
        };
        let failure = RootPlanningFailed {
            claim_event_id: claim_event.id,
            claim_id: claim.claim_id,
            cancellation_generation: 0,
            phase: RootPlanningFailurePhase::ModelDiscovery,
            reason: RootPlanningFailureReason::BackendDiscoveryFailed,
            evidence_artifact: artifact.clone(),
        };
        let failure_provenance = Provenance {
            producer: "root-planning-failure-test".to_owned(),
            backend: Some(run.spec.backend.clone()),
            raw_artifact: Some(artifact.clone()),
        };

        let mut wrong_claim = failure.clone();
        wrong_claim.claim_id = RunClaimId::new();
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(running.id),
                provenance: failure_provenance.clone(),
                payload: EventPayload::RootPlanningFailed(wrong_claim),
            }),
            Err(StoreError::InvalidStateEvent)
        ));

        let mut wrong_classification = failure.clone();
        wrong_classification.phase = RootPlanningFailurePhase::Preflight;
        wrong_classification.reason = RootPlanningFailureReason::BackendDiscoveryFailed;
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(running.id),
                provenance: failure_provenance.clone(),
                payload: EventPayload::RootPlanningFailed(wrong_classification),
            }),
            Err(StoreError::InvalidStateEvent)
        ));

        let other_artifact = fixture_artifact(&store, "different-failure-evidence");
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(running.id),
                provenance: Provenance {
                    raw_artifact: Some(other_artifact),
                    ..failure_provenance.clone()
                },
                payload: EventPayload::RootPlanningFailed(failure.clone()),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(claim_event.id),
                provenance: failure_provenance.clone(),
                payload: EventPayload::RootPlanningFailed(failure.clone()),
            }),
            Err(StoreError::InvalidStateEvent)
        ));

        let failed = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(running.id),
                provenance: failure_provenance,
                payload: EventPayload::RootPlanningFailed(failure),
            })
            .expect("exact typed pre-inference failure should persist");
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(failed.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(prepared_payload(
                    InferenceAttemptId::new(),
                    TokenReservationId::new(),
                    None,
                    &artifact,
                    0,
                    genesis,
                    0,
                )),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(failed.id),
                provenance: provenance(),
                payload: EventPayload::RunStateChanged {
                    from: RunState::Running,
                    to: RunState::Waiting,
                },
            }),
            Err(StoreError::InvalidStateEvent)
        ));

        let renewed_claim = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(failed.id),
                provenance: provenance(),
                payload: EventPayload::RunClaimed(RunClaimed {
                    claim_id: RunClaimId::new(),
                    runtime_instance_id: runtime_id,
                    claim_generation: 2,
                    cancellation_generation: 0,
                    lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
                }),
            })
            .expect("same owner may renew solely to terminalize replay");
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(renewed_claim.id),
                provenance: provenance(),
                payload: EventPayload::RunStateChanged {
                    from: RunState::Running,
                    to: RunState::Failed,
                },
            })
            .expect("Failed remains causally consistent across a replay claim");
        assert_eq!(
            store
                .get_run(run.id)
                .expect("run should load")
                .expect("run should exist")
                .state,
            RunState::Failed
        );
    }

    #[test]
    fn planner_inference_requires_prepared_before_exactly_one_terminal_outcome() {
        let (_directory, mut store, session, run, actor_id, _runtime_id, claim, artifact, genesis) =
            planner_store();
        let attempt_id = InferenceAttemptId::new();
        let reservation_id = TokenReservationId::new();
        let before_prepared = store.append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(claim.id),
            provenance: provenance(),
            payload: EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                attempt_id,
                token_reservation_id: reservation_id,
                prepared_event_id: claim.id,
                normalized_complete_evidence_artifact: artifact.clone(),
                outcome: PlannerInferenceObservation::Failed {
                    error: birdcode_protocol::PlannerInferenceError {
                        kind: birdcode_protocol::PlannerInferenceErrorKind::Transport,
                        retry: RetryDisposition::RequiresNewAttempt,
                    },
                },
            }),
        });
        assert!(matches!(
            before_prepared,
            Err(StoreError::InvalidStateEvent)
        ));

        let prepared = append_prepared(
            &mut store,
            &session,
            &run,
            actor_id,
            claim.id,
            prepared_payload(
                attempt_id,
                reservation_id,
                None,
                &artifact,
                0,
                genesis.clone(),
                0,
            ),
        );
        let observed =
            append_success_observation(&mut store, &session, &run, actor_id, &prepared, &artifact);
        let duplicate_outcome = store.append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(prepared.id),
            provenance: provenance(),
            payload: EventPayload::PlannerInferenceOutcomeUnknown(PlannerInferenceOutcomeUnknown {
                attempt_id,
                token_reservation_id: reservation_id,
                prepared_event_id: prepared.id,
                reason: UnknownInferenceOutcomeReason::EvidenceCommitIndeterminate,
                cancellation_generation: 0,
            }),
        });
        assert!(matches!(
            duplicate_outcome,
            Err(StoreError::InvalidStateEvent)
        ));

        for duplicate in [
            prepared_payload(
                attempt_id,
                TokenReservationId::new(),
                None,
                &artifact,
                0,
                genesis.clone(),
                0,
            ),
            prepared_payload(
                InferenceAttemptId::new(),
                reservation_id,
                None,
                &artifact,
                0,
                genesis.clone(),
                0,
            ),
        ] {
            assert!(matches!(
                store.append_event(NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(observed.id),
                    provenance: provenance(),
                    payload: EventPayload::PlannerInferencePrepared(duplicate),
                }),
                Err(StoreError::InvalidStateEvent)
            ));
        }
        assert_eq!(
            store.events_for_run_after(run.id, 0).unwrap().events.len(),
            5
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial flow verifies claim, cancellation, generation, and run binding"
    )]
    fn planner_claim_cancellation_and_cross_run_generations_fail_closed() {
        let (_directory, mut store, session, run, actor_id, runtime_id, claim, artifact, genesis) =
            planner_store();
        let bad_generation = store.append_event(NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(claim.id),
            provenance: provenance(),
            payload: EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id: runtime_id,
                claim_generation: 3,
                cancellation_generation: 0,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
        });
        assert!(matches!(bad_generation, Err(StoreError::InvalidStateEvent)));

        let cancellation_id = birdcode_protocol::CancellationRequestId::new();
        let cancellation = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(claim.id),
                provenance: provenance(),
                payload: EventPayload::CancellationRequested(CancellationRequested {
                    cancellation_request_id: cancellation_id,
                    cancellation_generation: 1,
                }),
            })
            .expect("first cancellation should persist");
        for request_id in [
            cancellation_id,
            birdcode_protocol::CancellationRequestId::new(),
        ] {
            assert!(matches!(
                store.append_event(NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(cancellation.id),
                    provenance: provenance(),
                    payload: EventPayload::CancellationRequested(CancellationRequested {
                        cancellation_request_id: request_id,
                        cancellation_generation: 2,
                    }),
                }),
                Err(StoreError::InvalidStateEvent)
            ));
        }
        let renewed_claim = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(cancellation.id),
                provenance: provenance(),
                payload: EventPayload::RunClaimed(RunClaimed {
                    claim_id: RunClaimId::new(),
                    runtime_instance_id: runtime_id,
                    claim_generation: 2,
                    cancellation_generation: 1,
                    lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
                }),
            })
            .expect("same owner should renew at the current cancellation generation");
        let wrong_generation = prepared_payload(
            InferenceAttemptId::new(),
            TokenReservationId::new(),
            None,
            &artifact,
            0,
            genesis,
            0,
        );
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(renewed_claim.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(wrong_generation),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        let cancelled_generation = prepared_payload(
            InferenceAttemptId::new(),
            TokenReservationId::new(),
            None,
            &artifact,
            0,
            digest('a'),
            1,
        );
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(renewed_claim.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(cancelled_generation),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        let cancelled = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(renewed_claim.id),
                provenance: provenance(),
                payload: EventPayload::RunStateChanged {
                    from: RunState::Running,
                    to: RunState::Cancelled,
                },
            })
            .expect("the live owner should honor the durable cancellation");

        let second_run = run_for(&session);
        let second_created = store
            .create_run(
                &second_run,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(second_run.id),
                    actor_id,
                    causal_parent: Some(cancelled.id),
                    provenance: provenance(),
                    payload: EventPayload::RunCreated {
                        run: second_run.clone(),
                    },
                },
            )
            .expect("second run should persist");
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(second_run.id),
                actor_id,
                causal_parent: Some(claim.id),
                provenance: provenance(),
                payload: EventPayload::RunClaimed(RunClaimed {
                    claim_id: RunClaimId::new(),
                    runtime_instance_id: RuntimeInstanceId::new(),
                    claim_generation: 1,
                    cancellation_generation: 0,
                    lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
                }),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        assert_eq!(
            store.events_for_run_after(second_run.id, 0).unwrap().events,
            vec![second_created]
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one proposal flow verifies digest binding, single decision, and plan CAS"
    )]
    fn proposal_decisions_are_single_success_bound_plan_cas_operations() {
        let (_directory, mut store, session, run, actor_id, _runtime_id, claim, artifact, genesis) =
            planner_store();
        let attempt_id = InferenceAttemptId::new();
        let prepared = append_prepared(
            &mut store,
            &session,
            &run,
            actor_id,
            claim.id,
            prepared_payload(
                attempt_id,
                TokenReservationId::new(),
                None,
                &artifact,
                0,
                genesis.clone(),
                0,
            ),
        );
        let observed =
            append_success_observation(&mut store, &session, &run, actor_id, &prepared, &artifact);
        let accepted_digest = Sha256Digest::parse(artifact.sha256.clone())
            .expect("accepted plan artifact hash should be canonical");
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(observed.id),
                provenance: provenance(),
                payload: EventPayload::PlanProposalAccepted(PlanProposalAccepted {
                    proposal_id: PlanProposalId::new(),
                    inference_attempt_id: attempt_id,
                    observed_event_id: observed.id,
                    proposal_artifact: artifact.clone(),
                    previous_plan_revision: 0,
                    previous_plan_digest: genesis.clone(),
                    accepted_plan_revision: 1,
                    accepted_plan_digest: digest('9'),
                    accepted_plan_artifact: artifact.clone(),
                    validation_evidence_artifact: artifact.clone(),
                }),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        let accepted = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(observed.id),
                provenance: provenance(),
                payload: EventPayload::PlanProposalAccepted(PlanProposalAccepted {
                    proposal_id: PlanProposalId::new(),
                    inference_attempt_id: attempt_id,
                    observed_event_id: observed.id,
                    proposal_artifact: artifact.clone(),
                    previous_plan_revision: 0,
                    previous_plan_digest: genesis.clone(),
                    accepted_plan_revision: 1,
                    accepted_plan_digest: accepted_digest.clone(),
                    accepted_plan_artifact: artifact.clone(),
                    validation_evidence_artifact: artifact.clone(),
                }),
            })
            .expect("matching proposal should be accepted");
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(observed.id),
                provenance: provenance(),
                payload: EventPayload::PlanProposalRejected(PlanProposalRejected {
                    proposal_id: PlanProposalId::new(),
                    inference_attempt_id: attempt_id,
                    observed_event_id: observed.id,
                    proposal_artifact: artifact.clone(),
                    base_plan_revision: 0,
                    base_plan_digest: genesis.clone(),
                    reason: PlanProposalRejectionReason::StaleBaseRevision,
                    validation_evidence_artifact: artifact.clone(),
                }),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(accepted.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(prepared_payload(
                    InferenceAttemptId::new(),
                    TokenReservationId::new(),
                    None,
                    &artifact,
                    0,
                    genesis,
                    0,
                )),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        let next_attempt = InferenceAttemptId::new();
        append_prepared(
            &mut store,
            &session,
            &run,
            actor_id,
            accepted.id,
            prepared_payload(
                next_attempt,
                TokenReservationId::new(),
                None,
                &artifact,
                1,
                accepted_digest,
                0,
            ),
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the read prepare/observe fixture deliberately shows the full causal record"
    )]
    fn read_operations_are_prepared_first_unique_and_plan_bound() {
        let (_directory, mut store, session, run, actor_id, _runtime_id, claim, artifact, genesis) =
            planner_store();
        let attempt_id = InferenceAttemptId::new();
        let inference = append_prepared(
            &mut store,
            &session,
            &run,
            actor_id,
            claim.id,
            prepared_payload(
                attempt_id,
                TokenReservationId::new(),
                None,
                &artifact,
                0,
                genesis.clone(),
                0,
            ),
        );
        let unknown = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(inference.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferenceOutcomeUnknown(
                    PlannerInferenceOutcomeUnknown {
                        attempt_id,
                        token_reservation_id: match &inference.payload {
                            EventPayload::PlannerInferencePrepared(value) => {
                                value.token_reservation.id
                            }
                            _ => unreachable!(),
                        },
                        prepared_event_id: inference.id,
                        reason: UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
                        cancellation_generation: 0,
                    },
                ),
            })
            .expect("unknown inference should persist");
        let operation_id = ReadOperationId::new();
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(unknown.id),
                provenance: provenance(),
                payload: EventPayload::ReadOperationObserved(ReadOperationObserved {
                    operation_id,
                    prepared_event_id: unknown.id,
                    normalized_complete_evidence_artifact: artifact.clone(),
                    outcome: ReadOperationObservation::Succeeded {
                        bytes_read: 1,
                        entries_read: 0,
                        truncated: false,
                    },
                }),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        let read_prepared = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(unknown.id),
                provenance: provenance(),
                payload: EventPayload::ReadOperationPrepared(ReadOperationPrepared {
                    operation_id,
                    operation: ReadOperation::ReadFile {
                        path: PathBuf::from("/tmp/planner-store/README.md").into(),
                        offset_bytes: 0,
                        max_bytes: 4096,
                    },
                    request_artifact: artifact.clone(),
                    plan_revision: 0,
                    plan_digest: genesis,
                    cancellation_generation: 0,
                }),
            })
            .expect("read prepare should persist");
        let observation = NewEvent {
            session_id: session.id,
            run_id: Some(run.id),
            actor_id,
            causal_parent: Some(read_prepared.id),
            provenance: provenance(),
            payload: EventPayload::ReadOperationObserved(ReadOperationObserved {
                operation_id,
                prepared_event_id: read_prepared.id,
                normalized_complete_evidence_artifact: artifact,
                outcome: ReadOperationObservation::Succeeded {
                    bytes_read: 8,
                    entries_read: 0,
                    truncated: false,
                },
            }),
        };
        store
            .append_event(observation.clone())
            .expect("first read observation should persist");
        assert!(matches!(
            store.append_event(observation),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn planner_nested_artifacts_must_exist_and_match_content() {
        let (_directory, mut store, session, run, actor_id, _runtime_id, claim, artifact, genesis) =
            planner_store();
        let missing = ArtifactRef {
            sha256: "0".repeat(64),
            size_bytes: 4,
            media_type: "application/json".to_owned(),
        };
        let missing_payload = prepared_payload(
            InferenceAttemptId::new(),
            TokenReservationId::new(),
            None,
            &missing,
            0,
            genesis.clone(),
            0,
        );
        assert!(
            store
                .append_event(NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(claim.id),
                    provenance: provenance(),
                    payload: EventPayload::PlannerInferencePrepared(missing_payload),
                })
                .is_err()
        );

        let path = store
            .artifact_path(&artifact.sha256)
            .expect("fixture artifact path should resolve");
        fs::write(
            &path,
            vec![b'x'; usize::try_from(artifact.size_bytes).unwrap()],
        )
        .expect("fixture artifact should be tampered");
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(claim.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(prepared_payload(
                    InferenceAttemptId::new(),
                    TokenReservationId::new(),
                    None,
                    &artifact,
                    0,
                    genesis,
                    0,
                )),
            }),
            Err(StoreError::ArtifactIntegrity)
        ));
    }

    #[test]
    fn planner_owner_operations_require_a_live_claim_lease() {
        let (
            _directory,
            mut store,
            session,
            run,
            actor_id,
            _runtime_id,
            running,
            artifact,
            genesis,
        ) = planner_store();
        let mut claim = store
            .events_for_run_after(run.id, 0)
            .unwrap()
            .events
            .into_iter()
            .find(|event| matches!(event.payload, EventPayload::RunClaimed(_)))
            .expect("planner fixture should contain a claim");
        let EventPayload::RunClaimed(value) = &mut claim.payload else {
            unreachable!()
        };
        value.lease_expires_at = Utc::now() - chrono::Duration::seconds(1);
        store
            .connection
            .execute_batch(
                "DROP TRIGGER events_are_immutable_on_update;
                 DROP TRIGGER events_are_immutable_on_delete;",
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE events SET value_json = ?1 WHERE id = ?2",
                params![serde_json::to_string(&claim).unwrap(), claim.id.to_string()],
            )
            .unwrap();
        store
            .connection
            .execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)
            .unwrap();

        let before = store.events_for_run_after(run.id, 0).unwrap().events.len();
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(running.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(prepared_payload(
                    InferenceAttemptId::new(),
                    TokenReservationId::new(),
                    None,
                    &artifact,
                    0,
                    genesis,
                    0,
                )),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        assert_eq!(
            store.events_for_run_after(run.id, 0).unwrap().events.len(),
            before
        );
    }

    #[test]
    fn planner_attempts_bind_selected_backend_and_reserved_token_ceiling() {
        let (
            _directory,
            mut store,
            session,
            run,
            actor_id,
            _runtime_id,
            running,
            artifact,
            genesis,
        ) = planner_store();
        let mut wrong_backend = prepared_payload(
            InferenceAttemptId::new(),
            TokenReservationId::new(),
            None,
            &artifact,
            0,
            genesis.clone(),
            0,
        );
        wrong_backend.backend_model.backend_id = "different-backend".to_owned();
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(running.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(wrong_backend),
            }),
            Err(StoreError::InvalidStateEvent)
        ));

        let attempt_id = InferenceAttemptId::new();
        let prepared = append_prepared(
            &mut store,
            &session,
            &run,
            actor_id,
            running.id,
            prepared_payload(
                attempt_id,
                TokenReservationId::new(),
                None,
                &artifact,
                0,
                genesis,
                0,
            ),
        );
        let EventPayload::PlannerInferencePrepared(prepared_payload) = &prepared.payload else {
            unreachable!()
        };
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(prepared.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferenceObserved(PlannerInferenceObserved {
                    attempt_id,
                    token_reservation_id: prepared_payload.token_reservation.id,
                    prepared_event_id: prepared.id,
                    normalized_complete_evidence_artifact: artifact,
                    outcome: PlannerInferenceObservation::Succeeded {
                        reported_backend_model: prepared_payload.backend_model.clone(),
                        token_usage: TokenUsage {
                            input_tokens: 65,
                            output_tokens: 64,
                            total_tokens: 129,
                            cached_input_tokens: None,
                        },
                    },
                }),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn terminal_runs_reject_new_claims_cancellations_and_planner_work() {
        let (_directory, mut store, session, run, actor_id, runtime_id, running, artifact, genesis) =
            planner_store();
        let cancellation = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(running.id),
                provenance: provenance(),
                payload: EventPayload::CancellationRequested(CancellationRequested {
                    cancellation_request_id: birdcode_protocol::CancellationRequestId::new(),
                    cancellation_generation: 1,
                }),
            })
            .expect("cancellation should be durable before terminal state");
        let terminal = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(cancellation.id),
                provenance: provenance(),
                payload: EventPayload::RunStateChanged {
                    from: RunState::Running,
                    to: RunState::Cancelled,
                },
            })
            .expect("the still-live original claim may honor cancellation without renewal");
        let before = store.events_for_run_after(run.id, 0).unwrap().events.len();

        let terminal_events = [
            EventPayload::RunClaimed(RunClaimed {
                claim_id: RunClaimId::new(),
                runtime_instance_id: runtime_id,
                claim_generation: 2,
                cancellation_generation: 0,
                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
            }),
            EventPayload::CancellationRequested(CancellationRequested {
                cancellation_request_id: birdcode_protocol::CancellationRequestId::new(),
                cancellation_generation: 1,
            }),
            EventPayload::PlannerInferencePrepared(prepared_payload(
                InferenceAttemptId::new(),
                TokenReservationId::new(),
                None,
                &artifact,
                0,
                genesis.clone(),
                0,
            )),
            EventPayload::ReadOperationPrepared(ReadOperationPrepared {
                operation_id: ReadOperationId::new(),
                operation: ReadOperation::ReadFile {
                    path: PathBuf::from("/tmp/planner-store/README.md").into(),
                    offset_bytes: 0,
                    max_bytes: 4_096,
                },
                request_artifact: artifact,
                plan_revision: 0,
                plan_digest: genesis,
                cancellation_generation: 0,
            }),
        ];
        for payload in terminal_events {
            assert!(matches!(
                store.append_event(NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(terminal.id),
                    provenance: provenance(),
                    payload,
                }),
                Err(StoreError::InvalidStateEvent)
            ));
        }
        assert_eq!(
            store.events_for_run_after(run.id, 0).unwrap().events.len(),
            before
        );
    }

    #[test]
    fn replacement_actor_may_terminalize_latest_durable_inactive_cancellation() {
        let (_directory, mut store) = test_store();
        let requesting_actor = ActorId::new();
        let replacement_actor = ActorId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/replacement-cancellation").into(),
            title: Some("Replacement cancellation owner".to_owned()),
        });
        let session_created = store
            .create_session(&session, session_event(&session, requesting_actor))
            .expect("session should persist");
        let run = run_for(&session);
        let run_created = store
            .create_run(
                &run,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id: requesting_actor,
                    causal_parent: Some(session_created.id),
                    provenance: provenance(),
                    payload: EventPayload::RunCreated { run: run.clone() },
                },
            )
            .expect("queued run should persist");
        let cancellation = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id: requesting_actor,
                causal_parent: Some(run_created.id),
                provenance: provenance(),
                payload: EventPayload::CancellationRequested(CancellationRequested {
                    cancellation_request_id: birdcode_protocol::CancellationRequestId::new(),
                    cancellation_generation: 1,
                }),
            })
            .expect("cancellation should persist before the simulated crash");

        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id: replacement_actor,
                causal_parent: Some(run_created.id),
                provenance: provenance(),
                payload: EventPayload::RunStateChanged {
                    from: RunState::Queued,
                    to: RunState::Cancelled,
                },
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        let terminal = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id: replacement_actor,
                causal_parent: Some(cancellation.id),
                provenance: provenance(),
                payload: EventPayload::RunStateChanged {
                    from: RunState::Queued,
                    to: RunState::Cancelled,
                },
            })
            .expect("durable cancellation should authorize the replacement actor");

        assert_eq!(terminal.causal_parent, Some(cancellation.id));
        assert_eq!(
            store
                .get_run(run.id)
                .unwrap()
                .expect("run should exist")
                .state,
            RunState::Cancelled
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one retry flow proves unknown outcomes consume budget and authority stays immutable"
    )]
    fn unknown_attempts_keep_their_aggregate_run_budget_consumed() {
        let (
            _directory,
            mut store,
            session,
            run,
            actor_id,
            _runtime_id,
            running,
            artifact,
            genesis,
        ) = planner_store_with_output_limit(Some(100));
        let first_attempt = InferenceAttemptId::new();
        let first = append_prepared(
            &mut store,
            &session,
            &run,
            actor_id,
            running.id,
            prepared_payload(
                first_attempt,
                TokenReservationId::new(),
                None,
                &artifact,
                0,
                genesis.clone(),
                0,
            ),
        );
        let EventPayload::PlannerInferencePrepared(first_payload) = &first.payload else {
            unreachable!()
        };
        let unknown = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(first.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferenceOutcomeUnknown(
                    PlannerInferenceOutcomeUnknown {
                        attempt_id: first_attempt,
                        token_reservation_id: first_payload.token_reservation.id,
                        prepared_event_id: first.id,
                        reason: UnknownInferenceOutcomeReason::RuntimeRestartedBeforeObservation,
                        cancellation_generation: 0,
                    },
                ),
            })
            .expect("unknown outcome should retain its reservation");
        let before = store.events_for_run_after(run.id, 0).unwrap().events.len();
        let second_attempt = InferenceAttemptId::new();
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(unknown.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(prepared_payload(
                    second_attempt,
                    TokenReservationId::new(),
                    Some(first_attempt),
                    &artifact,
                    0,
                    genesis.clone(),
                    0,
                )),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        assert_eq!(
            store.events_for_run_after(run.id, 0).unwrap().events.len(),
            before
        );

        let mut authority_mutation = prepared_payload(
            second_attempt,
            TokenReservationId::new(),
            Some(first_attempt),
            &artifact,
            0,
            genesis.clone(),
            0,
        );
        authority_mutation.token_reservation.max_output_tokens = 36;
        authority_mutation.obligation_snapshot_digest = digest('0');
        assert!(matches!(
            store.append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(unknown.id),
                provenance: provenance(),
                payload: EventPayload::PlannerInferencePrepared(authority_mutation),
            }),
            Err(StoreError::InvalidStateEvent)
        ));

        let mut exact_remaining = prepared_payload(
            second_attempt,
            TokenReservationId::new(),
            Some(first_attempt),
            &artifact,
            0,
            genesis,
            0,
        );
        exact_remaining.token_reservation.max_output_tokens = 36;
        append_prepared(
            &mut store,
            &session,
            &run,
            actor_id,
            unknown.id,
            exact_remaining,
        );
    }

    #[test]
    fn concurrent_distinct_reservations_cannot_oversubscribe_one_run() {
        let (directory, store, session, run, actor_id, _runtime_id, running, artifact, genesis) =
            planner_store_with_output_limit(Some(64));
        let database = directory.path().join("state.sqlite3");
        let artifacts = directory.path().join("artifacts");
        drop(store);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                let database = database.clone();
                let artifacts = artifacts.clone();
                let artifact = artifact.clone();
                let genesis = genesis.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(database, artifacts).unwrap();
                    barrier.wait();
                    store
                        .append_event(NewEvent {
                            session_id: session.id,
                            run_id: Some(run.id),
                            actor_id,
                            causal_parent: Some(running.id),
                            provenance: provenance(),
                            payload: EventPayload::PlannerInferencePrepared(prepared_payload(
                                InferenceAttemptId::new(),
                                TokenReservationId::new(),
                                None,
                                &artifact,
                                0,
                                genesis,
                                0,
                            )),
                        })
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|accepted| **accepted).count(), 1);
        let reopened = Store::open(database, artifacts).unwrap();
        let prepared = reopened
            .events_for_run_after(run.id, 0)
            .unwrap()
            .events
            .into_iter()
            .filter(|event| matches!(event.payload, EventPayload::PlannerInferencePrepared(_)))
            .count();
        assert_eq!(prepared, 1);
    }

    #[test]
    fn protocol_v2_persisted_runs_default_to_execute_only_inside_store_decode() {
        let (_directory, mut store) = test_store();
        let actor_id = ActorId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/v2-run-purpose").into(),
            title: None,
        });
        let session_created = store
            .create_session(&session, session_event(&session, actor_id))
            .unwrap();
        let run = run_for(&session);
        let run_created = store
            .create_run(
                &run,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(run.id),
                    actor_id,
                    causal_parent: Some(session_created.id),
                    provenance: provenance(),
                    payload: EventPayload::RunCreated { run: run.clone() },
                },
            )
            .unwrap();
        let mut run_value = serde_json::to_value(&run).unwrap();
        run_value["spec"].as_object_mut().unwrap().remove("purpose");
        assert!(serde_json::from_value::<Run>(run_value.clone()).is_err());
        let mut event_value = serde_json::to_value(&run_created).unwrap();
        event_value["payload"]["data"]["run"]["spec"]
            .as_object_mut()
            .unwrap()
            .remove("purpose");
        store
            .connection
            .execute_batch(
                "DROP TRIGGER events_are_immutable_on_update;
                 DROP TRIGGER events_are_immutable_on_delete;",
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE runs SET value_json = ?1 WHERE id = ?2",
                params![run_value.to_string(), run.id.to_string()],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE events SET value_json = ?1 WHERE id = ?2",
                params![event_value.to_string(), run_created.id.to_string()],
            )
            .unwrap();
        store
            .connection
            .execute_batch(SCHEMA_V2_IMMUTABILITY_TRIGGERS_SQL)
            .unwrap();
        assert_eq!(
            store.get_run(run.id).unwrap().unwrap().spec.purpose,
            RunPurpose::Execute
        );
        let replayed = store.events_for_run_after(run.id, 0).unwrap();
        assert!(matches!(
            &replayed.events[0].payload,
            EventPayload::RunCreated { run } if run.spec.purpose == RunPurpose::Execute
        ));
    }

    #[test]
    fn recovery_queries_are_run_bounded_deterministic_and_survive_reopen() {
        let (directory, mut store) = test_store();
        let actor_id = ActorId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/recovery-page").into(),
            title: None,
        });
        let session_created = store
            .create_session(&session, session_event(&session, actor_id))
            .unwrap();
        let first = run_for(&session);
        let first_created = store
            .create_run(
                &first,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(first.id),
                    actor_id,
                    causal_parent: Some(session_created.id),
                    provenance: provenance(),
                    payload: EventPayload::RunCreated { run: first.clone() },
                },
            )
            .unwrap();
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: None,
                actor_id,
                causal_parent: Some(first_created.id),
                provenance: provenance(),
                payload: EventPayload::UserInput { items: Vec::new() },
            })
            .unwrap();
        let second = run_for(&session);
        let second_created = store
            .create_run(
                &second,
                NewEvent {
                    session_id: session.id,
                    run_id: Some(second.id),
                    actor_id,
                    causal_parent: Some(first_created.id),
                    provenance: provenance(),
                    payload: EventPayload::RunCreated {
                        run: second.clone(),
                    },
                },
            )
            .unwrap();
        let page = store.nonterminal_runs(None).unwrap();
        let mut expected = vec![first.id, second.id];
        expected.sort();
        assert_eq!(
            page.runs.iter().map(|run| run.id).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            store.events_for_run_after(second.id, 0).unwrap().events,
            vec![second_created]
        );
        let database = directory.path().join("state.sqlite3");
        let artifacts = directory.path().join("artifacts");
        drop(store);
        let reopened = Store::open(database, artifacts).unwrap();
        assert_eq!(reopened.nonterminal_runs(None).unwrap().runs.len(), 2);
        assert_eq!(
            reopened.events_for_run_after(first.id, 0).unwrap().events,
            vec![first_created]
        );
    }

    #[test]
    fn nonterminal_recovery_pagination_crosses_its_page_boundary_exactly_once() {
        fn collect(store: &Store) -> (Vec<RunId>, usize) {
            let mut cursor = None;
            let mut ids = Vec::new();
            let mut pages = 0;
            loop {
                let page = store.nonterminal_runs(cursor).unwrap();
                pages += 1;
                for run in &page.runs {
                    if let Some(previous) = ids.last() {
                        assert!(previous < &run.id, "recovery cursor must increase strictly");
                    }
                    ids.push(run.id);
                }
                assert_eq!(page.next_run_id, ids.last().copied());
                cursor = page.next_run_id;
                if !page.has_more {
                    return (ids, pages);
                }
            }
        }

        let (directory, mut store) = test_store();
        let actor_id = ActorId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/recovery-page-boundary").into(),
            title: None,
        });
        let mut causal_parent = Some(
            store
                .create_session(&session, session_event(&session, actor_id))
                .unwrap()
                .id,
        );
        let mut expected = Vec::new();
        for _ in 0..usize::try_from(RUN_RECOVERY_PAGE_SIZE).unwrap() + 3 {
            let run = run_for(&session);
            let created = store
                .create_run(
                    &run,
                    NewEvent {
                        session_id: session.id,
                        run_id: Some(run.id),
                        actor_id,
                        causal_parent,
                        provenance: provenance(),
                        payload: EventPayload::RunCreated { run: run.clone() },
                    },
                )
                .unwrap();
            causal_parent = Some(created.id);
            expected.push(run.id);
        }
        expected.sort_unstable();

        let (ids, pages) = collect(&store);
        assert_eq!(pages, 2);
        assert_eq!(ids, expected);

        let database = directory.path().join("state.sqlite3");
        let artifacts = directory.path().join("artifacts");
        drop(store);
        let reopened = Store::open(database, artifacts).unwrap();
        assert_eq!(collect(&reopened), (expected, 2));
    }

    #[test]
    fn concurrent_connections_commit_exactly_one_claim_and_one_prepared_attempt() {
        let (directory, store, session, run, actor_id, runtime_id, claim, artifact, genesis) =
            planner_store();
        let database = directory.path().join("state.sqlite3");
        let artifacts = directory.path().join("artifacts");
        drop(store);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let claim_handles = (0..2)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                let database = database.clone();
                let artifacts = artifacts.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(database, artifacts).unwrap();
                    barrier.wait();
                    store
                        .append_event(NewEvent {
                            session_id: session.id,
                            run_id: Some(run.id),
                            actor_id,
                            causal_parent: Some(claim.id),
                            provenance: provenance(),
                            payload: EventPayload::RunClaimed(RunClaimed {
                                claim_id: RunClaimId::new(),
                                runtime_instance_id: runtime_id,
                                claim_generation: 2,
                                cancellation_generation: 0,
                                lease_expires_at: Utc::now() + chrono::Duration::minutes(10),
                            }),
                        })
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        let claim_results = claim_handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(claim_results.iter().filter(|result| **result).count(), 1);

        let reopened = Store::open(&database, &artifacts).unwrap();
        let latest_claim = reopened
            .events_for_run_after(run.id, 0)
            .unwrap()
            .events
            .into_iter()
            .rev()
            .find(|event| matches!(event.payload, EventPayload::RunClaimed(_)))
            .unwrap();
        drop(reopened);
        let attempt_id = InferenceAttemptId::new();
        let reservation_id = TokenReservationId::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let prepared_handles = (0..2)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                let database = database.clone();
                let artifacts = artifacts.clone();
                let artifact = artifact.clone();
                let genesis = genesis.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(database, artifacts).unwrap();
                    barrier.wait();
                    store
                        .append_event(NewEvent {
                            session_id: session.id,
                            run_id: Some(run.id),
                            actor_id,
                            causal_parent: Some(latest_claim.id),
                            provenance: provenance(),
                            payload: EventPayload::PlannerInferencePrepared(prepared_payload(
                                attempt_id,
                                reservation_id,
                                None,
                                &artifact,
                                0,
                                genesis,
                                0,
                            )),
                        })
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        let prepared_results = prepared_handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(prepared_results.iter().filter(|result| **result).count(), 1);
    }
}
