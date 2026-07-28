//! Core Store lifecycle, event, budget, recovery-page, and artifact APIs.

use super::{
    ArtifactRef, CURRENT_SCHEMA_VERSION, Cell, Connection, DURABLE_HEALTH_PROBE_INTERVAL, DateTime,
    DeadlineAppendOutcome, EVENT_PAGE_BYTES, EVENT_PAGE_SIZE, EventEnvelope, EventPage,
    EventPayload, IdempotentAppendOutcome, IdentifiedNewEvent, Instant, MAX_INLINE_EVENT_BYTES_U64,
    NewEvent, OptionalExtension, Path, PathBuf, RUN_RECOVERY_PAGE_SIZE, Run, RunId,
    RunModelBudgetProjection, RunRecoveryPage, RunState, Session, SessionId, Store, StoreError,
    TransactionBehavior, Utc, all_model_reserved_output_tokens_for_run, apply_exact_event_envelope,
    decode_canonical_event, decode_run_state, decode_stored_run, fs, incompatible,
    initialize_or_migrate_schema, load_event_by_id, new_event_from_envelope,
    new_run_acceptance_contract_is_valid, params, preallocate_event_envelope,
    preallocate_identified_event_envelope, prepare_private_directory, probe_artifact_root,
    put_artifact_at, read_json, read_verified_artifact, reject_public_store_owned_cleanup_event,
    reject_shared_writable_directory, schema_version, secure_sqlite_family,
    set_private_directory_permissions, set_private_file_permissions, validate_current_schema,
    validate_real_directory,
};

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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let envelope = preallocate_event_envelope(&transaction, event)?;
        if envelope.session_id != session.id
            || envelope.run_id.is_some()
            || !matches!(
                &envelope.payload,
                EventPayload::SessionCreated { session: value } if value == session
            )
        {
            return Err(StoreError::InvalidStateEvent);
        }
        apply_exact_event_envelope(&transaction, &self.artifact_root, &envelope)?;
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let envelope = preallocate_event_envelope(&transaction, event)?;
        if !new_run_acceptance_contract_is_valid(run)
            || envelope.session_id != run.spec.session_id
            || envelope.run_id != Some(run.id)
            || run.state != RunState::Queued
            || !matches!(
                &envelope.payload,
                EventPayload::RunCreated { run: value } if value == run
            )
        {
            return Err(StoreError::InvalidStateEvent);
        }
        apply_exact_event_envelope(&transaction, &self.artifact_root, &envelope)?;
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
        reject_public_store_owned_cleanup_event(&event.payload)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let envelope = preallocate_event_envelope(&transaction, event)?;
        if matches!(
            &envelope.payload,
            EventPayload::SessionCreated { .. } | EventPayload::RunCreated { .. }
        ) {
            return Err(StoreError::InvalidStateEvent);
        }
        apply_exact_event_envelope(&transaction, &self.artifact_root, &envelope)?;
        transaction.commit()?;
        Ok(envelope)
    }

    /// Appends one event under a caller-allocated durable identity.
    ///
    /// A retry returns [`IdempotentAppendOutcome::AlreadyPresent`] only when
    /// every caller-supplied field is byte-equivalent to the committed event's
    /// canonical `NewEvent` projection. Reusing the identity for any other
    /// session, run, actor, parent, provenance, or payload is a conflict. The
    /// lookup, semantic validation, insert, and commit share one immediate
    /// transaction, so concurrent retries cannot both append.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::IdentifiedEventConflict`] when the identity is
    /// already committed for different event fields. Other failures have the
    /// same meaning as [`Self::append_event`].
    pub fn append_identified_event(
        &mut self,
        identified: IdentifiedNewEvent,
    ) -> Result<IdempotentAppendOutcome, StoreError> {
        reject_public_store_owned_cleanup_event(&identified.event.payload)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_event_by_id(&transaction, identified.event_id)? {
            if existing.id != identified.event_id
                || new_event_from_envelope(&existing) != identified.event
            {
                return Err(StoreError::IdentifiedEventConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentAppendOutcome::AlreadyPresent { event: existing });
        }
        if matches!(
            &identified.event.payload,
            EventPayload::SessionCreated { .. } | EventPayload::RunCreated { .. }
        ) {
            return Err(StoreError::InvalidStateEvent);
        }
        let envelope = preallocate_identified_event_envelope(
            &transaction,
            identified.event_id,
            identified.event,
        )?;
        apply_exact_event_envelope(&transaction, &self.artifact_root, &envelope)?;
        transaction.commit()?;
        Ok(IdempotentAppendOutcome::Appended { event: envelope })
    }

    /// Appends one event only when an absolute wall deadline still permits the
    /// transaction to commit.
    ///
    /// The deadline check happens after `BEGIN IMMEDIATE` has acquired the
    /// writer lock and after the event has passed authoritative validation. It
    /// is then repeated at the final boundary immediately before commit, so
    /// time spent waiting for another `SQLite` writer can never produce a late
    /// durable event.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, rollback, or database access fails.
    pub fn append_event_before_deadline(
        &mut self,
        event: NewEvent,
        deadline: DateTime<Utc>,
    ) -> Result<DeadlineAppendOutcome, StoreError> {
        reject_public_store_owned_cleanup_event(&event.payload)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let envelope = preallocate_event_envelope(&transaction, event)?;
        if matches!(
            &envelope.payload,
            EventPayload::SessionCreated { .. } | EventPayload::RunCreated { .. }
        ) {
            return Err(StoreError::InvalidStateEvent);
        }
        apply_exact_event_envelope(&transaction, &self.artifact_root, &envelope)?;
        if deadline <= Utc::now() {
            transaction.rollback()?;
            return Ok(DeadlineAppendOutcome::DeadlineElapsed);
        }
        transaction.commit()?;
        Ok(DeadlineAppendOutcome::Appended)
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

    /// Returns the authoritative aggregate model reservation budget for one
    /// run. Callers must not reconstruct this by scanning selected event
    /// variants because every planner and child reservation participates.
    ///
    /// # Errors
    ///
    /// Returns an error if the run projection is corrupt or reserved output
    /// exceeds the run's declared aggregate ceiling.
    pub fn run_model_budget_projection(
        &self,
        run_id: RunId,
    ) -> Result<Option<RunModelBudgetProjection>, StoreError> {
        let Some(run) = self.get_run(run_id)? else {
            return Ok(None);
        };
        let reserved = all_model_reserved_output_tokens_for_run(
            &self.connection,
            run.spec.session_id,
            run_id,
        )?;
        let aggregate_limit = run.spec.limits.max_output_tokens;
        let remaining = aggregate_limit
            .map(|limit| {
                limit
                    .checked_sub(reserved)
                    .ok_or(StoreError::InvalidStateEvent)
            })
            .transpose()?;
        Ok(Some(RunModelBudgetProjection {
            aggregate_limit,
            reserved,
            remaining,
        }))
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
        put_artifact_at(&self.artifact_root, bytes, media_type.into())
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
}
