//! Store-derived, effect-free preparation for repository snapshot cleanup.
//!
//! A preflight permit proves only that Store observed one exact durable
//! lifecycle and one cleanup boundary while holding a `SQLite` writer lock. It
//! creates no event, artifact, workspace capability, cleanup handoff, or
//! external-effect authority.

use super::{
    MAX_SQLITE_INTEGER_U64, RepositorySnapshotLifecycleReplay, Store, StoreError,
    decode_canonical_event, durable_run_for_claim_refresh, latest_cancellation_for_run_before,
    latest_cancellation_generation, latest_claim_for_run, load_event_by_id,
    read_canonical_json_artifact, replay_repository_snapshot_lifecycle,
};
use birdcode_protocol::{
    ActorId, EventEnvelope, EventId, EventPayload, REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE,
    RepositorySnapshotCleanupBoundaryV1, RepositorySnapshotCleanupGrantId,
    RepositorySnapshotCleanupKindV1, RepositorySnapshotLeaseDocumentV1, RepositorySnapshotLeaseId,
    RepositorySnapshotLocalCleanupId, RepositorySnapshotRecoveryId,
    RepositoryWriterLeaseEvidenceDocumentV1, RunClaimed, RunId, RunPurpose, RuntimeInstanceId,
    SessionId,
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, TransactionBehavior};
use std::collections::BTreeSet;

const INITIAL_CLEANUP_GRANT_GENERATION: u64 = 1;

/// Caller-allocated mechanical identities for a future generation-one cleanup
/// grant and its two durable closure records.
///
/// Every identity must be non-nil and pairwise distinct even across its
/// nominal protocol type. The five future cleanup/closure identities must be
/// absent from the event-identity projection and the closed set of typed
/// snapshot/claim/cleanup identity fields checked by this version. The actor
/// and runtime may reuse an existing, matching principal pair. Store derives
/// every semantic field; these values never select a target, boundary, path,
/// or effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositorySnapshotCleanupPreflightAuthorityV1 {
    pub cleanup_actor_id: ActorId,
    pub cleanup_runtime_instance_id: RuntimeInstanceId,
    pub cleanup_grant_event_id: EventId,
    pub cleanup_grant_id: RepositorySnapshotCleanupGrantId,
    pub recovery_id: RepositorySnapshotRecoveryId,
    pub closure_event_id: EventId,
    pub workspace_finalized_event_id: EventId,
}

/// Store-owned fields common to either cleanup target.
///
/// References borrow the affine permit. This is an inspection view only and
/// cannot authorize a workspace or external effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySnapshotCleanupPreflightCommonViewV1<'a> {
    pub session_id: SessionId,
    pub run_id: RunId,
    pub cleanup_grant_event_id: EventId,
    pub cleanup_grant_id: RepositorySnapshotCleanupGrantId,
    pub cleanup_grant_generation: u64,
    pub recovery_id: RepositorySnapshotRecoveryId,
    pub closure_event_id: EventId,
    pub workspace_finalized_event_id: EventId,
    pub kind: RepositorySnapshotCleanupKindV1,
    pub boundary: &'a RepositorySnapshotCleanupBoundaryV1,
    pub lifecycle_tail_event_id: EventId,
    pub snapshot_id: &'a str,
    pub lease_id: RepositorySnapshotLeaseId,
    pub snapshot_lease_event_id: EventId,
    pub writer_revocation_event_id: EventId,
    pub lifecycle_owner_actor_id: ActorId,
    pub lifecycle_owner_runtime_instance_id: RuntimeInstanceId,
    /// Latest global claim for the run at the Store lock boundary. This may be
    /// newer than the claim retained by an interrupted capture lifecycle.
    pub source_claim_event: &'a EventEnvelope,
    pub source_claim: &'a RunClaimed,
    pub cancellation_generation: u64,
    pub cleanup_actor_id: ActorId,
    pub cleanup_runtime_instance_id: RuntimeInstanceId,
    pub store_checked_at: DateTime<Utc>,
    /// Local cleanup identity is deliberately deferred until Workspace has
    /// retained and locked an exact cleanup candidate.
    pub expected_local_cleanup_id: Option<RepositorySnapshotLocalCleanupId>,
}

/// Exact borrowed target behind a Store preflight permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositorySnapshotCleanupPreflightViewV1<'a> {
    CaptureAbandonment {
        common: RepositorySnapshotCleanupPreflightCommonViewV1<'a>,
        writer_revocation_event: &'a EventEnvelope,
        latest_capture_event: &'a EventEnvelope,
        /// Claim retained by the open capture itself. This can intentionally
        /// differ from `common.source_claim` after a takeover.
        lifecycle_claim_event: &'a EventEnvelope,
        lifecycle_claim: &'a RunClaimed,
        writer_evidence: &'a RepositoryWriterLeaseEvidenceDocumentV1,
    },
    LeaseReleaseReconciliation {
        common: RepositorySnapshotCleanupPreflightCommonViewV1<'a>,
        writer_revocation_event: &'a EventEnvelope,
        lease_event: &'a EventEnvelope,
        writer_evidence: &'a RepositoryWriterLeaseEvidenceDocumentV1,
        lease_document: &'a RepositorySnapshotLeaseDocumentV1,
    },
}

#[derive(Debug, Eq, PartialEq)]
struct RepositorySnapshotCleanupPreflightCommonMaterialV1 {
    session_id: SessionId,
    run_id: RunId,
    cleanup_grant_event_id: EventId,
    cleanup_grant_id: RepositorySnapshotCleanupGrantId,
    recovery_id: RepositorySnapshotRecoveryId,
    closure_event_id: EventId,
    workspace_finalized_event_id: EventId,
    kind: RepositorySnapshotCleanupKindV1,
    boundary: RepositorySnapshotCleanupBoundaryV1,
    lifecycle_tail_event_id: EventId,
    snapshot_id: String,
    lease_id: RepositorySnapshotLeaseId,
    snapshot_lease_event_id: EventId,
    writer_revocation_event_id: EventId,
    lifecycle_owner_actor_id: ActorId,
    lifecycle_owner_runtime_instance_id: RuntimeInstanceId,
    source_claim_event: EventEnvelope,
    source_claim: RunClaimed,
    cancellation_generation: u64,
    cleanup_actor_id: ActorId,
    cleanup_runtime_instance_id: RuntimeInstanceId,
    store_checked_at: DateTime<Utc>,
}

impl RepositorySnapshotCleanupPreflightCommonMaterialV1 {
    fn view(&self) -> RepositorySnapshotCleanupPreflightCommonViewV1<'_> {
        RepositorySnapshotCleanupPreflightCommonViewV1 {
            session_id: self.session_id,
            run_id: self.run_id,
            cleanup_grant_event_id: self.cleanup_grant_event_id,
            cleanup_grant_id: self.cleanup_grant_id,
            cleanup_grant_generation: INITIAL_CLEANUP_GRANT_GENERATION,
            recovery_id: self.recovery_id,
            closure_event_id: self.closure_event_id,
            workspace_finalized_event_id: self.workspace_finalized_event_id,
            kind: self.kind,
            boundary: &self.boundary,
            lifecycle_tail_event_id: self.lifecycle_tail_event_id,
            snapshot_id: &self.snapshot_id,
            lease_id: self.lease_id,
            snapshot_lease_event_id: self.snapshot_lease_event_id,
            writer_revocation_event_id: self.writer_revocation_event_id,
            lifecycle_owner_actor_id: self.lifecycle_owner_actor_id,
            lifecycle_owner_runtime_instance_id: self.lifecycle_owner_runtime_instance_id,
            source_claim_event: &self.source_claim_event,
            source_claim: &self.source_claim,
            cancellation_generation: self.cancellation_generation,
            cleanup_actor_id: self.cleanup_actor_id,
            cleanup_runtime_instance_id: self.cleanup_runtime_instance_id,
            store_checked_at: self.store_checked_at,
            expected_local_cleanup_id: None,
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "the already boxed permit retains complete immutable target documents for exact audit"
)]
#[derive(Debug, Eq, PartialEq)]
enum RepositorySnapshotCleanupPreflightMaterialV1 {
    CaptureAbandonment {
        common: RepositorySnapshotCleanupPreflightCommonMaterialV1,
        writer_revocation_event: EventEnvelope,
        latest_capture_event: EventEnvelope,
        lifecycle_claim_event: EventEnvelope,
        lifecycle_claim: RunClaimed,
        writer_evidence: RepositoryWriterLeaseEvidenceDocumentV1,
    },
    LeaseReleaseReconciliation {
        common: RepositorySnapshotCleanupPreflightCommonMaterialV1,
        writer_revocation_event: EventEnvelope,
        lease_event: EventEnvelope,
        writer_evidence: RepositoryWriterLeaseEvidenceDocumentV1,
        lease_document: RepositorySnapshotLeaseDocumentV1,
    },
}

/// Affine, process-local proof of one effect-free Store preflight.
///
/// The permit has no public constructor, is sealed only after the immediate
/// transaction commits, and deliberately implements neither cloning nor
/// serialization. Durable state may advance after that commit. A future grant
/// issue API must therefore begin a new immediate transaction, fully rederive
/// the lifecycle and boundary, and compare-and-swap every retained identity;
/// this permit alone must never be accepted by an effect API.
///
/// ```compile_fail
/// use birdcode_store::RepositorySnapshotCleanupPreflightPermitV1;
///
/// fn duplicate(value: RepositorySnapshotCleanupPreflightPermitV1) {
///     let _copy = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::RepositorySnapshotCleanupPreflightPermitV1;
///
/// let _forged = RepositorySnapshotCleanupPreflightPermitV1::default();
/// ```
///
/// ```compile_fail
/// use birdcode_store::RepositorySnapshotCleanupPreflightPermitV1;
///
/// fn serialize(value: &RepositorySnapshotCleanupPreflightPermitV1) {
///     let _json = serde_json::to_string(value).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use birdcode_store::RepositorySnapshotCleanupPreflightPermitV1;
///
/// let _decoded: RepositorySnapshotCleanupPreflightPermitV1 =
///     serde_json::from_str("{}").unwrap();
/// ```
#[must_use = "a Store preflight permit must be bound by Workspace or explicitly discarded"]
#[derive(Debug, Eq, PartialEq)]
pub struct RepositorySnapshotCleanupPreflightPermitV1 {
    material: Box<RepositorySnapshotCleanupPreflightMaterialV1>,
}

const _: () = assert!(
    std::mem::size_of::<RepositorySnapshotCleanupPreflightPermitV1>()
        == std::mem::size_of::<usize>()
);

impl RepositorySnapshotCleanupPreflightPermitV1 {
    /// Borrows the complete Store-derived preflight material.
    #[must_use]
    pub fn view(&self) -> RepositorySnapshotCleanupPreflightViewV1<'_> {
        match self.material.as_ref() {
            RepositorySnapshotCleanupPreflightMaterialV1::CaptureAbandonment {
                common,
                writer_revocation_event,
                latest_capture_event,
                lifecycle_claim_event,
                lifecycle_claim,
                writer_evidence,
            } => RepositorySnapshotCleanupPreflightViewV1::CaptureAbandonment {
                common: common.view(),
                writer_revocation_event,
                latest_capture_event,
                lifecycle_claim_event,
                lifecycle_claim,
                writer_evidence,
            },
            RepositorySnapshotCleanupPreflightMaterialV1::LeaseReleaseReconciliation {
                common,
                writer_revocation_event,
                lease_event,
                writer_evidence,
                lease_document,
            } => RepositorySnapshotCleanupPreflightViewV1::LeaseReleaseReconciliation {
                common: common.view(),
                writer_revocation_event,
                lease_event,
                writer_evidence,
                lease_document,
            },
        }
    }
}

/// Typed reason why no cleanup preflight is available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositorySnapshotCleanupPreflightNoAuthorityV1 {
    NoSnapshotLifecycle,
    SnapshotAlreadyClosed {
        kind: RepositorySnapshotCleanupKindV1,
        closure_event_id: EventId,
    },
    BoundaryNotReached {
        source_claim_event_id: EventId,
        claim_lease_expires_at: DateTime<Utc>,
        run_deadline_at: Option<DateTime<Utc>>,
    },
    /// Reserved for the later issue/redeem slice. A generation-one preflight
    /// currently rejects any `PendingCleanup` replay instead of returning this.
    CleanupGrantStillCurrent {
        cleanup_grant_event: EventEnvelope,
        cleanup_grant_generation: u64,
        grant_expires_at: DateTime<Utc>,
    },
    /// Reserved for bounded regrant support. Generation one never emits it.
    CleanupGrantGenerationExhausted {
        cleanup_grant_event: EventEnvelope,
        cleanup_grant_generation: u64,
    },
}

/// Closed result of the effect-free cleanup preparation step.
#[must_use = "the prepared cleanup material or explicit absence must be handled"]
#[allow(
    clippy::large_enum_variant,
    reason = "future no-authority variants retain an exact durable grant envelope for audit"
)]
#[derive(Debug, Eq, PartialEq)]
pub enum RepositorySnapshotCleanupPreflightOutcomeV1 {
    Prepared(RepositorySnapshotCleanupPreflightPermitV1),
    NoAuthority(RepositorySnapshotCleanupPreflightNoAuthorityV1),
}

/// Exact protocol identity columns and JSON fields relevant to snapshot
/// cleanup. This deliberately does not scan arbitrary JSON text: a user prompt
/// that happens to contain a UUID can never become an identity collision.
fn typed_lifecycle_identity_exists(
    connection: &Connection,
    identity: &str,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM events AS event
                 WHERE ?1 IN (
                     event.session_id,
                     event.run_id,
                     json_extract(event.value_json, '$.actor_id'),
                     event.causal_parent,
                     json_extract(event.value_json, '$.payload.data.claim_event_id'),
                     json_extract(event.value_json, '$.payload.data.claim_id'),
                     json_extract(event.value_json, '$.payload.data.runtime_instance_id'),
                     json_extract(event.value_json, '$.payload.data.claim_runtime_instance_id'),
                     json_extract(event.value_json, '$.payload.data.cancellation_request_id'),
                     json_extract(event.value_json, '$.payload.data.capture.lease_id'),
                     json_extract(event.value_json, '$.payload.data.capture.snapshot_lease_event_id'),
                     json_extract(event.value_json, '$.payload.data.snapshot.immutability_lease.lease_id'),
                     json_extract(event.value_json, '$.payload.data.lease_id'),
                     json_extract(event.value_json, '$.payload.data.lease_event_id'),
                     json_extract(event.value_json, '$.payload.data.snapshot_lease_event_id'),
                     json_extract(event.value_json, '$.payload.data.writer_revocation_event_id'),
                     json_extract(event.value_json, '$.payload.data.adoption_id'),
                     json_extract(event.value_json, '$.payload.data.prior_claim_event_id'),
                     json_extract(event.value_json, '$.payload.data.prior_claim_id'),
                     json_extract(event.value_json, '$.payload.data.prior_runtime_instance_id'),
                     json_extract(event.value_json, '$.payload.data.new_claim_event_id'),
                     json_extract(event.value_json, '$.payload.data.new_claim_id'),
                     json_extract(event.value_json, '$.payload.data.new_runtime_instance_id'),
                     json_extract(event.value_json, '$.payload.data.cleanup_grant_event_id'),
                     json_extract(event.value_json, '$.payload.data.cleanup_grant_id'),
                     json_extract(event.value_json, '$.payload.data.recovery_id'),
                     json_extract(event.value_json, '$.payload.data.local_cleanup_id'),
                     json_extract(event.value_json, '$.payload.data.closure_event_id'),
                     json_extract(event.value_json, '$.payload.data.workspace_finalized_event_id'),
                     json_extract(event.value_json, '$.payload.data.finalization_id'),
                     json_extract(event.value_json, '$.payload.data.cleanup_actor_id'),
                     json_extract(event.value_json, '$.payload.data.cleanup_runtime_instance_id'),
                     json_extract(event.value_json, '$.payload.data.lifecycle_owner_actor_id'),
                     json_extract(event.value_json, '$.payload.data.lifecycle_owner_runtime_instance_id'),
                     json_extract(event.value_json, '$.payload.data.source_claim_event_id'),
                     json_extract(event.value_json, '$.payload.data.source_claim_id'),
                     json_extract(event.value_json, '$.payload.data.source_claim_actor_id'),
                     json_extract(event.value_json, '$.payload.data.source_claim_runtime_instance_id')
                 )
                 LIMIT 1
             )",
            [identity],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn runtime_is_bound_to_other_actor(
    connection: &Connection,
    actor_id: ActorId,
    runtime_instance_id: RuntimeInstanceId,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM events
                 WHERE json_extract(value_json, '$.payload.type') = 'run_claimed'
                   AND json_extract(value_json, '$.payload.data.runtime_instance_id') = ?1
                   AND json_extract(value_json, '$.actor_id') != ?2
                 LIMIT 1
             )",
            [runtime_instance_id.to_string(), actor_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn exact_lifecycle_identity_strings(
    run_id: RunId,
    lifecycle: &RepositorySnapshotLifecycleReplay,
    source_claim_event: &EventEnvelope,
    source_claim: &RunClaimed,
) -> Result<BTreeSet<String>, StoreError> {
    let mut exact = BTreeSet::from([
        run_id.to_string(),
        source_claim_event.session_id.to_string(),
        source_claim_event.id.to_string(),
        source_claim.claim_id.to_string(),
    ]);
    let (open, lease_event) = match lifecycle {
        RepositorySnapshotLifecycleReplay::Open(open) => (open, None),
        RepositorySnapshotLifecycleReplay::Active { open, lease_event } => {
            (open, Some(lease_event))
        }
        _ => return Err(StoreError::InvalidStateEvent),
    };
    let identity = open
        .identity
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    exact.extend([
        open.writer_revocation_event.id.to_string(),
        open.writer_revocation.claim_event_id.to_string(),
        open.writer_revocation.claim_id.to_string(),
        open.latest_capture_event.id.to_string(),
        open.active_claim_event.id.to_string(),
        open.active_claim.claim_id.to_string(),
        identity.lease_id.to_string(),
        identity.lease_event_id.to_string(),
    ]);
    if let Some(lease_event) = lease_event {
        exact.insert(lease_event.id.to_string());
    }
    Ok(exact)
}

fn validate_identity_authority(
    connection: &Connection,
    run_id: RunId,
    lifecycle: &RepositorySnapshotLifecycleReplay,
    source_claim_event: &EventEnvelope,
    source_claim: &RunClaimed,
    authority: &RepositorySnapshotCleanupPreflightAuthorityV1,
) -> Result<(), StoreError> {
    let all_authority_identities = [
        authority.cleanup_actor_id.as_uuid(),
        authority.cleanup_runtime_instance_id.as_uuid(),
        authority.cleanup_grant_event_id.as_uuid(),
        authority.cleanup_grant_id.as_uuid(),
        authority.recovery_id.as_uuid(),
        authority.closure_event_id.as_uuid(),
        authority.workspace_finalized_event_id.as_uuid(),
    ];
    if all_authority_identities
        .iter()
        .any(|identity| identity.as_u128() == 0)
        || all_authority_identities
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != all_authority_identities.len()
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if runtime_is_bound_to_other_actor(
        connection,
        authority.cleanup_actor_id,
        authority.cleanup_runtime_instance_id,
    )? {
        return Err(StoreError::InvalidStateEvent);
    }
    let exact =
        exact_lifecycle_identity_strings(run_id, lifecycle, source_claim_event, source_claim)?;
    if exact.contains(&authority.cleanup_actor_id.to_string())
        || exact.contains(&authority.cleanup_runtime_instance_id.to_string())
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let fresh_identities = [
        authority.cleanup_grant_event_id.as_uuid(),
        authority.cleanup_grant_id.as_uuid(),
        authority.recovery_id.as_uuid(),
        authority.closure_event_id.as_uuid(),
        authority.workspace_finalized_event_id.as_uuid(),
    ];
    for identity in fresh_identities {
        let event_identity = EventId::from_uuid(identity);
        let identity = identity.to_string();
        if exact.contains(&identity)
            || load_event_by_id(connection, event_identity)?.is_some()
            || typed_lifecycle_identity_exists(connection, &identity)?
        {
            return Err(StoreError::InvalidStateEvent);
        }
    }
    Ok(())
}

fn store_anchored_run_deadline(
    connection: &Connection,
    run: &birdcode_protocol::Run,
) -> Result<Option<DateTime<Utc>>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT value_json FROM events
         WHERE run_id = ?1 AND session_id = ?2
           AND json_extract(value_json, '$.payload.type') = 'run_created'
         ORDER BY sequence ASC LIMIT 2",
    )?;
    let rows = statement
        .query_map(
            [run.id.to_string(), run.spec.session_id.to_string()],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let [json] = rows.as_slice() else {
        return Err(StoreError::InvalidStateEvent);
    };
    let event = decode_canonical_event(json)?;
    let EventPayload::RunCreated { run: retained_run } = &event.payload else {
        return Err(StoreError::InvalidStateEvent);
    };
    if retained_run != run
        || event.session_id != run.spec.session_id
        || event.run_id != Some(run.id)
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let Some(seconds) = run.spec.limits.max_wall_time_seconds else {
        return Ok(None);
    };
    let seconds = i64::try_from(seconds).map_err(|_| StoreError::InvalidStateEvent)?;
    event
        .occurred_at
        .checked_add_signed(chrono::TimeDelta::seconds(seconds))
        .map(Some)
        .ok_or(StoreError::InvalidStateEvent)
}

fn inactive_lifecycle_reason(
    lifecycle: &RepositorySnapshotLifecycleReplay,
) -> Result<Option<RepositorySnapshotCleanupPreflightNoAuthorityV1>, StoreError> {
    match lifecycle {
        RepositorySnapshotLifecycleReplay::None => Ok(Some(
            RepositorySnapshotCleanupPreflightNoAuthorityV1::NoSnapshotLifecycle,
        )),
        RepositorySnapshotLifecycleReplay::ClosedCapture {
            abandonment_event, ..
        } => Ok(Some(
            RepositorySnapshotCleanupPreflightNoAuthorityV1::SnapshotAlreadyClosed {
                kind: RepositorySnapshotCleanupKindV1::CaptureAbandonment,
                closure_event_id: abandonment_event.id,
            },
        )),
        RepositorySnapshotLifecycleReplay::ClosedLease { closure_event, .. } => Ok(Some(
            RepositorySnapshotCleanupPreflightNoAuthorityV1::SnapshotAlreadyClosed {
                kind: RepositorySnapshotCleanupKindV1::LeaseReleaseReconciliation,
                closure_event_id: closure_event.id,
            },
        )),
        RepositorySnapshotLifecycleReplay::PendingCleanup { .. } => {
            Err(StoreError::InvalidStateEvent)
        }
        RepositorySnapshotLifecycleReplay::Open(_)
        | RepositorySnapshotLifecycleReplay::Active { .. } => Ok(None),
    }
}

fn exact_latest_cancellation(
    connection: &Connection,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<(EventEnvelope, birdcode_protocol::CancellationRequested)>, StoreError> {
    let generation = latest_cancellation_generation(connection, session_id, run_id)?;
    let event =
        latest_cancellation_for_run_before(connection, session_id, run_id, MAX_SQLITE_INTEGER_U64)?;
    match (generation, event) {
        (0, None) => Ok(None),
        (0, Some(_)) | (_, None) => Err(StoreError::InvalidStateEvent),
        (generation, Some(event)) => {
            let EventPayload::CancellationRequested(cancellation) = event.payload.clone() else {
                return Err(StoreError::InvalidStateEvent);
            };
            if cancellation.cancellation_generation != generation {
                return Err(StoreError::InvalidStateEvent);
            }
            Ok(Some((event, cancellation)))
        }
    }
}

fn validate_store_bound_anchors(
    run: &birdcode_protocol::Run,
    lifecycle: &RepositorySnapshotLifecycleReplay,
    source_claim_event: &EventEnvelope,
    source_claim: &RunClaimed,
    cancellation: Option<&(EventEnvelope, birdcode_protocol::CancellationRequested)>,
) -> Result<(), StoreError> {
    if source_claim_event.id.as_uuid().is_nil()
        || source_claim_event.session_id != run.spec.session_id
        || source_claim_event.run_id != Some(run.id)
        || source_claim_event.actor_id.as_uuid().is_nil()
        || source_claim.claim_id.as_uuid().is_nil()
        || source_claim.runtime_instance_id.as_uuid().is_nil()
    {
        return Err(StoreError::InvalidStateEvent);
    }
    if let Some((event, request)) = cancellation
        && (event.id.as_uuid().is_nil()
            || event.session_id != run.spec.session_id
            || event.run_id != Some(run.id)
            || event.actor_id.as_uuid().is_nil()
            || request.cancellation_request_id.as_uuid().is_nil())
    {
        return Err(StoreError::InvalidStateEvent);
    }
    let (open, lease_event) = match lifecycle {
        RepositorySnapshotLifecycleReplay::Open(open) => (open, None),
        RepositorySnapshotLifecycleReplay::Active { open, lease_event } => {
            (open, Some(lease_event))
        }
        _ => return Err(StoreError::InvalidStateEvent),
    };
    let identity = open
        .identity
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    if open.writer_revocation_event.id.as_uuid().is_nil()
        || open.writer_revocation_event.actor_id.as_uuid().is_nil()
        || open.writer_revocation.claim_event_id.as_uuid().is_nil()
        || open.writer_revocation.claim_id.as_uuid().is_nil()
        || open
            .writer_revocation
            .claim_runtime_instance_id
            .as_uuid()
            .is_nil()
        || open.latest_capture_event.id.as_uuid().is_nil()
        || open.active_claim_event.id.as_uuid().is_nil()
        || open.active_claim_event.actor_id.as_uuid().is_nil()
        || open.active_claim.claim_id.as_uuid().is_nil()
        || open.active_claim.runtime_instance_id.as_uuid().is_nil()
        || identity.lease_id.as_uuid().is_nil()
        || identity.lease_event_id.as_uuid().is_nil()
        || lease_event.is_some_and(|event| event.id.as_uuid().is_nil())
    {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(())
}

fn derive_cleanup_boundary(
    cancellation: Option<&(EventEnvelope, birdcode_protocol::CancellationRequested)>,
    run_deadline_at: Option<DateTime<Utc>>,
    source_claim: &RunClaimed,
    checked_at: DateTime<Utc>,
) -> Option<RepositorySnapshotCleanupBoundaryV1> {
    if let Some((event, cancellation)) = cancellation {
        return Some(RepositorySnapshotCleanupBoundaryV1::CancellationRequested {
            cancellation_request_event_id: event.id,
            cancellation_request_id: cancellation.cancellation_request_id,
            cancellation_generation: cancellation.cancellation_generation,
        });
    }
    if run_deadline_at.is_some_and(|deadline| deadline <= checked_at) {
        return Some(RepositorySnapshotCleanupBoundaryV1::RunDeadlineElapsed {
            run_deadline_at: run_deadline_at.expect("elapsed deadline is present"),
        });
    }
    (source_claim.lease_expires_at <= checked_at).then_some(
        RepositorySnapshotCleanupBoundaryV1::PriorClaimExpired {
            claim_lease_expires_at: source_claim.lease_expires_at,
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the constructor binds every independently derived Store authority component"
)]
fn common_material(
    run_id: RunId,
    authority: &RepositorySnapshotCleanupPreflightAuthorityV1,
    kind: RepositorySnapshotCleanupKindV1,
    boundary: RepositorySnapshotCleanupBoundaryV1,
    open: &super::RepositorySnapshotOpenReplay,
    lifecycle_tail_event_id: EventId,
    source_claim_event: EventEnvelope,
    source_claim: RunClaimed,
    cancellation_generation: u64,
    store_checked_at: DateTime<Utc>,
) -> Result<RepositorySnapshotCleanupPreflightCommonMaterialV1, StoreError> {
    let identity = open
        .identity
        .as_ref()
        .ok_or(StoreError::InvalidStateEvent)?;
    Ok(RepositorySnapshotCleanupPreflightCommonMaterialV1 {
        session_id: open.writer_revocation_event.session_id,
        run_id,
        cleanup_grant_event_id: authority.cleanup_grant_event_id,
        cleanup_grant_id: authority.cleanup_grant_id,
        recovery_id: authority.recovery_id,
        closure_event_id: authority.closure_event_id,
        workspace_finalized_event_id: authority.workspace_finalized_event_id,
        kind,
        boundary,
        lifecycle_tail_event_id,
        snapshot_id: identity.snapshot_id.clone(),
        lease_id: identity.lease_id,
        snapshot_lease_event_id: identity.lease_event_id,
        writer_revocation_event_id: open.writer_revocation_event.id,
        lifecycle_owner_actor_id: open.writer_revocation_event.actor_id,
        lifecycle_owner_runtime_instance_id: open.writer_revocation.claim_runtime_instance_id,
        source_claim_event,
        source_claim,
        cancellation_generation,
        cleanup_actor_id: authority.cleanup_actor_id,
        cleanup_runtime_instance_id: authority.cleanup_runtime_instance_id,
        store_checked_at,
    })
}

impl Store {
    /// Prepares one exact generation-one cleanup candidate without creating
    /// durable state or external-effect authority.
    ///
    /// Store acquires `BEGIN IMMEDIATE` before reading its wall clock, replays
    /// the complete bounded snapshot lifecycle, derives the latest global run
    /// claim and boundary, validates all caller-allocated identities, then
    /// commits the read-only transaction before sealing the affine permit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidStateEvent`] for the wrong run purpose,
    /// corrupt or ambiguous history, any existing generation-one pending
    /// cleanup state, or any nil, duplicate, committed, preallocated, or
    /// cross-domain identity collision.
    #[allow(
        clippy::too_many_lines,
        reason = "one immediate transaction keeps lock, replay, boundary, identity, and post-commit sealing visibly contiguous"
    )]
    pub fn prepare_repository_snapshot_cleanup(
        &mut self,
        run_id: RunId,
        authority: RepositorySnapshotCleanupPreflightAuthorityV1,
    ) -> Result<RepositorySnapshotCleanupPreflightOutcomeV1, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let store_checked_at = Utc::now();
        let run = durable_run_for_claim_refresh(&transaction, run_id)?;
        if run.id != run_id
            || run.id.as_uuid().is_nil()
            || run.spec.session_id.as_uuid().is_nil()
            || run.spec.purpose != RunPurpose::ParallelRepositoryReconnaissanceV1
        {
            return Err(StoreError::InvalidStateEvent);
        }
        let lifecycle =
            replay_repository_snapshot_lifecycle(&transaction, &self.artifact_root, &run)?;
        if let Some(reason) = inactive_lifecycle_reason(&lifecycle)? {
            transaction.commit()?;
            return Ok(RepositorySnapshotCleanupPreflightOutcomeV1::NoAuthority(
                reason,
            ));
        }

        let source_claim_event = latest_claim_for_run(&transaction, run.spec.session_id, run.id)?
            .ok_or(StoreError::InvalidStateEvent)?;
        let EventPayload::RunClaimed(source_claim) = source_claim_event.payload.clone() else {
            return Err(StoreError::InvalidStateEvent);
        };
        let cancellation = exact_latest_cancellation(&transaction, run.spec.session_id, run.id)?;
        let cancellation_generation = cancellation
            .as_ref()
            .map_or(0, |(_, cancellation)| cancellation.cancellation_generation);
        validate_store_bound_anchors(
            &run,
            &lifecycle,
            &source_claim_event,
            &source_claim,
            cancellation.as_ref(),
        )?;
        let run_deadline_at = store_anchored_run_deadline(&transaction, &run)?;
        let Some(boundary) = derive_cleanup_boundary(
            cancellation.as_ref(),
            run_deadline_at,
            &source_claim,
            store_checked_at,
        ) else {
            let source_claim_event_id = source_claim_event.id;
            let claim_lease_expires_at = source_claim.lease_expires_at;
            transaction.commit()?;
            return Ok(RepositorySnapshotCleanupPreflightOutcomeV1::NoAuthority(
                RepositorySnapshotCleanupPreflightNoAuthorityV1::BoundaryNotReached {
                    source_claim_event_id,
                    claim_lease_expires_at,
                    run_deadline_at,
                },
            ));
        };

        validate_identity_authority(
            &transaction,
            run_id,
            &lifecycle,
            &source_claim_event,
            &source_claim,
            &authority,
        )?;
        let material = match lifecycle {
            RepositorySnapshotLifecycleReplay::Open(open) => {
                let common = common_material(
                    run_id,
                    &authority,
                    RepositorySnapshotCleanupKindV1::CaptureAbandonment,
                    boundary,
                    &open,
                    open.latest_capture_event.id,
                    source_claim_event,
                    source_claim,
                    cancellation_generation,
                    store_checked_at,
                )?;
                RepositorySnapshotCleanupPreflightMaterialV1::CaptureAbandonment {
                    common,
                    writer_revocation_event: open.writer_revocation_event,
                    latest_capture_event: open.latest_capture_event,
                    lifecycle_claim_event: open.active_claim_event,
                    lifecycle_claim: open.active_claim,
                    writer_evidence: open.writer_evidence,
                }
            }
            RepositorySnapshotLifecycleReplay::Active { open, lease_event } => {
                let EventPayload::RepositorySnapshotLeaseIssued(issued) = &lease_event.payload
                else {
                    return Err(StoreError::InvalidStateEvent);
                };
                let lease_document =
                    read_canonical_json_artifact::<RepositorySnapshotLeaseDocumentV1>(
                        &self.artifact_root,
                        &issued.snapshot.immutability_lease.lease_artifact,
                        REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE,
                    )?;
                let common = common_material(
                    run_id,
                    &authority,
                    RepositorySnapshotCleanupKindV1::LeaseReleaseReconciliation,
                    boundary,
                    &open,
                    lease_event.id,
                    source_claim_event,
                    source_claim,
                    cancellation_generation,
                    store_checked_at,
                )?;
                if common.lifecycle_owner_actor_id
                    != lease_document
                        .macos_read_only_mount
                        .lifecycle_owner_actor_id
                    || common.lifecycle_owner_runtime_instance_id
                        != lease_document
                            .macos_read_only_mount
                            .lifecycle_owner_runtime_instance_id
                {
                    return Err(StoreError::InvalidStateEvent);
                }
                RepositorySnapshotCleanupPreflightMaterialV1::LeaseReleaseReconciliation {
                    common,
                    writer_revocation_event: open.writer_revocation_event,
                    lease_event,
                    writer_evidence: open.writer_evidence,
                    lease_document,
                }
            }
            RepositorySnapshotLifecycleReplay::None
            | RepositorySnapshotLifecycleReplay::ClosedCapture { .. }
            | RepositorySnapshotLifecycleReplay::ClosedLease { .. }
            | RepositorySnapshotLifecycleReplay::PendingCleanup { .. } => {
                return Err(StoreError::InvalidStateEvent);
            }
        };
        transaction.commit()?;
        Ok(RepositorySnapshotCleanupPreflightOutcomeV1::Prepared(
            RepositorySnapshotCleanupPreflightPermitV1 {
                material: Box::new(material),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        REPOSITORY_WRITER_LEASE_EVIDENCE_MEDIA_TYPE, insert_event_in_transaction,
        preallocate_event_envelope,
    };
    use birdcode_protocol::{
        BackendKind, BackendSelection, CancellationRequestId, CancellationRequested,
        CreateSessionRequest, NewEvent, PlanAcceptanceContract, Provenance,
        RepositorySnapshotCaptureIdentityV1, RepositoryWriterLeaseRevokedV1, Run, RunClaimId,
        RunLimits, RunSpec, RunState, RuntimeClockReading, Session, Sha256Digest,
    };
    use chrono::TimeDelta;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct CaptureFixture {
        _directory: TempDir,
        database_path: PathBuf,
        artifact_root: PathBuf,
        store: Store,
        run: Run,
        actor_id: ActorId,
        runtime_instance_id: RuntimeInstanceId,
        claim_event: EventEnvelope,
        writer_event: EventEnvelope,
        tail_event_id: EventId,
        preallocated_lease_event_id: EventId,
    }

    fn provenance() -> Provenance {
        Provenance {
            producer: "cleanup-preflight-test".to_owned(),
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

    fn create_run(
        store: &mut Store,
        session: &Session,
        session_event: &EventEnvelope,
        actor_id: ActorId,
        max_wall_time_seconds: Option<u64>,
        caller_created_at: DateTime<Utc>,
    ) -> (Run, EventEnvelope) {
        let run = Run {
            id: RunId::new(),
            spec: RunSpec {
                session_id: session.id,
                purpose: RunPurpose::ParallelRepositoryReconnaissanceV1,
                plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
                backend: BackendSelection {
                    backend_id: "test".to_owned(),
                    kind: BackendKind::Model,
                    model: None,
                    reasoning_effort: None,
                },
                input: Vec::new(),
                limits: RunLimits {
                    max_output_tokens: None,
                    max_wall_time_seconds,
                    max_subagents: 1,
                },
            },
            state: RunState::Queued,
            created_at: caller_created_at,
        };
        let event = store
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
            .expect("run persists");
        (run, event)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture constructs a complete valid Store capture lifecycle"
    )]
    fn capture_fixture(
        max_wall_time_seconds: Option<u64>,
        caller_created_at: DateTime<Utc>,
    ) -> CaptureFixture {
        let directory = TempDir::new().expect("temporary directory");
        let database_path = directory.path().join("state.sqlite3");
        let artifact_root = directory.path().join("artifacts");
        let mut store = Store::open(&database_path, &artifact_root).expect("store opens");
        let actor_id = ActorId::new();
        let runtime_instance_id = RuntimeInstanceId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/cleanup-preflight-workspace").into(),
            title: Some("cleanup preflight".to_owned()),
        });
        let session_created = store
            .create_session(&session, session_event(&session, actor_id))
            .expect("session persists");
        let (run, run_created) = create_run(
            &mut store,
            &session,
            &session_created,
            actor_id,
            max_wall_time_seconds,
            caller_created_at,
        );
        let claim_event = store
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
                    lease_expires_at: Utc::now() + TimeDelta::hours(1),
                }),
            })
            .expect("claim persists");
        store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(claim_event.id),
                provenance: provenance(),
                payload: EventPayload::RunStateChanged {
                    from: RunState::Queued,
                    to: RunState::Running,
                },
            })
            .expect("run starts");
        let revoked_at = RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos: 1,
            observed_at: Utc::now(),
        };
        let writer_evidence = RepositoryWriterLeaseEvidenceDocumentV1 {
            schema_version: birdcode_protocol::CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            writer_lease_id: "cleanup-preflight-writer".to_owned(),
            writer_lease_generation: 1,
            source_path: session.workspace_root.clone(),
            source_root_identity: birdcode_protocol::RepositoryFileIdentityV1::Unix(
                birdcode_protocol::RepositoryUnixFileIdentityV1 {
                    device: 1,
                    inode: 2,
                    byte_len: 0,
                    modified_seconds: 1,
                    modified_nanoseconds: 0,
                    changed_seconds: 1,
                    changed_nanoseconds: 0,
                },
            ),
            exclusive: true,
            active_writer_count: 0,
            revoked_at,
        };
        let evidence_artifact = store
            .put_artifact(
                &serde_json::to_vec(&writer_evidence).expect("writer evidence encodes"),
                REPOSITORY_WRITER_LEASE_EVIDENCE_MEDIA_TYPE,
            )
            .expect("writer evidence persists");
        let evidence_digest =
            Sha256Digest::parse(evidence_artifact.sha256.clone()).expect("digest is canonical");
        let EventPayload::RunClaimed(claim) = claim_event.payload.clone() else {
            panic!("fixture claim is typed")
        };
        let preallocated_lease_event_id = EventId::new();
        let writer_event = store
            .append_event(NewEvent {
                session_id: session.id,
                run_id: Some(run.id),
                actor_id,
                causal_parent: Some(claim_event.id),
                provenance: Provenance {
                    producer: "cleanup-preflight-writer-revocation".to_owned(),
                    backend: None,
                    raw_artifact: Some(evidence_artifact.clone()),
                },
                payload: EventPayload::RepositoryWriterLeaseRevoked(
                    RepositoryWriterLeaseRevokedV1 {
                        issuer_actor_id: actor_id,
                        claim_event_id: claim_event.id,
                        claim_id: claim.claim_id,
                        claim_generation: claim.claim_generation,
                        claim_runtime_instance_id: runtime_instance_id,
                        cancellation_generation: 0,
                        capture: RepositorySnapshotCaptureIdentityV1 {
                            snapshot_id: "cleanup-preflight-snapshot".to_owned(),
                            lease_id: RepositorySnapshotLeaseId::new(),
                            snapshot_lease_event_id: preallocated_lease_event_id,
                        },
                        evidence_artifact,
                        evidence_digest,
                    },
                ),
            })
            .expect("writer revocation persists");
        CaptureFixture {
            _directory: directory,
            database_path,
            artifact_root,
            store,
            run,
            actor_id,
            runtime_instance_id,
            claim_event,
            writer_event: writer_event.clone(),
            tail_event_id: writer_event.id,
            preallocated_lease_event_id,
        }
    }

    fn authority(fixture: &CaptureFixture) -> RepositorySnapshotCleanupPreflightAuthorityV1 {
        RepositorySnapshotCleanupPreflightAuthorityV1 {
            cleanup_actor_id: fixture.actor_id,
            cleanup_runtime_instance_id: fixture.runtime_instance_id,
            cleanup_grant_event_id: EventId::new(),
            cleanup_grant_id: RepositorySnapshotCleanupGrantId::new(),
            recovery_id: RepositorySnapshotRecoveryId::new(),
            closure_event_id: EventId::new(),
            workspace_finalized_event_id: EventId::new(),
        }
    }

    fn cancel(fixture: &mut CaptureFixture) -> EventEnvelope {
        let event = fixture
            .store
            .append_event(NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: Some(fixture.run.id),
                actor_id: fixture.actor_id,
                causal_parent: Some(fixture.tail_event_id),
                provenance: provenance(),
                payload: EventPayload::CancellationRequested(CancellationRequested {
                    cancellation_request_id: CancellationRequestId::new(),
                    cancellation_generation: 1,
                }),
            })
            .expect("cancellation persists");
        fixture.tail_event_id = event.id;
        event
    }

    fn event_count(store: &Store) -> u64 {
        store
            .connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("event count reads")
    }

    fn artifact_file_count(path: &Path) -> u64 {
        std::fs::read_dir(path)
            .expect("artifact directory reads")
            .map(|entry| entry.expect("artifact entry reads").path())
            .map(|entry| {
                if entry.is_dir() {
                    artifact_file_count(&entry)
                } else {
                    1
                }
            })
            .sum()
    }

    fn durable_counts(store: &Store) -> (u64, u64, u64, u64) {
        let projections = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM event_identity_projection",
                [],
                |row| row.get(0),
            )
            .expect("identity projection count reads");
        (
            event_count(store),
            projections,
            store.connection.total_changes(),
            artifact_file_count(&store.artifact_root),
        )
    }

    #[test]
    fn permit_is_pointer_sized_and_capture_view_is_exact() {
        assert_eq!(
            std::mem::size_of::<RepositorySnapshotCleanupPreflightPermitV1>(),
            std::mem::size_of::<usize>()
        );
        let mut fixture = capture_fixture(None, Utc::now());
        let cancellation = cancel(&mut fixture);
        let issued = authority(&fixture);
        let outcome = fixture
            .store
            .prepare_repository_snapshot_cleanup(fixture.run.id, issued)
            .expect("preflight succeeds");
        let RepositorySnapshotCleanupPreflightOutcomeV1::Prepared(permit) = outcome else {
            panic!("cancellation creates a cleanup boundary")
        };
        let RepositorySnapshotCleanupPreflightViewV1::CaptureAbandonment {
            common,
            writer_revocation_event,
            latest_capture_event,
            lifecycle_claim_event,
            lifecycle_claim,
            writer_evidence,
        } = permit.view()
        else {
            panic!("open lifecycle derives capture abandonment")
        };
        assert_eq!(writer_revocation_event, &fixture.writer_event);
        assert_eq!(latest_capture_event, &fixture.writer_event);
        assert_eq!(lifecycle_claim_event, &fixture.claim_event);
        assert_eq!(common.source_claim_event, &fixture.claim_event);
        assert_eq!(lifecycle_claim, common.source_claim);
        assert_eq!(common.cleanup_grant_event_id, issued.cleanup_grant_event_id);
        assert_eq!(common.cleanup_grant_generation, 1);
        assert_eq!(common.lifecycle_tail_event_id, fixture.writer_event.id);
        assert_eq!(common.expected_local_cleanup_id, None);
        assert_eq!(writer_evidence.writer_lease_id, "cleanup-preflight-writer");
        assert!(matches!(
            common.boundary,
            RepositorySnapshotCleanupBoundaryV1::CancellationRequested {
                cancellation_request_event_id,
                ..
            } if *cancellation_request_event_id == cancellation.id
        ));
    }

    #[test]
    fn active_lease_view_retains_exact_canonical_documents() {
        let mut fixture = crate::tests::default_exact_pair_fixture();
        let cancellation = fixture
            .store
            .append_event(NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: Some(fixture.run.id),
                actor_id: fixture.actor_id,
                causal_parent: Some(fixture.lease_event.id),
                provenance: provenance(),
                payload: EventPayload::CancellationRequested(CancellationRequested {
                    cancellation_request_id: CancellationRequestId::new(),
                    cancellation_generation: 1,
                }),
            })
            .expect("active lease cancellation persists");
        let identity = RepositorySnapshotCleanupPreflightAuthorityV1 {
            cleanup_actor_id: fixture.actor_id,
            cleanup_runtime_instance_id: fixture.runtime_instance_id,
            cleanup_grant_event_id: EventId::new(),
            cleanup_grant_id: RepositorySnapshotCleanupGrantId::new(),
            recovery_id: RepositorySnapshotRecoveryId::new(),
            closure_event_id: EventId::new(),
            workspace_finalized_event_id: EventId::new(),
        };
        let prepared = fixture
            .store
            .prepare_repository_snapshot_cleanup(fixture.run.id, identity)
            .expect("active lifecycle preflight succeeds");
        let RepositorySnapshotCleanupPreflightOutcomeV1::Prepared(active_permit) = prepared else {
            panic!("active cleanup is prepared")
        };
        let RepositorySnapshotCleanupPreflightViewV1::LeaseReleaseReconciliation {
            common,
            writer_revocation_event: viewed_writer,
            lease_event: viewed_lease,
            writer_evidence: viewed_writer_evidence,
            lease_document: viewed_lease_document,
        } = active_permit.view()
        else {
            panic!("active material produces lease view")
        };
        let EventPayload::RepositorySnapshotLeaseIssued(issued) = &fixture.lease_event.payload
        else {
            panic!("fixture lease event is typed")
        };
        let expected_lease_document =
            read_canonical_json_artifact::<RepositorySnapshotLeaseDocumentV1>(
                &fixture.store.artifact_root,
                &issued.snapshot.immutability_lease.lease_artifact,
                REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE,
            )
            .expect("canonical lease reads");
        assert_eq!(
            common.kind,
            RepositorySnapshotCleanupKindV1::LeaseReleaseReconciliation
        );
        assert_eq!(viewed_lease, &fixture.lease_event);
        assert_eq!(viewed_lease_document, &expected_lease_document);
        assert_eq!(
            viewed_writer.id,
            expected_lease_document
                .macos_read_only_mount
                .source_quiescence
                .writer_lease_event_id
        );
        assert_eq!(
            viewed_writer_evidence.writer_lease_id,
            expected_lease_document
                .macos_read_only_mount
                .source_quiescence
                .workspace_writer_lease_id
        );
        assert!(matches!(
            common.boundary,
            RepositorySnapshotCleanupBoundaryV1::CancellationRequested {
                cancellation_request_event_id,
                ..
            } if *cancellation_request_event_id == cancellation.id
        ));
    }

    #[test]
    fn no_lifecycle_and_store_anchored_deadline_are_typed() {
        let directory = TempDir::new().expect("temporary directory");
        let mut store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("store opens");
        let actor_id = ActorId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: PathBuf::from("/tmp/no-cleanup-lifecycle").into(),
            title: None,
        });
        let session_created = store
            .create_session(&session, session_event(&session, actor_id))
            .expect("session persists");
        let (run, _) = create_run(
            &mut store,
            &session,
            &session_created,
            actor_id,
            Some(1),
            Utc::now() - TimeDelta::days(365),
        );
        let outcome = store
            .prepare_repository_snapshot_cleanup(
                run.id,
                RepositorySnapshotCleanupPreflightAuthorityV1 {
                    cleanup_actor_id: actor_id,
                    cleanup_runtime_instance_id: RuntimeInstanceId::new(),
                    cleanup_grant_event_id: EventId::new(),
                    cleanup_grant_id: RepositorySnapshotCleanupGrantId::new(),
                    recovery_id: RepositorySnapshotRecoveryId::new(),
                    closure_event_id: EventId::new(),
                    workspace_finalized_event_id: EventId::new(),
                },
            )
            .expect("empty lifecycle is typed");
        assert!(matches!(
            outcome,
            RepositorySnapshotCleanupPreflightOutcomeV1::NoAuthority(
                RepositorySnapshotCleanupPreflightNoAuthorityV1::NoSnapshotLifecycle
            )
        ));

        let mut capture = capture_fixture(Some(3600), Utc::now() - TimeDelta::days(365));
        let outcome = capture
            .store
            .prepare_repository_snapshot_cleanup(capture.run.id, authority(&capture))
            .expect("preflight reads Store-anchored deadline");
        assert!(matches!(
            outcome,
            RepositorySnapshotCleanupPreflightOutcomeV1::NoAuthority(
                RepositorySnapshotCleanupPreflightNoAuthorityV1::BoundaryNotReached { .. }
            )
        ));
    }

    #[test]
    fn boundary_priority_and_equality_are_closed() {
        let runtime = RuntimeInstanceId::new();
        let checked_at = Utc::now();
        let claim = RunClaimed {
            claim_id: RunClaimId::new(),
            runtime_instance_id: runtime,
            claim_generation: 1,
            cancellation_generation: 0,
            lease_expires_at: checked_at,
        };
        assert!(matches!(
            derive_cleanup_boundary(None, Some(checked_at), &claim, checked_at),
            Some(RepositorySnapshotCleanupBoundaryV1::RunDeadlineElapsed { run_deadline_at })
                if run_deadline_at == checked_at
        ));
        assert!(matches!(
            derive_cleanup_boundary(None, None, &claim, checked_at),
            Some(RepositorySnapshotCleanupBoundaryV1::PriorClaimExpired {
                claim_lease_expires_at
            }) if claim_lease_expires_at == checked_at
        ));
        let cancellation = CancellationRequested {
            cancellation_request_id: CancellationRequestId::new(),
            cancellation_generation: 1,
        };
        let event = EventEnvelope {
            id: EventId::new(),
            sequence: 1,
            session_id: SessionId::new(),
            run_id: Some(RunId::new()),
            actor_id: ActorId::new(),
            causal_parent: None,
            occurred_at: checked_at,
            provenance: provenance(),
            payload: EventPayload::CancellationRequested(cancellation.clone()),
        };
        assert!(matches!(
            derive_cleanup_boundary(
                Some(&(event.clone(), cancellation)),
                Some(checked_at),
                &claim,
                checked_at,
            ),
            Some(RepositorySnapshotCleanupBoundaryV1::CancellationRequested {
                cancellation_request_event_id,
                ..
            }) if cancellation_request_event_id == event.id
        ));
    }

    #[test]
    fn collisions_fail_without_durable_mutation() {
        let mut fixture = capture_fixture(None, Utc::now());
        cancel(&mut fixture);
        let before = event_count(&fixture.store);

        let mut preallocated = authority(&fixture);
        preallocated.closure_event_id = fixture.preallocated_lease_event_id;
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, preallocated),
            Err(StoreError::InvalidStateEvent)
        ));

        let mut committed = authority(&fixture);
        committed.cleanup_grant_event_id = fixture.writer_event.id;
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, committed),
            Err(StoreError::InvalidStateEvent)
        ));

        let mut cross_domain = authority(&fixture);
        cross_domain.cleanup_grant_id =
            RepositorySnapshotCleanupGrantId::from_uuid(fixture.run.id.as_uuid());
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, cross_domain),
            Err(StoreError::InvalidStateEvent)
        ));

        let duplicate_uuid = EventId::new().as_uuid();
        let mut duplicate = authority(&fixture);
        duplicate.cleanup_grant_event_id = EventId::from_uuid(duplicate_uuid);
        duplicate.recovery_id = RepositorySnapshotRecoveryId::from_uuid(duplicate_uuid);
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, duplicate),
            Err(StoreError::InvalidStateEvent)
        ));

        let mut nil = authority(&fixture);
        nil.recovery_id = RepositorySnapshotRecoveryId::from_uuid(uuid::Uuid::nil());
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, nil),
            Err(StoreError::InvalidStateEvent)
        ));

        let mut mismatched_principal = authority(&fixture);
        mismatched_principal.cleanup_actor_id = ActorId::new();
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, mismatched_principal),
            Err(StoreError::InvalidStateEvent)
        ));
        assert_eq!(event_count(&fixture.store), before);
    }

    #[test]
    fn durable_cleanup_finalization_identity_blocks_cross_domain_reuse() {
        let mut fixture = capture_fixture(None, Utc::now());
        cancel(&mut fixture);
        let (finalization_payload, finalization_id) =
            crate::tests::generic_cleanup_v2_payloads(&fixture.store, fixture.run.spec.session_id)
                .into_iter()
                .find_map(|payload| match payload {
                    EventPayload::WorkspaceRecoveryFinalizedV1(finalized) => {
                        let finalization_id = finalized.finalization_id;
                        Some((
                            EventPayload::WorkspaceRecoveryFinalizedV1(finalized),
                            finalization_id,
                        ))
                    }
                    _ => None,
                })
                .expect("fixture contains workspace finalization");
        let transaction = fixture
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("fixture transaction begins");
        let envelope = preallocate_event_envelope(
            &transaction,
            NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: None,
                actor_id: fixture.actor_id,
                causal_parent: Some(fixture.tail_event_id),
                provenance: provenance(),
                payload: finalization_payload,
            },
        )
        .expect("raw finalization preallocates");
        insert_event_in_transaction(&transaction, &envelope)
            .expect("raw finalization identity inserts");
        transaction.commit().expect("raw finalization commits");

        let before = durable_counts(&fixture.store);
        let mut reused = authority(&fixture);
        reused.recovery_id = RepositorySnapshotRecoveryId::from_uuid(finalization_id.as_uuid());
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, reused),
            Err(StoreError::InvalidStateEvent)
        ));
        assert_eq!(durable_counts(&fixture.store), before);
    }

    #[test]
    fn prepared_preflight_has_no_durable_mutation_and_reopens() {
        let mut fixture = capture_fixture(None, Utc::now());
        cancel(&mut fixture);
        let before = durable_counts(&fixture.store);
        let identity = authority(&fixture);
        let outcome = fixture
            .store
            .prepare_repository_snapshot_cleanup(fixture.run.id, identity)
            .expect("preflight succeeds");
        assert!(matches!(
            outcome,
            RepositorySnapshotCleanupPreflightOutcomeV1::Prepared(_)
        ));
        assert_eq!(durable_counts(&fixture.store), before);

        let run_id = fixture.run.id;
        let database_path = fixture.database_path.clone();
        let artifact_root = fixture.artifact_root.clone();
        drop(fixture.store);
        let mut reopened = Store::open(database_path, artifact_root).expect("store reopens");
        let reopened_before = durable_counts(&reopened);
        assert_eq!(reopened_before.0, before.0);
        assert_eq!(reopened_before.1, before.1);
        assert_eq!(reopened_before.3, before.3);
        assert!(matches!(
            reopened
                .prepare_repository_snapshot_cleanup(run_id, identity)
                .expect("same effect-free identity remains uncommitted"),
            RepositorySnapshotCleanupPreflightOutcomeV1::Prepared(_)
        ));
        assert_eq!(durable_counts(&reopened), reopened_before);
    }

    #[test]
    fn latest_global_claim_controls_boundary_and_capture_claim_is_retained() {
        let mut fixture = capture_fixture(None, Utc::now());
        let second_claim = RunClaimed {
            claim_id: RunClaimId::new(),
            runtime_instance_id: fixture.runtime_instance_id,
            claim_generation: 2,
            cancellation_generation: 0,
            lease_expires_at: Utc::now() + TimeDelta::hours(2),
        };
        let transaction = fixture
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("fixture transaction begins");
        let envelope = preallocate_event_envelope(
            &transaction,
            NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: Some(fixture.run.id),
                actor_id: fixture.actor_id,
                causal_parent: Some(fixture.tail_event_id),
                provenance: provenance(),
                payload: EventPayload::RunClaimed(second_claim.clone()),
            },
        )
        .expect("claim envelope preallocates");
        insert_event_in_transaction(&transaction, &envelope).expect("fixture claim inserts");
        transaction.commit().expect("fixture claim commits");
        fixture.tail_event_id = envelope.id;

        let no_boundary = fixture
            .store
            .prepare_repository_snapshot_cleanup(fixture.run.id, authority(&fixture))
            .expect("latest live claim is authoritative");
        assert!(matches!(
            no_boundary,
            RepositorySnapshotCleanupPreflightOutcomeV1::NoAuthority(
                RepositorySnapshotCleanupPreflightNoAuthorityV1::BoundaryNotReached {
                    source_claim_event_id,
                    ..
                }
            ) if source_claim_event_id == envelope.id
        ));

        cancel(&mut fixture);
        let prepared = fixture
            .store
            .prepare_repository_snapshot_cleanup(fixture.run.id, authority(&fixture))
            .expect("cancellation authorizes cleanup");
        let RepositorySnapshotCleanupPreflightOutcomeV1::Prepared(permit) = prepared else {
            panic!("cleanup is prepared")
        };
        let RepositorySnapshotCleanupPreflightViewV1::CaptureAbandonment {
            common,
            lifecycle_claim_event,
            ..
        } = permit.view()
        else {
            panic!("capture view")
        };
        assert_eq!(common.source_claim_event.id, envelope.id);
        assert_eq!(common.source_claim, &second_claim);
        assert_eq!(lifecycle_claim_event.id, fixture.claim_event.id);
    }

    #[test]
    fn closed_lifecycle_reason_is_exact_and_pending_is_fail_closed() {
        let fixture = capture_fixture(None, Utc::now());
        let RepositorySnapshotLifecycleReplay::Open(open) = replay_repository_snapshot_lifecycle(
            &fixture.store.connection,
            &fixture.store.artifact_root,
            &fixture.run,
        )
        .expect("capture replays") else {
            panic!("fixture is open")
        };
        let closure = fixture.writer_event.clone();
        let closed = RepositorySnapshotLifecycleReplay::ClosedCapture {
            open: open.clone(),
            abandonment_event: closure.clone(),
        };
        assert_eq!(
            inactive_lifecycle_reason(&closed).expect("closed is typed"),
            Some(
                RepositorySnapshotCleanupPreflightNoAuthorityV1::SnapshotAlreadyClosed {
                    kind: RepositorySnapshotCleanupKindV1::CaptureAbandonment,
                    closure_event_id: closure.id,
                }
            )
        );
        let pending = RepositorySnapshotLifecycleReplay::PendingCleanup {
            target: super::super::RepositorySnapshotCleanupTargetReplay::Capture { open },
            grants: Vec::new(),
        };
        assert!(matches!(
            inactive_lifecycle_reason(&pending),
            Err(StoreError::InvalidStateEvent)
        ));
    }

    #[test]
    fn durable_pending_cleanup_is_rejected_without_preflight_mutation() {
        let mut fixture = capture_fixture(None, Utc::now());
        let payloads =
            crate::tests::generic_cleanup_v2_payloads(&fixture.store, fixture.run.spec.session_id);
        let grant = payloads
            .into_iter()
            .find(|payload| matches!(payload, EventPayload::RepositorySnapshotCleanupGrantedV1(_)))
            .expect("fixture contains a cleanup grant");
        let transaction = fixture
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("fixture transaction begins");
        let envelope = preallocate_event_envelope(
            &transaction,
            NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: Some(fixture.run.id),
                actor_id: fixture.actor_id,
                causal_parent: Some(fixture.tail_event_id),
                provenance: provenance(),
                payload: grant,
            },
        )
        .expect("raw grant preallocates");
        insert_event_in_transaction(&transaction, &envelope).expect("raw grant inserts");
        transaction.commit().expect("raw grant commits");
        let before = event_count(&fixture.store);
        let result = fixture
            .store
            .prepare_repository_snapshot_cleanup(fixture.run.id, authority(&fixture));
        assert!(matches!(result, Err(StoreError::InvalidStateEvent)));
        assert_eq!(event_count(&fixture.store), before);
    }

    #[test]
    fn raw_nil_latest_claim_anchor_fails_closed() {
        let mut fixture = capture_fixture(None, Utc::now());
        let transaction = fixture
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("fixture transaction begins");
        let envelope = preallocate_event_envelope(
            &transaction,
            NewEvent {
                session_id: fixture.run.spec.session_id,
                run_id: Some(fixture.run.id),
                actor_id: fixture.actor_id,
                causal_parent: Some(fixture.tail_event_id),
                provenance: provenance(),
                payload: EventPayload::RunClaimed(RunClaimed {
                    claim_id: RunClaimId::from_uuid(uuid::Uuid::nil()),
                    runtime_instance_id: fixture.runtime_instance_id,
                    claim_generation: 2,
                    cancellation_generation: 0,
                    lease_expires_at: Utc::now() + TimeDelta::hours(2),
                }),
            },
        )
        .expect("raw nil claim preallocates");
        insert_event_in_transaction(&transaction, &envelope).expect("raw nil claim inserts");
        transaction.commit().expect("raw nil claim commits");
        let before = event_count(&fixture.store);
        assert!(matches!(
            fixture
                .store
                .prepare_repository_snapshot_cleanup(fixture.run.id, authority(&fixture)),
            Err(StoreError::InvalidStateEvent)
        ));
        assert_eq!(event_count(&fixture.store), before);
    }
}
