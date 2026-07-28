use crate::artifact::{ArtifactBoundaryError, RetainedArtifact};
use crate::boundary::{ClockBoundaryError, CommandBoundaryErrorKind};
use crate::journal::{JournalError, JournalRecoveryLock, recovery_disposition};
use crate::manifest::{ManifestError, ManifestObservation};
use crate::platform::{MountPresence, PlatformError};
use crate::plist_decode::AttachPlistError;
use crate::{
    ArtifactBoundary, COMMAND_STDERR_MEDIA_TYPE, COMMAND_STDOUT_MEDIA_TYPE, ClockBoundary,
    CommandBoundary, FileCleanupJournal, PreparedMacOsCommand, RAW_MACOS_PLIST_MEDIA_TYPE,
    RecoveryInspectionV1, RepositoryManifestLimitsV1, RetainedArtifact as Artifact,
    SOURCE_CONTENT_MANIFEST_MEDIA_TYPE, SystemClock, SystemCommandBoundary,
};
use birdcode_protocol::{
    ActorId, ArtifactRef, CHILD_RECONNAISSANCE_CONTRACT_VERSION, EventEnvelope, EventId,
    EventPayload, REPOSITORY_MACOS_ATTACH_EVIDENCE_MEDIA_TYPE,
    REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE, REPOSITORY_SNAPSHOT_MANIFEST_MEDIA_TYPE,
    REPOSITORY_SNAPSHOT_RELEASE_MEDIA_TYPE, REPOSITORY_WRITER_LEASE_EVIDENCE_MEDIA_TYPE,
    RepositoryCommandArgumentV1, RepositoryExternalImageIdentityV1, RepositoryFileHashReceiptV1,
    RepositoryFileIdentityV1, RepositoryMacOsAttachEvidenceV1, RepositoryMacOsCommandReceiptV1,
    RepositoryMacOsDiskImageOperationV1, RepositoryMacOsReadOnlyMountEvidenceV1,
    RepositoryMacOsStatFsReceiptV1, RepositoryRootBindingV1, RepositorySnapshotBindingV1,
    RepositorySnapshotCaptureIdentityV1, RepositorySnapshotCleanupStateV1,
    RepositorySnapshotImageFormatV1, RepositorySnapshotLeaseBindingV1,
    RepositorySnapshotLeaseDocumentV1, RepositorySnapshotLeaseId, RepositorySnapshotLeaseIssuedV1,
    RepositorySnapshotLeaseModeV1, RepositorySnapshotLeaseReleasedV1,
    RepositorySnapshotManifestDocumentV1, RepositorySnapshotReleaseDocumentV1,
    RepositorySourceQuiescenceV1, RepositoryWriterLeaseEvidenceDocumentV1,
    RepositoryWriterLeaseRevokedV1, RunClaimId, RunClaimed, RunId, RuntimeClockReading,
    RuntimeInstanceId, SessionId, Sha256Digest,
};
use birdcode_store::{
    ParallelReconSnapshotClaimHandoffV1, ParallelReconSnapshotClaimHandoffViewV1,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

mod snapshot_acquisition;
mod snapshot_release;

const MAX_IDENTIFIER_BYTES: usize = 128;
const PARALLEL_RECON_CLAIM_REFRESH_PRODUCER: &str =
    "birdcode-store-parallel-recon-claim-refresh-v1";

#[derive(Debug, Eq, PartialEq)]
struct SnapshotRuntimeAuthorityV1 {
    session_id: SessionId,
    run_id: RunId,
    issuer_actor_id: ActorId,
    claim_event_id: EventId,
    claim_id: RunClaimId,
    claim_generation: u64,
    claim_runtime_instance_id: RuntimeInstanceId,
    cancellation_generation: u64,
    claim_sequence: Option<u64>,
    claim_occurred_at: Option<DateTime<Utc>>,
    claim_lease_expires_at: Option<DateTime<Utc>>,
}

impl SnapshotRuntimeAuthorityV1 {
    /// Constructs snapshot authority only from one exact durable `RunClaimed`
    /// envelope. The retained sequence and lease are later used to prove that
    /// every consuming typestate rebind is ordered and gap-free.
    ///
    /// # Errors
    ///
    /// Rejects an envelope with the wrong payload or scope, invalid identities,
    /// a zero generation/sequence, unexpected backend/raw provenance, or an
    /// already expired claim at its own durable event boundary.
    fn from_claim_event(event: &EventEnvelope) -> Result<Self, WorkspaceManagerError> {
        let Some(run_id) = event.run_id else {
            return Err(WorkspaceManagerError::InvalidClaimEnvelope);
        };
        let EventPayload::RunClaimed(claim) = &event.payload else {
            return Err(WorkspaceManagerError::InvalidClaimEnvelope);
        };
        if event.sequence == 0
            || event.session_id.as_uuid().is_nil()
            || run_id.as_uuid().is_nil()
            || event.actor_id.as_uuid().is_nil()
            || event.id.as_uuid().is_nil()
            || event
                .causal_parent
                .is_none_or(|parent| parent.as_uuid().is_nil() || parent == event.id)
            || event.provenance.producer.is_empty()
            || event.provenance.backend.is_some()
            || event.provenance.raw_artifact.is_some()
            || claim.claim_id.as_uuid().is_nil()
            || claim.runtime_instance_id.as_uuid().is_nil()
            || claim.claim_generation == 0
            || claim.lease_expires_at <= event.occurred_at
        {
            return Err(WorkspaceManagerError::InvalidClaimEnvelope);
        }
        Ok(Self::from_claim(event, run_id, claim))
    }

    fn from_claim(event: &EventEnvelope, run_id: RunId, claim: &RunClaimed) -> Self {
        Self {
            session_id: event.session_id,
            run_id,
            issuer_actor_id: event.actor_id,
            claim_event_id: event.id,
            claim_id: claim.claim_id,
            claim_generation: claim.claim_generation,
            claim_runtime_instance_id: claim.runtime_instance_id,
            cancellation_generation: claim.cancellation_generation,
            claim_sequence: Some(event.sequence),
            claim_occurred_at: Some(event.occurred_at),
            claim_lease_expires_at: Some(claim.lease_expires_at),
        }
    }
}

#[derive(Debug)]
struct SnapshotClaimCursor {
    current: SnapshotRuntimeAuthorityV1,
    current_claim_event: EventEnvelope,
    capture_tail_event_id: Option<EventId>,
    capture_tail_sequence: Option<u64>,
    capture_clock: Option<RuntimeClockReading>,
}

impl SnapshotClaimCursor {
    fn from_claim_event(
        current_claim_event: &EventEnvelope,
    ) -> Result<Self, WorkspaceManagerError> {
        let current = SnapshotRuntimeAuthorityV1::from_claim_event(current_claim_event)?;
        Ok(Self {
            current,
            current_claim_event: current_claim_event.clone(),
            capture_tail_event_id: None,
            capture_tail_sequence: None,
            capture_clock: None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRequestV1 {
    pub writer_revocation_event_id: EventId,
    pub snapshot_lease_event_id: EventId,
    pub snapshot_lease_id: RepositorySnapshotLeaseId,
    pub snapshot_id: String,
    pub repository_root_id: String,
    pub workspace_writer_lease_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotReleaseRequestV1 {
    pub release_event_id: EventId,
    /// Store-derived parent: the lease event or latest terminal child event.
    pub causal_parent_event_id: EventId,
}

#[derive(Clone, Debug)]
pub struct WorkspaceManagerConfig {
    pub source_path: PathBuf,
    pub state_root: PathBuf,
    pub manifest_limits: RepositoryManifestLimitsV1,
}

impl WorkspaceManagerConfig {
    #[must_use]
    pub fn new(source_path: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self {
            source_path: source_path.into(),
            state_root: state_root.into(),
            manifest_limits: RepositoryManifestLimitsV1::default(),
        }
    }
}

#[derive(Default)]
struct WriterGate {
    generation: u64,
    active_writers: u32,
    revoked: bool,
}

pub struct WorkspaceWriterPermit {
    gate: Arc<Mutex<WriterGate>>,
    generation: u64,
    released: bool,
}

impl WorkspaceWriterPermit {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut gate) = self.gate.lock() {
            gate.active_writers = gate.active_writers.saturating_sub(1);
        }
        self.released = true;
    }
}

impl Drop for WorkspaceWriterPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

pub struct WorkspaceManager {
    pub(crate) source_path: PathBuf,
    pub(crate) images_root: PathBuf,
    pub(crate) mounts_root: PathBuf,
    pub(crate) manifest_limits: RepositoryManifestLimitsV1,
    pub(crate) command: Arc<dyn CommandBoundary>,
    pub(crate) artifacts: Arc<dyn ArtifactBoundary>,
    clock: Arc<dyn ClockBoundary>,
    pub(crate) journal: FileCleanupJournal,
    gate: Arc<Mutex<WriterGate>>,
}

impl WorkspaceManager {
    /// Opens the production macOS adapter with system command and clock
    /// boundaries and deterministic in-memory artifact bundles.
    ///
    /// # Errors
    ///
    /// Fails typably on unsupported platforms, unsafe roots or corrupt recovery
    /// state.
    pub fn open_system(config: WorkspaceManagerConfig) -> Result<Self, WorkspaceManagerError> {
        Self::open_with_boundaries(
            config,
            Arc::new(SystemCommandBoundary),
            Arc::new(crate::CanonicalArtifactBoundary),
            Arc::new(SystemClock::new()),
        )
    }

    /// Opens the adapter with injectable command/artifact/clock boundaries.
    ///
    /// # Errors
    ///
    /// Applies the same root and recovery validation as [`Self::open_system`].
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the macOS branch consumes config ownership while unsupported targets reject it"
    )]
    pub fn open_with_boundaries(
        config: WorkspaceManagerConfig,
        command: Arc<dyn CommandBoundary>,
        artifacts: Arc<dyn ArtifactBoundary>,
        clock: Arc<dyn ClockBoundary>,
    ) -> Result<Self, WorkspaceManagerError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (config, command, artifacts, clock);
            return Err(WorkspaceManagerError::UnsupportedPlatform);
        }
        #[cfg(target_os = "macos")]
        {
            let source_path = canonical_directory(&config.source_path, false)?;
            let state_root = canonical_directory(&config.state_root, true)?;
            if state_root.starts_with(&source_path) || source_path.starts_with(&state_root) {
                return Err(WorkspaceManagerError::OverlappingRoots);
            }
            let images_root = canonical_directory(&state_root.join("images"), true)?;
            let mounts_root = canonical_directory(&state_root.join("mounts"), true)?;
            let journal = FileCleanupJournal::open(state_root.join("journal"))?;
            let records = journal.load_all()?;
            let revoked = records.iter().any(|record| {
                matches!(
                    record.stage,
                    crate::CleanupStageV1::WriterRevoked
                        | crate::CleanupStageV1::CreatePrepared
                        | crate::CleanupStageV1::CreateOutcomeUnknown
                )
            });
            Ok(Self {
                source_path,
                images_root,
                mounts_root,
                manifest_limits: config.manifest_limits,
                command,
                artifacts,
                clock,
                journal,
                gate: Arc::new(Mutex::new(WriterGate {
                    revoked,
                    ..WriterGate::default()
                })),
            })
        }
    }

    /// Acquires cooperative authority to mutate the managed source.
    ///
    /// # Errors
    ///
    /// Fails while a snapshot capture has revoked writers.
    pub fn acquire_writer(&self) -> Result<WorkspaceWriterPermit, WorkspaceManagerError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| WorkspaceManagerError::StateUnavailable)?;
        if gate.revoked {
            return Err(WorkspaceManagerError::WritersRevoked);
        }
        gate.active_writers = gate
            .active_writers
            .checked_add(1)
            .ok_or(WorkspaceManagerError::WriterCountOverflow)?;
        Ok(WorkspaceWriterPermit {
            gate: Arc::clone(&self.gate),
            generation: gate.generation,
            released: false,
        })
    }

    /// Rebinds a snapshot that has not yet revoked writers to the exact next
    /// durable claim. Since no external effect exists yet, an expired-owner
    /// takeover is permitted; a live owner can only continue gap-free.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, skipped-generation or live-owner-substituted
    /// claim envelopes and cursors recovered without historical claim proof.
    pub fn rebind_prepared_snapshot_claim(
        &self,
        mut prepared: PreparedSnapshot,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<PreparedSnapshot, WorkspaceManagerError> {
        let rebound = resolve_pre_capture_rebind(
            &prepared.claim_cursor,
            &claim_handoff,
            ClaimTransitionPolicy::AllowExpiredTakeover,
        )?;
        drop(claim_handoff);
        if let Some((next, current_claim)) = rebound {
            prepared.claim_cursor.current = next;
            prepared.claim_cursor.current_claim_event = current_claim;
        }
        Ok(prepared)
    }

    /// Rebinds pre-commit writer evidence to one gap-free renewal. A takeover
    /// cannot relabel the already observed revocation clock or local journal.
    ///
    /// # Errors
    ///
    /// Rejects any claim except the exact next same-actor, same-runtime claim
    /// whose event occurs before the prior lease expires.
    pub fn rebind_writer_revocation_claim(
        &self,
        mut bundle: WriterRevocationBundle,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<WriterRevocationBundle, WorkspaceManagerError> {
        let rebound = resolve_pre_capture_rebind(
            &bundle.prepared.claim_cursor,
            &claim_handoff,
            ClaimTransitionPolicy::SameOwnerOnly,
        )?;
        drop(claim_handoff);
        let Some((next, current_claim)) = rebound else {
            return Ok(bundle);
        };
        if bundle.revoked_at.runtime_instance_id != next.claim_runtime_instance_id {
            return Err(WorkspaceManagerError::InvalidClaimTransition);
        }
        let next_occurred_at = next
            .claim_occurred_at
            .ok_or(WorkspaceManagerError::InvalidClaimTransition)?;
        if bundle.revoked_at.observed_at > next_occurred_at {
            return Err(WorkspaceManagerError::InvalidClaimTransition);
        }
        apply_authority_to_writer_bundle(&mut bundle, next, current_claim);
        Ok(bundle)
    }

    /// Adopts a committed writer revocation under Store's exact capture event.
    ///
    /// # Errors
    ///
    /// Rejects any claim/adoption envelope, identity, clock or parent mismatch.
    pub fn adopt_committed_writer_revocation_claim(
        &self,
        mut committed: CommittedWriterRevocation,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<CommittedWriterRevocation, WorkspaceManagerError> {
        apply_capture_adoption_handoff(&mut committed.bundle, &claim_handoff)?;
        drop(claim_handoff);
        Ok(committed)
    }

    /// Adopts a create-prepared capture under Store's exact capture event.
    ///
    /// # Errors
    ///
    /// Rejects any claim/adoption envelope, identity, clock or parent mismatch.
    pub fn adopt_capture_prepared_claim(
        &self,
        mut prepared: CapturePrepared,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<CapturePrepared, WorkspaceManagerError> {
        apply_capture_adoption_handoff(&mut prepared.writer, &claim_handoff)?;
        drop(claim_handoff);
        Ok(prepared)
    }

    /// Adopts a captured image under Store's exact capture event.
    ///
    /// # Errors
    ///
    /// Rejects adoption predating capture completion or any exact binding.
    pub fn adopt_captured_image_claim(
        &self,
        mut captured: CapturedImage,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<CapturedImage, WorkspaceManagerError> {
        apply_capture_adoption_handoff(&mut captured.writer, &claim_handoff)?;
        drop(claim_handoff);
        Ok(captured)
    }

    /// Adopts an attach-prepared image under Store's exact capture event.
    ///
    /// # Errors
    ///
    /// Rejects adoption predating capture completion or any exact binding.
    pub fn adopt_snapshot_attach_prepared_claim(
        &self,
        mut prepared: SnapshotAttachPrepared,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<SnapshotAttachPrepared, WorkspaceManagerError> {
        apply_capture_adoption_handoff(&mut prepared.captured.writer, &claim_handoff)?;
        drop(claim_handoff);
        Ok(prepared)
    }

    /// Rebinds a completed attach bundle before its durable lease event is
    /// committed. The retained lease document has no claim ID/generation, so
    /// only the claim-bearing lease payload is rewritten.
    ///
    /// # Errors
    ///
    /// Rejects adoption predating the latest attach observation or any exact
    /// claim, capture, clock, identity or parent binding.
    pub fn adopt_snapshot_lease_bundle_claim(
        &self,
        mut bundle: SnapshotLeaseBundle,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<SnapshotLeaseBundle, WorkspaceManagerError> {
        apply_capture_adoption_handoff(&mut bundle.prepared.writer, &claim_handoff)?;
        drop(claim_handoff);
        apply_authority_to_lease_payload(
            &mut bundle.payload,
            &bundle.prepared.writer.prepared.claim_cursor.current,
        );
        Ok(bundle)
    }

    /// Rebinds an active lease before any detach command is prepared.
    ///
    /// # Errors
    ///
    /// Rejects malformed or non-next claims and live-lease owner substitution.
    pub fn rebind_active_snapshot_release_claim(
        &self,
        mut active: ActiveSnapshotLease,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<ActiveSnapshotLease, WorkspaceManagerError> {
        rebind_active_lease_cursor(&mut active, &claim_handoff)?;
        drop(claim_handoff);
        Ok(active)
    }

    /// Binds fully attested restart state to Store's current active-lease claim.
    ///
    /// Recovery deliberately returns no claim authority. The complete durable
    /// lease envelope in the Store-issued handoff must exactly equal the lease
    /// that recovery attested before this method creates an active typestate.
    ///
    /// # Errors
    ///
    /// Rejects the wrong handoff variant, a substituted lease envelope, an
    /// invalid current claim, or a previous/current claim pair outside the
    /// recovered lease's session and run.
    pub fn bind_recovered_snapshot_lease(
        &self,
        recovered: crate::recovery::RecoveredSnapshotLease,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<ActiveSnapshotLease, WorkspaceManagerError> {
        let (lease_event, previous_claim, current_claim) = match claim_handoff.view() {
            ParallelReconSnapshotClaimHandoffViewV1::ActiveLease {
                lease_event,
                previous_claim,
                current_claim,
            } => (lease_event, previous_claim, current_claim),
            ParallelReconSnapshotClaimHandoffViewV1::PreCapture { .. }
            | ParallelReconSnapshotClaimHandoffViewV1::CaptureAdoption { .. } => {
                return Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff);
            }
        };
        if lease_event != &recovered.lease_event {
            return Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff);
        }
        let claim_cursor = match previous_claim {
            Some(previous_claim) => {
                let previous_cursor = SnapshotClaimCursor::from_claim_event(previous_claim)?;
                validate_next_claim(
                    &previous_cursor,
                    previous_claim,
                    current_claim,
                    ClaimTransitionPolicy::AllowExpiredTakeover,
                )?;
                SnapshotClaimCursor::from_claim_event(current_claim)?
            }
            None => SnapshotClaimCursor::from_claim_event(current_claim)?,
        };
        validate_active_lease_claim_scope(lease_event, &claim_cursor.current)?;
        drop(claim_handoff);
        Ok(ActiveSnapshotLease {
            snapshot: recovered.snapshot,
            root: recovered.root,
            mount_path: recovered.mount_path,
            image_path: recovered.image_path,
            unmounted_root_identity: recovered.unmounted_root_identity,
            expected_image: recovered.expected_image,
            lease_event: recovered.lease_event,
            claim_cursor,
            record: recovered.record,
        })
    }

    /// Rebinds a prepared but not yet executed detach to the exact next claim.
    ///
    /// # Errors
    ///
    /// Rejects malformed or non-next claims and live-lease owner substitution.
    pub fn rebind_snapshot_release_prepared_claim(
        &self,
        mut prepared: SnapshotReleasePrepared,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<SnapshotReleasePrepared, WorkspaceManagerError> {
        rebind_active_lease_cursor(&mut prepared.active, &claim_handoff)?;
        drop(claim_handoff);
        Ok(prepared)
    }

    /// Rejects relabeling a completed detach under a later claim.
    ///
    /// A detach receipt predates the proposed claim, while the current Store
    /// contract does not prove that ordering. Recovery reconciliation must
    /// therefore attest the completed side effect instead of rebinding it.
    ///
    /// # Errors
    ///
    /// Always returns [`WorkspaceManagerError::ReleaseRequiresRecovery`].
    pub fn rebind_snapshot_release_bundle_claim(
        &self,
        _bundle: SnapshotReleaseBundle,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<SnapshotReleaseBundle, WorkspaceManagerError> {
        let result = match claim_handoff.view() {
            ParallelReconSnapshotClaimHandoffViewV1::ActiveLease { .. } => {
                Err(WorkspaceManagerError::ReleaseRequiresRecovery)
            }
            ParallelReconSnapshotClaimHandoffViewV1::PreCapture { .. }
            | ParallelReconSnapshotClaimHandoffViewV1::CaptureAdoption { .. } => {
                Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff)
            }
        };
        drop(claim_handoff);
        result
    }

    pub(crate) fn now(
        &self,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<RuntimeClockReading, WorkspaceManagerError> {
        let reading = self.clock.now(runtime_instance_id)?;
        if reading.runtime_instance_id != runtime_instance_id {
            return Err(WorkspaceManagerError::ClockRuntimeMismatch);
        }
        Ok(reading)
    }

    pub(crate) fn retain(
        &self,
        media_type: &'static str,
        bytes: Vec<u8>,
    ) -> Result<RetainedArtifact, WorkspaceManagerError> {
        let artifact = self.artifacts.retain(media_type, bytes)?;
        artifact.verify(media_type)?;
        Ok(artifact)
    }

    fn retain_json<T: Serialize>(
        &self,
        media_type: &'static str,
        value: &T,
    ) -> Result<RetainedArtifact, WorkspaceManagerError> {
        let bytes = serde_json::to_vec(value).map_err(|_| WorkspaceManagerError::Encoding)?;
        self.retain(media_type, bytes)
    }

    pub(crate) fn resume_writers(&self) -> Result<(), WorkspaceManagerError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| WorkspaceManagerError::StateUnavailable)?;
        gate.revoked = false;
        Ok(())
    }

    pub(crate) fn reconcile_writer_gate_from_journal_locked(
        &self,
        recovery_lock: &JournalRecoveryLock<'_>,
    ) -> Result<(), WorkspaceManagerError> {
        self.reconcile_writer_gate_from_records(&recovery_lock.load_all_locked()?)
    }

    fn reconcile_writer_gate_from_records(
        &self,
        records: &[crate::CleanupJournalRecordV1],
    ) -> Result<(), WorkspaceManagerError> {
        let revoked = records.iter().any(|record| {
            matches!(
                record.stage,
                crate::CleanupStageV1::WriterRevoked
                    | crate::CleanupStageV1::CreatePrepared
                    | crate::CleanupStageV1::CreateOutcomeUnknown
            )
        });
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| WorkspaceManagerError::StateUnavailable)?;
        gate.revoked = revoked;
        Ok(())
    }

    /// Loads strict, checksummed recovery state without claiming an effect
    /// outcome. In particular, prepared create/attach/detach phases remain
    /// explicitly unknown.
    ///
    /// # Errors
    ///
    /// Rejects any corrupt or non-canonical recovery record.
    pub fn recovery_inspections(&self) -> Result<Vec<RecoveryInspectionV1>, WorkspaceManagerError> {
        Self::recovery_inspections_from_records(self.journal.load_all()?)
    }

    pub(crate) fn recovery_inspections_locked(
        recovery_lock: &JournalRecoveryLock<'_>,
    ) -> Result<Vec<RecoveryInspectionV1>, WorkspaceManagerError> {
        Self::recovery_inspections_from_records(recovery_lock.load_all_locked()?)
    }

    fn recovery_inspections_from_records(
        records: Vec<crate::CleanupJournalRecordV1>,
    ) -> Result<Vec<RecoveryInspectionV1>, WorkspaceManagerError> {
        records
            .into_iter()
            .map(|record| {
                let disposition = recovery_disposition(record.stage);
                Ok(RecoveryInspectionV1 {
                    record,
                    disposition,
                })
            })
            .collect()
    }

    /// Reconciles an exact snapshot of the local cleanup journal without ever
    /// blindly repeating a prepared or outcome-unknown disk-image effect.
    ///
    /// # Errors
    ///
    /// Rejects stale/substituted inspections, unsafe paths, invalid durable
    /// lease evidence, or filesystem state that cannot be safely observed.
    pub fn recover_inspections(
        &self,
        request: crate::WorkspaceRecoveryRequestV1,
    ) -> Result<crate::WorkspaceRecoveryReportV1, crate::WorkspaceRecoveryError> {
        crate::recovery::execute(self, request)
    }
}

#[derive(Debug)]
pub struct PreparedSnapshot {
    claim_cursor: SnapshotClaimCursor,
    request: SnapshotRequestV1,
    source_path: PathBuf,
    image_path: PathBuf,
    mount_path: PathBuf,
}

#[derive(Debug)]
pub struct WriterRevocationBundle {
    pub event_id: EventId,
    pub payload: RepositoryWriterLeaseRevokedV1,
    pub evidence: Artifact,
    pub source_manifest_artifact: Artifact,
    prepared: PreparedSnapshot,
    source_before: ManifestObservation,
    revoked_at: RuntimeClockReading,
    writer_generation: u64,
    record: crate::CleanupJournalRecordV1,
}

pub struct CommittedWriterRevocation {
    bundle: WriterRevocationBundle,
}

pub struct CapturePrepared {
    writer: WriterRevocationBundle,
    pub command: PreparedMacOsCommand,
    record: crate::CleanupJournalRecordV1,
}

#[derive(Debug)]
pub struct CapturedImage {
    writer: WriterRevocationBundle,
    pub create_receipt: RepositoryMacOsCommandReceiptV1,
    pub create_stdout: Artifact,
    pub create_stderr: Artifact,
    pub image: RepositoryExternalImageIdentityV1,
    pub image_hash_receipt: RepositoryFileHashReceiptV1,
    source_after: ManifestObservation,
    pub source_after_artifact: Artifact,
    capture_completed_at: RuntimeClockReading,
    record: crate::CleanupJournalRecordV1,
}

pub struct SnapshotAttachPrepared {
    captured: CapturedImage,
    pub command: PreparedMacOsCommand,
    unmounted_root_identity: RepositoryFileIdentityV1,
    record: crate::CleanupJournalRecordV1,
}

#[derive(Debug)]
pub struct SnapshotLeaseBundle {
    pub event_id: EventId,
    pub payload: RepositorySnapshotLeaseIssuedV1,
    pub lease_document: RepositorySnapshotLeaseDocumentV1,
    pub lease: Artifact,
    pub attach_evidence: Artifact,
    pub raw_attach_plist: Artifact,
    pub attach_stderr: Artifact,
    pub snapshot_manifest: Artifact,
    pub mounted_content_manifest: Artifact,
    unmounted_root_identity: RepositoryFileIdentityV1,
    prepared: CapturedImage,
    record: crate::CleanupJournalRecordV1,
}

pub struct CommittedSnapshotLease {
    bundle: SnapshotLeaseBundle,
    lease_event: EventEnvelope,
}

#[derive(Debug)]
pub struct ActiveSnapshotLease {
    snapshot: RepositorySnapshotBindingV1,
    root: RepositoryRootBindingV1,
    mount_path: PathBuf,
    image_path: PathBuf,
    unmounted_root_identity: RepositoryFileIdentityV1,
    expected_image: RepositoryExternalImageIdentityV1,
    lease_event: EventEnvelope,
    claim_cursor: SnapshotClaimCursor,
    record: crate::CleanupJournalRecordV1,
}

impl ActiveSnapshotLease {
    #[must_use]
    pub fn snapshot(&self) -> &RepositorySnapshotBindingV1 {
        &self.snapshot
    }

    #[must_use]
    pub fn root(&self) -> &RepositoryRootBindingV1 {
        &self.root
    }

    #[must_use]
    pub fn mount_path(&self) -> &Path {
        &self.mount_path
    }
}

pub struct SnapshotReleasePrepared {
    active: ActiveSnapshotLease,
    request: SnapshotReleaseRequestV1,
    pub command: PreparedMacOsCommand,
    record: crate::CleanupJournalRecordV1,
}

#[derive(Debug)]
pub struct SnapshotReleaseBundle {
    pub event_id: EventId,
    pub payload: RepositorySnapshotLeaseReleasedV1,
    pub release_document: RepositorySnapshotReleaseDocumentV1,
    pub release: Artifact,
    pub detach_stdout: Artifact,
    pub detach_stderr: Artifact,
    image_path: PathBuf,
    mount_path: PathBuf,
    unmounted_root_identity: RepositoryFileIdentityV1,
    expected_image: RepositoryExternalImageIdentityV1,
    claim_cursor: SnapshotClaimCursor,
    causal_parent_event_id: EventId,
    lease_id: RepositorySnapshotLeaseId,
}

#[derive(Debug, Error)]
pub enum WorkspaceManagerError {
    #[error("workspace snapshot adapter is supported only on macOS")]
    UnsupportedPlatform,
    #[error("source and workspace-manager state roots must not overlap")]
    OverlappingRoots,
    #[error("workspace root is not a safe canonical directory")]
    UnsafeRoot,
    #[error("snapshot authority or caller-preallocated identifier is invalid")]
    InvalidRequest,
    #[error("durable run-claim envelope is invalid")]
    InvalidClaimEnvelope,
    #[error("snapshot claim transition is stale, discontinuous, or unauthorized")]
    InvalidClaimTransition,
    #[error("snapshot capture adoption does not exactly bind the open typestate")]
    InvalidCaptureAdoption,
    #[error("Store-issued snapshot claim handoff has the wrong lifecycle capability")]
    InvalidSnapshotClaimHandoff,
    #[error("post-detach claim takeover requires snapshot recovery reconciliation")]
    ReleaseRequiresRecovery,
    #[error("writer and snapshot event IDs must be distinct")]
    DuplicateDurableEventId,
    #[error("snapshot lease ID already has local recovery state")]
    DuplicateSnapshotLeaseId,
    #[error("snapshot image path already exists")]
    ImageAlreadyExists,
    #[error("snapshot mount path already exists")]
    MountPathAlreadyExists,
    #[error("workspace writer gate is revoked")]
    WritersRevoked,
    #[error("cannot revoke {actual} active cooperative writers")]
    ActiveWriters { actual: u32 },
    #[error("cooperative writer count overflow")]
    WriterCountOverflow,
    #[error("cooperative writer generation overflow")]
    WriterGenerationOverflow,
    #[error("workspace manager state lock is unavailable")]
    StateUnavailable,
    #[error("committed durable event does not exactly match the prepared payload")]
    CommittedEventMismatch,
    #[error("clock returned a different runtime instance")]
    ClockRuntimeMismatch,
    #[error("clock monotonic observation moved backwards")]
    ClockMovedBackwards,
    #[error("canonical JSON encoding failed")]
    Encoding,
    #[error("source changed during cooperative image capture")]
    SourceChangedDuringCapture {
        before: Sha256Digest,
        after: Sha256Digest,
    },
    #[error("mount directory identity changed before attach or cleanup")]
    MountDirectoryChanged,
    #[error("snapshot image identity changed before cleanup")]
    ImageChangedBeforeCleanup,
    #[error("mounted repository content differs from the post-capture source manifest")]
    MountedManifestMismatch {
        source_digest: Sha256Digest,
        mounted_digest: Sha256Digest,
    },
    #[error("detach completed but a separate mount observation did not prove unmounted state")]
    UnmountNotVerified { presence: MountPresence },
    #[error("macOS command returned a nonzero exit code")]
    CommandFailed {
        receipt: Box<RepositoryMacOsCommandReceiptV1>,
        stdout: Box<RetainedArtifact>,
        stderr: Box<RetainedArtifact>,
    },
    #[error(transparent)]
    CommandBoundary(#[from] crate::CommandBoundaryError),
    #[error(transparent)]
    ArtifactBoundary(#[from] ArtifactBoundaryError),
    #[error(transparent)]
    ClockBoundary(#[from] ClockBoundaryError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    AttachPlist(#[from] AttachPlistError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("workspace filesystem operation failed (os error {raw_os_error:?})")]
    Io { raw_os_error: Option<i32> },
}

impl WorkspaceManagerError {
    #[allow(
        clippy::needless_pass_by_value,
        reason = "map_err supplies owned std I/O errors at each filesystem boundary"
    )]
    fn io(error: std::io::Error) -> Self {
        Self::Io {
            raw_os_error: error.raw_os_error(),
        }
    }
}

#[derive(Clone, Copy)]
enum ClaimTransitionPolicy {
    SameOwnerOnly,
    AllowExpiredTakeover,
}

fn resolve_pre_capture_rebind(
    cursor: &SnapshotClaimCursor,
    claim_handoff: &ParallelReconSnapshotClaimHandoffV1,
    policy: ClaimTransitionPolicy,
) -> Result<Option<(SnapshotRuntimeAuthorityV1, EventEnvelope)>, WorkspaceManagerError> {
    match claim_handoff.view() {
        ParallelReconSnapshotClaimHandoffViewV1::PreCapture {
            previous_claim: Some(previous_claim),
            current_claim,
        } => Ok(Some((
            validate_next_claim(cursor, previous_claim, current_claim, policy)?,
            current_claim.clone(),
        ))),
        ParallelReconSnapshotClaimHandoffViewV1::PreCapture {
            previous_claim: None,
            current_claim,
        } if current_claim == &cursor.current_claim_event => Ok(None),
        ParallelReconSnapshotClaimHandoffViewV1::PreCapture { .. }
        | ParallelReconSnapshotClaimHandoffViewV1::CaptureAdoption { .. }
        | ParallelReconSnapshotClaimHandoffViewV1::ActiveLease { .. } => {
            Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff)
        }
    }
}

fn apply_capture_adoption_handoff(
    writer: &mut WriterRevocationBundle,
    claim_handoff: &ParallelReconSnapshotClaimHandoffV1,
) -> Result<(), WorkspaceManagerError> {
    match claim_handoff.view() {
        ParallelReconSnapshotClaimHandoffViewV1::CaptureAdoption {
            previous_claim,
            current_claim,
            adoption,
        } => apply_capture_adoption(writer, previous_claim, current_claim, adoption),
        ParallelReconSnapshotClaimHandoffViewV1::PreCapture { .. }
        | ParallelReconSnapshotClaimHandoffViewV1::ActiveLease { .. } => {
            Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff)
        }
    }
}

fn rebind_active_lease_cursor(
    active: &mut ActiveSnapshotLease,
    claim_handoff: &ParallelReconSnapshotClaimHandoffV1,
) -> Result<(), WorkspaceManagerError> {
    let (lease_event, previous_claim, current_claim) = match claim_handoff.view() {
        ParallelReconSnapshotClaimHandoffViewV1::ActiveLease {
            lease_event,
            previous_claim,
            current_claim,
        } => (lease_event, previous_claim, current_claim),
        ParallelReconSnapshotClaimHandoffViewV1::PreCapture { .. }
        | ParallelReconSnapshotClaimHandoffViewV1::CaptureAdoption { .. } => {
            return Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff);
        }
    };
    if lease_event != &active.lease_event {
        return Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff);
    }
    match previous_claim {
        Some(previous_claim) => {
            let next = validate_next_claim(
                &active.claim_cursor,
                previous_claim,
                current_claim,
                ClaimTransitionPolicy::AllowExpiredTakeover,
            )?;
            active.claim_cursor.current = next;
            active.claim_cursor.current_claim_event = current_claim.clone();
        }
        None if current_claim == &active.claim_cursor.current_claim_event => {}
        None => return Err(WorkspaceManagerError::InvalidClaimTransition),
    }
    validate_active_lease_claim_scope(lease_event, &active.claim_cursor.current)?;
    Ok(())
}

fn validate_active_lease_claim_scope(
    lease_event: &EventEnvelope,
    authority: &SnapshotRuntimeAuthorityV1,
) -> Result<(), WorkspaceManagerError> {
    let EventPayload::RepositorySnapshotLeaseIssued(lease) = &lease_event.payload else {
        return Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff);
    };
    if lease_event.session_id != authority.session_id
        || lease_event.run_id != Some(authority.run_id)
        || lease_event.actor_id != lease.issuer_actor_id
        || lease_event.causal_parent != Some(lease.claim_event_id)
        || lease_event.provenance.backend.is_some()
        || lease_event.provenance.raw_artifact.is_none()
        || lease
            .snapshot
            .immutability_lease
            .lease_id
            .as_uuid()
            .is_nil()
        || lease.snapshot.snapshot_id.is_empty()
        || lease.root.repository_root_id.is_empty()
    {
        return Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff);
    }
    Ok(())
}

fn validate_next_claim(
    cursor: &SnapshotClaimCursor,
    previous_claim_event: &EventEnvelope,
    event: &EventEnvelope,
    policy: ClaimTransitionPolicy,
) -> Result<SnapshotRuntimeAuthorityV1, WorkspaceManagerError> {
    if previous_claim_event != &cursor.current_claim_event {
        return Err(WorkspaceManagerError::InvalidClaimTransition);
    }
    let prior = &cursor.current;
    let prior_sequence = prior
        .claim_sequence
        .ok_or(WorkspaceManagerError::InvalidClaimTransition)?;
    let prior_occurred_at = prior
        .claim_occurred_at
        .ok_or(WorkspaceManagerError::InvalidClaimTransition)?;
    let prior_lease_expires_at = prior
        .claim_lease_expires_at
        .ok_or(WorkspaceManagerError::InvalidClaimTransition)?;
    let next = SnapshotRuntimeAuthorityV1::from_claim_event(event)?;
    let next_sequence = next
        .claim_sequence
        .ok_or(WorkspaceManagerError::InvalidClaimTransition)?;
    let next_occurred_at = next
        .claim_occurred_at
        .ok_or(WorkspaceManagerError::InvalidClaimTransition)?;
    let next_generation = prior
        .claim_generation
        .checked_add(1)
        .ok_or(WorkspaceManagerError::InvalidClaimTransition)?;
    if next.session_id != prior.session_id
        || next.run_id != prior.run_id
        || next.claim_generation != next_generation
        || next.cancellation_generation != prior.cancellation_generation
        || next.claim_event_id == prior.claim_event_id
        || next.claim_id == prior.claim_id
        || next_sequence <= prior_sequence
        || next_occurred_at < prior_occurred_at
    {
        return Err(WorkspaceManagerError::InvalidClaimTransition);
    }

    let same_actor = next.issuer_actor_id == prior.issuer_actor_id;
    let same_runtime = next.claim_runtime_instance_id == prior.claim_runtime_instance_id;
    if same_runtime && !same_actor {
        return Err(WorkspaceManagerError::InvalidClaimTransition);
    }
    match policy {
        ClaimTransitionPolicy::SameOwnerOnly
            if !same_actor || !same_runtime || prior_lease_expires_at <= next_occurred_at =>
        {
            return Err(WorkspaceManagerError::InvalidClaimTransition);
        }
        ClaimTransitionPolicy::AllowExpiredTakeover
            if prior_lease_expires_at > next_occurred_at && (!same_actor || !same_runtime) =>
        {
            return Err(WorkspaceManagerError::InvalidClaimTransition);
        }
        _ => {}
    }
    Ok(next)
}

fn apply_authority_to_writer_bundle(
    bundle: &mut WriterRevocationBundle,
    authority: SnapshotRuntimeAuthorityV1,
    current_claim_event: EventEnvelope,
) {
    bundle.prepared.claim_cursor.current = authority;
    bundle.prepared.claim_cursor.current_claim_event = current_claim_event;
    let authority = &bundle.prepared.claim_cursor.current;
    bundle.payload.issuer_actor_id = authority.issuer_actor_id;
    bundle.payload.claim_event_id = authority.claim_event_id;
    bundle.payload.claim_id = authority.claim_id;
    bundle.payload.claim_generation = authority.claim_generation;
    bundle.payload.claim_runtime_instance_id = authority.claim_runtime_instance_id;
    bundle.payload.cancellation_generation = authority.cancellation_generation;
}

fn apply_authority_to_lease_payload(
    payload: &mut RepositorySnapshotLeaseIssuedV1,
    authority: &SnapshotRuntimeAuthorityV1,
) {
    payload.issuer_actor_id = authority.issuer_actor_id;
    payload.claim_event_id = authority.claim_event_id;
    payload.claim_id = authority.claim_id;
    payload.claim_generation = authority.claim_generation;
    payload.claim_runtime_instance_id = authority.claim_runtime_instance_id;
    payload.cancellation_generation = authority.cancellation_generation;
}

#[allow(
    clippy::too_many_lines,
    reason = "the open-capture adoption is one closed verification gate over every durable binding"
)]
fn apply_capture_adoption(
    writer: &mut WriterRevocationBundle,
    previous_claim_event: &EventEnvelope,
    current_claim_event: &EventEnvelope,
    adoption_event: &EventEnvelope,
) -> Result<(), WorkspaceManagerError> {
    let cursor = &writer.prepared.claim_cursor;
    let prior = &cursor.current;
    let next = validate_next_claim(
        cursor,
        previous_claim_event,
        current_claim_event,
        ClaimTransitionPolicy::SameOwnerOnly,
    )?;
    let EventPayload::RepositorySnapshotCaptureClaimAdoptedV1(adopted) = &adoption_event.payload
    else {
        return Err(WorkspaceManagerError::InvalidCaptureAdoption);
    };
    let Some(capture_tail_event_id) = cursor.capture_tail_event_id else {
        return Err(WorkspaceManagerError::InvalidCaptureAdoption);
    };
    let Some(capture_tail_sequence) = cursor.capture_tail_sequence else {
        return Err(WorkspaceManagerError::InvalidCaptureAdoption);
    };
    let Some(prior_capture_clock) = cursor.capture_clock.as_ref() else {
        return Err(WorkspaceManagerError::InvalidCaptureAdoption);
    };
    let Some(prior_lease_expires_at) = prior.claim_lease_expires_at else {
        return Err(WorkspaceManagerError::InvalidCaptureAdoption);
    };
    let next_claim_occurred_at = next
        .claim_occurred_at
        .ok_or(WorkspaceManagerError::InvalidCaptureAdoption)?;
    let next_claim_lease_expires_at = next
        .claim_lease_expires_at
        .ok_or(WorkspaceManagerError::InvalidCaptureAdoption)?;
    let request = &writer.prepared.request;
    if previous_claim_event != &cursor.current_claim_event
        || adoption_event.id.as_uuid().is_nil()
        || adopted.adoption_id.as_uuid().is_nil()
        || current_claim_event.sequence <= capture_tail_sequence
        || adoption_event.sequence != current_claim_event.sequence.checked_add(1).unwrap_or(0)
        || adoption_event.session_id != prior.session_id
        || adoption_event.run_id != Some(prior.run_id)
        || adoption_event.actor_id != prior.issuer_actor_id
        || adoption_event.causal_parent != Some(capture_tail_event_id)
        || adoption_event.provenance.producer != PARALLEL_RECON_CLAIM_REFRESH_PRODUCER
        || adoption_event.provenance.backend.is_some()
        || adoption_event.provenance.raw_artifact.is_some()
        || current_claim_event.actor_id != prior.issuer_actor_id
        || prior.issuer_actor_id != next.issuer_actor_id
        || prior.claim_runtime_instance_id != next.claim_runtime_instance_id
        || prior.cancellation_generation != next.cancellation_generation
        || prior_lease_expires_at <= adoption_event.occurred_at
        || next_claim_lease_expires_at <= adoption_event.occurred_at
        || adopted.issuer_actor_id != prior.issuer_actor_id
        || adopted.snapshot_id != request.snapshot_id
        || adopted.lease_id != request.snapshot_lease_id
        || adopted.snapshot_lease_event_id != request.snapshot_lease_event_id
        || adopted.workspace_writer_lease_id != request.workspace_writer_lease_id
        || adopted.writer_lease_generation != writer.writer_generation
        || adopted.writer_revocation_event_id != request.writer_revocation_event_id
        || adopted.prior_claim_event_id != prior.claim_event_id
        || adopted.prior_claim_id != prior.claim_id
        || adopted.prior_claim_generation != prior.claim_generation
        || adopted.prior_runtime_instance_id != prior.claim_runtime_instance_id
        || adopted.new_claim_event_id != next.claim_event_id
        || adopted.new_claim_id != next.claim_id
        || adopted.new_claim_generation != next.claim_generation
        || adopted.new_runtime_instance_id != next.claim_runtime_instance_id
        || adopted.cancellation_generation != next.cancellation_generation
        || adopted.adopted_at.runtime_instance_id != next.claim_runtime_instance_id
        || adopted.adopted_at.monotonic_nanos == 0
        || prior_capture_clock.runtime_instance_id != adopted.adopted_at.runtime_instance_id
        || prior_capture_clock.monotonic_nanos > adopted.adopted_at.monotonic_nanos
        || prior_capture_clock.observed_at > adopted.adopted_at.observed_at
        || adopted.adopted_at.observed_at > next_claim_occurred_at
        || next_claim_occurred_at > adoption_event.occurred_at
    {
        return Err(WorkspaceManagerError::InvalidCaptureAdoption);
    }

    writer.prepared.claim_cursor.current = next;
    writer.prepared.claim_cursor.current_claim_event = current_claim_event.clone();
    writer.prepared.claim_cursor.capture_tail_event_id = Some(adoption_event.id);
    writer.prepared.claim_cursor.capture_tail_sequence = Some(adoption_event.sequence);
    writer.prepared.claim_cursor.capture_clock = Some(adopted.adopted_at.clone());
    Ok(())
}

fn validate_snapshot_request(
    request: &SnapshotRequestV1,
    authority: &SnapshotRuntimeAuthorityV1,
) -> Result<(), WorkspaceManagerError> {
    if authority.claim_generation == 0
        || invalid_authority(authority)
        || authority.claim_sequence.is_none()
        || authority.claim_occurred_at.is_none()
        || authority.claim_lease_expires_at.is_none()
        || request.writer_revocation_event_id.as_uuid().is_nil()
        || request.snapshot_lease_event_id.as_uuid().is_nil()
        || request.snapshot_lease_id.as_uuid().is_nil()
        || request.writer_revocation_event_id == authority.claim_event_id
        || request.snapshot_lease_event_id == authority.claim_event_id
        || !valid_identifier(&request.snapshot_id)
        || !valid_identifier(&request.repository_root_id)
        || !valid_identifier(&request.workspace_writer_lease_id)
    {
        return Err(WorkspaceManagerError::InvalidRequest);
    }
    Ok(())
}

fn invalid_authority(authority: &SnapshotRuntimeAuthorityV1) -> bool {
    authority.session_id.as_uuid().is_nil()
        || authority.run_id.as_uuid().is_nil()
        || authority.issuer_actor_id.as_uuid().is_nil()
        || authority.claim_event_id.as_uuid().is_nil()
        || authority.claim_id.as_uuid().is_nil()
        || authority.claim_runtime_instance_id.as_uuid().is_nil()
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES
}

fn require_clock_order(
    previous: &RuntimeClockReading,
    next: &RuntimeClockReading,
) -> Result<(), WorkspaceManagerError> {
    if previous.runtime_instance_id != next.runtime_instance_id {
        return Err(WorkspaceManagerError::ClockRuntimeMismatch);
    }
    if previous.monotonic_nanos > next.monotonic_nanos {
        return Err(WorkspaceManagerError::ClockMovedBackwards);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn canonical_directory(path: &Path, create: bool) -> Result<PathBuf, WorkspaceManagerError> {
    if create {
        std::fs::create_dir_all(path).map_err(WorkspaceManagerError::io)?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(WorkspaceManagerError::io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(WorkspaceManagerError::UnsafeRoot);
    }
    std::fs::canonicalize(path).map_err(WorkspaceManagerError::io)
}

fn create_command(source: &Path, image: &Path) -> PreparedMacOsCommand {
    let native_argv = vec![
        OsString::from("create"),
        OsString::from("-srcfolder"),
        source.as_os_str().to_owned(),
        OsString::from("-format"),
        OsString::from("UDRO"),
        image.as_os_str().to_owned(),
    ];
    let protocol_argv = vec![
        literal("create"),
        literal("-srcfolder"),
        path(source),
        literal("-format"),
        literal("UDRO"),
        path(image),
    ];
    PreparedMacOsCommand::hdiutil(
        RepositoryMacOsDiskImageOperationV1::CreateUdroFromQuiescedSource,
        native_argv,
        protocol_argv,
    )
}

fn attach_command(mount: &Path, image: &Path) -> PreparedMacOsCommand {
    let native_argv = vec![
        OsString::from("attach"),
        OsString::from("-readonly"),
        OsString::from("-mountpoint"),
        mount.as_os_str().to_owned(),
        OsString::from("-noautoopen"),
        OsString::from("-plist"),
        image.as_os_str().to_owned(),
    ];
    let protocol_argv = vec![
        literal("attach"),
        literal("-readonly"),
        literal("-mountpoint"),
        path(mount),
        literal("-noautoopen"),
        literal("-plist"),
        path(image),
    ];
    PreparedMacOsCommand::hdiutil(
        RepositoryMacOsDiskImageOperationV1::AttachReadOnly,
        native_argv,
        protocol_argv,
    )
}

fn detach_command(mount: &Path) -> PreparedMacOsCommand {
    PreparedMacOsCommand::hdiutil(
        RepositoryMacOsDiskImageOperationV1::Detach,
        vec![OsString::from("detach"), mount.as_os_str().to_owned()],
        vec![literal("detach"), path(mount)],
    )
}

pub(crate) fn recovery_detach_device_command(device: &str) -> Option<PreparedMacOsCommand> {
    if !crate::recovery::valid_device_path(device) {
        return None;
    }
    let device = Path::new(device);
    Some(PreparedMacOsCommand::hdiutil(
        RepositoryMacOsDiskImageOperationV1::Detach,
        vec![OsString::from("detach"), device.as_os_str().to_owned()],
        vec![literal("detach"), path(device)],
    ))
}

fn literal(value: &str) -> RepositoryCommandArgumentV1 {
    RepositoryCommandArgumentV1::Literal {
        value: value.to_owned(),
    }
}

fn path(value: &Path) -> RepositoryCommandArgumentV1 {
    RepositoryCommandArgumentV1::Path {
        value: value.to_path_buf().into(),
    }
}

fn command_receipt(
    command: &PreparedMacOsCommand,
    exit_code: i32,
    stdout: &RetainedArtifact,
    stderr: &RetainedArtifact,
    completed_at: RuntimeClockReading,
) -> RepositoryMacOsCommandReceiptV1 {
    RepositoryMacOsCommandReceiptV1 {
        operation: command.operation(),
        executable: command.executable_wire(),
        argv: command.protocol_argv().to_vec(),
        exit_code,
        stdout_artifact: stdout.artifact.clone(),
        stderr_artifact: stderr.artifact.clone(),
        completed_at,
    }
}

fn require_committed_event(
    committed: &EventEnvelope,
    expected_event_id: EventId,
    authority: &SnapshotRuntimeAuthorityV1,
    expected_causal_parent: EventId,
    expected_payload: &EventPayload,
    expected_raw_artifact: &ArtifactRef,
) -> Result<(), WorkspaceManagerError> {
    if committed.id != expected_event_id
        || committed.session_id != authority.session_id
        || committed.run_id != Some(authority.run_id)
        || committed.actor_id != authority.issuer_actor_id
        || committed.causal_parent != Some(expected_causal_parent)
        || &committed.payload != expected_payload
        || committed.provenance.backend.is_some()
        || committed.provenance.raw_artifact.as_ref() != Some(expected_raw_artifact)
    {
        return Err(WorkspaceManagerError::CommittedEventMismatch);
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests;
