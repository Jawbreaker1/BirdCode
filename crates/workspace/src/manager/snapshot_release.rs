use super::{
    ActiveSnapshotLease, CHILD_RECONNAISSANCE_CONTRACT_VERSION, COMMAND_STDERR_MEDIA_TYPE,
    COMMAND_STDOUT_MEDIA_TYPE, CommandBoundaryErrorKind, EventEnvelope, EventPayload,
    MountPresence, PlatformError, REPOSITORY_SNAPSHOT_RELEASE_MEDIA_TYPE,
    RepositorySnapshotLeaseReleasedV1, RepositorySnapshotReleaseDocumentV1, SnapshotReleaseBundle,
    SnapshotReleasePrepared, SnapshotReleaseRequestV1, WorkspaceManager, WorkspaceManagerError,
    command_receipt, detach_command, invalid_authority, require_committed_event,
};

impl WorkspaceManager {
    /// Fsyncs detach-prepared recovery state before exposing the exact detach
    /// command. Release authority and event ID are caller-preallocated.
    ///
    /// # Errors
    ///
    /// Rejects invalid or colliding caller authority.
    pub fn prepare_release(
        &self,
        active: ActiveSnapshotLease,
        request: SnapshotReleaseRequestV1,
    ) -> Result<SnapshotReleasePrepared, WorkspaceManagerError> {
        let authority = &active.claim_cursor.current;
        if authority.claim_sequence.is_none()
            || authority.claim_occurred_at.is_none()
            || authority.claim_lease_expires_at.is_none()
        {
            return Err(WorkspaceManagerError::ReleaseRequiresRecovery);
        }
        if authority.claim_generation == 0
            || invalid_authority(authority)
            || request.release_event_id.as_uuid().is_nil()
            || request.causal_parent_event_id.as_uuid().is_nil()
            || request.release_event_id == active.lease_event.id
            || request.release_event_id == request.causal_parent_event_id
            || request.release_event_id == authority.claim_event_id
            || request.release_event_id == active.record.writer_revocation_event_id
        {
            return Err(WorkspaceManagerError::InvalidRequest);
        }
        let mut record = active.record.clone();
        record.stage = crate::CleanupStageV1::DetachPrepared;
        self.journal.write(&record)?;
        let command = detach_command(&active.mount_path);
        Ok(SnapshotReleasePrepared {
            active,
            request,
            command,
            record,
        })
    }

    /// Executes exact detach and separately observes that the mounted root is
    /// gone before constructing a release bundle.
    ///
    /// # Errors
    ///
    /// A lost/ambiguous post-spawn boundary remains `DetachOutcomeUnknown` and
    /// never produces `unmounted_verified: true`.
    pub fn execute_release(
        &self,
        prepared: SnapshotReleasePrepared,
    ) -> Result<SnapshotReleaseBundle, WorkspaceManagerError> {
        let output = match self.command.run(&prepared.command) {
            Ok(output) => output,
            Err(error) if error.kind == CommandBoundaryErrorKind::NotStarted => {
                let mut record = prepared.record;
                record.stage = crate::CleanupStageV1::LeaseCommitted;
                self.journal.write(&record)?;
                return Err(WorkspaceManagerError::CommandBoundary(error));
            }
            Err(error) => {
                let mut record = prepared.record;
                record.stage = crate::CleanupStageV1::DetachOutcomeUnknown;
                self.journal.write(&record)?;
                return Err(WorkspaceManagerError::CommandBoundary(error));
            }
        };
        let authority = &prepared.active.claim_cursor.current;
        let completed_at = self.now(authority.claim_runtime_instance_id)?;
        let stdout = self.retain(COMMAND_STDOUT_MEDIA_TYPE, output.stdout)?;
        let stderr = self.retain(COMMAND_STDERR_MEDIA_TYPE, output.stderr)?;
        let receipt = command_receipt(
            &prepared.command,
            output.exit_code,
            &stdout,
            &stderr,
            completed_at,
        );
        if output.exit_code != 0 {
            let mut record = prepared.record;
            record.stage = crate::CleanupStageV1::DetachOutcomeUnknown;
            self.journal.write(&record)?;
            return Err(WorkspaceManagerError::CommandFailed {
                receipt: Box::new(receipt),
                stdout: Box::new(stdout),
                stderr: Box::new(stderr),
            });
        }
        let presence = crate::platform::observe_mount_presence(
            &prepared.active.mount_path,
            prepared.active.root.descriptor_identity,
            prepared.active.unmounted_root_identity,
        )?;
        if !matches!(
            presence,
            MountPresence::UnmountedExpected | MountPresence::Missing
        ) {
            let mut record = prepared.record;
            record.stage = crate::CleanupStageV1::DetachOutcomeUnknown;
            self.journal.write(&record)?;
            return Err(WorkspaceManagerError::UnmountNotVerified { presence });
        }
        let release_document = RepositorySnapshotReleaseDocumentV1 {
            schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            lease_id: prepared.active.snapshot.immutability_lease.lease_id,
            lease_event_id: prepared.active.lease_event.id,
            detach_receipt: receipt,
            unmounted_verified: true,
        };
        let release =
            self.retain_json(REPOSITORY_SNAPSHOT_RELEASE_MEDIA_TYPE, &release_document)?;
        let payload = RepositorySnapshotLeaseReleasedV1 {
            issuer_actor_id: authority.issuer_actor_id,
            claim_event_id: authority.claim_event_id,
            claim_id: authority.claim_id,
            claim_generation: authority.claim_generation,
            claim_runtime_instance_id: authority.claim_runtime_instance_id,
            cancellation_generation: authority.cancellation_generation,
            lease_event_id: prepared.active.lease_event.id,
            release_artifact: release.artifact.clone(),
            release_digest: release.digest.clone(),
        };
        let mut record = prepared.record;
        record.stage = crate::CleanupStageV1::DetachedObserved;
        self.journal.write(&record)?;
        Ok(SnapshotReleaseBundle {
            event_id: prepared.request.release_event_id,
            payload,
            release_document,
            release,
            detach_stdout: stdout,
            detach_stderr: stderr,
            image_path: prepared.active.image_path,
            mount_path: prepared.active.mount_path,
            unmounted_root_identity: prepared.active.unmounted_root_identity,
            expected_image: prepared.active.expected_image,
            claim_cursor: prepared.active.claim_cursor,
            causal_parent_event_id: prepared.request.causal_parent_event_id,
            lease_id: record.lease_id,
        })
    }

    /// Validates the committed release event, then deletes only the derived
    /// image and empty derived mount directory before removing local recovery
    /// state.
    ///
    /// # Errors
    ///
    /// Never deletes before the exact release envelope is confirmed.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "successful cleanup consumes the one-shot release capability"
    )]
    pub fn confirm_release(
        &self,
        bundle: SnapshotReleaseBundle,
        committed: &EventEnvelope,
    ) -> Result<(), WorkspaceManagerError> {
        require_committed_event(
            committed,
            bundle.event_id,
            &bundle.claim_cursor.current,
            bundle.causal_parent_event_id,
            &EventPayload::RepositorySnapshotLeaseReleased(bundle.payload.clone()),
            &bundle.release.artifact,
        )?;
        match crate::platform::file_hash(&bundle.image_path) {
            Ok(observed)
                if observed.byte_len == bundle.expected_image.byte_len
                    && observed.sha256 == bundle.expected_image.sha256 => {}
            Ok(_) => return Err(WorkspaceManagerError::ImageChangedBeforeCleanup),
            Err(PlatformError::Io {
                raw_os_error: Some(value),
            }) if crate::platform::is_not_found_errno(value) => {}
            Err(error) => return Err(error.into()),
        }
        match std::fs::remove_file(&bundle.image_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(WorkspaceManagerError::io(error)),
        }
        match crate::platform::ensure_empty_directory(&bundle.mount_path) {
            Ok(identity) if identity == bundle.unmounted_root_identity => {
                std::fs::remove_dir(&bundle.mount_path).map_err(WorkspaceManagerError::io)?;
            }
            Ok(_) => return Err(WorkspaceManagerError::MountDirectoryChanged),
            Err(PlatformError::Io {
                raw_os_error: Some(value),
            }) if crate::platform::is_not_found_errno(value) => {}
            Err(error) => return Err(error.into()),
        }
        self.journal.remove(bundle.lease_id)?;
        Ok(())
    }
}
