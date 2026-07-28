use super::{
    ActiveSnapshotLease, CHILD_RECONNAISSANCE_CONTRACT_VERSION, COMMAND_STDERR_MEDIA_TYPE,
    COMMAND_STDOUT_MEDIA_TYPE, CapturePrepared, CapturedImage, ClaimTransitionPolicy,
    CommandBoundaryErrorKind, CommittedSnapshotLease, CommittedWriterRevocation, EventEnvelope,
    EventPayload, ParallelReconSnapshotClaimHandoffV1, ParallelReconSnapshotClaimHandoffViewV1,
    PreparedSnapshot, RAW_MACOS_PLIST_MEDIA_TYPE, REPOSITORY_MACOS_ATTACH_EVIDENCE_MEDIA_TYPE,
    REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE, REPOSITORY_SNAPSHOT_MANIFEST_MEDIA_TYPE,
    REPOSITORY_WRITER_LEASE_EVIDENCE_MEDIA_TYPE, RepositoryExternalImageIdentityV1,
    RepositoryFileHashReceiptV1, RepositoryMacOsAttachEvidenceV1,
    RepositoryMacOsReadOnlyMountEvidenceV1, RepositoryMacOsStatFsReceiptV1,
    RepositoryRootBindingV1, RepositorySnapshotBindingV1, RepositorySnapshotCaptureIdentityV1,
    RepositorySnapshotCleanupStateV1, RepositorySnapshotImageFormatV1,
    RepositorySnapshotLeaseBindingV1, RepositorySnapshotLeaseDocumentV1,
    RepositorySnapshotLeaseIssuedV1, RepositorySnapshotLeaseModeV1,
    RepositorySnapshotManifestDocumentV1, RepositorySourceQuiescenceV1,
    RepositoryWriterLeaseEvidenceDocumentV1, RepositoryWriterLeaseRevokedV1,
    SOURCE_CONTENT_MANIFEST_MEDIA_TYPE, SnapshotAttachPrepared, SnapshotClaimCursor,
    SnapshotLeaseBundle, SnapshotRequestV1, WorkspaceManager, WorkspaceManagerError,
    WriterRevocationBundle, attach_command, command_receipt, create_command, require_clock_order,
    require_committed_event, validate_next_claim, validate_snapshot_request,
};

impl WorkspaceManager {
    /// Validates caller-preallocated IDs and derives confined image/mount paths.
    /// No writer or external-command effect occurs.
    ///
    /// # Errors
    ///
    /// Rejects malformed authority, duplicate event IDs and path collisions.
    pub fn prepare_snapshot(
        &self,
        request: SnapshotRequestV1,
        claim_handoff: ParallelReconSnapshotClaimHandoffV1,
    ) -> Result<PreparedSnapshot, WorkspaceManagerError> {
        let claim_cursor = match claim_handoff.view() {
            ParallelReconSnapshotClaimHandoffViewV1::PreCapture {
                previous_claim,
                current_claim,
            } => {
                if let Some(previous_claim) = previous_claim {
                    let previous_cursor = SnapshotClaimCursor::from_claim_event(previous_claim)?;
                    validate_next_claim(
                        &previous_cursor,
                        previous_claim,
                        current_claim,
                        ClaimTransitionPolicy::AllowExpiredTakeover,
                    )?;
                }
                SnapshotClaimCursor::from_claim_event(current_claim)?
            }
            ParallelReconSnapshotClaimHandoffViewV1::CaptureAdoption { .. }
            | ParallelReconSnapshotClaimHandoffViewV1::ActiveLease { .. } => {
                return Err(WorkspaceManagerError::InvalidSnapshotClaimHandoff);
            }
        };
        drop(claim_handoff);
        validate_snapshot_request(&request, &claim_cursor.current)?;
        if request.writer_revocation_event_id == request.snapshot_lease_event_id {
            return Err(WorkspaceManagerError::DuplicateDurableEventId);
        }
        if self
            .journal
            .load_all()?
            .iter()
            .any(|record| record.lease_id == request.snapshot_lease_id)
        {
            return Err(WorkspaceManagerError::DuplicateSnapshotLeaseId);
        }
        let stem = request.snapshot_lease_id.to_string();
        let image_path = self.images_root.join(format!("{stem}.dmg"));
        let mount_path = self.mounts_root.join(stem);
        if image_path.try_exists().map_err(WorkspaceManagerError::io)? {
            return Err(WorkspaceManagerError::ImageAlreadyExists);
        }
        if mount_path.try_exists().map_err(WorkspaceManagerError::io)? {
            return Err(WorkspaceManagerError::MountPathAlreadyExists);
        }
        Ok(PreparedSnapshot {
            claim_cursor,
            request,
            source_path: self.source_path.clone(),
            image_path,
            mount_path,
        })
    }

    /// Revokes cooperative writers and returns the exact canonical evidence and
    /// preallocated Protocol event payload. No `hdiutil` process is started.
    ///
    /// # Errors
    ///
    /// Requires zero live writer permits and an unchanged descriptor-confined
    /// source observation.
    pub fn revoke_writers(
        &self,
        prepared: PreparedSnapshot,
    ) -> Result<WriterRevocationBundle, WorkspaceManagerError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| WorkspaceManagerError::StateUnavailable)?;
        if gate.revoked {
            return Err(WorkspaceManagerError::WritersRevoked);
        }
        if gate.active_writers != 0 {
            return Err(WorkspaceManagerError::ActiveWriters {
                actual: gate.active_writers,
            });
        }
        gate.generation = gate
            .generation
            .checked_add(1)
            .ok_or(WorkspaceManagerError::WriterGenerationOverflow)?;
        gate.revoked = true;
        let generation = gate.generation;
        drop(gate);

        let result = self.revoke_writers_inner(prepared, generation);
        if result.is_err()
            && let Ok(mut gate) = self.gate.lock()
        {
            gate.revoked = false;
        }
        result
    }

    fn revoke_writers_inner(
        &self,
        mut prepared: PreparedSnapshot,
        generation: u64,
    ) -> Result<WriterRevocationBundle, WorkspaceManagerError> {
        let revoked_at = self.now(prepared.claim_cursor.current.claim_runtime_instance_id)?;
        let source_before = crate::manifest::observe(&prepared.source_path, self.manifest_limits)?;
        let source_manifest_artifact = self.retain(
            SOURCE_CONTENT_MANIFEST_MEDIA_TYPE,
            source_before.canonical_bytes.clone(),
        )?;
        let evidence_document = RepositoryWriterLeaseEvidenceDocumentV1 {
            schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            writer_lease_id: prepared.request.workspace_writer_lease_id.clone(),
            writer_lease_generation: generation,
            source_path: prepared.source_path.clone().into(),
            source_root_identity: source_before.root_identity,
            exclusive: true,
            active_writer_count: 0,
            revoked_at: revoked_at.clone(),
        };
        let evidence = self.retain_json(
            REPOSITORY_WRITER_LEASE_EVIDENCE_MEDIA_TYPE,
            &evidence_document,
        )?;
        prepared.claim_cursor.capture_clock = Some(revoked_at.clone());
        let authority = &prepared.claim_cursor.current;
        let payload = RepositoryWriterLeaseRevokedV1 {
            issuer_actor_id: authority.issuer_actor_id,
            claim_event_id: authority.claim_event_id,
            claim_id: authority.claim_id,
            claim_generation: authority.claim_generation,
            claim_runtime_instance_id: authority.claim_runtime_instance_id,
            cancellation_generation: authority.cancellation_generation,
            capture: RepositorySnapshotCaptureIdentityV1 {
                snapshot_id: prepared.request.snapshot_id.clone(),
                lease_id: prepared.request.snapshot_lease_id,
                snapshot_lease_event_id: prepared.request.snapshot_lease_event_id,
            },
            evidence_artifact: evidence.artifact.clone(),
            evidence_digest: evidence.digest.clone(),
        };
        let record = crate::CleanupJournalRecordV1::new(
            prepared.request.snapshot_id.clone(),
            prepared.request.snapshot_lease_id,
            prepared.request.writer_revocation_event_id,
            prepared.request.snapshot_lease_event_id,
            prepared.source_path.clone().into(),
            prepared.image_path.clone().into(),
            prepared.mount_path.clone().into(),
            authority.issuer_actor_id,
            authority.claim_runtime_instance_id,
        );
        self.journal.write(&record)?;
        Ok(WriterRevocationBundle {
            event_id: prepared.request.writer_revocation_event_id,
            payload,
            evidence,
            source_manifest_artifact,
            prepared,
            source_before,
            revoked_at,
            writer_generation: generation,
            record,
        })
    }

    /// Validates the exact committed writer-revocation envelope.
    ///
    /// # Errors
    ///
    /// Rejects any substituted ID, payload, actor, parent or raw artifact.
    pub fn confirm_writer_revocation(
        &self,
        mut bundle: WriterRevocationBundle,
        committed: &EventEnvelope,
    ) -> Result<CommittedWriterRevocation, WorkspaceManagerError> {
        require_committed_event(
            committed,
            bundle.event_id,
            &bundle.prepared.claim_cursor.current,
            bundle.prepared.claim_cursor.current.claim_event_id,
            &EventPayload::RepositoryWriterLeaseRevoked(bundle.payload.clone()),
            &bundle.evidence.artifact,
        )?;
        let claim_sequence = bundle
            .prepared
            .claim_cursor
            .current
            .claim_sequence
            .ok_or(WorkspaceManagerError::CommittedEventMismatch)?;
        let claim_occurred_at = bundle
            .prepared
            .claim_cursor
            .current
            .claim_occurred_at
            .ok_or(WorkspaceManagerError::CommittedEventMismatch)?;
        let claim_lease_expires_at = bundle
            .prepared
            .claim_cursor
            .current
            .claim_lease_expires_at
            .ok_or(WorkspaceManagerError::CommittedEventMismatch)?;
        if committed.sequence <= claim_sequence
            || committed.occurred_at < claim_occurred_at
            || committed.occurred_at >= claim_lease_expires_at
        {
            return Err(WorkspaceManagerError::CommittedEventMismatch);
        }
        bundle.prepared.claim_cursor.capture_tail_event_id = Some(committed.id);
        bundle.prepared.claim_cursor.capture_tail_sequence = Some(committed.sequence);
        Ok(CommittedWriterRevocation { bundle })
    }

    /// Persists local create-prepared recovery state and returns the only exact
    /// command authorized by the v1 capture contract.
    ///
    /// # Errors
    ///
    /// Fails if the fsync-backed recovery journal cannot be advanced.
    pub fn prepare_capture(
        &self,
        committed: CommittedWriterRevocation,
    ) -> Result<CapturePrepared, WorkspaceManagerError> {
        let mut record = committed.bundle.record.clone();
        record.stage = crate::CleanupStageV1::CreatePrepared;
        self.journal.write(&record)?;
        let command = create_command(
            &committed.bundle.prepared.source_path,
            &committed.bundle.prepared.image_path,
        );
        Ok(CapturePrepared {
            writer: committed.bundle,
            command,
            record,
        })
    }

    /// Executes the exact UDRO image command, hashes the image and requires
    /// byte-identical descriptor-confined pre/post source manifests.
    ///
    /// # Errors
    ///
    /// Outcome-unknown boundaries remain journaled and keep writers revoked.
    /// Known capture rejection leaves a typed cleanup-required record.
    #[allow(
        clippy::too_many_lines,
        reason = "one closed capture effect gate preserves exact recovery transitions and evidence"
    )]
    pub fn execute_capture(
        &self,
        mut prepared: CapturePrepared,
    ) -> Result<CapturedImage, WorkspaceManagerError> {
        let output = match self.command.run(&prepared.command) {
            Ok(output) => output,
            Err(error) if error.kind == CommandBoundaryErrorKind::NotStarted => {
                self.journal
                    .remove(prepared.writer.prepared.request.snapshot_lease_id)?;
                self.resume_writers()?;
                return Err(WorkspaceManagerError::CommandBoundary(error));
            }
            Err(error) => {
                let mut record = prepared.record;
                record.stage = crate::CleanupStageV1::CreateOutcomeUnknown;
                self.journal.write(&record)?;
                return Err(WorkspaceManagerError::CommandBoundary(error));
            }
        };
        let completed_at = self.now(
            prepared
                .writer
                .prepared
                .claim_cursor
                .current
                .claim_runtime_instance_id,
        )?;
        require_clock_order(&prepared.writer.revoked_at, &completed_at)?;
        let stdout = self.retain(COMMAND_STDOUT_MEDIA_TYPE, output.stdout)?;
        let stderr = self.retain(COMMAND_STDERR_MEDIA_TYPE, output.stderr)?;
        let receipt = command_receipt(
            &prepared.command,
            output.exit_code,
            &stdout,
            &stderr,
            completed_at.clone(),
        );
        if output.exit_code != 0 {
            let mut record = prepared.record;
            record.stage = crate::CleanupStageV1::CreateCleanupRequired;
            self.journal.write(&record)?;
            self.resume_writers()?;
            return Err(WorkspaceManagerError::CommandFailed {
                receipt: Box::new(receipt),
                stdout: Box::new(stdout),
                stderr: Box::new(stderr),
            });
        }
        let image_hash = crate::platform::file_hash(&prepared.writer.prepared.image_path)?;
        let hash_completed_at = self.now(
            prepared
                .writer
                .prepared
                .claim_cursor
                .current
                .claim_runtime_instance_id,
        )?;
        require_clock_order(&completed_at, &hash_completed_at)?;
        let source_after =
            crate::manifest::observe(&prepared.writer.prepared.source_path, self.manifest_limits)?;
        let capture_completed_at = self.now(
            prepared
                .writer
                .prepared
                .claim_cursor
                .current
                .claim_runtime_instance_id,
        )?;
        require_clock_order(&hash_completed_at, &capture_completed_at)?;
        if source_after.root_identity != prepared.writer.source_before.root_identity
            || source_after.canonical_bytes != prepared.writer.source_before.canonical_bytes
            || source_after.digest != prepared.writer.source_before.digest
        {
            let mut record = prepared.record;
            record.stage = crate::CleanupStageV1::CreateCleanupRequired;
            self.journal.write(&record)?;
            self.resume_writers()?;
            return Err(WorkspaceManagerError::SourceChangedDuringCapture {
                before: prepared.writer.source_before.digest,
                after: source_after.digest,
            });
        }
        let source_after_artifact = self.retain(
            SOURCE_CONTENT_MANIFEST_MEDIA_TYPE,
            source_after.canonical_bytes.clone(),
        )?;
        let mut record = prepared.record;
        record.stage = crate::CleanupStageV1::ImageCaptured;
        self.journal.write(&record)?;
        self.resume_writers()?;
        prepared.writer.prepared.claim_cursor.capture_clock = Some(capture_completed_at.clone());
        let image_path = prepared.writer.prepared.image_path.clone();
        Ok(CapturedImage {
            writer: prepared.writer,
            create_receipt: receipt,
            create_stdout: stdout,
            create_stderr: stderr,
            image: RepositoryExternalImageIdentityV1 {
                format: RepositorySnapshotImageFormatV1::Udro,
                byte_len: image_hash.byte_len,
                sha256: image_hash.sha256.clone(),
            },
            image_hash_receipt: RepositoryFileHashReceiptV1 {
                path: image_path.into(),
                byte_len: image_hash.byte_len,
                sha256: image_hash.sha256,
                completed_at: hash_completed_at,
            },
            source_after,
            source_after_artifact,
            capture_completed_at,
            record,
        })
    }

    /// Fsyncs attach-prepared recovery state before exposing the exact attach
    /// command.
    ///
    /// # Errors
    ///
    /// Requires the confined mount directory to remain empty and unchanged.
    pub fn prepare_attach(
        &self,
        captured: CapturedImage,
    ) -> Result<SnapshotAttachPrepared, WorkspaceManagerError> {
        std::fs::create_dir(&captured.writer.prepared.mount_path)
            .map_err(WorkspaceManagerError::io)?;
        let observed_unmounted =
            match crate::platform::ensure_empty_directory(&captured.writer.prepared.mount_path) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = std::fs::remove_dir(&captured.writer.prepared.mount_path);
                    return Err(error.into());
                }
            };
        let mut record = captured.record.clone();
        record.stage = crate::CleanupStageV1::AttachPrepared;
        record.unmounted_root_identity = Some(observed_unmounted);
        if let Err(error) = self.journal.write(&record) {
            let _ = std::fs::remove_dir(&captured.writer.prepared.mount_path);
            return Err(error.into());
        }
        let command = attach_command(
            &captured.writer.prepared.mount_path,
            &captured.writer.prepared.image_path,
        );
        Ok(SnapshotAttachPrepared {
            captured,
            command,
            unmounted_root_identity: observed_unmounted,
            record,
        })
    }

    /// Attaches the exact image, structurally decodes plist output, verifies
    /// kernel readonly state and EROFS, then requires the mounted content
    /// manifest to equal the post-capture source manifest byte-for-byte.
    ///
    /// # Errors
    ///
    /// Any post-spawn uncertainty remains `AttachOutcomeUnknown`; once a mount
    /// is proven, every later failure remains `MountedDetachRequired`.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed Store snapshot lease wire is assembled losslessly in one effect gate"
    )]
    pub fn execute_attach(
        &self,
        mut prepared: SnapshotAttachPrepared,
    ) -> Result<SnapshotLeaseBundle, WorkspaceManagerError> {
        let output = match self.command.run(&prepared.command) {
            Ok(output) => output,
            Err(error) if error.kind == CommandBoundaryErrorKind::NotStarted => {
                let mut record = prepared.record;
                record.stage = crate::CleanupStageV1::ImageCaptured;
                record.unmounted_root_identity = None;
                let observed = crate::platform::ensure_empty_directory(
                    &prepared.captured.writer.prepared.mount_path,
                )?;
                if observed != prepared.unmounted_root_identity {
                    return Err(WorkspaceManagerError::MountDirectoryChanged);
                }
                std::fs::remove_dir(&prepared.captured.writer.prepared.mount_path)
                    .map_err(WorkspaceManagerError::io)?;
                self.journal.write(&record)?;
                return Err(WorkspaceManagerError::CommandBoundary(error));
            }
            Err(error) => {
                let mut record = prepared.record;
                record.stage = crate::CleanupStageV1::AttachOutcomeUnknown;
                self.journal.write(&record)?;
                return Err(WorkspaceManagerError::CommandBoundary(error));
            }
        };
        let runtime_id = prepared
            .captured
            .writer
            .prepared
            .claim_cursor
            .current
            .claim_runtime_instance_id;
        let attach_completed_at = self.now(runtime_id)?;
        require_clock_order(
            &prepared.captured.capture_completed_at,
            &attach_completed_at,
        )?;
        let raw_plist = self.retain(RAW_MACOS_PLIST_MEDIA_TYPE, output.stdout)?;
        let stderr = self.retain(COMMAND_STDERR_MEDIA_TYPE, output.stderr)?;
        if output.exit_code != 0 {
            let receipt = command_receipt(
                &prepared.command,
                output.exit_code,
                &raw_plist,
                &stderr,
                attach_completed_at,
            );
            let mut record = prepared.record;
            record.stage = crate::CleanupStageV1::AttachOutcomeUnknown;
            self.journal.write(&record)?;
            return Err(WorkspaceManagerError::CommandFailed {
                receipt: Box::new(receipt),
                stdout: Box::new(raw_plist),
                stderr: Box::new(stderr),
            });
        }
        let decoded = match crate::plist_decode::decode_attach_plist(
            &raw_plist.bytes,
            &prepared.captured.writer.prepared.mount_path,
        ) {
            Ok(decoded) => decoded,
            Err(error) => {
                let mut record = prepared.record;
                record.stage = crate::CleanupStageV1::AttachOutcomeUnknown;
                self.journal.write(&record)?;
                return Err(error.into());
            }
        };
        let probe = format!(
            ".birdcode-readonly-probe-{}",
            prepared.captured.writer.prepared.request.snapshot_lease_id
        );
        let mount_observation = match crate::platform::verify_read_only_mount(
            &prepared.captured.writer.prepared.mount_path,
            probe.as_bytes(),
        ) {
            Ok(observation) => observation,
            Err(error) => {
                let mut record = prepared.record;
                record.stage = crate::CleanupStageV1::AttachOutcomeUnknown;
                self.journal.write(&record)?;
                return Err(error.into());
            }
        };
        let statfs_observed_at = self.now(runtime_id)?;
        require_clock_order(&attach_completed_at, &statfs_observed_at)?;

        let mut record = prepared.record;
        record.stage = crate::CleanupStageV1::MountedDetachRequired;
        record.mounted_root_identity = Some(mount_observation.mounted_root_identity);
        record.leaf_device_identifier = Some(decoded.leaf_device_identifier.clone());
        self.journal.write(&record)?;

        let mounted = crate::manifest::observe(
            &prepared.captured.writer.prepared.mount_path,
            self.manifest_limits,
        )?;
        if mounted.canonical_bytes != prepared.captured.source_after.canonical_bytes
            || mounted.digest != prepared.captured.source_after.digest
        {
            return Err(WorkspaceManagerError::MountedManifestMismatch {
                source_digest: prepared.captured.source_after.digest,
                mounted_digest: mounted.digest,
            });
        }
        let lease_observed_at = self.now(runtime_id)?;
        require_clock_order(&statfs_observed_at, &lease_observed_at)?;

        let request = &prepared.captured.writer.prepared.request;
        let source_quiescence = RepositorySourceQuiescenceV1 {
            workspace_writer_lease_id: request.workspace_writer_lease_id.clone(),
            writer_lease_generation: prepared.captured.writer.writer_generation,
            writer_lease_event_id: request.writer_revocation_event_id,
            writer_lease_evidence_artifact: prepared.captured.writer.evidence.artifact.clone(),
            writer_lease_evidence_digest: prepared.captured.writer.evidence.digest.clone(),
            writers_revoked_at: prepared.captured.writer.revoked_at.clone(),
            source_identity_before: prepared.captured.writer.source_before.root_identity,
            source_identity_after: prepared.captured.source_after.root_identity,
            source_manifest_before: prepared.captured.writer.source_before.digest.clone(),
            source_manifest_after: prepared.captured.source_after.digest.clone(),
            capture_completed_at: prepared.captured.capture_completed_at.clone(),
        };
        let attach_evidence_document = RepositoryMacOsAttachEvidenceV1 {
            schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            leaf_device_identifier: decoded.leaf_device_identifier.clone(),
            mount_path: prepared.captured.writer.prepared.mount_path.clone().into(),
            read_only: true,
        };
        let attach_evidence = self.retain_json(
            REPOSITORY_MACOS_ATTACH_EVIDENCE_MEDIA_TYPE,
            &attach_evidence_document,
        )?;
        let attach_receipt = command_receipt(
            &prepared.command,
            output.exit_code,
            &attach_evidence,
            &stderr,
            attach_completed_at,
        );
        let statfs_receipt = RepositoryMacOsStatFsReceiptV1 {
            mount_path: prepared.captured.writer.prepared.mount_path.clone().into(),
            statfs_flags: mount_observation.statfs_flags,
            mnt_rdonly_mask: mount_observation.mnt_rdonly_mask,
            leaf_device_identifier: decoded.leaf_device_identifier.clone(),
            mounted_root_identity: mount_observation.mounted_root_identity,
            write_open_errno: mount_observation.write_open_errno,
            observed_at: statfs_observed_at,
        };
        let snapshot_manifest_document = RepositorySnapshotManifestDocumentV1 {
            schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            snapshot_id: request.snapshot_id.clone(),
            source_path: prepared.captured.writer.prepared.source_path.clone().into(),
            source_root_identity: prepared.captured.source_after.root_identity,
            mounted_root_identity: mount_observation.mounted_root_identity,
            entries_digest: prepared.captured.source_after.digest.clone(),
        };
        let snapshot_manifest = self.retain_json(
            REPOSITORY_SNAPSHOT_MANIFEST_MEDIA_TYPE,
            &snapshot_manifest_document,
        )?;
        let root = RepositoryRootBindingV1 {
            repository_root_id: request.repository_root_id.clone(),
            descriptor_identity: mount_observation.mounted_root_identity,
        };
        let mount_evidence = RepositoryMacOsReadOnlyMountEvidenceV1 {
            source_quiescence,
            image: prepared.captured.image.clone(),
            create_receipt: prepared.captured.create_receipt.clone(),
            attach_receipt,
            attach_plist_artifact: attach_evidence.artifact.clone(),
            source_path: prepared.captured.writer.prepared.source_path.clone().into(),
            image_path: prepared.captured.writer.prepared.image_path.clone().into(),
            mount_path: prepared.captured.writer.prepared.mount_path.clone().into(),
            leaf_device_identifier: decoded.leaf_device_identifier,
            image_hash_receipt: prepared.captured.image_hash_receipt.clone(),
            statfs_receipt,
            post_mount_manifest_artifact: snapshot_manifest.artifact.clone(),
            post_mount_manifest_digest: snapshot_manifest.digest.clone(),
            lifecycle_owner_actor_id: prepared
                .captured
                .writer
                .prepared
                .claim_cursor
                .current
                .issuer_actor_id,
            lifecycle_owner_runtime_instance_id: prepared
                .captured
                .writer
                .prepared
                .claim_cursor
                .current
                .claim_runtime_instance_id,
            cleanup_state: RepositorySnapshotCleanupStateV1::MountedDetachRequired,
        };
        let lease_document = RepositorySnapshotLeaseDocumentV1 {
            schema_version: CHILD_RECONNAISSANCE_CONTRACT_VERSION,
            lease_id: request.snapshot_lease_id,
            mode: RepositorySnapshotLeaseModeV1::MacOsCooperativeQuiescedReadOnlyDiskImage,
            snapshot_id: request.snapshot_id.clone(),
            declared_snapshot_digest: snapshot_manifest.digest.clone(),
            root: root.clone(),
            macos_read_only_mount: mount_evidence,
        };
        let lease = self.retain_json(REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE, &lease_document)?;
        let snapshot = RepositorySnapshotBindingV1 {
            snapshot_id: request.snapshot_id.clone(),
            declared_snapshot_digest: snapshot_manifest.digest.clone(),
            immutability_lease: RepositorySnapshotLeaseBindingV1 {
                lease_id: request.snapshot_lease_id,
                mode: RepositorySnapshotLeaseModeV1::MacOsCooperativeQuiescedReadOnlyDiskImage,
                lease_artifact: lease.artifact.clone(),
                lease_digest: lease.digest.clone(),
            },
        };
        let authority = &prepared.captured.writer.prepared.claim_cursor.current;
        let payload = RepositorySnapshotLeaseIssuedV1 {
            issuer_actor_id: authority.issuer_actor_id,
            claim_event_id: authority.claim_event_id,
            claim_id: authority.claim_id,
            claim_generation: authority.claim_generation,
            claim_runtime_instance_id: authority.claim_runtime_instance_id,
            cancellation_generation: authority.cancellation_generation,
            snapshot,
            root,
        };
        let mounted_content_manifest =
            self.retain(SOURCE_CONTENT_MANIFEST_MEDIA_TYPE, mounted.canonical_bytes)?;
        prepared.captured.writer.prepared.claim_cursor.capture_clock = Some(lease_observed_at);
        Ok(SnapshotLeaseBundle {
            event_id: request.snapshot_lease_event_id,
            payload,
            lease_document,
            lease,
            attach_evidence,
            raw_attach_plist: raw_plist,
            attach_stderr: stderr,
            snapshot_manifest,
            mounted_content_manifest,
            unmounted_root_identity: prepared.unmounted_root_identity,
            prepared: prepared.captured,
            record,
        })
    }

    /// Validates the exact committed snapshot-lease envelope.
    ///
    /// # Errors
    ///
    /// Rejects any substituted lease document, payload or authority.
    pub fn confirm_snapshot_lease(
        &self,
        bundle: SnapshotLeaseBundle,
        committed: &EventEnvelope,
    ) -> Result<CommittedSnapshotLease, WorkspaceManagerError> {
        let authority = &bundle.prepared.writer.prepared.claim_cursor.current;
        require_committed_event(
            committed,
            bundle.event_id,
            authority,
            authority.claim_event_id,
            &EventPayload::RepositorySnapshotLeaseIssued(bundle.payload.clone()),
            &bundle.lease.artifact,
        )?;
        Ok(CommittedSnapshotLease {
            bundle,
            lease_event: committed.clone(),
        })
    }

    /// Marks the already committed lease as active in local cleanup state.
    ///
    /// # Errors
    ///
    /// Fails if the local fsync-backed journal cannot be advanced.
    pub fn activate_snapshot_lease(
        &self,
        committed: CommittedSnapshotLease,
    ) -> Result<ActiveSnapshotLease, WorkspaceManagerError> {
        let mut record = committed.bundle.record.clone();
        record.stage = crate::CleanupStageV1::LeaseCommitted;
        self.journal.write(&record)?;
        let SnapshotLeaseBundle {
            payload,
            unmounted_root_identity,
            prepared,
            ..
        } = committed.bundle;
        let CapturedImage {
            writer,
            image: expected_image,
            ..
        } = prepared;
        let PreparedSnapshot {
            claim_cursor,
            mount_path,
            image_path,
            ..
        } = writer.prepared;
        Ok(ActiveSnapshotLease {
            snapshot: payload.snapshot,
            root: payload.root,
            mount_path,
            image_path,
            unmounted_root_identity,
            expected_image,
            lease_event: committed.lease_event,
            claim_cursor,
            record,
        })
    }
}
