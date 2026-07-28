use super::*;

struct CorruptArtifactBoundary;

impl ArtifactBoundary for CorruptArtifactBoundary {
    fn retain(
        &self,
        media_type: &'static str,
        bytes: Vec<u8>,
    ) -> Result<RetainedArtifact, ArtifactBoundaryError> {
        let mut retained = CanonicalArtifactBoundary.retain(media_type, bytes)?;
        retained.artifact.sha256 = "0".repeat(Sha256Digest::HEX_LENGTH);
        Ok(retained)
    }
}

#[test]
fn exact_hdiutil_commands_preserve_native_paths_without_shell_parsing() {
    let source = Path::new("/tmp/源 code");
    let image = Path::new("/tmp/image path.dmg");
    let mount = Path::new("/tmp/mount path");
    let create = create_command(source, image);
    assert_eq!(
        create.native_argv(),
        &[
            OsString::from("create"),
            OsString::from("-srcfolder"),
            source.as_os_str().to_owned(),
            OsString::from("-format"),
            OsString::from("UDRO"),
            image.as_os_str().to_owned(),
        ]
    );
    assert_eq!(
        create.operation(),
        RepositoryMacOsDiskImageOperationV1::CreateUdroFromQuiescedSource
    );

    let attach = attach_command(mount, image);
    assert_eq!(
        attach.native_argv(),
        &[
            OsString::from("attach"),
            OsString::from("-readonly"),
            OsString::from("-mountpoint"),
            mount.as_os_str().to_owned(),
            OsString::from("-noautoopen"),
            OsString::from("-plist"),
            image.as_os_str().to_owned(),
        ]
    );
    assert_eq!(
        detach_command(mount).native_argv(),
        &[OsString::from("detach"), mount.as_os_str().to_owned()]
    );
}

#[test]
fn active_cooperative_writer_prevents_revocation() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, manager) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let _permit = manager.acquire_writer().expect("writer acquired");
    let prepared = manager
        .prepare_snapshot(request(), store_issued_fresh_handoff(&manager))
        .expect("snapshot prepares");
    assert!(matches!(
        manager.revoke_writers(prepared),
        Err(WorkspaceManagerError::ActiveWriters { actual: 1 })
    ));
}

#[test]
fn not_started_create_is_aborted_durably_and_writers_resume() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: Some(2),
    })));
    let (_source, _state, manager) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let capture = capture_prepared(&manager);
    assert!(matches!(
        manager.execute_capture(capture),
        Err(WorkspaceManagerError::CommandBoundary(
            CommandBoundaryError {
                kind: CommandBoundaryErrorKind::NotStarted,
                ..
            }
        ))
    ));
    assert!(
        manager
            .recovery_inspections()
            .expect("recovery reads")
            .is_empty()
    );
    assert!(manager.acquire_writer().is_ok());
}

#[test]
fn post_spawn_create_uncertainty_remains_recoverable_and_revoked() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::OutcomeUnknown,
        raw_os_error: Some(5),
    })));
    let (_source, _state, manager) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let capture = capture_prepared(&manager);
    assert!(matches!(
        manager.execute_capture(capture),
        Err(WorkspaceManagerError::CommandBoundary(
            CommandBoundaryError {
                kind: CommandBoundaryErrorKind::OutcomeUnknown,
                ..
            }
        ))
    ));
    let inspections = manager.recovery_inspections().expect("recovery reads");
    assert_eq!(inspections.len(), 1);
    assert_eq!(
        inspections[0].record.stage,
        crate::CleanupStageV1::CreateOutcomeUnknown
    );
    assert_eq!(
        inspections[0].disposition,
        crate::RecoveryDispositionV1::InspectCreateOutcome
    );
    assert!(matches!(
        manager.acquire_writer(),
        Err(WorkspaceManagerError::WritersRevoked)
    ));
}

#[test]
fn exact_committed_event_scope_is_required() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, manager) = manager(command, Arc::new(CanonicalArtifactBoundary));
    let request = request();
    let prepared = manager
        .prepare_snapshot(request, store_issued_fresh_handoff(&manager))
        .expect("snapshot prepares");
    let bundle = manager.revoke_writers(prepared).expect("writers revoke");
    let mut event = committed(
        &bundle.prepared.claim_cursor.current,
        bundle.event_id,
        bundle.prepared.claim_cursor.current.claim_event_id,
        EventPayload::RepositoryWriterLeaseRevoked(bundle.payload.clone()),
        bundle.evidence.artifact.clone(),
    );
    event.run_id = Some(RunId::from_uuid(uuid(77)));
    assert!(matches!(
        manager.confirm_writer_revocation(bundle, &event),
        Err(WorkspaceManagerError::CommittedEventMismatch)
    ));
}

#[test]
fn injected_artifact_substitution_fails_closed_and_resumes_writers() {
    let command = Arc::new(FakeCommandBoundary::one(Err(CommandBoundaryError {
        kind: CommandBoundaryErrorKind::NotStarted,
        raw_os_error: None,
    })));
    let (_source, _state, manager) = manager(command, Arc::new(CorruptArtifactBoundary));
    let prepared = manager
        .prepare_snapshot(request(), store_issued_fresh_handoff(&manager))
        .expect("snapshot prepares");
    assert!(matches!(
        manager.revoke_writers(prepared),
        Err(WorkspaceManagerError::ArtifactBoundary(
            ArtifactBoundaryError::InvalidRetainedArtifact
        ))
    ));
    assert!(manager.acquire_writer().is_ok());
    assert!(
        manager
            .recovery_inspections()
            .expect("recovery reads")
            .is_empty()
    );
}
