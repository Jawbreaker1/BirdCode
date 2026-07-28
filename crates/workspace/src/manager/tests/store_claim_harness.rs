use super::*;

pub(super) struct StoreClaimHarness {
    _directory: tempfile::TempDir,
    store: Store,
    run_id: RunId,
    actor_id: ActorId,
    runtime_instance_id: RuntimeInstanceId,
    pub(super) current_claim: EventEnvelope,
}

impl StoreClaimHarness {
    #[allow(
        clippy::too_many_lines,
        reason = "the test fixture persists one complete Store-issued claim history"
    )]
    pub(super) fn new(workspace_root: &Path) -> (Self, ParallelReconSnapshotClaimHandoffV1) {
        let directory = tempfile::tempdir().expect("Store fixture directory");
        let mut store = Store::open(
            directory.path().join("state.sqlite3"),
            directory.path().join("artifacts"),
        )
        .expect("Store fixture opens");
        let actor_id = ActorId::new();
        let runtime_instance_id = RuntimeInstanceId::new();
        let session = Session::new(CreateSessionRequest {
            workspace_root: workspace_root.to_path_buf().into(),
            title: Some("workspace Store handoff".to_owned()),
        });
        let provenance = || Provenance {
            producer: "workspace-store-handoff-test".to_owned(),
            backend: None,
            raw_artifact: None,
        };
        let session_created = store
            .create_session(
                &session,
                NewEvent {
                    session_id: session.id,
                    run_id: None,
                    actor_id,
                    causal_parent: None,
                    provenance: provenance(),
                    payload: EventPayload::SessionCreated {
                        session: session.clone(),
                    },
                },
            )
            .expect("Store session persists");
        let run = Run::new(RunSpec {
            session_id: session.id,
            purpose: RunPurpose::ParallelRepositoryReconnaissanceV1,
            plan_acceptance: PlanAcceptanceContract::IndependentSemanticReviewV1,
            backend: BackendSelection {
                backend_id: "workspace-test".to_owned(),
                kind: BackendKind::Model,
                model: Some("fixture".to_owned()),
                reasoning_effort: None,
            },
            input: vec![InputItem::Text {
                text: "exercise Store-issued snapshot authority".to_owned(),
            }],
            limits: RunLimits {
                max_output_tokens: Some(1_024),
                max_wall_time_seconds: Some(60),
                max_subagents: 2,
            },
        });
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
            .expect("Store run persists");
        let now = Utc::now();
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
                    lease_expires_at: now + chrono::Duration::minutes(30),
                }),
            })
            .expect("Store claim persists");
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
            .expect("Store run starts");
        let outcome = store
            .refresh_parallel_recon_claim(
                run.id,
                ParallelReconClaimRefreshAuthority {
                    actor_id,
                    runtime_instance_id,
                    renewal_claim_id: RunClaimId::new(),
                    snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
                    child_adoption_ids: [
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                    ],
                    refreshed_at: RuntimeClockReading {
                        runtime_instance_id,
                        monotonic_nanos: 1,
                        observed_at: now,
                    },
                    fresh_through: now + chrono::Duration::minutes(1),
                    renewed_lease_expires_at: now + chrono::Duration::minutes(45),
                },
            )
            .expect("Store resolves fresh handoff");
        let ParallelReconClaimRefreshOutcome::Fresh {
            snapshot_claim: ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(snapshot_claim),
            ..
        } = outcome
        else {
            panic!("fresh Store fixture must issue pre-capture authority")
        };
        (
            Self {
                _directory: directory,
                store,
                run_id: run.id,
                actor_id,
                runtime_instance_id,
                current_claim: claim,
            },
            snapshot_claim,
        )
    }

    pub(super) fn append_writer_event(&mut self, bundle: &WriterRevocationBundle) -> EventEnvelope {
        let retained = self
            .store
            .put_artifact(
                &bundle.evidence.bytes,
                REPOSITORY_WRITER_LEASE_EVIDENCE_MEDIA_TYPE,
            )
            .expect("Store retains writer evidence");
        assert_eq!(retained, bundle.evidence.artifact);
        let outcome = self
            .store
            .append_identified_event(IdentifiedNewEvent {
                event_id: bundle.event_id,
                event: NewEvent {
                    session_id: self.current_claim.session_id,
                    run_id: Some(self.run_id),
                    actor_id: self.actor_id,
                    causal_parent: Some(self.current_claim.id),
                    provenance: Provenance {
                        producer: "workspace-store-handoff-test".to_owned(),
                        backend: None,
                        raw_artifact: Some(bundle.evidence.artifact.clone()),
                    },
                    payload: EventPayload::RepositoryWriterLeaseRevoked(bundle.payload.clone()),
                },
            })
            .expect("Store commits workspace writer event");
        match outcome {
            IdempotentAppendOutcome::Appended { event }
            | IdempotentAppendOutcome::AlreadyPresent { event } => event,
        }
    }

    pub(super) fn renew_open_capture(&mut self) -> ParallelReconSnapshotClaimHandoffV1 {
        let EventPayload::RunClaimed(current) = &self.current_claim.payload else {
            panic!("harness current event is a claim")
        };
        let observed_at = Utc::now();
        let outcome = self
            .store
            .refresh_parallel_recon_claim(
                self.run_id,
                ParallelReconClaimRefreshAuthority {
                    actor_id: self.actor_id,
                    runtime_instance_id: self.runtime_instance_id,
                    renewal_claim_id: RunClaimId::new(),
                    snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
                    child_adoption_ids: [
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                    ],
                    refreshed_at: RuntimeClockReading {
                        runtime_instance_id: self.runtime_instance_id,
                        monotonic_nanos: 100,
                        observed_at,
                    },
                    fresh_through: current.lease_expires_at + chrono::Duration::milliseconds(1),
                    renewed_lease_expires_at: current.lease_expires_at
                        + chrono::Duration::minutes(10),
                },
            )
            .expect("Store renews open capture");
        let ParallelReconClaimRefreshOutcome::Renewed {
            claim,
            snapshot_claim: ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(snapshot_claim),
            ..
        } = outcome
        else {
            panic!("open capture renewal must issue adoption authority")
        };
        self.current_claim = claim.event;
        snapshot_claim
    }

    pub(super) fn renew_pre_capture(&mut self) -> ParallelReconSnapshotClaimHandoffV1 {
        let EventPayload::RunClaimed(current) = &self.current_claim.payload else {
            panic!("harness current event is a claim")
        };
        let observed_at = Utc::now();
        let outcome = self
            .store
            .refresh_parallel_recon_claim(
                self.run_id,
                ParallelReconClaimRefreshAuthority {
                    actor_id: self.actor_id,
                    runtime_instance_id: self.runtime_instance_id,
                    renewal_claim_id: RunClaimId::new(),
                    snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
                    child_adoption_ids: [
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                    ],
                    refreshed_at: RuntimeClockReading {
                        runtime_instance_id: self.runtime_instance_id,
                        monotonic_nanos: 100,
                        observed_at,
                    },
                    fresh_through: current.lease_expires_at + chrono::Duration::milliseconds(1),
                    renewed_lease_expires_at: current.lease_expires_at
                        + chrono::Duration::minutes(10),
                },
            )
            .expect("Store renews pre-capture claim");
        let ParallelReconClaimRefreshOutcome::Renewed {
            claim,
            snapshot_claim: ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(snapshot_claim),
            ..
        } = outcome
        else {
            panic!("pre-capture renewal must issue authority")
        };
        self.current_claim = claim.event;
        snapshot_claim
    }

    pub(super) fn fresh_pre_capture(&mut self) -> ParallelReconSnapshotClaimHandoffV1 {
        let observed_at = Utc::now();
        let outcome = self
            .store
            .refresh_parallel_recon_claim(
                self.run_id,
                ParallelReconClaimRefreshAuthority {
                    actor_id: self.actor_id,
                    runtime_instance_id: self.runtime_instance_id,
                    renewal_claim_id: RunClaimId::new(),
                    snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
                    child_adoption_ids: [
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                    ],
                    refreshed_at: RuntimeClockReading {
                        runtime_instance_id: self.runtime_instance_id,
                        monotonic_nanos: 0,
                        observed_at,
                    },
                    fresh_through: observed_at + chrono::Duration::minutes(1),
                    renewed_lease_expires_at: observed_at + chrono::Duration::minutes(10),
                },
            )
            .expect("Store reissues exact-current pre-capture authority");
        let ParallelReconClaimRefreshOutcome::Fresh {
            claim,
            snapshot_claim: ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(snapshot_claim),
            ..
        } = outcome
        else {
            panic!("fresh pre-capture state must issue exact-current authority")
        };
        self.current_claim = claim.event;
        snapshot_claim
    }

    pub(super) fn append_lease_event(&mut self, bundle: &SnapshotLeaseBundle) -> EventEnvelope {
        let artifacts = [
            &bundle.lease,
            &bundle.attach_evidence,
            &bundle.attach_stderr,
            &bundle.snapshot_manifest,
            &bundle.prepared.create_stdout,
            &bundle.prepared.create_stderr,
            &bundle.prepared.writer.evidence,
        ];
        for artifact in artifacts {
            let retained = self
                .store
                .put_artifact(&artifact.bytes, artifact.artifact.media_type.clone())
                .expect("Store retains lease evidence");
            assert_eq!(retained, artifact.artifact);
        }
        let outcome = self
            .store
            .append_identified_event(IdentifiedNewEvent {
                event_id: bundle.event_id,
                event: NewEvent {
                    session_id: self.current_claim.session_id,
                    run_id: Some(self.run_id),
                    actor_id: self.actor_id,
                    causal_parent: Some(self.current_claim.id),
                    provenance: Provenance {
                        producer: "workspace-store-handoff-test".to_owned(),
                        backend: None,
                        raw_artifact: Some(bundle.lease.artifact.clone()),
                    },
                    payload: EventPayload::RepositorySnapshotLeaseIssued(bundle.payload.clone()),
                },
            })
            .expect("Store commits workspace snapshot lease");
        match outcome {
            IdempotentAppendOutcome::Appended { event }
            | IdempotentAppendOutcome::AlreadyPresent { event } => event,
        }
    }

    pub(super) fn active_lease_handoff(
        &mut self,
        force_renewal: bool,
    ) -> ParallelReconSnapshotClaimHandoffV1 {
        let EventPayload::RunClaimed(current) = &self.current_claim.payload else {
            panic!("harness current event is a claim")
        };
        let observed_at = Utc::now();
        let fresh_through = if force_renewal {
            current.lease_expires_at + chrono::Duration::milliseconds(1)
        } else {
            observed_at + chrono::Duration::minutes(1)
        };
        let outcome = self
            .store
            .refresh_parallel_recon_claim(
                self.run_id,
                ParallelReconClaimRefreshAuthority {
                    actor_id: self.actor_id,
                    runtime_instance_id: self.runtime_instance_id,
                    renewal_claim_id: RunClaimId::new(),
                    snapshot_capture_adoption_id: RepositorySnapshotCaptureClaimAdoptionId::new(),
                    child_adoption_ids: [
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                        birdcode_protocol::ChildClaimAdoptionId::new(),
                    ],
                    refreshed_at: RuntimeClockReading {
                        runtime_instance_id: self.runtime_instance_id,
                        monotonic_nanos: 200,
                        observed_at,
                    },
                    fresh_through,
                    renewed_lease_expires_at: fresh_through + chrono::Duration::minutes(10),
                },
            )
            .expect("Store resolves active lease handoff");
        match outcome {
            ParallelReconClaimRefreshOutcome::Fresh {
                claim,
                snapshot_claim: ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(snapshot_claim),
                ..
            }
            | ParallelReconClaimRefreshOutcome::Renewed {
                claim,
                snapshot_claim: ParallelReconSnapshotClaimHandoffOutcomeV1::Issued(snapshot_claim),
                ..
            } => {
                self.current_claim = claim.event;
                snapshot_claim
            }
            _ => panic!("active lease must issue release authority"),
        }
    }
}

pub(super) fn store_issued_fresh_handoff(
    manager: &WorkspaceManager,
) -> ParallelReconSnapshotClaimHandoffV1 {
    StoreClaimHarness::new(&manager.source_path).1
}
