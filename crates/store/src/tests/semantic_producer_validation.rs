use super::*;

#[test]
fn high_reasoning_provenance_rejects_backend_reasoning_and_raw_substitution() {
    let (_directory, store) = test_store();
    let session = Session::new(CreateSessionRequest {
        workspace_root: PathBuf::from("/tmp/high-reasoning-provenance").into(),
        title: Some("Exact high-reasoning provenance".to_owned()),
    });
    let mut run = run_for(&session);
    run.spec.backend.reasoning_effort = Some("high".to_owned());
    run.spec.backend.model = Some("gemma-fixture".to_owned());
    let prepared = prepared_payload(
        InferenceAttemptId::new(),
        TokenReservationId::new(),
        None,
        &fixture_artifact(&store, "prepared input"),
        0,
        digest('a'),
        0,
    );
    let expected = expected_backend_selection(&run, &prepared.backend_model);
    assert_eq!(expected.reasoning_effort.as_deref(), Some("high"));
    let evidence = fixture_artifact(&store, "normalized inference evidence");
    let other_evidence = fixture_artifact(&store, "substituted inference evidence");
    let base_event = EventEnvelope {
        id: EventId::new(),
        sequence: 1,
        session_id: session.id,
        run_id: Some(run.id),
        actor_id: ActorId::new(),
        causal_parent: None,
        occurred_at: Utc::now(),
        provenance: exact_model_provenance_for_run(
            &run,
            &prepared.backend_model.backend_id,
            &prepared.backend_model.model_id,
        ),
        payload: EventPayload::RunStateChanged {
            from: RunState::Queued,
            to: RunState::Running,
        },
    };

    assert!(require_exact_model_provenance(&base_event, &expected, None).is_ok());
    let mut observed_event = base_event.clone();
    observed_event.provenance.raw_artifact = Some(evidence.clone());
    assert!(require_exact_model_provenance(&observed_event, &expected, Some(&evidence)).is_ok());

    let mut attacks = Vec::new();
    let mut wrong_backend = base_event.clone();
    wrong_backend
        .provenance
        .backend
        .as_mut()
        .expect("fixture has a backend")
        .backend_id = "substituted-backend".to_owned();
    attacks.push((wrong_backend, None));
    let mut wrong_model = base_event.clone();
    wrong_model
        .provenance
        .backend
        .as_mut()
        .expect("fixture has a backend")
        .model = Some("substituted-model".to_owned());
    attacks.push((wrong_model, None));
    let mut missing_reasoning = base_event.clone();
    missing_reasoning
        .provenance
        .backend
        .as_mut()
        .expect("fixture has a backend")
        .reasoning_effort = None;
    attacks.push((missing_reasoning, None));
    let mut wrong_reasoning = base_event.clone();
    wrong_reasoning
        .provenance
        .backend
        .as_mut()
        .expect("fixture has a backend")
        .reasoning_effort = Some("medium".to_owned());
    attacks.push((wrong_reasoning, None));
    let mut prepared_with_raw = base_event.clone();
    prepared_with_raw.provenance.raw_artifact = Some(evidence.clone());
    attacks.push((prepared_with_raw, None));
    let mut observed_without_raw = base_event.clone();
    attacks.push((observed_without_raw.clone(), Some(&evidence)));
    observed_without_raw.provenance.raw_artifact = Some(other_evidence);
    attacks.push((observed_without_raw, Some(&evidence)));

    for (attack, expected_raw) in attacks {
        assert!(matches!(
            require_exact_model_provenance(&attack, &expected, expected_raw),
            Err(StoreError::InvalidStateEvent)
        ));
    }
}

#[test]
fn semantic_producer_rejection_cannot_replace_a_valid_observed_plan() {
    let mut fixture = semantic_producer_fixture(true);
    assert!(fixture.rejection.is_none());
    let EventPayload::PlannerInferencePrepared(prepared) = &fixture.prepared.payload else {
        panic!("producer fixture requires Prepared")
    };
    let decision_provenance =
        semantic_decision_provenance(&fixture.store, &fixture.run, &fixture.observed);
    let forged_validation = fixture
        .store
        .put_artifact(
            &serde_json::to_vec(&RetainedPlanValidation {
                status: "rejected".to_owned(),
                violations: vec!["forged rejection over valid output".to_owned()],
            })
            .expect("forged receipt should serialize"),
            PLAN_VALIDATION_MEDIA_TYPE,
        )
        .expect("forged receipt should persist as evidence");
    let before = fixture
        .store
        .events_for_run_after(fixture.run.id, 0)
        .expect("history should load")
        .events
        .len();

    assert!(matches!(
        fixture.store.append_event(NewEvent {
            session_id: fixture.session.id,
            run_id: Some(fixture.run.id),
            actor_id: fixture.supervisor,
            causal_parent: Some(fixture.observed.id),
            provenance: decision_provenance,
            payload: EventPayload::PlanProposalRejected(PlanProposalRejected {
                proposal_id: PlanProposalId::new(),
                inference_attempt_id: fixture.attempt_id,
                observed_event_id: fixture.observed.id,
                proposal_artifact: fixture.proposal_artifact,
                base_plan_revision: prepared.plan_revision,
                base_plan_digest: prepared.plan_digest.clone(),
                reason: PlanProposalRejectionReason::InvalidSchema,
                validation_evidence_artifact: forged_validation,
            }),
        }),
        Err(StoreError::InvalidStateEvent)
    ));
    assert_eq!(
        fixture
            .store
            .events_for_run_after(fixture.run.id, 0)
            .expect("rejected history should load")
            .events
            .len(),
        before
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one invalid producer observation drives reason, receipt, canonical-byte, and media attacks"
)]
fn semantic_producer_rejection_requires_exact_reason_receipt_and_media() {
    let mut fixture = semantic_producer_fixture(false);
    let (expected_reason, expected_violation) = fixture
        .rejection
        .take()
        .expect("invalid output should have one typed rejection classification");
    let EventPayload::PlannerInferencePrepared(prepared) = &fixture.prepared.payload else {
        panic!("producer fixture requires Prepared")
    };
    let decision_provenance =
        semantic_decision_provenance(&fixture.store, &fixture.run, &fixture.observed);
    let exact_receipt = RetainedPlanValidation {
        status: "rejected".to_owned(),
        violations: vec![expected_violation],
    };
    let exact_receipt_bytes =
        serde_json::to_vec(&exact_receipt).expect("exact receipt should serialize");
    let exact_validation = fixture
        .store
        .put_artifact(&exact_receipt_bytes, PLAN_VALIDATION_MEDIA_TYPE)
        .expect("exact receipt should persist");
    let wrong_receipt = fixture
        .store
        .put_artifact(
            &serde_json::to_vec(&RetainedPlanValidation {
                status: "rejected".to_owned(),
                violations: vec!["substituted typed violation".to_owned()],
            })
            .expect("wrong receipt should serialize"),
            PLAN_VALIDATION_MEDIA_TYPE,
        )
        .expect("wrong receipt should persist");
    let noncanonical_receipt = fixture
        .store
        .put_artifact(
            serde_json::to_string_pretty(&exact_receipt)
                .expect("pretty receipt should serialize")
                .as_bytes(),
            PLAN_VALIDATION_MEDIA_TYPE,
        )
        .expect("noncanonical receipt should persist");
    let wrong_media_validation = fixture
        .store
        .put_artifact(&exact_receipt_bytes, "application/json")
        .expect("wrong-media receipt should persist");
    let proposal_bytes = fixture
        .store
        .get_artifact(&fixture.proposal_artifact)
        .expect("proposal should load");
    let wrong_media_proposal = fixture
        .store
        .put_artifact(&proposal_bytes, "application/json")
        .expect("wrong-media proposal should persist");
    let wrong_reason = match expected_reason {
        PlanProposalRejectionReason::DependencyCycle => PlanProposalRejectionReason::InvalidSchema,
        _ => PlanProposalRejectionReason::DependencyCycle,
    };
    let attacks = [
        (
            fixture.proposal_artifact.clone(),
            exact_validation.clone(),
            wrong_reason,
        ),
        (
            fixture.proposal_artifact.clone(),
            wrong_receipt,
            expected_reason,
        ),
        (
            fixture.proposal_artifact.clone(),
            noncanonical_receipt,
            expected_reason,
        ),
        (
            fixture.proposal_artifact.clone(),
            wrong_media_validation,
            expected_reason,
        ),
        (
            wrong_media_proposal,
            exact_validation.clone(),
            expected_reason,
        ),
    ];
    let before = fixture
        .store
        .events_for_run_after(fixture.run.id, 0)
        .expect("history should load")
        .events
        .len();
    for (proposal_artifact, validation_evidence_artifact, reason) in attacks {
        assert!(matches!(
            fixture.store.append_event(NewEvent {
                session_id: fixture.session.id,
                run_id: Some(fixture.run.id),
                actor_id: fixture.supervisor,
                causal_parent: Some(fixture.observed.id),
                provenance: decision_provenance.clone(),
                payload: EventPayload::PlanProposalRejected(PlanProposalRejected {
                    proposal_id: PlanProposalId::new(),
                    inference_attempt_id: fixture.attempt_id,
                    observed_event_id: fixture.observed.id,
                    proposal_artifact,
                    base_plan_revision: prepared.plan_revision,
                    base_plan_digest: prepared.plan_digest.clone(),
                    reason,
                    validation_evidence_artifact,
                }),
            }),
            Err(StoreError::InvalidStateEvent)
        ));
        assert_eq!(
            fixture
                .store
                .events_for_run_after(fixture.run.id, 0)
                .expect("rejected history should load")
                .events
                .len(),
            before
        );
    }
    fixture
        .store
        .append_event(NewEvent {
            session_id: fixture.session.id,
            run_id: Some(fixture.run.id),
            actor_id: fixture.supervisor,
            causal_parent: Some(fixture.observed.id),
            provenance: decision_provenance,
            payload: EventPayload::PlanProposalRejected(PlanProposalRejected {
                proposal_id: PlanProposalId::new(),
                inference_attempt_id: fixture.attempt_id,
                observed_event_id: fixture.observed.id,
                proposal_artifact: fixture.proposal_artifact,
                base_plan_revision: prepared.plan_revision,
                base_plan_digest: prepared.plan_digest.clone(),
                reason: expected_reason,
                validation_evidence_artifact: exact_validation,
            }),
        })
        .expect("the exact typed rejection and canonical receipt should persist");
    assert_eq!(
        fixture
            .store
            .events_for_run_after(fixture.run.id, 0)
            .expect("accepted rejection history should load")
            .events
            .len(),
        before + 1
    );
}

#[test]
fn semantic_producer_decisions_revalidate_execution_policy_after_observed() {
    for valid_output in [true, false] {
        let mut fixture = semantic_producer_fixture(valid_output);
        let EventPayload::PlannerInferencePrepared(prepared) = &fixture.prepared.payload else {
            panic!("producer fixture requires Prepared")
        };
        let decision_provenance =
            semantic_decision_provenance(&fixture.store, &fixture.run, &fixture.observed);
        let base_plan_revision = prepared.plan_revision;
        let base_plan_digest = prepared.plan_digest.clone();
        let payload = if valid_output {
            let validation_evidence_artifact = semantic_plan_validation_artifact(&fixture.store);
            let accepted_plan_digest = Sha256Digest::parse(fixture.output_artifact.sha256.clone())
                .expect("accepted plan digest should be canonical");
            EventPayload::PlanProposalAccepted(PlanProposalAccepted {
                proposal_id: PlanProposalId::new(),
                inference_attempt_id: fixture.attempt_id,
                observed_event_id: fixture.observed.id,
                proposal_artifact: fixture.proposal_artifact.clone(),
                previous_plan_revision: base_plan_revision,
                previous_plan_digest: base_plan_digest.clone(),
                accepted_plan_revision: base_plan_revision + 1,
                accepted_plan_digest,
                accepted_plan_artifact: fixture.output_artifact.clone(),
                validation_evidence_artifact,
            })
        } else {
            let (reason, violation) = fixture
                .rejection
                .take()
                .expect("invalid output should have a typed rejection");
            let validation_evidence_artifact = fixture
                .store
                .put_artifact(
                    &serde_json::to_vec(&RetainedPlanValidation {
                        status: "rejected".to_owned(),
                        violations: vec![violation],
                    })
                    .expect("exact rejection receipt should serialize"),
                    PLAN_VALIDATION_MEDIA_TYPE,
                )
                .expect("exact rejection receipt should persist");
            EventPayload::PlanProposalRejected(PlanProposalRejected {
                proposal_id: PlanProposalId::new(),
                inference_attempt_id: fixture.attempt_id,
                observed_event_id: fixture.observed.id,
                proposal_artifact: fixture.proposal_artifact.clone(),
                base_plan_revision,
                base_plan_digest: base_plan_digest.clone(),
                reason,
                validation_evidence_artifact,
            })
        };
        let policy_path = fixture
            .store
            .artifact_path(&fixture.execution_policy_artifact.sha256)
            .expect("execution policy path should resolve");
        if valid_output {
            fs::write(policy_path, b"{}")
                .expect("accept attack should corrupt the execution policy");
        } else {
            fs::remove_file(policy_path).expect("reject attack should delete the execution policy");
        }
        let before = fixture
            .store
            .events_for_run_after(fixture.run.id, 0)
            .expect("history should load")
            .events
            .len();

        let result = fixture.store.append_event(NewEvent {
            session_id: fixture.session.id,
            run_id: Some(fixture.run.id),
            actor_id: fixture.supervisor,
            causal_parent: Some(fixture.observed.id),
            provenance: decision_provenance,
            payload,
        });
        let policy_failure = match &result {
            Err(StoreError::ArtifactIntegrity) => valid_output,
            Err(StoreError::Io(error)) => !valid_output && error.kind() == io::ErrorKind::NotFound,
            _ => false,
        };
        assert!(
            policy_failure,
            "valid_output={valid_output}, result={result:?}"
        );
        assert_eq!(
            fixture
                .store
                .events_for_run_after(fixture.run.id, 0)
                .expect("rejected history should load")
                .events
                .len(),
            before
        );
    }
}
