use super::*;
use crate::tests::{
    ExactPairFixture, default_exact_pair_fixture,
    parallel_recon_bootstrap::bootstrap_default_exact_pair,
};
use birdcode_protocol::{
    ChildModelCallId, RuntimeClockReading, TokenReservation, TokenReservationId,
    UnknownInferenceBoundary,
};
use chrono::Utc;
use std::sync::{Arc, Barrier, mpsc};

fn preparation_authority(
    runtime_instance_id: birdcode_protocol::RuntimeInstanceId,
) -> ChildRepositoryExplorerPreparationAuthority {
    ChildRepositoryExplorerPreparationAuthority {
        event_id: EventId::new(),
        model_call_id: ChildModelCallId::new(),
        token_reservation: TokenReservation {
            id: TokenReservationId::new(),
            reserved_tokens: 1_048_576,
            max_output_tokens: 1_024,
        },
        prepared_at: RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos: 40,
            observed_at: Utc::now(),
        },
    }
}

fn close_abandoned_dispatch(
    fixture: &mut ExactPairFixture,
    prepared_event_id: EventId,
    run_id: RunId,
) {
    fixture
        .store
        .reconcile_child_repository_explorer_turn_unknown(
            run_id,
            ChildRepositoryExplorerUnknownAuthority {
                event_id: EventId::new(),
                prepared_event_id,
                boundary: UnknownInferenceBoundary::Restart,
                boundary_at: RuntimeClockReading {
                    runtime_instance_id: fixture.runtime_instance_id,
                    monotonic_nanos: 50,
                    observed_at: Utc::now(),
                },
            },
        )
        .expect("winner closes the abandoned dispatch boundary");
}

#[test]
fn fresh_prepare_issues_one_affine_handoff_while_replay_and_recovery_are_evidence_only() {
    fn assert_send_static<T: Send + 'static>() {}

    assert_send_static::<ChildModelDispatchHandoff>();
    assert_eq!(
        std::mem::size_of::<ChildModelDispatchHandoff>(),
        std::mem::size_of::<usize>()
    );

    let mut fixture = default_exact_pair_fixture();
    let bootstrap = bootstrap_default_exact_pair(&mut fixture);
    let child = &bootstrap.children[0];
    let work_order_id = child.projection.spec.work_order_id;
    let authority = preparation_authority(fixture.runtime_instance_id);

    let first = fixture
        .store
        .prepare_child_repository_explorer_dispatch(
            fixture.run.id,
            work_order_id,
            authority.clone(),
        )
        .expect("fresh preparation commits");
    let (evidence, dispatch) = match first {
        ChildModelDispatchPreparationOutcome::Appended { evidence, dispatch } => {
            (evidence, dispatch)
        }
        ChildModelDispatchPreparationOutcome::AlreadyPresent { .. } => {
            panic!("fresh preparation must own the sole dispatch handoff")
        }
    };
    assert_eq!(evidence.prepared_event.id, authority.event_id);
    assert_eq!(dispatch.prepared_event(), &evidence.prepared_event);
    let request = dispatch.into_backend_request();
    assert_eq!(
        request.model_id().as_str(),
        child.projection.spec.resolved_model.model_id
    );
    assert_eq!(request.max_output_tokens(), 1_024);

    let replay = fixture
        .store
        .prepare_child_repository_explorer_dispatch(fixture.run.id, work_order_id, authority)
        .expect("exact replay validates");
    let ChildModelDispatchPreparationOutcome::AlreadyPresent {
        evidence: replay_evidence,
    } = replay
    else {
        panic!("exact replay must not recreate dispatch authority")
    };
    assert_eq!(replay_evidence, evidence);
    assert_eq!(
        fixture
            .store
            .recover_child_repository_explorer_dispatch(fixture.run.id, work_order_id)
            .expect("recovery validates"),
        Some(evidence)
    );
}

#[test]
fn exact_writer_after_initial_miss_converges_after_winner_closes_the_boundary() {
    let mut fixture = default_exact_pair_fixture();
    let bootstrap = bootstrap_default_exact_pair(&mut fixture);
    let work_order_id = bootstrap.children[0].projection.spec.work_order_id;
    let run_id = fixture.run.id;
    let authority = preparation_authority(fixture.runtime_instance_id);
    let database = fixture.database.clone();
    let artifacts = fixture.artifacts.clone();
    let losing_authority = authority.clone();
    let (missed_sender, missed_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);

    let loser = std::thread::spawn(move || {
        let mut store = Store::open(database, artifacts).expect("losing Store opens");
        store.prepare_child_repository_explorer_dispatch_after_initial_miss(
            run_id,
            work_order_id,
            &losing_authority,
            || {
                missed_sender
                    .send(())
                    .expect("loser reports the initial miss");
                resume_receiver
                    .recv()
                    .expect("loser resumes after winner commit");
            },
            || {},
        )
    });

    missed_receiver
        .recv()
        .expect("loser reaches the deterministic race window");
    let winner = fixture
        .store
        .prepare_child_repository_explorer_dispatch(run_id, work_order_id, authority.clone())
        .expect("winner commits");
    let (winning_evidence, dispatch) = match winner {
        ChildModelDispatchPreparationOutcome::Appended { evidence, dispatch } => {
            (evidence, dispatch)
        }
        ChildModelDispatchPreparationOutcome::AlreadyPresent { .. } => {
            panic!("the only writer past the miss window must append")
        }
    };
    assert_eq!(dispatch.prepared_event(), &winning_evidence.prepared_event);
    drop(dispatch);
    close_abandoned_dispatch(&mut fixture, winning_evidence.prepared_event.id, run_id);
    resume_sender
        .send(())
        .expect("loser may continue after winner commit");
    let losing_outcome = loser
        .join()
        .expect("losing writer joins")
        .expect("losing writer converges");
    let ChildModelDispatchPreparationOutcome::AlreadyPresent {
        evidence: losing_evidence,
    } = losing_outcome
    else {
        panic!("losing writer must receive replay-only evidence")
    };

    assert_eq!(winning_evidence, losing_evidence);
    let mut reopened =
        Store::open(&fixture.database, &fixture.artifacts).expect("recovery Store reopens");
    assert_eq!(
        reopened
            .recover_child_repository_explorer_dispatch(run_id, work_order_id)
            .expect("reopened recovery validates the closed boundary"),
        None
    );
    let exact_replay = reopened
        .prepare_child_repository_explorer_dispatch(run_id, work_order_id, authority)
        .expect("reopened exact replay validates");
    let ChildModelDispatchPreparationOutcome::AlreadyPresent {
        evidence: reopened_evidence,
    } = exact_replay
    else {
        panic!("closed exact replay must never recreate dispatch authority")
    };
    assert_eq!(reopened_evidence, winning_evidence);
}

#[test]
fn exact_writer_after_build_converges_when_winner_advances_before_append() {
    let mut fixture = default_exact_pair_fixture();
    let bootstrap = bootstrap_default_exact_pair(&mut fixture);
    let work_order_id = bootstrap.children[0].projection.spec.work_order_id;
    let run_id = fixture.run.id;
    let authority = preparation_authority(fixture.runtime_instance_id);
    let database = fixture.database.clone();
    let artifacts = fixture.artifacts.clone();
    let losing_authority = authority.clone();
    let (built_sender, built_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);

    let loser = std::thread::spawn(move || {
        let mut store = Store::open(database, artifacts).expect("losing Store opens");
        store.prepare_child_repository_explorer_dispatch_after_initial_miss(
            run_id,
            work_order_id,
            &losing_authority,
            || {},
            || {
                built_sender
                    .send(())
                    .expect("loser reports its completed build");
                resume_receiver
                    .recv()
                    .expect("loser resumes after winner advances");
            },
        )
    });

    built_receiver
        .recv()
        .expect("loser reaches the deterministic pre-append window");
    let winner = fixture
        .store
        .prepare_child_repository_explorer_dispatch(run_id, work_order_id, authority)
        .expect("winner commits");
    let (winning_evidence, dispatch) = match winner {
        ChildModelDispatchPreparationOutcome::Appended { evidence, dispatch } => {
            (evidence, dispatch)
        }
        ChildModelDispatchPreparationOutcome::AlreadyPresent { .. } => {
            panic!("the only writer allowed to append must own the handoff")
        }
    };
    drop(dispatch);
    close_abandoned_dispatch(&mut fixture, winning_evidence.prepared_event.id, run_id);
    resume_sender
        .send(())
        .expect("loser may append after winner advances");
    let losing_outcome = loser
        .join()
        .expect("losing writer joins")
        .expect("losing append converges");
    let ChildModelDispatchPreparationOutcome::AlreadyPresent {
        evidence: losing_evidence,
    } = losing_outcome
    else {
        panic!("losing append must receive replay-only evidence")
    };
    assert_eq!(losing_evidence, winning_evidence);
}

#[test]
fn exact_event_identity_rejects_every_runtime_authority_substitution() {
    let mut fixture = default_exact_pair_fixture();
    let bootstrap = bootstrap_default_exact_pair(&mut fixture);
    let left_work_order_id = bootstrap.children[0].projection.spec.work_order_id;
    let right_work_order_id = bootstrap.children[1].projection.spec.work_order_id;
    let run_id = fixture.run.id;
    let authority = preparation_authority(fixture.runtime_instance_id);
    let prepared = fixture
        .store
        .prepare_child_repository_explorer_dispatch(run_id, left_work_order_id, authority.clone())
        .expect("fresh preparation commits");
    assert!(matches!(
        prepared,
        ChildModelDispatchPreparationOutcome::Appended { .. }
    ));

    let mut changed_model_call = authority.clone();
    changed_model_call.model_call_id = ChildModelCallId::new();
    let mut changed_reservation = authority.clone();
    changed_reservation.token_reservation.id = TokenReservationId::new();
    let mut changed_clock = authority.clone();
    changed_clock.prepared_at.monotonic_nanos += 1;

    for (work_order_id, changed_authority) in [
        (left_work_order_id, changed_model_call),
        (left_work_order_id, changed_reservation),
        (left_work_order_id, changed_clock),
        (right_work_order_id, authority),
    ] {
        assert!(matches!(
            fixture.store.prepare_child_repository_explorer_dispatch(
                run_id,
                work_order_id,
                changed_authority,
            ),
            Err(StoreError::IdentifiedEventConflict)
        ));
    }
}

#[test]
fn concurrent_same_authority_prepare_issues_exactly_one_dispatch_handoff() {
    let mut fixture = default_exact_pair_fixture();
    let bootstrap = bootstrap_default_exact_pair(&mut fixture);
    let work_order_id = bootstrap.children[0].projection.spec.work_order_id;
    let run_id = fixture.run.id;
    let authority = preparation_authority(fixture.runtime_instance_id);
    let barrier = Arc::new(Barrier::new(2));

    let handles = (0..2)
        .map(|_| {
            let database = fixture.database.clone();
            let artifacts = fixture.artifacts.clone();
            let authority = authority.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut store = Store::open(database, artifacts).expect("Store opens");
                barrier.wait();
                store
                    .prepare_child_repository_explorer_dispatch(run_id, work_order_id, authority)
                    .map(|outcome| {
                        matches!(
                            outcome,
                            ChildModelDispatchPreparationOutcome::Appended { .. }
                        )
                    })
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().expect("prepare thread joins"))
        .collect::<Result<Vec<_>, _>>()
        .expect("both preparations converge");

    assert_eq!(outcomes.iter().filter(|fresh| **fresh).count(), 1);
    assert!(
        fixture
            .store
            .recover_child_repository_explorer_dispatch(run_id, work_order_id)
            .expect("winning preparation is recoverable")
            .is_some()
    );
}
