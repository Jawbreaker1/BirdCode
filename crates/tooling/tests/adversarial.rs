#![cfg(unix)]

use birdcode_protocol::{
    ArtifactRef, ChildActorId, ChildAttemptId, ChildContextId, ChildExecutionBinding,
    ChildExecutionId, ChildLocalPlanBindingV1, ChildLocalPlanId, ChildModelCallId, ChildToolCallId,
    ChildToolOperation, ChildToolUnknownBoundary, ChildToolUnknownReason,
    ChildValidatedActionBindingV1, ChildValidatedActionId, ChildWorkOrderId, EventId,
    REPOSITORY_BROKER_CONTRACT_VERSION, REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE,
    REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES, REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES,
    REPOSITORY_TOOL_POLICY_MEDIA_TYPE, REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE,
    RepositoryBrokerEpochStateV1, RepositoryBrokerInstanceId, RepositoryCleanupReportV2,
    RepositoryFileIdentityV1, RepositoryFilesystemEffectV1, RepositoryInterruptionBoundaryV1,
    RepositoryLiteralFileScanV1, RepositoryLiteralMatchV1, RepositoryNodeKindV1,
    RepositoryRelativePathV1, RepositoryRootBindingV1, RepositorySnapshotBindingV1,
    RepositorySnapshotLeaseBindingV1, RepositorySnapshotLeaseId, RepositorySnapshotLeaseModeV1,
    RepositoryToolAuthorizationDecisionV2, RepositoryToolBoundsV1, RepositoryToolGrantId,
    RepositoryToolGrantV1, RepositoryToolObservedTerminalV2, RepositoryToolReceiptAuthorityV2,
    RepositoryToolResultV2, RepositoryToolUnknownTimingV2, RepositoryTreeEntryV1,
    RepositoryUnixFileIdentityV1, RuntimeClockReading, Sha256Digest,
    decode_repository_tool_result_v2, encode_repository_tool_result_v2,
    repository_tool_result_v2_preflight_size,
};
use birdcode_tooling::{
    BrokerOpenError, PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2, RepositoryToolBroker,
    RepositoryToolExecuteInputV2, RepositoryToolInterruptionInputV2, RepositoryToolPrepareInputV2,
    RepositoryToolRestartReconciliationInputV2, RepositoryToolTerminalV2, RetainedArtifactV2,
    project_observed_event_v2, project_prepared_event_v2, project_unknown_event_v2,
    verify_terminal_output_v2,
};
use serde_json::json;
use std::cell::Cell;
use std::fs;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::path::Path;
use tempfile::TempDir;
use uuid::Uuid;

fn uuid(index: u128) -> Uuid {
    Uuid::from_u128(index)
}

fn artifact(index: u8, media_type: &str) -> ArtifactRef {
    let bytes = [index];
    ArtifactRef {
        sha256: Sha256Digest::of_bytes(&bytes).as_str().to_owned(),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_owned(),
    }
}

fn retained(media_type: &str, bytes: Vec<u8>) -> RetainedArtifactV2 {
    RetainedArtifactV2 {
        artifact: ArtifactRef {
            sha256: Sha256Digest::of_bytes(&bytes).as_str().to_owned(),
            size_bytes: u64::try_from(bytes.len()).expect("test artifact length fits u64"),
            media_type: media_type.to_owned(),
        },
        bytes,
    }
}

fn runtime_clock(index: u128) -> RuntimeClockReading {
    serde_json::from_value(json!({
        "runtime_instance_id": uuid(90).to_string(),
        "monotonic_nanos": u64::try_from(index).expect("fixture clock fits u64"),
        "observed_at": "2026-07-21T00:00:00Z"
    }))
    .expect("runtime clock fixture decodes")
}

fn root_identity(root: &Path) -> RepositoryFileIdentityV1 {
    let metadata = fs::symlink_metadata(root).expect("root metadata");
    RepositoryFileIdentityV1::Unix(RepositoryUnixFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        byte_len: i64::try_from(metadata.size()).expect("fixture size fits i64"),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn bounds() -> RepositoryToolBoundsV1 {
    RepositoryToolBoundsV1 {
        max_calls_per_broker: 10_000,
        max_request_bytes: 2 * 1024 * 1024,
        max_path_components: 256,
        max_path_bytes: 256 * 1024,
        max_component_bytes: 16 * 1024,
        max_read_bytes: REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
        max_tree_depth: 32,
        max_tree_entries: 16_384,
        max_directory_entries_scanned: 65_536,
        max_directory_name_bytes_scanned: 64 * 1024 * 1024,
        max_search_pattern_bytes: 64 * 1024,
        max_search_depth: 32,
        max_search_files: 8_192,
        max_search_matches: 65_536,
        max_search_bytes_per_file: 8 * 1024 * 1024,
        max_search_total_bytes: 64 * 1024 * 1024,
        max_artifact_bytes: REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
    }
}

fn tree_grant(id: RepositoryToolGrantId) -> RepositoryToolGrantV1 {
    RepositoryToolGrantV1::RepositoryTree {
        tool_grant_id: id,
        max_path_components: 256,
        max_path_bytes: 256 * 1024,
        max_component_bytes: 16 * 1024,
        max_depth: 32,
        max_entries: 16_384,
    }
}

fn read_grant(id: RepositoryToolGrantId) -> RepositoryToolGrantV1 {
    RepositoryToolGrantV1::RepositoryFileRead {
        tool_grant_id: id,
        max_path_components: 256,
        max_path_bytes: 256 * 1024,
        max_component_bytes: 16 * 1024,
        max_offset_bytes: REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
        max_bytes: REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
    }
}

fn search_grant(id: RepositoryToolGrantId) -> RepositoryToolGrantV1 {
    RepositoryToolGrantV1::LiteralSearch {
        tool_grant_id: id,
        max_path_components: 256,
        max_path_bytes: 256 * 1024,
        max_component_bytes: 16 * 1024,
        max_literal_bytes: 64 * 1024,
        max_depth: 32,
        max_files: 8_192,
        max_matches: 65_536,
        max_bytes_per_file: 8 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
    }
}

fn authority_with_bounds(
    root: &Path,
    grants: Vec<RepositoryToolGrantV1>,
    broker_bounds: RepositoryToolBoundsV1,
) -> RepositoryToolReceiptAuthorityV2 {
    let policy_digest = Sha256Digest::of_bytes(b"test-policy-v2");
    RepositoryToolReceiptAuthorityV2 {
        policy_id: "test-policy-v2".to_owned(),
        policy_artifact: ArtifactRef {
            sha256: policy_digest.as_str().to_owned(),
            size_bytes: 14,
            media_type: REPOSITORY_TOOL_POLICY_MEDIA_TYPE.to_owned(),
        },
        policy_digest,
        snapshot: RepositorySnapshotBindingV1 {
            snapshot_id: "snapshot-v2".to_owned(),
            declared_snapshot_digest: Sha256Digest::of_bytes(b"snapshot-v2"),
            immutability_lease: RepositorySnapshotLeaseBindingV1 {
                lease_id: RepositorySnapshotLeaseId::from_uuid(uuid(51)),
                mode: RepositorySnapshotLeaseModeV1::MacOsCooperativeQuiescedReadOnlyDiskImage,
                lease_artifact: artifact(52, REPOSITORY_SNAPSHOT_LEASE_MEDIA_TYPE),
                lease_digest: Sha256Digest::of_bytes(&[52]),
            },
        },
        root: RepositoryRootBindingV1 {
            repository_root_id: "fixture-root".to_owned(),
            descriptor_identity: root_identity(root),
        },
        broker_bounds,
        tool_grants: grants,
    }
}

fn authority(root: &Path, grants: Vec<RepositoryToolGrantV1>) -> RepositoryToolReceiptAuthorityV2 {
    authority_with_bounds(root, grants, bounds())
}

fn epoch(active: u128, closed: &[u128]) -> RepositoryBrokerEpochStateV1 {
    RepositoryBrokerEpochStateV1 {
        active_broker_instance_id: RepositoryBrokerInstanceId::from_uuid(uuid(active)),
        closed_broker_instance_ids: closed
            .iter()
            .copied()
            .map(uuid)
            .map(RepositoryBrokerInstanceId::from_uuid)
            .collect(),
    }
}

fn binding() -> ChildExecutionBinding {
    ChildExecutionBinding {
        work_order_id: ChildWorkOrderId::from_uuid(uuid(61)),
        execution_id: ChildExecutionId::from_uuid(uuid(62)),
        attempt_id: ChildAttemptId::from_uuid(uuid(63)),
        child_actor_id: ChildActorId::from_uuid(uuid(64)),
        context_id: ChildContextId::from_uuid(uuid(65)),
        work_order_digest: Sha256Digest::of_bytes(b"work-order"),
        context_manifest_digest: Sha256Digest::of_bytes(b"context"),
    }
}

fn action_binding(index: u128) -> ChildValidatedActionBindingV1 {
    ChildValidatedActionBindingV1 {
        action_id: ChildValidatedActionId::from_uuid(uuid(1_000 + index)),
        source_model_call_id: ChildModelCallId::from_uuid(uuid(2_000 + index)),
        source_model_call_ordinal: u32::try_from(index).expect("fixture ordinal fits u32"),
        source_model_observed_event_id: EventId::from_uuid(uuid(3_000 + index)),
        source_model_evidence_digest: Sha256Digest::of_bytes(b"model-evidence"),
        source_plan: ChildLocalPlanBindingV1 {
            plan_id: ChildLocalPlanId::from_uuid(uuid(4_000 + index)),
            revision: 2,
            plan_digest: Sha256Digest::of_bytes(b"local-plan"),
        },
        active_plan_step_id: None,
        completion_handoff_id: None,
        validated_action_artifact: artifact(66, "application/vnd.birdcode.action.v1+json"),
        validated_action_digest: Sha256Digest::of_bytes(&[66]),
    }
}

fn path(components: &[&[u8]]) -> RepositoryRelativePathV1 {
    RepositoryRelativePathV1::Unix {
        components: components
            .iter()
            .map(|component| component.to_vec())
            .collect(),
    }
}

fn prepare(
    broker: &RepositoryToolBroker,
    index: u128,
    grant: RepositoryToolGrantId,
    operation: ChildToolOperation,
) -> Result<PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2> {
    broker.prepare(RepositoryToolPrepareInputV2 {
        parameters: birdcode_protocol::RepositoryToolCanonicalParametersV1 {
            schema_version: REPOSITORY_BROKER_CONTRACT_VERSION,
            binding: binding(),
            tool_call_id: ChildToolCallId::from_uuid(uuid(5_000 + index)),
            tool_ordinal: u32::try_from(index).expect("fixture ordinal fits u32"),
            action_binding: action_binding(index),
            tool_grant_id: grant,
            operation,
        },
        runtime_prepared_at: runtime_clock(10 + index),
    })
}

fn execute(
    broker: &RepositoryToolBroker,
    prepared: &PreparedRepositoryToolCallV2,
    index: u128,
) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2> {
    broker.execute(
        RepositoryToolExecuteInputV2 {
            prepared: prepared.clone(),
            prepared_event_id: EventId::from_uuid(uuid(6_000 + index)),
        },
        || runtime_clock(100 + index),
    )
}

fn successful_result_artifact(terminal: &RepositoryToolTerminalV2) -> &RetainedArtifactV2 {
    let RepositoryToolTerminalV2::Observed(observed) = terminal else {
        panic!("expected observed terminal");
    };
    let RepositoryToolObservedTerminalV2::Succeeded { result_artifact } =
        &observed.receipt.terminal
    else {
        panic!("expected successful terminal");
    };
    observed
        .supporting_artifacts
        .iter()
        .find(|candidate| candidate.artifact == *result_artifact)
        .expect("result artifact is supplied separately")
}

fn successful_result(terminal: &RepositoryToolTerminalV2) -> RepositoryToolResultV2 {
    let artifact = successful_result_artifact(terminal);
    decode_repository_tool_result_v2(&artifact.bytes).expect("result uses canonical Protocol codec")
}

fn observed_failure(
    terminal: &RepositoryToolTerminalV2,
) -> &birdcode_protocol::RepositoryToolFailureV1 {
    let RepositoryToolTerminalV2::Observed(observed) = terminal else {
        panic!("expected observed terminal");
    };
    let RepositoryToolObservedTerminalV2::Failed { failure, .. } = &observed.receipt.terminal
    else {
        panic!("expected failed terminal");
    };
    failure
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end test proves all operation/result/projection branches share Protocol v7"
)]
fn all_operations_use_protocol_v7_results_and_lossless_unix_paths() {
    let root = TempDir::new().expect("temp root");
    fs::create_dir(root.path().join("src")).expect("src directory");
    fs::write(
        root.path().join("src/lib.rs"),
        b"prefix [a-z].* literal suffix\n",
    )
    .expect("source fixture");
    let native_name = std::ffi::OsString::from_vec("日本語-e\u{301}.bin".as_bytes().to_vec());
    fs::write(root.path().join(&native_name), [0_u8, 1, 2, 255]).expect("binary fixture");

    let tree_id = RepositoryToolGrantId::from_uuid(uuid(101));
    let read_id = RepositoryToolGrantId::from_uuid(uuid(102));
    let search_id = RepositoryToolGrantId::from_uuid(uuid(103));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(
            root.path(),
            vec![
                tree_grant(tree_id),
                read_grant(read_id),
                search_grant(search_id),
            ],
        ),
        epoch(201, &[]),
    )
    .expect("broker opens exact root");

    let tree = prepare(
        &broker,
        1,
        tree_id,
        ChildToolOperation::RepositoryTree {
            path: RepositoryRelativePathV1::default(),
            max_depth: 3,
            max_entries: 20,
        },
    )
    .expect("tree prepares");
    assert_eq!(
        tree.receipt.authorization,
        RepositoryToolAuthorizationDecisionV2::Authorized
    );
    let prepared_event = project_prepared_event_v2(&tree).expect("Prepared projects exactly");
    assert_eq!(prepared_event.tool_call_id, tree.receipt.tool_call_id);
    assert_eq!(
        prepared_event.prepared_receipt_artifact,
        tree.prepared_receipt.artifact
    );
    let tree_terminal = execute(&broker, &tree, 1).expect("tree executes");
    assert!(verify_terminal_output_v2(&tree, &tree_terminal));
    let RepositoryToolTerminalV2::Observed(tree_observed) = &tree_terminal else {
        panic!("expected observed tree terminal");
    };
    let observed_event =
        project_observed_event_v2(&tree, tree_observed).expect("Observed projects exactly");
    assert_eq!(
        observed_event.terminal_receipt_artifact,
        tree_observed.terminal_receipt.artifact
    );
    let RepositoryToolResultV2::RepositoryTree(tree_result) = successful_result(&tree_terminal)
    else {
        panic!("expected tree result");
    };
    assert!(tree_result.entries.iter().any(|entry| {
        entry.path.unix_components() == ["日本語-e\u{301}.bin".as_bytes().to_vec()]
    }));

    let read = prepare(
        &broker,
        2,
        read_id,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"src", b"lib.rs"]),
            offset_bytes: 7,
            max_bytes: 8,
        },
    )
    .expect("read prepares");
    let read_terminal = execute(&broker, &read, 2).expect("read executes");
    assert!(verify_terminal_output_v2(&read, &read_terminal));
    let RepositoryToolResultV2::RepositoryFileRead(read_result) = successful_result(&read_terminal)
    else {
        panic!("expected read result");
    };
    assert_eq!(read_result.bytes, b"[a-z].* ");
    let RepositoryToolTerminalV2::Observed(read_observed) = &read_terminal else {
        panic!("expected observed read");
    };
    assert!(
        String::from_utf8_lossy(&read_observed.supporting_artifacts[0].bytes)
            .contains("\"bytes_base64\"")
    );

    let search = prepare(
        &broker,
        3,
        search_id,
        ChildToolOperation::LiteralSearch {
            path: RepositoryRelativePathV1::default(),
            literal_utf8: "[a-z].*".to_owned(),
            max_depth: 4,
            max_files: 20,
            max_matches: 20,
            max_bytes_per_file: 1024,
            max_total_bytes: 4096,
        },
    )
    .expect("search prepares");
    let search_terminal = execute(&broker, &search, 3).expect("search executes");
    assert!(verify_terminal_output_v2(&search, &search_terminal));
    let RepositoryToolResultV2::LiteralSearch(search_result) = successful_result(&search_terminal)
    else {
        panic!("expected literal search result");
    };
    assert_eq!(search_result.matches.len(), 1);
    assert_eq!(search_result.matches[0].byte_offset, 7);
}

#[test]
fn execute_samples_finish_clock_once_after_descriptor_confined_read() {
    let root = TempDir::new().expect("temp root");
    let file = root.path().join("clock-ordering.txt");
    fs::write(&file, b"read-before-clock").expect("initial file");
    let grant = RepositoryToolGrantId::from_uuid(uuid(10_001));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![read_grant(grant)]),
        epoch(10_002, &[]),
    )
    .expect("broker");
    let prepared = prepare(
        &broker,
        10,
        grant,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"clock-ordering.txt"]),
            offset_bytes: 0,
            max_bytes: 64,
        },
    )
    .expect("read prepares");
    let clock_calls = Cell::new(0_u32);
    let expected_finished_at = runtime_clock(10_003);

    let terminal = broker
        .execute(
            RepositoryToolExecuteInputV2 {
                prepared: prepared.clone(),
                prepared_event_id: EventId::from_uuid(uuid(10_004)),
            },
            || {
                clock_calls.set(clock_calls.get() + 1);
                fs::write(&file, b"clock-ran-after-read").expect("clock ordering marker");
                expected_finished_at.clone()
            },
        )
        .expect("read executes");

    assert_eq!(clock_calls.get(), 1, "finish clock is sampled exactly once");
    let RepositoryToolResultV2::RepositoryFileRead(result) = successful_result(&terminal) else {
        panic!("expected read result");
    };
    assert_eq!(
        result.bytes, b"read-before-clock",
        "the descriptor-confined read completed before the clock callback mutated the file"
    );
    let RepositoryToolTerminalV2::Observed(observed) = terminal else {
        panic!("expected observed terminal");
    };
    assert_eq!(observed.receipt.runtime_finished_at, expected_finished_at);
    assert_eq!(
        fs::read(file).expect("ordering marker remains"),
        b"clock-ran-after-read"
    );
}

#[test]
fn authorization_denial_samples_finish_clock_exactly_once() {
    let root = TempDir::new().expect("temp root");
    let granted = RepositoryToolGrantId::from_uuid(uuid(10_101));
    let ungranted = RepositoryToolGrantId::from_uuid(uuid(10_102));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![read_grant(granted)]),
        epoch(10_103, &[]),
    )
    .expect("broker");
    let prepared = prepare(
        &broker,
        11,
        ungranted,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"never-opened"]),
            offset_bytes: 0,
            max_bytes: 1,
        },
    )
    .expect("denial prepares");
    assert!(matches!(
        prepared.receipt.authorization,
        RepositoryToolAuthorizationDecisionV2::Denied { .. }
    ));
    let clock_calls = Cell::new(0_u32);
    let expected_finished_at = runtime_clock(10_104);

    let terminal = broker
        .execute(
            RepositoryToolExecuteInputV2 {
                prepared: prepared.clone(),
                prepared_event_id: EventId::from_uuid(uuid(10_105)),
            },
            || {
                clock_calls.set(clock_calls.get() + 1);
                expected_finished_at.clone()
            },
        )
        .expect("denial closes");

    assert_eq!(clock_calls.get(), 1, "finish clock is sampled exactly once");
    let RepositoryToolTerminalV2::Observed(observed) = terminal else {
        panic!("expected observed terminal");
    };
    assert!(matches!(
        observed.receipt.terminal,
        RepositoryToolObservedTerminalV2::AuthorizationDenied { .. }
    ));
    assert_eq!(
        observed.receipt.effect,
        RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted
    );
    assert_eq!(observed.receipt.runtime_finished_at, expected_finished_at);
}

#[test]
fn worst_width_empty_result_preflight_denies_every_tool_before_filesystem_access() {
    let root = TempDir::new().expect("temp root");
    let missing = path(&[b"missing"]);
    let cases = [
        (
            11_u128,
            RepositoryToolGrantId::from_uuid(uuid(11_001)),
            tree_grant(RepositoryToolGrantId::from_uuid(uuid(11_001))),
            ChildToolOperation::RepositoryTree {
                path: missing.clone(),
                max_depth: 1,
                max_entries: 1,
            },
        ),
        (
            12_u128,
            RepositoryToolGrantId::from_uuid(uuid(11_002)),
            read_grant(RepositoryToolGrantId::from_uuid(uuid(11_002))),
            ChildToolOperation::RepositoryFileRead {
                path: missing.clone(),
                offset_bytes: 0,
                max_bytes: 1,
            },
        ),
        (
            13_u128,
            RepositoryToolGrantId::from_uuid(uuid(11_003)),
            search_grant(RepositoryToolGrantId::from_uuid(uuid(11_003))),
            ChildToolOperation::LiteralSearch {
                path: missing,
                literal_utf8: "literal".to_owned(),
                max_depth: 1,
                max_files: 1,
                max_matches: 1,
                max_bytes_per_file: 1,
                max_total_bytes: 1,
            },
        ),
    ];

    for (index, grant_id, grant, operation) in cases {
        let required = repository_tool_result_v2_preflight_size(&operation);
        assert!(required > 1, "typed result envelope is nonempty");
        let mut narrow = bounds();
        narrow.max_artifact_bytes = required - 1;
        let broker = RepositoryToolBroker::open(
            root.path(),
            authority_with_bounds(root.path(), vec![grant], narrow),
            epoch(12_000 + index, &[]),
        )
        .expect("tiny-cap broker opens");
        let prepared = prepare(&broker, index, grant_id, operation).expect("denial is durable");
        assert_eq!(
            prepared.receipt.authorization,
            RepositoryToolAuthorizationDecisionV2::Denied {
                denial: birdcode_protocol::RepositoryToolPreparationDenialV2::LimitExceeded {
                    limit: birdcode_protocol::RepositoryLimitKindV2::ArtifactBytes,
                    requested: required,
                    maximum: required - 1,
                }
            }
        );
        let terminal = execute(&broker, &prepared, index).expect("denial closes");
        let RepositoryToolTerminalV2::Observed(observed) = terminal else {
            panic!("denial is an observed terminal");
        };
        assert!(matches!(
            observed.receipt.terminal,
            RepositoryToolObservedTerminalV2::AuthorizationDenied { .. }
        ));
        assert_eq!(
            observed.receipt.effect,
            RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted,
            "the missing path was never resolved"
        );
    }
}

#[test]
fn file_read_budgets_complete_base64_json_before_reading_content() {
    let root = TempDir::new().expect("temp root");
    let body = vec![0xa5; 4_096];
    fs::write(root.path().join("binary"), &body).expect("binary fixture");
    let grant = RepositoryToolGrantId::from_uuid(uuid(13_001));
    let operation = ChildToolOperation::RepositoryFileRead {
        path: path(&[b"binary"]),
        offset_bytes: 0,
        max_bytes: u64::try_from(body.len()).expect("fixture length fits u64"),
    };
    let mut narrow = bounds();
    narrow.max_artifact_bytes = repository_tool_result_v2_preflight_size(&operation) + 8;
    let exact_cap = narrow.max_artifact_bytes;
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority_with_bounds(root.path(), vec![read_grant(grant)], narrow),
        epoch(13_002, &[]),
    )
    .expect("broker");
    let prepared = prepare(&broker, 21, grant, operation).expect("read prepares");
    assert_eq!(
        prepared.receipt.authorization,
        RepositoryToolAuthorizationDecisionV2::Authorized,
        "the raw read request may exceed the artifact cap because the collector truncates"
    );
    let terminal = execute(&broker, &prepared, 21).expect("budgeted read executes");
    let artifact = successful_result_artifact(&terminal);
    assert!(artifact.artifact.size_bytes <= exact_cap);
    let RepositoryToolResultV2::RepositoryFileRead(result) = successful_result(&terminal) else {
        panic!("expected read result");
    };
    assert!(!result.bytes.is_empty());
    assert!(result.bytes.len() < body.len());
    assert!(result.truncated);
    assert_eq!(
        encode_repository_tool_result_v2(&RepositoryToolResultV2::RepositoryFileRead(result))
            .expect("result re-encodes"),
        artifact.bytes,
        "the exact canonical base64 JSON, not raw bytes, is capped"
    );
}

#[test]
fn tree_canonical_budget_retains_only_the_first_four_long_path_entries() {
    let root = TempDir::new().expect("temp root");
    let names = (0_u8..6)
        .map(|index| format!("{index:02}-{}", "p".repeat(216)).into_bytes())
        .collect::<Vec<_>>();
    for name in &names {
        fs::write(
            root.path().join(std::ffi::OsString::from_vec(name.clone())),
            [1_u8],
        )
        .expect("long-name fixture");
    }
    let grant = RepositoryToolGrantId::from_uuid(uuid(14_001));
    let requested_bounds = bounds();
    let operation = ChildToolOperation::RepositoryTree {
        path: RepositoryRelativePathV1::default(),
        max_depth: requested_bounds.max_tree_depth,
        max_entries: requested_bounds.max_tree_entries,
    };
    let expected = names
        .iter()
        .take(4)
        .map(|name| RepositoryTreeEntryV1 {
            path: path(&[name]),
            kind: RepositoryNodeKindV1::RegularFile,
            byte_len: Some(1),
        })
        .collect::<Vec<_>>();
    let entry_bytes = expected
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            u64::try_from(serde_json::to_vec(entry).expect("entry encodes").len())
                .expect("entry length fits u64")
                + u64::from(index > 0)
        })
        .sum::<u64>();
    let mut narrow = requested_bounds;
    narrow.max_artifact_bytes = repository_tool_result_v2_preflight_size(&operation) + entry_bytes;
    let exact_cap = narrow.max_artifact_bytes;
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority_with_bounds(root.path(), vec![tree_grant(grant)], narrow),
        epoch(14_002, &[]),
    )
    .expect("broker");
    let prepared = prepare(&broker, 31, grant, operation).expect("tree prepares");
    let terminal = execute(&broker, &prepared, 31).expect("tree executes");
    let artifact = successful_result_artifact(&terminal);
    assert!(artifact.artifact.size_bytes <= exact_cap);
    let RepositoryToolResultV2::RepositoryTree(result) = successful_result(&terminal) else {
        panic!("expected tree result");
    };
    assert_eq!(result.entries, expected);
    assert!(result.truncated);
    assert!(
        result
            .entries
            .iter()
            .all(|entry| { entry.path != path(&[&names[4]]) && entry.path != path(&[&names[5]]) })
    );
}

#[test]
fn literal_search_canonical_budget_cannot_leak_a_fifth_match() {
    let root = TempDir::new().expect("temp root");
    let name = format!("00-{}", "s".repeat(216)).into_bytes();
    let body = b"x-x-x-x-x-x-x";
    fs::write(
        root.path().join(std::ffi::OsString::from_vec(name.clone())),
        body,
    )
    .expect("search fixture");
    let grant = RepositoryToolGrantId::from_uuid(uuid(15_001));
    let requested_bounds = bounds();
    let operation = ChildToolOperation::LiteralSearch {
        path: RepositoryRelativePathV1::default(),
        literal_utf8: "x".to_owned(),
        max_depth: requested_bounds.max_search_depth,
        max_files: requested_bounds.max_search_files,
        max_matches: requested_bounds.max_search_matches,
        max_bytes_per_file: requested_bounds.max_search_bytes_per_file,
        max_total_bytes: requested_bounds.max_search_total_bytes,
    };
    let result_path = path(&[&name]);
    let scan = RepositoryLiteralFileScanV1 {
        path: result_path.clone(),
        bytes_scanned: u64::try_from(body.len()).expect("fixture length fits u64"),
        file_byte_len: u64::try_from(body.len()).expect("fixture length fits u64"),
        truncated: false,
    };
    let matches = [0_u64, 2, 4, 6].map(|byte_offset| RepositoryLiteralMatchV1 {
        path: result_path.clone(),
        byte_offset,
    });
    let scan_bytes =
        u64::try_from(serde_json::to_vec(&scan).expect("scan encodes").len()).expect("length");
    let match_bytes = matches
        .iter()
        .enumerate()
        .map(|(index, matched)| {
            u64::try_from(serde_json::to_vec(matched).expect("match encodes").len())
                .expect("length")
                + u64::from(index > 0)
        })
        .sum::<u64>();
    let mut narrow = requested_bounds;
    narrow.max_artifact_bytes =
        repository_tool_result_v2_preflight_size(&operation) + scan_bytes + match_bytes;
    let exact_cap = narrow.max_artifact_bytes;
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority_with_bounds(root.path(), vec![search_grant(grant)], narrow),
        epoch(15_002, &[]),
    )
    .expect("broker");
    let prepared = prepare(&broker, 41, grant, operation).expect("search prepares");
    let terminal = execute(&broker, &prepared, 41).expect("search executes");
    let artifact = successful_result_artifact(&terminal);
    assert!(artifact.artifact.size_bytes <= exact_cap);
    let RepositoryToolResultV2::LiteralSearch(result) = successful_result(&terminal) else {
        panic!("expected search result");
    };
    assert_eq!(result.matches, matches);
    assert_eq!(result.file_scans, vec![scan]);
    assert!(result.truncated);
    assert!(
        !result
            .matches
            .iter()
            .any(|matched| matched.byte_offset >= 8)
    );
}

#[test]
fn duplicate_sibling_grant_id_denies_without_filesystem_effect() {
    let root = TempDir::new().expect("temp root");
    let duplicate = RepositoryToolGrantId::from_uuid(uuid(301));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(
            root.path(),
            vec![tree_grant(duplicate), read_grant(duplicate)],
        ),
        epoch(302, &[]),
    )
    .expect("malformed authority remains auditable at evaluator");
    let prepared = prepare(
        &broker,
        10,
        duplicate,
        ChildToolOperation::RepositoryTree {
            path: RepositoryRelativePathV1::default(),
            max_depth: 1,
            max_entries: 1,
        },
    )
    .expect("denied call still produces Prepared");
    assert!(matches!(
        prepared.receipt.authorization,
        RepositoryToolAuthorizationDecisionV2::Denied {
            denial: birdcode_protocol::RepositoryToolPreparationDenialV2::GrantIdentityMismatch
        }
    ));
    let terminal = execute(&broker, &prepared, 10).expect("denial closes as observed");
    let RepositoryToolTerminalV2::Observed(observed) = &terminal else {
        panic!("expected observed denial");
    };
    assert!(matches!(
        observed.receipt.terminal,
        RepositoryToolObservedTerminalV2::AuthorizationDenied { .. }
    ));
    assert_eq!(
        observed.receipt.effect,
        RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted
    );
    assert!(verify_terminal_output_v2(&prepared, &terminal));
}

#[test]
fn prepared_substitution_is_rejected_without_consuming_the_original() {
    let root = TempDir::new().expect("temp root");
    fs::write(root.path().join("file"), b"content").expect("fixture");
    let grant = RepositoryToolGrantId::from_uuid(uuid(401));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![read_grant(grant)]),
        epoch(402, &[]),
    )
    .expect("broker");
    let prepared = prepare(
        &broker,
        1,
        grant,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"file"]),
            offset_bytes: 0,
            max_bytes: 7,
        },
    )
    .expect("prepare");

    let mut substituted = prepared.clone();
    substituted.receipt.tool_ordinal = 2;
    substituted.prepared_receipt = retained(
        &substituted.prepared_receipt.artifact.media_type,
        serde_json::to_vec(&substituted.receipt).expect("substituted receipt encodes"),
    );
    assert_eq!(
        execute(&broker, &substituted, 1),
        Err(RepositoryBrokerErrorV2::PreparedSubstitution)
    );

    let terminal = execute(&broker, &prepared, 1).expect("original remains executable");
    assert!(verify_terminal_output_v2(&prepared, &terminal));
    assert_eq!(
        execute(&broker, &prepared, 2),
        Err(RepositoryBrokerErrorV2::PreparedCallAlreadyConsumed)
    );
}

#[test]
fn cross_root_invalid_paths_and_symlinks_cannot_expand_authority() {
    let root = TempDir::new().expect("root");
    let other = TempDir::new().expect("other root");
    fs::write(other.path().join("secret"), b"secret").expect("secret fixture");
    symlink(other.path(), root.path().join("escape")).expect("directory symlink");
    let grant = RepositoryToolGrantId::from_uuid(uuid(501));
    let issued_authority = authority(root.path(), vec![read_grant(grant)]);

    assert!(matches!(
        RepositoryToolBroker::open(other.path(), issued_authority.clone(), epoch(502, &[])),
        Err(BrokerOpenError::RootIdentityMismatch { .. })
    ));

    let broker =
        RepositoryToolBroker::open(root.path(), issued_authority, epoch(502, &[])).expect("broker");
    let traversal = prepare(
        &broker,
        1,
        grant,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"..", b"secret"]),
            offset_bytes: 0,
            max_bytes: 10,
        },
    )
    .expect("invalid path is retained as denied Prepared");
    assert!(matches!(
        traversal.receipt.authorization,
        RepositoryToolAuthorizationDecisionV2::Denied {
            denial: birdcode_protocol::RepositoryToolPreparationDenialV2::InvalidPath { .. }
        }
    ));

    let linked = prepare(
        &broker,
        2,
        grant,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"escape", b"secret"]),
            offset_bytes: 0,
            max_bytes: 10,
        },
    )
    .expect("syntactically valid linked path prepares");
    let terminal = execute(&broker, &linked, 2).expect("known symlink failure is observed");
    assert!(matches!(
        observed_failure(&terminal),
        birdcode_protocol::RepositoryToolFailureV1::Io { .. }
            | birdcode_protocol::RepositoryToolFailureV1::SymlinkRejected
            | birdcode_protocol::RepositoryToolFailureV1::WrongFileType { .. }
    ));
    assert!(verify_terminal_output_v2(&linked, &terminal));
}

#[test]
fn root_symlink_and_identity_race_are_rejected_at_open() {
    let parent = TempDir::new().expect("parent");
    let root = parent.path().join("root");
    fs::create_dir(&root).expect("root directory");
    let grant = RepositoryToolGrantId::from_uuid(uuid(601));
    let before_mutation = authority(&root, vec![tree_grant(grant)]);
    let replaced = parent.path().join("replaced-root");
    fs::rename(&root, &replaced).expect("move issued root");
    fs::create_dir(&root).expect("replace issued root with a new inode");
    assert!(matches!(
        RepositoryToolBroker::open(&root, before_mutation, epoch(602, &[])),
        Err(BrokerOpenError::RootIdentityMismatch { .. })
    ));

    let link = parent.path().join("root-link");
    symlink(&root, &link).expect("root symlink");
    let target_authority = authority(&root, vec![tree_grant(grant)]);
    assert!(matches!(
        RepositoryToolBroker::open(&link, target_authority, epoch(603, &[])),
        Err(BrokerOpenError::RootUnavailable { .. })
    ));
}

#[test]
fn same_length_result_mutation_breaks_exact_artifact_verification() {
    let root = TempDir::new().expect("root");
    fs::write(root.path().join("file"), b"abcdefgh").expect("fixture");
    let grant = RepositoryToolGrantId::from_uuid(uuid(701));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![read_grant(grant)]),
        epoch(702, &[]),
    )
    .expect("broker");
    let prepared = prepare(
        &broker,
        1,
        grant,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"file"]),
            offset_bytes: 0,
            max_bytes: 8,
        },
    )
    .expect("prepare");
    let mut terminal = execute(&broker, &prepared, 1).expect("execute");
    assert!(verify_terminal_output_v2(&prepared, &terminal));
    let RepositoryToolTerminalV2::Observed(observed) = &mut terminal else {
        panic!("expected observed");
    };
    let result_artifact = observed
        .supporting_artifacts
        .first_mut()
        .expect("result artifact");
    let index = result_artifact.bytes.len() / 2;
    result_artifact.bytes[index] ^= 1;
    assert_eq!(
        result_artifact.artifact.size_bytes,
        u64::try_from(result_artifact.bytes.len()).expect("length fits u64")
    );
    assert!(!verify_terminal_output_v2(&prepared, &terminal));
}

#[test]
fn result_larger_than_terminal_cap_remains_separate_and_succeeds() {
    let root = TempDir::new().expect("root");
    let body = vec![b'x'; 300 * 1024];
    fs::write(root.path().join("large"), &body).expect("large fixture");
    let grant = RepositoryToolGrantId::from_uuid(uuid(801));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![read_grant(grant)]),
        epoch(802, &[]),
    )
    .expect("broker");
    let prepared = prepare(
        &broker,
        1,
        grant,
        ChildToolOperation::RepositoryFileRead {
            path: path(&[b"large"]),
            offset_bytes: 0,
            max_bytes: u64::try_from(body.len()).expect("body length fits u64"),
        },
    )
    .expect("prepare");
    let terminal = execute(&broker, &prepared, 1).expect("execute");
    let RepositoryToolTerminalV2::Observed(observed) = &terminal else {
        panic!("expected observed");
    };
    let RepositoryToolObservedTerminalV2::Succeeded { result_artifact } =
        &observed.receipt.terminal
    else {
        panic!("expected success");
    };
    assert_eq!(
        result_artifact.media_type,
        REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE
    );
    assert!(result_artifact.size_bytes > REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES);
    assert!(result_artifact.size_bytes <= REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES);
    assert!(
        observed.terminal_receipt.artifact.size_bytes
            <= REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES
    );
    assert!(verify_terminal_output_v2(&prepared, &terminal));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one lifecycle test contrasts active interruption and closed-epoch reconciliation"
)]
fn interruption_and_restart_have_distinct_typed_timing_and_effects() {
    let root = TempDir::new().expect("root");
    let grant = RepositoryToolGrantId::from_uuid(uuid(901));
    let authority = authority(root.path(), vec![tree_grant(grant)]);
    let old_broker = RepositoryToolBroker::open(root.path(), authority.clone(), epoch(902, &[]))
        .expect("old broker");

    let interrupted = prepare(
        &old_broker,
        1,
        grant,
        ChildToolOperation::RepositoryTree {
            path: RepositoryRelativePathV1::default(),
            max_depth: 1,
            max_entries: 10,
        },
    )
    .expect("prepare interruption");
    let active_unknown = old_broker
        .record_interruption(RepositoryToolInterruptionInputV2 {
            prepared: interrupted.clone(),
            prepared_event_id: EventId::from_uuid(uuid(9_100)),
            boundary: RepositoryInterruptionBoundaryV1::Deadline,
            cancellation: None,
            runtime_boundary_at: runtime_clock(200),
        })
        .expect("active interruption");
    let RepositoryToolTerminalV2::Unknown(active_unknown) = &active_unknown else {
        panic!("expected active unknown");
    };
    assert!(matches!(
        active_unknown.receipt.timing,
        RepositoryToolUnknownTimingV2::BrokerRecorded { .. }
    ));
    assert_eq!(
        active_unknown.receipt.effect,
        RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted
    );
    assert!(verify_terminal_output_v2(
        &interrupted,
        &RepositoryToolTerminalV2::Unknown(active_unknown.clone())
    ));
    let active_event = project_unknown_event_v2(
        &interrupted,
        active_unknown,
        ChildToolUnknownReason::ClaimExpiredBeforeObservation,
        ChildToolUnknownBoundary::Deadline,
    )
    .expect("active Unknown projects from exact typed lifecycle metadata");
    assert_eq!(active_event.timing, active_unknown.receipt.timing);
    assert_eq!(
        project_unknown_event_v2(
            &interrupted,
            active_unknown,
            ChildToolUnknownReason::RuntimeRestartedBeforeObservation,
            ChildToolUnknownBoundary::Restart,
        ),
        Err(RepositoryBrokerErrorV2::UnknownProjectionMismatch)
    );
    assert_eq!(
        execute(&old_broker, &interrupted, 2),
        Err(RepositoryBrokerErrorV2::PreparedCallAlreadyConsumed)
    );

    let abandoned = prepare(
        &old_broker,
        2,
        grant,
        ChildToolOperation::RepositoryTree {
            path: RepositoryRelativePathV1::default(),
            max_depth: 1,
            max_entries: 10,
        },
    )
    .expect("prepare abandoned call");
    let new_broker = RepositoryToolBroker::open(root.path(), authority, epoch(903, &[902]))
        .expect("new broker epoch");
    let reconciled = new_broker
        .reconcile_abandoned_prepared(RepositoryToolRestartReconciliationInputV2 {
            prepared: abandoned.clone(),
            prepared_event_id: EventId::from_uuid(uuid(9_200)),
            boundary: RepositoryInterruptionBoundaryV1::RuntimeRestart,
            cancellation: None,
            runtime_boundary_at: runtime_clock(300),
        })
        .expect("closed epoch reconciles");
    let RepositoryToolTerminalV2::Unknown(reconciled_unknown) = &reconciled else {
        panic!("expected reconciled unknown");
    };
    assert_eq!(
        reconciled_unknown.receipt.timing,
        RepositoryToolUnknownTimingV2::RuntimeReconciled {
            abandoned_broker_instance_id: RepositoryBrokerInstanceId::from_uuid(uuid(902))
        }
    );
    assert_eq!(
        reconciled_unknown.receipt.effect,
        RepositoryFilesystemEffectV1::Indeterminate
    );
    assert!(matches!(
        reconciled_unknown.receipt.cleanup,
        RepositoryCleanupReportV2::Indeterminate { .. }
    ));
    assert!(verify_terminal_output_v2(&abandoned, &reconciled));
    project_unknown_event_v2(
        &abandoned,
        reconciled_unknown,
        ChildToolUnknownReason::RuntimeRestartedBeforeObservation,
        ChildToolUnknownBoundary::Restart,
    )
    .expect("reconciled Unknown projects exactly");
    assert_eq!(
        new_broker.reconcile_abandoned_prepared(RepositoryToolRestartReconciliationInputV2 {
            prepared: abandoned,
            prepared_event_id: EventId::from_uuid(uuid(9_201)),
            boundary: RepositoryInterruptionBoundaryV1::RuntimeRestart,
            cancellation: None,
            runtime_boundary_at: runtime_clock(301),
        }),
        Err(RepositoryBrokerErrorV2::PreparedCallAlreadyConsumed)
    );
}

#[test]
fn invalid_interruption_metadata_fails_before_consuming_prepared() {
    let root = TempDir::new().expect("root");
    let grant = RepositoryToolGrantId::from_uuid(uuid(951));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![tree_grant(grant)]),
        epoch(952, &[]),
    )
    .expect("broker");
    let prepared = prepare(
        &broker,
        1,
        grant,
        ChildToolOperation::RepositoryTree {
            path: RepositoryRelativePathV1::default(),
            max_depth: 1,
            max_entries: 1,
        },
    )
    .expect("prepare");

    assert_eq!(
        broker.record_interruption(RepositoryToolInterruptionInputV2 {
            prepared: prepared.clone(),
            prepared_event_id: EventId::from_uuid(uuid(9_510)),
            boundary: RepositoryInterruptionBoundaryV1::Cancellation,
            cancellation: None,
            runtime_boundary_at: runtime_clock(210),
        }),
        Err(RepositoryBrokerErrorV2::InvalidInterruptionMetadata)
    );

    broker
        .record_interruption(RepositoryToolInterruptionInputV2 {
            prepared,
            prepared_event_id: EventId::from_uuid(uuid(9_511)),
            boundary: RepositoryInterruptionBoundaryV1::Deadline,
            cancellation: None,
            runtime_boundary_at: runtime_clock(211),
        })
        .expect("invalid metadata did not consume Prepared");
}

#[test]
fn active_epoch_reuse_and_duplicate_closed_epochs_fail_closed() {
    let root = TempDir::new().expect("root");
    let grant = RepositoryToolGrantId::from_uuid(uuid(1_001));
    let authority = authority(root.path(), vec![tree_grant(grant)]);
    assert!(matches!(
        RepositoryToolBroker::open(root.path(), authority.clone(), epoch(1_002, &[1_002])),
        Err(BrokerOpenError::ActiveBrokerAlreadyClosed)
    ));
    assert!(matches!(
        RepositoryToolBroker::open(root.path(), authority, epoch(1_003, &[1_002, 1_002])),
        Err(BrokerOpenError::DuplicateClosedBrokerEpoch)
    ));
}

#[test]
fn broker_call_bound_denies_second_call_and_prepared_receipt_cap_is_enforced() {
    let root = TempDir::new().expect("root");
    let grant = RepositoryToolGrantId::from_uuid(uuid(1_101));
    let mut narrow = bounds();
    narrow.max_calls_per_broker = 1;
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority_with_bounds(root.path(), vec![tree_grant(grant)], narrow),
        epoch(1_102, &[]),
    )
    .expect("narrow broker");
    let operation = ChildToolOperation::RepositoryTree {
        path: RepositoryRelativePathV1::default(),
        max_depth: 1,
        max_entries: 1,
    };
    let first = prepare(&broker, 1, grant, operation.clone()).expect("first prepares");
    let second = prepare(&broker, 2, grant, operation).expect("denied second prepares");
    assert_eq!(
        first.receipt.authorization,
        RepositoryToolAuthorizationDecisionV2::Authorized
    );
    assert!(matches!(
        second.receipt.authorization,
        RepositoryToolAuthorizationDecisionV2::Denied {
            denial: birdcode_protocol::RepositoryToolPreparationDenialV2::LimitExceeded {
                limit: birdcode_protocol::RepositoryLimitKindV2::BrokerCalls,
                ..
            }
        }
    ));

    let many_grants = (0_u128..2_000)
        .map(|index| RepositoryToolGrantId::from_uuid(uuid(20_000 + index)))
        .map(tree_grant)
        .collect::<Vec<_>>();
    let selected = many_grants[0].tool_grant_id();
    let oversized_broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), many_grants),
        epoch(1_103, &[]),
    )
    .expect("large authority opens but cannot emit oversized receipt");
    assert!(matches!(
        prepare(
            &oversized_broker,
            3,
            selected,
            ChildToolOperation::RepositoryTree {
                path: RepositoryRelativePathV1::default(),
                max_depth: 1,
                max_entries: 1,
            }
        ),
        Err(RepositoryBrokerErrorV2::PreparedReceiptTooLarge {
            maximum: REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES,
            ..
        })
    ));
}

#[test]
fn duplicate_prepare_does_not_consume_broker_sequence() {
    let root = TempDir::new().expect("root");
    let grant = RepositoryToolGrantId::from_uuid(uuid(1_201));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![tree_grant(grant)]),
        epoch(1_202, &[]),
    )
    .expect("broker");
    let operation = ChildToolOperation::RepositoryTree {
        path: RepositoryRelativePathV1::default(),
        max_depth: 1,
        max_entries: 1,
    };

    let first = prepare(&broker, 1, grant, operation.clone()).expect("first prepares");
    assert_eq!(first.receipt.broker_call_sequence, 1);
    assert_eq!(
        prepare(&broker, 1, grant, operation.clone()),
        Err(RepositoryBrokerErrorV2::DuplicateToolCallId)
    );

    let second = prepare(&broker, 2, grant, operation).expect("fresh call prepares");
    assert_eq!(second.receipt.broker_call_sequence, 2);
}

#[test]
fn concurrent_duplicate_prepare_cannot_publish_sequence_two_first() {
    let root = TempDir::new().expect("root");
    let grant = RepositoryToolGrantId::from_uuid(uuid(1_301));
    let broker = std::sync::Arc::new(
        RepositoryToolBroker::open(
            root.path(),
            authority(root.path(), vec![tree_grant(grant)]),
            epoch(1_302, &[]),
        )
        .expect("broker"),
    );
    let start = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let broker = std::sync::Arc::clone(&broker);
        let start = std::sync::Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            start.wait();
            prepare(
                &broker,
                1,
                grant,
                ChildToolOperation::RepositoryTree {
                    path: RepositoryRelativePathV1::default(),
                    max_depth: 1,
                    max_entries: 1,
                },
            )
        }));
    }
    start.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("prepare worker does not panic"))
        .collect::<Vec<_>>();
    let successes = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().ok())
        .collect::<Vec<_>>();
    let duplicate_count = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(RepositoryBrokerErrorV2::DuplicateToolCallId)))
        .count();
    assert_eq!(successes.len(), 1);
    assert_eq!(successes[0].receipt.broker_call_sequence, 1);
    assert_eq!(duplicate_count, 1);

    let second = prepare(
        &broker,
        2,
        grant,
        ChildToolOperation::RepositoryTree {
            path: RepositoryRelativePathV1::default(),
            max_depth: 1,
            max_entries: 1,
        },
    )
    .expect("fresh call follows the one published duplicate winner");
    assert_eq!(second.receipt.broker_call_sequence, 2);
}

#[test]
fn oversized_prepared_receipt_does_not_consume_broker_sequence() {
    let root = TempDir::new().expect("root");
    let search = RepositoryToolGrantId::from_uuid(uuid(1_401));
    let tree = RepositoryToolGrantId::from_uuid(uuid(1_402));
    let broker = RepositoryToolBroker::open(
        root.path(),
        authority(root.path(), vec![search_grant(search), tree_grant(tree)]),
        epoch(1_403, &[]),
    )
    .expect("broker");
    let oversized_literal = "x".repeat(
        usize::try_from(REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES)
            .expect("receipt cap fits usize")
            + 1_024,
    );
    assert!(matches!(
        prepare(
            &broker,
            1,
            search,
            ChildToolOperation::LiteralSearch {
                path: RepositoryRelativePathV1::default(),
                literal_utf8: oversized_literal,
                max_depth: 1,
                max_files: 1,
                max_matches: 1,
                max_bytes_per_file: 1,
                max_total_bytes: 1,
            },
        ),
        Err(RepositoryBrokerErrorV2::PreparedReceiptTooLarge { .. })
    ));

    let first = prepare(
        &broker,
        2,
        tree,
        ChildToolOperation::RepositoryTree {
            path: RepositoryRelativePathV1::default(),
            max_depth: 1,
            max_entries: 1,
        },
    )
    .expect("a valid call remains the first published Prepare");
    assert_eq!(first.receipt.broker_call_sequence, 1);
}
