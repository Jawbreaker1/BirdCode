#![allow(
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use birdcode_protocol::WorkspacePath;
use birdcode_validation::{
    ActorIdentity, AdapterCatalog, AdapterDeclaration, AdapterKind, AgentId, AgentIdentity,
    AppendError, ArtifactId, ArtifactKind, ArtifactRecord, AttemptId, BlindAttemptId,
    BlindProcessExit, CandidateId, CaptureLimits, CheckEvidence, CheckId, CheckKind, CheckOutcome,
    CheckRequirement, CommandComponent, CommandSpec, EXECUTION_PHASES, EnvironmentEntry,
    EnvironmentMetadataField, EnvironmentSnapshot, EnvironmentValue, EvaluationCaseId,
    ExecutionBounds, ExecutionPhase, ExecutionPlatform, ExecutionPlatformKind, ExecutionTarget,
    ExitRequirement, ModelId, ModelIdentity, NativeArgument, NativeEncoding, OperatingSystem,
    PhaseOutcome, PhaseRequirement, ProcessExit, ProvenanceEvent, ProviderId, RetainedArgument,
    RetainedStdin, RunContextManifest, RunId, RunProvenance, RunVerdict, Sha256Digest, TargetError,
    TargetId, TargetSurface, ToolchainEntry, ValidationCheck, ValidationPolicy, ValidationReport,
    ValidationViolation,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use url::Url;
use uuid::Uuid;

const SENSITIVE_PROVIDER: &str = "sensitive-provider-lineage";
const SENSITIVE_MODEL: &str = "sensitive-model-lineage";
const SENSITIVE_AGENT: &str = "sensitive-agent-identity";
const SENSITIVE_TARGET: &str = "sensitive-raw-target";
const SENSITIVE_HOST: &str = "sensitive-raw-host";
const SENSITIVE_STORAGE: &str = "sensitive-storage-reference";
const SENSITIVE_FAILURE: &str = "sensitive-launch-failure-code";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeFamily {
    Unix,
    Windows,
}

struct Fixture {
    provenance: RunProvenance,
    policy: ValidationPolicy,
}

#[derive(Clone)]
struct FixtureOptions {
    phases: Vec<ExecutionPhase>,
    not_applicable: BTreeSet<ExecutionPhase>,
    check_kind: CheckKind,
    check_outcome: CheckOutcome,
    artifact_kind: ArtifactKind,
    build_command: Option<CommandSpec>,
    package_failure: Option<(PhaseOutcome, CommandSpec, ProcessExit)>,
    failure_phase: Option<(ExecutionPhase, PhaseOutcome)>,
    primary_truncated: bool,
    extra_artifacts: Vec<ArtifactKind>,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            phases: EXECUTION_PHASES.to_vec(),
            not_applicable: BTreeSet::new(),
            check_kind: CheckKind::Test,
            check_outcome: CheckOutcome::Passed,
            artifact_kind: ArtifactKind::TestReport,
            build_command: None,
            package_failure: None,
            failure_phase: None,
            primary_truncated: false,
            extra_artifacts: Vec::new(),
        }
    }
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(label.as_bytes())
}

fn target_id(value: &str) -> TargetId {
    TargetId::new(value).expect("test target IDs are valid")
}

fn cli_target(platform: ExecutionPlatform) -> ExecutionTarget {
    ExecutionTarget::new(target_id(SENSITIVE_TARGET), platform, TargetSurface::Cli)
        .expect("CLI target is structurally valid")
}

fn mac_cli_target() -> ExecutionTarget {
    cli_target(ExecutionPlatform::MacOs {
        host_id: target_id(SENSITIVE_HOST),
    })
}

fn windows_cli_target() -> ExecutionTarget {
    cli_target(ExecutionPlatform::Windows {
        host_id: target_id(SENSITIVE_HOST),
    })
}

fn web_target(platform: ExecutionPlatform) -> ExecutionTarget {
    ExecutionTarget::new(
        target_id(SENSITIVE_TARGET),
        platform,
        TargetSurface::WebPlaywright {
            url: Url::parse("https://example.invalid/application?case=retained")
                .expect("static URL is valid"),
        },
    )
    .expect("web target is structurally valid")
}

fn native_argument(family: NativeFamily, bytes: &[u8]) -> NativeArgument {
    match family {
        NativeFamily::Unix => NativeArgument::from_unix_bytes(bytes.to_vec()),
        NativeFamily::Windows => {
            NativeArgument::from_windows_utf16(bytes.iter().copied().map(u16::from).collect())
        }
    }
}

fn workspace_path(family: NativeFamily, bytes: &[u8]) -> WorkspacePath {
    match family {
        NativeFamily::Unix => WorkspacePath::from_unix_bytes(bytes.to_vec()),
        NativeFamily::Windows => {
            WorkspacePath::from_windows_utf16(bytes.iter().copied().map(u16::from).collect())
        }
    }
}

fn command(family: NativeFamily) -> CommandSpec {
    CommandSpec {
        executable: workspace_path(family, b"sensitive-command-executable"),
        arguments: vec![RetainedArgument::PlainText {
            value: native_argument(family, b"argument"),
        }],
        working_directory: workspace_path(family, b"workspace"),
        environment: vec![EnvironmentEntry {
            name: native_argument(family, b"BIRDCODE_TEST"),
            value: EnvironmentValue::PlainText {
                value: native_argument(family, b"enabled"),
            },
        }],
        stdin: Some(RetainedStdin::PlainText {
            bytes: b"stdin".to_vec(),
        }),
        capture: CaptureLimits {
            stdout_bytes: 64,
            stderr_bytes: 64,
        },
    }
}

fn environment(family: NativeFamily) -> EnvironmentSnapshot {
    let operating_system = match family {
        NativeFamily::Unix => OperatingSystem::MacOs,
        NativeFamily::Windows => OperatingSystem::Windows,
    };
    EnvironmentSnapshot {
        operating_system,
        architecture: match family {
            NativeFamily::Unix => "arm64",
            NativeFamily::Windows => "x86_64",
        }
        .to_owned(),
        os_version: "test-os-1".to_owned(),
        locale: Some("sv_SE.UTF-8".to_owned()),
        selected_variables: vec![EnvironmentEntry {
            name: native_argument(family, b"PATH"),
            value: EnvironmentValue::PlainText {
                value: native_argument(family, b"tool-bin"),
            },
        }],
        toolchain: vec![ToolchainEntry {
            tool_id: target_id("rustc"),
            version: "1.92.0".to_owned(),
            executable_sha256: Some(digest("rustc")),
        }],
    }
}

fn actor() -> AgentIdentity {
    AgentIdentity::new(
        AgentId::new(SENSITIVE_AGENT).expect("agent ID is valid"),
        ActorIdentity::Model {
            model: ModelIdentity::new(
                ProviderId::new(SENSITIVE_PROVIDER).expect("provider ID is valid"),
                ModelId::new(SENSITIVE_MODEL).expect("model ID is valid"),
                Some(digest("model-configuration")),
            ),
        },
    )
}

fn manifest(target: &ExecutionTarget, policy: &ValidationPolicy) -> RunContextManifest {
    RunContextManifest {
        source_workspace_snapshot_sha256: digest("source-workspace"),
        task_fixture_sha256: digest("task-fixture"),
        validation_plan_sha256: policy.validation_plan_sha256(),
        validation_policy_sha256: policy.policy_sha256(),
        harness_configuration_sha256: digest("harness-configuration"),
        adapter: AdapterDeclaration {
            requirement: target
                .required_adapter()
                .expect("fixture target requires an adapter"),
            implementation_id: target_id("adapter-implementation"),
            version: target_id("adapter-version"),
            implementation_sha256: digest("adapter-binary"),
        },
        permission_policy_sha256: digest("permission-policy"),
        network_policy_sha256: digest("network-policy"),
    }
}

fn validation_policy(
    check_id: CheckId,
    check_kind: CheckKind,
    artifact_kind: ArtifactKind,
    not_applicable: &BTreeSet<ExecutionPhase>,
    minimum_evidence_items: u32,
) -> ValidationPolicy {
    let phase_requirements = EXECUTION_PHASES.map(|phase| {
        let requirement = if not_applicable.contains(&phase) {
            PhaseRequirement::DeclaredNotApplicable
        } else {
            PhaseRequirement::RequiredSuccess
        };
        (phase, requirement)
    });
    ValidationPolicy::new(
        digest("validation-plan"),
        phase_requirements,
        [(
            check_id,
            CheckRequirement {
                expected_kind: check_kind,
                allowed_artifact_kinds: [artifact_kind].into_iter().collect(),
                attempt_exit: ExitRequirement::Disallowed,
                minimum_evidence_items,
                allow_truncated_artifacts: false,
            },
        )],
        1,
    )
}

fn default_policy(check_id: CheckId) -> ValidationPolicy {
    validation_policy(
        check_id,
        CheckKind::Test,
        ArtifactKind::TestReport,
        &BTreeSet::new(),
        1,
    )
}

fn new_provenance(
    target: ExecutionTarget,
    bounds: ExecutionBounds,
    environment: EnvironmentSnapshot,
    policy: &ValidationPolicy,
) -> RunProvenance {
    let manifest = manifest(&target, policy);
    RunProvenance::new(
        CandidateId::new(),
        EvaluationCaseId::new(),
        target,
        bounds,
        environment,
        manifest,
    )
    .expect("fixture provenance is serializable")
}

fn append_event(provenance: &mut RunProvenance, clock: &mut u64, event: ProvenanceEvent) {
    provenance
        .append(*clock, event)
        .expect("fixture event preserves append invariants");
    *clock += 1;
}

fn artifact(
    attempt_id: AttemptId,
    kind: ArtifactKind,
    suffix: &str,
    retained_bytes: u64,
) -> ArtifactRecord {
    ArtifactRecord {
        artifact_id: ArtifactId::new(),
        attempt_id,
        kind,
        sha256: digest(&format!("artifact-{suffix}")),
        retained_bytes,
        observed_bytes: Some(retained_bytes),
        truncated: false,
        media_type: "application/octet-stream".to_owned(),
        storage_ref: target_id(&format!("{SENSITIVE_STORAGE}-{suffix}")),
    }
}

fn build_fixture(
    target: ExecutionTarget,
    bounds: ExecutionBounds,
    environment: EnvironmentSnapshot,
    options: FixtureOptions,
) -> Fixture {
    let check_id = CheckId::new();
    let policy = validation_policy(
        check_id,
        options.check_kind,
        options.artifact_kind,
        &options.not_applicable,
        1,
    );
    let mut provenance = new_provenance(target, bounds, environment, &policy);
    let mut clock = 1_000;

    for phase in options.phases.iter().copied() {
        let attempt_id = AttemptId::new();
        let selected_command = if phase == ExecutionPhase::Package {
            options
                .package_failure
                .as_ref()
                .map(|(_, command, _)| command.clone())
        } else if phase == ExecutionPhase::Build {
            options.build_command.clone()
        } else {
            None
        };
        append_event(
            &mut provenance,
            &mut clock,
            ProvenanceEvent::AttemptStarted {
                attempt_id,
                parent_attempt_id: None,
                phase,
                actor: actor(),
                timeout_ms: 10_000,
                command: selected_command.clone(),
            },
        );

        if phase == ExecutionPhase::Validate {
            let mut primary_artifact = artifact(attempt_id, options.artifact_kind, "primary", 8);
            if options.primary_truncated {
                primary_artifact.truncated = true;
                primary_artifact.observed_bytes = Some(16);
            }
            let primary_artifact_id = primary_artifact.artifact_id;
            append_event(
                &mut provenance,
                &mut clock,
                ProvenanceEvent::ArtifactRecorded {
                    artifact: primary_artifact,
                },
            );
            for (index, kind) in options.extra_artifacts.iter().copied().enumerate() {
                append_event(
                    &mut provenance,
                    &mut clock,
                    ProvenanceEvent::ArtifactRecorded {
                        artifact: artifact(attempt_id, kind, &format!("extra-{index}"), 8),
                    },
                );
            }
            append_event(
                &mut provenance,
                &mut clock,
                ProvenanceEvent::CheckRecorded {
                    check: ValidationCheck {
                        check_id,
                        attempt_id,
                        kind: options.check_kind,
                        outcome: options.check_outcome,
                        evidence: vec![CheckEvidence::Artifact {
                            artifact_id: primary_artifact_id,
                        }],
                    },
                },
            );
        }

        let (outcome, process_exit) = if phase == ExecutionPhase::Package {
            if let Some((outcome, _, process_exit)) = &options.package_failure {
                (*outcome, Some(process_exit.clone()))
            } else if let Some((failure_phase, outcome)) = options.failure_phase
                && failure_phase == phase
            {
                (outcome, None)
            } else if options.not_applicable.contains(&phase) {
                (PhaseOutcome::NotApplicable, None)
            } else if selected_command.is_some() {
                (
                    PhaseOutcome::Succeeded,
                    Some(ProcessExit::Exited { code: 0 }),
                )
            } else {
                (PhaseOutcome::Succeeded, None)
            }
        } else if let Some((failure_phase, outcome)) = options.failure_phase
            && failure_phase == phase
        {
            (outcome, None)
        } else if options.not_applicable.contains(&phase) {
            (PhaseOutcome::NotApplicable, None)
        } else if selected_command.is_some() {
            (
                PhaseOutcome::Succeeded,
                Some(ProcessExit::Exited { code: 0 }),
            )
        } else {
            (PhaseOutcome::Succeeded, None)
        };
        append_event(
            &mut provenance,
            &mut clock,
            ProvenanceEvent::AttemptFinished {
                attempt_id,
                outcome,
                process_exit,
                elapsed_ms: 10,
                stdout_artifact_id: None,
                stderr_artifact_id: None,
            },
        );
    }

    Fixture { provenance, policy }
}

fn mechanical_fixture() -> Fixture {
    let mut options = FixtureOptions::default();
    options.not_applicable.insert(ExecutionPhase::Install);
    build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        options,
    )
}

fn report_codes(report: &ValidationReport) -> BTreeSet<String> {
    report
        .violations()
        .iter()
        .map(|violation| {
            serde_json::to_value(violation)
                .expect("violation serializes")
                .get("type")
                .and_then(Value::as_str)
                .expect("violation has a type tag")
                .to_owned()
        })
        .collect()
}

fn from_mutated_provenance(
    provenance: &RunProvenance,
    mutate: impl FnOnce(&mut Value),
) -> RunProvenance {
    let mut value = serde_json::to_value(provenance).expect("provenance serializes");
    mutate(&mut value);
    serde_json::from_value(value).expect("mutation remains structurally deserializable")
}

fn assert_context_mutation(fixture: &Fixture, label: &str, mutate: impl FnOnce(&mut Value)) {
    let provenance = from_mutated_provenance(&fixture.provenance, mutate);
    let report = provenance.validate(&fixture.policy);
    assert_eq!(
        report.verdict(),
        RunVerdict::Failed,
        "{label} mutation must fail closed"
    );
    assert!(
        report_codes(&report).contains("run_context_hash_mismatch"),
        "{label} was not bound into run_context_sha256: {:?}",
        report.violations()
    );
}

fn assert_unknown_field_rejected<T>(value: &T)
where
    T: Serialize + DeserializeOwned,
{
    let mut wire = serde_json::to_value(value).expect("value serializes");
    wire.as_object_mut()
        .expect("tested wire type is an object")
        .insert("unexpected_field".to_owned(), json!(true));
    assert!(
        serde_json::from_value::<T>(wire).is_err(),
        "{} accepted an unknown field",
        std::any::type_name::<T>()
    );
}

fn first_started_event_with_command(value: &mut Value) -> &mut Value {
    value["records"]
        .as_array_mut()
        .expect("records is an array")
        .iter_mut()
        .find_map(|record| {
            let event = &mut record["event"];
            (event["type"] == "attempt_started" && !event["command"].is_null()).then_some(event)
        })
        .expect("fixture has a command attempt")
}

#[test]
fn uuid_versions_unknown_fields_and_digest_encoding_fail_closed() {
    assert!(serde_json::from_value::<RunId>(json!(Uuid::new_v4())).is_err());
    assert!(serde_json::from_value::<AttemptId>(json!(Uuid::new_v4())).is_err());
    assert!(serde_json::from_value::<CandidateId>(json!(Uuid::now_v7())).is_err());
    assert!(serde_json::from_value::<EvaluationCaseId>(json!(Uuid::now_v7())).is_err());
    assert!(serde_json::from_value::<ArtifactId>(json!(Uuid::now_v7())).is_err());
    assert!(serde_json::from_value::<CheckId>(json!(Uuid::now_v7())).is_err());
    assert!(serde_json::from_value::<BlindAttemptId>(json!(Uuid::now_v7())).is_err());
    assert!(serde_json::from_value::<RunId>(json!(Uuid::nil())).is_err());
    assert!(serde_json::from_value::<CandidateId>(json!(Uuid::nil())).is_err());

    let canonical = digest("canonical").to_string();
    assert_eq!(canonical.len(), 64);
    assert!(canonical.bytes().all(|byte| !byte.is_ascii_uppercase()));
    assert!(serde_json::from_value::<Sha256Digest>(json!(canonical)).is_ok());
    assert!(serde_json::from_value::<Sha256Digest>(json!("A".repeat(64))).is_err());
    assert!(serde_json::from_value::<Sha256Digest>(json!("a".repeat(63))).is_err());
    assert!(serde_json::from_value::<Sha256Digest>(json!("g".repeat(64))).is_err());

    let fixture = mechanical_fixture();
    let first_record = &fixture.provenance.records()[0];
    let started_event = match &first_record.event {
        ProvenanceEvent::AttemptStarted { .. } => &first_record.event,
        _ => panic!("first fixture event is an attempt start"),
    };
    assert_unknown_field_rejected(fixture.provenance.bounds());
    assert_unknown_field_rejected(fixture.provenance.environment());
    assert_unknown_field_rejected(fixture.provenance.manifest());
    assert_unknown_field_rejected(fixture.provenance.target());
    assert_unknown_field_rejected(started_event);
    assert_unknown_field_rejected(&fixture.policy);
    assert_unknown_field_rejected(&fixture.provenance);

    let mut path = serde_json::to_value(WorkspacePath::from_unix_bytes(b"path".to_vec()))
        .expect("path serializes");
    path["wire_version"] = json!(999);
    assert!(serde_json::from_value::<WorkspacePath>(path).is_err());
}

#[test]
fn adapter_requirements_are_composite_and_catalogs_never_claim_defaults() {
    let mac_cli = mac_cli_target();
    let windows_cli = windows_cli_target();
    let mac_web = web_target(ExecutionPlatform::MacOs {
        host_id: target_id("mac-web-host"),
    });
    let windows_web = web_target(ExecutionPlatform::Windows {
        host_id: target_id("windows-web-host"),
    });

    let mac_cli_requirement = mac_cli.required_adapter().expect("valid requirement");
    let windows_cli_requirement = windows_cli.required_adapter().expect("valid requirement");
    let mac_web_requirement = mac_web.required_adapter().expect("valid requirement");
    let windows_web_requirement = windows_web.required_adapter().expect("valid requirement");
    assert_eq!(mac_cli_requirement.kind, AdapterKind::Cli);
    assert_eq!(windows_cli_requirement.kind, AdapterKind::Cli);
    assert_eq!(mac_web_requirement.kind, AdapterKind::PlaywrightWeb);
    assert_eq!(windows_web_requirement.kind, AdapterKind::PlaywrightWeb);
    assert_eq!(mac_cli_requirement.platform, ExecutionPlatformKind::MacOs);
    assert_eq!(
        windows_cli_requirement.platform,
        ExecutionPlatformKind::Windows
    );
    assert_ne!(mac_cli_requirement, windows_cli_requirement);
    assert_ne!(mac_web_requirement, windows_web_requirement);

    let empty = AdapterCatalog::default();
    assert_eq!(empty.declarations().count(), 0);
    assert!(matches!(
        empty.resolve(&mac_cli),
        Err(TargetError::AdapterUnavailable { .. })
    ));

    let declaration = AdapterDeclaration {
        requirement: mac_cli_requirement,
        implementation_id: target_id("mac-cli-adapter"),
        version: target_id("1"),
        implementation_sha256: digest("mac-cli-adapter"),
    };
    let catalog = AdapterCatalog::new([declaration.clone()]).expect("single declaration is valid");
    assert_eq!(catalog.resolve(&mac_cli), Ok(&declaration));
    let catalog_wire = serde_json::to_value(&catalog).expect("catalog serializes as a list");
    assert!(catalog_wire.is_array());
    assert_eq!(
        serde_json::from_value::<AdapterCatalog>(catalog_wire.clone())
            .expect("catalog list round-trips"),
        catalog
    );
    let duplicate_wire = json!([catalog_wire[0].clone(), catalog_wire[0].clone()]);
    assert!(serde_json::from_value::<AdapterCatalog>(duplicate_wire).is_err());
    assert!(matches!(
        catalog.resolve(&windows_cli),
        Err(TargetError::AdapterUnavailable { .. })
    ));
    assert!(matches!(
        AdapterCatalog::new([declaration.clone(), declaration]),
        Err(TargetError::DuplicateAdapter { .. })
    ));

    let unsupported = ExecutionTarget::new(
        target_id("bad-desktop"),
        ExecutionPlatform::Android {
            device_id: target_id("android-device"),
        },
        TargetSurface::DesktopApplication {
            application_id: target_id("desktop-app"),
            bundle_id: None,
        },
    );
    assert!(matches!(
        unsupported,
        Err(TargetError::UnsupportedTargetCombination { .. })
    ));

    let credentialed = ExecutionTarget::new(
        target_id("credentialed-web"),
        ExecutionPlatform::MacOs {
            host_id: target_id("host"),
        },
        TargetSurface::WebPlaywright {
            url: Url::parse("https://user:password@example.invalid/").expect("static URL is valid"),
        },
    );
    assert!(matches!(
        credentialed,
        Err(TargetError::CredentialedUrl { .. })
    ));
}

#[test]
fn wrong_adapter_declaration_cannot_accumulate_trusted_provenance() {
    let target = mac_cli_target();
    let check_id = CheckId::new();
    let policy = default_policy(check_id);
    let mut wrong_manifest = manifest(&target, &policy);
    wrong_manifest.adapter.requirement.platform = ExecutionPlatformKind::Windows;
    let mut provenance = RunProvenance::new(
        CandidateId::new(),
        EvaluationCaseId::new(),
        target,
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        wrong_manifest,
    )
    .expect("the immutable malformed header remains inspectable");
    let attempt_id = AttemptId::new();
    let result = provenance.append(
        1,
        ProvenanceEvent::AttemptStarted {
            attempt_id,
            parent_attempt_id: None,
            phase: ExecutionPhase::Prepare,
            actor: actor(),
            timeout_ms: 10,
            command: None,
        },
    );
    assert_eq!(result, Err(AppendError::InvalidExistingLog));
    assert!(provenance.records().is_empty());
    assert!(report_codes(&provenance.validate(&policy)).contains("adapter_binding_mismatch"));
}

#[test]
fn complete_lifecycle_requires_all_twelve_phases_in_order_and_explicit_na() {
    let complete = mechanical_fixture();
    let report = complete.provenance.validate(&complete.policy);
    assert_eq!(report.verdict(), RunVerdict::CompletePass);
    assert!(report.is_accepted());

    let observed_phases: Vec<_> = complete
        .provenance
        .records()
        .iter()
        .filter_map(|record| match record.event {
            ProvenanceEvent::AttemptStarted { phase, .. } => Some(phase),
            _ => None,
        })
        .collect();
    assert_eq!(observed_phases, EXECUTION_PHASES);
    assert!(complete.provenance.records().iter().any(|record| matches!(
        record.event,
        ProvenanceEvent::AttemptFinished {
            outcome: PhaseOutcome::NotApplicable,
            ..
        }
    )));

    let check_id = CheckId::new();
    let empty_policy = default_policy(check_id);
    let empty = new_provenance(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        &empty_policy,
    );
    let empty_report = empty.validate(&empty_policy);
    assert_ne!(empty_report.verdict(), RunVerdict::CompletePass);
    assert_eq!(
        empty_report
            .violations()
            .iter()
            .filter(|violation| matches!(
                violation,
                ValidationViolation::MissingPhaseTerminal { .. }
            ))
            .count(),
        12
    );

    let single = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            phases: vec![ExecutionPhase::Prepare],
            ..FixtureOptions::default()
        },
    );
    assert_ne!(
        single.provenance.validate(&single.policy).verdict(),
        RunVerdict::CompletePass
    );

    let omitted = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            phases: EXECUTION_PHASES
                .into_iter()
                .filter(|phase| *phase != ExecutionPhase::Install)
                .collect(),
            ..FixtureOptions::default()
        },
    );
    let omitted_report = omitted.provenance.validate(&omitted.policy);
    assert_ne!(omitted_report.verdict(), RunVerdict::CompletePass);
    assert!(omitted_report.violations().iter().any(|violation| matches!(
        violation,
        ValidationViolation::MissingPhaseTerminal {
            phase: ExecutionPhase::Install
        }
    )));
}

#[test]
fn phase_regression_is_rejected_prospectively_without_mutating_the_log() {
    let check_id = CheckId::new();
    let policy = default_policy(check_id);
    let mut provenance = new_provenance(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        &policy,
    );
    let mut clock = 10;
    let prepare = AttemptId::new();
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::AttemptStarted {
            attempt_id: prepare,
            parent_attempt_id: None,
            phase: ExecutionPhase::Prepare,
            actor: actor(),
            timeout_ms: 100,
            command: None,
        },
    );
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::AttemptFinished {
            attempt_id: prepare,
            outcome: PhaseOutcome::Succeeded,
            process_exit: None,
            elapsed_ms: 1,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
        },
    );
    let build = AttemptId::new();
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::AttemptStarted {
            attempt_id: build,
            parent_attempt_id: None,
            phase: ExecutionPhase::Build,
            actor: actor(),
            timeout_ms: 100,
            command: None,
        },
    );
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::AttemptFinished {
            attempt_id: build,
            outcome: PhaseOutcome::Succeeded,
            process_exit: None,
            elapsed_ms: 1,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
        },
    );

    let records_before = serde_json::to_value(provenance.records()).expect("records serialize");
    let result = provenance.append(
        clock,
        ProvenanceEvent::AttemptStarted {
            attempt_id: AttemptId::new(),
            parent_attempt_id: None,
            phase: ExecutionPhase::Prepare,
            actor: actor(),
            timeout_ms: 100,
            command: None,
        },
    );
    assert_eq!(result, Err(AppendError::InvalidNewRecord));
    assert_eq!(
        serde_json::to_value(provenance.records()).expect("records serialize"),
        records_before
    );
}

#[test]
fn vision_only_evidence_can_never_accept_a_candidate() {
    let fixture = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            check_kind: CheckKind::Visual,
            artifact_kind: ArtifactKind::Screenshot,
            ..FixtureOptions::default()
        },
    );
    let report = fixture.provenance.validate(&fixture.policy);
    assert!(!report.is_accepted());
    assert_ne!(report.verdict(), RunVerdict::CompletePass);
    assert!(report_codes(&report).contains("insufficient_primary_passes"));
}

#[test]
fn failures_malformed_evidence_and_infrastructure_errors_never_self_exclude() {
    let failed_check = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            check_outcome: CheckOutcome::Failed,
            ..FixtureOptions::default()
        },
    );
    assert_eq!(
        failed_check
            .provenance
            .validate(&failed_check.policy)
            .verdict(),
        RunVerdict::Failed
    );

    let valid = mechanical_fixture();
    let malformed = from_mutated_provenance(&valid.provenance, |value| {
        let check = value["records"]
            .as_array_mut()
            .expect("records is an array")
            .iter_mut()
            .find(|record| record["event"]["type"] == "check_recorded")
            .expect("fixture has a check");
        check["event"]["check"]["evidence"][0]["artifact_id"] = json!(ArtifactId::new());
    });
    let malformed_report = malformed.validate(&valid.policy);
    assert_eq!(malformed_report.verdict(), RunVerdict::Failed);
    assert_ne!(
        malformed_report.verdict(),
        RunVerdict::InfrastructureInvalid
    );
    assert!(malformed_report.has_structural_violations());

    let infrastructure_error = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            package_failure: Some((
                PhaseOutcome::InfrastructureError,
                command(NativeFamily::Unix),
                ProcessExit::LaunchFailed {
                    failure_code: target_id("infra-launch-failure"),
                },
            )),
            ..FixtureOptions::default()
        },
    );
    let infrastructure_report = infrastructure_error
        .provenance
        .validate(&infrastructure_error.policy);
    assert_eq!(infrastructure_report.verdict(), RunVerdict::Failed);
    assert_ne!(
        infrastructure_report.verdict(),
        RunVerdict::InfrastructureInvalid
    );

    let corrupt_hash = from_mutated_provenance(&valid.provenance, |value| {
        value["records"][0]["record_sha256"] = json!(digest("forged-record"));
    });
    let corrupt_report = corrupt_hash.validate(&valid.policy);
    assert_eq!(corrupt_report.verdict(), RunVerdict::Failed);
    assert_ne!(corrupt_report.verdict(), RunVerdict::InfrastructureInvalid);
}

#[test]
fn every_reproducibility_input_is_bound_into_the_run_context_digest() {
    let fixture = mechanical_fixture();
    let replacement = digest("mutated");
    assert_context_mutation(&fixture, "source workspace", |value| {
        value["manifest"]["source_workspace_snapshot_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "task fixture", |value| {
        value["manifest"]["task_fixture_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "validation plan", |value| {
        value["manifest"]["validation_plan_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "validation policy", |value| {
        value["manifest"]["validation_policy_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "harness configuration", |value| {
        value["manifest"]["harness_configuration_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "adapter", |value| {
        value["manifest"]["adapter"]["implementation_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "permission policy", |value| {
        value["manifest"]["permission_policy_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "network policy", |value| {
        value["manifest"]["network_policy_sha256"] = json!(replacement);
    });
    assert_context_mutation(&fixture, "target", |value| {
        value["target"]["target_id"] = json!(target_id("mutated-target"));
    });
    assert_context_mutation(&fixture, "execution bounds", |value| {
        value["bounds"]["max_stdout_bytes"] = json!(123_456_u64);
    });
    assert_context_mutation(&fixture, "environment", |value| {
        value["environment"]["architecture"] = json!("mutated-architecture");
    });
    assert_context_mutation(&fixture, "schema version", |value| {
        value["schema_version"] = json!(2);
    });
    assert_context_mutation(&fixture, "run identity", |value| {
        value["run_id"] = json!(RunId::new());
    });
    assert_context_mutation(&fixture, "candidate identity", |value| {
        value["candidate_id"] = json!(CandidateId::new());
    });
    assert_context_mutation(&fixture, "evaluation case identity", |value| {
        value["evaluation_case_id"] = json!(EvaluationCaseId::new());
    });

    let schema_mutation = from_mutated_provenance(&fixture.provenance, |value| {
        value["schema_version"] = json!(2);
    });
    let schema_report = schema_mutation.validate(&fixture.policy);
    let schema_codes = report_codes(&schema_report);
    assert!(schema_codes.contains("unsupported_schema_version"));
    assert!(schema_codes.contains("run_context_hash_mismatch"));
    assert!(schema_codes.contains("record_hash_mismatch"));
}

#[test]
fn append_is_prospective_transactional_and_enforces_causality() {
    let check_id = CheckId::new();
    let policy = default_policy(check_id);
    let mut provenance = new_provenance(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        &policy,
    );
    let unknown_attempt = AttemptId::new();
    assert_eq!(
        provenance.append(
            1,
            ProvenanceEvent::AttemptFinished {
                attempt_id: unknown_attempt,
                outcome: PhaseOutcome::Succeeded,
                process_exit: None,
                elapsed_ms: 1,
                stdout_artifact_id: None,
                stderr_artifact_id: None,
            }
        ),
        Err(AppendError::InvalidNewRecord)
    );
    assert!(provenance.records().is_empty());

    let prepare = AttemptId::new();
    provenance
        .append(
            2,
            ProvenanceEvent::AttemptStarted {
                attempt_id: prepare,
                parent_attempt_id: None,
                phase: ExecutionPhase::Prepare,
                actor: actor(),
                timeout_ms: 100,
                command: None,
            },
        )
        .expect("first start is valid");
    let stable_records = serde_json::to_value(provenance.records()).expect("records serialize");

    let invalid_events = [
        ProvenanceEvent::AttemptStarted {
            attempt_id: prepare,
            parent_attempt_id: None,
            phase: ExecutionPhase::Prepare,
            actor: actor(),
            timeout_ms: 100,
            command: None,
        },
        ProvenanceEvent::AttemptStarted {
            attempt_id: AttemptId::new(),
            parent_attempt_id: Some(AttemptId::new()),
            phase: ExecutionPhase::Prepare,
            actor: actor(),
            timeout_ms: 100,
            command: None,
        },
        ProvenanceEvent::ArtifactRecorded {
            artifact: artifact(AttemptId::new(), ArtifactKind::RuntimeLog, "orphan", 1),
        },
        ProvenanceEvent::CheckRecorded {
            check: ValidationCheck {
                check_id: CheckId::new(),
                attempt_id: prepare,
                kind: CheckKind::Test,
                outcome: CheckOutcome::Passed,
                evidence: vec![CheckEvidence::Artifact {
                    artifact_id: ArtifactId::new(),
                }],
            },
        },
    ];
    for event in invalid_events {
        assert_eq!(
            provenance.append(3, event),
            Err(AppendError::InvalidNewRecord)
        );
        assert_eq!(
            serde_json::to_value(provenance.records()).expect("records serialize"),
            stable_records
        );
    }
    assert_eq!(
        provenance.append(
            1,
            ProvenanceEvent::AttemptFinished {
                attempt_id: prepare,
                outcome: PhaseOutcome::Succeeded,
                process_exit: None,
                elapsed_ms: 1,
                stdout_artifact_id: None,
                stderr_artifact_id: None,
            }
        ),
        Err(AppendError::InvalidNewRecord)
    );
    assert_eq!(
        serde_json::to_value(provenance.records()).expect("records serialize"),
        stable_records
    );

    let mut tampered = from_mutated_provenance(&provenance, |value| {
        value["records"][0]["sequence"] = json!(99);
    });
    assert_eq!(
        tampered.append(
            3,
            ProvenanceEvent::AttemptFinished {
                attempt_id: prepare,
                outcome: PhaseOutcome::Succeeded,
                process_exit: None,
                elapsed_ms: 1,
                stdout_artifact_id: None,
                stderr_artifact_id: None,
            }
        ),
        Err(AppendError::InvalidExistingLog)
    );
}

#[test]
fn sequence_timestamp_previous_hash_record_hash_and_context_invariants_are_observable() {
    let fixture = mechanical_fixture();
    let cases: [(&str, fn(&mut Value), &str); 4] = [
        (
            "sequence",
            |value| value["records"][1]["sequence"] = json!(99),
            "non_contiguous_sequence",
        ),
        (
            "timestamp",
            |value| value["records"][1]["observed_at_unix_ms"] = json!(0),
            "timestamp_regressed",
        ),
        (
            "previous hash",
            |value| {
                value["records"][1]["previous_record_sha256"] = json!(digest("wrong-previous"));
            },
            "previous_record_hash_mismatch",
        ),
        (
            "record hash",
            |value| value["records"][0]["record_sha256"] = json!(digest("wrong-record")),
            "record_hash_mismatch",
        ),
    ];
    for (label, mutate, expected_code) in cases {
        let provenance = from_mutated_provenance(&fixture.provenance, mutate);
        let report = provenance.validate(&fixture.policy);
        assert_eq!(report.verdict(), RunVerdict::Failed, "{label}");
        assert!(
            report_codes(&report).contains(expected_code),
            "{label}: {:?}",
            report.violations()
        );
    }
}

#[test]
fn blind_projection_is_panic_free_failure_preserving_and_attribution_free() {
    let fixture = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            package_failure: Some((
                PhaseOutcome::CandidateFailure,
                command(NativeFamily::Unix),
                ProcessExit::LaunchFailed {
                    failure_code: target_id(SENSITIVE_FAILURE),
                },
            )),
            ..FixtureOptions::default()
        },
    );
    let source_json = serde_json::to_string(&fixture.provenance).expect("source serializes");
    for marker in [
        SENSITIVE_PROVIDER,
        SENSITIVE_MODEL,
        SENSITIVE_AGENT,
        SENSITIVE_TARGET,
        SENSITIVE_HOST,
        SENSITIVE_STORAGE,
        SENSITIVE_FAILURE,
    ] {
        assert!(
            source_json.contains(marker),
            "source fixture lacks {marker}"
        );
    }
    assert!(source_json.contains("command"));
    assert!(source_json.contains("executable"));

    let source_candidate_id = fixture.provenance.candidate_id().as_uuid().to_string();
    let report = fixture.provenance.validate(&fixture.policy);
    assert_eq!(report.verdict(), RunVerdict::Failed);
    assert!(!report.has_structural_violations());
    let sealed = fixture
        .provenance
        .clone()
        .seal(fixture.policy.clone())
        .expect("ordinary candidate failures can be sealed");
    assert_eq!(sealed.report(), &report);
    let package = sealed
        .build_blind_evaluation_package()
        .expect("ordinary candidate failures remain blind-evaluable");
    assert!(package.input.attempts.iter().any(|attempt| {
        attempt.outcome == PhaseOutcome::CandidateFailure
            && attempt.process_exit == Some(BlindProcessExit::LaunchFailed)
    }));
    let blind_json = serde_json::to_string(&package.input).expect("blind input serializes");
    for forbidden_key in [
        "provider_id",
        "model_id",
        "agent_id",
        "command",
        "environment",
        "target_id",
        "host_id",
        "storage_ref",
        "failure_code",
        "executable",
        "working_directory",
        "elapsed_ms",
        "sha256",
        "retained_bytes",
        "observed_bytes",
        "media_type",
    ] {
        assert!(
            !blind_json.contains(&format!("\"{forbidden_key}\"")),
            "blind input leaked key {forbidden_key}: {blind_json}"
        );
    }
    for marker in [
        SENSITIVE_PROVIDER,
        SENSITIVE_MODEL,
        SENSITIVE_AGENT,
        SENSITIVE_TARGET,
        SENSITIVE_HOST,
        SENSITIVE_STORAGE,
        SENSITIVE_FAILURE,
    ] {
        assert!(!blind_json.contains(marker), "blind input leaked {marker}");
    }
    assert!(!blind_json.contains(&source_candidate_id));
    assert_eq!(
        package.input_sha256,
        Sha256Digest::of_bytes(
            &serde_json::to_vec(&package.input).expect("blind input serializes canonically")
        )
    );

    let malformed = from_mutated_provenance(&fixture.provenance, |value| {
        value["records"][0]["record_sha256"] = json!(digest("malformed"));
    });
    let sealing = catch_unwind(AssertUnwindSafe(|| malformed.seal(fixture.policy.clone())));
    assert!(sealing.is_ok(), "structural seal gate panicked");
    assert!(sealing.expect("panic was checked").is_err());
}

#[test]
fn every_execution_bound_is_enforced() {
    let options = FixtureOptions {
        build_command: Some(command(NativeFamily::Unix)),
        extra_artifacts: vec![
            ArtifactKind::RuntimeLog,
            ArtifactKind::Trace,
            ArtifactKind::Screenshot,
            ArtifactKind::Video,
        ],
        ..FixtureOptions::default()
    };
    let fixture = build_fixture(
        web_target(ExecutionPlatform::MacOs {
            host_id: target_id(SENSITIVE_HOST),
        }),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        options,
    );
    assert_eq!(
        fixture.provenance.validate(&fixture.policy).verdict(),
        RunVerdict::CompletePass
    );

    let cases = [
        ("max_records", 1_u64, "record_count_out_of_bounds"),
        ("max_attempts", 1, "attempt_count_out_of_bounds"),
        ("max_checks", 0, "check_count_out_of_bounds"),
        (
            "max_check_evidence_items",
            0,
            "check_evidence_items_out_of_bounds",
        ),
        (
            "max_total_evidence_items",
            0,
            "total_evidence_items_out_of_bounds",
        ),
        (
            "max_total_elapsed_ms",
            1,
            "total_elapsed_time_out_of_bounds",
        ),
        ("max_timeout_ms", 0_u64, "zero_maximum_timeout"),
        ("max_argv_items", 0, "argv_items_out_of_bounds"),
        ("max_argument_bytes", 1, "argument_bytes_out_of_bounds"),
        ("max_path_bytes", 1, "path_out_of_bounds"),
        (
            "max_environment_entries",
            0,
            "environment_entries_out_of_bounds",
        ),
        (
            "max_environment_bytes",
            1,
            "environment_bytes_out_of_bounds",
        ),
        (
            "max_toolchain_entries",
            0,
            "toolchain_entries_out_of_bounds",
        ),
        (
            "max_metadata_bytes",
            1,
            "environment_metadata_out_of_bounds",
        ),
        ("max_url_bytes", 1, "target_url_out_of_bounds"),
        ("max_storage_ref_bytes", 1, "storage_ref_out_of_bounds"),
        ("max_stdin_bytes", 1, "stdin_out_of_bounds"),
        ("max_stdout_bytes", 1, "capture_out_of_bounds"),
        ("max_stderr_bytes", 1, "capture_out_of_bounds"),
        ("max_artifacts", 0, "artifact_count_out_of_bounds"),
        ("max_artifact_bytes", 1, "artifact_out_of_bounds"),
        (
            "max_total_artifact_bytes",
            1,
            "total_artifact_bytes_out_of_bounds",
        ),
        ("max_runtime_log_bytes", 1, "artifact_kind_out_of_bounds"),
        ("max_trace_bytes", 1, "artifact_kind_out_of_bounds"),
        ("max_screenshots", 0, "screenshot_count_out_of_bounds"),
        ("max_videos", 0, "video_count_out_of_bounds"),
    ];
    for (field, maximum, expected_code) in cases {
        let provenance = from_mutated_provenance(&fixture.provenance, |value| {
            value["bounds"][field] = json!(maximum);
        });
        let report = provenance.validate(&fixture.policy);
        assert!(
            report_codes(&report).contains(expected_code),
            "bound {field} was not enforced: {:?}",
            report.violations()
        );
        assert_eq!(report.verdict(), RunVerdict::Failed, "bound {field}");
    }

    let stdout_report = from_mutated_provenance(&fixture.provenance, |value| {
        value["bounds"]["max_stdout_bytes"] = json!(1);
    })
    .validate(&fixture.policy);
    assert!(stdout_report.violations().iter().any(|violation| matches!(
        violation,
        ValidationViolation::CaptureOutOfBounds {
            stream: ArtifactKind::StdoutLog,
            ..
        }
    )));
    let stderr_report = from_mutated_provenance(&fixture.provenance, |value| {
        value["bounds"]["max_stderr_bytes"] = json!(1);
    })
    .validate(&fixture.policy);
    assert!(stderr_report.violations().iter().any(|violation| matches!(
        violation,
        ValidationViolation::CaptureOutOfBounds {
            stream: ArtifactKind::StderrLog,
            ..
        }
    )));
}

#[test]
fn native_unix_and_windows_encodings_are_lossless_and_mismatch_safe() {
    let mut unix_command = command(NativeFamily::Unix);
    unix_command.arguments = vec![RetainedArgument::PlainText {
        value: NativeArgument::from_unix_bytes(vec![0xff, 0xfe, b'x']),
    }];
    unix_command.executable = WorkspacePath::from_unix_bytes(vec![b'/', 0xff, b'x']);
    let unix_fixture = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            build_command: Some(unix_command),
            ..FixtureOptions::default()
        },
    );
    assert_eq!(
        unix_fixture
            .provenance
            .validate(&unix_fixture.policy)
            .verdict(),
        RunVerdict::CompletePass
    );

    let mut windows_command = command(NativeFamily::Windows);
    windows_command.arguments = vec![RetainedArgument::PlainText {
        value: NativeArgument::from_windows_utf16(vec![0xd800, b'x'.into()]),
    }];
    windows_command.executable =
        WorkspacePath::from_windows_utf16(vec![b'C'.into(), b':'.into(), 0xd800]);
    let windows_fixture = build_fixture(
        windows_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Windows),
        FixtureOptions {
            build_command: Some(windows_command),
            ..FixtureOptions::default()
        },
    );
    assert_eq!(
        windows_fixture
            .provenance
            .validate(&windows_fixture.policy)
            .verdict(),
        RunVerdict::CompletePass
    );

    let nul_unix = from_mutated_provenance(&unix_fixture.provenance, |value| {
        first_started_event_with_command(value)["command"]["arguments"][0] = json!({
            "retention": "plain_text",
            "value": {
                "encoding": "unix_bytes",
                "bytes": [0]
            }
        });
    });
    assert!(
        nul_unix
            .validate(&unix_fixture.policy)
            .violations()
            .iter()
            .any(|violation| matches!(
                violation,
                ValidationViolation::CommandValueContainsNul {
                    component: CommandComponent::Argument { index: 0 },
                    ..
                }
            ))
    );

    let wrong_windows_encoding = from_mutated_provenance(&windows_fixture.provenance, |value| {
        first_started_event_with_command(value)["command"]["arguments"][0] = json!({
            "retention": "plain_text",
            "value": {
                "encoding": "unix_bytes",
                "bytes": [120]
            }
        });
    });
    assert!(
        wrong_windows_encoding
            .validate(&windows_fixture.policy)
            .violations()
            .iter()
            .any(|violation| matches!(
                violation,
                ValidationViolation::CommandEncodingMismatch {
                    component: CommandComponent::Argument { index: 0 },
                    ..
                }
            ))
    );

    let wrong_unix_path = from_mutated_provenance(&unix_fixture.provenance, |value| {
        first_started_event_with_command(value)["command"]["working_directory"] =
            serde_json::to_value(WorkspacePath::from_windows_utf16(vec![
                b'C'.into(),
                b':'.into(),
            ]))
            .expect("path serializes");
    });
    assert!(
        wrong_unix_path
            .validate(&unix_fixture.policy)
            .violations()
            .iter()
            .any(|violation| matches!(
                violation,
                ValidationViolation::CommandEncodingMismatch {
                    component: CommandComponent::WorkingDirectory,
                    ..
                }
            ))
    );

    let snapshot_mismatch = from_mutated_provenance(&unix_fixture.provenance, |value| {
        value["environment"]["selected_variables"][0]["name"] = json!({
            "encoding": "windows_utf16",
            "code_units": [80, 65, 84, 72]
        });
    });
    assert!(
        snapshot_mismatch
            .validate(&unix_fixture.policy)
            .violations()
            .iter()
            .any(|violation| matches!(
                violation,
                ValidationViolation::EnvironmentValueEncodingMismatch { index: 0, .. }
            ))
    );
}

#[test]
fn environment_metadata_edges_are_bounded_and_nonempty() {
    let fixture = mechanical_fixture();
    let empty_architecture = from_mutated_provenance(&fixture.provenance, |value| {
        value["environment"]["architecture"] = json!("");
    });
    assert!(
        empty_architecture
            .validate(&fixture.policy)
            .violations()
            .iter()
            .any(|violation| matches!(
                violation,
                ValidationViolation::EnvironmentMetadataEmpty {
                    field: EnvironmentMetadataField::Architecture
                }
            ))
    );
}

#[test]
fn typed_rules_reject_all_na_truncated_and_duplicate_evidence() {
    let all_na = EXECUTION_PHASES.into_iter().collect();
    let forged = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            not_applicable: all_na,
            check_kind: CheckKind::Compiler,
            artifact_kind: ArtifactKind::CompilerOutput,
            ..FixtureOptions::default()
        },
    );
    let forged_report = forged.provenance.validate(&forged.policy);
    assert_eq!(forged_report.verdict(), RunVerdict::Failed);
    assert!(report_codes(&forged_report).contains("zero_required_success_phases"));

    let truncated = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            primary_truncated: true,
            ..FixtureOptions::default()
        },
    );
    let truncated_report = truncated.provenance.validate(&truncated.policy);
    let truncated_codes = report_codes(&truncated_report);
    assert!(truncated_codes.contains("truncated_artifact_evidence_disallowed"));
    assert!(truncated_codes.contains("insufficient_primary_passes"));
    assert!(!truncated_report.has_structural_violations());
    let package = truncated
        .provenance
        .clone()
        .seal(truncated.policy.clone())
        .expect("typed outcome rejection remains sealable")
        .build_blind_evaluation_package()
        .expect("sealed rejected outcome remains blindable");
    assert!(
        package
            .input
            .artifacts
            .iter()
            .any(|artifact| artifact.truncated)
    );
    assert!(
        package
            .input
            .policy
            .check_requirements
            .iter()
            .all(|requirement| !requirement.allow_truncated_artifacts)
    );

    let fixture = mechanical_fixture();
    let mut stricter_policy_wire =
        serde_json::to_value(&fixture.policy).expect("policy serializes");
    stricter_policy_wire["check_requirements"]
        .as_object_mut()
        .expect("check requirements are a map")
        .values_mut()
        .next()
        .expect("fixture has a requirement")["minimum_evidence_items"] = json!(2);
    let stricter_policy: ValidationPolicy =
        serde_json::from_value(stricter_policy_wire).expect("policy deserializes");
    let duplicate = from_mutated_provenance(&fixture.provenance, |value| {
        let check = value["records"]
            .as_array_mut()
            .expect("records is an array")
            .iter_mut()
            .find(|record| record["event"]["type"] == "check_recorded")
            .expect("fixture has a check");
        let evidence = check["event"]["check"]["evidence"][0].clone();
        check["event"]["check"]["evidence"]
            .as_array_mut()
            .expect("evidence is an array")
            .push(evidence);
    });
    let duplicate_codes = report_codes(&duplicate.validate(&stricter_policy));
    assert!(duplicate_codes.contains("duplicate_check_evidence"));
    assert!(duplicate_codes.contains("check_evidence_count_below_minimum"));
    assert!(duplicate_codes.contains("insufficient_primary_passes"));
}

#[test]
fn target_environment_secret_sizes_encodings_and_environment_names_fail_closed() {
    let check_id = CheckId::new();
    let policy = default_policy(check_id);
    let mismatch = new_provenance(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Windows),
        &policy,
    );
    assert!(report_codes(&mismatch.validate(&policy)).contains("target_environment_mismatch"));

    let fixture = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            build_command: Some(command(NativeFamily::Unix)),
            ..FixtureOptions::default()
        },
    );
    let secret = from_mutated_provenance(&fixture.provenance, |value| {
        let command = &mut first_started_event_with_command(value)["command"];
        command["arguments"][0] = json!({
            "retention": "secret_reference",
            "reference": "x",
            "encoding": "unix_bytes",
            "resolved_bytes": 104_857_600_u64
        });
        command["stdin"] = json!({
            "retention": "secret_reference",
            "reference": "y",
            "resolved_bytes": 104_857_600_u64
        });
        command["environment"][0]["value"] = json!({
            "retention": "redacted",
            "encoding": "windows_utf16",
            "resolved_bytes": 104_857_600_u64
        });
        let entry = command["environment"][0].clone();
        command["environment"]
            .as_array_mut()
            .expect("environment is an array")
            .push(entry);
    });
    let secret_report = secret.validate(&fixture.policy);
    let secret_codes = report_codes(&secret_report);
    assert!(secret_codes.contains("argument_bytes_out_of_bounds"));
    assert!(secret_codes.contains("stdin_out_of_bounds"));
    assert!(secret_codes.contains("environment_bytes_out_of_bounds"));
    assert!(secret_codes.contains("duplicate_environment_name"));
    assert!(secret_report.violations().iter().any(|violation| matches!(
        violation,
        ValidationViolation::CommandEncodingMismatch {
            component: CommandComponent::EnvironmentValue { .. },
            expected: NativeEncoding::UnixBytes,
            actual: NativeEncoding::WindowsUtf16,
            ..
        }
    )));

    let windows = build_fixture(
        windows_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Windows),
        FixtureOptions {
            build_command: Some(command(NativeFamily::Windows)),
            ..FixtureOptions::default()
        },
    );
    let windows_names = from_mutated_provenance(&windows.provenance, |value| {
        let command = &mut first_started_event_with_command(value)["command"];
        let mut entry = command["environment"][0].clone();
        entry["name"] = json!({
            "encoding": "windows_utf16",
            "code_units": [98, 105, 114, 100, 99, 111, 100, 101, 95, 116, 101, 115, 116]
        });
        command["environment"]
            .as_array_mut()
            .expect("environment is an array")
            .push(entry);
        let mut equals_entry = command["environment"][0].clone();
        equals_entry["name"] = json!({
            "encoding": "windows_utf16",
            "code_units": [61, 67, 58]
        });
        command["environment"]
            .as_array_mut()
            .expect("environment is an array")
            .push(equals_entry);
        value["environment"]["selected_variables"][0]["name"] = json!({
            "encoding": "windows_utf16",
            "code_units": [61, 67, 58]
        });
    });
    let name_codes = report_codes(&windows_names.validate(&windows.policy));
    assert!(name_codes.contains("duplicate_environment_name"));
    assert!(name_codes.contains("environment_name_contains_equals"));
    assert!(name_codes.contains("snapshot_environment_name_contains_equals"));
}

#[test]
fn all_open_attempts_block_advance_and_stream_links_require_same_attempt_and_kind() {
    let check_id = CheckId::new();
    let policy = default_policy(check_id);
    let mut provenance = new_provenance(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        &policy,
    );
    let mut clock = 100;
    let first = AttemptId::new();
    let second = AttemptId::new();
    for attempt_id in [first, second] {
        append_event(
            &mut provenance,
            &mut clock,
            ProvenanceEvent::AttemptStarted {
                attempt_id,
                parent_attempt_id: None,
                phase: ExecutionPhase::Prepare,
                actor: actor(),
                timeout_ms: 1_000,
                command: None,
            },
        );
    }
    let wrong_attempt = artifact(second, ArtifactKind::StdoutLog, "wrong-attempt", 1);
    let wrong_attempt_id = wrong_attempt.artifact_id;
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::ArtifactRecorded {
            artifact: wrong_attempt,
        },
    );
    let wrong_kind = artifact(first, ArtifactKind::RuntimeLog, "wrong-kind", 1);
    let wrong_kind_id = wrong_kind.artifact_id;
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::ArtifactRecorded {
            artifact: wrong_kind,
        },
    );
    for artifact_id in [wrong_attempt_id, wrong_kind_id] {
        assert_eq!(
            provenance.append(
                clock,
                ProvenanceEvent::AttemptFinished {
                    attempt_id: first,
                    outcome: PhaseOutcome::Succeeded,
                    process_exit: None,
                    elapsed_ms: 1,
                    stdout_artifact_id: Some(artifact_id),
                    stderr_artifact_id: None,
                }
            ),
            Err(AppendError::InvalidNewRecord)
        );
    }
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::AttemptFinished {
            attempt_id: first,
            outcome: PhaseOutcome::Succeeded,
            process_exit: None,
            elapsed_ms: 1,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
        },
    );
    let stable_len = provenance.records().len();
    assert_eq!(
        provenance.append(
            clock,
            ProvenanceEvent::AttemptStarted {
                attempt_id: AttemptId::new(),
                parent_attempt_id: None,
                phase: ExecutionPhase::Build,
                actor: actor(),
                timeout_ms: 1_000,
                command: None,
            }
        ),
        Err(AppendError::InvalidNewRecord)
    );
    assert_eq!(provenance.records().len(), stable_len);
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::AttemptFinished {
            attempt_id: second,
            outcome: PhaseOutcome::Succeeded,
            process_exit: None,
            elapsed_ms: 1,
            stdout_artifact_id: Some(wrong_attempt_id),
            stderr_artifact_id: None,
        },
    );
    append_event(
        &mut provenance,
        &mut clock,
        ProvenanceEvent::AttemptStarted {
            attempt_id: AttemptId::new(),
            parent_attempt_id: None,
            phase: ExecutionPhase::Build,
            actor: actor(),
            timeout_ms: 1_000,
            command: None,
        },
    );
}

#[test]
fn seals_bind_terminal_state_and_cancelled_and_early_failed_runs_are_blindable() {
    let fixture = mechanical_fixture();
    let sealed = fixture
        .provenance
        .clone()
        .seal(fixture.policy.clone())
        .expect("complete run seals");
    let sealed_again = fixture
        .provenance
        .clone()
        .seal(fixture.policy.clone())
        .expect("same run seals deterministically");
    assert_eq!(sealed.sealed_run_sha256(), sealed_again.sealed_run_sha256());
    assert_eq!(
        sealed.report_sha256(),
        Sha256Digest::of_bytes(
            &serde_json::to_vec(sealed.report()).expect("sealed report serializes")
        )
    );
    assert_eq!(
        sealed.terminal_record_sha256(),
        fixture
            .provenance
            .records()
            .last()
            .expect("complete run has terminal record")
            .record_sha256
    );

    let mut extended = fixture.provenance.clone();
    let mut clock = extended
        .records()
        .last()
        .expect("complete run has records")
        .observed_at_unix_ms
        + 1;
    let retry = AttemptId::new();
    append_event(
        &mut extended,
        &mut clock,
        ProvenanceEvent::AttemptStarted {
            attempt_id: retry,
            parent_attempt_id: None,
            phase: ExecutionPhase::Package,
            actor: actor(),
            timeout_ms: 1_000,
            command: None,
        },
    );
    append_event(
        &mut extended,
        &mut clock,
        ProvenanceEvent::AttemptFinished {
            attempt_id: retry,
            outcome: PhaseOutcome::Succeeded,
            process_exit: None,
            elapsed_ms: 1,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
        },
    );
    let extended_seal = extended
        .seal(fixture.policy.clone())
        .expect("extended terminal state seals");
    assert_ne!(
        sealed.sealed_run_sha256(),
        extended_seal.sealed_run_sha256()
    );
    assert_ne!(
        sealed.terminal_sequence(),
        extended_seal.terminal_sequence()
    );

    let cancelled = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            package_failure: Some((
                PhaseOutcome::Cancelled,
                command(NativeFamily::Unix),
                ProcessExit::Cancelled,
            )),
            ..FixtureOptions::default()
        },
    );
    assert_eq!(
        cancelled.provenance.validate(&cancelled.policy).verdict(),
        RunVerdict::Cancelled
    );
    assert!(
        cancelled
            .provenance
            .seal(cancelled.policy)
            .expect("cancelled lifecycle seals")
            .build_blind_evaluation_package()
            .expect("cancelled run is blindable")
            .input
            .attempts
            .iter()
            .any(|attempt| attempt.outcome == PhaseOutcome::Cancelled)
    );

    let not_applicable = EXECUTION_PHASES
        .into_iter()
        .filter(|phase| phase.ordinal() > ExecutionPhase::Build.ordinal())
        .collect();
    let failed = build_fixture(
        mac_cli_target(),
        ExecutionBounds::default(),
        environment(NativeFamily::Unix),
        FixtureOptions {
            not_applicable,
            failure_phase: Some((ExecutionPhase::Build, PhaseOutcome::CandidateFailure)),
            ..FixtureOptions::default()
        },
    );
    let failed_report = failed.provenance.validate(&failed.policy);
    assert_eq!(failed_report.verdict(), RunVerdict::Failed);
    assert!(!failed_report.has_structural_violations());
    let failed_input = failed
        .provenance
        .seal(failed.policy)
        .expect("candidate failure with complete lifecycle seals")
        .build_blind_evaluation_package()
        .expect("candidate failure is blindable")
        .input;
    assert!(failed_input.attempts.iter().any(|attempt| {
        attempt.phase == ExecutionPhase::Build && attempt.outcome == PhaseOutcome::CandidateFailure
    }));
    assert!(failed_input.attempts.iter().any(|attempt| {
        attempt.phase == ExecutionPhase::Package && attempt.outcome == PhaseOutcome::NotApplicable
    }));
}
