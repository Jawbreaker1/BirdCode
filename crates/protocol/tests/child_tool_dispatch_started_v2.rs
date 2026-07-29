use birdcode_protocol::{
    ArtifactRef, CHILD_REPOSITORY_EXPLORER_V1_INPUT_WIRE_SHA256,
    CHILD_REPOSITORY_EXPLORER_V1_INTRODUCTION_PROTOCOL_VERSION, ChildActorId, ChildAttemptId,
    ChildContextId, ChildExecutionBinding, ChildExecutionId, ChildLocalPlanBindingV1,
    ChildModelCallId, ChildToolCallId, ChildToolDispatchStartedV2, ChildValidatedActionBindingV1,
    ChildValidatedActionId, ChildWorkOrderId, EventId, EventPayload, PROTOCOL_VERSION,
    RepositoryBrokerInstanceId, RunClaimId, RuntimeClockReading, RuntimeInstanceId, Sha256Digest,
    child_repository_explorer_v1_input_wire_manifest,
};
use chrono::Utc;

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::of_bytes(bytes)
}

fn started() -> ChildToolDispatchStartedV2 {
    let runtime_instance_id = RuntimeInstanceId::new();
    ChildToolDispatchStartedV2 {
        binding: ChildExecutionBinding {
            work_order_id: ChildWorkOrderId::new(),
            execution_id: ChildExecutionId::new(),
            attempt_id: ChildAttemptId::new(),
            child_actor_id: ChildActorId::new(),
            context_id: ChildContextId::new(),
            work_order_digest: digest(b"work-order"),
            context_manifest_digest: digest(b"context"),
        },
        tool_call_id: ChildToolCallId::new(),
        prepared_event_id: EventId::new(),
        action_binding: ChildValidatedActionBindingV1 {
            action_id: ChildValidatedActionId::new(),
            source_model_call_id: ChildModelCallId::new(),
            source_model_call_ordinal: 1,
            source_model_observed_event_id: EventId::new(),
            source_model_evidence_digest: digest(b"model"),
            source_plan: ChildLocalPlanBindingV1 {
                plan_id: birdcode_protocol::ChildLocalPlanId::new(),
                revision: 1,
                plan_digest: digest(b"plan"),
            },
            active_plan_step_id: None,
            completion_handoff_id: None,
            validated_action_artifact: ArtifactRef {
                sha256: digest(b"action").as_str().to_owned(),
                size_bytes: 6,
                media_type: "application/vnd.birdcode.child-validated-action+json".to_owned(),
            },
            validated_action_digest: digest(b"action"),
        },
        prepared_receipt_digest: digest(b"prepared"),
        claim_event_id: EventId::new(),
        claim_id: RunClaimId::new(),
        claim_generation: 4,
        runtime_instance_id,
        cancellation_generation: 2,
        broker_epoch_activation_event_id: EventId::new(),
        broker_instance_id: RepositoryBrokerInstanceId::new(),
        started_at: RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos: 99,
            observed_at: Utc::now(),
        },
    }
}

#[test]
fn protocol_v9_dispatch_start_is_closed_and_additive_to_the_frozen_v7_wire() {
    assert_eq!(PROTOCOL_VERSION, 9);
    assert_eq!(
        CHILD_REPOSITORY_EXPLORER_V1_INTRODUCTION_PROTOCOL_VERSION,
        7
    );
    assert_eq!(
        CHILD_REPOSITORY_EXPLORER_V1_INPUT_WIRE_SHA256,
        "e5685b26aa84646bdf54bb0902234ff682b15c45e88fe26faaec025e306d537e"
    );

    let payload = EventPayload::ChildToolDispatchStartedV2(started());
    let canonical = serde_json::to_value(&payload).expect("dispatch start should encode");
    assert_eq!(canonical["type"], "child_tool_dispatch_started_v2");
    let decoded: EventPayload =
        serde_json::from_value(canonical.clone()).expect("dispatch start should decode");
    assert_eq!(decoded, payload);

    let mut unknown = canonical;
    unknown["data"]["lease_expires_at"] = serde_json::json!("never");
    serde_json::from_value::<EventPayload>(unknown)
        .expect_err("dispatch start must reject unknown fields");

    let frozen = child_repository_explorer_v1_input_wire_manifest();
    let variants = frozen["types"]["EventPayload"]["variants_in_wire_order"]
        .as_array()
        .expect("frozen event variants should be an array");
    assert!(
        !variants
            .iter()
            .any(|variant| variant["wire_name"] == "child_tool_dispatch_started_v2")
    );
}
