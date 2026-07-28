//! Canonical conversion and matching for backend and protocol inference identities.

use super::{
    BackendDeploymentId, BackendEndpointOrigin, BackendError, BackendId, BackendInstanceIdentity,
    BackendTransportIdentity, PlannerV2NotDispatchedReason, ProtocolBackendInstanceIdentity,
    RetryDisposition, StoreError, StructuredInferenceResponse,
};

pub(super) fn protocol_backend_instance_identity(
    identity: &BackendInstanceIdentity,
) -> Result<ProtocolBackendInstanceIdentity, StoreError> {
    identity
        .validate_integrity()
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let transport = match identity.transport() {
        BackendTransportIdentity::HttpOrigin { origin } => {
            birdcode_protocol::BackendTransportIdentityV1::HttpOrigin {
                origin: origin.as_str().to_owned(),
            }
        }
    };
    let protocol = ProtocolBackendInstanceIdentity::new(
        identity.backend_id().as_str().to_owned(),
        transport,
        identity.configured_deployment_id().as_str().to_owned(),
    )
    .map_err(|_| StoreError::InvalidStateEvent)?;
    if protocol.identity_sha256.as_str() != identity.identity_sha256().as_str() {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(protocol)
}

pub(super) fn backend_instance_from_protocol_identity(
    identity: &ProtocolBackendInstanceIdentity,
) -> Result<BackendInstanceIdentity, StoreError> {
    identity
        .validate_integrity()
        .map_err(|_| StoreError::InvalidStateEvent)?;
    let transport = match &identity.transport {
        birdcode_protocol::BackendTransportIdentityV1::HttpOrigin { origin } => {
            BackendTransportIdentity::HttpOrigin {
                origin: BackendEndpointOrigin::parse(origin.clone())
                    .map_err(|_| StoreError::InvalidStateEvent)?,
            }
        }
    };
    let backend = BackendInstanceIdentity::new(
        BackendId::new(identity.backend_id.clone()).map_err(|_| StoreError::InvalidStateEvent)?,
        transport,
        BackendDeploymentId::new(identity.configured_deployment_id.clone())
            .map_err(|_| StoreError::InvalidStateEvent)?,
    )
    .map_err(|_| StoreError::InvalidStateEvent)?;
    if backend.identity_sha256().as_str() != identity.identity_sha256.as_str() {
        return Err(StoreError::InvalidStateEvent);
    }
    Ok(backend)
}

pub(super) fn response_matches_protocol_backend_instance(
    identity: &ProtocolBackendInstanceIdentity,
    response: &StructuredInferenceResponse,
) -> bool {
    backend_instance_from_protocol_identity(identity)
        .is_ok_and(|expected| expected.matches_response_evidence(&response.evidence))
}

pub(super) fn error_matches_protocol_backend_instance(
    identity: &ProtocolBackendInstanceIdentity,
    error: &BackendError,
) -> bool {
    backend_instance_from_protocol_identity(identity).is_ok_and(|expected| {
        error.backend_id == *expected.backend_id()
            && error.backend_instance.as_deref() == Some(&expected)
            && error
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.endpoint.as_deref())
                .is_none_or(|endpoint| expected.endpoint_origin().matches_endpoint(endpoint))
    })
}

pub(super) const fn planner_v2_not_dispatched_failure(
    reason: PlannerV2NotDispatchedReason,
) -> birdcode_protocol::PlannerInferenceError {
    use PlannerV2NotDispatchedReason as Reason;
    let (kind, retry) = match reason {
        Reason::DeadlineElapsed => (
            birdcode_protocol::PlannerInferenceErrorKind::Timeout,
            RetryDisposition::Never,
        ),
        Reason::RuntimeShutdown | Reason::SchedulerClosed | Reason::ClaimLost => (
            birdcode_protocol::PlannerInferenceErrorKind::Cancelled,
            RetryDisposition::RequiresNewAttempt,
        ),
        Reason::CancellationRequested => (
            birdcode_protocol::PlannerInferenceErrorKind::Cancelled,
            RetryDisposition::Never,
        ),
        Reason::RequestContextExceeded
        | Reason::ModelProfileDrift
        | Reason::BackendInstanceDrift => (
            birdcode_protocol::PlannerInferenceErrorKind::ProtocolViolation,
            RetryDisposition::Never,
        ),
    };
    birdcode_protocol::PlannerInferenceError { kind, retry }
}
