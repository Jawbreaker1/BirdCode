//! Exact, provider-neutral routing to configured model backend instances.
//!
//! The registry deliberately has no model-name matching or implicit fallback.
//! A route is the exact provider ID and configured deployment ID attested by a
//! backend instance. Model IDs remain request data and never select transport.

use birdcode_backends::{
    BackendDeploymentId, BackendId, BackendInstanceIdentity, BackendInstanceIdentityError,
    ContractError, ModelBackend,
};
use birdcode_protocol::{BackendInstanceIdentityV1, BackendInstanceIdentityV1Error, ModelLineage};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// Exact lookup key for one configured backend deployment.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendRouteKey {
    backend_id: BackendId,
    configured_deployment_id: BackendDeploymentId,
}

impl BackendRouteKey {
    #[must_use]
    pub const fn new(backend_id: BackendId, configured_deployment_id: BackendDeploymentId) -> Self {
        Self {
            backend_id,
            configured_deployment_id,
        }
    }

    #[must_use]
    pub fn from_instance(identity: &BackendInstanceIdentity) -> Self {
        Self::new(
            identity.backend_id().clone(),
            identity.configured_deployment_id().clone(),
        )
    }

    #[must_use]
    pub const fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    #[must_use]
    pub const fn configured_deployment_id(&self) -> &BackendDeploymentId {
        &self.configured_deployment_id
    }
}

impl TryFrom<&ModelLineage> for BackendRouteKey {
    type Error = BackendRouteKeyError;

    fn try_from(lineage: &ModelLineage) -> Result<Self, Self::Error> {
        let backend_id = BackendId::new(lineage.backend_id.clone())
            .map_err(BackendRouteKeyError::InvalidBackendId)?;
        let configured_deployment_id = BackendDeploymentId::new(lineage.deployment_id.clone())
            .map_err(BackendRouteKeyError::InvalidDeploymentId)?;
        Ok(Self::new(backend_id, configured_deployment_id))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendRouteKeyError {
    InvalidBackendId(ContractError),
    InvalidDeploymentId(BackendInstanceIdentityError),
}

impl fmt::Display for BackendRouteKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBackendId(error) => write!(formatter, "invalid backend ID: {error}"),
            Self::InvalidDeploymentId(error) => {
                write!(formatter, "invalid configured deployment ID: {error}")
            }
        }
    }
}

impl Error for BackendRouteKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBackendId(error) => Some(error),
            Self::InvalidDeploymentId(error) => Some(error),
        }
    }
}

#[derive(Clone)]
struct RegisteredBackend {
    backend: Arc<dyn ModelBackend>,
    identity: BackendInstanceIdentity,
}

/// Immutable registry of explicitly configured backend instances.
///
/// Construction validates every backend-authored identity and rejects route
/// collisions. A primary route exists only when the caller supplies one, and
/// ordinary resolution never falls back to it.
#[derive(Clone)]
pub struct BackendRegistry {
    entries: BTreeMap<BackendRouteKey, RegisteredBackend>,
    primary: Option<BackendRouteKey>,
}

impl BackendRegistry {
    /// Builds a registry and optionally designates one already registered
    /// exact route as primary.
    ///
    /// # Errors
    ///
    /// Rejects invalid or internally inconsistent backend identities,
    /// duplicate route keys, and a primary route that is not registered.
    pub fn new(
        backends: impl IntoIterator<Item = Arc<dyn ModelBackend>>,
        primary: Option<BackendRouteKey>,
    ) -> Result<Self, BackendRegistryError> {
        let mut entries = BTreeMap::new();
        for backend in backends {
            let identity = backend.instance_identity().clone();
            let key = BackendRouteKey::from_instance(&identity);
            validate_instance(&backend, &key, &identity)?;
            if entries
                .insert(key.clone(), RegisteredBackend { backend, identity })
                .is_some()
            {
                return Err(BackendRegistryError::DuplicateRoute(key));
            }
        }

        if let Some(primary_key) = primary.as_ref()
            && !entries.contains_key(primary_key)
        {
            return Err(BackendRegistryError::PrimaryRouteNotRegistered(
                primary_key.clone(),
            ));
        }

        Ok(Self { entries, primary })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn primary_key(&self) -> Option<&BackendRouteKey> {
        self.primary.as_ref()
    }

    /// Resolves only the supplied exact route. The primary is not a fallback.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the route is absent or the registered
    /// backend no longer reports the identity validated at construction.
    pub fn resolve(
        &self,
        key: &BackendRouteKey,
    ) -> Result<Arc<dyn ModelBackend>, BackendRegistryError> {
        let registered = self
            .entries
            .get(key)
            .ok_or_else(|| BackendRegistryError::UnknownRoute(key.clone()))?;
        validate_instance(&registered.backend, key, &registered.identity)?;
        if registered.backend.instance_identity() != &registered.identity {
            return Err(BackendRegistryError::InstanceIdentityChanged(key.clone()));
        }
        Ok(Arc::clone(&registered.backend))
    }

    /// Converts trusted lineage routing fields to typed IDs and resolves them
    /// exactly. `model_id` and `independence_domain_id` do not affect routing.
    ///
    /// # Errors
    ///
    /// Returns a typed route-key or registry error; it never selects a backend
    /// by inspecting the model name.
    pub fn resolve_lineage(
        &self,
        lineage: &ModelLineage,
    ) -> Result<Arc<dyn ModelBackend>, BackendRegistryError> {
        let key =
            BackendRouteKey::try_from(lineage).map_err(BackendRegistryError::InvalidRouteKey)?;
        self.resolve(&key)
    }

    /// Resolves an exact persisted protocol identity and verifies its full
    /// transport-bound attestation against the live backend instance.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid protocol identity material, an absent
    /// route, or any difference between the persisted and live identities.
    pub fn resolve_instance(
        &self,
        expected: &BackendInstanceIdentityV1,
    ) -> Result<Arc<dyn ModelBackend>, BackendRegistryError> {
        expected
            .validate_integrity()
            .map_err(BackendRegistryError::InvalidProtocolInstanceIdentity)?;
        let key = BackendRouteKey::new(
            BackendId::new(expected.backend_id.clone()).map_err(|error| {
                BackendRegistryError::InvalidRouteKey(BackendRouteKeyError::InvalidBackendId(error))
            })?,
            BackendDeploymentId::new(expected.configured_deployment_id.clone()).map_err(
                |error| {
                    BackendRegistryError::InvalidRouteKey(
                        BackendRouteKeyError::InvalidDeploymentId(error),
                    )
                },
            )?,
        );
        let backend = self.resolve(&key)?;
        let actual = backend.instance_identity();
        if expected.backend_id != actual.backend_id().as_str()
            || expected.configured_deployment_id != actual.configured_deployment_id().as_str()
            || expected.endpoint_origin() != actual.endpoint_origin().as_str()
            || expected.identity_sha256.as_str() != actual.identity_sha256().as_str()
        {
            return Err(BackendRegistryError::ProtocolInstanceMismatch(key));
        }
        Ok(backend)
    }

    /// Resolves the explicitly configured primary route, if one exists.
    ///
    /// # Errors
    ///
    /// Returns an integrity error if the registered primary backend changed
    /// identity after registry construction.
    pub fn resolve_primary(&self) -> Result<Option<Arc<dyn ModelBackend>>, BackendRegistryError> {
        self.primary
            .as_ref()
            .map(|key| self.resolve(key))
            .transpose()
    }
}

fn validate_instance(
    backend: &Arc<dyn ModelBackend>,
    key: &BackendRouteKey,
    identity: &BackendInstanceIdentity,
) -> Result<(), BackendRegistryError> {
    identity.validate_integrity().map_err(|source| {
        BackendRegistryError::InvalidInstanceIdentity {
            route: key.clone(),
            source,
        }
    })?;
    if backend.backend_id() != identity.backend_id() {
        return Err(BackendRegistryError::BackendIdMismatch {
            route: key.clone(),
            reported_backend_id: backend.backend_id().clone(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendRegistryError {
    InvalidRouteKey(BackendRouteKeyError),
    InvalidProtocolInstanceIdentity(BackendInstanceIdentityV1Error),
    InvalidInstanceIdentity {
        route: BackendRouteKey,
        source: BackendInstanceIdentityError,
    },
    BackendIdMismatch {
        route: BackendRouteKey,
        reported_backend_id: BackendId,
    },
    DuplicateRoute(BackendRouteKey),
    PrimaryRouteNotRegistered(BackendRouteKey),
    UnknownRoute(BackendRouteKey),
    InstanceIdentityChanged(BackendRouteKey),
    ProtocolInstanceMismatch(BackendRouteKey),
}

impl fmt::Display for BackendRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRouteKey(error) => write!(formatter, "invalid backend route: {error}"),
            Self::InvalidProtocolInstanceIdentity(error) => {
                write!(
                    formatter,
                    "invalid protocol backend instance identity: {error}"
                )
            }
            Self::InvalidInstanceIdentity { route, source } => write!(
                formatter,
                "backend route {} / {} has an invalid instance identity: {source}",
                route.backend_id(),
                route.configured_deployment_id().as_str()
            ),
            Self::BackendIdMismatch {
                route,
                reported_backend_id,
            } => write!(
                formatter,
                "backend route {} / {} is exposed by backend {}",
                route.backend_id(),
                route.configured_deployment_id().as_str(),
                reported_backend_id
            ),
            Self::DuplicateRoute(route) => write!(
                formatter,
                "duplicate backend route {} / {}",
                route.backend_id(),
                route.configured_deployment_id().as_str()
            ),
            Self::PrimaryRouteNotRegistered(route) => write!(
                formatter,
                "primary backend route {} / {} is not registered",
                route.backend_id(),
                route.configured_deployment_id().as_str()
            ),
            Self::UnknownRoute(route) => write!(
                formatter,
                "backend route {} / {} is not registered",
                route.backend_id(),
                route.configured_deployment_id().as_str()
            ),
            Self::InstanceIdentityChanged(route) => write!(
                formatter,
                "backend route {} / {} changed identity after registration",
                route.backend_id(),
                route.configured_deployment_id().as_str()
            ),
            Self::ProtocolInstanceMismatch(route) => write!(
                formatter,
                "backend route {} / {} does not match the exact persisted instance identity",
                route.backend_id(),
                route.configured_deployment_id().as_str()
            ),
        }
    }
}

impl Error for BackendRegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRouteKey(error) => Some(error),
            Self::InvalidProtocolInstanceIdentity(error) => Some(error),
            Self::InvalidInstanceIdentity { source, .. } => Some(source),
            Self::BackendIdMismatch { .. }
            | Self::DuplicateRoute(_)
            | Self::PrimaryRouteNotRegistered(_)
            | Self::UnknownRoute(_)
            | Self::InstanceIdentityChanged(_)
            | Self::ProtocolInstanceMismatch(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use birdcode_backends::{
        BackendFuture, ModelCatalog, StructuredInferenceRequest, StructuredInferenceResponse,
    };
    use birdcode_protocol::BackendTransportIdentityV1;
    use url::Url;

    struct TestBackend {
        backend_id: BackendId,
        identity: BackendInstanceIdentity,
    }

    impl ModelBackend for TestBackend {
        fn backend_id(&self) -> &BackendId {
            &self.backend_id
        }

        fn instance_identity(&self) -> &BackendInstanceIdentity {
            &self.identity
        }

        fn discover_models(&self) -> BackendFuture<'_, ModelCatalog> {
            Box::pin(std::future::pending())
        }

        fn infer_structured(
            &self,
            _request: StructuredInferenceRequest,
        ) -> BackendFuture<'_, StructuredInferenceResponse> {
            Box::pin(std::future::pending())
        }
    }

    fn route_key(backend_id: &str, deployment_id: &str) -> BackendRouteKey {
        BackendRouteKey::new(
            BackendId::new(backend_id).expect("valid backend ID"),
            BackendDeploymentId::new(deployment_id).expect("valid deployment ID"),
        )
    }

    fn test_backend(
        backend_id: &str,
        deployment_id: &str,
        endpoint: &str,
    ) -> Arc<dyn ModelBackend> {
        let backend_id = BackendId::new(backend_id).expect("valid backend ID");
        let identity = BackendInstanceIdentity::for_http_origin(
            backend_id.clone(),
            BackendDeploymentId::new(deployment_id).expect("valid deployment ID"),
            &Url::parse(endpoint).expect("valid endpoint"),
        )
        .expect("valid identity");
        Arc::new(TestBackend {
            backend_id,
            identity,
        })
    }

    fn protocol_instance(
        backend_id: &str,
        deployment_id: &str,
        endpoint_origin: &str,
    ) -> BackendInstanceIdentityV1 {
        BackendInstanceIdentityV1::new(
            backend_id.to_owned(),
            BackendTransportIdentityV1::HttpOrigin {
                origin: endpoint_origin.to_owned(),
            },
            deployment_id.to_owned(),
        )
        .expect("valid protocol identity")
    }

    #[test]
    fn exact_route_returns_the_registered_arc() {
        let backend = test_backend("lmstudio", "local-a", "http://127.0.0.1:1234/v1");
        let registry =
            BackendRegistry::new([Arc::clone(&backend)], None).expect("registry is valid");

        let resolved = registry
            .resolve(&route_key("lmstudio", "local-a"))
            .expect("exact route resolves");

        assert!(Arc::ptr_eq(&backend, &resolved));
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
    }

    #[test]
    fn duplicate_exact_route_is_rejected_even_when_transport_differs() {
        let first = test_backend("lmstudio", "local-a", "http://127.0.0.1:1234/v1");
        let second = test_backend("lmstudio", "local-a", "http://127.0.0.1:5678/v1");

        let error = BackendRegistry::new([first, second], None)
            .err()
            .expect("ambiguous route is rejected");

        assert_eq!(
            error,
            BackendRegistryError::DuplicateRoute(route_key("lmstudio", "local-a"))
        );
    }

    #[test]
    fn lineage_resolution_uses_only_exact_typed_routing_fields() {
        let backend = test_backend("lmstudio", "local-a", "http://127.0.0.1:1234/v1");
        let registry =
            BackendRegistry::new([Arc::clone(&backend)], None).expect("registry is valid");
        let lineage = ModelLineage {
            backend_id: "lmstudio".to_owned(),
            model_id: "a-model-name-that-does-not-select-a-backend".to_owned(),
            deployment_id: "local-a".to_owned(),
            independence_domain_id: "operator-domain".to_owned(),
        };

        let resolved = registry
            .resolve_lineage(&lineage)
            .expect("exact lineage route resolves");
        assert!(Arc::ptr_eq(&backend, &resolved));

        let different_deployment = ModelLineage {
            deployment_id: "local-b".to_owned(),
            ..lineage
        };
        assert_eq!(
            registry
                .resolve_lineage(&different_deployment)
                .err()
                .expect("no approximate routing or fallback"),
            BackendRegistryError::UnknownRoute(route_key("lmstudio", "local-b"))
        );
    }

    #[test]
    fn persisted_instance_resolution_requires_the_full_transport_attestation() {
        let backend = test_backend("lmstudio", "local-a", "http://127.0.0.1:1234/v1");
        let registry =
            BackendRegistry::new([Arc::clone(&backend)], None).expect("registry is valid");
        let exact = protocol_instance("lmstudio", "local-a", "http://127.0.0.1:1234");
        let resolved = registry
            .resolve_instance(&exact)
            .expect("full instance identity resolves");
        assert!(Arc::ptr_eq(&backend, &resolved));

        let same_route_different_transport =
            protocol_instance("lmstudio", "local-a", "http://127.0.0.1:5678");
        assert_eq!(
            registry
                .resolve_instance(&same_route_different_transport)
                .err()
                .expect("transport substitution is rejected"),
            BackendRegistryError::ProtocolInstanceMismatch(route_key("lmstudio", "local-a"))
        );
    }

    #[test]
    fn primary_exists_only_when_explicitly_configured() {
        let backend = test_backend("lmstudio", "local-a", "http://127.0.0.1:1234/v1");
        let without_primary =
            BackendRegistry::new([Arc::clone(&backend)], None).expect("registry is valid");
        assert!(without_primary.primary_key().is_none());
        assert!(
            without_primary
                .resolve_primary()
                .expect("registry remains valid")
                .is_none()
        );

        let key = route_key("lmstudio", "local-a");
        let with_primary = BackendRegistry::new([Arc::clone(&backend)], Some(key.clone()))
            .expect("registered primary is valid");
        assert_eq!(with_primary.primary_key(), Some(&key));
        assert!(Arc::ptr_eq(
            &backend,
            &with_primary
                .resolve_primary()
                .expect("registry remains valid")
                .expect("primary exists")
        ));
        assert_eq!(
            with_primary
                .resolve(&route_key("other-provider", "local-a"))
                .err()
                .expect("ordinary resolution does not fall back to primary"),
            BackendRegistryError::UnknownRoute(route_key("other-provider", "local-a"))
        );

        let error = BackendRegistry::new([backend], Some(route_key("lmstudio", "not-registered")))
            .err()
            .expect("missing primary is rejected");
        assert_eq!(
            error,
            BackendRegistryError::PrimaryRouteNotRegistered(route_key(
                "lmstudio",
                "not-registered"
            ))
        );
    }

    #[test]
    fn backend_id_must_match_its_attested_instance_identity() {
        let identity = BackendInstanceIdentity::for_http_origin(
            BackendId::new("lmstudio").expect("valid backend ID"),
            BackendDeploymentId::new("local-a").expect("valid deployment ID"),
            &Url::parse("http://127.0.0.1:1234/v1").expect("valid endpoint"),
        )
        .expect("valid identity");
        let backend: Arc<dyn ModelBackend> = Arc::new(TestBackend {
            backend_id: BackendId::new("other-provider").expect("valid backend ID"),
            identity,
        });

        let error = BackendRegistry::new([backend], None)
            .err()
            .expect("inconsistent instance is rejected");

        assert_eq!(
            error,
            BackendRegistryError::BackendIdMismatch {
                route: route_key("lmstudio", "local-a"),
                reported_backend_id: BackendId::new("other-provider").expect("valid backend ID"),
            }
        );
    }

    #[test]
    fn malformed_lineage_route_is_rejected_before_lookup() {
        let registry = BackendRegistry::new(std::iter::empty(), None)
            .expect("empty registry without primary is valid");
        let lineage = ModelLineage {
            backend_id: String::new(),
            model_id: "unused".to_owned(),
            deployment_id: "local-a".to_owned(),
            independence_domain_id: "unused".to_owned(),
        };

        assert!(matches!(
            registry.resolve_lineage(&lineage),
            Err(BackendRegistryError::InvalidRouteKey(
                BackendRouteKeyError::InvalidBackendId(_)
            ))
        ));
    }
}
