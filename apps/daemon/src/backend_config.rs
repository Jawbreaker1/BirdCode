//! Strict, versioned configuration for the daemon's backend registry.
//!
//! The manifest contains routing data and references to credential environment
//! variables. Secret values are never accepted from JSON, retained in the
//! validated manifest, or included in diagnostics.

use crate::backend_registry::{BackendRegistry, BackendRegistryError, BackendRouteKey};
use birdcode_backends::{
    BackendDeploymentId, BackendEndpointOrigin, BackendError, BackendId,
    BackendInstanceIdentityError, ContractError, LmStudioBackend, LmStudioConfig, ModelBackend,
    SecretToken,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use url::{ParseError as UrlParseError, Url};

pub const BACKEND_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MAX_BACKEND_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_BACKEND_MANIFEST_BACKENDS: usize = 64;

const LMSTUDIO_BACKEND_ID: &str = "lmstudio";

#[derive(Debug, Deserialize)]
struct BackendManifestVersionProbe {
    schema_version: u32,
    #[serde(flatten)]
    _remaining: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendManifestDocument {
    schema_version: u32,
    default_route: BackendRouteDocument,
    backends: Vec<BackendDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendRouteDocument {
    backend_id: String,
    deployment_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BackendAdapterDocument {
    Lmstudio,
}

impl BackendAdapterDocument {
    const fn backend_id(self) -> &'static str {
        match self {
            Self::Lmstudio => LMSTUDIO_BACKEND_ID,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendDocument {
    adapter: BackendAdapterDocument,
    deployment_id: String,
    base_url: String,
    #[serde(default)]
    bearer_token_env: Option<String>,
}

#[derive(Clone, Debug)]
struct ValidatedLmStudioBackend {
    route: BackendRouteKey,
    base_url: Url,
    bearer_token_env: Option<String>,
}

/// Validated, secret-free configuration for an exact backend registry.
#[derive(Clone, Debug)]
pub struct BackendManifest {
    default_route: BackendRouteKey,
    backends: Vec<ValidatedLmStudioBackend>,
}

impl BackendManifest {
    /// Reads and validates a manifest without ever reading more than the
    /// configured byte limit plus one sentinel byte.
    ///
    /// # Errors
    ///
    /// Returns a typed error for file I/O, an oversized or malformed manifest,
    /// unsupported configuration, or ambiguous routing.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BackendManifestError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| BackendManifestError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut bytes = Vec::with_capacity(MAX_BACKEND_MANIFEST_BYTES.min(8 * 1024));
        file.take((MAX_BACKEND_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| BackendManifestError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        Self::from_json_slice(&bytes)
    }

    /// Decodes and validates one strict version-1 JSON manifest.
    ///
    /// # Errors
    ///
    /// Rejects oversized input, malformed JSON, duplicate or unknown fields,
    /// unsupported adapters, unsafe endpoints, duplicate routes or origins,
    /// and an unregistered default route.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, BackendManifestError> {
        if bytes.len() > MAX_BACKEND_MANIFEST_BYTES {
            return Err(BackendManifestError::ManifestTooLarge {
                maximum: MAX_BACKEND_MANIFEST_BYTES,
            });
        }
        let version: BackendManifestVersionProbe =
            serde_json::from_slice(bytes).map_err(BackendManifestError::InvalidJson)?;
        if version.schema_version != BACKEND_MANIFEST_SCHEMA_VERSION {
            return Err(BackendManifestError::UnsupportedSchemaVersion {
                actual: version.schema_version,
            });
        }
        let document: BackendManifestDocument =
            serde_json::from_slice(bytes).map_err(BackendManifestError::InvalidJson)?;
        Self::validate(document)
    }

    fn validate(document: BackendManifestDocument) -> Result<Self, BackendManifestError> {
        if document.schema_version != BACKEND_MANIFEST_SCHEMA_VERSION {
            return Err(BackendManifestError::UnsupportedSchemaVersion {
                actual: document.schema_version,
            });
        }
        if document.backends.is_empty() {
            return Err(BackendManifestError::NoBackends);
        }
        if document.backends.len() > MAX_BACKEND_MANIFEST_BACKENDS {
            return Err(BackendManifestError::TooManyBackends {
                actual: document.backends.len(),
                maximum: MAX_BACKEND_MANIFEST_BACKENDS,
            });
        }

        let default_route = route_from_document(document.default_route, "default_route")?;
        let mut routes = BTreeSet::new();
        let mut origins = BTreeMap::<BackendEndpointOrigin, BackendRouteKey>::new();
        let mut backends = Vec::with_capacity(document.backends.len());

        for backend in document.backends {
            let backend_id = BackendId::new(backend.adapter.backend_id()).map_err(|source| {
                BackendManifestError::InvalidBackendId {
                    field: "backends[].adapter",
                    source,
                }
            })?;
            let deployment_id =
                BackendDeploymentId::new(backend.deployment_id).map_err(|source| {
                    BackendManifestError::InvalidDeploymentId {
                        field: "backends[].deployment_id",
                        source,
                    }
                })?;
            let route = BackendRouteKey::new(backend_id, deployment_id);
            if !routes.insert(route.clone()) {
                return Err(BackendManifestError::DuplicateRoute(route));
            }

            if let Some(variable) = backend.bearer_token_env.as_deref() {
                validate_environment_reference(&route, variable)?;
            }

            let base_url = Url::parse(&backend.base_url).map_err(|source| {
                BackendManifestError::InvalidBaseUrl {
                    route: route.clone(),
                    source,
                }
            })?;
            let probe = build_lmstudio_backend(&route, base_url.clone(), None)?;
            let origin = probe.instance_identity().endpoint_origin().clone();
            if let Some(first_route) = origins.insert(origin.clone(), route.clone()) {
                return Err(BackendManifestError::DuplicateLmStudioOrigin {
                    origin,
                    first_route,
                    duplicate_route: route,
                });
            }

            backends.push(ValidatedLmStudioBackend {
                route,
                base_url,
                bearer_token_env: backend.bearer_token_env,
            });
        }

        if !routes.contains(&default_route) {
            return Err(BackendManifestError::DefaultRouteNotRegistered(
                default_route,
            ));
        }

        Ok(Self {
            default_route,
            backends,
        })
    }

    #[must_use]
    pub const fn default_route(&self) -> &BackendRouteKey {
        &self.default_route
    }

    #[must_use]
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Resolves credential environment references at the last responsible
    /// moment and constructs the exact immutable registry.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a missing, empty, or non-Unicode credential,
    /// adapter construction failure, or registry integrity failure.
    pub fn build_registry(&self) -> Result<BackendRegistry, BackendManifestError> {
        self.build_registry_with_environment(|variable| std::env::var_os(variable))
    }

    fn build_registry_with_environment(
        &self,
        mut lookup: impl FnMut(&str) -> Option<OsString>,
    ) -> Result<BackendRegistry, BackendManifestError> {
        let mut backends = Vec::<Arc<dyn ModelBackend>>::with_capacity(self.backends.len());
        for backend in &self.backends {
            let token = backend
                .bearer_token_env
                .as_deref()
                .map(|variable| resolve_credential(&backend.route, variable, &mut lookup))
                .transpose()?;
            let concrete = build_lmstudio_backend(&backend.route, backend.base_url.clone(), token)?;
            backends.push(Arc::new(concrete));
        }
        BackendRegistry::new(backends, Some(self.default_route.clone()))
            .map_err(BackendManifestError::Registry)
    }
}

fn route_from_document(
    document: BackendRouteDocument,
    field: &'static str,
) -> Result<BackendRouteKey, BackendManifestError> {
    let backend_id = BackendId::new(document.backend_id)
        .map_err(|source| BackendManifestError::InvalidBackendId { field, source })?;
    let deployment_id = BackendDeploymentId::new(document.deployment_id)
        .map_err(|source| BackendManifestError::InvalidDeploymentId { field, source })?;
    Ok(BackendRouteKey::new(backend_id, deployment_id))
}

fn validate_environment_reference(
    route: &BackendRouteKey,
    variable: &str,
) -> Result<(), BackendManifestError> {
    if variable.is_empty() {
        return Err(BackendManifestError::EmptyCredentialEnvironmentReference {
            route: route.clone(),
        });
    }
    if variable.contains(['=', '\0']) {
        return Err(
            BackendManifestError::InvalidCredentialEnvironmentReference {
                route: route.clone(),
            },
        );
    }
    Ok(())
}

fn resolve_credential(
    route: &BackendRouteKey,
    variable: &str,
    lookup: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<SecretToken, BackendManifestError> {
    let value = lookup(variable).ok_or_else(|| BackendManifestError::MissingCredential {
        route: route.clone(),
        variable: variable.to_owned(),
    })?;
    let value = value
        .into_string()
        .map_err(|_| BackendManifestError::NonUnicodeCredential {
            route: route.clone(),
            variable: variable.to_owned(),
        })?;
    if value.is_empty() {
        return Err(BackendManifestError::EmptyCredential {
            route: route.clone(),
            variable: variable.to_owned(),
        });
    }
    Ok(SecretToken::new(value))
}

fn build_lmstudio_backend(
    route: &BackendRouteKey,
    base_url: Url,
    token: Option<SecretToken>,
) -> Result<LmStudioBackend, BackendManifestError> {
    let mut config = LmStudioConfig::new(base_url);
    config.deployment_id = Some(route.configured_deployment_id().clone());
    config.api_token = token;
    LmStudioBackend::new(config).map_err(|source| BackendManifestError::AdapterConfiguration {
        route: route.clone(),
        source,
    })
}

#[derive(Debug)]
pub enum BackendManifestError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    ManifestTooLarge {
        maximum: usize,
    },
    InvalidJson(serde_json::Error),
    UnsupportedSchemaVersion {
        actual: u32,
    },
    NoBackends,
    TooManyBackends {
        actual: usize,
        maximum: usize,
    },
    InvalidBackendId {
        field: &'static str,
        source: ContractError,
    },
    InvalidDeploymentId {
        field: &'static str,
        source: BackendInstanceIdentityError,
    },
    DuplicateRoute(BackendRouteKey),
    InvalidBaseUrl {
        route: BackendRouteKey,
        source: UrlParseError,
    },
    AdapterConfiguration {
        route: BackendRouteKey,
        source: BackendError,
    },
    DuplicateLmStudioOrigin {
        origin: BackendEndpointOrigin,
        first_route: BackendRouteKey,
        duplicate_route: BackendRouteKey,
    },
    DefaultRouteNotRegistered(BackendRouteKey),
    EmptyCredentialEnvironmentReference {
        route: BackendRouteKey,
    },
    InvalidCredentialEnvironmentReference {
        route: BackendRouteKey,
    },
    MissingCredential {
        route: BackendRouteKey,
        variable: String,
    },
    EmptyCredential {
        route: BackendRouteKey,
        variable: String,
    },
    NonUnicodeCredential {
        route: BackendRouteKey,
        variable: String,
    },
    Registry(BackendRegistryError),
}

impl fmt::Display for BackendManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::ManifestTooLarge { maximum } => {
                write!(formatter, "backend manifest exceeds {maximum} bytes")
            }
            Self::InvalidJson(error) => write!(formatter, "invalid backend manifest JSON: {error}"),
            Self::UnsupportedSchemaVersion { actual } => write!(
                formatter,
                "unsupported backend manifest schema version {actual}; expected {BACKEND_MANIFEST_SCHEMA_VERSION}"
            ),
            Self::NoBackends => formatter.write_str("backend manifest must contain a backend"),
            Self::TooManyBackends { actual, maximum } => write!(
                formatter,
                "backend manifest contains {actual} backends; maximum is {maximum}"
            ),
            Self::InvalidBackendId { field, source } => {
                write!(formatter, "invalid {field} backend ID: {source}")
            }
            Self::InvalidDeploymentId { field, source } => {
                write!(formatter, "invalid {field} deployment ID: {source}")
            }
            Self::DuplicateRoute(route) => write_route(formatter, "duplicate backend route", route),
            Self::InvalidBaseUrl { route, source } => {
                write_route(formatter, "invalid base URL for backend route", route)?;
                write!(formatter, ": {source}")
            }
            Self::AdapterConfiguration { route, source } => {
                write_route(formatter, "invalid configuration for backend route", route)?;
                write!(formatter, ": {source}")
            }
            Self::DuplicateLmStudioOrigin {
                origin,
                first_route,
                duplicate_route,
            } => {
                write!(
                    formatter,
                    "LM Studio origin {} is configured by ",
                    origin.as_str()
                )?;
                write_route(formatter, "route", first_route)?;
                formatter.write_str(" and ")?;
                write_route(formatter, "route", duplicate_route)
            }
            Self::DefaultRouteNotRegistered(route) => {
                write_route(formatter, "default backend route is not registered", route)
            }
            Self::EmptyCredentialEnvironmentReference { route } => write_route(
                formatter,
                "credential environment reference is empty for backend route",
                route,
            ),
            Self::InvalidCredentialEnvironmentReference { route } => write_route(
                formatter,
                "credential environment reference is invalid for backend route",
                route,
            ),
            Self::MissingCredential { route, variable } => {
                write!(
                    formatter,
                    "credential environment variable {variable} is missing for "
                )?;
                write_route(formatter, "backend route", route)
            }
            Self::EmptyCredential { route, variable } => {
                write!(
                    formatter,
                    "credential environment variable {variable} is empty for "
                )?;
                write_route(formatter, "backend route", route)
            }
            Self::NonUnicodeCredential { route, variable } => write!(
                formatter,
                "credential environment variable {variable} is not valid Unicode for backend route {} / {}",
                route.backend_id(),
                route.configured_deployment_id().as_str()
            ),
            Self::Registry(error) => write!(formatter, "invalid backend registry: {error}"),
        }
    }
}

fn write_route(
    formatter: &mut fmt::Formatter<'_>,
    prefix: &str,
    route: &BackendRouteKey,
) -> fmt::Result {
    write!(
        formatter,
        "{prefix} {} / {}",
        route.backend_id(),
        route.configured_deployment_id().as_str()
    )
}

impl Error for BackendManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::InvalidJson(source) => Some(source),
            Self::InvalidBackendId { source, .. } => Some(source),
            Self::InvalidDeploymentId { source, .. } => Some(source),
            Self::InvalidBaseUrl { source, .. } => Some(source),
            Self::AdapterConfiguration { source, .. } => Some(source),
            Self::Registry(source) => Some(source),
            Self::ManifestTooLarge { .. }
            | Self::UnsupportedSchemaVersion { .. }
            | Self::NoBackends
            | Self::TooManyBackends { .. }
            | Self::DuplicateRoute(_)
            | Self::DuplicateLmStudioOrigin { .. }
            | Self::DefaultRouteNotRegistered(_)
            | Self::EmptyCredentialEnvironmentReference { .. }
            | Self::InvalidCredentialEnvironmentReference { .. }
            | Self::MissingCredential { .. }
            | Self::EmptyCredential { .. }
            | Self::NonUnicodeCredential { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::io::Write as _;

    fn manifest(backends: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "default_route": {
                "backend_id": "lmstudio",
                "deployment_id": "local-primary"
            },
            "backends": backends
        }))
        .expect("test manifest serializes")
    }

    fn primary_backend() -> Value {
        json!({
            "adapter": "lmstudio",
            "deployment_id": "local-primary",
            "base_url": "http://127.0.0.1:1234"
        })
    }

    #[test]
    fn checked_in_example_manifest_remains_strictly_valid() {
        let manifest = BackendManifest::from_json_slice(include_bytes!(
            "../../../examples/backend-manifest.json"
        ))
        .expect("checked-in backend manifest is valid");

        assert_eq!(manifest.backend_count(), 2);
        assert_eq!(
            manifest.default_route().configured_deployment_id().as_str(),
            "REPLACE_WITH_TRUSTED_PRODUCER_DEPLOYMENT_ID"
        );
    }

    #[test]
    fn valid_manifest_builds_exact_registry_and_primary_route() {
        let parsed = BackendManifest::from_json_slice(&manifest(json!([primary_backend()])))
            .expect("manifest is valid");
        let registry = parsed
            .build_registry_with_environment(|_| None)
            .expect("registry builds without credentials");

        assert_eq!(parsed.backend_count(), 1);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.primary_key(), Some(parsed.default_route()));
        assert!(
            registry
                .resolve_primary()
                .expect("primary route resolves")
                .is_some()
        );
    }

    #[test]
    fn schema_is_versioned_and_rejects_unknown_or_inline_secret_fields() {
        let unsupported = manifest(json!([primary_backend()]));
        let mut unsupported: Value =
            serde_json::from_slice(&unsupported).expect("fixture is valid JSON");
        unsupported["schema_version"] = json!(2);
        assert!(matches!(
            BackendManifest::from_json_slice(
                &serde_json::to_vec(&unsupported).expect("fixture serializes")
            ),
            Err(BackendManifestError::UnsupportedSchemaVersion { actual: 2 })
        ));

        let future_shape = br#"{"schema_version":2,"future_field":true}"#;
        assert!(matches!(
            BackendManifest::from_json_slice(future_shape),
            Err(BackendManifestError::UnsupportedSchemaVersion { actual: 2 })
        ));

        let inline_secret = manifest(json!([{
            "adapter": "lmstudio",
            "deployment_id": "local-primary",
            "base_url": "http://127.0.0.1:1234",
            "bearer_token": "must-never-be-accepted"
        }]));
        let error = BackendManifest::from_json_slice(&inline_secret)
            .expect_err("inline credentials are unknown fields");
        assert!(matches!(&error, BackendManifestError::InvalidJson(_)));
        assert!(!error.to_string().contains("must-never-be-accepted"));
    }

    #[test]
    fn input_bytes_and_backend_count_are_bounded() {
        let oversized = vec![b' '; MAX_BACKEND_MANIFEST_BYTES + 1];
        assert!(matches!(
            BackendManifest::from_json_slice(&oversized),
            Err(BackendManifestError::ManifestTooLarge { .. })
        ));

        let backends = (0..=MAX_BACKEND_MANIFEST_BACKENDS)
            .map(|index| {
                json!({
                    "adapter": "lmstudio",
                    "deployment_id": format!("deployment-{index}"),
                    "base_url": format!("https://model-{index}.example.test")
                })
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            BackendManifest::from_json_slice(&manifest(json!(backends))),
            Err(BackendManifestError::TooManyBackends { .. })
        ));
    }

    #[test]
    fn file_loader_enforces_the_same_byte_bound() {
        let mut file = tempfile::NamedTempFile::new().expect("temporary file is created");
        file.write_all(&vec![b' '; MAX_BACKEND_MANIFEST_BYTES + 1])
            .expect("oversized fixture is written");

        assert!(matches!(
            BackendManifest::load(file.path()),
            Err(BackendManifestError::ManifestTooLarge { .. })
        ));
    }

    #[test]
    fn duplicate_exact_routes_are_rejected_before_transport_aliases() {
        let error = BackendManifest::from_json_slice(&manifest(json!([
            primary_backend(),
            {
                "adapter": "lmstudio",
                "deployment_id": "local-primary",
                "base_url": "http://localhost:4321"
            }
        ])))
        .expect_err("duplicate route must fail");
        assert!(matches!(error, BackendManifestError::DuplicateRoute(_)));
    }

    #[test]
    fn duplicate_canonical_lmstudio_origins_are_rejected() {
        let error = BackendManifest::from_json_slice(&manifest(json!([
            primary_backend(),
            {
                "adapter": "lmstudio",
                "deployment_id": "local-secondary",
                "base_url": "http://127.0.0.1:1234/"
            }
        ])))
        .expect_err("one transport origin cannot masquerade as two deployments");
        assert!(matches!(
            error,
            BackendManifestError::DuplicateLmStudioOrigin { .. }
        ));
    }

    #[test]
    fn transport_security_matches_lmstudio_adapter_policy() {
        let remote_http = BackendManifest::from_json_slice(&manifest(json!([{
            "adapter": "lmstudio",
            "deployment_id": "local-primary",
            "base_url": "http://192.0.2.10:1234"
        }])))
        .expect_err("remote plain HTTP must fail");
        assert!(matches!(
            remote_http,
            BackendManifestError::AdapterConfiguration { .. }
        ));

        BackendManifest::from_json_slice(&manifest(json!([{
            "adapter": "lmstudio",
            "deployment_id": "local-primary",
            "base_url": "https://models.example.test"
        }])))
        .expect("remote HTTPS is allowed");
    }

    #[test]
    fn default_route_must_be_an_exact_registered_route() {
        let bytes = serde_json::to_vec(&json!({
            "schema_version": 1,
            "default_route": {
                "backend_id": "lmstudio",
                "deployment_id": "not-registered"
            },
            "backends": [primary_backend()]
        }))
        .expect("fixture serializes");
        assert!(matches!(
            BackendManifest::from_json_slice(&bytes),
            Err(BackendManifestError::DefaultRouteNotRegistered(_))
        ));
    }

    fn credential_manifest() -> BackendManifest {
        BackendManifest::from_json_slice(&manifest(json!([{
            "adapter": "lmstudio",
            "deployment_id": "local-primary",
            "base_url": "http://127.0.0.1:1234",
            "bearer_token_env": "BIRDCODE_TEST_TOKEN"
        }])))
        .expect("credential fixture is valid")
    }

    #[test]
    fn missing_and_empty_credentials_have_distinct_typed_errors() {
        let parsed = credential_manifest();
        assert!(matches!(
            parsed.build_registry_with_environment(|_| None),
            Err(BackendManifestError::MissingCredential { .. })
        ));
        assert!(matches!(
            parsed.build_registry_with_environment(|_| Some(OsString::from(""))),
            Err(BackendManifestError::EmptyCredential { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_credentials_have_a_typed_error() {
        use std::os::unix::ffi::OsStringExt as _;

        let parsed = credential_manifest();
        let error = match parsed
            .build_registry_with_environment(|_| Some(OsString::from_vec(vec![0xff])))
        {
            Err(error) => error,
            Ok(_) => panic!("non-Unicode credentials must fail closed"),
        };
        assert!(matches!(
            error,
            BackendManifestError::NonUnicodeCredential { .. }
        ));
    }

    #[test]
    fn credential_reference_must_be_a_safe_environment_key() {
        for variable in ["", "NAME=VALUE", "NAME\0VALUE"] {
            let error = BackendManifest::from_json_slice(&manifest(json!([{
                "adapter": "lmstudio",
                "deployment_id": "local-primary",
                "base_url": "http://127.0.0.1:1234",
                "bearer_token_env": variable
            }])))
            .expect_err("unsafe environment reference must fail");
            assert!(matches!(
                error,
                BackendManifestError::EmptyCredentialEnvironmentReference { .. }
                    | BackendManifestError::InvalidCredentialEnvironmentReference { .. }
            ));
        }
    }
}
