use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;
use url::Url;

const MAX_TARGET_ID_BYTES: usize = 512;

/// Opaque target/adapter identity supplied explicitly by the planner.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TargetId(String);

impl TargetId {
    /// Creates an exact target identity without interpreting its contents.
    ///
    /// # Errors
    ///
    /// Rejects empty and overlong identities.
    pub fn new(value: impl Into<String>) -> Result<Self, TargetError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TargetError::EmptyTargetId);
        }
        if value.len() > MAX_TARGET_ID_BYTES {
            return Err(TargetError::TargetIdTooLong {
                maximum: MAX_TARGET_ID_BYTES,
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TargetId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Structural target/catalog errors; no semantic inference is performed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TargetError {
    #[error("target_id must not be empty")]
    EmptyTargetId,
    #[error("target_id exceeds {maximum} UTF-8 bytes")]
    TargetIdTooLong { maximum: usize },
    #[error("adapter {requirement:?} was declared more than once")]
    DuplicateAdapter { requirement: AdapterRequirement },
    #[error("no adapter satisfying {requirement:?} is registered")]
    AdapterUnavailable { requirement: AdapterRequirement },
    #[error("surface {surface:?} cannot run on platform {platform:?}")]
    UnsupportedTargetCombination {
        surface: TargetSurfaceKind,
        platform: ExecutionPlatformKind,
    },
    #[error("{field} must not contain URL userinfo or a password")]
    CredentialedUrl { field: &'static str },
}

/// Stable target family visible to a blind evaluator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    WebPlaywright,
    ApiServer,
    Cli,
    Tui,
    MacOsDesktop,
    AppleSimulator,
    Android,
    Windows,
    Linux,
}

/// Exact adapter capability required by a typed target.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    PlaywrightWeb,
    ApiServer,
    Cli,
    Tui,
    MacOsDesktop,
    AppleSimulator,
    Android,
    Windows,
    Linux,
}

/// Apple simulator family selected explicitly by the planner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppleSimulatorPlatform {
    Ios,
    IpadOs,
    TvOs,
    WatchOs,
    VisionOs,
}

/// Orthogonal execution platform supplied explicitly by the planner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ExecutionPlatform {
    MacOs {
        host_id: TargetId,
    },
    Windows {
        host_id: TargetId,
    },
    Linux {
        host_id: TargetId,
    },
    AppleSimulator {
        platform: AppleSimulatorPlatform,
        device_id: TargetId,
    },
    Android {
        device_id: TargetId,
    },
    Other {
        platform_id: TargetId,
        host_id: TargetId,
    },
}

/// Stable structural platform category used only for compatibility checks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPlatformKind {
    MacOs,
    Windows,
    Linux,
    AppleSimulator,
    Android,
    Other,
}

/// Adapter lookup key preserving both surface capability and host platform.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRequirement {
    pub kind: AdapterKind,
    pub platform: ExecutionPlatformKind,
}

impl ExecutionPlatform {
    #[must_use]
    pub const fn kind(&self) -> ExecutionPlatformKind {
        match self {
            Self::MacOs { .. } => ExecutionPlatformKind::MacOs,
            Self::Windows { .. } => ExecutionPlatformKind::Windows,
            Self::Linux { .. } => ExecutionPlatformKind::Linux,
            Self::AppleSimulator { .. } => ExecutionPlatformKind::AppleSimulator,
            Self::Android { .. } => ExecutionPlatformKind::Android,
            Self::Other { .. } => ExecutionPlatformKind::Other,
        }
    }
}

/// Application surface independent of the platform that hosts it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "surface", rename_all = "snake_case")]
pub enum TargetSurface {
    WebPlaywright {
        url: Url,
    },
    ApiServer {
        endpoint: Url,
    },
    Cli,
    Tui,
    DesktopApplication {
        application_id: TargetId,
        bundle_id: Option<TargetId>,
    },
    MobileApplication {
        application_id: TargetId,
    },
}

/// Stable structural surface category used only for compatibility checks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetSurfaceKind {
    WebPlaywright,
    ApiServer,
    Cli,
    Tui,
    DesktopApplication,
    MobileApplication,
}

impl TargetSurface {
    #[must_use]
    pub const fn kind(&self) -> TargetSurfaceKind {
        match self {
            Self::WebPlaywright { .. } => TargetSurfaceKind::WebPlaywright,
            Self::ApiServer { .. } => TargetSurfaceKind::ApiServer,
            Self::Cli => TargetSurfaceKind::Cli,
            Self::Tui => TargetSurfaceKind::Tui,
            Self::DesktopApplication { .. } => TargetSurfaceKind::DesktopApplication,
            Self::MobileApplication { .. } => TargetSurfaceKind::MobileApplication,
        }
    }
}

/// Concrete target composed from independent platform and surface dimensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecutionTarget {
    target_id: TargetId,
    platform: ExecutionPlatform,
    surface: TargetSurface,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionTargetWire {
    target_id: TargetId,
    platform: ExecutionPlatform,
    surface: TargetSurface,
}

impl<'de> Deserialize<'de> for ExecutionTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ExecutionTargetWire::deserialize(deserializer)?;
        Self::new(wire.target_id, wire.platform, wire.surface).map_err(serde::de::Error::custom)
    }
}

impl ExecutionTarget {
    /// Constructs a target and rejects credentials embedded in web/API URLs.
    ///
    /// Query data is preserved verbatim. Integrations must put query-based
    /// secrets behind an explicit secret reference or broker before retention.
    ///
    /// # Errors
    ///
    /// Rejects URL userinfo/password and incompatible surface/platform pairs.
    pub fn new(
        target_id: TargetId,
        platform: ExecutionPlatform,
        surface: TargetSurface,
    ) -> Result<Self, TargetError> {
        let target = Self {
            target_id,
            platform,
            surface,
        };
        target.reject_credentialed_url()?;
        target.kind()?;
        Ok(target)
    }

    fn reject_credentialed_url(&self) -> Result<(), TargetError> {
        let (field, url) = match &self.surface {
            TargetSurface::WebPlaywright { url } => ("url", url),
            TargetSurface::ApiServer { endpoint } => ("endpoint", endpoint),
            TargetSurface::Cli
            | TargetSurface::Tui
            | TargetSurface::DesktopApplication { .. }
            | TargetSurface::MobileApplication { .. } => return Ok(()),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(TargetError::CredentialedUrl { field });
        }
        Ok(())
    }

    /// Returns the declared family from enum variants alone.
    ///
    /// # Errors
    ///
    /// Rejects structurally incompatible surface/platform pairs.
    pub const fn kind(&self) -> Result<TargetKind, TargetError> {
        let kind = match (&self.surface, &self.platform) {
            (TargetSurface::WebPlaywright { .. }, _) => TargetKind::WebPlaywright,
            (TargetSurface::ApiServer { .. }, _) => TargetKind::ApiServer,
            (TargetSurface::Cli, _) => TargetKind::Cli,
            (TargetSurface::Tui, _) => TargetKind::Tui,
            (TargetSurface::DesktopApplication { .. }, ExecutionPlatform::MacOs { .. }) => {
                TargetKind::MacOsDesktop
            }
            (TargetSurface::DesktopApplication { .. }, ExecutionPlatform::Windows { .. }) => {
                TargetKind::Windows
            }
            (TargetSurface::DesktopApplication { .. }, ExecutionPlatform::Linux { .. }) => {
                TargetKind::Linux
            }
            (TargetSurface::MobileApplication { .. }, ExecutionPlatform::AppleSimulator { .. }) => {
                TargetKind::AppleSimulator
            }
            (TargetSurface::MobileApplication { .. }, ExecutionPlatform::Android { .. }) => {
                TargetKind::Android
            }
            _ => {
                return Err(TargetError::UnsupportedTargetCombination {
                    surface: self.surface.kind(),
                    platform: self.platform.kind(),
                });
            }
        };
        Ok(kind)
    }

    /// Mechanically maps the enum variant to its required adapter capability.
    ///
    /// # Errors
    ///
    /// Rejects structurally incompatible surface/platform pairs.
    pub fn required_adapter(&self) -> Result<AdapterRequirement, TargetError> {
        let kind = match self.kind()? {
            TargetKind::WebPlaywright => AdapterKind::PlaywrightWeb,
            TargetKind::ApiServer => AdapterKind::ApiServer,
            TargetKind::Cli => AdapterKind::Cli,
            TargetKind::Tui => AdapterKind::Tui,
            TargetKind::MacOsDesktop => AdapterKind::MacOsDesktop,
            TargetKind::AppleSimulator => AdapterKind::AppleSimulator,
            TargetKind::Android => AdapterKind::Android,
            TargetKind::Windows => AdapterKind::Windows,
            TargetKind::Linux => AdapterKind::Linux,
        };
        Ok(AdapterRequirement {
            kind,
            platform: self.platform.kind(),
        })
    }

    #[must_use]
    pub const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    #[must_use]
    pub const fn platform(&self) -> &ExecutionPlatform {
        &self.platform
    }

    #[must_use]
    pub const fn surface(&self) -> &TargetSurface {
        &self.surface
    }
}

/// Declaration supplied by an integration that actually implements an adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterDeclaration {
    pub requirement: AdapterRequirement,
    pub implementation_id: TargetId,
    pub version: TargetId,
    pub implementation_sha256: crate::Sha256Digest,
}

/// Explicit adapter inventory. Its default value contains no adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdapterCatalog(BTreeMap<AdapterRequirement, AdapterDeclaration>);

impl Serialize for AdapterCatalog {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.values().collect::<Vec<_>>().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AdapterCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let declarations = Vec::<AdapterDeclaration>::deserialize(deserializer)?;
        Self::new(declarations).map_err(serde::de::Error::custom)
    }
}

impl AdapterCatalog {
    /// Builds an inventory and rejects duplicate capability claims.
    ///
    /// # Errors
    ///
    /// Returns the duplicated adapter kind without dropping other declarations.
    pub fn new(
        declarations: impl IntoIterator<Item = AdapterDeclaration>,
    ) -> Result<Self, TargetError> {
        let mut entries = BTreeMap::new();
        for declaration in declarations {
            let requirement = declaration.requirement;
            if entries.insert(requirement, declaration).is_some() {
                return Err(TargetError::DuplicateAdapter { requirement });
            }
        }
        Ok(Self(entries))
    }

    /// Resolves only the capability dictated by the typed target variant.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::AdapterUnavailable`] when no real integration
    /// registered the required adapter.
    pub fn resolve(&self, target: &ExecutionTarget) -> Result<&AdapterDeclaration, TargetError> {
        let requirement = target.required_adapter()?;
        self.0
            .get(&requirement)
            .ok_or(TargetError::AdapterUnavailable { requirement })
    }

    pub fn declarations(&self) -> impl Iterator<Item = &AdapterDeclaration> {
        self.0.values()
    }
}
