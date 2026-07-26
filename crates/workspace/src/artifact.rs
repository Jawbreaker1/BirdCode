use birdcode_protocol::{ArtifactRef, Sha256Digest};
use std::fmt;

/// Exact bytes retained at a workspace lifecycle boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedArtifact {
    pub artifact: ArtifactRef,
    pub digest: Sha256Digest,
    pub bytes: Vec<u8>,
}

impl RetainedArtifact {
    fn from_exact_bytes(media_type: &str, bytes: Vec<u8>) -> Self {
        let digest = Sha256Digest::of_bytes(&bytes);
        let artifact = ArtifactRef {
            sha256: digest.as_str().to_owned(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            media_type: media_type.to_owned(),
        };
        Self {
            artifact,
            digest,
            bytes,
        }
    }

    pub(crate) fn verify(&self, media_type: &str) -> Result<(), ArtifactBoundaryError> {
        let expected = Self::from_exact_bytes(media_type, self.bytes.clone());
        if self.artifact != expected.artifact || self.digest != expected.digest {
            return Err(ArtifactBoundaryError::InvalidRetainedArtifact);
        }
        Ok(())
    }
}

/// Injectable content-addressing boundary.
///
/// The production implementation is pure and returns bytes to the caller. A
/// daemon may persist them after return, but this crate never writes Store.
pub trait ArtifactBoundary: Send + Sync {
    /// Retains exact bytes with the supplied closed media type.
    ///
    /// # Errors
    ///
    /// Returns a typed boundary failure if the artifact cannot be retained.
    fn retain(
        &self,
        media_type: &'static str,
        bytes: Vec<u8>,
    ) -> Result<RetainedArtifact, ArtifactBoundaryError>;
}

/// Deterministic SHA-256 content-addressing boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalArtifactBoundary;

impl ArtifactBoundary for CanonicalArtifactBoundary {
    fn retain(
        &self,
        media_type: &'static str,
        bytes: Vec<u8>,
    ) -> Result<RetainedArtifact, ArtifactBoundaryError> {
        Ok(RetainedArtifact::from_exact_bytes(media_type, bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactBoundaryError {
    Rejected,
    InvalidRetainedArtifact,
}

impl fmt::Display for ArtifactBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => formatter.write_str("artifact boundary rejected exact bytes"),
            Self::InvalidRetainedArtifact => {
                formatter.write_str("artifact boundary returned a mismatched content address")
            }
        }
    }
}

impl std::error::Error for ArtifactBoundaryError {}
