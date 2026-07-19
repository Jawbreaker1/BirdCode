//! Typed foundation for `BirdCode`'s generic Execution & Validation Plane.
//!
//! This crate defines contracts only. It does not execute processes or claim
//! that any platform adapter is available. Semantic target selection belongs
//! to an LLM-driven planning layer; once selected, this layer accepts only an
//! explicit [`ExecutionTarget`] and maps it mechanically to an [`AdapterKind`].

mod blind;
mod command;
mod evidence;
mod identity;
mod provenance;
mod target;
mod validation;

pub use blind::{
    BlindArtifact, BlindArtifactHandle, BlindArtifactMapping, BlindAttemptId, BlindAttemptOutcome,
    BlindBuildError, BlindCandidateId, BlindCandidateMapping, BlindCheck, BlindCheckEvidence,
    BlindCheckId, BlindCheckMapping, BlindCheckRequirement, BlindDisclosure, BlindEvaluationInput,
    BlindEvaluationPackage, BlindIdError, BlindIdMapping, BlindProcessExit, BlindRunId,
    BlindRunMapping, BlindValidationPolicy,
};
pub use command::{
    CaptureLimits, CommandSpec, EnvironmentEntry, EnvironmentSnapshot, EnvironmentValue,
    ExecutionBounds, NativeArgument, NativeEncoding, OperatingSystem, ProcessExit,
    RetainedArgument, RetainedStdin, ToolchainEntry,
};
pub use evidence::{
    ArtifactId, ArtifactKind, ArtifactRecord, CheckEvidence, CheckId, CheckKind, CheckOutcome,
    DigestError, EvidenceClass, EvidenceIdError, Sha256Digest, ValidationCheck,
};
pub use identity::{
    ActorIdentity, AgentId, AgentIdentity, CandidateId, EvaluationCaseId, IdentityError, ModelId,
    ModelIdentity, ProviderId,
};
pub use provenance::{
    AppendError, AttemptId, EXECUTION_PHASES, ExecutionPhase, PROVENANCE_SCHEMA_VERSION,
    PhaseOutcome, ProvenanceEvent, ProvenanceIdError, ProvenanceRecord, RunContextManifest, RunId,
    RunProvenance, SealError, SealedRunProvenance,
};
pub use target::{
    AdapterCatalog, AdapterDeclaration, AdapterKind, AdapterRequirement, AppleSimulatorPlatform,
    ExecutionPlatform, ExecutionPlatformKind, ExecutionTarget, TargetError, TargetId, TargetKind,
    TargetSurface, TargetSurfaceKind,
};
pub use validation::{
    AcceptanceDecision, CheckRequirement, CommandComponent, EnvironmentMetadataField,
    ExitRequirement, PhaseRequirement, RunVerdict, ValidationPolicy, ValidationReport,
    ValidationViolation,
};
