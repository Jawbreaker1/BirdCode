//! Provider-neutral model inference contracts and concrete backend adapters.
//!
//! This crate deliberately has no dependency on the desktop, daemon, runtime,
//! storage, or tool-execution layers. Backend futures are owned and may be
//! cancelled by dropping them, which lets a future scheduler apply its own
//! cancellation and budget policy.

mod contract;
mod lmstudio;

pub use contract::{
    BackendError, BackendErrorEvidence, BackendErrorKind, BackendFuture, BackendId,
    BackendOperation, CapabilityState, ContractError, DiscoveryEvidence, HttpEvidence,
    InferenceEvidence, LoadedInstance, Message, MessageRole, ModelBackend, ModelCapabilities,
    ModelCatalog, ModelDescriptor, ModelId, ModelKind, ModelLoadState, NativeDiscoveryEvidence,
    NativeMatch, NativeMatchKey, Quantization, ReasoningCapabilities, ReasoningOption,
    ReasoningSetting, StructuredInferenceRequest, StructuredInferenceResponse,
    StructuredOutputSpec, TokenUsage,
};
pub use lmstudio::{HttpLimits, LmStudioBackend, LmStudioConfig, SecretToken};
