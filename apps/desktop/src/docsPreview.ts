import type { PlannerModel, RuntimeBridge, RuntimeHealth } from "./runtime";

const observedLmStudioModel: PlannerModel = {
  backendId: "lmstudio",
  modelId: "google/gemma-4-26b-a4b",
  displayName: "google/gemma-4-26b-a4b",
  contextWindowTokens: null,
  maxOutputTokens: 16_384,
};

function previewHealth(policyConfigured: boolean): RuntimeHealth {
  return {
    state: "ready",
    transport: "stdio",
    protocolVersion: "5",
    daemonVersion: "0.1.0",
    message: policyConfigured
      ? "Runtime and model discovery are ready. A producer/critic role-policy path is configured; exact producer, critic, and model availability are enforced at run preflight."
      : "Runtime and model discovery are ready. Set BIRDCODE_MODEL_POLICY to an explicit strict role-policy file before starting policy-separated planning review.",
    semanticPolicyConfigured: policyConfigured,
    backends: [{
      id: "lmstudio",
      displayName: "LM Studio",
      state: "ready",
      modelIdentity: observedLmStudioModel.modelId,
    }],
  };
}

/**
 * Deterministic development-only bridge used to capture truthful documentation
 * images when macOS Screen Recording permission is unavailable. It represents
 * the retained protocol-v5 UI states and the exact read-only LM Studio model
 * inventory checked into `docs/evidence`; it never simulates a model result.
 */
export function docsPreviewBridge(mode: string | null): RuntimeBridge | undefined {
  if (!import.meta.env.DEV || (mode !== "policy-required" && mode !== "policy-configured")) {
    return undefined;
  }
  const policyConfigured = mode === "policy-configured";
  return {
    health: async () => previewHealth(policyConfigured),
    reset: async () => undefined,
    discoverModels: async () => [observedLmStudioModel],
  };
}
