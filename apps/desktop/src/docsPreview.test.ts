import { describe, expect, test } from "vitest";
import { docsPreviewBridge } from "./docsPreview";

describe("documentation preview bridge", () => {
  test("fails closed for unknown preview modes", () => {
    expect(docsPreviewBridge(null)).toBeUndefined();
    expect(docsPreviewBridge("unknown")).toBeUndefined();
  });

  test("projects the retained protocol-v5 model inventory without a policy", async () => {
    const bridge = docsPreviewBridge("policy-required");
    expect(bridge).toBeDefined();
    await expect(bridge?.health()).resolves.toMatchObject({
      state: "ready",
      protocolVersion: "5",
      semanticPolicyConfigured: false,
    });
    await expect(bridge?.discoverModels?.()).resolves.toEqual([
      expect.objectContaining({ modelId: "google/gemma-4-26b-a4b" }),
    ]);
  });

  test("labels a configured path without claiming preflight success", async () => {
    const bridge = docsPreviewBridge("policy-configured");
    await expect(bridge?.health()).resolves.toMatchObject({
      semanticPolicyConfigured: true,
      message: expect.stringContaining("enforced at run preflight"),
    });
  });
});
