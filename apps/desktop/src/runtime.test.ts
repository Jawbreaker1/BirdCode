import { afterEach, vi } from "vitest";
import { runtimeBridge } from "./runtime";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

afterEach(() => {
  invoke.mockReset();
  Reflect.deleteProperty(window, "__TAURI_INTERNALS__");
});

test("browser preview reset fails instead of pretending to reset a runtime", async () => {
  expect("__TAURI_INTERNALS__" in window).toBe(false);
  await expect(runtimeBridge.reset()).rejects.toThrow("Desktop runtime bridge is unavailable in browser preview.");
});

test("browser preview refuses every durable planning mutation", async () => {
  await expect(runtimeBridge.discoverModels!()).rejects.toThrow("Desktop runtime bridge is unavailable in browser preview.");
  await expect(runtimeBridge.startPlan!({
    workspaceRoot: "/tmp/project",
    goal: "Plan it",
    backendId: "lmstudio",
    modelId: "exact-model",
    maxOutputTokens: 4096,
    maxWallTimeSeconds: 180,
    reasoningEffort: "medium",
  })).rejects.toThrow("Desktop runtime bridge is unavailable in browser preview.");
  await expect(runtimeBridge.reconcilePlanStart!("run")).rejects.toThrow("Desktop runtime bridge is unavailable in browser preview.");
  await expect(runtimeBridge.pollPlan!("session", "run", 0)).rejects.toThrow("Desktop runtime bridge is unavailable in browser preview.");
  await expect(runtimeBridge.cancelPlan!("run")).rejects.toThrow("Desktop runtime bridge is unavailable in browser preview.");
});

test("reconciles only the exact retained run identity through the native command", async () => {
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    configurable: true,
    value: {},
  });
  const runId = "019b0000-0000-7000-8000-000000000042";
  const outcome = {
    status: "reconciliation_required" as const,
    data: {
      sessionId: "019b0000-0000-7000-8000-000000000041",
      runId,
      workspaceRoot: "/tmp/project",
      modelId: "exact-model",
      mayHaveExecuted: true,
      message: "Exact reconciliation remains required.",
    },
  };
  invoke.mockResolvedValue(outcome);

  await expect(runtimeBridge.reconcilePlanStart!(runId)).resolves.toEqual(outcome);
  expect(invoke).toHaveBeenCalledExactlyOnceWith("runtime_reconcile_plan_start", {
    request: { runId },
  });
});
