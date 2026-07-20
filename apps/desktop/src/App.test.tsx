import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import { App } from "./App";
import type { RuntimeBridge } from "./runtime";

const offline: RuntimeBridge = {
  health: async () => ({ state: "not_started", transport: "stdio", protocolVersion: null, daemonVersion: null, message: "Runtime process has not been started.", backends: [] }),
  reset: async () => {},
};

afterEach(() => {
  vi.useRealTimers();
});

test("reports the real disconnected state and never enables a fake run", async () => {
  render(<App bridge={offline} />);
  await waitFor(() => expect(screen.getAllByText("Runtime not started").length).toBeGreaterThan(0));
  expect((screen.getByLabelText("Run task") as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(/No model output is simulated/)).toBeTruthy();
  expect(screen.getByText("What should BirdCode plan?")).toBeTruthy();
  expect(screen.queryByText(/orchestration/i)).toBeNull();
  for (const name of ["Projects", "Settings", "Workspace actions", "Close inspector"]) {
    const unavailable = screen.getByRole("button", { name }) as HTMLButtonElement;
    expect(unavailable.disabled).toBe(true);
    expect(unavailable.title).toBe("Unavailable in this PlanOnly slice");
  }
});

test("does not claim task readiness or interactive setup without a backend", async () => {
  const readyWithoutBackend: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "2", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
  };

  render(<App bridge={readyWithoutBackend} />);
  await waitFor(() => expect(screen.getByText("Runtime ready · connect a backend")).toBeTruthy());
  expect(screen.queryByText("Ready for a task")).toBeNull();
  expect((screen.getByRole("button", { name: "Agent ▾" }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: "Auto context" }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: "Local" }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByLabelText("Run task") as HTMLButtonElement).disabled).toBe(true);
});

test("fails closed when the runtime is ready but no producer/critic policy is loaded", async () => {
  const startPlan = vi.fn<NonNullable<RuntimeBridge["startPlan"]>>();
  const bridge: RuntimeBridge = {
    health: async () => ({
      state: "ready",
      transport: "stdio",
      protocolVersion: "5",
      daemonVersion: "0.1.0",
      message: "Runtime and model discovery are ready; review policy is required.",
      semanticPolicyConfigured: false,
      backends: [],
    }),
    reset: async () => {},
    discoverModels: async () => [{
      backendId: "lmstudio",
      modelId: "exact-model",
      displayName: "Exact model",
      contextWindowTokens: null,
      maxOutputTokens: null,
    }],
    startPlan,
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("exact-model"));
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Planera detta" } });

  expect(screen.getByText("Configure policy-separated review")).toBeTruthy();
  expect(screen.getByText("Policy required")).toBeTruthy();
  expect(screen.getByText(/Set BIRDCODE_MODEL_POLICY/)).toBeTruthy();
  const run = screen.getByLabelText("Run task") as HTMLButtonElement;
  expect(run.disabled).toBe(true);
  fireEvent.click(run);
  expect(startPlan).not.toHaveBeenCalled();
});

test("preserves multilingual task input without parsing it", () => {
  render(<App bridge={offline} />);
  const input = screen.getByLabelText("Task prompt") as HTMLTextAreaElement;
  const task = "Rätta felet och 説明してください — بدون تخمين";
  fireEvent.change(input, { target: { value: task } });
  expect(input.value).toBe(task);
});

test("polls runtime health through failure and recovery", async () => {
  vi.useFakeTimers();
  const health = vi
    .fn<RuntimeBridge["health"]>()
    .mockResolvedValueOnce({ state: "ready", transport: "stdio", protocolVersion: "1", daemonVersion: "0.1.0", message: "Ready", backends: [] })
    .mockResolvedValueOnce({ state: "unavailable", transport: "stdio", protocolVersion: null, daemonVersion: null, message: "Stopped", backends: [] })
    .mockResolvedValue({ state: "ready", transport: "stdio", protocolVersion: "1", daemonVersion: "0.1.0", message: "Recovered", backends: [] });

  const view = render(<App bridge={{ health, reset: async () => {} }} />);
  await act(async () => {});
  expect(screen.getAllByText("Runtime ready").length).toBeGreaterThan(0);

  await act(async () => {
    await vi.advanceTimersByTimeAsync(5_000);
  });
  expect(screen.getAllByText("Runtime unavailable").length).toBeGreaterThan(0);

  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_000);
  });
  expect(screen.getAllByText("Runtime ready").length).toBeGreaterThan(0);
  expect(health).toHaveBeenCalledTimes(3);
  view.unmount();
});

test("ignores stale health completion across hidden and visible transitions", async () => {
  vi.useFakeTimers();
  const originalVisibility = Object.getOwnPropertyDescriptor(document, "visibilityState");
  let visibility: DocumentVisibilityState = "visible";
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    get: () => visibility,
  });
  let resolveFirst!: (health: Awaited<ReturnType<RuntimeBridge["health"]>>) => void;
  let resolveSecond!: (health: Awaited<ReturnType<RuntimeBridge["health"]>>) => void;
  const ready: Awaited<ReturnType<RuntimeBridge["health"]>> = { state: "ready", transport: "stdio", protocolVersion: "1", daemonVersion: "0.1.0", message: "Ready", backends: [] };
  const unavailable: Awaited<ReturnType<RuntimeBridge["health"]>> = { state: "unavailable", transport: "stdio", protocolVersion: null, daemonVersion: null, message: "Stopped", backends: [] };
  const health = vi
    .fn<RuntimeBridge["health"]>()
    .mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve; }))
    .mockImplementationOnce(() => new Promise((resolve) => { resolveSecond = resolve; }))
    .mockResolvedValue(ready);

  const view = render(<App bridge={{ health, reset: async () => {} }} />);
  await act(async () => {});
  expect(health).toHaveBeenCalledTimes(1);

  await act(async () => {
    visibility = "hidden";
    document.dispatchEvent(new Event("visibilitychange"));
    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
  });
  expect(health).toHaveBeenCalledTimes(2);

  await act(async () => resolveSecond(ready));
  expect(screen.getAllByText("Runtime ready").length).toBeGreaterThan(0);
  await act(async () => resolveFirst(unavailable));
  expect(screen.queryByText("Runtime unavailable")).toBeNull();

  await act(async () => {
    await vi.advanceTimersByTimeAsync(5_000);
  });
  expect(health).toHaveBeenCalledTimes(3);

  view.unmount();
  if (originalVisibility) {
    Object.defineProperty(document, "visibilityState", originalVisibility);
  } else {
    Reflect.deleteProperty(document, "visibilityState");
  }
});

test("offers an explicit runtime reset and checks health again immediately", async () => {
  const health = vi
    .fn<RuntimeBridge["health"]>()
    .mockResolvedValueOnce({ state: "error", transport: "stdio", protocolVersion: null, daemonVersion: null, message: "Startup timed out", backends: [] })
    .mockResolvedValue({ state: "ready", transport: "stdio", protocolVersion: "2", daemonVersion: "0.1.0", message: "Recovered", backends: [] });
  const reset = vi.fn<RuntimeBridge["reset"]>().mockResolvedValue();

  render(<App bridge={{ health, reset }} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Reset runtime" })).toBeTruthy());

  fireEvent.click(screen.getByRole("button", { name: "Reset runtime" }));

  await waitFor(() => expect(reset).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(screen.getAllByText("Runtime ready").length).toBeGreaterThan(0));
  expect(health).toHaveBeenCalledTimes(2);
});

test("invalidates an older health request as soon as reset starts", async () => {
  vi.useFakeTimers();
  let resolveStale!: (health: Awaited<ReturnType<RuntimeBridge["health"]>>) => void;
  const recovered: Awaited<ReturnType<RuntimeBridge["health"]>> = { state: "ready", transport: "stdio", protocolVersion: "2", daemonVersion: "0.1.0", message: "Recovered after reset", backends: [] };
  const health = vi
    .fn<RuntimeBridge["health"]>()
    .mockResolvedValueOnce({ state: "error", transport: "stdio", protocolVersion: null, daemonVersion: null, message: "Startup timed out", backends: [] })
    .mockImplementationOnce(() => new Promise((resolve) => { resolveStale = resolve; }))
    .mockResolvedValue(recovered);
  const reset = vi.fn<RuntimeBridge["reset"]>().mockResolvedValue();

  const view = render(<App bridge={{ health, reset }} />);
  await act(async () => {});
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_000);
  });
  expect(health).toHaveBeenCalledTimes(2);

  fireEvent.click(screen.getByRole("button", { name: "Reset runtime" }));
  await act(async () => {});
  expect(reset).toHaveBeenCalledTimes(1);
  expect(health).toHaveBeenCalledTimes(3);
  expect(screen.getByText("Recovered after reset")).toBeTruthy();

  await act(async () => resolveStale({ state: "unavailable", transport: "stdio", protocolVersion: null, daemonVersion: null, message: "Stale pre-reset result", backends: [] }));
  expect(screen.queryByText("Stale pre-reset result")).toBeNull();
  expect(screen.getByText("Recovered after reset")).toBeTruthy();
  view.unmount();
});

test("coalesces repeated reset clicks while the first reset is pending", async () => {
  let resolveReset!: () => void;
  const health = vi
    .fn<RuntimeBridge["health"]>()
    .mockResolvedValueOnce({ state: "error", transport: "stdio", protocolVersion: null, daemonVersion: null, message: "Startup timed out", backends: [] })
    .mockResolvedValue({ state: "ready", transport: "stdio", protocolVersion: "2", daemonVersion: "0.1.0", message: "Recovered", backends: [] });
  const reset = vi.fn<RuntimeBridge["reset"]>().mockImplementation(() => new Promise<void>((resolve) => { resolveReset = resolve; }));

  render(<App bridge={{ health, reset }} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Reset runtime" })).toBeTruthy());
  const button = screen.getByRole("button", { name: "Reset runtime" });

  fireEvent.click(button);
  fireEvent.click(button);
  expect(reset).toHaveBeenCalledTimes(1);
  expect((button as HTMLButtonElement).disabled).toBe(true);

  await act(async () => resolveReset());
  await waitFor(() => expect(screen.getAllByText("Runtime ready").length).toBeGreaterThan(0));
  expect(health).toHaveBeenCalledTimes(2);
});

test("does not poll while initially hidden and checks immediately when visible", async () => {
  const originalVisibility = Object.getOwnPropertyDescriptor(document, "visibilityState");
  let visibility: DocumentVisibilityState = "hidden";
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    get: () => visibility,
  });
  const health = vi.fn<RuntimeBridge["health"]>().mockResolvedValue({ state: "ready", transport: "stdio", protocolVersion: "2", daemonVersion: "0.1.0", message: "Visible", backends: [] });

  const view = render(<App bridge={{ health, reset: async () => {} }} />);
  await act(async () => {});
  expect(health).not.toHaveBeenCalled();

  await act(async () => {
    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
  });
  expect(health).toHaveBeenCalledTimes(1);

  view.unmount();
  if (originalVisibility) {
    Object.defineProperty(document, "visibilityState", originalVisibility);
  } else {
    Reflect.deleteProperty(document, "visibilityState");
  }
});

test("submits an exact discovered model and renders the verified accepted plan", async () => {
  const startPlan = vi.fn<NonNullable<RuntimeBridge["startPlan"]>>().mockResolvedValue({
    status: "started",
    data: {
      sessionId: "019b0000-0000-7000-8000-000000000001",
      runId: "019b0000-0000-7000-8000-000000000002",
      state: "queued",
      workspaceRoot: "/tmp/birdcode-project",
      modelId: "google/gemma-4-26b-a4b",
    },
  });
  const pollPlan = vi.fn<NonNullable<RuntimeBridge["pollPlan"]>>().mockResolvedValue({
    runId: "019b0000-0000-7000-8000-000000000002",
    state: "completed",
    nextSequence: 8,
    events: [{
      sequence: 8,
      occurredAt: "2026-07-19T16:00:00Z",
      kind: "plan_semantic_review_accepted",
      tone: "success",
      title: "Independent semantic review passed",
      detail: "Revision 1",
    }],
    acceptedPlan: {
      revision: 1,
      digest: "a".repeat(64),
      directive: "plan",
      rationale: "Split the bounded outcome into independently verifiable work.",
      decisionEvidence: [{ section: "root", basis: "Bound user goal" }],
      workOrders: [{
        id: "work-1",
        objective: "Implement the durable core",
        obligationIds: ["root_goal"],
        dependencies: [],
        verificationTargets: [{ kind: "repository_file", selector: "Cargo.toml", question: "Does the workspace build?" }],
      }],
      clarifications: [],
      escalations: [],
    },
  });
  const bridge: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "3", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
    discoverModels: async () => [{
      backendId: "lmstudio",
      modelId: "google/gemma-4-26b-a4b",
      displayName: "Gemma 4 26B",
      contextWindowTokens: 121088,
      maxOutputTokens: null,
    }],
    startPlan,
    pollPlan,
    cancelPlan: async () => ({
      runId: "019b0000-0000-7000-8000-000000000002",
      cancellationRequestId: "019b0000-0000-7000-8000-000000000003",
      cancellationGeneration: 1,
      disposition: "recorded",
    }),
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("google/gemma-4-26b-a4b"));
  expect(screen.getByText("Policy/model match will be checked at preflight")).toBeTruthy();
  expect(screen.getByText("Policy configured · model match pending")).toBeTruthy();
  expect(screen.getByText("Policy configured")).toBeTruthy();
  expect(screen.getByText(/selected planner model must exactly match the policy producer/i)).toBeTruthy();
  expect(screen.getByText(/may reject the run/i)).toBeTruthy();
  expect(screen.queryByText(/review ready/i)).toBeNull();
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Bygg planen — 説明も含めて" } });
  fireEvent.click(screen.getByLabelText("Run task"));

  await waitFor(() => expect(startPlan).toHaveBeenCalledTimes(1));
  expect(startPlan.mock.calls[0]?.[0]).toEqual({
    workspaceRoot: "/tmp/birdcode-project",
    goal: "Bygg planen — 説明も含めて",
    backendId: "lmstudio",
    modelId: "google/gemma-4-26b-a4b",
    maxOutputTokens: 16_384,
    maxWallTimeSeconds: 180,
    reasoningEffort: null,
  });
  await waitFor(() => expect(screen.getByText("Accepted root plan")).toBeTruthy());
  expect(screen.getByText("Implement the durable core")).toBeTruthy();
  expect(screen.getByText("Proposed work orders")).toBeTruthy();
  expect(screen.getByText("No dependencies declared")).toBeTruthy();
  expect(screen.queryByText(/ready for parallel orchestration/i)).toBeNull();
  expect(pollPlan).toHaveBeenCalledWith(
    "019b0000-0000-7000-8000-000000000001",
    "019b0000-0000-7000-8000-000000000002",
    0,
  );
});

test("retains one ambiguous run identity until exact reconciliation starts it", async () => {
  const sessionId = "019b0000-0000-7000-8000-000000000041";
  const runId = "019b0000-0000-7000-8000-000000000042";
  const pending = {
    status: "reconciliation_required" as const,
    data: {
      sessionId,
      runId,
      workspaceRoot: "/tmp/birdcode-project",
      modelId: "exact-model",
      mayHaveExecuted: true,
      message: "The response was lost after the exact CreateRun may have reached the daemon.",
    },
  };
  const startPlan = vi
    .fn<NonNullable<RuntimeBridge["startPlan"]>>()
    .mockResolvedValue(pending);
  const reconcilePlanStart = vi
    .fn<NonNullable<RuntimeBridge["reconcilePlanStart"]>>()
    .mockResolvedValueOnce({
      ...pending,
      data: { ...pending.data, message: "The same run still requires reconciliation." },
    })
    .mockResolvedValueOnce({
      status: "started",
      data: {
        sessionId,
        runId,
        state: "queued",
        workspaceRoot: "/tmp/birdcode-project",
        modelId: "exact-model",
      },
    });
  const pollPlan = vi.fn<NonNullable<RuntimeBridge["pollPlan"]>>().mockResolvedValue({
    runId,
    state: "completed",
    nextSequence: 1,
    events: [],
    acceptedPlan: null,
  });
  const bridge: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "4", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
    discoverModels: async () => [{ backendId: "lmstudio", modelId: "exact-model", displayName: "Exact model", contextWindowTokens: null, maxOutputTokens: null }],
    startPlan,
    reconcilePlanStart,
    pollPlan,
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("exact-model"));
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Plan exactly once" } });
  fireEvent.click(screen.getByLabelText("Run task"));

  await waitFor(() => expect(screen.getByText("Keep this run identity")).toBeTruthy());
  expect(screen.getAllByText(runId).length).toBeGreaterThan(0);
  expect(screen.getByText("May already exist")).toBeTruthy();
  expect(startPlan).toHaveBeenCalledTimes(1);
  expect((screen.getByLabelText("Run task") as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByLabelText("Task prompt") as HTMLTextAreaElement).disabled).toBe(true);

  fireEvent.click(screen.getByRole("button", { name: "Reconcile run" }));
  await waitFor(() => expect(reconcilePlanStart).toHaveBeenCalledTimes(1));
  expect(reconcilePlanStart).toHaveBeenLastCalledWith(runId);
  await waitFor(() => expect(screen.getByText("The same run still requires reconciliation.")).toBeTruthy());
  expect(screen.getAllByText(runId).length).toBeGreaterThan(0);
  expect(startPlan).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("button", { name: "Reconcile run" }));
  await waitFor(() => expect(reconcilePlanStart).toHaveBeenCalledTimes(2));
  expect(reconcilePlanStart).toHaveBeenLastCalledWith(runId);
  await waitFor(() => expect(pollPlan).toHaveBeenCalledWith(sessionId, runId, 0));
  expect(screen.queryByText("Keep this run identity")).toBeNull();
  expect(startPlan).toHaveBeenCalledTimes(1);
});

test("rejects a reconciliation response that changes any retained plan identity", async () => {
  const sessionId = "019b0000-0000-7000-8000-000000000051";
  const runId = "019b0000-0000-7000-8000-000000000052";
  const startPlan = vi.fn<NonNullable<RuntimeBridge["startPlan"]>>().mockResolvedValue({
    status: "reconciliation_required",
    data: {
      sessionId,
      runId,
      workspaceRoot: "/tmp/birdcode-project",
      modelId: "exact-model",
      mayHaveExecuted: false,
      message: "Retained for exact submission.",
    },
  });
  const reconcilePlanStart = vi.fn<NonNullable<RuntimeBridge["reconcilePlanStart"]>>().mockResolvedValue({
    status: "reconciliation_required",
    data: {
      sessionId,
      runId,
      workspaceRoot: "/tmp/birdcode-project",
      modelId: "different-model",
      mayHaveExecuted: false,
      message: "Wrong identity",
    },
  });
  const bridge: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "4", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
    discoverModels: async () => [{ backendId: "lmstudio", modelId: "exact-model", displayName: "Exact model", contextWindowTokens: null, maxOutputTokens: null }],
    startPlan,
    reconcilePlanStart,
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("exact-model"));
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Plan once" } });
  fireEvent.click(screen.getByLabelText("Run task"));
  fireEvent.click(await screen.findByRole("button", { name: "Reconcile run" }));

  await waitFor(() => expect(screen.getByText("Runtime returned a different retained plan identity during reconciliation")).toBeTruthy());
  expect(screen.getAllByText(runId).length).toBeGreaterThan(0);
  expect(screen.queryByText("Wrong identity")).toBeNull();
  expect(startPlan).toHaveBeenCalledTimes(1);
});

test("offers only truthful LM Studio reasoning choices and enforces the planner token ceiling", async () => {
  const startPlan = vi.fn<NonNullable<RuntimeBridge["startPlan"]>>().mockResolvedValue({
    status: "started",
    data: {
      sessionId: "019b0000-0000-7000-8000-000000000021",
      runId: "019b0000-0000-7000-8000-000000000022",
      state: "completed",
      workspaceRoot: "/tmp/birdcode-project",
      modelId: "exact-model",
    },
  });
  const bridge: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "3", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
    discoverModels: async () => [{ backendId: "lmstudio", modelId: "exact-model", displayName: "Exact model", contextWindowTokens: null, maxOutputTokens: null }],
    startPlan,
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("exact-model"));

  const reasoning = screen.getByLabelText("Reasoning") as HTMLSelectElement;
  expect([...reasoning.options].map((option) => [option.value, option.text])).toEqual([
    ["auto", "Auto"],
    ["off", "Off"],
  ]);
  expect(reasoning.value).toBe("auto");

  const outputTokens = screen.getByLabelText("Aggregate output ceiling") as HTMLInputElement;
  expect(outputTokens.max).toBe("16384");
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Plan this" } });
  fireEvent.change(outputTokens, { target: { value: "16385" } });
  expect((screen.getByLabelText("Run task") as HTMLButtonElement).disabled).toBe(true);

  fireEvent.change(outputTokens, { target: { value: "16384" } });
  fireEvent.change(reasoning, { target: { value: "off" } });
  fireEvent.click(screen.getByLabelText("Run task"));

  await waitFor(() => expect(startPlan).toHaveBeenCalledTimes(1));
  expect(startPlan.mock.calls[0]?.[0]).toMatchObject({
    maxOutputTokens: 16_384,
    reasoningEffort: "off",
  });
});

test("records cancellation at most once from repeated UI clicks", async () => {
  let resolveCancellation!: () => void;
  const cancelPlan = vi.fn<NonNullable<RuntimeBridge["cancelPlan"]>>().mockImplementation(() => new Promise((resolve) => {
    resolveCancellation = () => resolve({
      runId: "019b0000-0000-7000-8000-000000000012",
      cancellationRequestId: "019b0000-0000-7000-8000-000000000013",
      cancellationGeneration: 1,
      disposition: "recorded",
    });
  }));
  const bridge: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "3", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
    discoverModels: async () => [{ backendId: "lmstudio", modelId: "exact-model", displayName: "Exact model", contextWindowTokens: null, maxOutputTokens: null }],
    startPlan: async () => ({
      status: "started",
      data: {
        sessionId: "019b0000-0000-7000-8000-000000000011",
        runId: "019b0000-0000-7000-8000-000000000012",
        state: "running",
        workspaceRoot: "/tmp/birdcode-project",
        modelId: "exact-model",
      },
    }),
    pollPlan: async (_sessionId, runId, afterSequence) => ({
      runId,
      state: "running",
      nextSequence: afterSequence,
      events: [],
      acceptedPlan: null,
    }),
    cancelPlan,
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("exact-model"));
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Plan this" } });
  fireEvent.click(screen.getByLabelText("Run task"));
  const cancel = await screen.findByRole("button", { name: "Cancel run" });
  fireEvent.click(cancel);
  fireEvent.click(cancel);
  expect(cancelPlan).toHaveBeenCalledTimes(1);

  await act(async () => resolveCancellation());
  await waitFor(() => expect(screen.getByRole("button", { name: "Cancellation recorded" })).toBeTruthy());
  fireEvent.click(screen.getByRole("button", { name: "Cancellation recorded" }));
  expect(cancelPlan).toHaveBeenCalledTimes(1);
});

test("reports an already-terminal receipt without claiming cancellation was recorded", async () => {
  const runId = "019b0000-0000-7000-8000-000000000022";
  const cancelPlan = vi.fn<NonNullable<RuntimeBridge["cancelPlan"]>>().mockResolvedValue({
    runId,
    cancellationRequestId: "019b0000-0000-7000-8000-000000000023",
    cancellationGeneration: 0,
    disposition: "run_already_terminal",
  });
  const bridge: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "4", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
    discoverModels: async () => [{ backendId: "lmstudio", modelId: "exact-model", displayName: "Exact model", contextWindowTokens: null, maxOutputTokens: null }],
    startPlan: async () => ({
      status: "started",
      data: {
        sessionId: "019b0000-0000-7000-8000-000000000021",
        runId,
        state: "running",
        workspaceRoot: "/tmp/birdcode-project",
        modelId: "exact-model",
      },
    }),
    pollPlan: async () => new Promise(() => {}),
    cancelPlan,
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("exact-model"));
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Plan this" } });
  fireEvent.click(screen.getByLabelText("Run task"));
  fireEvent.click(await screen.findByRole("button", { name: "Cancel run" }));

  await waitFor(() => expect(screen.getByRole("button", { name: "Run already terminal" })).toBeTruthy());
  expect(screen.queryByRole("button", { name: "Cancellation recorded" })).toBeNull();
  expect(screen.getByRole("alert").textContent).toContain("no cancellation was recorded");
  expect(cancelPlan).toHaveBeenCalledTimes(1);
});

test("re-enables cancellation after a transient rejection while coalescing the retry", async () => {
  let resolveRetry!: () => void;
  const cancelPlan = vi
    .fn<NonNullable<RuntimeBridge["cancelPlan"]>>()
    .mockRejectedValueOnce(new Error("temporary transport failure"))
    .mockImplementationOnce(() => new Promise((resolve) => {
      resolveRetry = () => resolve({
        runId: "019b0000-0000-7000-8000-000000000032",
        cancellationRequestId: "019b0000-0000-7000-8000-000000000033",
        cancellationGeneration: 1,
        disposition: "already_requested",
      });
    }));
  const bridge: RuntimeBridge = {
    health: async () => ({ state: "ready", transport: "stdio", protocolVersion: "3", daemonVersion: "0.1.0", message: "Ready", semanticPolicyConfigured: true, backends: [] }),
    reset: async () => {},
    discoverModels: async () => [{ backendId: "lmstudio", modelId: "exact-model", displayName: "Exact model", contextWindowTokens: null, maxOutputTokens: null }],
    startPlan: async () => ({
      status: "started",
      data: {
        sessionId: "019b0000-0000-7000-8000-000000000031",
        runId: "019b0000-0000-7000-8000-000000000032",
        state: "running",
        workspaceRoot: "/tmp/birdcode-project",
        modelId: "exact-model",
      },
    }),
    pollPlan: async (_sessionId, runId, afterSequence) => ({
      runId,
      state: "running",
      nextSequence: afterSequence,
      events: [],
      acceptedPlan: null,
    }),
    cancelPlan,
  };

  render(<App bridge={bridge} />);
  await waitFor(() => expect(
    (screen.getByLabelText("Exact LM Studio model") as HTMLSelectElement).value,
  ).toBe("exact-model"));
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "/tmp/birdcode-project" } });
  fireEvent.change(screen.getByLabelText("Task prompt"), { target: { value: "Plan this" } });
  fireEvent.click(screen.getByLabelText("Run task"));

  fireEvent.click(await screen.findByRole("button", { name: "Cancel run" }));
  await waitFor(() => expect(cancelPlan).toHaveBeenCalledTimes(1));
  const retry = await screen.findByRole("button", { name: "Cancel run" });
  expect((retry as HTMLButtonElement).disabled).toBe(false);

  fireEvent.click(retry);
  fireEvent.click(retry);
  expect(cancelPlan).toHaveBeenCalledTimes(2);

  await act(async () => resolveRetry());
  await waitFor(() => expect(screen.getByRole("button", { name: "Cancellation recorded" })).toBeTruthy());
  expect(cancelPlan).toHaveBeenCalledTimes(2);
});
