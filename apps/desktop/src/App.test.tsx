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
