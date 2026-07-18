import { runtimeBridge } from "./runtime";

test("browser preview reset fails instead of pretending to reset a runtime", async () => {
  expect("__TAURI_INTERNALS__" in window).toBe(false);
  await expect(runtimeBridge.reset()).rejects.toThrow("Desktop runtime bridge is unavailable in browser preview.");
});
