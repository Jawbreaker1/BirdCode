import { invoke } from "@tauri-apps/api/core";

export type RuntimeState = "checking" | "ready" | "not_started" | "unavailable" | "error";

export interface BackendHealth {
  id: string;
  displayName: string;
  state: "ready" | "unavailable";
  modelIdentity?: string;
}

export interface RuntimeHealth {
  state: RuntimeState;
  transport: "stdio" | "preview";
  protocolVersion: string | null;
  daemonVersion: string | null;
  message: string;
  backends: BackendHealth[];
}

export interface RuntimeBridge {
  health(): Promise<RuntimeHealth>;
  reset(): Promise<void>;
}

export const runtimeBridge: RuntimeBridge = {
  async health() {
    if (!("__TAURI_INTERNALS__" in window)) {
      return {
        state: "unavailable",
        transport: "preview",
        protocolVersion: null,
        daemonVersion: null,
        message: "Desktop runtime bridge is unavailable in browser preview.",
        backends: [],
      };
    }
    return invoke<RuntimeHealth>("runtime_health");
  },
  async reset() {
    if (!("__TAURI_INTERNALS__" in window)) {
      throw new Error("Desktop runtime bridge is unavailable in browser preview.");
    }
    await invoke<void>("runtime_reset");
  },
};
