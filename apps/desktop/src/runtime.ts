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

export interface PlannerModel {
  backendId: string;
  modelId: string;
  displayName: string;
  contextWindowTokens: number | null;
  maxOutputTokens: number | null;
}

export type PlannerReasoningEffort = "off" | "low" | "medium" | "high";
export type PlanRunState = "queued" | "running" | "waiting" | "completed" | "failed" | "cancelled";

export interface StartPlanRequest {
  workspaceRoot: string;
  goal: string;
  backendId: string;
  modelId: string;
  maxOutputTokens: number;
  maxWallTimeSeconds: number;
  reasoningEffort: PlannerReasoningEffort | null;
}

export interface StartedPlan {
  sessionId: string;
  runId: string;
  state: PlanRunState;
  workspaceRoot: string;
  modelId: string;
}

export interface ReconciliationRequiredPlan {
  sessionId: string;
  runId: string;
  workspaceRoot: string;
  modelId: string;
  mayHaveExecuted: boolean;
  message: string;
}

export type StartPlanOutcome =
  | { status: "started"; data: StartedPlan }
  | { status: "reconciliation_required"; data: ReconciliationRequiredPlan };

export interface PlanEvent {
  sequence: number;
  occurredAt: string;
  kind: string;
  tone: "neutral" | "active" | "success" | "warning" | "danger";
  title: string;
  detail: string;
}

export interface DecisionEvidence {
  section: string;
  basis: string;
}

export interface VerificationTarget {
  kind: string;
  selector: string;
  question: string;
}

export interface WorkOrder {
  id: string;
  objective: string;
  obligationIds: string[];
  dependencies: string[];
  verificationTargets: VerificationTarget[];
}

export interface Escalation {
  reason: string;
  blockedObligationIds: string[];
  requestedDecision: string;
}

export interface AcceptedPlan {
  revision: number;
  digest: string;
  directive: "plan" | "clarify" | "escalate";
  rationale: string;
  decisionEvidence: DecisionEvidence[];
  workOrders: WorkOrder[];
  clarifications: string[];
  escalations: Escalation[];
}

export interface PlanPoll {
  runId: string;
  state: PlanRunState;
  nextSequence: number;
  events: PlanEvent[];
  acceptedPlan: AcceptedPlan | null;
}

export interface CancellationReceipt {
  runId: string;
  cancellationRequestId: string;
  cancellationGeneration: number;
  disposition: "recorded" | "already_requested" | "run_already_terminal";
}

export interface RuntimeBridge {
  health(): Promise<RuntimeHealth>;
  reset(): Promise<void>;
  discoverModels?(): Promise<PlannerModel[]>;
  startPlan?(request: StartPlanRequest): Promise<StartPlanOutcome>;
  reconcilePlanStart?(runId: string): Promise<StartPlanOutcome>;
  pollPlan?(sessionId: string, runId: string, afterSequence: number): Promise<PlanPoll>;
  cancelPlan?(runId: string): Promise<CancellationReceipt>;
}

function requireDesktopRuntime(): void {
  if (!("__TAURI_INTERNALS__" in window)) {
    throw new Error("Desktop runtime bridge is unavailable in browser preview.");
  }
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
    requireDesktopRuntime();
    await invoke<void>("runtime_reset");
  },
  async discoverModels() {
    requireDesktopRuntime();
    return invoke<PlannerModel[]>("runtime_discover_models");
  },
  async startPlan(request) {
    requireDesktopRuntime();
    return invoke<StartPlanOutcome>("runtime_start_plan", { request });
  },
  async reconcilePlanStart(runId) {
    requireDesktopRuntime();
    return invoke<StartPlanOutcome>("runtime_reconcile_plan_start", {
      request: { runId },
    });
  },
  async pollPlan(sessionId, runId, afterSequence) {
    requireDesktopRuntime();
    return invoke<PlanPoll>("runtime_poll_plan", {
      request: { sessionId, runId, afterSequence },
    });
  },
  async cancelPlan(runId) {
    requireDesktopRuntime();
    return invoke<CancellationReceipt>("runtime_cancel_plan", {
      request: { runId },
    });
  },
};
