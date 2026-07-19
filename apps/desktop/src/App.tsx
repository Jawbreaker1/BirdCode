import { useEffect, useRef, useState, type FormEvent } from "react";
import appIcon from "../src-tauri/icons/128x128.png";
import {
  runtimeBridge,
  type AcceptedPlan,
  type PlanEvent,
  type PlannerModel,
  type PlannerReasoningEffort,
  type ReconciliationRequiredPlan,
  type RuntimeBridge,
  type RuntimeHealth,
  type StartedPlan,
} from "./runtime";
import "./styles.css";

const checking: RuntimeHealth = {
  state: "checking",
  transport: "stdio",
  protocolVersion: null,
  daemonVersion: null,
  message: "Checking local runtime…",
  backends: [],
};

const statusLabel: Record<RuntimeHealth["state"], string> = {
  checking: "Checking runtime",
  ready: "Runtime ready",
  not_started: "Runtime not started",
  unavailable: "Runtime unavailable",
  error: "Runtime error",
};

const READY_HEALTH_POLL_MS = 5_000;
const RETRY_HEALTH_POLL_MS = 1_000;
const RUN_POLL_MS = 350;
const RUN_RETRY_POLL_MS = 1_500;
const MODEL_REFRESH_MS = 10_000;
const MODEL_RETRY_MS = 2_000;
const MAX_ROOT_PLANNER_OUTPUT_TOKENS = 16_384;

interface AppProps { bridge?: RuntimeBridge }

function isTerminal(state: StartedPlan["state"]): boolean {
  return state === "completed" || state === "failed" || state === "cancelled";
}

function shortDigest(digest: string): string {
  return digest.slice(0, 10) + "…" + digest.slice(-8);
}

function displayTime(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function App({ bridge = runtimeBridge }: AppProps) {
  const [health, setHealth] = useState(checking);
  const [goal, setGoal] = useState("");
  const [workspaceRoot, setWorkspaceRoot] = useState("");
  const [models, setModels] = useState<PlannerModel[]>([]);
  const [selectedModelId, setSelectedModelId] = useState("");
  const [modelStatus, setModelStatus] = useState("Waiting for runtime");
  const [maxOutputTokens, setMaxOutputTokens] = useState(4096);
  const [maxWallTimeSeconds, setMaxWallTimeSeconds] = useState(180);
  const [reasoningEffort, setReasoningEffort] = useState<PlannerReasoningEffort | null>(null);
  const [activeRun, setActiveRun] = useState<StartedPlan | null>(null);
  const [pendingReconciliation, setPendingReconciliation] = useState<ReconciliationRequiredPlan | null>(null);
  const [events, setEvents] = useState<PlanEvent[]>([]);
  const [acceptedPlan, setAcceptedPlan] = useState<AcceptedPlan | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [cancellationAttempted, setCancellationAttempted] = useState(false);
  const [cancellationRecorded, setCancellationRecorded] = useState(false);
  const [runAlreadyTerminal, setRunAlreadyTerminal] = useState(false);
  const [resetGeneration, setResetGeneration] = useState(0);
  const [resetting, setResetting] = useState(false);
  const runtimeGenerationRef = useRef(0);
  const resetInFlightRef = useRef(false);
  const resetCompletedRef = useRef(false);
  const cancelAttemptedRef = useRef(false);
  const reconcileInFlightRef = useRef(false);

  useEffect(() => {
    if (resetCompletedRef.current) {
      resetCompletedRef.current = false;
      resetInFlightRef.current = false;
    }
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let generation = 0;
    let inFlight = false;

    const schedule = (delay: number) => {
      if (!active || document.visibilityState === "hidden") return;
      if (timer !== undefined) clearTimeout(timer);
      timer = setTimeout(() => {
        timer = undefined;
        void check();
      }, delay);
    };
    const check = async () => {
      if (!active || inFlight || resetInFlightRef.current || document.visibilityState === "hidden") return;
      inFlight = true;
      const requestGeneration = ++generation;
      const runtimeGeneration = runtimeGenerationRef.current;
      try {
        const next = await bridge.health();
        if (!active || requestGeneration !== generation || runtimeGeneration !== runtimeGenerationRef.current) return;
        inFlight = false;
        setHealth(next);
        schedule(next.state === "ready" ? READY_HEALTH_POLL_MS : RETRY_HEALTH_POLL_MS);
      } catch (error: unknown) {
        if (!active || requestGeneration !== generation || runtimeGeneration !== runtimeGenerationRef.current) return;
        inFlight = false;
        setHealth({
          ...checking,
          state: "error",
          message: error instanceof Error ? error.message : "Runtime health check failed.",
        });
        schedule(RETRY_HEALTH_POLL_MS);
      }
    };
    const onVisibilityChange = () => {
      generation += 1;
      inFlight = false;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      if (document.visibilityState !== "visible") return;
      void check();
    };

    document.addEventListener("visibilitychange", onVisibilityChange);
    void check();
    return () => {
      active = false;
      generation += 1;
      if (timer !== undefined) clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [bridge, resetGeneration]);

  useEffect(() => {
    if (health.state !== "ready") {
      setModels([]);
      setSelectedModelId("");
      setModelStatus("Waiting for runtime");
      return;
    }
    if (!bridge.discoverModels) {
      setModels([]);
      setSelectedModelId("");
      setModelStatus("Planning bridge unavailable");
      return;
    }
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setModelStatus("Discovering exact model identities…");
    const discover = async () => {
      try {
        const discovered = await bridge.discoverModels!();
        if (!active) return;
        setModels(discovered);
        setSelectedModelId((current) => (
          discovered.some((model) => model.modelId === current)
            ? current
            : discovered[0]?.modelId ?? ""
        ));
        setModelStatus(discovered.length ? String(discovered.length) + " model" + (discovered.length === 1 ? "" : "s") + " discovered" : "No LM Studio models discovered");
        timer = setTimeout(() => void discover(), MODEL_REFRESH_MS);
      } catch (error: unknown) {
        if (!active) return;
        setModels([]);
        setSelectedModelId("");
        setModelStatus(error instanceof Error ? error.message : "Model discovery failed");
        timer = setTimeout(() => void discover(), MODEL_RETRY_MS);
      }
    };
    void discover();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [bridge, health.state]);

  const activeRunId = activeRun?.runId ?? null;
  const activeSessionId = activeRun?.sessionId ?? null;
  useEffect(() => {
    if (!activeRunId || !activeSessionId || !bridge.pollPlan) return;
    const sessionId = activeSessionId;
    const runId = activeRunId;
    let active = true;
    let cursor = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let polling = false;

    const schedule = (delay: number) => {
      if (!active) return;
      timer = setTimeout(() => {
        timer = undefined;
        void poll();
      }, delay);
    };
    const poll = async () => {
      if (!active || polling) return;
      polling = true;
      try {
        const next = await bridge.pollPlan!(sessionId, runId, cursor);
        if (!active || next.runId !== runId) return;
        cursor = next.nextSequence;
        setEvents((current) => {
          const merged = new Map(current.map((item) => [item.sequence, item]));
          for (const item of next.events) merged.set(item.sequence, item);
          return [...merged.values()].sort((left, right) => left.sequence - right.sequence);
        });
        setActiveRun((current) => current?.runId === runId ? { ...current, state: next.state } : current);
        if (next.acceptedPlan) setAcceptedPlan(next.acceptedPlan);
        setRunError(null);
        polling = false;
        if (!isTerminal(next.state)) schedule(RUN_POLL_MS);
      } catch (error: unknown) {
        if (!active) return;
        polling = false;
        setRunError(error instanceof Error ? error.message : "Plan polling failed");
        schedule(RUN_RETRY_POLL_MS);
      }
    };
    void poll();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [activeRunId, activeSessionId, bridge]);

  const resetRuntime = async () => {
    if (resetInFlightRef.current) return;
    resetInFlightRef.current = true;
    runtimeGenerationRef.current += 1;
    setResetting(true);
    try {
      await bridge.reset();
      setHealth(checking);
    } catch (error: unknown) {
      setHealth({
        ...checking,
        state: "error",
        message: error instanceof Error ? "Runtime reset failed: " + error.message : "Runtime reset failed.",
      });
    } finally {
      resetCompletedRef.current = true;
      setResetting(false);
      setResetGeneration((generation) => generation + 1);
    }
  };

  const selectedModel = models.find((model) => model.modelId === selectedModelId);
  const runInProgress = activeRun !== null && !isTerminal(activeRun.state);
  const runLocked = runInProgress || pendingReconciliation !== null;
  const limitsValid = Number.isSafeInteger(maxOutputTokens)
    && maxOutputTokens > 0
    && maxOutputTokens <= MAX_ROOT_PLANNER_OUTPUT_TOKENS
    && Number.isSafeInteger(maxWallTimeSeconds)
    && maxWallTimeSeconds > 0
    && maxWallTimeSeconds <= 3_600;
  const canRun = health.state === "ready"
    && selectedModel !== undefined
    && goal.trim().length > 0
    && workspaceRoot.trim().length > 0
    && limitsValid
    && !runInProgress
    && pendingReconciliation === null
    && !starting
    && bridge.startPlan !== undefined;
  const canResetRuntime = health.transport === "stdio" && health.state !== "ready" && health.state !== "checking";
  const readinessTitle = health.state !== "ready"
    ? "Ready when your runtime is"
    : pendingReconciliation
      ? "Run reconciliation required"
    : selectedModel
      ? "Ready for a root plan"
      : "Runtime ready · connect a backend";

  const startPlan = async (event: FormEvent) => {
    event.preventDefault();
    if (!canRun || !selectedModel || !bridge.startPlan) return;
    setStarting(true);
    setRunError(null);
    setEvents([]);
    setAcceptedPlan(null);
    setCancellationAttempted(false);
    setCancellationRecorded(false);
    setRunAlreadyTerminal(false);
    cancelAttemptedRef.current = false;
    try {
      const outcome = await bridge.startPlan({
        workspaceRoot,
        goal,
        backendId: selectedModel.backendId,
        modelId: selectedModel.modelId,
        maxOutputTokens,
        maxWallTimeSeconds,
        reasoningEffort,
      });
      if (outcome.status === "started") {
        setPendingReconciliation(null);
        setActiveRun(outcome.data);
        setWorkspaceRoot(outcome.data.workspaceRoot);
      } else {
        setActiveRun(null);
        setPendingReconciliation(outcome.data);
        setWorkspaceRoot(outcome.data.workspaceRoot);
      }
    } catch (error: unknown) {
      setRunError(error instanceof Error ? error.message : "Could not start durable plan run");
    } finally {
      setStarting(false);
    }
  };

  const reconcilePlanStart = async () => {
    const pending = pendingReconciliation;
    if (!pending || !bridge.reconcilePlanStart || reconcileInFlightRef.current) return;
    reconcileInFlightRef.current = true;
    setReconciling(true);
    setRunError(null);
    try {
      const outcome = await bridge.reconcilePlanStart(pending.runId);
      if (
        outcome.data.runId !== pending.runId
        || outcome.data.sessionId !== pending.sessionId
        || outcome.data.workspaceRoot !== pending.workspaceRoot
        || outcome.data.modelId !== pending.modelId
      ) {
        throw new Error("Runtime returned a different retained plan identity during reconciliation");
      }
      if (outcome.status === "started") {
        setPendingReconciliation(null);
        setActiveRun(outcome.data);
        setWorkspaceRoot(outcome.data.workspaceRoot);
      } else {
        setPendingReconciliation(outcome.data);
      }
    } catch (error: unknown) {
      setRunError(error instanceof Error ? error.message : "Could not reconcile durable plan run");
    } finally {
      reconcileInFlightRef.current = false;
      setReconciling(false);
    }
  };

  const cancelPlan = async () => {
    if (!activeRun || isTerminal(activeRun.state) || cancelAttemptedRef.current || !bridge.cancelPlan) return;
    cancelAttemptedRef.current = true;
    setCancellationAttempted(true);
    setCancelling(true);
    try {
      const receipt = await bridge.cancelPlan(activeRun.runId);
      if (receipt.runId !== activeRun.runId) throw new Error("Cancellation receipt belongs to another run");
      if (receipt.disposition === "run_already_terminal") {
        setCancellationRecorded(false);
        setRunAlreadyTerminal(true);
        setRunError("The run was already terminal; no cancellation was recorded. Its authoritative final state is being refreshed.");
      } else {
        setCancellationRecorded(true);
        setRunAlreadyTerminal(false);
      }
    } catch (error: unknown) {
      // A lost response is safe to retry because daemon cancellation is
      // idempotent for a run. Keep the synchronous ref latched only while one
      // request is in flight or after a receipt has been verified.
      cancelAttemptedRef.current = false;
      setCancellationAttempted(false);
      setRunError(error instanceof Error ? error.message : "Could not record cancellation");
    } finally {
      setCancelling(false);
    }
  };

  return (
    <main className="shell">
      <nav className="rail" aria-label="Primary navigation">
        <img className="brand-mark" src={appIcon} alt="" aria-hidden="true" />
        <button className="rail-button active" aria-label="Runs">⌁</button>
        <button className="rail-button" type="button" aria-label="Projects" title="Unavailable in this PlanOnly slice" disabled>◇</button>
        <div className="rail-spacer" />
        <button className="rail-button" type="button" aria-label="Settings" title="Unavailable in this PlanOnly slice" disabled>⚙</button>
      </nav>

      <aside className="sidebar">
        <header className="sidebar-header">
          <span className="eyebrow">WORKSPACE</span>
          <button className="icon-button" type="button" aria-label="Workspace actions" title="Unavailable in this PlanOnly slice" disabled>•••</button>
        </header>
        <section className={workspaceRoot ? "project-card" : "project-empty"}>
          <div className="folder-glyph">⌁</div>
          <strong>{workspaceRoot || "No project open"}</strong>
          <p>{workspaceRoot ? "Local workspace · read-only planning" : "Enter a local repository in Run setup."}</p>
        </section>
        <div className="section-title"><span>SESSIONS</span><span>{activeRun || pendingReconciliation ? 1 : 0}</span></div>
        {activeRun ? (
          <section className="session-card">
            <span className={"mini-state " + activeRun.state} />
            <div><strong>Root plan</strong><small>{activeRun.modelId}</small><code>{activeRun.runId}</code></div>
          </section>
        ) : pendingReconciliation ? (
          <section className="session-card">
            <span className="mini-state waiting" />
            <div><strong>Reconciliation required</strong><small>{pendingReconciliation.modelId}</small><code>{pendingReconciliation.runId}</code></div>
          </section>
        ) : (
          <section className="session-empty">
            <p>No sessions yet</p>
            <span>Your durable agent runs will appear here.</span>
          </section>
        )}
        <footer className="runtime-card">
          <div className={"status-dot " + health.state} />
          <div className="runtime-copy" aria-live="polite">
            <strong>{statusLabel[health.state]}</strong>
            <span>{health.transport === "stdio" ? "Local daemon · stdio" : "Browser preview"}</span>
          </div>
          {canResetRuntime ? <button className="runtime-reset" type="button" aria-label="Reset runtime" aria-busy={resetting} disabled={resetting} onClick={() => void resetRuntime()}>{resetting ? "Resetting…" : "Reset runtime"}</button> : null}
        </footer>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div><span className="muted">{workspaceRoot || "NO WORKSPACE"}</span><span className="crumb">/</span><strong>{activeRun || pendingReconciliation ? "Root plan" : "New run"}</strong></div>
          <div className={"status-pill " + health.state}><span /><span>{statusLabel[health.state]}</span></div>
        </header>

        <div className="run-header">
          <div><span className="eyebrow">DURABLE ROOT PLANNER · PLAN ONLY</span><h1>{activeRun ? "Plan evidence" : pendingReconciliation ? "Confirm the durable run" : "What should BirdCode plan?"}</h1></div>
          {runInProgress ? (
            <button className="secondary cancel" type="button" disabled={cancellationAttempted} onClick={() => void cancelPlan()}>
              {cancelling ? "Recording…" : cancellationRecorded ? "Cancellation recorded" : runAlreadyTerminal ? "Run already terminal" : cancellationAttempted ? "Cancellation not confirmed" : "Cancel run"}
            </button>
          ) : <button className="secondary" disabled>Compare run</button>}
        </div>

        <section className={"timeline " + (activeRun || pendingReconciliation ? "has-run" : "")} aria-label="Run timeline">
          {pendingReconciliation ? (
            <div className="reconciliation-required" role="status">
              <span className="eyebrow">EXACT CREATE-RUN RECONCILIATION</span>
              <h2>Keep this run identity</h2>
              <p>{pendingReconciliation.message}</p>
              <dl>
                <div><dt>Run</dt><dd><code>{pendingReconciliation.runId}</code></dd></div>
                <div><dt>Session</dt><dd><code>{pendingReconciliation.sessionId}</code></dd></div>
                <div><dt>Submission</dt><dd>{pendingReconciliation.mayHaveExecuted ? "May already exist" : "Not submitted"}</dd></div>
              </dl>
              <button
                className="secondary reconcile"
                type="button"
                aria-label="Reconcile run"
                disabled={reconciling || bridge.reconcilePlanStart === undefined}
                onClick={() => void reconcilePlanStart()}
              >
                {reconciling ? "Reconciling…" : "Reconcile run"}
              </button>
              {bridge.reconcilePlanStart === undefined ? <small>The native reconciliation bridge is unavailable.</small> : null}
            </div>
          ) : !activeRun ? (
            <div className="empty-run">
              <div className="pulse-mark"><span /></div>
              <h2>{readinessTitle}</h2>
              <p>No model output is simulated. Select an exact discovered model and start a run to see durable typed events here.</p>
              <div className="readiness-grid">
                <div><span className="step">01</span><strong>Repository</strong><small>{workspaceRoot || "Not selected"}</small></div>
                <div><span className="step">02</span><strong>Backend</strong><small>{modelStatus}</small></div>
                <div><span className="step">03</span><strong>Authority</strong><small>Plan only · no writes</small></div>
              </div>
            </div>
          ) : (
            <div className="run-stream">
              <div className="run-summary">
                <div><span className={"run-state " + activeRun.state}>{activeRun.state}</span><strong>{activeRun.modelId}</strong></div>
                <code>{activeRun.runId}</code>
              </div>
              <div className="event-list" aria-live="polite">
                {events.length === 0 ? (
                  <div className="event-pending"><span />Waiting for the first durable event…</div>
                ) : events.map((item) => (
                  <article className={"event-row " + item.tone} key={item.sequence}>
                    <div className="event-node"><span /></div>
                    <div className="event-copy">
                      <div><strong>{item.title}</strong><time>{displayTime(item.occurredAt)}</time></div>
                      <p>{item.detail}</p>
                      <code>#{item.sequence} · {item.kind}</code>
                    </div>
                  </article>
                ))}
              </div>
              {acceptedPlan ? <PlanResult plan={acceptedPlan} /> : null}
            </div>
          )}
          {runError ? <div className="run-error" role="alert"><strong>Runtime evidence error</strong><span>{runError}</span></div> : null}
        </section>

        <form className="composer" onSubmit={(event) => void startPlan(event)}>
          <textarea value={goal} onChange={(event) => setGoal(event.target.value)} disabled={runLocked || starting || reconciling} placeholder="Describe the complete outcome BirdCode should plan…" aria-label="Task prompt" />
          <div className="composer-footer">
            <div className="composer-options">
              <button type="button" disabled>Agent ▾</button>
              <button type="button" disabled>Auto context</button>
              <button type="button" disabled>Local</button>
              <span className="authority-chip">PLAN ONLY</span>
            </div>
            <button className="run-button" disabled={!canRun} type="submit" aria-label="Run task">{starting ? "…" : "↗"}</button>
          </div>
        </form>
      </section>

      <aside className="inspector">
        <header><span className="eyebrow">RUN SETUP</span><button className="icon-button" type="button" aria-label="Close inspector" title="Unavailable in this PlanOnly slice" disabled>×</button></header>
        <section>
          <label htmlFor="workspace-root">Repository</label>
          <input id="workspace-root" className="setup-input" value={workspaceRoot} disabled={runLocked} onChange={(event) => setWorkspaceRoot(event.target.value)} placeholder="/Users/name/github_repos/project" />
          <small className="field-hint">Existing local directory; canonicalized by the native bridge.</small>
        </section>
        <section>
          <label htmlFor="planner-model">Exact LM Studio model</label>
          <select id="planner-model" className="setup-input" value={selectedModelId} disabled={health.state !== "ready" || runLocked || models.length === 0} onChange={(event) => setSelectedModelId(event.target.value)}>
            {models.length === 0 ? <option value="">No model available</option> : models.map((model) => <option value={model.modelId} key={model.backendId + "/" + model.modelId}>{model.displayName} · {model.modelId}</option>)}
          </select>
          <small className="field-hint">{modelStatus}</small>
        </section>
        <section className="limits">
          <label>Limits</label>
          <div className="limit-grid">
            <label htmlFor="max-output">Output tokens<input id="max-output" type="number" min="1" max={MAX_ROOT_PLANNER_OUTPUT_TOKENS} value={maxOutputTokens} disabled={runLocked} onChange={(event) => setMaxOutputTokens(Number(event.target.value))} /></label>
            <label htmlFor="wall-time">Wall time (s)<input id="wall-time" type="number" min="1" max="3600" value={maxWallTimeSeconds} disabled={runLocked} onChange={(event) => setMaxWallTimeSeconds(Number(event.target.value))} /></label>
            <label htmlFor="reasoning">Reasoning<select id="reasoning" value={reasoningEffort ?? "auto"} disabled={runLocked} onChange={(event) => setReasoningEffort(event.target.value === "off" ? "off" : null)}><option value="auto">Auto</option><option value="off">Off</option></select></label>
          </div>
        </section>
        <section><label>Authority</label><div className="setup-row"><span className="setup-icon">⌾</span><div><strong>Read-only planning</strong><small>Execution is rejected in this slice</small></div></div></section>
        <section className="health-detail"><label>RUNTIME</label><dl><div><dt>Status</dt><dd>{statusLabel[health.state]}</dd></div><div><dt>Transport</dt><dd>{health.transport}</dd></div><div><dt>Protocol</dt><dd>{health.protocolVersion ?? "—"}</dd></div></dl><p>{health.message}</p></section>
      </aside>
    </main>
  );
}

function PlanResult({ plan }: { plan: AcceptedPlan }) {
  return (
    <section className="plan-result" aria-label="Accepted plan">
      <header>
        <div><span className="accepted-mark">✓</span><div><span className="eyebrow">HASH-VERIFIED ARTIFACT</span><h2>Accepted root plan</h2></div></div>
        <div className="plan-identity"><span>revision {plan.revision}</span><code title={plan.digest}>{shortDigest(plan.digest)}</code></div>
      </header>
      <div className="plan-rationale"><span className={"directive " + plan.directive}>{plan.directive}</span><p>{plan.rationale}</p></div>

      {plan.workOrders.length ? (
        <div className="plan-section">
          <h3>Proposed work orders <span>{plan.workOrders.length}</span></h3>
          <div className="work-orders">
            {plan.workOrders.map((work, index) => (
              <article className="work-order" key={work.id}>
                <div className="work-index">{String(index + 1).padStart(2, "0")}</div>
                <div>
                  <div className="work-title"><strong>{work.objective}</strong><code>{work.id}</code></div>
                  {work.dependencies.length ? <p className="work-meta">Depends on {work.dependencies.join(", ")}</p> : <p className="work-meta">No dependencies declared</p>}
                  {work.verificationTargets.length ? <ul>{work.verificationTargets.map((target, targetIndex) => <li key={work.id + "-" + String(targetIndex)}><span>{target.kind}</span><strong>{target.question}</strong><code>{target.selector}</code></li>)}</ul> : null}
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : null}

      {plan.clarifications.length ? (
        <div className="plan-section questions"><h3>Clarifications <span>{plan.clarifications.length}</span></h3>{plan.clarifications.map((question, index) => <p key={question}><span>{index + 1}</span>{question}</p>)}</div>
      ) : null}
      {plan.escalations.length ? (
        <div className="plan-section escalations"><h3>Escalations <span>{plan.escalations.length}</span></h3>{plan.escalations.map((escalation, index) => <article key={escalation.reason + "-" + String(index)}><strong>{escalation.reason}</strong><p>{escalation.requestedDecision}</p></article>)}</div>
      ) : null}
      {plan.decisionEvidence.length ? (
        <details className="decision-evidence"><summary>Decision evidence · {plan.decisionEvidence.length} records</summary>{plan.decisionEvidence.map((evidence, index) => <p key={evidence.section + "-" + String(index)}><strong>{evidence.section}</strong>{evidence.basis}</p>)}</details>
      ) : null}
    </section>
  );
}
