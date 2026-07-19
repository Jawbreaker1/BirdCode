import { useEffect, useRef, useState } from "react";
import appIcon from "../src-tauri/icons/128x128.png";
import { runtimeBridge, type RuntimeBridge, type RuntimeHealth } from "./runtime";
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

interface AppProps { bridge?: RuntimeBridge }

export function App({ bridge = runtimeBridge }: AppProps) {
  const [health, setHealth] = useState(checking);
  const [prompt, setPrompt] = useState("");
  const [resetGeneration, setResetGeneration] = useState(0);
  const [resetting, setResetting] = useState(false);
  const runtimeGenerationRef = useRef(0);
  const resetInFlightRef = useRef(false);
  const resetCompletedRef = useRef(false);

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
      if (document.visibilityState !== "visible") {
        return;
      }
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
        message: error instanceof Error ? `Runtime reset failed: ${error.message}` : "Runtime reset failed.",
      });
    } finally {
      resetCompletedRef.current = true;
      setResetting(false);
      setResetGeneration((generation) => generation + 1);
    }
  };

  const hasReadyBackend = health.backends.some((backend) => backend.state === "ready");
  const canRun = health.state === "ready" && hasReadyBackend && prompt.trim().length > 0;
  const canResetRuntime = health.transport === "stdio" && health.state !== "ready" && health.state !== "checking";
  const readinessTitle = health.state !== "ready"
    ? "Ready when your runtime is"
    : hasReadyBackend
      ? "Ready for a task"
      : "Runtime ready · connect a backend";

  return (
    <main className="shell">
      <nav className="rail" aria-label="Primary navigation">
        <img className="brand-mark" src={appIcon} alt="" aria-hidden="true" />
        <button className="rail-button active" aria-label="Runs">⌁</button>
        <button className="rail-button" aria-label="Projects">◇</button>
        <div className="rail-spacer" />
        <button className="rail-button" aria-label="Settings">⚙</button>
      </nav>

      <aside className="sidebar">
        <header className="sidebar-header">
          <span className="eyebrow">WORKSPACE</span>
          <button className="icon-button" aria-label="Workspace actions">•••</button>
        </header>
        <section className="project-empty">
          <div className="folder-glyph">⌁</div>
          <strong>No project open</strong>
          <p>Connect the runtime to select a local repository.</p>
        </section>
        <div className="section-title"><span>SESSIONS</span><span>0</span></div>
        <section className="session-empty">
          <p>No sessions yet</p>
          <span>Your durable agent runs will appear here.</span>
        </section>
        <footer className="runtime-card">
          <div className={`status-dot ${health.state}`} />
          <div className="runtime-copy" aria-live="polite">
            <strong>{statusLabel[health.state]}</strong>
            <span>{health.transport === "stdio" ? "Local daemon · stdio" : "Browser preview"}</span>
          </div>
          {canResetRuntime ? <button className="runtime-reset" type="button" aria-label="Reset runtime" aria-busy={resetting} disabled={resetting} onClick={() => void resetRuntime()}>{resetting ? "Resetting…" : "Reset runtime"}</button> : null}
        </footer>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div><span className="muted">NO WORKSPACE</span><span className="crumb">/</span><strong>New run</strong></div>
          <div className={`status-pill ${health.state}`}><span /><span>{statusLabel[health.state]}</span></div>
        </header>

        <div className="run-header">
          <div><span className="eyebrow">AGENT RUN</span><h1>What should BirdCode build?</h1></div>
          <button className="secondary" disabled>Compare run</button>
        </div>

        <section className="timeline" aria-label="Run timeline">
          <div className="empty-run">
            <div className="pulse-mark"><span /></div>
            <h2>{readinessTitle}</h2>
            <p>No model output is simulated. Connect a backend and start a run to see real agent events here.</p>
            <div className="readiness-grid">
              <div><span className="step">01</span><strong>Repository</strong><small>Not selected</small></div>
              <div><span className="step">02</span><strong>Backend</strong><small>{health.backends.length ? `${health.backends.length} discovered` : "None discovered"}</small></div>
              <div><span className="step">03</span><strong>Execution</strong><small>Awaiting configuration</small></div>
            </div>
          </div>
        </section>

        <form className="composer" onSubmit={(event) => event.preventDefault()}>
          <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Describe a task, ask a question, or paste an error…" aria-label="Task prompt" />
          <div className="composer-footer">
            <div className="composer-options"><button type="button" disabled title="Agent selection is not wired yet">Agent ▾</button><button type="button" disabled title="Automatic context is not wired yet">Auto context</button><button type="button" disabled title="Backend selection is not wired yet">Local</button></div>
            <button className="run-button" disabled={!canRun} type="submit" aria-label="Run task">↗</button>
          </div>
        </form>
      </section>

      <aside className="inspector">
        <header><span className="eyebrow">RUN SETUP</span><button className="icon-button" aria-label="Close inspector">×</button></header>
        <section><label>Repository</label><div className="setup-row"><span className="setup-icon">◇</span><div><strong>Not selected</strong><small>Local workspace</small></div></div></section>
        <section><label>Backend</label><div className="setup-row"><span className="setup-icon">◎</span><div><strong>{health.backends[0]?.displayName ?? "Not connected"}</strong><small>{health.backends[0]?.modelIdentity ?? "Model identity unavailable"}</small></div></div></section>
        <section><label>Permissions</label><div className="setup-row"><span className="setup-icon">⌾</span><div><strong>Ask before changes</strong><small>No permission policy loaded</small></div></div></section>
        <section className="health-detail"><label>RUNTIME</label><dl><div><dt>Status</dt><dd>{statusLabel[health.state]}</dd></div><div><dt>Transport</dt><dd>{health.transport}</dd></div><div><dt>Protocol</dt><dd>{health.protocolVersion ?? "—"}</dd></div></dl><p>{health.message}</p></section>
      </aside>
    </main>
  );
}
