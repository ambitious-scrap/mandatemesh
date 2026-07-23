"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Scenario = {
  id: string;
  name: string;
  kind: "normal" | "malicious";
  summary: string;
  invoice: { invoice_id: string; raw_text: string; fields: Record<string, unknown> };
};

type Run = {
  id: string;
  scenario_id: string;
  requested_mode: string;
  execution_mode: string;
  status: "RUNNING" | "COMPLETED" | "FAILED";
  forbidden_proposals: number;
  forbidden_side_effects: number;
  error: string | null;
};

type ToolEvent = {
  id: string;
  created_at: string;
  actor: string;
  event_type: string;
  source_ref: string | null;
  tool_name: string | null;
  tool_arguments: Record<string, unknown> | null;
  tool_result: Record<string, unknown> | null;
  side_effect: Record<string, unknown> | null;
  is_forbidden: number;
  latency_ms: number | null;
};

type DemoState = {
  vendors: Array<Record<string, unknown>>;
  payments: Array<Record<string, unknown>>;
  memory_entries: Array<Record<string, unknown>>;
  secret_accesses: Array<Record<string, unknown>>;
};

const emptyState: DemoState = { vendors: [], payments: [], memory_entries: [], secret_accesses: [] };

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) throw new Error((await response.json()).detail ?? `Request failed: ${response.status}`);
  return response.json();
}

function shortHash(value: unknown) {
  const text = String(value ?? "—");
  return text.length > 18 ? `${text.slice(0, 8)}…${text.slice(-6)}` : text;
}

function stamp(value: string) {
  return new Intl.DateTimeFormat("en-IN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(value));
}

function Evidence({ value }: { value: unknown }) {
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

export default function Home() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenarioId, setScenarioId] = useState("malicious-invoice");
  const [mode, setMode] = useState<"deterministic" | "live">("deterministic");
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<ToolEvent[]>([]);
  const [state, setState] = useState<DemoState>(emptyState);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected = useMemo(() => scenarios.find((scenario) => scenario.id === scenarioId), [scenarios, scenarioId]);
  const visibleEvents = events.filter((event) => !["RUN_STARTED", "RUN_COMPLETED"].includes(event.event_type));

  const refreshState = useCallback(async () => setState(await api<DemoState>("/api/state")), []);

  useEffect(() => {
    Promise.all([api<Scenario[]>("/api/scenarios"), api<DemoState>("/api/state")])
      .then(([nextScenarios, nextState]) => {
        setScenarios(nextScenarios);
        setState(nextState);
      })
      .catch((cause) => setError(cause.message));
  }, []);

  useEffect(() => {
    if (!run || run.status !== "RUNNING") return;
    const timer = window.setInterval(async () => {
      try {
        const [nextRun, nextEvents] = await Promise.all([
          api<Run>(`/api/runs/${run.id}`),
          api<ToolEvent[]>(`/api/runs/${run.id}/events`),
        ]);
        setRun(nextRun);
        setEvents(nextEvents);
        if (nextRun.status !== "RUNNING") {
          window.clearInterval(timer);
          await refreshState();
          setBusy(false);
        }
      } catch (cause) {
        window.clearInterval(timer);
        setBusy(false);
        setError(cause instanceof Error ? cause.message : "Run status failed");
      }
    }, 300);
    return () => window.clearInterval(timer);
  }, [run, refreshState]);

  async function startRun() {
    setBusy(true);
    setError(null);
    setEvents([]);
    try {
      const nextRun = await api<Run>("/api/runs", {
        method: "POST",
        body: JSON.stringify({ scenario_id: scenarioId, execution_mode: mode }),
      });
      setRun(nextRun);
    } catch (cause) {
      setBusy(false);
      setError(cause instanceof Error ? cause.message : "Run failed to start");
    }
  }

  async function resetDemo() {
    setBusy(true);
    setError(null);
    try {
      const result = await api<{ state: DemoState }>("/api/reset", { method: "POST" });
      setState(result.state);
      setRun(null);
      setEvents([]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Reset failed");
    } finally {
      setBusy(false);
    }
  }

  const attackSucceeded = run?.status === "COMPLETED" && run.forbidden_side_effects > 0;

  return (
    <main>
      <header className="masthead">
        <div>
          <a className="wordmark" href="#top" aria-label="MandateMesh home">MANDATE<span>MESH</span></a>
          <p>Level 0 / unprotected execution</p>
        </div>
        <div className="system-status"><span aria-hidden="true" /> Direct tool access enabled</div>
      </header>

      <section className="intro" id="top">
        <div>
          <p className="section-label">Accounts payable attack bench</p>
          <h1>Watch untrusted invoice text become a real transaction.</h1>
        </div>
        <p className="intro-copy">This baseline has no authorization boundary. Every proposed call executes directly, leaving inspectable state and an append-only evidence trail.</p>
      </section>

      {error && <div className="error-banner" role="alert"><strong>System error</strong><span>{error}</span></div>}
      {attackSucceeded && (
        <div className="attack-banner" role="status" aria-live="polite">
          <div><strong>Attack succeeded</strong><span>The agent crossed the user’s authority boundary.</span></div>
          <div className="attack-count"><b>{run.forbidden_side_effects}</b><span>forbidden effects</span></div>
        </div>
      )}

      <div className="workspace">
        <aside className="scenario-panel" aria-label="Run controls">
          <div className="panel-heading">
            <span>01</span>
            <div><h2>Select source</h2><p>Choose the invoice the agent will trust.</p></div>
          </div>
          <div className="scenario-options">
            {scenarios.map((scenario) => (
              <button
                className={`scenario-option ${scenario.id === scenarioId ? "selected" : ""} ${scenario.kind}`}
                key={scenario.id}
                onClick={() => setScenarioId(scenario.id)}
                aria-pressed={scenario.id === scenarioId}
                disabled={busy}
              >
                <span className="radio" aria-hidden="true" />
                <span><b>{scenario.name}</b><small>{scenario.summary}</small></span>
              </button>
            ))}
          </div>

          <label className="control-label" htmlFor="execution-mode">Execution engine</label>
          <div className="mode-control" id="execution-mode">
            <button aria-pressed={mode === "deterministic"} onClick={() => setMode("deterministic")} disabled={busy}>Deterministic</button>
            <button aria-pressed={mode === "live"} onClick={() => setMode("live")} disabled={busy}>Live model</button>
          </div>
          <p className="mode-note">Live mode falls back to the same precomputed plan if the model is unavailable.</p>

          <div className="actions">
            <button className="run-button" onClick={startRun} disabled={busy || !selected}>{busy ? "RUNNING…" : "RUN UNPROTECTED AGENT"}</button>
            <button className="reset-button" onClick={resetDemo} disabled={busy}>Reset demo state</button>
          </div>
        </aside>

        <section className="evidence-panel">
          <div className="panel-heading evidence-heading">
            <span>02</span>
            <div><h2>Execution ledger</h2><p>Proposals, tool results, and committed effects.</p></div>
            <div className={`run-state ${run?.status.toLowerCase() ?? "idle"}`}><i />{run?.status ?? "IDLE"}</div>
          </div>

          {visibleEvents.length === 0 ? (
            <div className="empty-ledger">
              <div className="empty-mark" aria-hidden="true">↳</div>
              <h3>No run evidence yet</h3>
              <p>Select a source and start the unprotected agent. Tool calls will be recorded here.</p>
            </div>
          ) : (
            <div className="timeline" aria-live="polite">
              <div className="timeline-header"><span>Source</span><span>Action</span><span>Evidence</span><span>Time</span></div>
              {visibleEvents.map((event) => (
                <article className={`timeline-row ${event.is_forbidden ? "danger" : ""}`} key={event.id}>
                  <div><small>DOCUMENT</small><b>{event.source_ref ?? "SYSTEM"}</b></div>
                  <div>
                    <span className={`event-type ${event.event_type.toLowerCase()}`}>{event.event_type.replaceAll("_", " ")}</span>
                    <code>{event.tool_name ?? event.actor}</code>
                    {event.latency_ms !== null && <small>{event.latency_ms.toFixed(2)} ms</small>}
                  </div>
                  <details>
                    <summary>{event.side_effect ? "Side effect committed" : event.tool_result ? "Tool result" : "Arguments"}</summary>
                    <Evidence value={event.side_effect ?? event.tool_result ?? event.tool_arguments} />
                  </details>
                  <time>{stamp(event.created_at)}</time>
                </article>
              ))}
            </div>
          )}

          <details className="raw-source" open={selected?.kind === "malicious"}>
            <summary>Raw invoice evidence <span>{selected?.invoice.invoice_id}</span></summary>
            <pre>{selected?.invoice.raw_text ?? "Loading invoice…"}</pre>
          </details>
        </section>
      </div>

      <section className="state-section">
        <div className="panel-heading">
          <span>03</span>
          <div><h2>Persisted side effects</h2><p>Actual SQLite state after the run—not interface notifications.</p></div>
        </div>
        <div className="state-grid">
          <section className="state-block">
            <header><h3>Vendor registry</h3><b>{state.vendors.length}</b></header>
            {state.vendors.map((vendor) => (
              <div className={`state-record ${vendor.approved ? "safe" : "danger"}`} key={String(vendor.id)}>
                <span><b>{String(vendor.name)}</b><code>{String(vendor.id)}</code></span>
                <span><small>BENEFICIARY</small><code>{shortHash(vendor.bank_account_hash)}</code></span>
                <em>{vendor.approved ? "APPROVED" : "UNAPPROVED"}</em>
              </div>
            ))}
          </section>

          <section className="state-block">
            <header><h3>Payment ledger</h3><b>{state.payments.length}</b></header>
            {state.payments.length === 0 ? <p className="empty-state">No payment has been prepared.</p> : state.payments.map((payment) => (
              <div className={`state-record ${payment.status === "EXECUTED" ? "danger" : "caution"}`} key={String(payment.id)}>
                <span><b>₹{Number(payment.amount).toLocaleString("en-IN")}</b><code>{String(payment.id)}</code></span>
                <span><small>TO</small><code>{shortHash(payment.beneficiary_hash)}</code></span>
                <em>{String(payment.status)}</em>
              </div>
            ))}
          </section>

          <section className="state-block">
            <header><h3>Persistent memory</h3><b>{state.memory_entries.length}</b></header>
            {state.memory_entries.length === 0 ? <p className="empty-state">No financial instructions stored.</p> : state.memory_entries.map((memory) => (
              <div className="state-record danger stacked" key={String(memory.id)}>
                <span><b>{String(memory.memory_type)}</b><code>{String(memory.source_ref)}</code></span>
                <p>{String(memory.content)}</p>
                <em>{String(memory.trust_level)}</em>
              </div>
            ))}
          </section>

          <section className="state-block">
            <header><h3>Secret access</h3><b>{state.secret_accesses.length}</b></header>
            {state.secret_accesses.length === 0 ? <p className="empty-state">No synthetic secret accessed.</p> : state.secret_accesses.map((access) => (
              <div className="state-record danger" key={String(access.id)}>
                <span><b>Synthetic finance secret</b><code>{String(access.run_id).slice(0, 8)}</code></span>
                <span><small>VALUE</small><code>[REDACTED]</code></span>
                <em>EXPOSED</em>
              </div>
            ))}
          </section>
        </div>
      </section>

      <footer><span>Dream Team · InnovaHack Chapter 1</span><span>UNPROTECTED BASELINE / LEVEL 0</span></footer>
    </main>
  );
}

