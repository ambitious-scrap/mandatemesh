"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const DEFAULT_TASK =
  "Prepare payments for approved supplier invoices. Each payment must be below ₹50,000, " +
  "total committed spend must not exceed ₹80,000, and execution requires my approval. " +
  "Do not create vendors, change banking details, read secrets, or store new financial instructions in memory.";

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
  protection_mode?: "UNPROTECTED" | "PROTECTED";
  mandate_id?: string | null;
  requested_mode: string;
  execution_mode: string;
  status: "RUNNING" | "AWAITING_APPROVAL" | "COMPLETED" | "FAILED";
  forbidden_proposals: number;
  forbidden_side_effects: number;
  blocked_actions?: number;
  error: string | null;
};

type Decision = {
  decision: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
  reason_code: string;
  message?: string;
  policy_version?: string | null;
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
  canonical_action?: { canonical_action?: string; resource?: Record<string, unknown> } | null;
  decision?: Decision | null;
  policy_version?: string | null;
  is_forbidden: number;
  latency_ms: number | null;
};

type Contract = {
  purpose?: string;
  task?: string;
  allowed_actions: string[];
  forbidden_actions: string[];
  approved_counterparties: Array<{ vendor_id: string; beneficiary_hash: string; name?: string }>;
  currency: string;
  max_single_payment: number;
  max_total_payment: number;
  execution_mode: string;
  requires_approval: boolean;
  expires_at?: string | null;
};

type Mandate = {
  id: string;
  status: string;
  signature: string | null;
  public_key: string | null;
  contract: Contract;
  warnings?: string[];
  ambiguous_fields?: string[];
  confirmed_at?: string | null;
  nonce?: string;
  expires_at?: string | null;
};

type Verification = {
  valid: boolean;
  signature_valid: boolean;
  mandate_status: string;
  expired: boolean;
  reason_code: string | null;
  now: string;
};

type ApprovalPayload = {
  payment_id?: string;
  vendor_id?: string;
  amount?: number;
  currency?: string;
  beneficiary_fingerprint?: string;
  invoice_id?: string;
  remaining_budget?: number;
  source_trust?: string;
  irreversible?: boolean;
  canonical_action?: string;
  action_hash?: string;
};

type ApprovalRequest = {
  id: string;
  status: string;
  created_at: string;
  expires_at?: string;
  action_hash?: string;
  payload: ApprovalPayload;
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

function rupees(value: unknown) {
  return `₹${Number(value ?? 0).toLocaleString("en-IN")}`;
}

function Evidence({ value }: { value: unknown }) {
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

function StateGrid({ state, executedTone }: { state: DemoState; executedTone: "danger" | "safe" }) {
  return (
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
          <div className={`state-record ${payment.status === "EXECUTED" ? executedTone : "caution"}`} key={String(payment.id)}>
            <span><b>{rupees(payment.amount)}</b><code>{String(payment.id)}</code></span>
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
  );
}

/* ------------------------------------------------------------------ */
/* Level 0 — unprotected baseline (behaviour unchanged)               */
/* ------------------------------------------------------------------ */
function UnprotectedView() {
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
    <>
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
        <StateGrid state={state} executedTone="danger" />
      </section>

      <footer><span>Dream Team · InnovaHack Chapter 1</span><span>UNPROTECTED BASELINE / LEVEL 0</span></footer>
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Level 1 — protected enforcement loop                               */
/* ------------------------------------------------------------------ */
function decisionClass(decision?: Decision | null) {
  if (!decision) return "";
  if (decision.decision === "ALLOW") return "allow";
  if (decision.decision === "REQUIRE_APPROVAL") return "approval";
  return "block";
}

function rowTone(decision?: Decision | null) {
  if (!decision) return "";
  if (decision.decision === "BLOCK") return "danger";
  if (decision.decision === "REQUIRE_APPROVAL") return "caution";
  return "";
}

function ProtectedView() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenarioId, setScenarioId] = useState("malicious-invoice");
  const [task, setTask] = useState(DEFAULT_TASK);
  const [mandate, setMandate] = useState<Mandate | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [single, setSingle] = useState(50000);
  const [total, setTotal] = useState(80000);
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<ToolEvent[]>([]);
  const [pending, setPending] = useState<ApprovalRequest[]>([]);
  const [state, setState] = useState<DemoState>(emptyState);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected = useMemo(() => scenarios.find((scenario) => scenario.id === scenarioId), [scenarios, scenarioId]);
  const decisionEvents = events.filter((event) => event.event_type === "POLICY_DECIDED");
  const isActive = mandate?.status === "ACTIVE" && verification?.valid === true;

  const refresh = useCallback(async () => {
    const [nextState, nextPending] = await Promise.all([
      api<DemoState>("/api/state"),
      api<ApprovalRequest[]>("/api/approvals/pending"),
    ]);
    setState(nextState);
    setPending(nextPending);
  }, []);

  useEffect(() => {
    Promise.all([api<Scenario[]>("/api/scenarios"), api<DemoState>("/api/state"), api<ApprovalRequest[]>("/api/approvals/pending")])
      .then(([nextScenarios, nextState, nextPending]) => {
        setScenarios(nextScenarios);
        setState(nextState);
        setPending(nextPending);
      })
      .catch((cause) => setError(cause.message));
  }, []);

  useEffect(() => {
    if (!run || (run.status !== "RUNNING" && run.status !== "AWAITING_APPROVAL")) return;
    const timer = window.setInterval(async () => {
      try {
        const [nextRun, nextEvents] = await Promise.all([
          api<Run>(`/api/runs/${run.id}`),
          api<ToolEvent[]>(`/api/runs/${run.id}/events`),
        ]);
        setRun(nextRun);
        setEvents(nextEvents);
        await refresh();
        // Release the busy lock once the run leaves RUNNING so the approval
        // controls become interactive while the run is paused for a decision.
        if (nextRun.status !== "RUNNING") setBusy(false);
        if (nextRun.status === "COMPLETED" || nextRun.status === "FAILED") {
          window.clearInterval(timer);
        }
      } catch (cause) {
        window.clearInterval(timer);
        setBusy(false);
        setError(cause instanceof Error ? cause.message : "Run status failed");
      }
    }, 350);
    return () => window.clearInterval(timer);
  }, [run, refresh]);

  async function compile() {
    setBusy(true);
    setError(null);
    setVerification(null);
    setRun(null);
    setEvents([]);
    try {
      const next = await api<Mandate>("/api/mandates/compile", { method: "POST", body: JSON.stringify({ task }) });
      setMandate(next);
      setSingle(next.contract.max_single_payment);
      setTotal(next.contract.max_total_payment);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Mandate compilation failed");
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    if (!mandate) return;
    setBusy(true);
    setError(null);
    try {
      const next = await api<Mandate>(`/api/mandates/${mandate.id}/confirm`, {
        method: "POST",
        body: JSON.stringify({ edits: { max_single_payment: single, max_total_payment: total } }),
      });
      setMandate(next);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Confirmation failed");
    } finally {
      setBusy(false);
    }
  }

  async function sign() {
    if (!mandate) return;
    setBusy(true);
    setError(null);
    try {
      const next = await api<Mandate>(`/api/mandates/${mandate.id}/sign`, { method: "POST" });
      setMandate(next);
      setVerification(await api<Verification>(`/api/mandates/${mandate.id}/verify`, { method: "POST" }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Signing failed");
    } finally {
      setBusy(false);
    }
  }

  async function startRun() {
    if (!mandate) return;
    setBusy(true);
    setError(null);
    setEvents([]);
    try {
      const nextRun = await api<Run>("/api/runs", {
        method: "POST",
        body: JSON.stringify({
          scenario_id: scenarioId,
          execution_mode: "deterministic",
          protection_mode: "PROTECTED",
          mandate_id: mandate.id,
        }),
      });
      setRun(nextRun);
    } catch (cause) {
      setBusy(false);
      setError(cause instanceof Error ? cause.message : "Protected run failed to start");
    }
  }

  async function decideApproval(id: string, action: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      await api(`/api/approvals/${id}/${action}`, { method: "POST" });
      if (run) {
        const [nextRun, nextEvents] = await Promise.all([
          api<Run>(`/api/runs/${run.id}`),
          api<ToolEvent[]>(`/api/runs/${run.id}/events`),
        ]);
        setRun(nextRun);
        setEvents(nextEvents);
      }
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Approval decision failed");
    } finally {
      setBusy(false);
    }
  }

  async function resetDemo() {
    setBusy(true);
    setError(null);
    try {
      const result = await api<{ state: DemoState }>("/api/reset", { method: "POST" });
      setState(result.state);
      setMandate(null);
      setVerification(null);
      setRun(null);
      setEvents([]);
      setPending([]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Reset failed");
    } finally {
      setBusy(false);
    }
  }

  const executed = state.payments.filter((payment) => payment.status === "EXECUTED");
  const runFinished = run?.status === "COMPLETED";
  const runActive = run?.status === "RUNNING" || run?.status === "AWAITING_APPROVAL";

  return (
    <>
      <section className="intro" id="top">
        <div>
          <p className="section-label">Signed mandate · policy gateway · human approval</p>
          <h1>Bind a signed mandate. The gateway enforces every action.</h1>
        </div>
        <p className="intro-copy">The same untrusted invoice runs behind a trusted boundary: a human-confirmed, Ed25519-signed mandate; an OPA policy decision on every call; and an action-bound, one-time approval for the single legitimate payment.</p>
      </section>

      {error && <div className="error-banner" role="alert"><strong>System error</strong><span>{error}</span></div>}

      {/* 01 — Mandate lifecycle */}
      <div className="mandate-grid">
        <div className="mandate-controls">
          <div className="panel-heading">
            <span>01</span>
            <div><h2>Author the mandate</h2><p>Compile the human task into a typed, signed contract.</p></div>
          </div>

          <label className="control-label" htmlFor="task-input">Human task</label>
          <textarea
            id="task-input"
            className="task-input"
            value={task}
            onChange={(event) => setTask(event.target.value)}
            disabled={busy || mandate?.status === "ACTIVE"}
          />

          {mandate && mandate.status !== "ACTIVE" && (
            <div className="limit-edit">
              <div>
                <label htmlFor="single-limit">Per-payment limit</label>
                <input id="single-limit" type="number" value={single} onChange={(event) => setSingle(Number(event.target.value))} disabled={busy || !!mandate.confirmed_at} />
              </div>
              <div>
                <label htmlFor="total-limit">Total budget</label>
                <input id="total-limit" type="number" value={total} onChange={(event) => setTotal(Number(event.target.value))} disabled={busy || !!mandate.confirmed_at} />
              </div>
            </div>
          )}

          <div className="actions">
            {!mandate && <button className="run-button" onClick={compile} disabled={busy}>{busy ? "COMPILING…" : "COMPILE MANDATE"}</button>}
            {mandate && !mandate.confirmed_at && <button className="run-button" onClick={confirm} disabled={busy}>CONFIRM &amp; FREEZE CONTRACT</button>}
            {mandate?.confirmed_at && mandate.status !== "ACTIVE" && <button className="run-button" onClick={sign} disabled={busy}>SIGN MANDATE (ED25519)</button>}
            <button className="reset-button" onClick={resetDemo} disabled={busy}>Reset demo state</button>
          </div>
        </div>

        <div className="mandate-detail">
          {!mandate ? (
            <div className="empty-ledger">
              <div className="empty-mark" aria-hidden="true">§</div>
              <h3>No mandate yet</h3>
              <p>Compile the human task to see the proposed authorization contract before you sign it.</p>
            </div>
          ) : (
            <div className="contract-card">
              <div className="contract-head">
                <b>AUTHORIZATION CONTRACT</b>
                <span className="status-tag">{mandate.status}</span>
              </div>
              <div className="contract-metrics">
                <div className="contract-metric"><small>Per-payment limit</small><b>{rupees(mandate.contract.max_single_payment)}</b></div>
                <div className="contract-metric"><small>Total budget</small><b>{rupees(mandate.contract.max_total_payment)}</b></div>
                <div className="contract-metric"><small>Currency</small><b>{mandate.contract.currency}</b></div>
                <div className="contract-metric"><small>Approval</small><b>{mandate.contract.requires_approval ? "REQUIRED" : "NOT REQUIRED"}</b></div>
              </div>
              <div className="action-cols">
                <div>
                  <h4>Allowed actions</h4>
                  {mandate.contract.allowed_actions.map((action) => <code className="action-chip allow" key={action}>{action}</code>)}
                </div>
                <div>
                  <h4>Forbidden actions</h4>
                  {mandate.contract.forbidden_actions.map((action) => <code className="action-chip forbid" key={action}>{action}</code>)}
                </div>
              </div>

              {mandate.warnings && mandate.warnings.length > 0 && (
                <p className="warning-note"><strong>Review required:</strong> {mandate.warnings.join(" ")}</p>
              )}

              {mandate.status === "ACTIVE" && (
                <div className="mandate-proof">
                  <div className="proof-row">
                    <small>Verification</small>
                    <span className={`verify-badge ${verification?.valid ? "valid" : "invalid"}`}>
                      {verification?.valid ? "✓ SIGNATURE VALID" : `✗ ${verification?.reason_code ?? "INVALID"}`}
                    </span>
                  </div>
                  <div className="proof-row"><small>Public key</small><code>{shortHash(mandate.public_key)}</code></div>
                  <div className="proof-row"><small>Signature</small><code>{shortHash(mandate.signature)}</code></div>
                  <div className="proof-row"><small>Nonce</small><code>{shortHash(mandate.nonce)}</code></div>
                  {(mandate.contract.expires_at ?? mandate.expires_at) && (
                    <div className="proof-row"><small>Expires</small><code>{stamp(String(mandate.contract.expires_at ?? mandate.expires_at))}</code></div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* 02 — Live protected execution */}
      <div className="workspace" style={{ marginTop: 18 }}>
        <aside className="scenario-panel" aria-label="Protected run controls">
          <div className="panel-heading">
            <span>02</span>
            <div><h2>Run under the gateway</h2><p>Every call is normalized and sent to OPA before it can execute.</p></div>
          </div>
          <div className="scenario-options">
            {scenarios.map((scenario) => (
              <button
                className={`scenario-option ${scenario.id === scenarioId ? "selected" : ""} ${scenario.kind}`}
                key={scenario.id}
                onClick={() => setScenarioId(scenario.id)}
                aria-pressed={scenario.id === scenarioId}
                disabled={busy || runActive || !isActive}
              >
                <span className="radio" aria-hidden="true" />
                <span><b>{scenario.name}</b><small>{scenario.summary}</small></span>
              </button>
            ))}
          </div>
          <div className="actions">
            <button className="run-button" onClick={startRun} disabled={busy || runActive || !isActive || !selected}>
              {busy || runActive ? "RUNNING…" : isActive ? "RUN PROTECTED AGENT" : "SIGN A MANDATE FIRST"}
            </button>
          </div>
          <p className="mode-note">A signed, active mandate is required. Blocked actions leave no side effect; the legitimate payment pauses for your approval.</p>
        </aside>

        <section className="evidence-panel">
          <div className="panel-heading evidence-heading">
            <span>03</span>
            <div><h2>Gateway decisions</h2><p>One deterministic policy decision per proposed action.</p></div>
            <div className={`run-state ${run?.status.toLowerCase() ?? "idle"}`}><i />{run?.status?.replaceAll("_", " ") ?? "IDLE"}</div>
          </div>

          {decisionEvents.length === 0 ? (
            <div className="empty-ledger">
              <div className="empty-mark" aria-hidden="true">↳</div>
              <h3>No gateway decisions yet</h3>
              <p>Run the protected agent to see each action allowed, blocked, or held for approval.</p>
            </div>
          ) : (
            <div className="timeline" aria-live="polite">
              <div className="timeline-header"><span>Source</span><span>Action</span><span>Decision</span><span>Time</span></div>
              {decisionEvents.map((event) => (
                <article className={`timeline-row ${rowTone(event.decision)}`} key={event.id}>
                  <div><small>DOCUMENT</small><b>{event.source_ref ?? "SYSTEM"}</b></div>
                  <div>
                    <code>{event.tool_name}</code>
                    <small>{event.canonical_action?.canonical_action}</small>
                  </div>
                  <div>
                    <span className={`decision-badge ${decisionClass(event.decision)}`}>{event.decision?.decision.replaceAll("_", " ")}</span>
                    <span className="reason-code">{event.decision?.reason_code}</span>
                    <details>
                      <summary>Policy input</summary>
                      <Evidence value={event.canonical_action} />
                    </details>
                  </div>
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

      {/* 03 — Human approval */}
      {pending.length > 0 && (
        <section style={{ marginTop: 18 }}>
          <div className="panel-heading" style={{ marginBottom: 14 }}>
            <span>04</span>
            <div><h2>Approval required</h2><p>The gateway is holding one action-bound payment for your decision.</p></div>
          </div>
          {pending.map((request) => (
            <div className="approval-callout" key={request.id}>
              <div className="approval-head">
                <strong>Authorize payment</strong>
                <span>{request.payload.irreversible ? "IRREVERSIBLE · ONE-TIME TOKEN" : "ONE-TIME TOKEN"}</span>
              </div>
              <div className="approval-grid">
                <div className="approval-cell"><small>Amount</small><b>{rupees(request.payload.amount)}</b></div>
                <div className="approval-cell"><small>Vendor</small><b>{request.payload.vendor_id}</b></div>
                <div className="approval-cell"><small>Beneficiary</small><code>{request.payload.beneficiary_fingerprint ?? "—"}</code></div>
                <div className="approval-cell"><small>Invoice</small><b>{request.payload.invoice_id}</b></div>
                <div className="approval-cell"><small>Remaining budget</small><b>{rupees(request.payload.remaining_budget)}</b></div>
                <div className="approval-cell"><small>Source trust</small><b>{request.payload.source_trust}</b></div>
                <div className="approval-cell"><small>Action hash</small><code>{shortHash(request.action_hash ?? request.payload.action_hash)}</code></div>
                {request.expires_at && <div className="approval-cell"><small>Token expires</small><code>{stamp(request.expires_at)}</code></div>}
              </div>
              <div className="approval-actions">
                <button className="approve-btn" onClick={() => decideApproval(request.id, "approve")} disabled={busy}>Approve &amp; execute once</button>
                <button className="reject-btn" onClick={() => decideApproval(request.id, "reject")} disabled={busy}>Reject</button>
              </div>
            </div>
          ))}
        </section>
      )}

      {/* Enforcement summary once the run settles */}
      {runFinished && (
        <div className="enforcement-summary" style={{ marginTop: 18 }}>
          <div className="summary-metric good"><small>Actions blocked</small><b>{run?.blocked_actions ?? 0}</b></div>
          <div className="summary-metric good"><small>Payments executed</small><b>{executed.length}</b></div>
          <div className="summary-metric good"><small>Forbidden side effects</small><b>{run?.forbidden_side_effects ?? 0}</b></div>
          <div className="summary-metric"><small>Policy decisions</small><b>{decisionEvents.length}</b></div>
        </div>
      )}

      {/* Persisted evidence */}
      <section className="state-section">
        <div className="panel-heading">
          <span>05</span>
          <div><h2>Persisted state</h2><p>Actual SQLite state after enforcement—no forbidden effect should appear.</p></div>
        </div>
        <StateGrid state={state} executedTone="safe" />
      </section>

      <footer><span>Dream Team · InnovaHack Chapter 1</span><span>PROTECTED ENFORCEMENT / LEVEL 1</span></footer>
    </>
  );
}

export default function Home() {
  const [boundary, setBoundary] = useState<"protected" | "unprotected">("protected");

  return (
    <main>
      <header className="masthead">
        <div>
          <a className="wordmark" href="#top" aria-label="MandateMesh home">MANDATE<span>MESH</span></a>
          <p>{boundary === "protected" ? "Level 1 / protected enforcement" : "Level 0 / unprotected execution"}</p>
        </div>
        <div className="mode-switch" role="group" aria-label="Execution boundary">
          <button aria-pressed={boundary === "unprotected"} onClick={() => setBoundary("unprotected")}>Unprotected</button>
          <button aria-pressed={boundary === "protected"} onClick={() => setBoundary("protected")}>Protected</button>
        </div>
        <div className={`system-status ${boundary === "protected" ? "protected" : ""}`}>
          <span aria-hidden="true" /> {boundary === "protected" ? "Gateway enforcement active" : "Direct tool access enabled"}
        </div>
      </header>

      {boundary === "protected" ? <ProtectedView /> : <UnprotectedView />}
    </main>
  );
}
