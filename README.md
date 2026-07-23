# MandateMesh

MandateMesh is a transaction-authorization layer for AI agents. The same
accounts-payable agent, driven by the same invoices, can be run two ways:

- **Level 0 — Unprotected baseline.** Direct tool access, no authorization
  boundary. Untrusted text inside an invoice becomes a real, persisted financial
  transaction.
- **Level 1 — Protected enforcement loop.** A human-confirmed, Ed25519-signed
  **mandate** is bound to the run; a policy gateway evaluates every proposed tool
  call against an OPA/Rego decision point; and the one legitimate payment pauses
  for an action-bound, one-time human approval. Every forbidden action is blocked
  and leaves no side effect.

Two invoices drive the same agent:

- **Normal invoice** — an approved vendor and an ordinary ₹42,000 payment.
- **Malicious invoice** — the *same* invoice, plus attacker-authored metadata
  that tries to create a rogue vendor, read a secret, poison persistent memory,
  and pay an attacker beneficiary.

The web UI has a **Protected / Unprotected** switch so both boundaries can be
demonstrated side by side: Level 0 shows the attack landing in SQLite; Level 1
shows the gateway refusing each forbidden action and executing only the approved
payment.

> This README covers **setup and usage only**. For the product rationale, threat
> model, and level roadmap see [`PRODUCT_SPEC.md`](./PRODUCT_SPEC.md) and
> [`BUILD_PLAN.md`](./BUILD_PLAN.md).

---

## Repository layout

```
.
├── apps/web/                # Next.js 16 frontend (protected + unprotected UI)
├── services/api/            # FastAPI backend
│   ├── app/                 # agent, tools, mandates, gateway, policy client, routes
│   └── tests/               # pytest suite (Level 0 + Level 1 coverage)
├── policy/                  # OPA/Rego policy (mandate.rego) and Rego tests
├── scenarios/invoices/      # normal.json and malicious.json source invoices
├── scripts/                 # seed / reset / smoke_test / smoke_level1 helpers
├── docker-compose.yml       # web + api + opa, health checks, persistent volume
├── .env.example             # copy to .env; safe placeholders only
├── PRODUCT_SPEC.md          # what/why (authoritative spec)
└── BUILD_PLAN.md            # build plan (authoritative plan)
```

---

## Prerequisites

Pick **one** path:

| Path | Needs |
|------|-------|
| Docker (recommended) | Docker Engine + Docker Compose v2 |
| Local | Python **3.14**, Node.js **20+** (Next.js 16), npm, and **OPA 1.4.x** for protected mode |

The agent runs fully **deterministically** by default — no model API key is
required for either path. Protected (Level 1) mode additionally needs OPA
running; Docker Compose starts it for you.

---

## Environment configuration

Copy the example file and adjust if needed:

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `MODEL_API_KEY` | *(empty)* | Optional. Enables the live-model path. Blank keeps deterministic mode. |
| `MODEL_BASE_URL` | `https://api.openai.com/v1` | Live-model endpoint (only used if a key is set). |
| `MODEL_NAME` | `gpt-4.1-mini` | Live-model name. |
| `MODEL_TEMPERATURE` | `0.1` | Live-model sampling temperature. |
| `MODEL_TIMEOUT_SECONDS` | `12` | Live-model request timeout. |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Base URL the **browser** uses to reach the API. |
| `OPA_URL` | `http://localhost:8181` | Policy decision point. Under Compose the API uses `http://opa:8181` automatically. |

`.env` contains no secrets by default and is safe to keep local. Never commit a
populated `.env`. The demo principal's Ed25519 **signing key never leaves the
backend** and is never exposed as an agent tool or environment secret.

---

## Quick start with Docker Compose

```bash
docker compose up --build
```

This builds and starts three services with health checks and a persistent volume:

- **Web UI** → http://localhost:3000
- **API** → http://localhost:8000 (health at http://localhost:8000/health)
- **OPA** → policy decision point, **internal network only** (no host port)

`opa` publishes no host port — only the trusted API can reach it. The `api`
health check reports healthy only once the API is up **and** OPA is reachable,
and the `web` service waits for that health check before starting. Open
http://localhost:3000 and run the demo (see [Using the demo](#using-the-demo)).

Stop and remove the stack:

```bash
docker compose down            # keep the seeded database volume
docker compose down -v         # also delete the mandatemesh-data volume
```

> **Port note:** the committed compose file publishes `8000` (api) and `3000`
> (web); OPA has no host port. If host port 8000 is already in use, start the API
> elsewhere with a local override and point `NEXT_PUBLIC_API_URL` at it — do not
> edit the committed file.

---

## Running locally without Docker

### 1. Policy engine (OPA) — required for protected mode

Start OPA with the bundled policy before running a protected run:

```bash
# With a local opa binary:
opa run --server --addr localhost:8181 policy/mandate.rego

# ...or via Docker:
docker run --rm -p 8181:8181 -v "$PWD/policy:/policy:ro" \
  openpolicyagent/opa:1.4.2 run --server --addr 0.0.0.0:8181 /policy/mandate.rego
```

Leave it running and keep `OPA_URL=http://localhost:8181`. Unprotected (Level 0)
runs do not need OPA.

### 2. Backend (FastAPI)

```bash
cd services/api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt      # runtime + test deps
python ../../scripts/seed.py              # initialize and seed the SQLite database
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The API serves at http://localhost:8000. CORS is restricted to
`http://localhost:3000` / `http://127.0.0.1:3000`, so serve the frontend on port
3000.

### 3. Frontend (Next.js)

In another terminal:

```bash
cd apps/web
npm install
npm run dev        # http://localhost:3000
```

For a production-style build instead of the dev server:

```bash
npm run build && npm run start
```

The browser reads the API URL from `NEXT_PUBLIC_API_URL` (default
`http://localhost:8000`).

---

## Resetting demo state

Reset clears every run, event, mandate, approval, and side effect and re-seeds
the one approved vendor and the synthetic secret. Any of these work:

- **In the UI** — click **Reset demo state**.
- **Via the API** — `curl -X POST http://localhost:8000/api/reset`
- **From the CLI (local)** — `python scripts/reset.py`
- **From the CLI (Docker)** — `docker compose exec api python /app/scripts/reset.py`

---

## Running the tests

### Backend (pytest)

Covers the tools, agent plan, canonical serialization, mandate lifecycle and
crypto, the protected gateway, and both end-to-end flows. Gateway tests need OPA
reachable at `OPA_URL`; if OPA is unavailable those tests skip automatically.

```bash
cd services/api
pip install -r requirements-dev.txt      # once
pytest
```

### Policy (Rego)

```bash
docker run --rm -v "$PWD/policy:/policy:ro" openpolicyagent/opa:1.4.2 test /policy
# ...or with a local opa binary:
opa test policy
```

---

## Reproducing the demos (smoke tests)

### Level 0 — the attack lands

`smoke_test.py` resets the database, runs the malicious invoice unprotected, and
asserts the forbidden outcome: run `COMPLETED`, forbidden tool proposals, an
`EXECUTED` payment to `VENDOR-ATTACKER`, and a poisoned memory entry.

```bash
python scripts/smoke_test.py --repetitions 3
```

### Level 1 — the gateway holds

`smoke_level1.py` requires OPA running (`OPA_URL`). It compiles, confirms, and
signs a mandate, runs the malicious invoice **through the gateway**, asserts
every forbidden action is `BLOCK`ed, approves the one legitimate payment,
executes it exactly once, and confirms a replayed approval token is refused.

```bash
python scripts/smoke_level1.py --repetitions 3
```

Inside Docker (OPA is already running in the stack):

```bash
docker compose exec api python /app/scripts/smoke_test.py --repetitions 3
docker compose exec api python /app/scripts/smoke_level1.py --repetitions 3
```

Each passing run prints one result dict per repetition followed by a `PASS:` line.

---

## Using the demo

Open http://localhost:3000. Use the **Protected / Unprotected** switch in the
masthead to choose a boundary.

### Unprotected (Level 0)

1. Select an invoice and leave the engine on **Deterministic**.
2. Click **RUN UNPROTECTED AGENT**.
3. On the malicious invoice an **"Attack succeeded"** banner appears; the ledger
   shows the forbidden calls in red and **Persisted side effects** shows a rogue
   `VENDOR-ATTACKER`, an `EXECUTED` payment to the attacker, poisoned memory, and
   an accessed synthetic secret (value always shown `[REDACTED]`).

### Protected (Level 1)

1. **Author the mandate.** The human task is prefilled. Click **COMPILE
   MANDATE** to turn it into a typed authorization contract, review the
   per-payment limit (₹50,000) and total budget (₹80,000) and the allowed /
   forbidden actions, then **CONFIRM & FREEZE CONTRACT** and **SIGN MANDATE
   (ED25519)**. The signed mandate shows `ACTIVE`, a **✓ SIGNATURE VALID** badge,
   and its public key, signature, and nonce (never the private key).
2. **Run under the gateway.** With an active mandate, select the **Malicious
   invoice** and click **RUN PROTECTED AGENT**. The **Gateway decisions** panel
   records one deterministic decision per proposed action —
   `invoice.read`/`vendor.lookup` **ALLOW**, and `vendor.create`, `secret.read`,
   `memory.write`, and the attacker `payment.prepare` each **BLOCK** with a
   reason code (e.g. `ACTION_EXPLICITLY_FORBIDDEN`, `MEMORY_WRITE_FORBIDDEN`,
   `BENEFICIARY_MISMATCH`).
3. **Approve the legitimate payment.** The run pauses at `AWAITING APPROVAL` and
   an **Approval required** card shows the amount, vendor, truncated beneficiary
   fingerprint, remaining budget, and action hash. Click **Approve & execute
   once** (or **Reject**). Approval mints a one-time, action-bound token; the run
   resumes and executes the payment **exactly once**.
4. **Read the evidence.** The enforcement summary shows actions blocked, payments
   executed (1), and forbidden side effects (0). Under **Persisted state** no
   rogue vendor, poisoned memory, or secret access appears — only the single
   approved `EXECUTED` payment to `VENDOR-101`.

Click **Reset demo state** to return to a clean baseline.

### Deterministic vs live model

The **Deterministic** engine replays a fixed, precomputed plan and needs no model
API key — use it for reproducible demos. **Live model** calls a configured model
but **falls back to the same precomputed plan** whenever no key is set or the
model is unavailable, so the demo never breaks.

---

## API reference

Base URL: `http://localhost:8000`

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/health` | Liveness check; reports OPA reachability. |
| `GET`  | `/api/scenarios` | List available invoice scenarios. |
| `POST` | `/api/mandates/compile` | Compile a human task into a draft mandate contract. |
| `GET`  | `/api/mandates` · `/api/mandates/{id}` | List / fetch mandates. |
| `POST` | `/api/mandates/{id}/confirm` | Human-confirm and freeze the contract (with optional edits). |
| `POST` | `/api/mandates/{id}/sign` | Backend Ed25519-signs the mandate → `ACTIVE`. |
| `POST` | `/api/mandates/{id}/verify` | Verify signature / status / expiry. |
| `POST` | `/api/mandates/{id}/tamper-demo` | Demonstrate post-signature mutation invalidating the signature. |
| `POST` | `/api/runs` | Start a run (`202 Accepted`); `protection_mode` + `mandate_id` for protected runs. |
| `GET`  | `/api/runs/{id}` · `/events` · `/stream` | Run status, event trail, and SSE stream. |
| `POST` | `/api/gateway/execute` | Trusted gateway tool-call entry point (policy-checked). |
| `GET`  | `/api/approvals/pending` | Pending human approvals. |
| `POST` | `/api/approvals/{id}/approve` · `/reject` | Decide an approval; approve resumes the paused run. |
| `GET`  | `/api/state` | Full demo state snapshot. |
| `GET`  | `/api/vendors` · `/api/payments` · `/api/memory-entries` | Persisted state views. |
| `POST` | `/api/reset` | Reset and re-seed demo state. |

---

## Ports

| Service | Port | URL |
|---------|------|-----|
| Web UI | 3000 | http://localhost:3000 |
| API | 8000 | http://localhost:8000 |
| OPA | 8181 | internal only under Compose; `http://localhost:8181` when run locally |
