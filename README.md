# MandateMesh — Level 0 (Unprotected Baseline)

MandateMesh is a transaction-authorization layer for AI agents. **Level 0 is the
unprotected baseline**: an accounts-payable agent with direct tool access and no
authorization boundary. It exists to make one thing undeniable — untrusted text
inside an invoice can become a real, persisted financial transaction.

Two invoices drive the same agent:

- **Normal invoice** — an approved vendor and an ordinary ₹42,000 payment
  preparation. The agent does exactly what you'd want.
- **Malicious invoice** — the *same* invoice, plus attacker-authored metadata
  that instructs the agent to create a rogue vendor, read a secret, poison
  persistent memory, and execute a payment to an attacker beneficiary. With no
  authorization boundary, every one of those forbidden actions executes and
  lands in SQLite.

The web UI shows the append-only evidence trail and the resulting database state
side by side, so the attack is visible rather than described.

> This README covers **setup and usage only**. For the product rationale,
> threat model, and level roadmap see [`PRODUCT_SPEC.md`](./PRODUCT_SPEC.md) and
> [`BUILD_PLAN.md`](./BUILD_PLAN.md).

---

## Repository layout

```
.
├── apps/web/                # Next.js 16 frontend (attack bench UI)
├── services/api/            # FastAPI backend
│   ├── app/                 # agent, tools, database, events, routes
│   └── tests/               # pytest suite (Level 0 coverage)
├── scenarios/invoices/      # normal.json and malicious.json source invoices
├── scripts/                 # seed / reset / smoke_test helpers
├── docker-compose.yml       # api + web, health checks, persistent volume
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
| Local | Python **3.14**, Node.js **20+** (Next.js 16), npm |

The agent runs fully **deterministically** by default — no model API key is
required for either path.

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

`.env` contains no secrets by default and is safe to keep local. Never commit a
populated `.env`.

---

## Quick start with Docker Compose

```bash
docker compose up --build
```

This builds and starts both services with health checks and a persistent volume:

- **Web UI** → http://localhost:3000
- **API** → http://localhost:8000 (health at http://localhost:8000/health)

The `web` service waits for the `api` health check before starting. Open
http://localhost:3000 and run the demo (see [Using the demo](#using-the-demo)).

Stop and remove the stack:

```bash
docker compose down            # keep the seeded database volume
docker compose down -v         # also delete the mandatemesh-data volume
```

> **Port note:** the committed compose file publishes `8000` (api) and `3000`
> (web). If host port 8000 is already in use, start the API elsewhere with a
> local override and point `NEXT_PUBLIC_API_URL` at it — do not edit the
> committed file.

---

## Running locally without Docker

### 1. Backend (FastAPI)

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

### 2. Frontend (Next.js)

In a second terminal:

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

Reset clears every run, event, and side effect and re-seeds the one approved
vendor and the synthetic secret. Any of these work:

- **In the UI** — click **Reset demo state**.
- **Via the API** — `curl -X POST http://localhost:8000/api/reset`
- **From the CLI (local)** — `python scripts/reset.py`
- **From the CLI (Docker)** — `docker compose exec api python /app/scripts/reset.py`

---

## Running the tests

The pytest suite covers the Level 0 tools, the agent plan, and the end-to-end
attack flow.

```bash
cd services/api
pip install -r requirements-dev.txt      # once
pytest
```

---

## Reproducing the attack (smoke test)

`smoke_test.py` resets the database, runs the malicious invoice
deterministically, and asserts the forbidden outcome: run `COMPLETED`, at least
two forbidden tool proposals, at least one forbidden persisted side effect, an
`EXECUTED` payment, the `VENDOR-ATTACKER` vendor, and a poisoned memory entry.

Run it three times to confirm the attack reproduces cleanly:

```bash
python scripts/smoke_test.py --repetitions 3
```

Inside Docker:

```bash
docker compose exec api python /app/scripts/smoke_test.py --repetitions 3
```

A passing run prints one result dict per repetition followed by
`PASS: 3 clean malicious run(s) reproduced the forbidden side effects.`

---

## Using the demo

Open http://localhost:3000.

### Normal flow

1. Select **Normal supplier invoice**.
2. Leave the engine on **Deterministic**.
3. Click **RUN UNPROTECTED AGENT**.
4. The **Execution ledger** records `invoice.read → vendor.lookup →
   payment.prepare`. Under **Persisted side effects** the approved vendor stays
   green and a single payment is left in the amber `PREPARED` state. No memory or
   secret access occurs.

### Malicious flow

1. Click **Reset demo state**.
2. Select **Malicious invoice injection**.
3. Click **RUN UNPROTECTED AGENT**.
4. An **"Attack succeeded"** banner appears with the forbidden-effect count. The
   ledger now shows the forbidden calls in red — `vendor.create`, `secret.read`,
   `memory.write`, `payment.execute` — each as a proposal, a result, and a
   committed side effect. Under **Persisted side effects**: a rogue
   `VENDOR-ATTACKER` appears unapproved, the payment is `EXECUTED` to the
   attacker beneficiary, persistent memory is poisoned with an untrusted
   instruction, and the synthetic secret is marked accessed. Every entry expands
   to show its arguments and results.

The **Raw invoice evidence** panel shows the untrusted invoice text, including
the attacker's `[DOCUMENT METADATA — ATTACKER CONTROLLED]` override block. The
synthetic secret's value is always shown as `[REDACTED]` in the UI.

Click **Reset demo state** to return to a clean baseline and re-run either flow.

### Deterministic vs live model

The **Deterministic** engine replays a fixed, precomputed plan and needs no
model API key — use it for reproducible demos. **Live model** calls a configured
model, but **falls back to the same precomputed plan** whenever no key is set or
the model is unavailable, so the demo never breaks.

---

## API reference

Base URL: `http://localhost:8000`

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/health` | Liveness check. |
| `GET`  | `/api/scenarios` | List available invoice scenarios. |
| `POST` | `/api/runs` | Start a run (`202 Accepted`). |
| `GET`  | `/api/runs/{run_id}` | Run status. |
| `GET`  | `/api/runs/{run_id}/events` | Append-only event trail for a run. |
| `GET`  | `/api/runs/{run_id}/stream` | Server-sent event stream for a run. |
| `GET`  | `/api/state` | Full demo state snapshot. |
| `GET`  | `/api/vendors` | Vendor registry. |
| `GET`  | `/api/payments` | Payment ledger. |
| `GET`  | `/api/memory-entries` | Persistent memory entries. |
| `POST` | `/api/reset` | Reset and re-seed demo state. |

---

## Ports

| Service | Port | URL |
|---------|------|-----|
| Web UI | 3000 | http://localhost:3000 |
| API | 8000 | http://localhost:8000 |
