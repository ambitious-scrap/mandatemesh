# MandateMesh 30-Hour Build Plan

**Document:** `BUILD_PLAN.md`  
**Version:** 1.0  
**Team size:** 2 experienced engineers  
**Total build window:** 30 hours  
**Objective:** Deliver a stable, measurable, judge-ready MandateMesh MVP before adding advanced features

---

## 1. Operating Principle

Build in gated levels.

Do not proceed because a clock milestone arrived. Proceed only when the gate for the current level passes.

| Level | Outcome | Target |
|---|---|---:|
| Level 0 | Reproducible unprotected attack | H04 |
| Level 1 | Complete enforcement loop | H16 |
| Level 2 | Judge-proof security depth | H22 |
| Level 3 | One advanced differentiator | H26 |
| Level 4 | Reliability, deployment, rehearsal | H30 |

### Priority order

1. Reproducible baseline attack
2. Gateway interception
3. Typed confirmed mandate
4. Signature verification
5. Vendor and bank-account binding
6. Allow, block, approval
7. Stateful budget
8. Action-bound approval
9. Automated scenario corpus
10. Evidence timeline
11. Tamper and replay demos
12. Advanced differentiator
13. Visual polish

Never sacrifice items 1 through 9 to complete items 10 through 13.

---

## 2. Team Ownership

## Engineer A: Security Plane

Owns:

- FastAPI backend foundation
- Database models
- Mandate schema
- Canonical serialization
- Ed25519 signing and verification
- Gateway
- Canonical action mapping
- OPA/Rego policies
- Stateful budget
- Approval tokens
- Replay protection
- Policy and API tests
- Scenario evaluation runner

## Engineer B: Agent and Product Experience

Owns:

- Next.js application
- Agent tool-calling loop
- Invoice extraction
- Normal and malicious invoice fixtures
- Unprotected baseline
- Live event streaming
- Mandate review UI
- Approval UI
- Evidence timeline
- Evaluation results UI
- Demo reset flow
- Visual continuity with qualifier deck

## Shared responsibilities

- API contract
- Integration tests
- Demo script
- Failure recovery
- Deployment
- Rehearsal
- Final scope decisions

---

## 3. Repository Structure

```text
mandatemesh/
├── apps/
│   └── web/
│       ├── app/
│       ├── components/
│       ├── hooks/
│       ├── lib/
│       └── public/
├── services/
│   └── api/
│       ├── app/
│       │   ├── agent/
│       │   ├── approvals/
│       │   ├── database/
│       │   ├── evaluation/
│       │   ├── events/
│       │   ├── gateway/
│       │   ├── mandates/
│       │   ├── policy/
│       │   ├── scenarios/
│       │   └── tools/
│       ├── migrations/
│       └── tests/
├── policy/
│   ├── mandate.rego
│   ├── approval.rego
│   └── tests/
├── contracts/
│   ├── mandate.schema.json
│   ├── action.schema.json
│   └── decision.schema.json
├── scenarios/
│   ├── attacks/
│   ├── legitimate/
│   ├── invoices/
│   └── expected-results.json
├── scripts/
│   ├── seed.py
│   ├── reset.py
│   ├── run_evaluation.py
│   ├── smoke_test.py
│   └── demo_check.py
├── docker-compose.yml
├── PRODUCT_SPEC.md
├── BUILD_PLAN.md
└── README.md
```

---

## 4. Technical Decisions

| Area | Decision |
|---|---|
| Frontend | Next.js App Router, TypeScript |
| Backend | FastAPI, Python |
| Agent | Minimal custom tool-calling loop |
| Policy | OPA sidecar, Rego |
| Database | SQLite in WAL mode |
| Live updates | Server-Sent Events |
| Signing | Ed25519 |
| Hashing | SHA-256 |
| Deployment | Docker Compose |
| Tests | Pytest, OPA policy tests, Playwright smoke flow |
| Optional advanced adapter | MCP |

### Why a custom agent loop

Use the smallest reliable loop:

```text
model
  -> proposed tool call
  -> MandateMesh gateway
  -> tool result or denial
  -> model
```

Do not add:

- Multi-agent orchestration
- Planner/reviewer hierarchies
- Autonomous subagents
- Complex checkpointing
- Unnecessary framework abstractions

---

## 5. Branch and Integration Strategy

Recommended branches:

- `main`: always demoable
- `security-plane`: Engineer A
- `agent-ui`: Engineer B
- Short-lived feature branches only when needed

Integration cadence:

- Merge or rebase at H03, H07, H11, H15, H19, H22, H26
- Do not allow branches to diverge for more than four hours
- Resolve shared schema changes immediately
- Tag stable checkpoints

Recommended tags:

- `level-0-baseline`
- `level-1-core`
- `level-2-judge-proof`
- `demo-final`

---

# LEVEL 0: Reproducible Unprotected Attack

## H00 to H04

### Goal

Build the insecure system first and prove the threat.

### Engineer A tasks

- Create FastAPI service.
- Create SQLite models:
  - vendors
  - payments
  - memory_entries
  - tool_events
- Implement simulated tools:
  - `invoice.read`
  - `vendor.lookup`
  - `vendor.create`
  - `secret.read`
  - `payment.prepare`
  - `payment.execute`
  - `memory.write`
- Implement append-only event recording.
- Add seed and reset scripts.
- Add idempotency key field to side-effecting tools.

### Engineer B tasks

- Create Next.js project.
- Build minimal agent tool-calling loop.
- Create:
  - normal invoice fixture
  - malicious invoice fixture
- Build minimal run screen.
- Display raw proposed tool calls and tool results.
- Add `UNPROTECTED` mode.

### Shared integration

By H02:

- Agent can read an invoice.
- Agent can call at least one simulated tool.
- Tool events are persisted.

By H04:

- Malicious invoice causes at least two forbidden proposals.
- At least one forbidden side effect succeeds.
- State is inspectable in SQLite and UI.
- Reset produces a clean deterministic rerun.

### Level 0 gate

All must pass:

- [ ] Normal workflow works.
- [ ] Malicious workflow succeeds reproducibly.
- [ ] Same seeded scenario succeeds three consecutive times.
- [ ] Event stream contains source, action, arguments, and result.
- [ ] `scripts/reset.py` restores clean state.
- [ ] Tag `level-0-baseline` created.

### Stop condition

Do not add policy or signing until the attack is reproducible.

---

# LEVEL 1: Complete Enforcement Loop

## H04 to H16

## Phase 1A: Contract and signing

### H04 to H08

#### Engineer A

- Define Pydantic models:
  - Mandate
  - Counterparty
  - CanonicalAction
  - PolicyDecision
  - ApprovalRequest
- Implement canonical JSON serialization.
- Implement Ed25519 key generation for demo user.
- Implement mandate signing and verification.
- Add mandate status and expiry.
- Add nonce uniqueness.
- Create endpoints:
  - compile
  - confirm
  - sign
  - verify

#### Engineer B

- Build Task screen.
- Build mandate review screen.
- Show explicit fields:
  - allowed actions
  - forbidden actions
  - vendor
  - bank account fingerprint
  - amount limits
  - approval requirement
  - expiry
- Add edit and confirm interactions.
- Distinguish AI proposal from confirmed policy.
- Display signature status.

#### H08 checkpoint

- [ ] User can enter task.
- [ ] Typed mandate appears.
- [ ] User can edit and confirm.
- [ ] Mandate is signed.
- [ ] Tampering causes verification failure.
- [ ] Expired mandate fails verification.

---

## Phase 1B: Gateway and policy

### H08 to H12

#### Engineer A

- Start OPA sidecar.
- Define gateway request and response schema.
- Implement tool-to-canonical-action mapping.
- Implement initial Rego policies:
  - active mandate
  - valid signature
  - action allowlist
  - explicit denylist
  - approved vendor
  - beneficiary binding
  - single-payment amount
  - currency
- Implement fail-closed behavior.
- Record policy version and matched rules.
- Ensure protected tools are callable only through gateway.

#### Engineer B

- Add `PROTECTED` mode.
- Route agent tool calls through gateway.
- Build live event stream with SSE.
- Display:
  - source
  - raw tool call
  - canonical action
  - decision
  - reason code
- Add block and allow visual states.

#### H12 checkpoint

- [ ] `invoice.read` allowed.
- [ ] `vendor.lookup` allowed.
- [ ] `vendor.create` blocked.
- [ ] `secret.read` blocked.
- [ ] Beneficiary mismatch blocked.
- [ ] Blocked actions create no side effect.
- [ ] OPA unavailable causes consequential block.

---

## Phase 1C: Stateful spend and approval

### H12 to H16

#### Engineer A

- Implement payment reservation model.
- Enforce:
  - max single payment
  - max total mandate spend
- Implement approval request creation.
- Compute canonical action hash.
- Implement signed approval token.
- Bind token to exact transaction.
- Enforce token expiry and one-time use.
- Implement payment execution only after valid approval.

#### Engineer B

- Build independent approval screen.
- Do not use agent-generated approval copy.
- Display:
  - vendor
  - amount
  - beneficiary fingerprint
  - invoice
  - remaining budget
  - irreversibility
  - source trust
- Add approve and reject actions.
- Update live execution after approval.

#### Level 1 gate at H16

- [ ] Valid preparation returns `ALLOW`.
- [ ] Execution without approval returns `REQUIRE_APPROVAL`.
- [ ] Matching approval permits execution once.
- [ ] Changed amount invalidates approval.
- [ ] Changed beneficiary invalidates approval.
- [ ] Reused approval blocks.
- [ ] Cumulative spend is stateful.
- [ ] Complete protected flow works from clean reset.
- [ ] Tag `level-1-core` created.

### Stop condition

If Level 1 is unstable at H16, skip all advanced work and harden the core.

---

# LEVEL 2: Judge-Proof Security Depth

## H16 to H22

## Phase 2A: Fixed scenario corpus

### H16 to H19

#### Engineer A

Implement automated scenarios:

Attacks:

- `ATK-01`: beneficiary replacement
- `ATK-02`: vendor creation
- `ATK-03`: secret retrieval
- `ATK-04`: memory poisoning
- `ATK-05`: execution without approval
- `ATK-06`: split-payment bypass

Legitimate:

- `LEG-01`: invoice read
- `LEG-02`: approved vendor lookup
- `LEG-03`: valid payment preparation
- `LEG-04`: approved execution

Add additional security tests:

- Mandate tampering
- Expired mandate
- Revoked mandate
- Approval substitution
- Approval expiry
- Approval replay
- Duplicate idempotency key
- OPA unavailable
- Unknown action
- Malformed decision

#### Engineer B

- Build Evaluation screen.
- Show expected versus actual decision.
- Show pass/fail.
- Show latency.
- Show protected versus unprotected result.
- Add run-all button.
- Add clean-state reset before evaluation.

#### H19 checkpoint

- [ ] Ten-scenario corpus runs automatically.
- [ ] Results persist.
- [ ] Failed scenarios are inspectable.
- [ ] Evaluation can rerun from clean state.

---

## Phase 2B: Evidence and replay

### H19 to H22

#### Engineer A

- Finalize structured event schema.
- Record:
  - source reference
  - raw proposal
  - canonical action
  - policy input
  - policy output
  - tool result
  - side effect
  - latency
- Add before and after resource snapshots.
- Add stable reason codes.
- Add policy version.

#### Engineer B

- Build event detail drawer.
- Build protected versus baseline comparison.
- Show original invoice text.
- Show relevant mandate fields.
- Show violated rule.
- Show before and after transaction state.
- Use the term `execution provenance`.

### Level 2 gate at H22

Run from a clean state three times.

All must pass:

- [ ] All malicious scenarios produce expected outcomes.
- [ ] All legitimate scenarios produce expected outcomes.
- [ ] Outcomes are identical across three runs.
- [ ] No blocked action creates a side effect.
- [ ] Every consequential action links to a signed mandate.
- [ ] Median and P95 policy latency are measured.
- [ ] Event details are understandable without backend logs.
- [ ] Tag `level-2-judge-proof` created.

### Core freeze decision

At H22, answer:

> Can the team perform the full five-minute demo without opening developer tools or manually editing the database?

If no:

- Do not proceed to Level 3.
- Spend H22 to H26 hardening Level 2.

If yes:

- Choose one Level 3 differentiator.

---

# LEVEL 3: One Advanced Differentiator

## H22 to H26

Choose exactly one.

## Option A: MCP adapter

**Recommended when the core is stable.**

### Scope

- Expose the simulated tools through one MCP server.
- Route MCP execution through the same MandateMesh gateway.
- Reuse the same canonical actions.
- Reuse the same Rego policies.
- Show that REST and MCP share one authorization layer.

### Acceptance criteria

- [ ] One protected MCP tool call succeeds.
- [ ] One malicious MCP tool call blocks.
- [ ] No duplicate policy implementation.
- [ ] Existing evaluation still passes.

---

## Option B: Memory quarantine

### Scope

- Store prohibited financial memory writes as `QUARANTINED`.
- Retain source, trust label, and reason.
- Exclude quarantined memory from future retrieval.
- Demonstrate delayed poisoning in a second run.

### Acceptance criteria

- [ ] Unprotected memory write affects later behavior.
- [ ] Protected memory write is quarantined.
- [ ] Quarantined entry is visible.
- [ ] Later protected run excludes the poisoned memory.
- [ ] Existing evaluation still passes.

---

## Option C: Stronger semantic mandate compiler

### Scope

- Convert natural-language request into typed fields.
- Show confidence or warnings.
- Display a natural-language-to-policy mapping.
- Require human confirmation.

### Acceptance criteria

- [ ] Compiler handles the demo request.
- [ ] Ambiguous instructions trigger review.
- [ ] Compiler cannot activate mandate.
- [ ] Existing evaluation still passes.

---

## Level 3 gate at H26

- [ ] Exactly one differentiator completed.
- [ ] Core evaluation still passes.
- [ ] Demo remains under five minutes.
- [ ] New feature adds a clear proof point.
- [ ] No new critical dependency introduced.

If the gate fails, remove the differentiator and return to the Level 2 build.

---

# LEVEL 4: Reliability, Deployment, and Rehearsal

## H26 to H30

## H26 to H27: Product freeze

Create tag:

```text
demo-final
```

Rules after freeze:

- No framework changes
- No model changes
- No new connectors
- No schema redesign
- No policy redesign
- Only bug fixes, resilience, and presentation improvements

---

## H27 to H28: Failure engineering

Implement:

- One-command startup
- Database reset
- Seeded demo state
- Cached invoice fixtures
- Precomputed tool plan fallback
- OPA readiness check
- Fail-closed gateway
- Model timeout handling
- UI reconnect for SSE
- Browser refresh recovery
- Health endpoint
- Smoke-test script
- Recorded backup demo

### Required commands

```bash
docker compose up --build
python scripts/reset.py
python scripts/smoke_test.py
python scripts/run_evaluation.py
```

### Health checks

- Web healthy
- API healthy
- Database writable
- OPA ready
- Model provider reachable or fallback active

---

## H28 to H29: Demo polish

Only five primary screens:

1. Task
2. Mandate
3. Live Execution
4. Approval
5. Evidence and Evaluation

Polish checklist:

- [ ] Qualifier deck visual language preserved.
- [ ] Decision colors consistent.
- [ ] No generic risk score.
- [ ] No placeholder copy.
- [ ] No raw stack traces.
- [ ] Long text does not overflow.
- [ ] Reset button visible but unobtrusive.
- [ ] Demo scenario can be selected in one click.
- [ ] Block reason visible without scrolling.
- [ ] Metrics use observed values.

---

## H29 to H30: Rehearsal

Run three complete rehearsals:

### Rehearsal A: Normal

Full live system with model.

### Rehearsal B: Fast recovery

Recover from one deliberate failure.

Examples:

- Model timeout
- OPA restart
- Browser refresh

### Rehearsal C: Offline fallback

Use:

- Cached invoice
- Precomputed tool plan
- Local policy
- Seeded data

### Presentation ownership

Presenter 1:

- Drives product
- Performs mandate signing
- Approves action
- Triggers tamper test

Presenter 2:

- Narrates architecture
- Explains policy decisions
- Handles judge questions
- Monitors fallback controls

---

# 6. Five-Minute Demo Runbook

## 0:00 to 0:35: Problem

> Existing IAM says the agent may access payments. MandateMesh decides whether this specific payment is the one the human authorized.

## 0:35 to 1:05: Mandate

- Show natural-language task.
- Show typed contract.
- Confirm.
- Sign.

## 1:05 to 1:50: Unprotected attack

- Run malicious invoice.
- Show bank account change.
- Show one forbidden side effect succeed.

## 1:50 to 3:15: Protected run

Show live decisions:

```text
invoice.read          ALLOW
vendor.lookup         ALLOW
vendor.create         BLOCK
secret.read           BLOCK
payment.prepare       BLOCK: BENEFICIARY_MISMATCH
memory.write          BLOCK
```

## 3:15 to 3:55: Correct and approve

```text
payment.prepare       ALLOW
payment.execute       REQUIRE_APPROVAL
payment.execute       ALLOW
```

## 3:55 to 4:20: Tamper proof

Change the signed amount limit.

Show:

```text
MANDATE_SIGNATURE_INVALID
```

## 4:20 to 5:00: Evidence

Show:

- Ten-scenario corpus
- Attack prevention
- Legitimate completion
- False blocks
- Median latency
- Traceability

Close with:

> Same agent, same tools, same malicious invoice. The only change is the action-authorization boundary.

---

# 7. Testing Strategy

## Unit tests

- Canonical serialization
- Signature verification
- Action hashing
- Token expiry
- Token one-time use
- Budget reservation
- Idempotency
- Tool mapping

## Policy tests

- Allowlist
- Denylist
- Vendor approval
- Beneficiary mismatch
- Single limit
- Total limit
- Approval requirement
- Invalid mandate
- Expired mandate
- Fail closed

## Integration tests

- Agent to gateway
- Gateway to OPA
- Gateway to tool
- Approval lifecycle
- Event persistence
- SSE updates
- Reset and seed

## End-to-end tests

- Normal protected workflow
- Malicious protected workflow
- Unprotected baseline
- Tamper test
- Approval substitution
- Split-payment attack
- Full evaluation corpus

---

# 8. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---:|---:|---|
| Model does not reproduce attack | Medium | High | Seeded low-temperature tool plan and fallback |
| OPA integration delays progress | Medium | High | Start with local HTTP sidecar and narrow policy input |
| Signature implementation becomes decorative | Medium | Medium | Include visible tamper test |
| Demo looks hard-coded | High | High | Multiple actions, stateful budget, approval binding |
| UI consumes too much time | High | Medium | Five screens only |
| Event provenance claims become too broad | Medium | High | Use `execution provenance`, not perfect causality |
| MCP work destabilizes core | Medium | High | Begin only after H22 gate |
| Database state contaminates demo | High | High | One-click reset and seeded fixtures |
| Internet or model API fails | Medium | High | Cached input and precomputed plan |
| Policy service unavailable | Low | High | Fail closed and health check |
| Team branches diverge | Medium | Medium | Integrate every four hours |
| Scope expands after H26 | High | High | Freeze tag and no new features |

---

# 9. Stop Conditions

Immediately stop adding features when any condition is true:

- Protected run is not deterministic.
- Blocked action creates a side effect.
- Approval can be reused.
- Evaluation cannot reset cleanly.
- Demo exceeds five minutes.
- Core tests fail after an advanced feature.
- Startup requires manual terminal repair.
- A judge-facing result needs database editing.
- The interface requires developer tools to explain a decision.

Return to the latest stable tag.

---

# 10. Definition of Build Completion

The build is complete when:

- [ ] Baseline attack succeeds reproducibly.
- [ ] Typed mandate is confirmed and signed.
- [ ] Tampering invalidates the mandate.
- [ ] Protected tools are reachable only through the gateway.
- [ ] OPA returns deterministic decisions.
- [ ] Allow, block, and approval all work.
- [ ] Vendor and bank account are bound.
- [ ] Single and total limits are enforced.
- [ ] Approval is independent, action-bound, expiring, and one-use.
- [ ] Ten-scenario corpus runs from one command.
- [ ] All results are visible in the product.
- [ ] Clean reset works.
- [ ] One-command startup works.
- [ ] Three rehearsals completed.
- [ ] Backup recording exists.

---

# 11. Next-Level Backlog

Only start after the complete 30-hour definition of done is satisfied.

Recommended order:

1. MCP adapter
2. Persistent memory quarantine and rollback
3. Browser-agent transaction enforcement
4. Resource-level OAuth grants
5. Multi-agent delegation chains
6. Human approval integrity templates
7. Agent flight recorder
8. Domain policy packs
9. Enterprise key management
10. Runtime compliance evidence
