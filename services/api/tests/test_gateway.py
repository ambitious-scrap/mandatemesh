"""Protected gateway, OPA policy, approval, and stateful-budget enforcement.

Tests marked with the ``opa`` fixture require a reachable OPA (an already-running
instance or Docker to start one); they are skipped when neither is available.
Fail-closed, unknown-tool, and missing-mandate paths short-circuit before OPA and
run without the fixture.
"""
from __future__ import annotations

import json

from app import approvals, gateway, mandates, policy
from app.agent import create_run, execute_protected_run, get_run, resume_after_approval
from app.database import connect, rows

DEMO_TASK = (
    "Prepare payments for approved supplier invoices. Each payment must be below ₹50,000, "
    "total committed spend must not exceed ₹80,000, and execution requires my approval. "
    "Do not create vendors, change banking details, read secrets, or store new financial instructions in memory."
)
APPROVED_HASH = "cfb2aee019f9750dbec00537350fa1513d2014cbef2ae34597890b42d31c76c0"
INVOICE = "INV-ARUNA-042"


def _signed_mandate() -> str:
    m = mandates.compile_mandate(DEMO_TASK)
    mandates.confirm_mandate(m["id"])
    mandates.sign_mandate(m["id"])
    return m["id"]


def _run(mandate_id: str) -> str:
    return create_run("normal-invoice", "deterministic", "t", protection_mode="PROTECTED", mandate_id=mandate_id)["id"]


def _prepare(run_id, mandate_id, *, amount=42000, beneficiary=APPROVED_HASH, vendor="VENDOR-101", key="prep"):
    args = {
        "invoice_id": INVOICE, "vendor_id": vendor, "beneficiary_hash": beneficiary,
        "amount": amount, "currency": "INR", "idempotency_key": key,
    }
    return gateway.execute(run_id, mandate_id, "payment.prepare", args, source_ref=INVOICE, idempotency_key=key)


def _execute(run_id, mandate_id, payment_id, *, token=None, key="exec"):
    args = {"payment_id": payment_id, "idempotency_key": key}
    return gateway.execute(run_id, mandate_id, "payment.execute", args, source_ref=INVOICE, approval_token=token, idempotency_key=key)


# --- allowlist / denylist ---------------------------------------------------
def test_invoice_read_allowed(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = gateway.execute(rid, mid, "invoice.read", {"invoice_id": INVOICE}, source_ref=INVOICE)
    assert out["decision"]["decision"] == "ALLOW"
    assert out["decision"]["reason_code"] == "ACTION_ALLOWED"


def test_vendor_lookup_allowed(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = gateway.execute(rid, mid, "vendor.lookup", {"vendor_id": "VENDOR-101"}, source_ref=INVOICE)
    assert out["decision"]["decision"] == "ALLOW"


def test_vendor_create_forbidden_no_side_effect(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = gateway.execute(
        rid, mid, "vendor.create",
        {"vendor_id": "VENDOR-ATTACKER", "name": "x", "bank_account_hash": "h", "idempotency_key": "v"},
        source_ref=INVOICE, idempotency_key="v",
    )
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "ACTION_EXPLICITLY_FORBIDDEN"
    assert not rows("SELECT id FROM vendors WHERE id = 'VENDOR-ATTACKER'")


def test_secret_read_forbidden(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = gateway.execute(rid, mid, "secret.read", {"name": "banking-api-key"}, source_ref=INVOICE)
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "ACTION_EXPLICITLY_FORBIDDEN"
    assert not rows("SELECT id FROM tool_events WHERE tool_name = 'secret.read' AND event_type = 'SIDE_EFFECT_RECORDED'")


def test_memory_write_forbidden(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = gateway.execute(
        rid, mid, "memory.write",
        {"key": "pay-to", "value": "attacker", "source_ref": "UNTRUSTED", "idempotency_key": "m"},
        source_ref=INVOICE, idempotency_key="m",
    )
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "MEMORY_WRITE_FORBIDDEN"
    assert not rows("SELECT id FROM memory_entries")


# --- payment.prepare binding + limits ---------------------------------------
def test_beneficiary_mismatch_blocks_prepare(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = _prepare(rid, mid, beneficiary="deadbeef" * 8, key="mm")
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "BENEFICIARY_MISMATCH"
    assert not rows("SELECT id FROM payments")


def test_valid_prepare_allowed_and_bound_to_mandate(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = _prepare(rid, mid, key="ok")
    assert out["decision"]["decision"] == "ALLOW"
    payment = rows("SELECT mandate_id, status FROM payments WHERE id = ?", (out["tool_result"]["id"],))[0]
    assert payment["mandate_id"] == mid
    assert payment["status"] == "PREPARED"


def test_single_payment_limit_blocks(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    out = _prepare(rid, mid, amount=60000, key="big")
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "SINGLE_PAYMENT_LIMIT_EXCEEDED"


def test_cumulative_budget_blocks_second_prepare(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    assert _prepare(rid, mid, amount=42000, key="a")["decision"]["decision"] == "ALLOW"
    out = _prepare(rid, mid, amount=42000, key="b")  # 42000 + 42000 = 84000 > 80000
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "TOTAL_BUDGET_EXCEEDED"


# --- approval lifecycle -----------------------------------------------------
def test_execute_without_approval_requires_approval(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    pid = _prepare(rid, mid, key="p")["tool_result"]["id"]
    out = _execute(rid, mid, pid, key="e")
    assert out["decision"]["decision"] == "REQUIRE_APPROVAL"
    assert rows("SELECT status FROM payments WHERE id = ?", (pid,))[0]["status"] == "APPROVAL_PENDING"
    assert get_run(rid)["status"] == "AWAITING_APPROVAL"
    assert len(approvals.list_pending()) == 1


def test_approved_execute_runs_once_and_replay_blocks(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    pid = _prepare(rid, mid, key="p")["tool_result"]["id"]
    assert _execute(rid, mid, pid, key="e")["decision"]["decision"] == "REQUIRE_APPROVAL"

    granted = approvals.approve(approvals.list_pending()[0]["id"])
    allowed = _execute(rid, mid, pid, token=granted["token"], key="e2")
    assert allowed["decision"]["decision"] == "ALLOW"
    assert rows("SELECT status FROM payments WHERE id = ?", (pid,))[0]["status"] == "EXECUTED"

    replay = _execute(rid, mid, pid, token=granted["token"], key="e3")
    assert replay["decision"]["decision"] == "BLOCK"
    assert replay["decision"]["reason_code"] == "APPROVAL_ALREADY_USED"
    assert rows("SELECT COUNT(*) AS n FROM payments WHERE status = 'EXECUTED'")[0]["n"] == 1


def test_execution_idempotency_key_prevents_double_spend(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    pid = _prepare(rid, mid, key="p")["tool_result"]["id"]
    assert _execute(rid, mid, pid, key="e")["decision"]["decision"] == "REQUIRE_APPROVAL"
    granted = approvals.approve(approvals.list_pending()[0]["id"])
    assert _execute(rid, mid, pid, token=granted["token"], key="dup")["decision"]["decision"] == "ALLOW"
    # Re-entering the atomic execution layer with the same idempotency key
    # returns the prior execution rather than spending a second time.
    result, side_effect, outcome = gateway._execute_payment(pid, granted["token"], granted["action_hash"], "dup")
    assert outcome == "REPLAY"
    assert side_effect is None
    assert rows("SELECT COUNT(*) AS n FROM payments WHERE status = 'EXECUTED'")[0]["n"] == 1


def test_reject_cancels_payment(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    pid = _prepare(rid, mid, key="p")["tool_result"]["id"]
    _execute(rid, mid, pid, key="e")
    approvals.reject(approvals.list_pending()[0]["id"])
    assert rows("SELECT status FROM payments WHERE id = ?", (pid,))[0]["status"] != "EXECUTED"


# --- mandate gates ----------------------------------------------------------
def test_missing_mandate_blocks():
    rid = create_run("normal-invoice", "deterministic", "t", protection_mode="PROTECTED", mandate_id=None)["id"]
    out = gateway.execute(rid, None, "invoice.read", {"invoice_id": INVOICE}, source_ref=INVOICE)
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "MANDATE_INACTIVE"


def test_unknown_tool_blocks():
    mid = _signed_mandate()
    rid = _run(mid)
    out = gateway.execute(rid, mid, "filesystem.write", {"path": "/etc/passwd"}, source_ref=INVOICE)
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "ACTION_NOT_ALLOWED"


def test_tampered_mandate_signature_blocks(opa):
    mid = _signed_mandate()
    rid = _run(mid)
    # Mutate the stored contract after signing; the recomputed canonical no
    # longer matches the signature, so verification fails closed.
    record = mandates.get_mandate(mid)
    contract = dict(record["contract"])
    contract["max_single_payment"] = 999999
    with connect() as connection:
        connection.execute("UPDATE mandates SET payload_json = ? WHERE id = ?", (json.dumps(contract), mid))
    out = gateway.execute(rid, mid, "invoice.read", {"invoice_id": INVOICE}, source_ref=INVOICE)
    assert out["decision"]["decision"] == "BLOCK"
    assert out["decision"]["reason_code"] == "MANDATE_SIGNATURE_INVALID"


def test_policy_unavailable_fails_closed(monkeypatch):
    # No OPA fixture: point the client at a dead endpoint and confirm it blocks.
    monkeypatch.setattr(policy, "OPA_URL", "http://127.0.0.1:1")
    decision = policy.query_decision({"anything": True})
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "POLICY_UNAVAILABLE"


# --- full protected attack flow ---------------------------------------------
def test_full_protected_attack_flow(opa):
    mid = _signed_mandate()
    run = create_run("malicious-invoice", "deterministic", "attack", protection_mode="PROTECTED", mandate_id=mid)
    rid = run["id"]
    execute_protected_run(rid)

    after = get_run(rid)
    assert after["status"] == "AWAITING_APPROVAL"

    from app.events import list_events
    decisions = [
        (e["tool_name"], e["decision"]["decision"], e["decision"]["reason_code"])
        for e in list_events(rid) if e["event_type"] == "POLICY_DECIDED"
    ]
    assert ("invoice.read", "ALLOW", "ACTION_ALLOWED") in decisions
    assert ("vendor.lookup", "ALLOW", "ACTION_ALLOWED") in decisions
    assert ("vendor.create", "BLOCK", "ACTION_EXPLICITLY_FORBIDDEN") in decisions
    assert ("secret.read", "BLOCK", "ACTION_EXPLICITLY_FORBIDDEN") in decisions
    assert ("memory.write", "BLOCK", "MEMORY_WRITE_FORBIDDEN") in decisions
    assert ("payment.prepare", "BLOCK", "BENEFICIARY_MISMATCH") in decisions
    assert ("payment.execute", "REQUIRE_APPROVAL", "APPROVAL_REQUIRED") in decisions

    pending = approvals.list_pending()
    assert len(pending) == 1
    granted = approvals.approve(pending[0]["id"])
    outcome = resume_after_approval(rid, granted["payment_id"], granted["token"])
    assert outcome["decision"]["decision"] == "ALLOW"

    # exactly one executed payment, to the approved vendor only
    executed = rows("SELECT vendor_id, amount FROM payments WHERE status = 'EXECUTED'")
    assert len(executed) == 1
    assert executed[0]["vendor_id"] == "VENDOR-101"

    # no forbidden side effects landed
    assert not rows("SELECT id FROM vendors WHERE id = 'VENDOR-ATTACKER'")
    assert not rows("SELECT id FROM memory_entries")

    # replay of the consumed token with a fresh idempotency key is blocked
    replay = _execute(rid, mid, granted["payment_id"], token=granted["token"], key=rid + "-replay")
    assert replay["decision"]["decision"] == "BLOCK"
    assert replay["decision"]["reason_code"] == "APPROVAL_ALREADY_USED"
