"""Security-boundary regression tests for the Level 1 hardening pass."""
from __future__ import annotations

import importlib
import inspect
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from app import approvals, config, crypto, gateway, main, mandates, policy
from app.agent import create_run, get_run, resume_after_approval
from app.database import connect, rows
from app.events import list_events
from app.tools import payment_prepare

DEMO_TASK = (
    "Prepare payments for approved supplier invoices. Each payment must be below ₹50,000, "
    "total committed spend must not exceed ₹80,000, and execution requires my approval. "
    "Do not create vendors, change banking details, read secrets, or store new financial instructions in memory."
)
APPROVED_HASH = "cfb2aee019f9750dbec00537350fa1513d2014cbef2ae34597890b42d31c76c0"
INVOICE = "INV-ARUNA-042"


def _decision(value: str, code: str, message: str = "test policy") -> dict:
    return {
        "decision": value,
        "reason_code": code,
        "message": message,
        "matched_rules": ["test_policy"],
        "required_approval": None,
        "policy_version": "test-v1",
    }


def _local_decision(policy_input: dict) -> dict:
    verification = policy_input["verification"]
    if not verification["signature_valid"]:
        return _decision("BLOCK", "MANDATE_SIGNATURE_INVALID")
    if verification["mandate_status"] != "ACTIVE":
        return _decision("BLOCK", "MANDATE_INACTIVE")
    if verification["expired"]:
        return _decision("BLOCK", "MANDATE_EXPIRED")

    mandate = policy_input["mandate"]
    action = policy_input["action"]
    canonical = action["canonical_action"]
    if canonical in mandate["forbidden_actions"]:
        code = "MEMORY_WRITE_FORBIDDEN" if canonical == "memory.financial_instruction.write" else "ACTION_EXPLICITLY_FORBIDDEN"
        return _decision("BLOCK", code)
    if canonical not in mandate["allowed_actions"]:
        return _decision("BLOCK", "ACTION_NOT_ALLOWED")

    if canonical == "financial.payment.prepare":
        resource = action["resource"]
        cp = next((c for c in mandate["approved_counterparties"] if c["vendor_id"] == resource["vendor_id"]), None)
        if cp is None:
            return _decision("BLOCK", "VENDOR_NOT_APPROVED")
        if cp["beneficiary_hash"] != resource["beneficiary_hash"]:
            return _decision("BLOCK", "BENEFICIARY_MISMATCH")
        if resource["currency"] != mandate["currency"]:
            return _decision("BLOCK", "CURRENCY_MISMATCH")
        if resource["amount"] > mandate["max_single_payment"]:
            return _decision("BLOCK", "SINGLE_PAYMENT_LIMIT_EXCEEDED")
        if policy_input["task_state"]["committed_amount"] + resource["amount"] > mandate["max_total_payment"]:
            return _decision("BLOCK", "TOTAL_BUDGET_EXCEEDED")

    if canonical == "financial.payment.execute":
        approval = policy_input["approval"]
        if not approval["present"]:
            out = _decision("REQUIRE_APPROVAL", "APPROVAL_REQUIRED")
            out["required_approval"] = {"action_hash": action["action_hash"]}
            return out
        if approval["expired"]:
            return _decision("BLOCK", "APPROVAL_EXPIRED")
        if approval["consumed"]:
            return _decision("BLOCK", "APPROVAL_ALREADY_USED")
        if not approval["valid"] or not approval["action_hash_match"] or not approval.get("binding_match"):
            return _decision("BLOCK", "APPROVAL_INVALID")
    return _decision("ALLOW", "ACTION_ALLOWED")


@pytest.fixture
def local_policy(monkeypatch):
    monkeypatch.setattr(policy, "query_decision", _local_decision)


def _signed_mandate() -> str:
    mandate = mandates.compile_mandate(DEMO_TASK)
    mandates.confirm_mandate(mandate["id"])
    mandates.sign_mandate(mandate["id"])
    return mandate["id"]


def _protected_run(mandate_id: str) -> str:
    return create_run(
        "normal-invoice",
        "deterministic",
        "test",
        protection_mode="PROTECTED",
        mandate_id=mandate_id,
    )["id"]


def _prepare(run_id: str, mandate_id: str, key: str, amount: int = 42000) -> dict:
    arguments = {
        "invoice_id": INVOICE,
        "vendor_id": "VENDOR-101",
        "beneficiary_hash": APPROVED_HASH,
        "amount": amount,
        "currency": "INR",
        "idempotency_key": key,
    }
    return gateway.execute(
        run_id,
        mandate_id,
        "payment.prepare",
        arguments,
        source_ref=INVOICE,
        idempotency_key=key,
    )


def _request_approval(run_id: str, mandate_id: str, payment_id: str, key: str = "execute") -> dict:
    arguments = {"payment_id": payment_id, "idempotency_key": key}
    return gateway.execute(
        run_id,
        mandate_id,
        "payment.execute",
        arguments,
        source_ref=INVOICE,
        idempotency_key=key,
    )


# Persistent key material ----------------------------------------------------
def test_random_key_persists_and_is_not_publicly_derivable(tmp_path, monkeypatch):
    first_path = tmp_path / "principal-a.key"
    monkeypatch.setattr(config, "KEY_PATH", first_path)
    first_public = crypto.public_key_b64()
    assert first_path.exists()
    assert len(first_path.read_bytes()) == 32
    assert stat.S_IMODE(first_path.stat().st_mode) == 0o600
    assert crypto.public_key_b64() == first_public
    importlib.reload(crypto)
    assert crypto.public_key_b64() == first_public

    second_path = tmp_path / "principal-b.key"
    monkeypatch.setattr(config, "KEY_PATH", second_path)
    second_public = crypto.public_key_b64()
    assert second_public != first_public
    source = inspect.getsource(crypto)
    assert "_DEMO_SEED" not in source
    assert "mandatemesh-local-demo-principal-v1" not in source


# Cross-boundary identity binding -------------------------------------------
def test_run_mandate_and_unprotected_boundaries_fail_closed(local_policy):
    mandate_a = _signed_mandate()
    mandate_b = _signed_mandate()
    protected_run = _protected_run(mandate_a)
    mismatch = gateway.execute(
        protected_run,
        mandate_b,
        "invoice.read",
        {"invoice_id": INVOICE},
        source_ref=INVOICE,
    )
    assert mismatch["decision"]["reason_code"] == "RUN_MANDATE_MISMATCH"

    unprotected_run = create_run("normal-invoice", "deterministic", "test")["id"]
    unprotected = gateway.execute(
        unprotected_run,
        mandate_a,
        "invoice.read",
        {"invoice_id": INVOICE},
        source_ref=INVOICE,
    )
    assert unprotected["decision"]["reason_code"] == "RUN_NOT_PROTECTED"


def test_unprotected_payment_cannot_cross_into_protected_execution(local_policy):
    unprotected_run = create_run("normal-invoice", "deterministic", "test")["id"]
    raw_payment, _ = payment_prepare(
        {
            "invoice_id": INVOICE,
            "vendor_id": "VENDOR-101",
            "beneficiary_hash": APPROVED_HASH,
            "amount": 42000,
            "currency": "INR",
            "idempotency_key": "unprotected-payment",
        }
    )
    mandate_id = _signed_mandate()
    protected_run = _protected_run(mandate_id)
    outcome = _request_approval(protected_run, mandate_id, raw_payment["id"])
    assert outcome["decision"]["reason_code"] == "PAYMENT_MANDATE_MISMATCH"
    assert rows("SELECT status FROM payments WHERE id = ?", (raw_payment["id"],))[0]["status"] == "PREPARED"
    assert get_run(unprotected_run)["protection_mode"] == "UNPROTECTED"


# Transactional budgets and idempotency -------------------------------------
def test_concurrent_budget_reservations_have_one_winner(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda key: _prepare(run_id, mandate_id, key), ("budget-a", "budget-b")))
    decisions = sorted((item["decision"]["decision"], item["decision"]["reason_code"]) for item in outcomes)
    assert decisions == [("ALLOW", "ACTION_ALLOWED"), ("BLOCK", "TOTAL_BUDGET_EXCEEDED")]
    assert gateway.committed_amount(mandate_id) == 42000
    assert not rows("SELECT id FROM payments WHERE mandate_id IS NULL")


def test_concurrent_duplicate_idempotency_creates_one_payment(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: _prepare(run_id, mandate_id, "same-key"), range(2)))
    assert all(item["decision"]["decision"] == "ALLOW" for item in outcomes)
    payments = rows("SELECT * FROM payments WHERE idempotency_key = 'same-key'")
    assert len(payments) == 1
    assert gateway.committed_amount(mandate_id) == 42000


# Approval races, expiry, and evidence --------------------------------------
def test_concurrent_approval_clicks_mint_one_token(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    payment_id = _prepare(run_id, mandate_id, "approval-prep")["tool_result"]["id"]
    _request_approval(run_id, mandate_id, payment_id)
    request_id = approvals.list_pending()[0]["id"]

    def click():
        try:
            return approvals.approve(request_id)
        except approvals.ApprovalError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: click(), range(2)))
    assert sum(isinstance(item, dict) for item in results) == 1
    assert rows("SELECT COUNT(*) AS n FROM approval_tokens")[0]["n"] == 1


def test_expiry_is_rechecked_inside_execution_transaction(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    payment_id = _prepare(run_id, mandate_id, "expiry-prep")["tool_result"]["id"]
    _request_approval(run_id, mandate_id, payment_id)
    granted = approvals.approve(approvals.list_pending()[0]["id"])
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    _, _, outcome = gateway._execute_payment(
        payment_id,
        granted["token"],
        granted["action_hash"],
        "late-execution",
        run_id=run_id,
        mandate_id=mandate_id,
        now=future,
    )
    assert outcome == "APPROVAL_EXPIRED"
    assert rows("SELECT status FROM payments WHERE id = ?", (payment_id,))[0]["status"] == "APPROVAL_PENDING"
    assert rows("SELECT consumed_at FROM approval_tokens")[0]["consumed_at"] is None


def test_approval_events_correlate_to_run_and_failed_resume_is_not_complete(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    payment_id = _prepare(run_id, mandate_id, "event-prep")["tool_result"]["id"]
    _request_approval(run_id, mandate_id, payment_id)
    request_id = approvals.list_pending()[0]["id"]
    response = main.approvals_approve(request_id)
    assert response["decision"]["decision"] == "ALLOW"
    event_types = [event["event_type"] for event in list_events(run_id)]
    assert "APPROVAL_REQUESTED" in event_types
    assert "APPROVAL_GRANTED" in event_types
    assert "TOOL_EXECUTED" in event_types
    assert "RUN_COMPLETED" in event_types

    second_mandate = _signed_mandate()
    second_run = _protected_run(second_mandate)
    second_payment = _prepare(second_run, second_mandate, "bad-resume-prep")["tool_result"]["id"]
    _request_approval(second_run, second_mandate, second_payment, "bad-resume-request")
    blocked = resume_after_approval(second_run, second_payment, "not-a-real-token")
    assert blocked["decision"]["decision"] == "BLOCK"
    assert get_run(second_run)["status"] == "BLOCKED"
    assert "RUN_COMPLETED" not in [event["event_type"] for event in list_events(second_run)]


def test_ready_endpoint_distinguishes_protected_readiness(monkeypatch):
    monkeypatch.setattr(policy, "opa_healthy", lambda: False)
    assert main.ready().status_code == 503
    monkeypatch.setattr(policy, "opa_healthy", lambda: True)
    assert main.ready().status_code == 200


def test_malformed_payment_amount_fails_closed_without_side_effect(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    arguments = {
        "invoice_id": INVOICE,
        "vendor_id": "VENDOR-101",
        "beneficiary_hash": APPROVED_HASH,
        "amount": "not-a-number",
        "currency": "INR",
        "idempotency_key": "malformed-amount",
    }
    outcome = gateway.execute(
        run_id,
        mandate_id,
        "payment.prepare",
        arguments,
        source_ref=INVOICE,
        idempotency_key="malformed-amount",
    )
    assert outcome["decision"]["decision"] == "BLOCK"
    assert outcome["decision"]["reason_code"] == "ACTION_NOT_ALLOWED"
    assert not rows("SELECT id FROM payments")


def test_duplicate_approval_request_returns_same_pending_record(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    payment_id = _prepare(run_id, mandate_id, "duplicate-request-prep")["tool_result"]["id"]
    first = _request_approval(run_id, mandate_id, payment_id, "duplicate-request-exec")
    second = _request_approval(run_id, mandate_id, payment_id, "duplicate-request-exec")
    assert first["approval_request_id"] == second["approval_request_id"]
    assert len(approvals.list_pending()) == 1


def test_approval_after_request_expiry_cancels_reservation_and_blocks_run(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    payment_id = _prepare(run_id, mandate_id, "expired-request-prep")["tool_result"]["id"]
    _request_approval(run_id, mandate_id, payment_id, "expired-request-exec")
    request = approvals.list_pending()[0]
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with pytest.raises(approvals.ApprovalError, match="expired"):
        approvals.approve(request["id"], now=future)
    assert rows("SELECT status FROM payments WHERE id = ?", (payment_id,))[0]["status"] == "CANCELLED"
    assert get_run(run_id)["status"] == "BLOCKED"
    assert rows("SELECT COUNT(*) AS n FROM approval_tokens")[0]["n"] == 0


def test_token_from_another_mandate_and_payment_is_rejected(local_policy):
    mandate_a = _signed_mandate()
    run_a = _protected_run(mandate_a)
    payment_a = _prepare(run_a, mandate_a, "token-a-prep")["tool_result"]["id"]
    _request_approval(run_a, mandate_a, payment_a, "token-a-request")
    granted_a = approvals.approve(approvals.list_pending()[0]["id"])

    mandate_b = _signed_mandate()
    run_b = _protected_run(mandate_b)
    payment_b = _prepare(run_b, mandate_b, "token-b-prep")["tool_result"]["id"]
    action_hash_b = approvals.action_hash_for(mandate_b, rows("SELECT * FROM payments WHERE id = ?", (payment_b,))[0], run_b)
    _, _, outcome = gateway._execute_payment(
        payment_b,
        granted_a["token"],
        action_hash_b,
        "cross-token-exec",
        run_id=run_b,
        mandate_id=mandate_b,
    )
    assert outcome == "APPROVAL_INVALID"
    assert rows("SELECT status FROM payments WHERE id = ?", (payment_b,))[0]["status"] == "PREPARED"
    assert rows("SELECT consumed_at FROM approval_tokens WHERE token = ?", (granted_a["token"],))[0]["consumed_at"] is None


def test_payment_mutation_after_approval_does_not_consume_token(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    payment_id = _prepare(run_id, mandate_id, "mutation-prep")["tool_result"]["id"]
    _request_approval(run_id, mandate_id, payment_id, "mutation-request")
    granted = approvals.approve(approvals.list_pending()[0]["id"])
    with connect() as connection:
        connection.execute(
            "UPDATE payments SET beneficiary_hash = ? WHERE id = ?",
            ("attacker-beneficiary", payment_id),
        )
    _, _, outcome = gateway._execute_payment(
        payment_id,
        granted["token"],
        granted["action_hash"],
        "mutation-exec",
        run_id=run_id,
        mandate_id=mandate_id,
    )
    assert outcome == "BENEFICIARY_MISMATCH"
    assert rows("SELECT status FROM payments WHERE id = ?", (payment_id,))[0]["status"] == "APPROVAL_PENDING"
    assert rows("SELECT consumed_at FROM approval_tokens WHERE token = ?", (granted["token"],))[0]["consumed_at"] is None



def test_concurrent_token_consumption_executes_once(local_policy):
    mandate_id = _signed_mandate()
    run_id = _protected_run(mandate_id)
    payment_id = _prepare(run_id, mandate_id, "concurrent-exec-prep")["tool_result"]["id"]
    _request_approval(run_id, mandate_id, payment_id, "concurrent-exec-request")
    granted = approvals.approve(approvals.list_pending()[0]["id"])

    def execute_once(key: str):
        return gateway._execute_payment(
            payment_id,
            granted["token"],
            granted["action_hash"],
            key,
            run_id=run_id,
            mandate_id=mandate_id,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(execute_once, ("concurrent-exec-a", "concurrent-exec-b")))
    outcomes = [item[2] for item in results]
    assert outcomes.count("EXECUTED") == 1
    assert len([item for item in outcomes if item != "EXECUTED"]) == 1
    assert rows("SELECT COUNT(*) AS n FROM payments WHERE status = 'EXECUTED'")[0]["n"] == 1
    assert rows("SELECT COUNT(*) AS n FROM approval_tokens WHERE consumed_at IS NOT NULL")[0]["n"] == 1
