"""Protected tool-call gateway — the single enforcement point.

Every protected tool call passes through :func:`execute`. The gateway:

1. Verifies the mandate (Ed25519, status, expiry) in Python.
2. Normalizes the raw tool call into a canonical business action.
3. Loads trusted task state (committed spend, approval token binding).
4. Builds policy input — the only place policy input is constructed — and asks
   OPA for a decision.
5. Records the decision event *before* any tool executes.
6. Enforces ALLOW / BLOCK / REQUIRE_APPROVAL, failing closed on any error.

Blocked actions produce no side effect. Allowed side-effecting actions execute
exactly once under an idempotency key. Approval-required actions never execute
until an action-bound, one-use token is presented and consumed atomically.
"""
from __future__ import annotations

import time

from . import actions, approvals, mandates, policy
from .canonical import sha256_hex
from .database import connect, rows, utc_now
from .events import record_event
from .tools import ToolError, execute_tool

_CONSEQUENTIAL = actions.SIDE_EFFECTING


def committed_amount(mandate_id: str) -> int:
    """Reserved + executed spend for a mandate (PREPARED, APPROVAL_PENDING, EXECUTED)."""
    result = rows(
        """SELECT COALESCE(SUM(amount), 0) AS total FROM payments
        WHERE mandate_id = ? AND status IN ('PREPARED', 'APPROVAL_PENDING', 'EXECUTED')""",
        (mandate_id,),
    )
    return int(result[0]["total"])


def _synthetic_block(reason_code: str, message: str) -> dict:
    return {
        "decision": "BLOCK",
        "reason_code": reason_code,
        "message": message,
        "matched_rules": ["gateway_fail_closed"],
        "required_approval": None,
        "policy_version": None,
    }


def _redact(tool_name: str, result: dict) -> dict:
    if tool_name == "secret.read":
        return {"name": result.get("name"), "value": "[SYNTHETIC SECRET EXPOSED]", "exposed": True}
    return result


def _bump_blocked(run_id: str) -> None:
    with connect() as connection:
        connection.execute("UPDATE runs SET blocked_actions = blocked_actions + 1 WHERE id = ?", (run_id,))


def _load_payment(payment_id: str) -> dict | None:
    result = rows("SELECT * FROM payments WHERE id = ?", (payment_id,))
    return result[0] if result else None


def execute(
    run_id: str,
    mandate_id: str,
    tool_name: str,
    arguments: dict,
    *,
    source_ref: str | None = None,
    approval_token: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    started = time.perf_counter()

    mandate = mandates.get_mandate(mandate_id) if mandate_id else None
    if mandate is None:
        decision = _synthetic_block("MANDATE_INACTIVE", "No mandate is bound to this action.")
        event = record_event(run_id, "TOOL_BLOCKED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                              tool_name=tool_name, tool_arguments=arguments, decision=decision, is_forbidden=True)
        _bump_blocked(run_id)
        return {"decision": decision, "tool_result": None, "event_id": event["id"]}

    verification = mandates.verification_for(mandate)
    contract = mandate["contract"]

    canonical = actions.build_canonical_action(
        tool_name, arguments, source_ref=source_ref, mandate_id=mandate_id,
        task_state={"committed_amount": committed_amount(mandate_id)}, idempotency_key=idempotency_key,
    )
    if canonical is None:
        decision = _synthetic_block("ACTION_NOT_ALLOWED", f"Unknown tool: {tool_name}.")
        event = record_event(run_id, "TOOL_BLOCKED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                              tool_name=tool_name, tool_arguments=arguments, decision=decision, is_forbidden=True)
        _bump_blocked(run_id)
        return {"decision": decision, "tool_result": None, "event_id": event["id"]}

    canonical_action = canonical["canonical_action"]

    # Side-effecting actions must carry an idempotency key; fail closed otherwise.
    if canonical_action in _CONSEQUENTIAL and not idempotency_key:
        decision = _synthetic_block("IDEMPOTENCY_KEY_REQUIRED", "Side-effecting action requires an idempotency key.")
        event = record_event(run_id, "TOOL_BLOCKED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                              tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical, decision=decision, is_forbidden=True)
        _bump_blocked(run_id)
        return {"decision": decision, "tool_result": None, "event_id": event["id"]}

    # Resolve trusted resource + approval binding for execution.
    payment = None
    action_hash = sha256_hex(canonical["resource"])
    approval_snapshot = {"present": False, "valid": False, "expired": False, "consumed": False, "action_hash_match": False}
    if canonical_action == "financial.payment.execute":
        payment = _load_payment(arguments.get("payment_id"))
        if payment is None:
            decision = _synthetic_block("MANDATE_INACTIVE", f"Prepared payment not found: {arguments.get('payment_id')}.")
            event = record_event(run_id, "TOOL_BLOCKED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                                  tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical, decision=decision, is_forbidden=True)
            _bump_blocked(run_id)
            return {"decision": decision, "tool_result": None, "event_id": event["id"]}
        canonical["resource"] = {
            "payment_id": payment["id"],
            "vendor_id": payment["vendor_id"],
            "beneficiary_hash": payment["beneficiary_hash"],
            "amount": payment["amount"],
            "currency": payment["currency"],
        }
        action_hash = approvals.action_hash_for(mandate_id, payment)
        approval_snapshot = approvals.verify_token(approval_token, action_hash)

    canonical["action_hash"] = action_hash

    record_event(run_id, "ACTION_NORMALIZED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                 tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical)

    policy_input = {
        "verification": {k: verification[k] for k in ("signature_valid", "mandate_status", "expired", "now")},
        "mandate": {
            "id": mandate_id,
            "allowed_actions": contract["allowed_actions"],
            "forbidden_actions": contract["forbidden_actions"],
            "approved_counterparties": contract["approved_counterparties"],
            "currency": contract["currency"],
            "max_single_payment": contract["max_single_payment"],
            "max_total_payment": contract["max_total_payment"],
            "execution_mode": contract["execution_mode"],
            "requires_approval": contract["requires_approval"],
        },
        "action": {
            "canonical_action": canonical_action,
            "tool_name": tool_name,
            "resource": canonical["resource"],
            "provenance": canonical["provenance"],
            "action_hash": action_hash,
        },
        "task_state": {"committed_amount": committed_amount(mandate_id)},
        "approval": approval_snapshot,
    }

    decision = policy.query_decision(policy_input)
    policy_version = decision.get("policy_version")

    # Decision is recorded before any side effect.
    record_event(run_id, "POLICY_DECIDED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                 tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical,
                 decision=decision, policy_version=policy_version)

    if decision["decision"] == "REQUIRE_APPROVAL":
        return _require_approval(run_id, mandate_id, canonical, payment, source_ref, decision, policy_version)

    if decision["decision"] != "ALLOW":
        latency = round((time.perf_counter() - started) * 1000, 3)
        event = record_event(run_id, "TOOL_BLOCKED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                              tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical,
                              decision=decision, policy_version=policy_version, is_forbidden=True, latency_ms=latency)
        _bump_blocked(run_id)
        return {"decision": decision, "tool_result": None, "event_id": event["id"]}

    # ALLOW ------------------------------------------------------------------
    return _execute_allowed(
        run_id, mandate_id, tool_name, arguments, canonical, payment, action_hash,
        approval_token, idempotency_key, source_ref, decision, policy_version, started,
    )


def _require_approval(run_id, mandate_id, canonical, payment, source_ref, decision, policy_version) -> dict:
    contract = mandates.get_mandate(mandate_id)["contract"]
    remaining = contract["max_total_payment"] - committed_amount(mandate_id)
    request = approvals.create_request(
        run_id=run_id,
        mandate_id=mandate_id,
        payment=payment,
        invoice_id=payment["invoice_id"],
        remaining_budget=remaining,
        source_trust=canonical["provenance"]["source_trust"],
    )
    with connect() as connection:
        connection.execute(
            "UPDATE payments SET status = 'APPROVAL_PENDING' WHERE id = ? AND status = 'PREPARED'",
            (payment["id"],),
        )
        connection.execute("UPDATE runs SET status = 'AWAITING_APPROVAL' WHERE id = ?", (run_id,))
    event = record_event(run_id, "APPROVAL_REQUESTED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                         tool_name=canonical["tool_name"], canonical_action=canonical, decision=decision,
                         policy_version=policy_version, tool_result={"approval_request_id": request["id"], "action_hash": request["action_hash"]})
    return {"decision": decision, "tool_result": None, "event_id": event["id"], "approval_request_id": request["id"]}


def _execute_allowed(run_id, mandate_id, tool_name, arguments, canonical, payment, action_hash,
                     approval_token, idempotency_key, source_ref, decision, policy_version, started) -> dict:
    canonical_action = canonical["canonical_action"]

    if canonical_action == "financial.payment.execute":
        result, side_effect, outcome = _execute_payment(payment["id"], approval_token, action_hash, idempotency_key)
        if outcome == "ALREADY_USED":
            block = _synthetic_block("APPROVAL_ALREADY_USED", "Approval token has already been consumed.")
            latency = round((time.perf_counter() - started) * 1000, 3)
            event = record_event(run_id, "TOOL_BLOCKED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                                  tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical,
                                  decision=block, policy_version=policy_version, is_forbidden=True, latency_ms=latency)
            _bump_blocked(run_id)
            return {"decision": block, "tool_result": None, "event_id": event["id"]}
    else:
        try:
            result, side_effect = execute_tool(tool_name, arguments)
        except ToolError as error:
            block = _synthetic_block("ACTION_NOT_ALLOWED", str(error))
            latency = round((time.perf_counter() - started) * 1000, 3)
            event = record_event(run_id, "TOOL_BLOCKED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                                  tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical,
                                  decision=block, policy_version=policy_version, is_forbidden=True, latency_ms=latency)
            _bump_blocked(run_id)
            return {"decision": block, "tool_result": None, "event_id": event["id"]}
        if canonical_action == "financial.payment.prepare" and not result.get("idempotent_replay"):
            with connect() as connection:
                connection.execute("UPDATE payments SET mandate_id = ? WHERE id = ?", (mandate_id, result["id"]))

    latency = round((time.perf_counter() - started) * 1000, 3)
    public_result = _redact(tool_name, result)
    event = record_event(run_id, "TOOL_EXECUTED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                         tool_name=tool_name, tool_arguments=arguments, canonical_action=canonical,
                         tool_result={"ok": True, "data": public_result}, decision=decision,
                         policy_version=policy_version, latency_ms=latency)
    if side_effect:
        record_event(run_id, "SIDE_EFFECT_RECORDED", actor="gateway", mandate_id=mandate_id, source_ref=source_ref,
                     tool_name=tool_name, canonical_action=canonical, side_effect=side_effect, policy_version=policy_version)
    return {"decision": decision, "tool_result": public_result, "event_id": event["id"]}


def _execute_payment(payment_id: str, token: str | None, action_hash: str, idempotency_key: str):
    """Consume the approval token and execute the payment in one transaction.

    Returns ``(result, side_effect, outcome)`` where outcome is EXECUTED, REPLAY,
    or ALREADY_USED. The token is consumed atomically with the status flip so a
    replayed execution can never spend twice.
    """
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        replay = connection.execute(
            "SELECT * FROM payments WHERE execution_idempotency_key = ?", (idempotency_key,)
        ).fetchone()
        if replay:
            connection.commit()
            return {**dict(replay), "idempotent_replay": True}, None, "REPLAY"

        payment = connection.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
        if payment is None or payment["status"] not in ("PREPARED", "APPROVAL_PENDING"):
            connection.rollback()
            return None, None, "ALREADY_USED"

        if not approvals.consume_token(connection, token, action_hash):
            connection.rollback()
            return None, None, "ALREADY_USED"

        executed_at = utc_now()
        connection.execute(
            "UPDATE payments SET status = 'EXECUTED', execution_idempotency_key = ?, executed_at = ? WHERE id = ?",
            (idempotency_key, executed_at, payment_id),
        )
        connection.commit()
        before = dict(payment)
        after = {**before, "status": "EXECUTED", "execution_idempotency_key": idempotency_key, "executed_at": executed_at}
        return after, {"table": "payments", "operation": "UPDATE", "before": before, "after": after}, "EXECUTED"
    finally:
        connection.close()
