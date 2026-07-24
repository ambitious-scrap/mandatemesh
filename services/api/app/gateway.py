"""Protected tool-call gateway, the single enforcement point.

Every protected call is bound to trusted run state, normalized, decided by OPA,
and revalidated transactionally before any consequential side effect. The
transactional checks close time-of-check/time-of-use gaps in cumulative budgets,
payment ownership, approval expiry, and one-time token consumption.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid

from . import actions, approvals, crypto, evidence, mandates, memory, policy
from .canonical import canonical_json, sha256_hex
from .database import connect, rows, utc_now
from .events import record_event
from .tools import ToolError, execute_tool

_CONSEQUENTIAL = actions.SIDE_EFFECTING


def committed_amount(mandate_id: str, connection: sqlite3.Connection | None = None) -> int:
    """Reserved plus executed spend, counting each payment row exactly once."""
    query = """SELECT COALESCE(SUM(amount), 0) AS total FROM payments
        WHERE mandate_id = ? AND status IN ('PREPARED', 'APPROVAL_PENDING', 'EXECUTED')"""
    if connection is not None:
        return int(connection.execute(query, (mandate_id,)).fetchone()["total"])
    result = rows(query, (mandate_id,))
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


def _load_run(run_id: str) -> dict | None:
    result = rows("SELECT * FROM runs WHERE id = ?", (run_id,))
    return result[0] if result else None


def _load_payment(payment_id: str | None) -> dict | None:
    if not payment_id:
        return None
    result = rows("SELECT * FROM payments WHERE id = ?", (payment_id,))
    return result[0] if result else None


def _block(
    *,
    run_id: str,
    mandate_id: str | None,
    reason_code: str,
    message: str,
    source_ref: str | None,
    tool_name: str,
    arguments: dict,
    canonical: dict | None = None,
    policy_version: str | None = None,
    started: float | None = None,
    policy_input: dict | None = None,
    before_state: dict | None = None,
    after_state: dict | None = None,
) -> dict:
    decision = _synthetic_block(reason_code, message)
    if after_state is None:
        after_state = evidence.snapshot_resource(tool_name, arguments)
    latency = round((time.perf_counter() - started) * 1000, 3) if started is not None else None
    event = record_event(
        run_id,
        "TOOL_BLOCKED",
        actor="gateway",
        mandate_id=mandate_id,
        source_ref=source_ref,
        tool_name=tool_name,
        tool_arguments=arguments,
        canonical_action=canonical,
        decision=decision,
        policy_input=policy_input,
        before_state=before_state,
        after_state=after_state,
        policy_version=policy_version,
        is_forbidden=True,
        latency_ms=latency,
    )
    if _load_run(run_id):
        _bump_blocked(run_id)
    return {"decision": decision, "tool_result": None, "event_id": event["id"]}


def _active_contract_in_transaction(
    connection: sqlite3.Connection, mandate_id: str, now: str
) -> tuple[dict | None, str | None]:
    row = connection.execute("SELECT * FROM mandates WHERE id = ?", (mandate_id,)).fetchone()
    if row is None:
        return None, "MANDATE_INACTIVE"
    record = dict(row)
    contract = json.loads(record["payload_json"])
    if not record["signature"] or not record["public_key"]:
        return None, "MANDATE_SIGNATURE_INVALID"
    if not crypto.verify(canonical_json(contract).encode("utf-8"), record["signature"], record["public_key"]):
        return None, "MANDATE_SIGNATURE_INVALID"
    if record["status"] != "ACTIVE":
        return None, "MANDATE_INACTIVE"
    if record["expires_at"] and now >= record["expires_at"]:
        return None, "MANDATE_EXPIRED"
    return contract, None


def _same_prepare_action(existing: dict, mandate_id: str, arguments: dict) -> bool:
    try:
        amount = int(arguments.get("amount"))
    except (TypeError, ValueError):
        return False
    return (
        existing.get("mandate_id") == mandate_id
        and existing.get("invoice_id") == arguments.get("invoice_id")
        and existing.get("vendor_id") == arguments.get("vendor_id")
        and existing.get("beneficiary_hash") == arguments.get("beneficiary_hash")
        and int(existing.get("amount", 0)) == amount
        and existing.get("currency") == arguments.get("currency")
    )


def _payment_contract_violation(payment: dict, contract: dict) -> tuple[str, str] | None:
    counterpart = next(
        (
            item
            for item in contract.get("approved_counterparties", [])
            if item.get("vendor_id") == payment.get("vendor_id")
        ),
        None,
    )
    if counterpart is None:
        return "VENDOR_NOT_APPROVED", "Payment vendor is not approved by the mandate."
    if counterpart.get("beneficiary_hash") != payment.get("beneficiary_hash"):
        return "BENEFICIARY_MISMATCH", "Payment beneficiary no longer matches the mandate."
    if payment.get("currency") != contract.get("currency"):
        return "CURRENCY_MISMATCH", "Payment currency no longer matches the mandate."
    try:
        amount = int(payment.get("amount"))
    except (TypeError, ValueError):
        return "ACTION_NOT_ALLOWED", "Payment amount must be an integer."
    if amount <= 0:
        return "ACTION_NOT_ALLOWED", "Payment amount must be positive."
    if amount > int(contract.get("max_single_payment", 0)):
        return "SINGLE_PAYMENT_LIMIT_EXCEEDED", "Payment exceeds the mandate's single-payment limit."
    return None


def execute(
    run_id: str,
    mandate_id: str,
    tool_name: str,
    arguments: dict,
    *,
    source_ref: str | None = None,
    approval_token: str | None = None,
    idempotency_key: str | None = None,
    transport: str = "REST",
) -> dict:
    started = time.perf_counter()

    run = _load_run(run_id)
    if run is None:
        return _block(
            run_id=run_id,
            mandate_id=mandate_id,
            reason_code="RUN_NOT_FOUND",
            message="Protected run does not exist.",
            source_ref=source_ref,
            tool_name=tool_name,
            arguments=arguments,
            started=started,
        )
    if run["protection_mode"] != "PROTECTED":
        return _block(
            run_id=run_id,
            mandate_id=mandate_id,
            reason_code="RUN_NOT_PROTECTED",
            message="Unprotected runs cannot use the protected gateway.",
            source_ref=source_ref,
            tool_name=tool_name,
            arguments=arguments,
            started=started,
        )
    if run["mandate_id"] != mandate_id:
        return _block(
            run_id=run_id,
            mandate_id=mandate_id,
            reason_code="RUN_MANDATE_MISMATCH",
            message="Run is not bound to the supplied mandate.",
            source_ref=source_ref,
            tool_name=tool_name,
            arguments=arguments,
            started=started,
        )

    mandate = mandates.get_mandate(mandate_id) if mandate_id else None
    if mandate is None:
        return _block(
            run_id=run_id,
            mandate_id=mandate_id,
            reason_code="MANDATE_INACTIVE",
            message="No mandate is bound to this action.",
            source_ref=source_ref,
            tool_name=tool_name,
            arguments=arguments,
            started=started,
        )
    verification = mandates.verification_for(mandate)
    contract = mandate["contract"]

    canonical = actions.build_canonical_action(
        tool_name,
        arguments,
        source_ref=source_ref,
        mandate_id=mandate_id,
        task_state={"committed_amount": committed_amount(mandate_id)},
        idempotency_key=idempotency_key,
        transport=transport,
    )
    if canonical is None:
        return _block(
            run_id=run_id,
            mandate_id=mandate_id,
            reason_code="ACTION_NOT_ALLOWED",
            message=f"Unknown tool: {tool_name}.",
            source_ref=source_ref,
            tool_name=tool_name,
            arguments=arguments,
            started=started,
        )

    canonical_action = canonical["canonical_action"]
    before_state = evidence.snapshot_resource(tool_name, arguments)
    if canonical_action == "financial.payment.prepare":
        required = ("invoice_id", "vendor_id", "beneficiary_hash", "amount", "currency")
        missing = [name for name in required if arguments.get(name) in (None, "")]
        if missing:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="ACTION_NOT_ALLOWED",
                message=f"Missing required payment fields: {', '.join(missing)}.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        try:
            normalized_amount = int(arguments["amount"])
        except (TypeError, ValueError):
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="ACTION_NOT_ALLOWED",
                message="Payment amount must be an integer.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        if normalized_amount <= 0:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="ACTION_NOT_ALLOWED",
                message="Payment amount must be positive.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        canonical["resource"]["amount"] = normalized_amount

    if canonical_action in _CONSEQUENTIAL:
        if not idempotency_key:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="IDEMPOTENCY_KEY_REQUIRED",
                message="Side-effecting action requires an idempotency key.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        if arguments.get("idempotency_key") != idempotency_key:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="IDEMPOTENCY_KEY_MISMATCH",
                message="Gateway and tool idempotency keys do not match.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )

    committed_for_policy = committed_amount(mandate_id)
    if canonical_action == "financial.payment.prepare" and idempotency_key:
        existing_rows = rows("SELECT * FROM payments WHERE idempotency_key = ?", (idempotency_key,))
        if existing_rows and _same_prepare_action(existing_rows[0], mandate_id, arguments):
            # An exact idempotent replay reserves no new budget. OPA still sees
            # and decides the call, but evaluates the pre-original reservation.
            committed_for_policy = max(0, committed_for_policy - int(existing_rows[0]["amount"]))
    canonical["task_state"]["committed_amount"] = committed_for_policy

    payment = None
    action_hash = sha256_hex(canonical["resource"])
    approval_snapshot = {
        "present": False,
        "valid": False,
        "expired": False,
        "consumed": False,
        "action_hash_match": False,
        "binding_match": False,
    }
    if canonical_action == "financial.payment.execute":
        payment = _load_payment(arguments.get("payment_id"))
        if payment is None:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="PAYMENT_STATE_INVALID",
                message=f"Prepared payment not found: {arguments.get('payment_id')}.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        if payment.get("mandate_id") != mandate_id:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="PAYMENT_MANDATE_MISMATCH",
                message="Payment is not bound to this mandate.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        if payment["status"] not in {"PREPARED", "APPROVAL_PENDING"} and not (
            payment["status"] == "EXECUTED" and approval_token
        ):
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="PAYMENT_STATE_INVALID",
                message=f"Payment cannot execute from state {payment['status']}.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        violation = _payment_contract_violation(payment, contract)
        if violation:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code=violation[0],
                message=violation[1],
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                started=started,
            )
        canonical["resource"] = {
            "payment_id": payment["id"],
            "vendor_id": payment["vendor_id"],
            "beneficiary_hash": payment["beneficiary_hash"],
            "amount": payment["amount"],
            "currency": payment["currency"],
        }
        action_hash = approvals.action_hash_for(mandate_id, payment, run_id)
        approval_snapshot = approvals.verify_token(
            approval_token,
            action_hash,
            run_id=run_id,
            mandate_id=mandate_id,
            payment_id=payment["id"],
        )

    canonical["action_hash"] = action_hash
    record_event(
        run_id,
        "ACTION_NORMALIZED",
        actor="gateway",
        mandate_id=mandate_id,
        source_ref=source_ref,
        tool_name=tool_name,
        tool_arguments=arguments,
        canonical_action=canonical,
    )

    policy_input = {
        "verification": {key: verification[key] for key in ("signature_valid", "mandate_status", "expired", "now")},
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
        "task_state": {"committed_amount": committed_for_policy},
        "approval": approval_snapshot,
    }

    policy_started = time.perf_counter()
    decision = policy.query_decision(policy_input)
    policy_latency = round((time.perf_counter() - policy_started) * 1000, 3)
    policy_version = decision.get("policy_version")
    record_event(
        run_id,
        "POLICY_DECIDED",
        actor="gateway",
        mandate_id=mandate_id,
        source_ref=source_ref,
        tool_name=tool_name,
        tool_arguments=arguments,
        canonical_action=canonical,
        decision=decision,
        policy_input=policy_input,
        before_state=before_state,
        after_state=evidence.snapshot_resource(tool_name, arguments),
        policy_version=policy_version,
        latency_ms=policy_latency,
    )

    if decision["decision"] == "REQUIRE_APPROVAL":
        return _require_approval(
            run_id, mandate_id, canonical, payment, source_ref, decision, policy_version,
            policy_input=policy_input, before_state=before_state,
        )
    if decision["decision"] != "ALLOW":
        quarantine = None
        if (
            canonical_action == "memory.financial_instruction.write"
            and decision.get("reason_code") == "MEMORY_WRITE_FORBIDDEN"
        ):
            try:
                quarantine, quarantine_effect = memory.quarantine_attempt(
                    run_id=run_id,
                    mandate_id=mandate_id,
                    arguments=arguments,
                    reason_code=decision["reason_code"],
                )
                record_event(
                    run_id,
                    "MEMORY_QUARANTINED",
                    actor="gateway",
                    mandate_id=mandate_id,
                    source_ref=source_ref,
                    tool_name=tool_name,
                    tool_arguments=arguments,
                    canonical_action=canonical,
                    decision=decision,
                    side_effect=quarantine_effect,
                    policy_input=policy_input,
                    before_state=before_state,
                    after_state=evidence.snapshot_resource(tool_name, arguments),
                    policy_version=policy_version,
                    is_forbidden=True,
                )
            except memory.MemoryError as error:
                # Quarantine is evidence preservation, never an authorization
                # fallback. The original policy BLOCK remains authoritative.
                record_event(
                    run_id,
                    "MEMORY_QUARANTINE_FAILED",
                    actor="gateway",
                    mandate_id=mandate_id,
                    source_ref=source_ref,
                    tool_name=tool_name,
                    tool_arguments=arguments,
                    canonical_action=canonical,
                    decision=decision,
                    tool_result={"error": str(error)},
                    policy_version=policy_version,
                    is_forbidden=True,
                )
        latency = round((time.perf_counter() - started) * 1000, 3)
        event = record_event(
            run_id,
            "TOOL_BLOCKED",
            actor="gateway",
            mandate_id=mandate_id,
            source_ref=source_ref,
            tool_name=tool_name,
            tool_arguments=arguments,
            canonical_action=canonical,
            decision=decision,
            policy_input=policy_input,
            before_state=before_state,
            after_state=evidence.snapshot_resource(tool_name, arguments),
            policy_version=policy_version,
            is_forbidden=True,
            latency_ms=latency,
        )
        _bump_blocked(run_id)
        return {
            "decision": decision,
            "tool_result": None,
            "event_id": event["id"],
            "quarantine": quarantine,
        }

    return _execute_allowed(
        run_id,
        mandate_id,
        tool_name,
        arguments,
        canonical,
        payment,
        action_hash,
        approval_token,
        idempotency_key,
        source_ref,
        decision,
        policy_version,
        started,
        policy_input,
        before_state,
    )


def _require_approval(
    run_id: str,
    mandate_id: str,
    canonical: dict,
    payment: dict | None,
    source_ref: str | None,
    decision: dict,
    policy_version: str | None,
    *,
    policy_input: dict | None = None,
    before_state: dict | None = None,
) -> dict:
    if payment is None:
        return _block(
            run_id=run_id,
            mandate_id=mandate_id,
            reason_code="PAYMENT_STATE_INVALID",
            message="Approval requested without a prepared payment.",
            source_ref=source_ref,
            tool_name=canonical["tool_name"],
            arguments=canonical["arguments"],
            canonical=canonical,
            policy_version=policy_version,
            policy_input=policy_input,
            before_state=before_state,
        )
    contract = mandates.get_mandate(mandate_id)["contract"]
    remaining = contract["max_total_payment"] - committed_amount(mandate_id)
    try:
        request = approvals.create_request(
            run_id=run_id,
            mandate_id=mandate_id,
            payment=payment,
            invoice_id=payment["invoice_id"],
            remaining_budget=remaining,
            source_trust=canonical["provenance"]["source_trust"],
        )
    except approvals.ApprovalError as error:
        return _block(
            run_id=run_id,
            mandate_id=mandate_id,
            reason_code="APPROVAL_INVALID",
            message=str(error),
            source_ref=source_ref,
            tool_name=canonical["tool_name"],
            arguments=canonical["arguments"],
            canonical=canonical,
            policy_version=policy_version,
            policy_input=policy_input,
            before_state=before_state,
        )
    event = record_event(
        run_id,
        "APPROVAL_REQUESTED",
        actor="gateway",
        mandate_id=mandate_id,
        source_ref=source_ref,
        tool_name=canonical["tool_name"],
        canonical_action=canonical,
        decision=decision,
        policy_input=policy_input,
        before_state=before_state,
        after_state=evidence.snapshot_resource(canonical["tool_name"], canonical["arguments"]),
        policy_version=policy_version,
        tool_result={"approval_request_id": request["id"], "action_hash": request["action_hash"]},
    )
    return {
        "decision": decision,
        "tool_result": None,
        "event_id": event["id"],
        "approval_request_id": request["id"],
    }


def _prepare_payment_transactionally(
    mandate_id: str,
    arguments: dict,
    idempotency_key: str,
) -> tuple[dict | None, dict | None, tuple[str, str] | None]:
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        now = utc_now()
        contract, mandate_error = _active_contract_in_transaction(connection, mandate_id, now)
        if mandate_error:
            connection.rollback()
            return None, None, (mandate_error, "Mandate is no longer valid.")

        try:
            amount = int(arguments.get("amount"))
        except (TypeError, ValueError):
            connection.rollback()
            return None, None, ("ACTION_NOT_ALLOWED", "Payment amount must be an integer.")

        existing_row = connection.execute(
            "SELECT * FROM payments WHERE idempotency_key = ?", (idempotency_key,)
        ).fetchone()
        if existing_row:
            existing = dict(existing_row)
            connection.commit()
            if _same_prepare_action(existing, mandate_id, arguments):
                return {**existing, "idempotent_replay": True}, None, None
            return None, None, ("IDEMPOTENCY_KEY_CONFLICT", "Idempotency key belongs to a different payment action.")
        if amount <= 0:
            connection.rollback()
            return None, None, ("ACTION_NOT_ALLOWED", "Payment amount must be positive.")

        candidate = {
            "vendor_id": arguments.get("vendor_id"),
            "beneficiary_hash": arguments.get("beneficiary_hash"),
            "amount": amount,
            "currency": arguments.get("currency"),
        }
        violation = _payment_contract_violation(candidate, contract)
        if violation:
            connection.rollback()
            return None, None, violation

        vendor = connection.execute(
            "SELECT approved, bank_account_hash FROM vendors WHERE id = ?", (candidate["vendor_id"],)
        ).fetchone()
        if vendor is None or not bool(vendor["approved"]):
            connection.rollback()
            return None, None, ("VENDOR_NOT_APPROVED", "Trusted vendor record is not approved.")
        if vendor["bank_account_hash"] != candidate["beneficiary_hash"]:
            connection.rollback()
            return None, None, ("BENEFICIARY_MISMATCH", "Trusted vendor record does not match the beneficiary.")

        total = committed_amount(mandate_id, connection)
        if total + amount > int(contract["max_total_payment"]):
            connection.rollback()
            return None, None, ("TOTAL_BUDGET_EXCEEDED", "Concurrent reservation would exceed the mandate budget.")

        payment = {
            "id": f"PAY-{uuid.uuid4().hex[:10].upper()}",
            "mandate_id": mandate_id,
            "invoice_id": arguments.get("invoice_id"),
            "vendor_id": candidate["vendor_id"],
            "beneficiary_hash": candidate["beneficiary_hash"],
            "amount": amount,
            "currency": candidate["currency"],
            "status": "PREPARED",
            "idempotency_key": idempotency_key,
            "created_at": now,
            "executed_at": None,
        }
        connection.execute(
            """INSERT INTO payments
            (id, mandate_id, invoice_id, vendor_id, beneficiary_hash, amount, currency,
             status, idempotency_key, created_at, executed_at)
            VALUES (:id, :mandate_id, :invoice_id, :vendor_id, :beneficiary_hash, :amount, :currency,
                    :status, :idempotency_key, :created_at, :executed_at)""",
            payment,
        )
        connection.commit()
        return payment, {"table": "payments", "operation": "INSERT", "record": payment}, None
    except sqlite3.IntegrityError as error:
        connection.rollback()
        return None, None, ("IDEMPOTENCY_KEY_CONFLICT", f"Payment reservation conflict: {error}.")
    finally:
        connection.close()


def _execute_allowed(
    run_id: str,
    mandate_id: str,
    tool_name: str,
    arguments: dict,
    canonical: dict,
    payment: dict | None,
    action_hash: str,
    approval_token: str | None,
    idempotency_key: str,
    source_ref: str | None,
    decision: dict,
    policy_version: str | None,
    started: float,
    policy_input: dict | None,
    before_state: dict | None,
) -> dict:
    canonical_action = canonical["canonical_action"]
    if canonical_action == "financial.payment.execute":
        result, side_effect, outcome = _execute_payment(
            payment["id"],
            approval_token,
            action_hash,
            idempotency_key,
            run_id=run_id,
            mandate_id=mandate_id,
        )
        if outcome not in {"EXECUTED", "REPLAY"}:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code=outcome,
                message="Payment execution failed its transactional authorization checks.",
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                policy_version=policy_version,
                started=started,
                policy_input=policy_input,
                before_state=before_state,
            )
    elif canonical_action == "financial.payment.prepare":
        result, side_effect, failure = _prepare_payment_transactionally(
            mandate_id, arguments, idempotency_key
        )
        if failure:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code=failure[0],
                message=failure[1],
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                policy_version=policy_version,
                started=started,
                policy_input=policy_input,
                before_state=before_state,
            )
    else:
        try:
            result, side_effect = execute_tool(tool_name, arguments)
        except ToolError as error:
            return _block(
                run_id=run_id,
                mandate_id=mandate_id,
                reason_code="ACTION_NOT_ALLOWED",
                message=str(error),
                source_ref=source_ref,
                tool_name=tool_name,
                arguments=arguments,
                canonical=canonical,
                policy_version=policy_version,
                started=started,
                policy_input=policy_input,
                before_state=before_state,
            )

    latency = round((time.perf_counter() - started) * 1000, 3)
    public_result = _redact(tool_name, result)
    event = record_event(
        run_id,
        "TOOL_EXECUTED",
        actor="gateway",
        mandate_id=mandate_id,
        source_ref=source_ref,
        tool_name=tool_name,
        tool_arguments=arguments,
        canonical_action=canonical,
        tool_result={"ok": True, "data": public_result},
        side_effect=side_effect,
        decision=decision,
        policy_input=policy_input,
        before_state=before_state,
        after_state=evidence.snapshot_resource(tool_name, arguments),
        policy_version=policy_version,
        latency_ms=latency,
    )
    if side_effect:
        record_event(
            run_id,
            "SIDE_EFFECT_RECORDED",
            actor="gateway",
            mandate_id=mandate_id,
            source_ref=source_ref,
            tool_name=tool_name,
            canonical_action=canonical,
            side_effect=side_effect,
            policy_input=policy_input,
            before_state=before_state,
            after_state=evidence.snapshot_resource(tool_name, arguments),
            policy_version=policy_version,
        )
    return {"decision": decision, "tool_result": public_result, "event_id": event["id"]}


def _execute_payment(
    payment_id: str,
    token: str | None,
    action_hash: str,
    idempotency_key: str,
    *,
    run_id: str | None = None,
    mandate_id: str | None = None,
    now: str | None = None,
):
    """Consume approval and execute payment atomically.

    The four positional arguments remain compatible with the Level 1 test suite;
    hardened callers additionally pass trusted run and mandate identifiers.
    """
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        replay_row = connection.execute(
            "SELECT * FROM payments WHERE execution_idempotency_key = ?", (idempotency_key,)
        ).fetchone()
        if replay_row:
            replay = dict(replay_row)
            if replay["id"] != payment_id or (mandate_id and replay["mandate_id"] != mandate_id):
                connection.rollback()
                return None, None, "IDEMPOTENCY_KEY_CONFLICT"
            connection.commit()
            return {**replay, "idempotent_replay": True}, None, "REPLAY"

        payment_row = connection.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
        if payment_row is None:
            connection.rollback()
            return None, None, "PAYMENT_STATE_INVALID"
        payment = dict(payment_row)
        mandate_id = mandate_id or payment.get("mandate_id")
        if not mandate_id or payment.get("mandate_id") != mandate_id:
            connection.rollback()
            return None, None, "PAYMENT_MANDATE_MISMATCH"
        if payment["status"] not in {"PREPARED", "APPROVAL_PENDING"}:
            connection.rollback()
            return None, None, "PAYMENT_STATE_INVALID"

        now = now or utc_now()
        contract, mandate_error = _active_contract_in_transaction(connection, mandate_id, now)
        if mandate_error:
            connection.rollback()
            return None, None, mandate_error
        violation = _payment_contract_violation(payment, contract)
        if violation:
            connection.rollback()
            return None, None, violation[0]

        if run_id is None and token:
            token_row = connection.execute(
                "SELECT run_id FROM approval_tokens WHERE token = ?", (token,)
            ).fetchone()
            run_id = token_row["run_id"] if token_row else None
        if not run_id:
            connection.rollback()
            return None, None, "APPROVAL_INVALID"
        expected_hash = approvals.action_hash_for(mandate_id, payment, run_id)
        if expected_hash != action_hash:
            connection.rollback()
            return None, None, "APPROVAL_INVALID"

        outcome = approvals.consume_token_checked(
            connection,
            token,
            expected_hash,
            run_id=run_id,
            mandate_id=mandate_id,
            payment_id=payment_id,
            now=now,
        )
        if outcome != "OK":
            connection.rollback()
            return None, None, outcome

        executed_at = now
        updated = connection.execute(
            """UPDATE payments
            SET status = 'EXECUTED', execution_idempotency_key = ?, executed_at = ?
            WHERE id = ? AND mandate_id = ? AND status IN ('PREPARED', 'APPROVAL_PENDING')""",
            (idempotency_key, executed_at, payment_id, mandate_id),
        )
        if updated.rowcount != 1:
            connection.rollback()
            return None, None, "PAYMENT_STATE_INVALID"
        connection.commit()
        before = payment
        after = {
            **before,
            "status": "EXECUTED",
            "execution_idempotency_key": idempotency_key,
            "executed_at": executed_at,
        }
        return after, {"table": "payments", "operation": "UPDATE", "before": before, "after": after}, "EXECUTED"
    finally:
        connection.close()
