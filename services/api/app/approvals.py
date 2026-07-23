"""Independent, action-bound, expiring, one-time-use approvals.

Approval material is built only from trusted persisted state. Requests are
single-winner, tokens are signed over the exact run/mandate/payment tuple, and
token consumption is revalidated inside the same SQLite transaction that
executes the payment.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from . import crypto
from .canonical import canonical_bytes, canonical_json, sha256_hex
from .config import APPROVAL_TTL_SECONDS
from .database import connect, rows, utc_now


class ApprovalError(Exception):
    """Raised for invalid approval transitions."""


def bound_payload(mandate_id: str, payment: dict, run_id: str | None = None) -> dict:
    """Canonical action payload used for the approval action hash."""
    return {
        "run_id": run_id,
        "mandate_id": mandate_id,
        "canonical_action": "financial.payment.execute",
        "payment_id": payment["id"],
        "vendor_id": payment["vendor_id"],
        "beneficiary_hash": payment["beneficiary_hash"],
        "amount": int(payment["amount"]),
        "currency": payment["currency"],
    }


def action_hash_for(mandate_id: str, payment: dict, run_id: str | None = None) -> str:
    return sha256_hex(bound_payload(mandate_id, payment, run_id))


def _beneficiary_fingerprint(beneficiary_hash: str) -> str:
    return f"{beneficiary_hash[:8]}…{beneficiary_hash[-4:]}" if beneficiary_hash else ""


def _decorate(record: dict) -> dict:
    record["payload"] = json.loads(record["payload_json"])
    return record


def _request_row(connection: sqlite3.Connection, request_id: str) -> dict | None:
    row = connection.execute("SELECT * FROM approval_requests WHERE id = ?", (request_id,)).fetchone()
    return dict(row) if row else None


def get_request(request_id: str) -> dict | None:
    result = rows("SELECT * FROM approval_requests WHERE id = ?", (request_id,))
    return _decorate(result[0]) if result else None


def list_pending() -> list[dict]:
    return [
        _decorate(record)
        for record in rows("SELECT * FROM approval_requests WHERE status = 'PENDING' ORDER BY created_at")
    ]


def _validate_run_payment_binding(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    mandate_id: str,
    payment_id: str,
) -> tuple[dict, dict]:
    run_row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if run_row is None:
        raise ApprovalError("Approval run not found.")
    run = dict(run_row)
    if run["protection_mode"] != "PROTECTED" or run["mandate_id"] != mandate_id:
        raise ApprovalError("Approval run is not bound to this mandate.")

    payment_row = connection.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    if payment_row is None:
        raise ApprovalError("Approval payment not found.")
    payment = dict(payment_row)
    if payment["mandate_id"] != mandate_id:
        raise ApprovalError("Approval payment is not bound to this mandate.")
    if payment["status"] not in {"PREPARED", "APPROVAL_PENDING"}:
        raise ApprovalError(f"Payment cannot be approved from state {payment['status']}.")
    return run, payment


def create_request(
    *,
    run_id: str | None,
    mandate_id: str,
    payment: dict,
    invoice_id: str | None,
    remaining_budget: int | None,
    source_trust: str,
) -> dict:
    """Create or return the single pending request for an exact action."""
    if not run_id:
        raise ApprovalError("Approval requests require a protected run.")

    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        _, trusted_payment = _validate_run_payment_binding(
            connection,
            run_id=run_id,
            mandate_id=mandate_id,
            payment_id=payment["id"],
        )
        contract = _mandate_contract_in_transaction(connection, mandate_id, utc_now())
        if contract is None:
            raise ApprovalError("Approval mandate is no longer active and valid.")
        if not _payment_matches_contract(trusted_payment, contract):
            raise ApprovalError("Approval payment no longer matches the mandate.")
        action_hash = action_hash_for(mandate_id, trusted_payment, run_id)
        committed = int(
            connection.execute(
                """SELECT COALESCE(SUM(amount), 0) AS total FROM payments
                WHERE mandate_id = ? AND status IN ('PREPARED', 'APPROVAL_PENDING', 'EXECUTED')""",
                (mandate_id,),
            ).fetchone()["total"]
        )
        remaining_budget = max(0, int(contract["max_total_payment"]) - committed)
        existing = connection.execute(
            """SELECT * FROM approval_requests
            WHERE run_id = ? AND mandate_id = ? AND payment_id = ?
              AND action_hash = ? AND status = 'PENDING'""",
            (run_id, mandate_id, trusted_payment["id"], action_hash),
        ).fetchone()
        if existing:
            connection.commit()
            return _decorate(dict(existing))

        request_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(seconds=APPROVAL_TTL_SECONDS)).isoformat()
        display = {
            "vendor_id": trusted_payment["vendor_id"],
            "payment_id": trusted_payment["id"],
            "amount": trusted_payment["amount"],
            "currency": trusted_payment["currency"],
            "beneficiary_fingerprint": _beneficiary_fingerprint(trusted_payment["beneficiary_hash"]),
            "invoice_id": invoice_id,
            "remaining_budget": remaining_budget,
            "source_trust": source_trust,
            "irreversible": True,
            "canonical_action": "financial.payment.execute",
            "action_hash": action_hash,
            "run_id": run_id,
            "mandate_id": mandate_id,
            "expires_at": expires_at,
        }
        connection.execute(
            """INSERT INTO approval_requests
            (id, run_id, mandate_id, payment_id, action_hash, payload_json, status, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)""",
            (
                request_id,
                run_id,
                mandate_id,
                trusted_payment["id"],
                action_hash,
                json.dumps(display),
                expires_at,
                now.isoformat(),
            ),
        )
        connection.execute(
            "UPDATE payments SET status = 'APPROVAL_PENDING' WHERE id = ? AND status = 'PREPARED'",
            (trusted_payment["id"],),
        )
        connection.execute("UPDATE runs SET status = 'AWAITING_APPROVAL' WHERE id = ?", (run_id,))
        connection.commit()
        return get_request(request_id)
    except sqlite3.IntegrityError:
        connection.rollback()
        existing = rows(
            """SELECT * FROM approval_requests
            WHERE run_id = ? AND mandate_id = ? AND payment_id = ? AND status = 'PENDING'""",
            (run_id, mandate_id, payment["id"]),
        )
        if existing:
            return _decorate(existing[0])
        raise
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _token_payload_from_values(
    *,
    approval_request_id: str,
    run_id: str,
    mandate_id: str,
    payment_id: str,
    action_hash: str,
    vendor_id: str,
    beneficiary_hash: str,
    amount: int,
    currency: str,
    nonce: str,
    expires_at: str,
) -> dict:
    return {
        "approval_request_id": approval_request_id,
        "run_id": run_id,
        "mandate_id": mandate_id,
        "payment_id": payment_id,
        "canonical_action": "financial.payment.execute",
        "action_hash": action_hash,
        "vendor_id": vendor_id,
        "beneficiary_hash": beneficiary_hash,
        "amount": int(amount),
        "currency": currency,
        "nonce": nonce,
        "expires_at": expires_at,
    }


def _token_payload_from_row(row: dict) -> dict:
    return _token_payload_from_values(
        approval_request_id=row["approval_request_id"],
        run_id=row["run_id"],
        mandate_id=row["mandate_id"],
        payment_id=row["payment_id"],
        action_hash=row["action_hash"],
        vendor_id=row["vendor_id"],
        beneficiary_hash=row["beneficiary_hash"],
        amount=row["amount"],
        currency=row["currency"],
        nonce=row["nonce"],
        expires_at=row["expires_at"],
    )


def approve(request_id: str, *, now: str | None = None) -> dict:
    """Atomically approve one request and mint exactly one token."""
    now = now or utc_now()
    connection = connect()
    expired = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        request = _request_row(connection, request_id)
        if request is None:
            raise ApprovalError("Approval request not found.")
        if request["status"] != "PENDING":
            raise ApprovalError(f"Approval request is not pending (status={request['status']}).")
        if now >= request["expires_at"]:
            connection.execute(
                "UPDATE approval_requests SET status = 'EXPIRED', decided_at = ? WHERE id = ? AND status = 'PENDING'",
                (now, request_id),
            )
            connection.execute(
                "UPDATE payments SET status = 'CANCELLED' WHERE id = ? AND status IN ('PREPARED', 'APPROVAL_PENDING')",
                (request["payment_id"],),
            )
            if request["run_id"]:
                connection.execute(
                    "UPDATE runs SET status = 'BLOCKED', error = ?, completed_at = ? WHERE id = ? AND status = 'AWAITING_APPROVAL'",
                    ("Approval request expired.", now, request["run_id"]),
                )
            connection.commit()
            expired = True
        else:
            _, payment = _validate_run_payment_binding(
                connection,
                run_id=request["run_id"],
                mandate_id=request["mandate_id"],
                payment_id=request["payment_id"],
            )
            contract = _mandate_contract_in_transaction(connection, request["mandate_id"], now)
            if contract is None:
                raise ApprovalError("Approval mandate is no longer active and valid.")
            if not _payment_matches_contract(payment, contract):
                raise ApprovalError("Approval payment no longer matches the mandate.")
            expected_hash = action_hash_for(request["mandate_id"], payment, request["run_id"])
            if expected_hash != request["action_hash"]:
                raise ApprovalError("Approval request no longer matches the payment.")
            if connection.execute(
                "SELECT 1 FROM approval_tokens WHERE approval_request_id = ?", (request_id,)
            ).fetchone():
                raise ApprovalError("Approval request already minted a token.")

            nonce = secrets.token_hex(16)
            token_id = str(uuid.uuid4())
            payload = _token_payload_from_values(
                approval_request_id=request_id,
                run_id=request["run_id"],
                mandate_id=request["mandate_id"],
                payment_id=payment["id"],
                action_hash=request["action_hash"],
                vendor_id=payment["vendor_id"],
                beneficiary_hash=payment["beneficiary_hash"],
                amount=payment["amount"],
                currency=payment["currency"],
                nonce=nonce,
                expires_at=request["expires_at"],
            )
            token = crypto.sign(canonical_bytes(payload))
            updated = connection.execute(
                "UPDATE approval_requests SET status = 'APPROVED', decided_at = ? WHERE id = ? AND status = 'PENDING'",
                (now, request_id),
            )
            if updated.rowcount != 1:
                raise ApprovalError("Approval request was decided concurrently.")
            connection.execute(
                """INSERT INTO approval_tokens
                (id, approval_request_id, token, action_hash, nonce, expires_at, created_at, consumed_at,
                 run_id, mandate_id, payment_id, vendor_id, beneficiary_hash, amount, currency)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    token_id,
                    request_id,
                    token,
                    request["action_hash"],
                    nonce,
                    request["expires_at"],
                    now,
                    request["run_id"],
                    request["mandate_id"],
                    payment["id"],
                    payment["vendor_id"],
                    payment["beneficiary_hash"],
                    payment["amount"],
                    payment["currency"],
                ),
            )
            connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()

    if expired:
        raise ApprovalError("Approval request has expired.")
    request = get_request(request_id)
    return {
        "request": request,
        "token": token,
        "action_hash": request["action_hash"],
        "payment_id": request["payment_id"],
    }


def reject(request_id: str, *, now: str | None = None) -> dict:
    now = now or utc_now()
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        request = _request_row(connection, request_id)
        if request is None:
            raise ApprovalError("Approval request not found.")
        if request["status"] != "PENDING":
            raise ApprovalError(f"Approval request is not pending (status={request['status']}).")
        if now >= request["expires_at"]:
            status = "EXPIRED"
        else:
            status = "REJECTED"
        updated = connection.execute(
            "UPDATE approval_requests SET status = ?, decided_at = ? WHERE id = ? AND status = 'PENDING'",
            (status, now, request_id),
        )
        if updated.rowcount != 1:
            raise ApprovalError("Approval request was decided concurrently.")
        if request["payment_id"]:
            connection.execute(
                "UPDATE payments SET status = 'CANCELLED' WHERE id = ? AND status IN ('PREPARED', 'APPROVAL_PENDING')",
                (request["payment_id"],),
            )
        if status == "EXPIRED" and request["run_id"]:
            connection.execute(
                "UPDATE runs SET status = 'BLOCKED', error = ?, completed_at = ? WHERE id = ? AND status = 'AWAITING_APPROVAL'",
                ("Approval request expired.", now, request["run_id"]),
            )
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
    result = get_request(request_id)
    if result["status"] == "EXPIRED":
        raise ApprovalError("Approval request has expired.")
    return result


def _token_row(connection: sqlite3.Connection, token: str) -> dict | None:
    row = connection.execute(
        """SELECT t.*, r.status AS request_status,
                  r.run_id AS request_run_id,
                  r.mandate_id AS request_mandate_id,
                  r.payment_id AS request_payment_id,
                  r.action_hash AS request_action_hash
        FROM approval_tokens t
        JOIN approval_requests r ON r.id = t.approval_request_id
        WHERE t.token = ?""",
        (token,),
    ).fetchone()
    return dict(row) if row else None


def verify_token(
    token: str | None,
    expected_action_hash: str,
    *,
    run_id: str | None = None,
    mandate_id: str | None = None,
    payment_id: str | None = None,
    now: str | None = None,
) -> dict:
    """Read-only token snapshot used as OPA input."""
    absent = {
        "present": False,
        "valid": False,
        "expired": False,
        "consumed": False,
        "action_hash_match": False,
        "binding_match": False,
    }
    if not token:
        return absent
    now = now or utc_now()
    with connect() as connection:
        row = _token_row(connection, token)
    if row is None:
        return {**absent, "present": True}
    try:
        signature_valid = crypto.verify(canonical_bytes(_token_payload_from_row(row)), token)
    except (KeyError, TypeError, ValueError):
        signature_valid = False
    action_hash_match = row["action_hash"] == expected_action_hash
    request_binding_match = (
        row["run_id"] == row["request_run_id"]
        and row["mandate_id"] == row["request_mandate_id"]
        and row["payment_id"] == row["request_payment_id"]
        and row["action_hash"] == row["request_action_hash"]
    )
    binding_match = request_binding_match and all(
        expected is None or row[field] == expected
        for field, expected in (
            ("run_id", run_id),
            ("mandate_id", mandate_id),
            ("payment_id", payment_id),
        )
    )
    return {
        "present": True,
        "valid": signature_valid and row["request_status"] == "APPROVED" and binding_match,
        "expired": now >= row["expires_at"],
        "consumed": row["consumed_at"] is not None,
        "action_hash_match": action_hash_match,
        "binding_match": binding_match,
    }


def _mandate_contract_in_transaction(
    connection: sqlite3.Connection, mandate_id: str, now: str
) -> dict | None:
    row = connection.execute("SELECT * FROM mandates WHERE id = ?", (mandate_id,)).fetchone()
    if row is None:
        return None
    record = dict(row)
    if record["status"] != "ACTIVE" or not record["signature"] or not record["public_key"]:
        return None
    if record["expires_at"] and now >= record["expires_at"]:
        return None
    contract = json.loads(record["payload_json"])
    if not crypto.verify(canonical_json(contract).encode("utf-8"), record["signature"], record["public_key"]):
        return None
    return contract


def _payment_matches_contract(payment: dict, contract: dict) -> bool:
    counterparty = next(
        (item for item in contract.get("approved_counterparties", []) if item.get("vendor_id") == payment.get("vendor_id")),
        None,
    )
    return bool(
        counterparty
        and counterparty.get("beneficiary_hash") == payment.get("beneficiary_hash")
        and contract.get("currency") == payment.get("currency")
        and int(payment.get("amount", 0)) <= int(contract.get("max_single_payment", 0))
    )


def _mandate_valid_in_transaction(connection: sqlite3.Connection, mandate_id: str, now: str) -> bool:
    return _mandate_contract_in_transaction(connection, mandate_id, now) is not None


def consume_token_checked(
    connection: sqlite3.Connection,
    token: str | None,
    expected_action_hash: str,
    *,
    run_id: str,
    mandate_id: str,
    payment_id: str,
    now: str | None = None,
) -> str:
    """Validate and consume a token inside the caller's payment transaction."""
    now = now or utc_now()
    if not token:
        return "APPROVAL_INVALID"
    row = _token_row(connection, token)
    if row is None:
        return "APPROVAL_INVALID"
    if row["consumed_at"] is not None:
        return "APPROVAL_ALREADY_USED"
    if now >= row["expires_at"]:
        return "APPROVAL_EXPIRED"
    if row["request_status"] != "APPROVED":
        return "APPROVAL_INVALID"
    if (
        row["run_id"] != run_id
        or row["mandate_id"] != mandate_id
        or row["payment_id"] != payment_id
        or row["action_hash"] != expected_action_hash
        or row["run_id"] != row["request_run_id"]
        or row["mandate_id"] != row["request_mandate_id"]
        or row["payment_id"] != row["request_payment_id"]
        or row["action_hash"] != row["request_action_hash"]
    ):
        return "APPROVAL_INVALID"
    try:
        signature_valid = crypto.verify(canonical_bytes(_token_payload_from_row(row)), token)
    except (KeyError, TypeError, ValueError):
        signature_valid = False
    if not signature_valid:
        return "APPROVAL_INVALID"
    if not _mandate_valid_in_transaction(connection, mandate_id, now):
        return "MANDATE_INACTIVE"
    updated = connection.execute(
        "UPDATE approval_tokens SET consumed_at = ? WHERE token = ? AND consumed_at IS NULL",
        (now, token),
    )
    return "OK" if updated.rowcount == 1 else "APPROVAL_ALREADY_USED"


def consume_token(connection, token: str, expected_action_hash: str) -> bool:
    """Compatibility wrapper for older internal callers."""
    row = _token_row(connection, token)
    if row is None:
        return False
    return (
        consume_token_checked(
            connection,
            token,
            expected_action_hash,
            run_id=row["run_id"],
            mandate_id=row["mandate_id"],
            payment_id=row["payment_id"],
        )
        == "OK"
    )
