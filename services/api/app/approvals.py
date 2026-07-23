"""Independent, action-bound, expiring, one-time-use approvals.

An approval request is built by the trusted backend from persisted state — never
from agent-authored text. Granting it mints a short-lived Ed25519 token bound to
a SHA-256 hash of the exact financial action. The token is consumed atomically
with execution, so one token authorizes exactly one payment execution.
"""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from . import crypto
from .canonical import canonical_bytes, sha256_hex
from .config import APPROVAL_TTL_SECONDS
from .database import connect, rows, utc_now


class ApprovalError(Exception):
    """Raised for invalid approval transitions."""


def bound_payload(mandate_id: str, payment: dict) -> dict:
    """Canonical action-bound payload hashed into the approval action hash.

    Built only from trusted persisted fields (the prepared payment row and the
    mandate), so the hash cannot be influenced by agent-supplied arguments.
    """
    return {
        "mandate_id": mandate_id,
        "canonical_action": "financial.payment.execute",
        "payment_id": payment["id"],
        "vendor_id": payment["vendor_id"],
        "beneficiary_hash": payment["beneficiary_hash"],
        "amount": payment["amount"],
        "currency": payment["currency"],
    }


def action_hash_for(mandate_id: str, payment: dict) -> str:
    return sha256_hex(bound_payload(mandate_id, payment))


def _beneficiary_fingerprint(beneficiary_hash: str) -> str:
    return f"{beneficiary_hash[:8]}…{beneficiary_hash[-4:]}" if beneficiary_hash else ""


# --------------------------------------------------------------------------- #
# Request creation (trusted structured data only)
# --------------------------------------------------------------------------- #
def create_request(
    *,
    run_id: str | None,
    mandate_id: str,
    payment: dict,
    invoice_id: str | None,
    remaining_budget: int | None,
    source_trust: str,
) -> dict:
    request_id = str(uuid.uuid4())
    action_hash = action_hash_for(mandate_id, payment)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=APPROVAL_TTL_SECONDS)).isoformat()
    # Human-facing display payload — no secret values ever appear here.
    display = {
        "vendor_id": payment["vendor_id"],
        "payment_id": payment["id"],
        "amount": payment["amount"],
        "currency": payment["currency"],
        "beneficiary_fingerprint": _beneficiary_fingerprint(payment["beneficiary_hash"]),
        "invoice_id": invoice_id,
        "remaining_budget": remaining_budget,
        "source_trust": source_trust,
        "irreversible": True,
        "canonical_action": "financial.payment.execute",
        "action_hash": action_hash,
        "mandate_id": mandate_id,
        "expires_at": expires_at,
    }
    with connect() as connection:
        connection.execute(
            """INSERT INTO approval_requests
            (id, run_id, mandate_id, payment_id, action_hash, payload_json, status, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)""",
            (request_id, run_id, mandate_id, payment["id"], action_hash, json.dumps(display), expires_at, now.isoformat()),
        )
    return get_request(request_id)


def _decorate(record: dict) -> dict:
    record["payload"] = json.loads(record["payload_json"])
    return record


def get_request(request_id: str) -> dict | None:
    result = rows("SELECT * FROM approval_requests WHERE id = ?", (request_id,))
    return _decorate(result[0]) if result else None


def list_pending() -> list[dict]:
    return [_decorate(r) for r in rows("SELECT * FROM approval_requests WHERE status = 'PENDING' ORDER BY created_at")]


# --------------------------------------------------------------------------- #
# Grant / reject
# --------------------------------------------------------------------------- #
def _token_payload(approval_request_id: str, action_hash: str, nonce: str, expires_at: str) -> dict:
    return {
        "approval_request_id": approval_request_id,
        "action_hash": action_hash,
        "nonce": nonce,
        "expires_at": expires_at,
    }


def approve(request_id: str) -> dict:
    """Mark the request approved and mint a one-use token. Trusted action."""
    record = get_request(request_id)
    if record is None:
        raise ApprovalError("Approval request not found.")
    if record["status"] != "PENDING":
        raise ApprovalError(f"Approval request is not pending (status={record['status']}).")

    now = datetime.now(timezone.utc)
    expires_at = record["expires_at"]
    nonce = secrets.token_hex(16)
    token_id = str(uuid.uuid4())
    payload = _token_payload(request_id, record["action_hash"], nonce, expires_at)
    token = crypto.sign(canonical_bytes(payload))

    with connect() as connection:
        connection.execute(
            """INSERT INTO approval_tokens
            (id, approval_request_id, token, action_hash, nonce, expires_at, created_at, consumed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
            (token_id, request_id, token, record["action_hash"], nonce, expires_at, now.isoformat()),
        )
        connection.execute(
            "UPDATE approval_requests SET status = 'APPROVED', decided_at = ? WHERE id = ?",
            (now.isoformat(), request_id),
        )
    return {"request": get_request(request_id), "token": token, "action_hash": record["action_hash"], "payment_id": record["payment_id"]}


def reject(request_id: str) -> dict:
    record = get_request(request_id)
    if record is None:
        raise ApprovalError("Approval request not found.")
    if record["status"] != "PENDING":
        raise ApprovalError(f"Approval request is not pending (status={record['status']}).")
    with connect() as connection:
        connection.execute(
            "UPDATE approval_requests SET status = 'REJECTED', decided_at = ? WHERE id = ?",
            (utc_now(), request_id),
        )
        # Release the reservation: the prepared payment is cancelled.
        if record["payment_id"]:
            connection.execute(
                "UPDATE payments SET status = 'CANCELLED' WHERE id = ? AND status IN ('PREPARED', 'APPROVAL_PENDING')",
                (record["payment_id"],),
            )
    return get_request(request_id)


# --------------------------------------------------------------------------- #
# Token verification (read-only, for policy input) + atomic consumption
# --------------------------------------------------------------------------- #
def _token_row(connection, token: str) -> dict | None:
    result = connection.execute("SELECT * FROM approval_tokens WHERE token = ?", (token,)).fetchone()
    return dict(result) if result else None


def verify_token(token: str | None, expected_action_hash: str, now: str | None = None) -> dict:
    """Snapshot of token binding for policy input. Never consumes."""
    absent = {"present": False, "valid": False, "expired": False, "consumed": False, "action_hash_match": False}
    if not token:
        return absent
    now = now or utc_now()
    with connect() as connection:
        row = _token_row(connection, token)
    if row is None:
        return absent
    payload = _token_payload(row["approval_request_id"], row["action_hash"], row["nonce"], row["expires_at"])
    signature_valid = crypto.verify(canonical_bytes(payload), token)
    action_hash_match = row["action_hash"] == expected_action_hash
    return {
        "present": True,
        "valid": signature_valid,
        "expired": now >= row["expires_at"],
        "consumed": row["consumed_at"] is not None,
        "action_hash_match": action_hash_match,
    }


def consume_token(connection, token: str, expected_action_hash: str) -> bool:
    """Atomically consume a token inside the caller's transaction.

    Returns True only if the token existed unconsumed, matched the action hash,
    and was marked consumed by this call. Concurrent execution therefore cannot
    consume the same token twice.
    """
    row = _token_row(connection, token)
    if row is None or row["consumed_at"] is not None or row["action_hash"] != expected_action_hash:
        return False
    cursor = connection.execute(
        "UPDATE approval_tokens SET consumed_at = ? WHERE token = ? AND consumed_at IS NULL",
        (utc_now(), token),
    )
    return cursor.rowcount == 1
