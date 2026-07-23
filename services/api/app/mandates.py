"""Mandate lifecycle: compile -> confirm -> sign -> verify.

A mandate is the typed, signed, time-bound authority the human grants for a
task. AI may *propose* a mandate; it can never activate or sign one. The signed
material is the canonical JSON of the contract fields only — the Ed25519
signature is stored separately and is never part of the signed payload.

Lifecycle statuses: DRAFT -> ACTIVE -> {EXPIRED, COMPLETED, REVOKED}.
"""
from __future__ import annotations

import json
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from . import crypto
from .canonical import canonical_json, sha256_hex
from .config import MANDATE_TTL_SECONDS
from .database import APPROVED_VENDOR, connect, rows, utc_now

# Canonical action authority for the accounts-payable MVP task.
DEFAULT_ALLOWED_ACTIONS = [
    "document.invoice.read",
    "vendor.record.lookup",
    "financial.payment.prepare",
    "financial.payment.execute",
]
DEFAULT_FORBIDDEN_ACTIONS = [
    "vendor.record.create",
    "secret.value.read",
    "memory.financial_instruction.write",
]

DEFAULT_MAX_SINGLE = 50000
DEFAULT_MAX_TOTAL = 80000
DEFAULT_CURRENCY = "INR"

# Contract fields (payload) do NOT include the signature. TRANSIENT_FIELDS in
# canonical.py further guarantee no signature/timestamp leaks into signed bytes.
_AMOUNT_RE = re.compile(r"₹\s*([\d,]+)")


class MandateError(Exception):
    """Raised for invalid lifecycle transitions."""


# --------------------------------------------------------------------------- #
# Compilation (proposal only — never authoritative)
# --------------------------------------------------------------------------- #
def _parse_amount(text: str, default: int) -> tuple[int, bool]:
    match = _AMOUNT_RE.search(text)
    if not match:
        return default, True
    try:
        return int(match.group(1).replace(",", "")), False
    except ValueError:
        return default, True


def _propose_contract(task: str) -> tuple[dict, list[str], list[str]]:
    """Deterministic compiler for the accounts-payable task.

    Conservative defaults: approval always required, the three financial-risk
    actions always forbidden, and unresolved amounts fall back to the MVP limits
    with an explicit warning so the human reviews them.
    """
    warnings: list[str] = []
    ambiguous: list[str] = []

    amounts = [int(a.replace(",", "")) for a in _AMOUNT_RE.findall(task)]
    if len(amounts) >= 2:
        max_single, max_total = amounts[0], amounts[1]
    elif len(amounts) == 1:
        max_single = amounts[0]
        max_total = DEFAULT_MAX_TOTAL
        warnings.append("Only one amount detected in the task; total budget defaulted to the conservative limit.")
        ambiguous.append("max_total_payment")
    else:
        max_single, max_total = DEFAULT_MAX_SINGLE, DEFAULT_MAX_TOTAL
        warnings.append("No amounts detected in the task; single and total limits defaulted to conservative values.")
        ambiguous.extend(["max_single_payment", "max_total_payment"])

    if "approval" not in task.lower():
        warnings.append("Task did not explicitly mention approval; execution approval was required by default.")

    purpose = task.strip().split(".")[0].strip() or "Prepare payments for approved supplier invoices"

    contract = {
        "principal_id": crypto.PRINCIPAL_ID,
        "task": task,
        "purpose": purpose,
        "allowed_actions": list(DEFAULT_ALLOWED_ACTIONS),
        "forbidden_actions": list(DEFAULT_FORBIDDEN_ACTIONS),
        "approved_counterparties": [
            {
                "vendor_id": APPROVED_VENDOR["id"],
                "name": APPROVED_VENDOR["name"],
                "beneficiary_hash": APPROVED_VENDOR["bank_account_hash"],
            }
        ],
        "currency": DEFAULT_CURRENCY,
        "max_single_payment": max_single,
        "max_total_payment": max_total,
        "execution_mode": "REQUIRE_APPROVAL",
        "requires_approval": True,
        "data_restrictions": ["No secret or credential reads."],
        "memory_restrictions": ["No new financial instructions written to memory from untrusted content."],
    }
    return contract, warnings, ambiguous


def compile_mandate(task: str) -> dict:
    """Create a DRAFT mandate proposal. Never activates or signs."""
    contract, warnings, ambiguous = _propose_contract(task)
    mandate_id = str(uuid.uuid4())
    nonce = secrets.token_hex(16)
    contract = {"mandate_id": mandate_id, **contract, "nonce": nonce}
    now = utc_now()
    with connect() as connection:
        connection.execute(
            """INSERT INTO mandates
            (id, principal_id, payload_json, canonical_payload, signature, public_key,
             status, expires_at, nonce, created_at, confirmed_at)
            VALUES (?, ?, ?, NULL, NULL, NULL, 'DRAFT', NULL, ?, ?, NULL)""",
            (mandate_id, crypto.PRINCIPAL_ID, canonical_json(contract), nonce, now),
        )
    record = get_mandate(mandate_id)
    record["warnings"] = warnings
    record["ambiguous_fields"] = ambiguous
    return record


# --------------------------------------------------------------------------- #
# Retrieval
# --------------------------------------------------------------------------- #
def _decorate(record: dict) -> dict:
    record["contract"] = json.loads(record["payload_json"])
    return record


def get_mandate(mandate_id: str) -> dict | None:
    result = rows("SELECT * FROM mandates WHERE id = ?", (mandate_id,))
    return _decorate(result[0]) if result else None


def list_mandates() -> list[dict]:
    return [_decorate(r) for r in rows("SELECT * FROM mandates ORDER BY created_at DESC")]


def _require(mandate_id: str) -> dict:
    record = get_mandate(mandate_id)
    if record is None:
        raise MandateError("Mandate not found.")
    return record


# --------------------------------------------------------------------------- #
# Confirmation (human review/edit -> canonical serialization)
# --------------------------------------------------------------------------- #
_EDITABLE_FIELDS = {
    "task",
    "purpose",
    "allowed_actions",
    "forbidden_actions",
    "approved_counterparties",
    "currency",
    "max_single_payment",
    "max_total_payment",
    "execution_mode",
    "requires_approval",
    "data_restrictions",
    "memory_restrictions",
}


def confirm_mandate(mandate_id: str, edits: dict | None = None) -> dict:
    """Freeze the human-reviewed contract and canonically serialize it."""
    record = _require(mandate_id)
    if record["status"] != "DRAFT":
        raise MandateError(f"Only DRAFT mandates can be confirmed (status={record['status']}).")

    contract = dict(record["contract"])
    for key, value in (edits or {}).items():
        if key in _EDITABLE_FIELDS:
            contract[key] = value

    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=MANDATE_TTL_SECONDS)).isoformat()
    contract["issued_at"] = now.isoformat()
    contract["expires_at"] = expires_at

    canonical = canonical_json(contract)
    with connect() as connection:
        connection.execute(
            """UPDATE mandates
            SET payload_json = ?, canonical_payload = ?, expires_at = ?, confirmed_at = ?
            WHERE id = ?""",
            (canonical_json(contract), canonical, expires_at, now.isoformat(), mandate_id),
        )
    return get_mandate(mandate_id)


# --------------------------------------------------------------------------- #
# Signing (trusted backend action — the demo principal key never leaves crypto)
# --------------------------------------------------------------------------- #
def sign_mandate(mandate_id: str) -> dict:
    """Sign the confirmed canonical payload and activate the mandate.

    This is the trusted "Sign mandate" backend operation. It is never exposed as
    an agent tool and does not accept a client-supplied signature.
    """
    record = _require(mandate_id)
    if record["status"] != "DRAFT":
        raise MandateError(f"Only confirmed DRAFT mandates can be signed (status={record['status']}).")
    if not record["confirmed_at"] or not record["canonical_payload"]:
        raise MandateError("Mandate must be confirmed before signing.")

    signature = crypto.sign(record["canonical_payload"].encode("utf-8"))
    public_key = crypto.public_key_b64()
    with connect() as connection:
        connection.execute(
            "UPDATE mandates SET signature = ?, public_key = ?, status = 'ACTIVE' WHERE id = ?",
            (signature, public_key, mandate_id),
        )
    return get_mandate(mandate_id)


# --------------------------------------------------------------------------- #
# Verification (used by /verify and by the gateway before every protected call)
# --------------------------------------------------------------------------- #
def _recompute_canonical(record: dict) -> str:
    """Canonical JSON recomputed from the stored contract — tamper-evident."""
    return canonical_json(record["contract"])


def verification_for(record: dict, now: str | None = None) -> dict:
    """Trusted verification result the gateway passes into policy input.

    Recomputes the canonical payload from the stored contract so any
    post-signature mutation invalidates the signature.
    """
    now = now or utc_now()
    signature_valid = False
    if record.get("signature") and record.get("public_key"):
        recomputed = _recompute_canonical(record)
        signature_valid = crypto.verify(
            recomputed.encode("utf-8"), record["signature"], record["public_key"]
        )
    expires_at = record.get("expires_at")
    expired = bool(expires_at) and now >= expires_at

    if not signature_valid:
        reason_code = "MANDATE_SIGNATURE_INVALID"
    elif record["status"] != "ACTIVE":
        reason_code = "MANDATE_INACTIVE"
    elif expired:
        reason_code = "MANDATE_EXPIRED"
    else:
        reason_code = None

    return {
        "signature_valid": signature_valid,
        "mandate_status": record["status"],
        "expired": expired,
        "now": now,
        "reason_code": reason_code,
        "valid": reason_code is None,
    }


def verify_mandate(mandate_id: str) -> dict:
    record = _require(mandate_id)
    return verification_for(record)


# --------------------------------------------------------------------------- #
# Tamper demonstration (development/demo only — non-destructive)
# --------------------------------------------------------------------------- #
def tamper_demo(mandate_id: str, field: str = "max_single_payment", value=999999) -> dict:
    """Show that mutating a signed field invalidates the signature."""
    record = _require(mandate_id)
    if record["status"] != "ACTIVE" or not record.get("signature"):
        raise MandateError("Tamper demo requires a signed, active mandate.")

    original = verification_for(record)

    tampered_contract = dict(record["contract"])
    tampered_contract[field] = value
    tampered_canonical = canonical_json(tampered_contract)
    tampered_valid = crypto.verify(
        tampered_canonical.encode("utf-8"), record["signature"], record["public_key"]
    )
    return {
        "mandate_id": mandate_id,
        "tampered_field": field,
        "original_value": record["contract"].get(field),
        "tampered_value": value,
        "original_signature_valid": original["signature_valid"],
        "tampered_signature_valid": tampered_valid,
        "original_action_hash": sha256_hex(record["contract"]),
        "tampered_action_hash": sha256_hex(tampered_contract),
        "reason_code": "MANDATE_SIGNATURE_INVALID",
    }


# --------------------------------------------------------------------------- #
# Terminal status transitions
# --------------------------------------------------------------------------- #
def _set_status(mandate_id: str, status: str) -> dict:
    with connect() as connection:
        connection.execute("UPDATE mandates SET status = ? WHERE id = ?", (status, mandate_id))
    return get_mandate(mandate_id)


def complete_mandate(mandate_id: str) -> dict:
    return _set_status(mandate_id, "COMPLETED")


def revoke_mandate(mandate_id: str) -> dict:
    return _set_status(mandate_id, "REVOKED")


def expire_mandate(mandate_id: str) -> dict:
    return _set_status(mandate_id, "EXPIRED")
