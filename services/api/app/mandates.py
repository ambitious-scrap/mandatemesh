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
_MONEY_RE = re.compile(r"(?P<symbol>₹|INR\s*|USD\s*|\$|EUR\s*|€)\s*(?P<amount>[\d,]+)", re.IGNORECASE)
_DURATION_RE = re.compile(
    r"(?:for|within|valid\s+for)\s+(?P<value>\d+)\s*(?P<unit>minutes?|hours?)",
    re.IGNORECASE,
)
COMPILER_VERSION = "mandatemesh-semantic-v2"


class MandateError(Exception):
    """Raised for invalid lifecycle transitions."""


# --------------------------------------------------------------------------- #
# Compilation (proposal only — never authoritative)
# --------------------------------------------------------------------------- #
def _amount_candidates(task: str) -> list[dict]:
    candidates: list[dict] = []
    for match in _MONEY_RE.finditer(task):
        amount = int(match.group("amount").replace(",", ""))
        punctuation = max(
            task.rfind(".", 0, match.start()),
            task.rfind(";", 0, match.start()),
            task.rfind("\n", 0, match.start()),
        )
        segment_start = max(punctuation + 1, match.start() - 90)
        prefix = task[segment_start: match.start()].lower()
        # Classification is driven by the current clause before the amount.
        # Crossing a sentence boundary can misclassify a per-payment limit as
        # the previous sentence's total budget.
        if any(term in prefix for term in ("total", "cumulative", "aggregate", "overall", "committed spend", "budget")):
            role = "max_total_payment"
        elif any(term in prefix for term in ("each payment", "per payment", "single payment", "each invoice", "per invoice", "payment must", "invoice must")):
            role = "max_single_payment"
        else:
            role = "unclassified"
        symbol = match.group("symbol").strip().upper()
        currency = "INR" if symbol in {"₹", "INR"} else "USD" if symbol in {"$", "USD"} else "EUR"
        candidates.append({"amount": amount, "role": role, "currency": currency, "evidence": match.group(0)})
    return candidates


def _semantic_report(task: str) -> tuple[dict, dict]:
    """Compile the AP task into a conservative contract plus explainable report.

    This is intentionally domain-bounded rather than a universal policy
    compiler. It extracts limits, currency, approval language, prohibitions and
    an optional duration, then surfaces ambiguity for human review. It never
    confirms, signs or activates the resulting mandate.
    """
    warnings: list[str] = []
    ambiguous: list[str] = []
    review_requirements: list[str] = []
    confidence: dict[str, float] = {}
    candidates = _amount_candidates(task)

    by_role = {"max_single_payment": [], "max_total_payment": [], "unclassified": []}
    for candidate in candidates:
        by_role[candidate["role"]].append(candidate)

    max_single = by_role["max_single_payment"][0]["amount"] if by_role["max_single_payment"] else None
    max_total = by_role["max_total_payment"][0]["amount"] if by_role["max_total_payment"] else None
    leftovers = [item["amount"] for item in by_role["unclassified"]]

    if max_single is None and leftovers:
        max_single = leftovers.pop(0)
        confidence["max_single_payment"] = 0.72
    if max_total is None and leftovers:
        max_total = leftovers.pop(0)
        confidence["max_total_payment"] = 0.72

    if max_single is None:
        max_single = DEFAULT_MAX_SINGLE
        confidence["max_single_payment"] = 0.45
        ambiguous.append("max_single_payment")
    else:
        confidence.setdefault("max_single_payment", 0.96 if by_role["max_single_payment"] else 0.72)
    if max_total is None:
        max_total = DEFAULT_MAX_TOTAL
        confidence["max_total_payment"] = 0.45
        ambiguous.append("max_total_payment")
    else:
        confidence.setdefault("max_total_payment", 0.96 if by_role["max_total_payment"] else 0.72)

    if not candidates:
        warnings.append("No amounts detected in the task; single and total limits defaulted to conservative values.")
    elif len(candidates) == 1:
        warnings.append("Only one amount detected in the task; the unresolved limit defaulted to the conservative value.")
    if max_total < max_single:
        warnings.append("Total budget is lower than the single-payment limit; human review is required.")
        ambiguous.extend(["max_single_payment", "max_total_payment"])

    currencies = sorted({item["currency"] for item in candidates})
    if len(currencies) > 1:
        currency = DEFAULT_CURRENCY
        warnings.append("Multiple currencies were detected; currency defaulted to INR pending review.")
        ambiguous.append("currency")
        confidence["currency"] = 0.25
    elif currencies:
        currency = currencies[0]
        confidence["currency"] = 0.98
    else:
        currency = DEFAULT_CURRENCY
        confidence["currency"] = 0.55

    lower = task.lower()
    approval_terms = ("requires my approval", "require my approval", "requires approval", "require approval", "approval required")
    approval_explicit = any(term in lower for term in approval_terms)
    approval_conflict = any(term in lower for term in ("without approval", "no approval", "auto-execute", "automatically execute"))
    if approval_conflict:
        warnings.append("Task language suggests execution without approval; conservative independent approval remains required.")
        ambiguous.append("requires_approval")
        review_requirements.append("Confirm that payment execution must require independent human approval.")
        confidence["requires_approval"] = 0.35
    elif approval_explicit:
        confidence["requires_approval"] = 0.99
    else:
        warnings.append("Task did not explicitly mention approval; execution approval was required by default.")
        confidence["requires_approval"] = 0.6

    duration = _DURATION_RE.search(task)
    requested_ttl: int | None = None
    if duration:
        value = int(duration.group("value"))
        unit = duration.group("unit").lower()
        proposed_ttl = value * (60 if unit.startswith("minute") else 3600)
        # A task may request a shorter mandate, never a longer one than the
        # configured demo maximum without an explicit human edit.
        requested_ttl = max(300, min(proposed_ttl, MANDATE_TTL_SECONDS)) if MANDATE_TTL_SECONDS >= 0 else proposed_ttl
        confidence["requested_ttl_seconds"] = 0.96
    else:
        confidence["requested_ttl_seconds"] = 0.55

    prohibited_evidence = {
        "vendor.record.create": any(term in lower for term in ("do not create vendor", "do not create vendors", "no new vendors")),
        "secret.value.read": any(term in lower for term in ("do not read secrets", "no secret", "no credential")),
        "memory.financial_instruction.write": any(term in lower for term in ("do not store", "do not write", "no new financial instructions")) and "memory" in lower,
    }
    for action, explicit in prohibited_evidence.items():
        confidence[f"forbidden:{action}"] = 0.98 if explicit else 0.7
    dangerous_permission = any(
        term in lower
        for term in (
            "allow vendor creation",
            "create vendors if needed",
            "may create vendors",
            "can create vendors",
            "may read secrets",
            "can read secrets",
            "allow secret reads",
            "may store financial instructions",
            "can store financial instructions",
            "allow memory writes",
        )
    )
    if dangerous_permission:
        warnings.append("Potentially dangerous permission language was detected; the MVP denylist was retained.")
        review_requirements.append("Review all forbidden actions before confirmation.")
        ambiguous.append("forbidden_actions")

    ambiguous = list(dict.fromkeys(ambiguous))
    review_requirements.extend(f"Review compiler field: {field}." for field in ambiguous if f"Review compiler field: {field}." not in review_requirements)
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
        "currency": currency,
        "max_single_payment": max_single,
        "max_total_payment": max_total,
        "execution_mode": "REQUIRE_APPROVAL",
        "requires_approval": True,
        "requested_ttl_seconds": requested_ttl,
        "data_restrictions": ["No secret or credential reads."],
        "memory_restrictions": ["No new financial instructions written to memory from untrusted content."],
    }
    report = {
        "compiler_version": COMPILER_VERSION,
        "authoritative": False,
        "warnings": warnings,
        "ambiguous_fields": ambiguous,
        "review_requirements": review_requirements,
        "field_confidence": confidence,
        "extracted_constraints": {
            "amount_candidates": candidates,
            "currency": currency,
            "approval_explicit": approval_explicit,
            "approval_conflict": approval_conflict,
            "requested_ttl_seconds": requested_ttl,
            "explicit_prohibitions": prohibited_evidence,
        },
    }
    return contract, report


def _propose_contract(task: str) -> tuple[dict, list[str], list[str]]:
    """Compatibility wrapper retained for existing tests and callers."""
    contract, report = _semantic_report(task)
    return contract, report["warnings"], report["ambiguous_fields"]


def compile_mandate(task: str) -> dict:
    """Create a DRAFT semantic mandate proposal. Never activates or signs."""
    contract, report = _semantic_report(task)
    mandate_id = str(uuid.uuid4())
    nonce = secrets.token_hex(16)
    contract = {"mandate_id": mandate_id, **contract, "nonce": nonce}
    now = utc_now()
    with connect() as connection:
        connection.execute(
            """INSERT INTO mandates
            (id, principal_id, payload_json, canonical_payload, signature, public_key,
             status, expires_at, nonce, created_at, confirmed_at, compiler_report_json)
            VALUES (?, ?, ?, NULL, NULL, NULL, 'DRAFT', NULL, ?, ?, NULL, ?)""",
            (mandate_id, crypto.PRINCIPAL_ID, canonical_json(contract), nonce, now, json.dumps(report)),
        )
    return get_mandate(mandate_id)


# --------------------------------------------------------------------------- #
# Retrieval
# --------------------------------------------------------------------------- #
def _decorate(record: dict) -> dict:
    record["contract"] = json.loads(record["payload_json"])
    report = json.loads(record["compiler_report_json"]) if record.get("compiler_report_json") else {
        "compiler_version": "legacy",
        "authoritative": False,
        "warnings": [],
        "ambiguous_fields": [],
        "review_requirements": [],
        "field_confidence": {},
        "extracted_constraints": {},
    }
    record["compiler_report"] = report
    record["warnings"] = report.get("warnings", [])
    record["ambiguous_fields"] = report.get("ambiguous_fields", [])
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
    "requested_ttl_seconds",
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
    requested_ttl = contract.get("requested_ttl_seconds")
    requested_ttl = MANDATE_TTL_SECONDS if requested_ttl is None else int(requested_ttl)
    effective_ttl = (
        requested_ttl
        if MANDATE_TTL_SECONDS < 0
        else max(300, min(requested_ttl, MANDATE_TTL_SECONDS))
    )
    contract["requested_ttl_seconds"] = effective_ttl
    expires_at = (now + timedelta(seconds=effective_ttl)).isoformat()
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
