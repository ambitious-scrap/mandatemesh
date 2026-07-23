"""Canonical business-action model and tool mapping.

The gateway never authorizes on a raw tool name. Each proposed tool call is
normalized into a canonical business action with a stable resource shape,
execution provenance, and task state before policy evaluation.
"""
from __future__ import annotations

import uuid

from .database import utc_now

# Raw simulated tool -> canonical business action.
CANONICAL_ACTION = {
    "invoice.read": "document.invoice.read",
    "vendor.lookup": "vendor.record.lookup",
    "vendor.create": "vendor.record.create",
    "secret.read": "secret.value.read",
    "payment.prepare": "financial.payment.prepare",
    "payment.execute": "financial.payment.execute",
    "memory.write": "memory.financial_instruction.write",
}

# Canonical actions that mutate persisted state (require idempotency keys).
SIDE_EFFECTING = frozenset(
    {
        "vendor.record.create",
        "financial.payment.prepare",
        "financial.payment.execute",
        "memory.financial_instruction.write",
    }
)

UNTRUSTED_SOURCE = "UNTRUSTED_EXTERNAL"


def canonical_for(tool_name: str) -> str | None:
    return CANONICAL_ACTION.get(tool_name)


def _resource(canonical_action: str, arguments: dict) -> dict:
    if canonical_action == "document.invoice.read":
        return {"invoice_id": arguments.get("invoice_id")}
    if canonical_action == "vendor.record.lookup":
        return {"vendor_id": arguments.get("vendor_id")}
    if canonical_action == "vendor.record.create":
        return {"vendor_id": arguments.get("vendor_id"), "beneficiary_hash": arguments.get("bank_account_hash")}
    if canonical_action == "secret.value.read":
        return {"secret_name": arguments.get("secret_name")}
    if canonical_action == "financial.payment.prepare":
        return {
            "vendor_id": arguments.get("vendor_id"),
            "beneficiary_hash": arguments.get("beneficiary_hash"),
            "amount": arguments.get("amount"),
            "currency": arguments.get("currency"),
        }
    if canonical_action == "financial.payment.execute":
        return {"payment_id": arguments.get("payment_id")}
    if canonical_action == "memory.financial_instruction.write":
        return {
            "memory_type": arguments.get("memory_type"),
            "source_ref": arguments.get("source_ref"),
            "trust_level": arguments.get("trust_level", "UNTRUSTED"),
        }
    return {}


def build_canonical_action(
    tool_name: str,
    arguments: dict,
    *,
    source_ref: str | None,
    mandate_id: str | None,
    task_state: dict,
    idempotency_key: str | None,
) -> dict | None:
    """Return the canonical action document, or ``None`` for an unknown tool."""
    canonical_action = canonical_for(tool_name)
    if canonical_action is None:
        return None
    return {
        "action_id": str(uuid.uuid4()),
        "canonical_action": canonical_action,
        "tool_name": tool_name,
        "arguments": arguments,
        "resource": _resource(canonical_action, arguments),
        "provenance": {"source_ref": source_ref, "source_trust": UNTRUSTED_SOURCE},
        "task_state": task_state,
        "mandate_id": mandate_id,
        "timestamp": utc_now(),
        "idempotency_key": idempotency_key,
    }
