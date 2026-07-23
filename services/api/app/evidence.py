"""Judge-facing resource snapshots for execution provenance.

Snapshots are deliberately narrow and redact synthetic secret values. They are
captured before policy evaluation and after enforcement so the UI can explain
what changed without opening SQLite or backend logs.
"""
from __future__ import annotations

from .database import rows


def _one(query: str, parameters: tuple) -> dict | None:
    result = rows(query, parameters)
    return result[0] if result else None


def snapshot_resource(tool_name: str, arguments: dict) -> dict:
    if tool_name == "invoice.read":
        return {
            "resource_type": "invoice",
            "invoice_id": arguments.get("invoice_id"),
            "side_effect": "none",
        }
    if tool_name in {"vendor.lookup", "vendor.create"}:
        vendor_id = arguments.get("vendor_id")
        vendor = _one(
            "SELECT id, name, bank_account_hash, approved, created_at FROM vendors WHERE id = ?",
            (vendor_id,),
        )
        if vendor:
            vendor["approved"] = bool(vendor["approved"])
        return {"resource_type": "vendor", "resource_id": vendor_id, "record": vendor}
    if tool_name == "secret.read":
        secret_name = arguments.get("secret_name") or arguments.get("name")
        count = _one(
            """SELECT COUNT(*) AS count FROM tool_events
            WHERE event_type = 'SIDE_EFFECT_RECORDED' AND tool_name = 'secret.read'""",
            (),
        )
        return {
            "resource_type": "synthetic_secret",
            "resource_id": secret_name,
            "value": "[REDACTED]",
            "recorded_accesses": int((count or {}).get("count", 0)),
        }
    if tool_name == "payment.prepare":
        key = arguments.get("idempotency_key")
        payment = _one("SELECT * FROM payments WHERE idempotency_key = ?", (key,)) if key else None
        return {"resource_type": "payment", "idempotency_key": key, "record": payment}
    if tool_name == "payment.execute":
        payment_id = arguments.get("payment_id")
        payment = _one("SELECT * FROM payments WHERE id = ?", (payment_id,)) if payment_id else None
        return {"resource_type": "payment", "resource_id": payment_id, "record": payment}
    if tool_name == "memory.write":
        key = arguments.get("idempotency_key")
        memory = _one("SELECT * FROM memory_entries WHERE idempotency_key = ?", (key,)) if key else None
        return {"resource_type": "memory", "idempotency_key": key, "record": memory}
    return {"resource_type": "unknown", "tool_name": tool_name}
