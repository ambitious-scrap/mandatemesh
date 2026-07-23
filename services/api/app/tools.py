from __future__ import annotations

import uuid

from .database import connect, utc_now
from .scenarios import get_scenario_by_invoice


class ToolError(ValueError):
    pass


def _required(arguments: dict, *names: str) -> None:
    missing = [name for name in names if arguments.get(name) in (None, "")]
    if missing:
        raise ToolError(f"Missing required arguments: {', '.join(missing)}")


def _row(connection, query: str, parameters: tuple) -> dict | None:
    result = connection.execute(query, parameters).fetchone()
    return dict(result) if result else None


def execute_tool(tool_name: str, arguments: dict) -> tuple[dict, dict | None]:
    tools = {
        "invoice.read": invoice_read,
        "vendor.lookup": vendor_lookup,
        "vendor.create": vendor_create,
        "secret.read": secret_read,
        "payment.prepare": payment_prepare,
        "payment.execute": payment_execute,
        "memory.write": memory_write,
    }
    try:
        return tools[tool_name](arguments)
    except KeyError as error:
        raise ToolError(f"Unknown tool: {tool_name}") from error


def invoice_read(arguments: dict) -> tuple[dict, None]:
    _required(arguments, "invoice_id")
    invoice = get_scenario_by_invoice(arguments["invoice_id"])["invoice"]
    return {
        "invoice_id": invoice["invoice_id"],
        "fields": invoice["fields"],
        "extracted_text": invoice["raw_text"],
        "source_trust": "UNTRUSTED_DOCUMENT",
    }, None


def vendor_lookup(arguments: dict) -> tuple[dict, None]:
    _required(arguments, "vendor_id")
    with connect() as connection:
        vendor = _row(connection, "SELECT id, name, bank_account_hash, approved, created_at FROM vendors WHERE id = ?", (arguments["vendor_id"],))
    if not vendor:
        raise ToolError(f"Vendor not found: {arguments['vendor_id']}")
    vendor["approved"] = bool(vendor["approved"])
    return vendor, None


def vendor_create(arguments: dict) -> tuple[dict, dict]:
    _required(arguments, "vendor_id", "name", "bank_account_hash", "idempotency_key")
    with connect() as connection:
        existing = _row(connection, "SELECT * FROM vendors WHERE idempotency_key = ?", (arguments["idempotency_key"],))
        if existing:
            return {**existing, "approved": bool(existing["approved"]), "idempotent_replay": True}, None
        vendor = {
            "id": arguments["vendor_id"],
            "name": arguments["name"],
            "bank_account_hash": arguments["bank_account_hash"],
            "approved": int(bool(arguments.get("approved", False))),
            "idempotency_key": arguments["idempotency_key"],
            "created_at": utc_now(),
        }
        connection.execute(
            "INSERT INTO vendors (id, name, bank_account_hash, approved, idempotency_key, created_at) VALUES (:id, :name, :bank_account_hash, :approved, :idempotency_key, :created_at)",
            vendor,
        )
    public_vendor = {**vendor, "approved": bool(vendor["approved"])}
    return public_vendor, {"table": "vendors", "operation": "INSERT", "record": public_vendor}


def secret_read(arguments: dict) -> tuple[dict, dict]:
    _required(arguments, "secret_name")
    with connect() as connection:
        secret = _row(connection, "SELECT name, value FROM secrets WHERE name = ?", (arguments["secret_name"],))
    if not secret:
        raise ToolError(f"Secret not found: {arguments['secret_name']}")
    return secret, {"resource": secret["name"], "operation": "READ", "exposed": True}


def payment_prepare(arguments: dict) -> tuple[dict, dict | None]:
    _required(arguments, "invoice_id", "vendor_id", "beneficiary_hash", "amount", "currency", "idempotency_key")
    amount = int(arguments["amount"])
    if amount <= 0:
        raise ToolError("Payment amount must be positive")
    with connect() as connection:
        existing = _row(connection, "SELECT * FROM payments WHERE idempotency_key = ?", (arguments["idempotency_key"],))
        if existing:
            return {**existing, "idempotent_replay": True}, None
        payment = {
            "id": f"PAY-{uuid.uuid4().hex[:10].upper()}",
            "invoice_id": arguments["invoice_id"],
            "vendor_id": arguments["vendor_id"],
            "beneficiary_hash": arguments["beneficiary_hash"],
            "amount": amount,
            "currency": arguments["currency"],
            "status": "PREPARED",
            "idempotency_key": arguments["idempotency_key"],
            "created_at": utc_now(),
            "executed_at": None,
        }
        connection.execute(
            """INSERT INTO payments
            (id, invoice_id, vendor_id, beneficiary_hash, amount, currency, status, idempotency_key, created_at)
            VALUES (:id, :invoice_id, :vendor_id, :beneficiary_hash, :amount, :currency, :status, :idempotency_key, :created_at)""",
            payment,
        )
    return payment, {"table": "payments", "operation": "INSERT", "record": payment}


def payment_execute(arguments: dict) -> tuple[dict, dict | None]:
    _required(arguments, "payment_id", "idempotency_key")
    with connect() as connection:
        replay = _row(connection, "SELECT * FROM payments WHERE execution_idempotency_key = ?", (arguments["idempotency_key"],))
        if replay:
            return {**replay, "idempotent_replay": True}, None
        payment = _row(connection, "SELECT * FROM payments WHERE id = ?", (arguments["payment_id"],))
        if not payment:
            raise ToolError(f"Payment not found: {arguments['payment_id']}")
        if payment["status"] != "PREPARED":
            raise ToolError(f"Payment cannot execute from state {payment['status']}")
        executed_at = utc_now()
        connection.execute(
            "UPDATE payments SET status = 'EXECUTED', execution_idempotency_key = ?, executed_at = ? WHERE id = ?",
            (arguments["idempotency_key"], executed_at, payment["id"]),
        )
        after = {**payment, "status": "EXECUTED", "execution_idempotency_key": arguments["idempotency_key"], "executed_at": executed_at}
    return after, {"table": "payments", "operation": "UPDATE", "before": payment, "after": after}


def memory_write(arguments: dict) -> tuple[dict, dict | None]:
    _required(arguments, "content", "memory_type", "source_ref", "idempotency_key")
    with connect() as connection:
        existing = _row(connection, "SELECT * FROM memory_entries WHERE idempotency_key = ?", (arguments["idempotency_key"],))
        if existing:
            return {**existing, "idempotent_replay": True}, None
        entry = {
            "id": f"MEM-{uuid.uuid4().hex[:10].upper()}",
            "content": arguments["content"],
            "memory_type": arguments["memory_type"],
            "source_ref": arguments["source_ref"],
            "trust_level": arguments.get("trust_level", "UNTRUSTED"),
            "status": "ACTIVE",
            "idempotency_key": arguments["idempotency_key"],
            "created_at": utc_now(),
        }
        connection.execute(
            """INSERT INTO memory_entries
            (id, content, memory_type, source_ref, trust_level, status, idempotency_key, created_at)
            VALUES (:id, :content, :memory_type, :source_ref, :trust_level, :status, :idempotency_key, :created_at)""",
            entry,
        )
    return entry, {"table": "memory_entries", "operation": "INSERT", "record": entry}

