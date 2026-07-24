"""Minimal MCP Streamable HTTP adapter for MandateMesh.

The adapter implements the stable 2025-11-25 JSON-RPC lifecycle needed for a
hackathon proof: ``initialize``, ``tools/list`` and ``tools/call``. It contains
no authorization policy. Every tool invocation is delegated to the existing
MandateMesh gateway and therefore shares signature verification, canonical
normalization, OPA decisions, approvals, budgets, idempotency and evidence.
"""
from __future__ import annotations

import json
from typing import Any

from . import actions, gateway

PROTOCOL_VERSION = "2025-11-25"
SERVER_INFO = {
    "name": "mandatemesh",
    "version": "3.0.0",
    "description": "Action authorization for autonomous agents",
}
LOCAL_ORIGINS = frozenset(
    {
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    }
)

_ENVELOPE_PROPERTIES = {
    "run_id": {"type": "string", "description": "Protected MandateMesh run identifier"},
    "mandate_id": {"type": "string", "description": "Signed mandate bound to the run"},
    "source_ref": {"type": "string", "description": "Source document or provenance reference"},
    "approval_token": {"type": "string", "description": "Optional one-use approval token"},
}

_TOOL_ARGUMENTS: dict[str, tuple[dict[str, dict], list[str], bool, str]] = {
    "invoice.read": (
        {"invoice_id": {"type": "string"}}, ["invoice_id"], False, "Read an invoice through the protected gateway.",
    ),
    "vendor.lookup": (
        {"vendor_id": {"type": "string"}}, ["vendor_id"], False, "Look up a trusted vendor record.",
    ),
    "vendor.create": (
        {
            "vendor_id": {"type": "string"}, "name": {"type": "string"},
            "bank_account_hash": {"type": "string"}, "approved": {"type": "boolean"},
            "idempotency_key": {"type": "string"},
        },
        ["vendor_id", "name", "bank_account_hash", "idempotency_key"], True,
        "Propose creation of a vendor record. The demo mandate forbids this action.",
    ),
    "secret.read": (
        {"secret_name": {"type": "string"}}, ["secret_name"], False,
        "Propose reading a synthetic secret. The demo mandate forbids this action.",
    ),
    "payment.prepare": (
        {
            "invoice_id": {"type": "string"}, "vendor_id": {"type": "string"},
            "beneficiary_hash": {"type": "string"}, "amount": {"type": "integer", "minimum": 1},
            "currency": {"type": "string"}, "idempotency_key": {"type": "string"},
        },
        ["invoice_id", "vendor_id", "beneficiary_hash", "amount", "currency", "idempotency_key"],
        True, "Prepare a mandate-bound payment.",
    ),
    "payment.execute": (
        {"payment_id": {"type": "string"}, "idempotency_key": {"type": "string"}},
        ["payment_id", "idempotency_key"], True, "Execute a prepared payment with independent approval.",
    ),
    "memory.write": (
        {
            "content": {"type": "string"}, "memory_type": {"type": "string"},
            "source_ref": {"type": "string"}, "trust_level": {"type": "string"},
            "idempotency_key": {"type": "string"},
        },
        ["content", "memory_type", "source_ref", "idempotency_key"], True,
        "Propose a persistent financial-memory write. Denied writes are quarantined.",
    ),
}


def origin_allowed(origin: str | None) -> bool:
    return origin is None or origin in LOCAL_ORIGINS


def tool_definitions() -> list[dict]:
    definitions: list[dict] = []
    for name in sorted(_TOOL_ARGUMENTS):
        properties, required, destructive, description = _TOOL_ARGUMENTS[name]
        definitions.append(
            {
                "name": name,
                "title": actions.canonical_for(name),
                "description": description,
                "inputSchema": {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": {**_ENVELOPE_PROPERTIES, **properties},
                    "required": ["run_id", "mandate_id", *required],
                    "additionalProperties": False,
                },
                "annotations": {
                    "readOnlyHint": not destructive,
                    "destructiveHint": destructive,
                    "idempotentHint": destructive,
                    "openWorldHint": False,
                },
            }
        )
    return definitions


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _result(request_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _call_tool(params: dict) -> dict:
    name = params.get("name")
    supplied = params.get("arguments")
    if name not in _TOOL_ARGUMENTS:
        raise ValueError(f"Unknown MCP tool: {name}")
    if not isinstance(supplied, dict):
        raise ValueError("tools/call requires an arguments object")

    envelope = dict(supplied)
    run_id = envelope.pop("run_id", None)
    mandate_id = envelope.pop("mandate_id", None)
    source_ref = envelope.pop("source_ref", None)
    approval_token = envelope.pop("approval_token", None)
    # ``memory.write`` uses source_ref both as transport provenance and as a
    # persisted tool argument. Other tools use it only as provenance.
    if name == "memory.write" and source_ref is not None:
        envelope["source_ref"] = source_ref
    if not run_id or not mandate_id:
        raise ValueError("MCP tool calls require run_id and mandate_id")
    idempotency_key = envelope.get("idempotency_key")

    outcome = gateway.execute(
        str(run_id), str(mandate_id), str(name), envelope,
        source_ref=source_ref,
        approval_token=approval_token,
        idempotency_key=idempotency_key,
        transport="MCP",
    )
    decision = outcome["decision"]
    payload = {
        "transport": "MCP",
        "tool": name,
        "decision": decision,
        "tool_result": outcome.get("tool_result"),
        "event_id": outcome.get("event_id"),
        "approval_request_id": outcome.get("approval_request_id"),
        "quarantine": outcome.get("quarantine"),
    }
    return {
        "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
        "structuredContent": payload,
        "isError": decision.get("decision") == "BLOCK",
    }


def handle(message: dict) -> dict | None:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(message.get("id") if isinstance(message, dict) else None, -32600, "Invalid Request")
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    # Notifications intentionally have no JSON-RPC response.
    if request_id is None and method == "notifications/initialized":
        return None

    if method == "initialize":
        requested = params.get("protocolVersion")
        if requested and requested != PROTOCOL_VERSION:
            return _error(request_id, -32602, "Unsupported protocol version", {"supported": PROTOCOL_VERSION})
        return _result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": "All calls require a protected run and signed mandate; authorization is enforced by MandateMesh.",
            },
        )
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": tool_definitions()})
    if method == "tools/call":
        try:
            return _result(request_id, _call_tool(params))
        except ValueError as error:
            # MCP tool input/execution errors are returned inside the tool result
            # so an agent can self-correct without treating the protocol as broken.
            return _result(
                request_id,
                {
                    "content": [{"type": "text", "text": str(error)}],
                    "structuredContent": {"transport": "MCP", "error": str(error)},
                    "isError": True,
                },
            )
    return _error(request_id, -32601, f"Method not found: {method}")
