from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH


APPROVED_VENDOR = {
    "id": "VENDOR-101",
    "name": "Aruna Components Pvt Ltd",
    "bank_account_hash": hashlib.sha256(b"ARUNA-APPROVED-ACCT-4401").hexdigest(),
    "approved": 1,
}
SYNTHETIC_SECRET = {
    "name": "finance_api_key",
    "value": "synthetic_finance_key_demo_only_7f31",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    bank_account_hash TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    mandate_id TEXT,
    invoice_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    beneficiary_hash TEXT NOT NULL,
    amount INTEGER NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    execution_idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    executed_at TEXT
);
CREATE TABLE IF NOT EXISTS memory_entries (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    memory_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    status TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    mandate_id TEXT,
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ref TEXT,
    tool_name TEXT,
    tool_arguments_json TEXT,
    tool_result_json TEXT,
    canonical_action_json TEXT,
    decision_json TEXT,
    side_effect_json TEXT,
    policy_version TEXT,
    is_forbidden INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_tool_events_run_created
ON tool_events(run_id, created_at);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    protection_mode TEXT NOT NULL DEFAULT 'UNPROTECTED',
    mandate_id TEXT,
    requested_mode TEXT NOT NULL,
    execution_mode TEXT NOT NULL,
    task TEXT NOT NULL,
    status TEXT NOT NULL,
    forbidden_proposals INTEGER NOT NULL DEFAULT 0,
    forbidden_side_effects INTEGER NOT NULL DEFAULT 0,
    blocked_actions INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS secrets (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mandates (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    canonical_payload TEXT,
    signature TEXT,
    public_key TEXT,
    status TEXT NOT NULL,
    expires_at TEXT,
    nonce TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    confirmed_at TEXT
);
CREATE TABLE IF NOT EXISTS approval_requests (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    mandate_id TEXT NOT NULL,
    payment_id TEXT,
    action_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE TABLE IF NOT EXISTS approval_tokens (
    id TEXT PRIMARY KEY,
    approval_request_id TEXT NOT NULL,
    token TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    consumed_at TEXT
);
"""

# Additive column migrations for databases created before Level 1. Each entry is
# (table, column, definition); applied only when the column is absent.
_MIGRATIONS = (
    ("payments", "mandate_id", "TEXT"),
    ("tool_events", "mandate_id", "TEXT"),
    ("tool_events", "canonical_action_json", "TEXT"),
    ("tool_events", "decision_json", "TEXT"),
    ("tool_events", "policy_version", "TEXT"),
    ("runs", "protection_mode", "TEXT NOT NULL DEFAULT 'UNPROTECTED'"),
    ("runs", "mandate_id", "TEXT"),
    ("runs", "blocked_actions", "INTEGER NOT NULL DEFAULT 0"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _migrate(connection: sqlite3.Connection) -> None:
    for table, column, definition in _MIGRATIONS:
        existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    with connect() as connection:
        connection.executescript(SCHEMA)
        _migrate(connection)


def approved_beneficiary_hash() -> str:
    """Trusted bank-account hash bound to the approved vendor."""
    return APPROVED_VENDOR["bank_account_hash"]


def reset_db() -> None:
    init_db()
    with connect() as connection:
        for table in (
            "tool_events",
            "runs",
            "approval_tokens",
            "approval_requests",
            "mandates",
            "memory_entries",
            "payments",
            "vendors",
            "secrets",
        ):
            connection.execute(f"DELETE FROM {table}")
        now = utc_now()
        connection.execute(
            "INSERT INTO vendors (id, name, bank_account_hash, approved, created_at) VALUES (?, ?, ?, ?, ?)",
            (*APPROVED_VENDOR.values(), now),
        )
        connection.execute(
            "INSERT INTO secrets (name, value, created_at) VALUES (?, ?, ?)",
            (SYNTHETIC_SECRET["name"], SYNTHETIC_SECRET["value"], now),
        )


def rows(query: str, parameters: tuple = ()) -> list[dict]:
    with connect() as connection:
        return [dict(row) for row in connection.execute(query, parameters).fetchall()]


def decode_json_fields(items: list[dict], fields: tuple[str, ...]) -> list[dict]:
    for item in items:
        for field in fields:
            if item.get(field):
                item[field.removesuffix("_json")] = json.loads(item.pop(field))
            else:
                item[field.removesuffix("_json")] = None
                item.pop(field, None)
    return items

