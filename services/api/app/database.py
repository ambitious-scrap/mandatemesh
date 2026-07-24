from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH


class ClosingConnection(sqlite3.Connection):
    """SQLite connection whose context manager commits/rolls back and closes."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


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
    created_at TEXT NOT NULL,
    quarantine_reason TEXT,
    run_id TEXT,
    mandate_id TEXT,
    reviewed_at TEXT
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
    latency_ms REAL,
    policy_input_json TEXT,
    before_state_json TEXT,
    after_state_json TEXT
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
    completed_at TEXT,
    evaluation_run_id TEXT
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
    confirmed_at TEXT,
    compiler_report_json TEXT
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
    consumed_at TEXT,
    run_id TEXT,
    mandate_id TEXT,
    payment_id TEXT,
    vendor_id TEXT,
    beneficiary_hash TEXT,
    amount INTEGER,
    currency TEXT
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    total_scenarios INTEGER NOT NULL DEFAULT 0,
    passed_scenarios INTEGER NOT NULL DEFAULT 0,
    attack_prevented INTEGER NOT NULL DEFAULT 0,
    legitimate_succeeded INTEGER NOT NULL DEFAULT 0,
    false_blocks INTEGER NOT NULL DEFAULT 0,
    approval_escalations INTEGER NOT NULL DEFAULT 0,
    median_policy_latency_ms REAL,
    p95_policy_latency_ms REAL,
    repeatability_key TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS evaluation_results (
    id TEXT PRIMARY KEY,
    evaluation_run_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    expected_decision TEXT NOT NULL,
    actual_decision TEXT NOT NULL,
    reason_code TEXT,
    passed INTEGER NOT NULL,
    baseline_run_id TEXT,
    protected_run_id TEXT,
    baseline_outcome TEXT,
    protected_outcome TEXT,
    baseline_event_id TEXT,
    evidence_event_id TEXT,
    latency_ms REAL,
    side_effect_detected INTEGER NOT NULL DEFAULT 0,
    details_json TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(evaluation_run_id, scenario_id)
);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_run
ON evaluation_results(evaluation_run_id, scenario_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_approval_action
ON approval_requests(run_id, mandate_id, payment_id, action_hash)
WHERE status = 'PENDING';
CREATE UNIQUE INDEX IF NOT EXISTS uq_approval_token_request
ON approval_tokens(approval_request_id);
"""

# Additive migrations for databases created before hardening. Each entry is
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
    ("runs", "evaluation_run_id", "TEXT"),
    ("tool_events", "policy_input_json", "TEXT"),
    ("tool_events", "before_state_json", "TEXT"),
    ("tool_events", "after_state_json", "TEXT"),
    ("approval_tokens", "run_id", "TEXT"),
    ("approval_tokens", "mandate_id", "TEXT"),
    ("approval_tokens", "payment_id", "TEXT"),
    ("approval_tokens", "vendor_id", "TEXT"),
    ("approval_tokens", "beneficiary_hash", "TEXT"),
    ("approval_tokens", "amount", "INTEGER"),
    ("approval_tokens", "currency", "TEXT"),
    ("memory_entries", "quarantine_reason", "TEXT"),
    ("memory_entries", "run_id", "TEXT"),
    ("memory_entries", "mandate_id", "TEXT"),
    ("memory_entries", "reviewed_at", "TEXT"),
    ("mandates", "compiler_report_json", "TEXT"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10, factory=ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    return connection


def _migrate(connection: sqlite3.Connection) -> None:
    for table, column, definition in _MIGRATIONS:
        existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    # Index creation is repeated after migrations so an old approval_tokens table
    # receives the new constraints safely.
    connection.execute(
        """CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_approval_action
        ON approval_requests(run_id, mandate_id, payment_id, action_hash)
        WHERE status = 'PENDING'"""
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_approval_token_request ON approval_tokens(approval_request_id)"
    )


def init_db() -> None:
    with connect() as connection:
        connection.executescript(SCHEMA)
        _migrate(connection)


def approved_beneficiary_hash() -> str:
    """Trusted bank-account hash bound to the approved vendor."""
    return APPROVED_VENDOR["bank_account_hash"]


def _seed_trusted_state(connection: sqlite3.Connection) -> None:
    now = utc_now()
    connection.execute(
        "INSERT INTO vendors (id, name, bank_account_hash, approved, created_at) VALUES (?, ?, ?, ?, ?)",
        (*APPROVED_VENDOR.values(), now),
    )
    connection.execute(
        "INSERT INTO secrets (name, value, created_at) VALUES (?, ?, ?)",
        (SYNTHETIC_SECRET["name"], SYNTHETIC_SECRET["value"], now),
    )


def reset_domain_state() -> None:
    """Reset mutable business state while preserving evaluation evidence."""
    init_db()
    with connect() as connection:
        for table in (
            "approval_tokens",
            "approval_requests",
            "memory_entries",
            "payments",
            "vendors",
            "secrets",
        ):
            connection.execute(f"DELETE FROM {table}")
        connection.execute(
            """DELETE FROM mandates WHERE id NOT IN (
            SELECT mandate_id FROM runs
            WHERE evaluation_run_id IS NOT NULL AND mandate_id IS NOT NULL
            )"""
        )
        _seed_trusted_state(connection)


def _state_counts(connection: sqlite3.Connection) -> dict[str, int]:
    tables = (
        "vendors",
        "payments",
        "memory_entries",
        "runs",
        "tool_events",
        "mandates",
        "approval_requests",
        "approval_tokens",
        "evaluation_runs",
        "evaluation_results",
    )
    return {
        table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in tables
    }


def reset_db(*, preserve_evaluations: bool = True) -> dict:
    """Restore a deterministic demo state and return an auditable summary.

    The default keeps completed Level 2 reports so judges can inspect prior
    evidence after an interactive reset. ``preserve_evaluations=False`` is the
    clean-room reset used by reliability tests and pre-demo rehearsal. The
    persistent Ed25519 key lives outside SQLite and is intentionally untouched.
    """
    init_db()
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if preserve_evaluations:
            # Keep only evidence attached to evaluation runs. This also removes
            # mandate-lifecycle events whose run_id is a mandate id rather than
            # a row in runs, closing the stale-event gap in the older reset.
            connection.execute(
                """DELETE FROM tool_events
                WHERE run_id NOT IN (
                    SELECT id FROM runs WHERE evaluation_run_id IS NOT NULL
                )"""
            )
            connection.execute("DELETE FROM runs WHERE evaluation_run_id IS NULL")
        else:
            connection.execute("DELETE FROM tool_events")
            connection.execute("DELETE FROM evaluation_results")
            connection.execute("DELETE FROM evaluation_runs")
            connection.execute("DELETE FROM runs")

        for table in (
            "approval_tokens",
            "approval_requests",
            "memory_entries",
            "payments",
            "vendors",
            "secrets",
        ):
            connection.execute(f"DELETE FROM {table}")

        if preserve_evaluations:
            connection.execute(
                """DELETE FROM mandates WHERE id NOT IN (
                SELECT mandate_id FROM runs
                WHERE evaluation_run_id IS NOT NULL AND mandate_id IS NOT NULL
                )"""
            )
        else:
            connection.execute("DELETE FROM mandates")

        _seed_trusted_state(connection)
        counts = _state_counts(connection)

    return {
        "status": "reset",
        "scope": "demo" if preserve_evaluations else "all",
        "signing_key_preserved": True,
        "counts": counts,
    }


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
