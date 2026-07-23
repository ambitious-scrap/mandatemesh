"""Memory trust-state helpers.

Protected policy denials may preserve an attempted write as quarantined evidence,
but quarantined rows are never returned by trusted retrieval. The ordinary
``memory.write`` tool remains unchanged for the intentionally vulnerable Level 0
baseline.
"""
from __future__ import annotations

import uuid

from .database import connect, rows, utc_now


class MemoryError(ValueError):
    pass


def _same_attempt(existing: dict, arguments: dict, run_id: str, mandate_id: str) -> bool:
    return (
        existing.get("content") == arguments.get("content")
        and existing.get("memory_type") == arguments.get("memory_type")
        and existing.get("source_ref") == arguments.get("source_ref")
        and existing.get("run_id") == run_id
        and existing.get("mandate_id") == mandate_id
        and existing.get("status") == "QUARANTINED"
    )


def quarantine_attempt(
    *,
    run_id: str,
    mandate_id: str,
    arguments: dict,
    reason_code: str,
) -> tuple[dict, dict | None]:
    """Persist a denied memory write as non-retrievable evidence.

    Idempotency is enforced on the same key used by the proposed tool action.
    A collision with a different attempt fails closed rather than overwriting
    evidence.
    """
    required = ("content", "memory_type", "source_ref", "idempotency_key")
    missing = [name for name in required if arguments.get(name) in (None, "")]
    if missing:
        raise MemoryError(f"Missing quarantine fields: {', '.join(missing)}")

    key = str(arguments["idempotency_key"])
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM memory_entries WHERE idempotency_key = ?", (key,)
        ).fetchone()
        if row is not None:
            existing = dict(row)
            if _same_attempt(existing, arguments, run_id, mandate_id):
                connection.commit()
                return {**existing, "idempotent_replay": True}, None
            connection.rollback()
            raise MemoryError("Idempotency key belongs to a different memory write.")

        entry = {
            "id": f"MEMQ-{uuid.uuid4().hex[:10].upper()}",
            "content": arguments["content"],
            "memory_type": arguments["memory_type"],
            "source_ref": arguments["source_ref"],
            "trust_level": arguments.get("trust_level", "UNTRUSTED"),
            "status": "QUARANTINED",
            "idempotency_key": key,
            "created_at": utc_now(),
            "quarantine_reason": reason_code,
            "run_id": run_id,
            "mandate_id": mandate_id,
            "reviewed_at": None,
        }
        connection.execute(
            """INSERT INTO memory_entries
            (id, content, memory_type, source_ref, trust_level, status,
             idempotency_key, created_at, quarantine_reason, run_id, mandate_id, reviewed_at)
            VALUES (:id, :content, :memory_type, :source_ref, :trust_level, :status,
                    :idempotency_key, :created_at, :quarantine_reason, :run_id, :mandate_id, :reviewed_at)""",
            entry,
        )
        connection.commit()
    return entry, {"table": "memory_entries", "operation": "QUARANTINE", "record": entry}


def trusted_entries() -> list[dict]:
    """Return only entries eligible for future agent retrieval."""
    return rows(
        """SELECT * FROM memory_entries
        WHERE status = 'ACTIVE' AND trust_level IN ('TRUSTED', 'HUMAN_CONFIRMED')
        ORDER BY created_at"""
    )


def active_entries() -> list[dict]:
    """Return all non-quarantined active entries for diagnostic comparison."""
    return rows("SELECT * FROM memory_entries WHERE status = 'ACTIVE' ORDER BY created_at")


def quarantined_entries() -> list[dict]:
    return rows("SELECT * FROM memory_entries WHERE status = 'QUARANTINED' ORDER BY created_at")
