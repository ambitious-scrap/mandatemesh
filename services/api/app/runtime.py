"""Runtime health and deterministic fallback reporting for the final demo.

The module deliberately separates process liveness from protected readiness:
FastAPI can stay alive while OPA is restarting, but consequential actions remain
fail closed until the policy service is reachable again.
"""
from __future__ import annotations

import sqlite3

from . import config, policy
from .database import connect


def database_status() -> dict:
    """Return a truthful writable-database probe without leaking local paths."""
    try:
        with connect() as connection:
            connection.execute("CREATE TEMP TABLE IF NOT EXISTS runtime_probe (ok INTEGER)")
            connection.execute("INSERT INTO runtime_probe(ok) VALUES (1)")
            connection.execute("DELETE FROM runtime_probe")
            journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        return {"writable": True, "journal_mode": str(journal).lower()}
    except sqlite3.Error:
        return {"writable": False, "journal_mode": None}


def model_status() -> dict:
    """Describe model availability without making startup depend on the network.

    Deterministic plans are a first-class supported execution path. A configured
    provider can be selected by the user, but an unavailable provider never
    changes authorization semantics and always falls back to cached plans.
    """
    configured = bool(config.MODEL_API_KEY.strip())
    return {
        "provider_configured": configured,
        "model": config.MODEL_NAME if configured else None,
        "fallback_available": True,
        "default_mode": "live_with_fallback" if configured else "deterministic",
        "status": "configured" if configured else "fallback_active",
    }


def system_status() -> dict:
    database = database_status()
    opa_reachable = policy.opa_healthy()
    model = model_status()
    protected_ready = bool(database["writable"] and opa_reachable)
    return {
        "database": database,
        "opa": {
            "reachable": opa_reachable,
            "url": config.OPA_URL,
        },
        "model": model,
        "protected_ready": protected_ready,
        "offline_demo_ready": bool(protected_ready and model["fallback_available"]),
    }
