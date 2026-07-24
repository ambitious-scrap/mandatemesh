"""Level 4 reliability, reset, outage, fallback, and event recovery gates."""
from __future__ import annotations

import json
import urllib.error
from pathlib import Path

from fastapi.testclient import TestClient

from app import config, crypto, gateway, mandates, policy, runtime
from app.agent import create_run, execute_run, get_run
from app.database import connect, reset_db, rows, utc_now
from app.events import list_events, list_events_after, record_event
from app.main import app
from app.tools import execute_tool

DEMO_TASK = (
    "Prepare payments for approved supplier invoices. Each payment must be below ₹50,000, "
    "total committed spend must not exceed ₹80,000, and execution requires my approval. "
    "Do not create vendors, change banking details, read secrets, or store new financial instructions in memory."
)


def _signed_mandate() -> dict:
    draft = mandates.compile_mandate(DEMO_TASK)
    mandates.confirm_mandate(draft["id"])
    return mandates.sign_mandate(draft["id"])


def _protected_run(mandate_id: str) -> str:
    return create_run(
        "normal-invoice",
        "deterministic",
        DEMO_TASK,
        protection_mode="PROTECTED",
        mandate_id=mandate_id,
    )["id"]


class _Response:
    def __init__(self, payload: object, status: int = 200):
        self.status = status
        self._payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._payload


def test_reset_is_repeatable_complete_and_preserves_signing_key():
    key_path = Path(config.KEY_PATH)
    crypto.ensure_key()
    original_key = key_path.read_bytes()

    execute_tool(
        "vendor.create",
        {
            "vendor_id": "VENDOR-RESET",
            "name": "Reset Test",
            "bank_account_hash": "reset-hash",
            "approved": False,
            "idempotency_key": "reset-vendor",
        },
    )
    with connect() as connection:
        connection.execute(
            "INSERT INTO evaluation_runs (id, status, started_at) VALUES (?, ?, ?)",
            ("EVAL-KEEP", "COMPLETED", utc_now()),
        )

    first = reset_db()
    second = reset_db()
    assert first["counts"] == second["counts"]
    assert first["scope"] == "demo"
    assert rows("SELECT id FROM evaluation_runs") == [{"id": "EVAL-KEEP"}]
    assert rows("SELECT id FROM vendors") == [{"id": "VENDOR-101"}]
    assert key_path.read_bytes() == original_key

    clean_first = reset_db(preserve_evaluations=False)
    clean_second = reset_db(preserve_evaluations=False)
    assert clean_first["counts"] == clean_second["counts"]
    assert clean_first["scope"] == "all"
    assert rows("SELECT id FROM evaluation_runs") == []
    assert rows("SELECT id FROM runs") == []
    assert rows("SELECT id FROM tool_events") == []
    assert rows("SELECT id FROM vendors") == [{"id": "VENDOR-101"}]
    assert key_path.read_bytes() == original_key


def test_live_model_failure_uses_sanitized_deterministic_fallback(monkeypatch):
    monkeypatch.setattr(config, "MODEL_API_KEY", "")
    run = create_run("malicious-invoice", "live", "offline rehearsal")
    execute_run(run["id"])

    completed = get_run(run["id"])
    assert completed["status"] == "COMPLETED"
    assert completed["execution_mode"] == "deterministic_fallback"
    fallback = next(event for event in list_events(run["id"]) if event["event_type"] == "MODEL_FALLBACK")
    assert fallback["tool_result"] == {
        "reason_code": "MODEL_NOT_CONFIGURED",
        "fallback_mode": "deterministic",
        "authorization_semantics": "unchanged",
    }
    assert "MODEL_API_KEY" not in json.dumps(fallback)


def test_policy_unreachable_timeout_and_malformed_all_fail_closed(monkeypatch):
    failures = [
        urllib.error.URLError("connection refused"),
        TimeoutError("timed out"),
    ]
    for failure in failures:
        monkeypatch.setattr(policy.urllib.request, "urlopen", lambda *_a, _failure=failure, **_k: (_ for _ in ()).throw(_failure))
        decision = policy.query_decision({"action": {}})
        assert decision["decision"] == "BLOCK"
        assert decision["reason_code"] == "POLICY_UNAVAILABLE"
        assert "connection refused" not in decision["message"]

    monkeypatch.setattr(policy.urllib.request, "urlopen", lambda *_a, **_k: _Response("not-a-decision"))
    malformed = policy.query_decision({"action": {}})
    assert malformed["decision"] == "BLOCK"
    assert malformed["reason_code"] == "POLICY_UNAVAILABLE"


def test_policy_outage_has_no_side_effect_and_recovery_uses_policy_again(monkeypatch):
    signed = _signed_mandate()
    run_id = _protected_run(signed["id"])

    monkeypatch.setattr(
        policy.urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(urllib.error.URLError("down")),
    )
    blocked = gateway.execute(
        run_id,
        signed["id"],
        "vendor.create",
        {
            "vendor_id": "VENDOR-OUTAGE",
            "name": "Must Not Exist",
            "bank_account_hash": "bad",
            "approved": False,
            "idempotency_key": "outage-create",
        },
        source_ref="INV-ARUNA-042",
        idempotency_key="outage-create",
    )
    assert blocked["decision"]["reason_code"] == "POLICY_UNAVAILABLE"
    assert rows("SELECT id FROM vendors WHERE id = 'VENDOR-OUTAGE'") == []

    recovered_decision = {
        "decision": "ALLOW",
        "reason_code": "ACTION_ALLOWED",
        "message": "Allowed by recovered policy.",
        "matched_rules": ["allow_action"],
        "required_approval": None,
        "policy_version": "mandatemesh-authz-v1",
    }
    monkeypatch.setattr(
        policy.urllib.request,
        "urlopen",
        lambda *_a, **_k: _Response({"result": recovered_decision}),
    )
    allowed = gateway.execute(
        run_id,
        signed["id"],
        "invoice.read",
        {"invoice_id": "INV-ARUNA-042"},
        source_ref="INV-ARUNA-042",
    )
    assert allowed["decision"]["reason_code"] == "ACTION_ALLOWED"
    assert allowed["tool_result"]["invoice_id"] == "INV-ARUNA-042"


def test_event_resume_returns_only_unseen_events_and_stream_uses_stable_ids():
    run = create_run("normal-invoice", "deterministic", "event recovery")
    first = record_event(run["id"], "RECOVERY_ONE", actor="test")
    second = record_event(run["id"], "RECOVERY_TWO", actor="test")
    third = record_event(run["id"], "RECOVERY_THREE", actor="test")
    with connect() as connection:
        connection.execute(
            "UPDATE runs SET status = 'COMPLETED', completed_at = ? WHERE id = ?",
            (utc_now(), run["id"]),
        )

    assert [item["id"] for item in list_events_after(run["id"], first["id"])] == [second["id"], third["id"]]
    assert [item["id"] for item in list_events_after(run["id"], "stale-browser-id")] == [
        event["id"] for event in list_events(run["id"])
    ]

    client = TestClient(app)
    response = client.get(
        f"/api/runs/{run['id']}/stream",
        headers={"Last-Event-ID": second["id"]},
    )
    assert response.status_code == 200
    assert f"id: {third['id']}" in response.text
    assert f"id: {first['id']}" not in response.text
    assert "event: run_status" in response.text
    before = rows("SELECT COUNT(*) AS n FROM tool_events WHERE run_id = ?", (run["id"],))[0]["n"]
    client.get(f"/api/runs/{run['id']}/events?after={first['id']}")
    after = rows("SELECT COUNT(*) AS n FROM tool_events WHERE run_id = ?", (run["id"],))[0]["n"]
    assert before == after


def test_health_separates_liveness_readiness_and_offline_fallback(monkeypatch):
    monkeypatch.setattr(policy, "opa_healthy", lambda: False)
    health = runtime.system_status()
    assert health["database"]["writable"] is True
    assert health["protected_ready"] is False
    assert health["offline_demo_ready"] is False
    assert health["model"]["fallback_available"] is True

    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 503

    monkeypatch.setattr(policy, "opa_healthy", lambda: True)
    assert client.get("/ready").status_code == 200
    assert runtime.system_status()["offline_demo_ready"] is True


def test_reset_endpoint_rejects_unknown_scope():
    client = TestClient(app)
    response = client.post("/api/reset?scope=filesystem")
    assert response.status_code == 400
    assert "demo" in response.json()["detail"]


def test_secret_value_never_enters_events_or_browser_payloads():
    reset_db(preserve_evaluations=False)
    run = create_run("malicious-invoice", "deterministic", "secret redaction rehearsal")
    execute_run(run["id"])

    private_value = rows("SELECT value FROM secrets WHERE name = 'finance_api_key'")[0]["value"]
    event_payload = json.dumps(list_events(run["id"]), sort_keys=True)
    state_payload = TestClient(app).get("/api/state").text

    assert private_value not in event_payload
    assert private_value not in state_payload
    assert "[SYNTHETIC SECRET EXPOSED]" in event_payload
