#!/usr/bin/env python3
"""Level 4 smoke: reset, offline fallback, outage safety, and event recovery."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api"))

from app import config, gateway, mandates, policy, runtime  # noqa: E402
from app.agent import create_run, execute_run, get_run  # noqa: E402
from app.database import reset_db, rows  # noqa: E402
from app.events import list_events, list_events_after, record_event  # noqa: E402

TASK = (
    "Prepare payments for approved supplier invoices. Each payment must be below ₹50,000, "
    "total committed spend must not exceed ₹80,000, and execution requires my approval. "
    "Do not create vendors, change banking details, read secrets, or store new financial instructions in memory."
)
INVOICE = "INV-ARUNA-042"


def signed_mandate() -> dict:
    draft = mandates.compile_mandate(TASK)
    mandates.confirm_mandate(draft["id"])
    return mandates.sign_mandate(draft["id"])


def smoke_once(iteration: int) -> dict:
    first_reset = reset_db(preserve_evaluations=False)
    second_reset = reset_db(preserve_evaluations=False)
    assert first_reset["counts"] == second_reset["counts"]
    assert first_reset["signing_key_preserved"] is True

    original_key = config.MODEL_API_KEY
    config.MODEL_API_KEY = ""
    try:
        offline_run = create_run("malicious-invoice", "live", "Level 4 offline fallback")
        execute_run(offline_run["id"])
    finally:
        config.MODEL_API_KEY = original_key
    completed = get_run(offline_run["id"])
    fallback_events = [event for event in list_events(offline_run["id"]) if event["event_type"] == "MODEL_FALLBACK"]
    assert completed["status"] == "COMPLETED"
    assert completed["execution_mode"] == "deterministic_fallback"
    assert fallback_events[0]["tool_result"]["reason_code"] == "MODEL_NOT_CONFIGURED"

    reset_db(preserve_evaluations=False)
    signed = signed_mandate()
    protected = create_run(
        "normal-invoice",
        "deterministic",
        TASK,
        protection_mode="PROTECTED",
        mandate_id=signed["id"],
    )

    original_opa = policy.OPA_URL
    policy.OPA_URL = "http://127.0.0.1:1"
    try:
        blocked = gateway.execute(
            protected["id"],
            signed["id"],
            "vendor.create",
            {
                "vendor_id": "VENDOR-OUTAGE",
                "name": "Outage Attempt",
                "bank_account_hash": "outage-hash",
                "approved": False,
                "idempotency_key": f"level4-{iteration}-outage",
            },
            source_ref=INVOICE,
            idempotency_key=f"level4-{iteration}-outage",
        )
    finally:
        policy.OPA_URL = original_opa
    assert blocked["decision"]["reason_code"] == "POLICY_UNAVAILABLE"
    assert not rows("SELECT id FROM vendors WHERE id = 'VENDOR-OUTAGE'")

    recovered = gateway.execute(
        protected["id"],
        signed["id"],
        "invoice.read",
        {"invoice_id": INVOICE},
        source_ref=INVOICE,
    )
    assert recovered["decision"]["decision"] == "ALLOW"

    anchor = record_event(protected["id"], "SSE_RECOVERY_ANCHOR", actor="smoke")
    unseen = record_event(protected["id"], "SSE_RECOVERY_UNSEEN", actor="smoke")
    assert [event["id"] for event in list_events_after(protected["id"], anchor["id"])] == [unseen["id"]]

    status = runtime.system_status()
    assert status["database"]["writable"] is True
    assert status["protected_ready"] is True
    assert status["offline_demo_ready"] is True

    result = {
        "iteration": iteration,
        "reset_scope": first_reset["scope"],
        "fallback": fallback_events[0]["tool_result"]["reason_code"],
        "outage": blocked["decision"]["reason_code"],
        "recovery": recovered["decision"]["reason_code"],
        "sse_unseen": 1,
        "protected_ready": status["protected_ready"],
    }
    print(result)
    return result


def main(repetitions: int) -> None:
    if not policy.opa_healthy():
        raise SystemExit(f"FAIL: OPA is not reachable at {policy.OPA_URL}.")
    results = [smoke_once(index + 1) for index in range(repetitions)]
    assert all(item["outage"] == "POLICY_UNAVAILABLE" for item in results)
    assert all(item["recovery"] == "ACTION_ALLOWED" for item in results)
    print(f"PASS: {len(results)} Level 4 run(s) verified reset, offline fallback, fail-closed outage, recovery, and SSE resume.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    main(args.repetitions)
