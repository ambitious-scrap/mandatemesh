"""OPA policy decision-point client.

Only the trusted gateway constructs policy input and calls this module. The
input carries a ``verification`` block computed by the gateway (Ed25519 checked
in Python); OPA never sees or trusts a client-supplied signature flag.

Every failure path — connection error, timeout, non-200, malformed body, or a
response that does not match the decision contract — fails closed with a
``POLICY_UNAVAILABLE`` BLOCK. Consequential actions therefore never proceed on a
degraded policy engine.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .config import OPA_DECISION_PATH, OPA_TIMEOUT_SECONDS, OPA_URL

_DECISIONS = frozenset({"ALLOW", "BLOCK", "REQUIRE_APPROVAL"})


def _fail_closed(message: str) -> dict:
    return {
        "decision": "BLOCK",
        "reason_code": "POLICY_UNAVAILABLE",
        "message": message,
        "matched_rules": ["fail_closed"],
        "required_approval": None,
        "policy_version": None,
    }


def _valid(decision: object) -> bool:
    return (
        isinstance(decision, dict)
        and decision.get("decision") in _DECISIONS
        and isinstance(decision.get("reason_code"), str)
        and isinstance(decision.get("matched_rules"), list)
    )


def query_decision(policy_input: dict) -> dict:
    """Return an OPA decision, or a fail-closed BLOCK on any error."""
    body = json.dumps({"input": policy_input}).encode("utf-8")
    request = urllib.request.Request(
        f"{OPA_URL}{OPA_DECISION_PATH}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=OPA_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                return _fail_closed(f"Policy engine returned HTTP {response.status}.")
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return _fail_closed(f"Policy engine unreachable: {error}.")
    except (json.JSONDecodeError, ValueError) as error:
        return _fail_closed(f"Policy engine returned an unreadable body: {error}.")

    decision = payload.get("result") if isinstance(payload, dict) else None
    if not _valid(decision):
        return _fail_closed("Policy engine returned a malformed decision.")
    decision.setdefault("required_approval", None)
    decision.setdefault("message", "")
    return decision


def opa_healthy() -> bool:
    """Best-effort readiness probe used by /health. Never raises."""
    try:
        with urllib.request.urlopen(f"{OPA_URL}/health", timeout=OPA_TIMEOUT_SECONDS) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False
