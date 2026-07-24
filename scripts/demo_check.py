#!/usr/bin/env python3
"""Fast pre-presentation check against a running MandateMesh stack."""
from __future__ import annotations

import argparse
import json
import socket
import urllib.error
import urllib.request


def get_json(url: str) -> tuple[int, dict | list]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {"detail": "Service returned an unreadable error response."}
        return error.code, body
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
        return 0, {"detail": "Service is unreachable."}
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return 0, {"detail": "Service returned an unreadable response."}


def main(base_url: str) -> None:
    base = base_url.rstrip("/")
    health_code, health = get_json(f"{base}/health")
    ready_code, ready = get_json(f"{base}/ready")
    runtime_code, runtime = get_json(f"{base}/api/runtime")
    scenarios_code, scenarios = get_json(f"{base}/api/scenarios")

    result = {
        "api_health": health_code,
        "protected_readiness": ready_code,
        "runtime": runtime_code,
        "scenario_count": len(scenarios) if isinstance(scenarios, list) else 0,
        "database_writable": health.get("database", {}).get("writable") if isinstance(health, dict) else False,
        "opa_reachable": ready.get("opa", {}).get("reachable") if isinstance(ready, dict) else False,
        "offline_demo_ready": runtime.get("offline_demo_ready") if isinstance(runtime, dict) else False,
        "model_status": runtime.get("model", {}).get("status") if isinstance(runtime, dict) else None,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if health_code != 200 or ready_code != 200 or runtime_code != 200 or scenarios_code != 200:
        raise SystemExit("FAIL: stack is not fully demo-ready")
    if (
        result["scenario_count"] < 2
        or not result["database_writable"]
        or not result["opa_reachable"]
        or not result["offline_demo_ready"]
    ):
        raise SystemExit("FAIL: required demo services or fixtures are missing")
    print("PASS: MandateMesh stack is ready for the five-minute demo.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default="http://localhost:8000")
    args = parser.parse_args()
    main(args.api_url)
