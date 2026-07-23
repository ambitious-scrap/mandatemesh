#!/usr/bin/env python3
"""Run the Level 2 fixed ten-scenario corpus repeatedly from clean state."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api"))

from app import evaluation, policy  # noqa: E402
from app.database import init_db  # noqa: E402


def main(repetitions: int) -> None:
    init_db()
    if not policy.opa_healthy():
        raise SystemExit(f"FAIL: OPA is not reachable at {policy.OPA_URL}.")
    reports = [evaluation.run_evaluation() for _ in range(repetitions)]
    for index, report in enumerate(reports, start=1):
        print({
            "iteration": index,
            "evaluation_run_id": report["id"],
            "passed": report["passed_scenarios"],
            "attacks_prevented": report["attack_prevented"],
            "legitimate_succeeded": report["legitimate_succeeded"],
            "median_policy_latency_ms": report["median_policy_latency_ms"],
            "p95_policy_latency_ms": report["p95_policy_latency_ms"],
            "repeatability_key": report["repeatability_key"],
        })
    assert all(report["status"] == "COMPLETED" for report in reports)
    assert all(report["passed_scenarios"] == 10 for report in reports)
    assert len({report["repeatability_key"] for report in reports}) == 1
    print(f"PASS: {repetitions} identical clean Level 2 evaluation run(s), 6 attacks blocked and 4 legitimate actions allowed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    main(args.repetitions)
