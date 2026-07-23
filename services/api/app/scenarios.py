from __future__ import annotations

import json

from .config import SCENARIO_DIR


def list_scenarios() -> list[dict]:
    return [json.loads(path.read_text()) for path in sorted(SCENARIO_DIR.glob("*.json"))]


def get_scenario(scenario_id: str) -> dict:
    for scenario in list_scenarios():
        if scenario["id"] == scenario_id:
            return scenario
    raise KeyError(f"Unknown scenario: {scenario_id}")


def get_scenario_by_invoice(invoice_id: str) -> dict:
    for scenario in list_scenarios():
        if scenario["invoice"]["invoice_id"] == invoice_id:
            return scenario
    raise KeyError(f"Unknown invoice: {invoice_id}")

