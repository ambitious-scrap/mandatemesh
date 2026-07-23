"""Level 2 fixed-corpus evaluation and execution-provenance tests."""
from __future__ import annotations

from app import evaluation, mandates
from app.database import rows
from app.events import get_event, list_events


def test_fixed_corpus_contains_six_attacks_and_four_legitimate_actions():
    assert len(evaluation.CASES) == 10
    assert sum(case.category == "ATTACK" for case in evaluation.CASES) == 6
    assert sum(case.category == "LEGITIMATE" for case in evaluation.CASES) == 4


def test_evaluation_runs_all_ten_scenarios_and_persists_results(opa):
    report = evaluation.run_evaluation()
    assert report["status"] == "COMPLETED"
    assert report["total_scenarios"] == 10
    assert report["passed_scenarios"] == 10
    assert report["attack_prevented"] == 6
    assert report["legitimate_succeeded"] == 4
    assert report["false_blocks"] == 0
    assert len(report["results"]) == 10
    assert rows("SELECT COUNT(*) AS n FROM evaluation_results")[0]["n"] == 10


def test_evaluation_records_policy_latency_and_repeatability_key(opa):
    report = evaluation.run_evaluation()
    assert report["median_policy_latency_ms"] is not None
    assert report["p95_policy_latency_ms"] is not None
    assert report["p95_policy_latency_ms"] >= report["median_policy_latency_ms"]
    assert report["repeatability_key"]
    assert all(result["latency_ms"] is not None for result in report["results"])


def test_failed_or_passed_scenario_is_fully_inspectable(opa):
    report = evaluation.run_evaluation()
    result = next(item for item in report["results"] if item["scenario_id"] == "ATK-01")
    event = get_event(result["evidence_event_id"])
    assert event["source_ref"]
    assert event["tool_arguments"]
    assert event["canonical_action"]["canonical_action"] == "financial.payment.prepare"
    assert event["policy_input"]["mandate"]["max_total_payment"] == 80000
    assert event["decision"]["reason_code"] == "BENEFICIARY_MISMATCH"
    assert event["before_state"] is not None
    assert event["after_state"] is not None
    assert event["policy_version"] == "mandatemesh-authz-v1"


def test_blocked_attack_results_have_no_side_effect(opa):
    report = evaluation.run_evaluation()
    attacks = [result for result in report["results"] if result["category"] == "ATTACK"]
    assert len(attacks) == 6
    assert all(result["passed"] for result in attacks)
    assert not any(result["side_effect_detected"] for result in attacks)


def test_every_protected_consequential_action_links_to_signed_mandate(opa):
    report = evaluation.run_evaluation()
    for result in report["results"]:
        events = list_events(result["protected_run_id"])
        for event in events:
            canonical = event.get("canonical_action") or {}
            if canonical.get("canonical_action") in {
                "vendor.record.create",
                "financial.payment.prepare",
                "financial.payment.execute",
                "memory.financial_instruction.write",
            }:
                assert event["mandate_id"]
                assert canonical["mandate_id"] == event["mandate_id"]


def test_three_clean_evaluations_are_identical(opa):
    reports = [evaluation.run_evaluation() for _ in range(3)]
    assert all(report["status"] == "COMPLETED" for report in reports)
    assert len({report["repeatability_key"] for report in reports}) == 1
    signatures = [
        [(item["scenario_id"], item["actual_decision"], item["reason_code"], item["passed"]) for item in report["results"]]
        for report in reports
    ]
    assert signatures[0] == signatures[1] == signatures[2]


def test_evaluation_history_survives_interactive_reset(opa):
    from app.database import reset_db

    report = evaluation.run_evaluation()
    reset_db()
    persisted = evaluation.get_evaluation(report["id"])
    assert persisted is not None
    assert len(persisted["results"]) == 10
    assert get_event(persisted["results"][0]["evidence_event_id"])
    mandate_ids = {
        item["details"].get("mandate_id")
        for item in persisted["results"]
        if item["details"].get("mandate_id")
    }
    assert len(mandate_ids) == 10
    assert all(mandates.get_mandate(mandate_id) for mandate_id in mandate_ids)


def test_scenario_runtime_failure_is_persisted_and_inspectable(opa, monkeypatch):
    original = evaluation._run_protected

    def fail_one(evaluation_run_id, case):
        if case.scenario_id == "ATK-01":
            raise RuntimeError("synthetic evaluator fault")
        return original(evaluation_run_id, case)

    monkeypatch.setattr(evaluation, "_run_protected", fail_one)
    report = evaluation.run_evaluation()
    assert report["status"] == "FAILED"
    assert len(report["results"]) == 10
    failed = next(result for result in report["results"] if result["scenario_id"] == "ATK-01")
    assert failed["actual_decision"] == "ERROR"
    assert failed["reason_code"] == "EVALUATION_ERROR"
    event = get_event(failed["evidence_event_id"])
    assert event["event_type"] == "EVALUATION_ERROR"
    assert "synthetic evaluator fault" in event["tool_result"]["error"]


def test_database_context_manager_closes_connection():
    import sqlite3
    from app.database import connect

    connection = connect()
    with connection:
        connection.execute("SELECT 1")
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        pass
    else:
        raise AssertionError("database context manager must close its connection")
