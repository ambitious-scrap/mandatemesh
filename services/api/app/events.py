from __future__ import annotations

import json
import uuid

from .database import connect, decode_json_fields, rows, utc_now


_JSON_FIELDS = (
    "tool_arguments_json",
    "tool_result_json",
    "canonical_action_json",
    "decision_json",
    "side_effect_json",
    "policy_input_json",
    "before_state_json",
    "after_state_json",
)


def record_event(
    run_id: str,
    event_type: str,
    *,
    actor: str,
    mandate_id: str | None = None,
    source_ref: str | None = None,
    tool_name: str | None = None,
    tool_arguments: dict | None = None,
    tool_result: dict | None = None,
    canonical_action: dict | None = None,
    decision: dict | None = None,
    side_effect: dict | None = None,
    policy_input: dict | None = None,
    before_state: dict | None = None,
    after_state: dict | None = None,
    policy_version: str | None = None,
    is_forbidden: bool = False,
    latency_ms: float | None = None,
) -> dict:
    event = {
        "id": str(uuid.uuid4()),
        "run_id": run_id,
        "mandate_id": mandate_id,
        "created_at": utc_now(),
        "actor": actor,
        "event_type": event_type,
        "source_ref": source_ref,
        "tool_name": tool_name,
        "tool_arguments_json": json.dumps(tool_arguments) if tool_arguments is not None else None,
        "tool_result_json": json.dumps(tool_result) if tool_result is not None else None,
        "canonical_action_json": json.dumps(canonical_action) if canonical_action is not None else None,
        "decision_json": json.dumps(decision) if decision is not None else None,
        "side_effect_json": json.dumps(side_effect) if side_effect is not None else None,
        "policy_input_json": json.dumps(policy_input) if policy_input is not None else None,
        "before_state_json": json.dumps(before_state) if before_state is not None else None,
        "after_state_json": json.dumps(after_state) if after_state is not None else None,
        "policy_version": policy_version,
        "is_forbidden": int(is_forbidden),
        "latency_ms": latency_ms,
    }
    with connect() as connection:
        connection.execute(
            """INSERT INTO tool_events
            (id, run_id, mandate_id, created_at, actor, event_type, source_ref, tool_name,
             tool_arguments_json, tool_result_json, canonical_action_json, decision_json,
             side_effect_json, policy_input_json, before_state_json, after_state_json,
             policy_version, is_forbidden, latency_ms)
            VALUES (:id, :run_id, :mandate_id, :created_at, :actor, :event_type, :source_ref, :tool_name,
                    :tool_arguments_json, :tool_result_json, :canonical_action_json, :decision_json,
                    :side_effect_json, :policy_input_json, :before_state_json, :after_state_json,
                    :policy_version, :is_forbidden, :latency_ms)""",
            event,
        )
    return get_event(event["id"])


def get_event(event_id: str) -> dict:
    result = rows("SELECT * FROM tool_events WHERE id = ?", (event_id,))
    return decode_json_fields(result, _JSON_FIELDS)[0]


def list_events(run_id: str) -> list[dict]:
    result = rows("SELECT * FROM tool_events WHERE run_id = ? ORDER BY rowid", (run_id,))
    return decode_json_fields(result, _JSON_FIELDS)


def list_events_after(run_id: str, event_id: str | None) -> list[dict]:
    """Return persisted events after ``event_id`` for SSE resume/reload recovery.

    Unknown or stale event IDs deliberately fall back to the complete ledger;
    clients deduplicate by the stable UUID. This favors evidence recovery over
    silently skipping events after a browser cache or database reset.
    """
    if not event_id:
        return list_events(run_id)
    anchor = rows(
        "SELECT rowid AS sequence FROM tool_events WHERE id = ? AND run_id = ?",
        (event_id, run_id),
    )
    if not anchor:
        return list_events(run_id)
    result = rows(
        "SELECT * FROM tool_events WHERE run_id = ? AND rowid > ? ORDER BY rowid",
        (run_id, anchor[0]["sequence"]),
    )
    return decode_json_fields(result, _JSON_FIELDS)
