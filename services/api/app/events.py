from __future__ import annotations

import json
import uuid

from .database import connect, decode_json_fields, rows, utc_now


def record_event(
    run_id: str,
    event_type: str,
    *,
    actor: str,
    source_ref: str | None = None,
    tool_name: str | None = None,
    tool_arguments: dict | None = None,
    tool_result: dict | None = None,
    side_effect: dict | None = None,
    is_forbidden: bool = False,
    latency_ms: float | None = None,
) -> dict:
    event = {
        "id": str(uuid.uuid4()),
        "run_id": run_id,
        "created_at": utc_now(),
        "actor": actor,
        "event_type": event_type,
        "source_ref": source_ref,
        "tool_name": tool_name,
        "tool_arguments_json": json.dumps(tool_arguments) if tool_arguments is not None else None,
        "tool_result_json": json.dumps(tool_result) if tool_result is not None else None,
        "side_effect_json": json.dumps(side_effect) if side_effect is not None else None,
        "is_forbidden": int(is_forbidden),
        "latency_ms": latency_ms,
    }
    with connect() as connection:
        connection.execute(
            """INSERT INTO tool_events
            (id, run_id, created_at, actor, event_type, source_ref, tool_name,
             tool_arguments_json, tool_result_json, side_effect_json, is_forbidden, latency_ms)
            VALUES (:id, :run_id, :created_at, :actor, :event_type, :source_ref, :tool_name,
                    :tool_arguments_json, :tool_result_json, :side_effect_json, :is_forbidden, :latency_ms)""",
            event,
        )
    return get_event(event["id"])


def get_event(event_id: str) -> dict:
    result = rows("SELECT * FROM tool_events WHERE id = ?", (event_id,))
    return decode_json_fields(result, ("tool_arguments_json", "tool_result_json", "side_effect_json"))[0]


def list_events(run_id: str) -> list[dict]:
    result = rows("SELECT * FROM tool_events WHERE run_id = ? ORDER BY created_at, rowid", (run_id,))
    return decode_json_fields(result, ("tool_arguments_json", "tool_result_json", "side_effect_json"))

