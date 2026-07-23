from __future__ import annotations

import asyncio
import json
import sqlite3
import threading

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .agent import create_run, execute_run, get_run
from .database import DB_PATH, connect, init_db, reset_db, rows
from .events import list_events
from .scenarios import get_scenario, list_scenarios
from .schemas import RunRequest, RunResponse


app = FastAPI(title="MandateMesh Level 0 API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()
    if not rows("SELECT id FROM vendors LIMIT 1"):
        reset_db()


@app.get("/health")
def health() -> dict:
    with connect() as connection:
        connection.execute("CREATE TEMP TABLE IF NOT EXISTS health_probe (ok INTEGER)")
    return {"status": "ok", "database": "writable", "journal_mode": "wal", "database_path": str(DB_PATH)}


@app.get("/api/scenarios")
def scenarios() -> list[dict]:
    return list_scenarios()


@app.post("/api/runs", response_model=RunResponse, status_code=202)
def start_run(request: RunRequest) -> dict:
    try:
        get_scenario(request.scenario_id)
        run = create_run(request.scenario_id, request.execution_mode, request.task)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    threading.Thread(target=execute_run, args=(run["id"],), daemon=True).start()
    return run


@app.get("/api/runs/{run_id}", response_model=RunResponse)
def run_status(run_id: str) -> dict:
    try:
        return get_run(run_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.get("/api/runs/{run_id}/events")
def run_events(run_id: str) -> list[dict]:
    try:
        get_run(run_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return list_events(run_id)


@app.get("/api/runs/{run_id}/stream")
async def run_stream(run_id: str) -> StreamingResponse:
    try:
        get_run(run_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    async def stream():
        sent: set[str] = set()
        while True:
            for event in list_events(run_id):
                if event["id"] not in sent:
                    sent.add(event["id"])
                    yield f"event: tool_event\ndata: {json.dumps(event)}\n\n"
            run = get_run(run_id)
            if run["status"] in {"COMPLETED", "FAILED"}:
                yield f"event: run_status\ndata: {json.dumps(run)}\n\n"
                break
            await asyncio.sleep(0.15)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.get("/api/state")
def state() -> dict:
    vendors = rows("SELECT id, name, bank_account_hash, approved, created_at FROM vendors ORDER BY created_at")
    for vendor in vendors:
        vendor["approved"] = bool(vendor["approved"])
    secret_accesses = rows(
        """SELECT id, run_id, created_at, source_ref, tool_name, is_forbidden
        FROM tool_events WHERE event_type = 'SIDE_EFFECT_RECORDED' AND tool_name = 'secret.read'
        ORDER BY created_at"""
    )
    for access in secret_accesses:
        access["exposed"] = True
        access["is_forbidden"] = bool(access["is_forbidden"])
    return {
        "vendors": vendors,
        "payments": rows("SELECT * FROM payments ORDER BY created_at"),
        "memory_entries": rows("SELECT * FROM memory_entries ORDER BY created_at"),
        "secret_accesses": secret_accesses,
    }


@app.get("/api/vendors")
def vendors() -> list[dict]:
    return state()["vendors"]


@app.get("/api/payments")
def payments() -> list[dict]:
    return state()["payments"]


@app.get("/api/memory-entries")
def memory_entries() -> list[dict]:
    return state()["memory_entries"]


@app.post("/api/reset")
def reset() -> dict:
    try:
        reset_db()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=f"Reset failed: {error}") from error
    return {"status": "reset", "state": state()}

