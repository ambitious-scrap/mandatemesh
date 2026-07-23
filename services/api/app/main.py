from __future__ import annotations

import asyncio
import json
import sqlite3
import threading

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse

from . import approvals, crypto, evaluation, gateway, mandates, mcp, memory, policy
from .agent import create_run, execute_run, get_run, resume_after_approval
from .config import OPA_URL
from .database import DB_PATH, connect, init_db, reset_db, rows, utc_now
from .events import get_event, list_events, record_event
from .scenarios import get_scenario, list_scenarios
from .schemas import (
    CompileRequest,
    ConfirmRequest,
    EvaluationRunRequest,
    GatewayRequest,
    RunRequest,
    RunResponse,
    TamperRequest,
)


app = FastAPI(title="MandateMesh Level 3 API", version="3.0.0")
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
    crypto.ensure_key()
    if not rows("SELECT id FROM vendors LIMIT 1"):
        reset_db()


@app.get("/health")
def health() -> dict:
    with connect() as connection:
        connection.execute("CREATE TEMP TABLE IF NOT EXISTS health_probe (ok INTEGER)")
    opa_reachable = policy.opa_healthy()
    return {
        "status": "ok" if opa_reachable else "degraded",
        "database": "writable",
        "journal_mode": "wal",
        "database_path": str(DB_PATH),
        "protected_ready": opa_reachable,
        "opa": {"url": OPA_URL, "reachable": opa_reachable},
    }


@app.get("/ready")
def ready() -> JSONResponse:
    opa_reachable = policy.opa_healthy()
    payload = {
        "status": "ready" if opa_reachable else "not_ready",
        "database": "writable",
        "protected_ready": opa_reachable,
        "opa": {"url": OPA_URL, "reachable": opa_reachable},
    }
    return JSONResponse(status_code=200 if opa_reachable else 503, content=payload)


# --------------------------------------------------------------------------- #
# MCP Streamable HTTP adapter (same gateway and policy as REST)
# --------------------------------------------------------------------------- #
@app.post("/mcp")
async def mcp_post(request: Request) -> Response:
    origin = request.headers.get("origin")
    if not mcp.origin_allowed(origin):
        return JSONResponse(
            status_code=403,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Forbidden Origin"}},
        )
    try:
        message = await request.json()
    except (json.JSONDecodeError, ValueError):
        return JSONResponse(
            status_code=400,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
        )

    protocol = request.headers.get("mcp-protocol-version")
    if message.get("method") != "initialize" and protocol != mcp.PROTOCOL_VERSION:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32602, "message": "Unsupported MCP-Protocol-Version"},
            },
        )
    response = mcp.handle(message)
    if response is None:
        return Response(status_code=202)
    return JSONResponse(content=response, media_type="application/json")


@app.get("/mcp")
def mcp_get(request: Request) -> Response:
    if not mcp.origin_allowed(request.headers.get("origin")):
        return JSONResponse(
            status_code=403,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Forbidden Origin"}},
        )
    return JSONResponse(
        status_code=405,
        content={"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Server-initiated SSE is not enabled"}},
        headers={"Allow": "POST"},
    )


@app.get("/api/scenarios")
def scenarios() -> list[dict]:
    return list_scenarios()


# --------------------------------------------------------------------------- #
# Mandates
# --------------------------------------------------------------------------- #
@app.post("/api/mandates/compile")
def mandate_compile(request: CompileRequest) -> dict:
    mandate = mandates.compile_mandate(request.task)
    record_event(mandate["id"], "MANDATE_PROPOSED", actor="ai", mandate_id=mandate["id"],
                 tool_result={"status": mandate["status"], "warnings": mandate["warnings"]})
    return mandate


@app.get("/api/mandates")
def mandate_list() -> list[dict]:
    return mandates.list_mandates()


@app.get("/api/mandates/{mandate_id}")
def mandate_get(mandate_id: str) -> dict:
    mandate = mandates.get_mandate(mandate_id)
    if mandate is None:
        raise HTTPException(status_code=404, detail="Mandate not found.")
    return mandate


@app.get("/api/mandates/{mandate_id}/compiler-report")
def mandate_compiler_report(mandate_id: str) -> dict:
    mandate = mandates.get_mandate(mandate_id)
    if mandate is None:
        raise HTTPException(status_code=404, detail="Mandate not found.")
    return mandate["compiler_report"]


@app.post("/api/mandates/{mandate_id}/confirm")
def mandate_confirm(mandate_id: str, request: ConfirmRequest) -> dict:
    try:
        mandate = mandates.confirm_mandate(mandate_id, request.edits)
    except mandates.MandateError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record_event(mandate_id, "MANDATE_CONFIRMED", actor="user", mandate_id=mandate_id,
                 tool_result={"canonical_payload": mandate["canonical_payload"]})
    return mandate


@app.post("/api/mandates/{mandate_id}/sign")
def mandate_sign(mandate_id: str) -> dict:
    # The trusted backend holds the demo principal key and performs the signing.
    # No client-supplied signature is accepted; the agent cannot reach this path.
    try:
        mandate = mandates.sign_mandate(mandate_id)
    except mandates.MandateError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record_event(mandate_id, "MANDATE_SIGNED", actor="user", mandate_id=mandate_id,
                 tool_result={"status": mandate["status"], "public_key": mandate["public_key"]})
    return mandate


@app.post("/api/mandates/{mandate_id}/verify")
def mandate_verify(mandate_id: str) -> dict:
    try:
        result = mandates.verify_mandate(mandate_id)
    except mandates.MandateError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    if not result["valid"]:
        record_event(mandate_id, "MANDATE_VERIFICATION_FAILED", actor="gateway", mandate_id=mandate_id,
                     tool_result={"reason_code": result["reason_code"]})
    return result


@app.post("/api/mandates/{mandate_id}/tamper-demo")
def mandate_tamper(mandate_id: str, request: TamperRequest) -> dict:
    try:
        result = mandates.tamper_demo(mandate_id, request.field, request.value)
    except mandates.MandateError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record_event(mandate_id, "MANDATE_VERIFICATION_FAILED", actor="gateway", mandate_id=mandate_id,
                 tool_result={"reason_code": result["reason_code"], "tampered_field": result["tampered_field"]})
    return result


# --------------------------------------------------------------------------- #
# Runs
# --------------------------------------------------------------------------- #
@app.post("/api/runs", response_model=RunResponse, status_code=202)
def start_run(request: RunRequest) -> dict:
    try:
        get_scenario(request.scenario_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    if request.protection_mode == "PROTECTED":
        if not request.mandate_id:
            raise HTTPException(status_code=400, detail="Protected runs require a signed mandate_id.")
        mandate = mandates.get_mandate(request.mandate_id)
        if mandate is None:
            raise HTTPException(status_code=404, detail="Mandate not found.")
        verification = mandates.verification_for(mandate)
        if not verification["valid"]:
            raise HTTPException(status_code=400, detail=f"Mandate is not usable: {verification['reason_code']}.")

    run = create_run(
        request.scenario_id, request.execution_mode, request.task,
        protection_mode=request.protection_mode, mandate_id=request.mandate_id,
    )
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
            if run["status"] in {"COMPLETED", "FAILED", "BLOCKED", "REJECTED"}:
                yield f"event: run_status\ndata: {json.dumps(run)}\n\n"
                break
            await asyncio.sleep(0.15)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


# --------------------------------------------------------------------------- #
# Gateway (protected tool execution)
# --------------------------------------------------------------------------- #
@app.post("/api/gateway/execute")
def gateway_execute(request: GatewayRequest) -> dict:
    try:
        get_run(request.run_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return gateway.execute(
        request.run_id, request.mandate_id, request.tool_name, request.arguments,
        source_ref=request.source_ref, approval_token=request.approval_token,
        idempotency_key=request.idempotency_key,
    )


# --------------------------------------------------------------------------- #
# Approvals
# --------------------------------------------------------------------------- #
@app.get("/api/approvals/pending")
def approvals_pending() -> list[dict]:
    return approvals.list_pending()


@app.post("/api/approvals/{request_id}/approve")
def approvals_approve(request_id: str) -> dict:
    try:
        granted = approvals.approve(request_id)
    except approvals.ApprovalError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    request = granted["request"]
    event_run_id = request["run_id"] or request["mandate_id"]
    record_event(event_run_id, "APPROVAL_GRANTED", actor="user", mandate_id=request["mandate_id"],
                 tool_result={"approval_request_id": request_id, "action_hash": granted["action_hash"]})
    response: dict = {"request": request}
    # Resume the paused protected run with the freshly minted, one-use token.
    if request["run_id"]:
        outcome = resume_after_approval(request["run_id"], granted["payment_id"], granted["token"])
        response["decision"] = outcome["decision"]
    return response


@app.post("/api/approvals/{request_id}/reject")
def approvals_reject(request_id: str) -> dict:
    try:
        request = approvals.reject(request_id)
    except approvals.ApprovalError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    event_run_id = request["run_id"] or request["mandate_id"]
    record_event(event_run_id, "APPROVAL_REJECTED", actor="user", mandate_id=request["mandate_id"],
                 tool_result={"approval_request_id": request_id})
    if request["run_id"]:
        with connect() as connection:
            connection.execute(
                "UPDATE runs SET status = 'REJECTED', error = ?, completed_at = ? WHERE id = ? AND status = 'AWAITING_APPROVAL'",
                ("Human rejected the payment approval.", utc_now(), request["run_id"]),
            )
        record_event(request["run_id"], "RUN_REJECTED", actor="user", mandate_id=request["mandate_id"],
                     tool_result={"outcome": "approval_rejected"})
    return {"request": request}


# --------------------------------------------------------------------------- #
# Evidence and fixed evaluation corpus
# --------------------------------------------------------------------------- #
@app.get("/api/events/{event_id}")
def event_detail(event_id: str) -> dict:
    try:
        return get_event(event_id)
    except (IndexError, KeyError):
        raise HTTPException(status_code=404, detail="Event not found.")


@app.get("/api/evaluation")
def evaluation_list() -> list[dict]:
    return evaluation.list_evaluations()


@app.post("/api/evaluation/run")
def evaluation_run(request: EvaluationRunRequest) -> dict:
    if not policy.opa_healthy():
        raise HTTPException(status_code=503, detail="Protected evaluation requires a reachable OPA policy service.")
    try:
        return evaluation.run_evaluation()
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {error}") from error


@app.get("/api/evaluation/{evaluation_run_id}")
def evaluation_get(evaluation_run_id: str) -> dict:
    result = evaluation.get_evaluation(evaluation_run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Evaluation run not found.")
    return result


# --------------------------------------------------------------------------- #
# Memory trust state
# --------------------------------------------------------------------------- #
@app.get("/api/memory/trusted")
def memory_trusted() -> list[dict]:
    return memory.trusted_entries()


@app.get("/api/memory/quarantine")
def memory_quarantine() -> list[dict]:
    return memory.quarantined_entries()


@app.post("/api/level3/demo-session")
def level3_demo_session(request: CompileRequest) -> dict:
    """Create an idle protected run for an interactive MCP proof.

    The endpoint is a demo harness only. It creates and signs authority through
    the same trusted lifecycle, but it never exposes signing as an agent tool and
    does not execute a workflow in the background.
    """
    task = request.task
    mandate = mandates.compile_mandate(task)
    mandates.confirm_mandate(mandate["id"])
    signed = mandates.sign_mandate(mandate["id"])
    run = create_run(
        "normal-invoice",
        "deterministic",
        task,
        protection_mode="PROTECTED",
        mandate_id=signed["id"],
    )
    record_event(
        run["id"],
        "LEVEL3_DEMO_SESSION_CREATED",
        actor="user",
        mandate_id=signed["id"],
        tool_result={"transports": ["REST", "MCP"], "differentiators": ["MCP", "MEMORY_QUARANTINE", "SEMANTIC_COMPILER"]},
    )
    return {
        "run_id": run["id"],
        "mandate_id": signed["id"],
        "mandate_status": signed["status"],
        "protocol_version": mcp.PROTOCOL_VERSION,
        "compiler_report": signed["compiler_report"],
    }


@app.get("/api/level3/status")
def level3_status() -> dict:
    return {
        "level": 3,
        "features": {
            "mcp_adapter": {"enabled": True, "protocol_version": mcp.PROTOCOL_VERSION, "tools": len(mcp.tool_definitions())},
            "memory_quarantine": {
                "enabled": True,
                "quarantined": len(memory.quarantined_entries()),
                "trusted_retrievable": len(memory.trusted_entries()),
            },
            "semantic_compiler": {"enabled": True, "version": mandates.COMPILER_VERSION},
        },
    }


# --------------------------------------------------------------------------- #
# Persisted state
# --------------------------------------------------------------------------- #
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
    mandate_rows = [
        {
            "id": m["id"],
            "status": m["status"],
            "principal_id": m["principal_id"],
            "signed": bool(m["signature"]),
            "expires_at": m["expires_at"],
            "created_at": m["created_at"],
            "confirmed_at": m["confirmed_at"],
            "contract": m["contract"],
        }
        for m in mandates.list_mandates()
    ]
    return {
        "vendors": vendors,
        "payments": rows("SELECT * FROM payments ORDER BY created_at"),
        "memory_entries": rows("SELECT * FROM memory_entries ORDER BY created_at"),
        "trusted_memory": memory.trusted_entries(),
        "quarantined_memory": memory.quarantined_entries(),
        "secret_accesses": secret_accesses,
        "mandates": mandate_rows,
        "approval_requests": approvals.list_pending(),
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
