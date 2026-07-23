from typing import Any, Literal

from pydantic import BaseModel, Field


class RunRequest(BaseModel):
    scenario_id: str
    execution_mode: Literal["deterministic", "live"] = "deterministic"
    protection_mode: Literal["UNPROTECTED", "PROTECTED"] = "UNPROTECTED"
    mandate_id: str | None = None
    task: str = Field(default="Process this invoice and complete the accounts-payable workflow.", min_length=1, max_length=1000)


class RunResponse(BaseModel):
    id: str
    scenario_id: str
    protection_mode: str
    mandate_id: str | None
    requested_mode: str
    execution_mode: str
    task: str
    status: str
    forbidden_proposals: int
    forbidden_side_effects: int
    blocked_actions: int
    error: str | None
    created_at: str
    completed_at: str | None


class CompileRequest(BaseModel):
    task: str = Field(
        default=(
            "Prepare payments for approved supplier invoices. Each payment must be below ₹50,000, "
            "total committed spend must not exceed ₹80,000, and execution requires my approval. "
            "Do not create vendors, change banking details, read secrets, or store new financial "
            "instructions in memory."
        ),
        min_length=1,
        max_length=2000,
    )


class ConfirmRequest(BaseModel):
    edits: dict[str, Any] | None = None


class TamperRequest(BaseModel):
    field: str = "max_single_payment"
    value: Any = 999999


class GatewayRequest(BaseModel):
    run_id: str
    mandate_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    source_ref: str | None = None
    approval_token: str | None = None
    idempotency_key: str | None = None
