from __future__ import annotations

import os
import sys
from pathlib import Path


if sys.version_info[:2] != (3, 14):
    raise RuntimeError(
        "MandateMesh development and Docker environments require Python 3.14. "
        f"Detected {sys.version_info.major}.{sys.version_info.minor}."
    )


ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = Path(os.getenv("MANDATEMESH_DATA_DIR", ROOT / "data"))
DB_PATH = Path(os.getenv("MANDATEMESH_DB_PATH", DATA_DIR / "mandatemesh.sqlite3"))
KEY_PATH = Path(os.getenv("MANDATEMESH_KEY_PATH") or (DATA_DIR / "demo-principal-ed25519.key"))
SCENARIO_DIR = ROOT / "scenarios" / "invoices"

MODEL_API_KEY = os.getenv("MODEL_API_KEY", "")
MODEL_BASE_URL = os.getenv("MODEL_BASE_URL", "https://api.openai.com/v1").rstrip("/")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4.1-mini")
MODEL_TEMPERATURE = float(os.getenv("MODEL_TEMPERATURE", "0.1"))
MODEL_TIMEOUT_SECONDS = float(os.getenv("MODEL_TIMEOUT_SECONDS", "12"))

# OPA policy decision point (Level 1). The gateway is the only trusted caller.
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181").rstrip("/")
OPA_DECISION_PATH = os.getenv("OPA_DECISION_PATH", "/v1/data/mandatemesh/authz/decision")
OPA_TIMEOUT_SECONDS = float(os.getenv("OPA_TIMEOUT_SECONDS", "5"))

# Mandate lifecycle defaults (Level 1).
MANDATE_TTL_SECONDS = int(os.getenv("MANDATE_TTL_SECONDS", str(60 * 60 * 8)))
APPROVAL_TTL_SECONDS = int(os.getenv("APPROVAL_TTL_SECONDS", str(60 * 5)))
