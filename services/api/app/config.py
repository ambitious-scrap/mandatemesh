from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = Path(os.getenv("MANDATEMESH_DATA_DIR", ROOT / "data"))
DB_PATH = Path(os.getenv("MANDATEMESH_DB_PATH", DATA_DIR / "mandatemesh.sqlite3"))
SCENARIO_DIR = ROOT / "scenarios" / "invoices"

MODEL_API_KEY = os.getenv("MODEL_API_KEY", "")
MODEL_BASE_URL = os.getenv("MODEL_BASE_URL", "https://api.openai.com/v1").rstrip("/")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4.1-mini")
MODEL_TEMPERATURE = float(os.getenv("MODEL_TEMPERATURE", "0.1"))
MODEL_TIMEOUT_SECONDS = float(os.getenv("MODEL_TIMEOUT_SECONDS", "12"))

