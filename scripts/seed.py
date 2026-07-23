#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api"))

from app.database import reset_db  # noqa: E402


if __name__ == "__main__":
    reset_db()
    print("MandateMesh demo database initialized and seeded.")

