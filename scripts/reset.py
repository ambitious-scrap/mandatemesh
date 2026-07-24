#!/usr/bin/env python3
"""Reset MandateMesh to a deterministic seeded state.

Default behavior preserves completed Level 2 evaluation reports for judge review.
Use ``--full`` before a clean-room rehearsal to remove evaluation history too.
The persistent signing key is intentionally never deleted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api"))

from app.database import reset_db  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset and seed the MandateMesh demo database.")
    parser.add_argument(
        "--full",
        action="store_true",
        help="also clear persisted evaluation reports and evidence",
    )
    args = parser.parse_args()
    summary = reset_db(preserve_evaluations=not args.full)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
