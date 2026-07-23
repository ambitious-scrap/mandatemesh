from __future__ import annotations

import sys
from pathlib import Path

import pytest


API_DIR = Path(__file__).resolve().parents[1]
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    from app import database
    from app import main

    test_db = tmp_path / "mandatemesh-test.sqlite3"
    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(main, "DB_PATH", test_db)
    database.reset_db()
    yield test_db

