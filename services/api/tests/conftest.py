from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest


API_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = API_DIR.parents[1]
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

_OPA_CONTAINER = "mm-opa-pytest"


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    from app import config, database
    from app import main

    test_db = tmp_path / "mandatemesh-test.sqlite3"
    test_key = tmp_path / "demo-principal-ed25519.key"
    monkeypatch.setattr(config, "KEY_PATH", test_key)
    monkeypatch.setattr(database, "DB_PATH", test_db)
    monkeypatch.setattr(main, "DB_PATH", test_db)
    database.reset_db()
    yield test_db


def _wait_healthy(timeout: float = 20.0) -> bool:
    from app import policy

    deadline = time.time() + timeout
    while time.time() < deadline:
        if policy.opa_healthy():
            return True
        time.sleep(0.5)
    return False


@pytest.fixture(scope="session")
def opa():
    """Ensure OPA is reachable for gateway/policy integration tests.

    Uses an already-running OPA if one answers on OPA_URL; otherwise starts a
    disposable container serving the repo policy. Skips the dependent tests when
    neither OPA nor Docker is available.
    """
    from app import policy

    if policy.opa_healthy():
        yield policy
        return

    if not shutil_which("docker"):
        pytest.skip("OPA is not reachable and Docker is unavailable.")

    subprocess.run(["docker", "rm", "-f", _OPA_CONTAINER], capture_output=True)
    start = subprocess.run(
        [
            "docker", "run", "-d", "--name", _OPA_CONTAINER, "-p", "8181:8181",
            "-v", f"{REPO_ROOT / 'policy'}:/policy:ro",
            "openpolicyagent/opa:1.4.2", "run", "--server", "--addr", "0.0.0.0:8181", "/policy/mandate.rego",
        ],
        capture_output=True, text=True,
    )
    if start.returncode != 0:
        pytest.skip(f"Could not start OPA container: {start.stderr.strip()}")
    if not _wait_healthy():
        subprocess.run(["docker", "rm", "-f", _OPA_CONTAINER], capture_output=True)
        pytest.skip("OPA container did not become healthy.")
    yield policy
    subprocess.run(["docker", "rm", "-f", _OPA_CONTAINER], capture_output=True)


def shutil_which(cmd: str) -> str | None:
    import shutil

    return shutil.which(cmd)

