"""Ed25519 signing for the persistent local demo principal.

A random private key is generated on first use and stored outside source control
under MandateMesh's data directory. The file is reused across service restarts,
never exposed through the agent/tool surface, and never returned by an API.
This remains a local demo principal, not production PKI or a hardware-backed key.
"""
from __future__ import annotations

import base64
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import config

PRINCIPAL_ID = "demo-principal-local"
_KEY_BYTES = 32


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _read_key(path: Path) -> Ed25519PrivateKey:
    # A concurrently-created file may be visible a few microseconds before its
    # writer closes it. Retry briefly rather than accepting partial key material.
    for attempt in range(5):
        raw = path.read_bytes()
        if len(raw) == _KEY_BYTES:
            return Ed25519PrivateKey.from_private_bytes(raw)
        if attempt < 4:
            time.sleep(0.01)
    raise RuntimeError(f"Invalid Ed25519 key file at {path}: expected {_KEY_BYTES} bytes.")


def _load_or_create_private_key() -> Ed25519PrivateKey:
    path = Path(config.KEY_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return _read_key(path)

    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes_raw()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _read_key(path)

    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Some mounted filesystems do not support POSIX modes. The data-volume
        # location still keeps the key outside the repository and agent surface.
        pass
    return private


def ensure_key() -> Path:
    """Create/load the demo key and return only its filesystem path."""
    _load_or_create_private_key()
    return Path(config.KEY_PATH)


def public_key_b64() -> str:
    """Base64 raw public key stored alongside signed material."""
    return _b64(_load_or_create_private_key().public_key().public_bytes_raw())


def sign(message: bytes) -> str:
    """Sign raw bytes with the persistent demo principal private key."""
    return _b64(_load_or_create_private_key().sign(message))


def verify(message: bytes, signature_b64: str, public_key_b64_value: str | None = None) -> bool:
    """Verify a base64 signature, returning ``False`` for malformed input."""
    try:
        if public_key_b64_value:
            public = Ed25519PublicKey.from_public_bytes(_unb64(public_key_b64_value))
        else:
            public = _load_or_create_private_key().public_key()
        public.verify(_unb64(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError, OSError, RuntimeError):
        return False
