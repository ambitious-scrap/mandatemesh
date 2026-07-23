"""Canonical serialization and action hashing.

One serialization function is used everywhere a signature or hash is computed so
that semantically identical objects always produce identical bytes. Deterministic
JSON: keys sorted, compact separators, UTF-8, integers kept as integers, and no
transient or signature fields.
"""
from __future__ import annotations

import hashlib
import json


# Fields that must never contribute to a signed payload or a hash. They are
# stripped recursively before serialization so verification cannot depend on
# non-deterministic or self-referential values.
TRANSIENT_FIELDS = frozenset({"signature", "created_at", "confirmed_at", "verified_at"})


def _strip(value):
    if isinstance(value, dict):
        return {key: _strip(inner) for key, inner in value.items() if key not in TRANSIENT_FIELDS}
    if isinstance(value, (list, tuple)):
        return [_strip(inner) for inner in value]
    return value


def canonical_bytes(payload: dict) -> bytes:
    """Return the deterministic UTF-8 byte representation of ``payload``."""
    stripped = _strip(payload)
    return json.dumps(
        stripped,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json(payload: dict) -> str:
    """Return the deterministic string form of ``payload``."""
    return canonical_bytes(payload).decode("utf-8")


def sha256_hex(payload: dict) -> str:
    """SHA-256 hex digest over the canonical bytes of ``payload``."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()
