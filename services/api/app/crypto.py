"""Ed25519 signing for the local demo principal.

The demo principal keypair is derived deterministically from a fixed labelled
seed so the same public key is stable across restarts and resets without storing
a raw private key in the repository. This is a **local demo principal only** — it
is not production PKI, a KMS, a passkey, or hardware-backed storage.

The private key lives only inside this module. It is never returned by an API
endpoint, never placed in a prompt, and never exposed as an agent tool. Only the
explicit human "sign mandate" and "approve" backend operations call into it.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Deterministic, clearly-synthetic demo seed. Not a credential to any real
# system; derived through SHA-256 so no raw key material is committed.
_DEMO_SEED = hashlib.sha256(b"mandatemesh-local-demo-principal-v1").digest()

PRINCIPAL_ID = "demo-principal-local"

_private_key = Ed25519PrivateKey.from_private_bytes(_DEMO_SEED)
_public_key = _private_key.public_key()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def public_key_b64() -> str:
    """Base64 raw public key stored alongside signed material."""
    return _b64(_public_key.public_bytes_raw())


def sign(message: bytes) -> str:
    """Sign raw bytes with the demo principal private key (base64 signature)."""
    return _b64(_private_key.sign(message))


def verify(message: bytes, signature_b64: str, public_key_b64_value: str | None = None) -> bool:
    """Verify a base64 signature over ``message`` against a public key.

    Defaults to the demo principal public key. Returns ``False`` for any
    malformed input or verification failure — never raises.
    """
    try:
        if public_key_b64_value:
            public = Ed25519PublicKey.from_public_bytes(_unb64(public_key_b64_value))
        else:
            public = _public_key
        public.verify(_unb64(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
