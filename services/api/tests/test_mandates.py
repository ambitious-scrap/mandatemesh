"""Mandate lifecycle, canonical serialization, and crypto tests (no OPA)."""
from __future__ import annotations

import json

import pytest

from app import approvals, canonical, crypto, mandates

DEMO_TASK = (
    "Prepare payments for approved supplier invoices. Each payment must be below ₹50,000, "
    "total committed spend must not exceed ₹80,000, and execution requires my approval. "
    "Do not create vendors, change banking details, read secrets, or store new financial instructions in memory."
)


def _signed_mandate():
    m = mandates.compile_mandate(DEMO_TASK)
    mandates.confirm_mandate(m["id"])
    return mandates.sign_mandate(m["id"])


# --- canonical serialization ------------------------------------------------
def test_canonical_is_sorted_and_compact():
    raw = canonical.canonical_json({"b": 1, "a": 2})
    assert raw == '{"a":2,"b":1}'


def test_canonical_strips_signature_and_transient_fields():
    payload = {"a": 1, "signature": "SIG", "created_at": "t", "nested": {"confirmed_at": "t", "keep": 2}}
    out = json.loads(canonical.canonical_json(payload))
    assert "signature" not in out
    assert "created_at" not in out
    assert out["nested"] == {"keep": 2}


def test_canonical_unicode_preserved():
    assert "₹" in canonical.canonical_json({"note": "₹50,000"})


def test_sha256_hex_is_stable():
    assert canonical.sha256_hex({"x": 1, "y": 2}) == canonical.sha256_hex({"y": 2, "x": 1})


# --- crypto -----------------------------------------------------------------
def test_sign_and_verify_roundtrip():
    sig = crypto.sign(b"hello")
    assert crypto.verify(b"hello", sig)


def test_verify_fails_on_tampered_message():
    sig = crypto.sign(b"hello")
    assert not crypto.verify(b"goodbye", sig)


def test_verify_never_raises_on_garbage():
    assert crypto.verify(b"hello", "not-base64-!!!") is False


# --- lifecycle --------------------------------------------------------------
def test_compile_produces_draft_with_demo_limits():
    m = mandates.compile_mandate(DEMO_TASK)
    assert m["status"] == "DRAFT"
    assert m["signature"] is None
    assert m["contract"]["max_single_payment"] == 50000
    assert m["contract"]["max_total_payment"] == 80000
    assert m["contract"]["requires_approval"] is True
    assert "vendor.record.create" in m["contract"]["forbidden_actions"]
    assert m["warnings"] == []


def test_compile_conservative_defaults_when_amounts_missing():
    m = mandates.compile_mandate("Please just pay whatever the invoice says.")
    assert m["contract"]["max_single_payment"] == 50000
    assert m["contract"]["max_total_payment"] == 80000
    assert m["warnings"]  # surfaced to the human for review
    assert "max_single_payment" in m["ambiguous_fields"]


def test_confirm_freezes_and_canonicalizes():
    m = mandates.compile_mandate(DEMO_TASK)
    confirmed = mandates.confirm_mandate(m["id"])
    assert confirmed["status"] == "DRAFT"
    assert confirmed["confirmed_at"] is not None
    assert confirmed["canonical_payload"]
    assert confirmed["contract"]["expires_at"]


def test_confirm_applies_edits():
    m = mandates.compile_mandate(DEMO_TASK)
    confirmed = mandates.confirm_mandate(m["id"], {"max_single_payment": 40000})
    assert confirmed["contract"]["max_single_payment"] == 40000


def test_sign_activates_mandate():
    signed = _signed_mandate()
    assert signed["status"] == "ACTIVE"
    assert signed["signature"]
    assert signed["public_key"] == crypto.public_key_b64()
    assert "signature" not in signed["contract"]


def test_cannot_sign_before_confirm():
    m = mandates.compile_mandate(DEMO_TASK)
    with pytest.raises(mandates.MandateError):
        mandates.sign_mandate(m["id"])


def test_verify_valid_after_sign():
    signed = _signed_mandate()
    result = mandates.verify_mandate(signed["id"])
    assert result["valid"] is True
    assert result["reason_code"] is None


def test_post_signature_mutation_invalidates():
    signed = _signed_mandate()
    result = mandates.tamper_demo(signed["id"], "max_single_payment", 999999)
    assert result["original_signature_valid"] is True
    assert result["tampered_signature_valid"] is False
    assert result["reason_code"] == "MANDATE_SIGNATURE_INVALID"


def test_revoked_mandate_is_inactive():
    signed = _signed_mandate()
    mandates.revoke_mandate(signed["id"])
    result = mandates.verify_mandate(signed["id"])
    assert result["valid"] is False
    assert result["reason_code"] == "MANDATE_INACTIVE"


def test_expired_mandate_reported(monkeypatch):
    monkeypatch.setattr(mandates, "MANDATE_TTL_SECONDS", -10)
    m = mandates.compile_mandate(DEMO_TASK)
    mandates.confirm_mandate(m["id"])
    signed = mandates.sign_mandate(m["id"])
    result = mandates.verify_mandate(signed["id"])
    assert result["signature_valid"] is True
    assert result["expired"] is True
    assert result["reason_code"] == "MANDATE_EXPIRED"


def test_nonce_is_unique_per_mandate():
    a = mandates.compile_mandate(DEMO_TASK)
    b = mandates.compile_mandate(DEMO_TASK)
    assert a["nonce"] != b["nonce"]


# --- approval action hash ---------------------------------------------------
def test_action_hash_binds_payment_fields():
    payment = {"id": "PAY-1", "vendor_id": "VENDOR-101", "beneficiary_hash": "H", "amount": 42000, "currency": "INR"}
    changed = {**payment, "amount": 42001}
    assert approvals.action_hash_for("M1", payment) != approvals.action_hash_for("M1", changed)
