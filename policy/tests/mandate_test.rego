# Independent policy tests for the MandateMesh authorization policy.
#
# These exercise the Rego decision logic directly with synthetic policy input.
# They do not depend on the Python integration tests — `opa test policy/` runs
# them standalone.
package mandatemesh.authz_test

import data.mandatemesh.authz

base := {
	"verification": {"signature_valid": true, "mandate_status": "ACTIVE", "expired": false, "now": "2026-01-01T00:00:00+00:00"},
	"mandate": {
		"id": "M1",
		"allowed_actions": ["document.invoice.read", "vendor.record.lookup", "financial.payment.prepare", "financial.payment.execute"],
		"forbidden_actions": ["vendor.record.create", "secret.value.read", "memory.financial_instruction.write"],
		"approved_counterparties": [{"vendor_id": "VENDOR-101", "beneficiary_hash": "HASH_OK", "name": "Aruna Components Pvt Ltd"}],
		"currency": "INR",
		"max_single_payment": 50000,
		"max_total_payment": 80000,
		"execution_mode": "REQUIRE_APPROVAL",
		"requires_approval": true,
	},
	"action": {
		"canonical_action": "document.invoice.read",
		"tool_name": "invoice.read",
		"resource": {},
		"provenance": {"source_ref": "inv-1", "source_trust": "UNTRUSTED_EXTERNAL"},
		"action_hash": "AH",
	},
	"task_state": {"committed_amount": 0},
	"approval": {"present": false, "valid": false, "expired": false, "consumed": false, "action_hash_match": false},
}

simple_action(canonical, tool) := {
	"canonical_action": canonical,
	"tool_name": tool,
	"resource": {},
	"provenance": {"source_ref": "inv-1", "source_trust": "UNTRUSTED_EXTERNAL"},
	"action_hash": "AH",
}

prepare_action(amount, vendor, ben, cur) := {
	"canonical_action": "financial.payment.prepare",
	"tool_name": "payment.prepare",
	"resource": {"vendor_id": vendor, "beneficiary_hash": ben, "amount": amount, "currency": cur},
	"provenance": {"source_ref": "inv-1", "source_trust": "UNTRUSTED_EXTERNAL"},
	"action_hash": "AH",
}

execute_action := {
	"canonical_action": "financial.payment.execute",
	"tool_name": "payment.execute",
	"resource": {"payment_id": "P1", "vendor_id": "VENDOR-101", "beneficiary_hash": "HASH_OK", "amount": 42000, "currency": "INR"},
	"provenance": {"source_ref": "inv-1", "source_trust": "UNTRUSTED_EXTERNAL"},
	"action_hash": "AH",
}

# --- allowlist -------------------------------------------------------------
test_invoice_read_allow if {
	d := authz.decision with input as base
	d.decision == "ALLOW"
	d.reason_code == "ACTION_ALLOWED"
	d.policy_version == "mandatemesh-authz-v1"
}

test_vendor_lookup_allow if {
	d := authz.decision with input as object.union(base, {"action": simple_action("vendor.record.lookup", "vendor.lookup")})
	d.decision == "ALLOW"
}

test_unknown_action_not_allowed if {
	d := authz.decision with input as object.union(base, {"action": simple_action("system.shell.exec", "shell.exec")})
	d.decision == "BLOCK"
	d.reason_code == "ACTION_NOT_ALLOWED"
}

# --- denylist --------------------------------------------------------------
test_vendor_create_forbidden if {
	d := authz.decision with input as object.union(base, {"action": simple_action("vendor.record.create", "vendor.create")})
	d.decision == "BLOCK"
	d.reason_code == "ACTION_EXPLICITLY_FORBIDDEN"
}

test_secret_read_forbidden if {
	d := authz.decision with input as object.union(base, {"action": simple_action("secret.value.read", "secret.read")})
	d.decision == "BLOCK"
	d.reason_code == "ACTION_EXPLICITLY_FORBIDDEN"
}

test_memory_write_forbidden if {
	d := authz.decision with input as object.union(base, {"action": simple_action("memory.financial_instruction.write", "memory.write")})
	d.decision == "BLOCK"
	d.reason_code == "MEMORY_WRITE_FORBIDDEN"
}

# --- payment preparation ---------------------------------------------------
test_prepare_valid_allow if {
	d := authz.decision with input as object.union(base, {"action": prepare_action(42000, "VENDOR-101", "HASH_OK", "INR")})
	d.decision == "ALLOW"
	d.reason_code == "ACTION_ALLOWED"
}

test_prepare_bad_beneficiary_block if {
	d := authz.decision with input as object.union(base, {"action": prepare_action(42000, "VENDOR-101", "ATTACKER_HASH", "INR")})
	d.decision == "BLOCK"
	d.reason_code == "BENEFICIARY_MISMATCH"
}

test_prepare_unapproved_vendor_block if {
	d := authz.decision with input as object.union(base, {"action": prepare_action(42000, "VENDOR-ATTACKER", "ATTACKER_HASH", "INR")})
	d.decision == "BLOCK"
	d.reason_code == "VENDOR_NOT_APPROVED"
}

test_prepare_currency_mismatch_block if {
	d := authz.decision with input as object.union(base, {"action": prepare_action(42000, "VENDOR-101", "HASH_OK", "USD")})
	d.decision == "BLOCK"
	d.reason_code == "CURRENCY_MISMATCH"
}

test_prepare_single_limit_block if {
	d := authz.decision with input as object.union(base, {"action": prepare_action(60000, "VENDOR-101", "HASH_OK", "INR")})
	d.decision == "BLOCK"
	d.reason_code == "SINGLE_PAYMENT_LIMIT_EXCEEDED"
}

test_prepare_single_limit_boundary_allow if {
	d := authz.decision with input as object.union(base, {"action": prepare_action(50000, "VENDOR-101", "HASH_OK", "INR")})
	d.decision == "ALLOW"
}

test_prepare_total_budget_block if {
	inp := object.union(base, {
		"action": prepare_action(42000, "VENDOR-101", "HASH_OK", "INR"),
		"task_state": {"committed_amount": 50000},
	})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "TOTAL_BUDGET_EXCEEDED"
}

# --- execution / approval --------------------------------------------------
test_execute_without_approval_requires_approval if {
	d := authz.decision with input as object.union(base, {"action": execute_action})
	d.decision == "REQUIRE_APPROVAL"
	d.reason_code == "APPROVAL_REQUIRED"
	d.required_approval.action_hash == "AH"
}

test_execute_valid_approval_allow if {
	inp := object.union(base, {
		"action": execute_action,
		"approval": {"present": true, "valid": true, "expired": false, "consumed": false, "action_hash_match": true},
	})
	d := authz.decision with input as inp
	d.decision == "ALLOW"
	d.reason_code == "ACTION_ALLOWED"
}

test_execute_expired_approval_block if {
	inp := object.union(base, {
		"action": execute_action,
		"approval": {"present": true, "valid": true, "expired": true, "consumed": false, "action_hash_match": true},
	})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "APPROVAL_EXPIRED"
}

test_execute_consumed_approval_block if {
	inp := object.union(base, {
		"action": execute_action,
		"approval": {"present": true, "valid": true, "expired": false, "consumed": true, "action_hash_match": true},
	})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "APPROVAL_ALREADY_USED"
}

test_execute_hash_mismatch_block if {
	inp := object.union(base, {
		"action": execute_action,
		"approval": {"present": true, "valid": true, "expired": false, "consumed": false, "action_hash_match": false},
	})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "APPROVAL_INVALID"
}

# --- mandate gates ---------------------------------------------------------
test_signature_invalid_block if {
	inp := object.union(base, {"verification": {"signature_valid": false, "mandate_status": "ACTIVE", "expired": false, "now": "x"}})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "MANDATE_SIGNATURE_INVALID"
}

test_mandate_inactive_block if {
	inp := object.union(base, {"verification": {"signature_valid": true, "mandate_status": "REVOKED", "expired": false, "now": "x"}})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "MANDATE_INACTIVE"
}

test_mandate_expired_block if {
	inp := object.union(base, {"verification": {"signature_valid": true, "mandate_status": "ACTIVE", "expired": true, "now": "x"}})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "MANDATE_EXPIRED"
}

# --- precedence: signature gate beats a forbidden action -------------------
test_signature_precedence_over_forbidden if {
	inp := object.union(base, {
		"verification": {"signature_valid": false, "mandate_status": "ACTIVE", "expired": false, "now": "x"},
		"action": simple_action("vendor.record.create", "vendor.create"),
	})
	d := authz.decision with input as inp
	d.decision == "BLOCK"
	d.reason_code == "MANDATE_SIGNATURE_INVALID"
}
