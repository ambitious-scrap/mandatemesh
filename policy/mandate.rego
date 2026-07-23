# MandateMesh authorization policy (Level 1).
#
# The gateway is the only trusted caller. It performs Ed25519 verification in
# Python and passes the *trusted* verification result in as input. This policy
# never accepts a client-supplied signature flag — it reads input.verification,
# which only the gateway constructs.
#
# Decision precedence is rank-based: every applicable rule contributes a
# candidate with a rank, and the lowest rank wins. The floor candidate is ALLOW
# (rank 100); any violation has a lower rank and therefore takes precedence. The
# default value is a fail-closed BLOCK in case no candidate is produced.
package mandatemesh.authz

policy_version := "mandatemesh-authz-v1"

default decision := {
	"decision": "BLOCK",
	"reason_code": "ACTION_NOT_ALLOWED",
	"message": "No policy rule permitted this action.",
	"matched_rules": ["default_fail_closed"],
	"required_approval": null,
	"policy_version": "mandatemesh-authz-v1",
}

# ----------------------------------------------------------------------------
# Winner selection: lowest rank among candidates.
# ----------------------------------------------------------------------------
decision := out if {
	ranks := {c.rank | some c in candidates}
	winning := min(ranks)
	some c in candidates
	c.rank == winning
	out := object.union(c.out, {"policy_version": policy_version})
}

cand(rank, decision_value, code, msg, rules) := {
	"rank": rank,
	"out": {
		"decision": decision_value,
		"reason_code": code,
		"message": msg,
		"matched_rules": rules,
		"required_approval": null,
	},
}

# ----------------------------------------------------------------------------
# Mandate-level gates (apply to every action).
# ----------------------------------------------------------------------------
candidates contains c if {
	not input.verification.signature_valid
	c := cand(1, "BLOCK", "MANDATE_SIGNATURE_INVALID", "Mandate signature is invalid.", ["mandate_signature"])
}

candidates contains c if {
	input.verification.signature_valid
	input.verification.mandate_status != "ACTIVE"
	c := cand(2, "BLOCK", "MANDATE_INACTIVE", "Mandate is not active.", ["mandate_active_status"])
}

candidates contains c if {
	input.verification.signature_valid
	input.verification.mandate_status == "ACTIVE"
	input.verification.expired
	c := cand(3, "BLOCK", "MANDATE_EXPIRED", "Mandate has expired.", ["mandate_expiry"])
}

# ----------------------------------------------------------------------------
# Action allow / deny lists.
# ----------------------------------------------------------------------------
candidates contains c if {
	input.action.canonical_action == "memory.financial_instruction.write"
	input.action.canonical_action in input.mandate.forbidden_actions
	c := cand(10, "BLOCK", "MEMORY_WRITE_FORBIDDEN", "Writing financial instructions to memory is forbidden.", ["memory_write_restriction"])
}

candidates contains c if {
	input.action.canonical_action != "memory.financial_instruction.write"
	input.action.canonical_action in input.mandate.forbidden_actions
	c := cand(10, "BLOCK", "ACTION_EXPLICITLY_FORBIDDEN", "Action is explicitly forbidden by the mandate.", ["action_denylist"])
}

candidates contains c if {
	not input.action.canonical_action in input.mandate.allowed_actions
	not input.action.canonical_action in input.mandate.forbidden_actions
	c := cand(11, "BLOCK", "ACTION_NOT_ALLOWED", "Action is not in the mandate allowlist.", ["action_allowlist"])
}

# ----------------------------------------------------------------------------
# Payment preparation binding + limits.
# ----------------------------------------------------------------------------
approved_vendor if {
	some cp in input.mandate.approved_counterparties
	cp.vendor_id == input.action.resource.vendor_id
}

beneficiary_bound if {
	some cp in input.mandate.approved_counterparties
	cp.vendor_id == input.action.resource.vendor_id
	cp.beneficiary_hash == input.action.resource.beneficiary_hash
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.prepare"
	not approved_vendor
	c := cand(20, "BLOCK", "VENDOR_NOT_APPROVED", "Vendor is not an approved counterparty.", ["approved_vendor"])
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.prepare"
	approved_vendor
	not beneficiary_bound
	c := cand(21, "BLOCK", "BENEFICIARY_MISMATCH", "Beneficiary account does not match the approved vendor.", ["bank_account_binding"])
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.prepare"
	approved_vendor
	beneficiary_bound
	input.action.resource.currency != input.mandate.currency
	c := cand(22, "BLOCK", "CURRENCY_MISMATCH", "Payment currency does not match the mandate currency.", ["currency_match"])
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.prepare"
	approved_vendor
	beneficiary_bound
	input.action.resource.currency == input.mandate.currency
	input.action.resource.amount > input.mandate.max_single_payment
	c := cand(23, "BLOCK", "SINGLE_PAYMENT_LIMIT_EXCEEDED", "Payment exceeds the single-payment limit.", ["single_payment_limit"])
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.prepare"
	approved_vendor
	beneficiary_bound
	input.action.resource.currency == input.mandate.currency
	input.action.resource.amount <= input.mandate.max_single_payment
	input.task_state.committed_amount + input.action.resource.amount > input.mandate.max_total_payment
	c := cand(24, "BLOCK", "TOTAL_BUDGET_EXCEEDED", "Payment exceeds the cumulative mandate budget.", ["cumulative_budget"])
}

# ----------------------------------------------------------------------------
# Payment execution approval binding.
# ----------------------------------------------------------------------------
approval_ok if {
	input.action.canonical_action == "financial.payment.execute"
	input.approval.present
	input.approval.valid
	input.approval.action_hash_match
	not input.approval.expired
	not input.approval.consumed
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.execute"
	input.approval.present
	input.approval.expired
	c := cand(30, "BLOCK", "APPROVAL_EXPIRED", "Approval token has expired.", ["approval_expiry"])
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.execute"
	input.approval.present
	not input.approval.expired
	input.approval.consumed
	c := cand(31, "BLOCK", "APPROVAL_ALREADY_USED", "Approval token has already been used.", ["approval_one_time_use"])
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.execute"
	input.approval.present
	not input.approval.expired
	not input.approval.consumed
	not approval_binding_ok
	c := cand(32, "BLOCK", "APPROVAL_INVALID", "Approval token does not match this action.", ["approval_action_binding"])
}

approval_binding_ok if {
	input.approval.valid
	input.approval.action_hash_match
}

candidates contains c if {
	input.action.canonical_action == "financial.payment.execute"
	not input.approval.present
	c := {
		"rank": 50,
		"out": {
			"decision": "REQUIRE_APPROVAL",
			"reason_code": "APPROVAL_REQUIRED",
			"message": "Independent human approval is required before execution.",
			"matched_rules": ["approval_requirement"],
			"required_approval": {
				"action_hash": input.action.action_hash,
				"canonical_action": input.action.canonical_action,
				"amount": input.action.resource.amount,
				"currency": input.action.resource.currency,
				"vendor_id": input.action.resource.vendor_id,
				"beneficiary_hash": input.action.resource.beneficiary_hash,
			},
		},
	}
}

# ----------------------------------------------------------------------------
# Allow floor (rank 100): only wins when no violation candidate is lower.
# ----------------------------------------------------------------------------
candidates contains c if {
	c := cand(100, "ALLOW", "ACTION_ALLOWED", "Action is authorized by the mandate.", ["action_allowed"])
}
