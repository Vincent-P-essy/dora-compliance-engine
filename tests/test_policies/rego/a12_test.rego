package iso27001.a12_test

import data.iso27001.a12

now := "2026-07-19T12:00:00+00:00"

clean_operations := {
	"evidence": {
		"secret_scan": {"findings": 0, "commits_scanned": 30},
		"secrets_log": {"unauthorized": 0, "events": 128, "window_days": 7},
		"commits": {"signed_ratio": 0.8, "count": 30},
	},
	"now": now,
}

test_clean_operations_pass if {
	count(a12.violations) == 0 with input as clean_operations
}

test_leaked_secret_denied if {
	inp := {"evidence": {"secret_scan": {"findings": 2, "commits_scanned": 30}}, "now": now}
	vs := a12.violations with input as inp
	some v in vs
	v.control == "ISO-A12-SECRETS"
	contains(v.msg, "2 potential secret(s)")
}

test_unauthorized_access_denied if {
	inp := {"evidence": {"secrets_log": {"unauthorized": 3, "events": 100, "window_days": 7}}, "now": now}
	vs := a12.violations with input as inp
	some v in vs
	v.control == "ISO-A12-ACCESS"
	contains(v.msg, "3 unauthorized")
}

test_low_signature_ratio_denied if {
	inp := {"evidence": {"commits": {"signed_ratio": 0.3, "count": 30}}, "now": now}
	vs := a12.violations with input as inp
	some v in vs
	v.control == "ISO-A12-SIGNED"
	contains(v.msg, "30%")
}

test_missing_evidence_fails_all_three_controls if {
	vs := a12.violations with input as {"evidence": {}, "now": now}
	{v.control | some v in vs} == {"ISO-A12-SECRETS", "ISO-A12-ACCESS", "ISO-A12-SIGNED"}
}
