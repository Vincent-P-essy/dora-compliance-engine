# Native OPA unit tests — run with:
#   opa test engine/policies tests/test_policies/rego -v

package dora.article_09_test

import data.dora.article_09

now := "2026-07-19T12:00:00+00:00"

healthy := {
	"evidence": {
		"coverage": {"percent": 92.4},
		"tests": {"failures": 0, "errors": 0},
		"vulnerabilities": {"by_severity": {"CRITICAL": 0, "HIGH": 1}, "critical_ids": []},
		"sbom": {"components": 42},
	},
	"now": now,
}

test_healthy_input_has_no_violations if {
	count(article_09.violations) == 0 with input as healthy
}

test_low_coverage_fails_cov_control if {
	inp := {"evidence": {"coverage": {"percent": 63.2}}, "now": now}
	vs := article_09.violations with input as inp
	some v in vs
	v.control == "DORA-09-COV"
	contains(v.msg, "63.2%")
}

test_red_test_suite_fails_cov_control if {
	inp := {"evidence": {"tests": {"failures": 2, "errors": 1}}, "now": now}
	vs := article_09.violations with input as inp
	some v in vs
	v.control == "DORA-09-COV"
	contains(v.msg, "2 failure(s)")
}

test_critical_vulnerabilities_denied if {
	inp := {
		"evidence": {"vulnerabilities": {
			"by_severity": {"CRITICAL": 2},
			"critical_ids": ["CVE-2026-11111", "CVE-2026-99999"],
		}},
		"now": now,
	}
	vs := article_09.violations with input as inp
	some v in vs
	v.control == "DORA-09-VULN"
	contains(v.msg, "CVE-2026-11111")
}

test_empty_sbom_denied if {
	inp := {"evidence": {"sbom": {"components": 0}}, "now": now}
	vs := article_09.violations with input as inp
	some v in vs
	v.control == "DORA-09-SBOM"
}

test_missing_evidence_fails_closed if {
	vs := article_09.violations with input as {"evidence": {}, "now": now}
	{v.control | some v in vs} == {"DORA-09-COV", "DORA-09-VULN", "DORA-09-SBOM"}
}

test_deny_exposes_plain_messages if {
	msgs := article_09.deny with input as {"evidence": {}, "now": now}
	count(msgs) == 3
}
