# DORA Article 25 — Digital operational resilience testing.
#
# Controls:
#   DORA-25-TEST  a resilience exercise (failover drill, chaos test, DR run)
#                 was performed within the last 90 days
#   DORA-25-DOC   that exercise is documented with a retrievable report

package dora.article_25

days_since(ts) := (time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns(ts)) / 86400000000000

violations contains v if {
	not input.evidence.resilience
	v := {
		"control": "DORA-25-TEST",
		"msg": "No resilience-testing evidence collected — Art. 25 requires periodic testing",
	}
}

violations contains v if {
	days_since(input.evidence.resilience.performed_at) > 90
	v := {
		"control": "DORA-25-TEST",
		"msg": sprintf(
			"Last resilience exercise (%s) is %v days old (max 90 days)",
			[
				input.evidence.resilience.exercise,
				round(days_since(input.evidence.resilience.performed_at)),
			],
		),
	}
}

violations contains v if {
	not input.evidence.resilience
	v := {
		"control": "DORA-25-DOC",
		"msg": "Cannot attest documentation: no resilience exercise on record",
	}
}

violations contains v if {
	input.evidence.resilience.documented != true
	v := {
		"control": "DORA-25-DOC",
		"msg": sprintf(
			"Resilience exercise '%s' ran but was never documented",
			[input.evidence.resilience.exercise],
		),
	}
}

violations contains v if {
	input.evidence.resilience.documented == true
	not input.evidence.resilience.report_url
	v := {
		"control": "DORA-25-DOC",
		"msg": "Resilience exercise marked documented but no report URL is attached",
	}
}

deny contains msg if {
	some v in violations
	msg := v.msg
}
