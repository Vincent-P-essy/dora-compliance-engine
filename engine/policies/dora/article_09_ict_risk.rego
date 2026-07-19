# DORA Article 9 — ICT risk management: protection and prevention.
#
# Controls:
#   DORA-09-COV   test suite green and line coverage >= 80% before production
#   DORA-09-VULN  zero unresolved CRITICAL vulnerabilities
#   DORA-09-SBOM  a non-empty software inventory (SBOM) exists
#
# Fail-closed: absence of evidence is itself a violation — an auditor cannot
# accept "we did not measure" as a passing state.

package dora.article_09

violations contains v if {
	not input.evidence.coverage
	v := {
		"control": "DORA-09-COV",
		"msg": "No test-coverage evidence collected — protection measures cannot be attested",
	}
}

violations contains v if {
	input.evidence.coverage.percent < 80
	v := {
		"control": "DORA-09-COV",
		"msg": sprintf(
			"Test coverage is %v%%, below the 80%% floor required before production deployment",
			[input.evidence.coverage.percent],
		),
	}
}

violations contains v if {
	input.evidence.tests.failures + input.evidence.tests.errors > 0
	v := {
		"control": "DORA-09-COV",
		"msg": sprintf(
			"CI test suite is red: %d failure(s) and %d error(s) in the latest run",
			[input.evidence.tests.failures, input.evidence.tests.errors],
		),
	}
}

violations contains v if {
	not input.evidence.vulnerabilities
	v := {
		"control": "DORA-09-VULN",
		"msg": "No vulnerability-scan evidence collected — exposure is unknown",
	}
}

violations contains v if {
	input.evidence.vulnerabilities.by_severity.CRITICAL > 0
	v := {
		"control": "DORA-09-VULN",
		"msg": sprintf(
			"%d CRITICAL vulnerabilities are unresolved [%s]",
			[
				input.evidence.vulnerabilities.by_severity.CRITICAL,
				concat(", ", input.evidence.vulnerabilities.critical_ids),
			],
		),
	}
}

violations contains v if {
	not input.evidence.sbom
	v := {
		"control": "DORA-09-SBOM",
		"msg": "No SBOM evidence collected — the ICT asset inventory is unknown",
	}
}

violations contains v if {
	input.evidence.sbom.components == 0
	v := {
		"control": "DORA-09-SBOM",
		"msg": "SBOM is empty: the software inventory lists zero components",
	}
}

deny contains msg if {
	some v in violations
	msg := v.msg
}
