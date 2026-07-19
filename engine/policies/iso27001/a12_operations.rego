# ISO/IEC 27001:2022 Annex A.12 — Operations security.
#
# Controls:
#   ISO-A12-SECRETS  zero secrets detected in recent commit history
#   ISO-A12-ACCESS   zero unauthorized accesses in the secret-manager audit log
#   ISO-A12-SIGNED   at least 50% of recent commits carry a GPG signature

package iso27001.a12

violations contains v if {
	not input.evidence.secret_scan
	v := {
		"control": "ISO-A12-SECRETS",
		"msg": "No secret-scan evidence collected over the commit history",
	}
}

violations contains v if {
	input.evidence.secret_scan.findings > 0
	v := {
		"control": "ISO-A12-SECRETS",
		"msg": sprintf(
			"%d potential secret(s) detected in the last %d commits — rotate and purge immediately",
			[input.evidence.secret_scan.findings, input.evidence.secret_scan.commits_scanned],
		),
	}
}

violations contains v if {
	not input.evidence.secrets_log
	v := {
		"control": "ISO-A12-ACCESS",
		"msg": "No secret-access audit log collected — operations logging cannot be attested",
	}
}

violations contains v if {
	input.evidence.secrets_log.unauthorized > 0
	v := {
		"control": "ISO-A12-ACCESS",
		"msg": sprintf(
			"%d unauthorized secret access(es) recorded in the last %d days",
			[input.evidence.secrets_log.unauthorized, input.evidence.secrets_log.window_days],
		),
	}
}

violations contains v if {
	not input.evidence.commits
	v := {
		"control": "ISO-A12-SIGNED",
		"msg": "No commit-history evidence collected — change integrity is unknown",
	}
}

violations contains v if {
	input.evidence.commits.signed_ratio < 0.5
	v := {
		"control": "ISO-A12-SIGNED",
		"msg": sprintf(
			"Only %v%% of the last %d commits are GPG-signed (minimum 50%%)",
			[round(input.evidence.commits.signed_ratio * 100), input.evidence.commits.count],
		),
	}
}

deny contains msg if {
	some v in violations
	msg := v.msg
}
