# DORA Article 11 — Response and recovery: backup policies and restoration.
#
# Controls:
#   DORA-11-BACKUP   a verified backup succeeded within the last 24 hours
#   DORA-11-RESTORE  a real restore was exercised within the last 90 days
#
# Timestamps are RFC 3339; `input.now` is injected by the policy engine so
# rules stay deterministic and unit-testable.

package dora.article_11

hours_since(ts) := (time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns(ts)) / 3600000000000

days_since(ts) := (time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns(ts)) / 86400000000000

violations contains v if {
	not input.evidence.backup
	v := {
		"control": "DORA-11-BACKUP",
		"msg": "No backup evidence collected — continuity posture is unknown",
	}
}

violations contains v if {
	hours_since(input.evidence.backup.last_success) > 24
	v := {
		"control": "DORA-11-BACKUP",
		"msg": sprintf(
			"Last successful backup is %v hours old — DORA Art. 11 requires a verified backup every 24h",
			[round(hours_since(input.evidence.backup.last_success))],
		),
	}
}

violations contains v if {
	input.evidence.backup.verified != true
	v := {
		"control": "DORA-11-BACKUP",
		"msg": "Latest backup exists but its integrity was never verified",
	}
}

violations contains v if {
	not input.evidence.backup.restore_tested_at
	v := {
		"control": "DORA-11-RESTORE",
		"msg": "No restore test on record — backups are unproven until restored once",
	}
}

violations contains v if {
	days_since(input.evidence.backup.restore_tested_at) > 90
	v := {
		"control": "DORA-11-RESTORE",
		"msg": sprintf(
			"Last restore test is %v days old (max 90 days)",
			[round(days_since(input.evidence.backup.restore_tested_at))],
		),
	}
}

deny contains msg if {
	some v in violations
	msg := v.msg
}
