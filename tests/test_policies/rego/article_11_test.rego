package dora.article_11_test

import data.dora.article_11

now := "2026-07-19T12:00:00+00:00"

fresh_backup := {
	"evidence": {"backup": {
		"job": "postgres-nightly",
		"last_success": "2026-07-19T02:00:00+00:00",
		"verified": true,
		"restore_tested_at": "2026-06-28T00:00:00+00:00",
	}},
	"now": now,
}

test_fresh_verified_backup_passes if {
	count(article_11.violations) == 0 with input as fresh_backup
}

test_stale_backup_denied if {
	inp := {
		"evidence": {"backup": {
			"job": "postgres-nightly",
			"last_success": "2026-07-17T12:00:00+00:00",
			"verified": true,
			"restore_tested_at": "2026-06-28T00:00:00+00:00",
		}},
		"now": now,
	}
	vs := article_11.violations with input as inp
	some v in vs
	v.control == "DORA-11-BACKUP"
	contains(v.msg, "48 hours")
}

test_unverified_backup_denied if {
	inp := {
		"evidence": {"backup": {
			"job": "postgres-nightly",
			"last_success": "2026-07-19T02:00:00+00:00",
			"verified": false,
			"restore_tested_at": "2026-06-28T00:00:00+00:00",
		}},
		"now": now,
	}
	vs := article_11.violations with input as inp
	some v in vs
	v.control == "DORA-11-BACKUP"
	contains(v.msg, "never verified")
}

test_restore_never_tested_denied if {
	inp := {
		"evidence": {"backup": {
			"job": "postgres-nightly",
			"last_success": "2026-07-19T02:00:00+00:00",
			"verified": true,
		}},
		"now": now,
	}
	vs := article_11.violations with input as inp
	some v in vs
	v.control == "DORA-11-RESTORE"
}

test_restore_too_old_denied if {
	inp := {
		"evidence": {"backup": {
			"job": "postgres-nightly",
			"last_success": "2026-07-19T02:00:00+00:00",
			"verified": true,
			"restore_tested_at": "2026-01-01T00:00:00+00:00",
		}},
		"now": now,
	}
	vs := article_11.violations with input as inp
	some v in vs
	v.control == "DORA-11-RESTORE"
	contains(v.msg, "days old")
}

test_missing_backup_evidence_fails_both_controls if {
	vs := article_11.violations with input as {"evidence": {}, "now": now}
	{v.control | some v in vs} == {"DORA-11-BACKUP", "DORA-11-RESTORE"}
}
