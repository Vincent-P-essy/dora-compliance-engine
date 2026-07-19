package dora.article_25_test

import data.dora.article_25

now := "2026-07-19T12:00:00+00:00"

recent_drill := {
	"evidence": {"resilience": {
		"exercise": "regional-failover-drill",
		"performed_at": "2026-07-07T10:00:00+00:00",
		"documented": true,
		"report_url": "https://wiki.internal/resilience/2026-07-drill",
	}},
	"now": now,
}

test_recent_documented_drill_passes if {
	count(article_25.violations) == 0 with input as recent_drill
}

test_old_exercise_denied if {
	inp := {
		"evidence": {"resilience": {
			"exercise": "dr-run",
			"performed_at": "2026-01-01T00:00:00+00:00",
			"documented": true,
			"report_url": "https://wiki.internal/dr",
		}},
		"now": now,
	}
	vs := article_25.violations with input as inp
	some v in vs
	v.control == "DORA-25-TEST"
	contains(v.msg, "days old")
}

test_undocumented_exercise_denied if {
	inp := {
		"evidence": {"resilience": {
			"exercise": "dr-run",
			"performed_at": "2026-07-07T10:00:00+00:00",
			"documented": false,
		}},
		"now": now,
	}
	vs := article_25.violations with input as inp
	some v in vs
	v.control == "DORA-25-DOC"
	contains(v.msg, "never documented")
}

test_documented_without_report_url_denied if {
	inp := {
		"evidence": {"resilience": {
			"exercise": "dr-run",
			"performed_at": "2026-07-07T10:00:00+00:00",
			"documented": true,
		}},
		"now": now,
	}
	vs := article_25.violations with input as inp
	some v in vs
	v.control == "DORA-25-DOC"
	contains(v.msg, "no report URL")
}

test_missing_resilience_evidence_fails_both_controls if {
	vs := article_25.violations with input as {"evidence": {}, "now": now}
	{v.control | some v in vs} == {"DORA-25-TEST", "DORA-25-DOC"}
}
