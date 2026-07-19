package iso27001.a5_test

import data.iso27001.a5

now := "2026-07-19T12:00:00+00:00"

test_all_releases_documented_passes if {
	inp := {
		"evidence": {"changelog": {
			"tags": ["v1.0.0", "v1.1.0"],
			"documented_versions": ["v1.0.0", "v1.1.0"],
			"missing": [],
			"changelog_exists": true,
		}},
		"now": now,
	}
	count(a5.violations) == 0 with input as inp
}

test_undocumented_release_denied if {
	inp := {
		"evidence": {"changelog": {
			"tags": ["v1.0.0", "v1.1.0"],
			"documented_versions": ["v1.0.0"],
			"missing": ["v1.1.0"],
			"changelog_exists": true,
		}},
		"now": now,
	}
	vs := a5.violations with input as inp
	some v in vs
	v.control == "ISO-A5-CHANGELOG"
	contains(v.msg, "v1.1.0")
}

test_releases_without_changelog_file_denied if {
	inp := {
		"evidence": {"changelog": {
			"tags": ["v1.0.0"],
			"documented_versions": [],
			"missing": ["v1.0.0"],
			"changelog_exists": false,
		}},
		"now": now,
	}
	vs := a5.violations with input as inp
	some v in vs
	contains(v.msg, "no CHANGELOG.md")
}

test_missing_changelog_evidence_fails_closed if {
	vs := a5.violations with input as {"evidence": {}, "now": now}
	count(vs) == 1
}
