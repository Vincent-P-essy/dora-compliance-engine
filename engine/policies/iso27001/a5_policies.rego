# ISO/IEC 27001:2022 Annex A.5 — Organizational controls.
#
# Control:
#   ISO-A5-CHANGELOG  every release (git tag) has a matching changelog entry,
#                     so changes remain traceable for audit.

package iso27001.a5

violations contains v if {
	not input.evidence.changelog
	v := {
		"control": "ISO-A5-CHANGELOG",
		"msg": "No changelog evidence collected — release traceability is unknown",
	}
}

violations contains v if {
	count(input.evidence.changelog.tags) > 0
	input.evidence.changelog.changelog_exists != true
	v := {
		"control": "ISO-A5-CHANGELOG",
		"msg": "Releases exist but the repository has no CHANGELOG.md",
	}
}

violations contains v if {
	some tag in input.evidence.changelog.missing
	v := {
		"control": "ISO-A5-CHANGELOG",
		"msg": sprintf("Release %s has no changelog entry", [tag]),
	}
}

deny contains msg if {
	some v in violations
	msg := v.msg
}
