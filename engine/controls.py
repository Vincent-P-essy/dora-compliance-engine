"""Registry of automated controls and their mapping to policy packages.

This is the single source of truth for what the engine measures. Each control
maps a regulatory requirement to one Rego policy package and the evidence type
that feeds it. The scorer walks this registry: a control passes when the
policy evaluation produced no violation bearing its ID.
"""

from __future__ import annotations

FRAMEWORKS = ("dora", "iso27001")

CONTROLS: dict[str, dict] = {
    # ── DORA — Regulation (EU) 2022/2554, applicable since 17 Jan 2025 ───────
    "DORA-09-COV": {
        "framework": "dora",
        "ref": "DORA Art. 9(2) — Protection and prevention",
        "title": "Tested before production deployment",
        "description": "The CI suite must be green and line coverage >= 80%.",
        "package": "dora.article_09",
        "evidence_types": ["ci.coverage", "ci.tests"],
    },
    "DORA-09-VULN": {
        "framework": "dora",
        "ref": "DORA Art. 9(4)(c) — Vulnerability management",
        "title": "No unresolved critical vulnerabilities",
        "description": "The latest dependency/image scan must report zero CRITICAL findings.",
        "package": "dora.article_09",
        "evidence_types": ["scan.vulnerabilities"],
    },
    "DORA-09-SBOM": {
        "framework": "dora",
        "ref": "DORA Art. 9(1) — ICT asset knowledge",
        "title": "Software inventory (SBOM) is current",
        "description": "A non-empty CycloneDX SBOM must exist for the deployed artifact.",
        "package": "dora.article_09",
        "evidence_types": ["sbom.cyclonedx"],
    },
    "DORA-11-BACKUP": {
        "framework": "dora",
        "ref": "DORA Art. 11(2) — Backup policies",
        "title": "Verified backup within 24 hours",
        "description": "The scheduled backup job must have succeeded and been verified in the last 24h.",
        "package": "dora.article_11",
        "evidence_types": ["ci.backup"],
    },
    "DORA-11-RESTORE": {
        "framework": "dora",
        "ref": "DORA Art. 11(4) — Restoration and recovery",
        "title": "Restore procedure tested within 90 days",
        "description": "A real restore from backup must have been exercised in the last 90 days.",
        "package": "dora.article_11",
        "evidence_types": ["ci.backup"],
    },
    "DORA-25-TEST": {
        "framework": "dora",
        "ref": "DORA Art. 25(1) — Testing of ICT tools and systems",
        "title": "Resilience exercise within 90 days",
        "description": "A resilience/DR exercise (e.g. failover drill) must have run in the last 90 days.",
        "package": "dora.article_25",
        "evidence_types": ["ci.resilience"],
    },
    "DORA-25-DOC": {
        "framework": "dora",
        "ref": "DORA Art. 25(2) — Documentation of testing",
        "title": "Resilience exercise is documented",
        "description": "The latest exercise must be documented with a retrievable report.",
        "package": "dora.article_25",
        "evidence_types": ["ci.resilience"],
    },
    # ── ISO/IEC 27001:2022 — Annex A ─────────────────────────────────────────
    "ISO-A5-CHANGELOG": {
        "framework": "iso27001",
        "ref": "ISO 27001 A.5 — Organizational controls",
        "title": "Changelog entry for every release",
        "description": "Every git release tag must have a matching CHANGELOG entry.",
        "package": "iso27001.a5",
        "evidence_types": ["git.changelog"],
    },
    "ISO-A12-SECRETS": {
        "framework": "iso27001",
        "ref": "ISO 27001 A.12 / A.8.28 — Secure development",
        "title": "No secrets in the commit history",
        "description": "The secret scan over recent commits must report zero findings.",
        "package": "iso27001.a12",
        "evidence_types": ["git.secret_scan"],
    },
    "ISO-A12-ACCESS": {
        "framework": "iso27001",
        "ref": "ISO 27001 A.12 — Operations security (logging)",
        "title": "No unauthorized secret access",
        "description": "The secret-manager audit log must contain zero unauthorized accesses.",
        "package": "iso27001.a12",
        "evidence_types": ["access.secrets_log"],
    },
    "ISO-A12-SIGNED": {
        "framework": "iso27001",
        "ref": "ISO 27001 A.12 — Change integrity",
        "title": "Majority of commits are signed",
        "description": "At least 50% of recent commits must carry a GPG signature.",
        "package": "iso27001.a12",
        "evidence_types": ["git.commits"],
    },
}


def controls_for(framework: str) -> dict[str, dict]:
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework '{framework}' (expected one of {FRAMEWORKS})")
    return {cid: meta for cid, meta in CONTROLS.items() if meta["framework"] == framework}
