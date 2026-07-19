"""Synthetic demo dataset used by `flask seed-demo`.

Represents a healthy financial-services pipeline observed today: fresh
verified backup, recent failover drill, clean scans, one undocumented
release tag left in on purpose so the demo shows a realistic non-perfect
posture. All timestamps are relative to "now" so policies evaluate the
same way whenever the demo is seeded.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.collectors import Evidence


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def build_demo_evidence(now: datetime | None = None) -> list[Evidence]:
    now = now or datetime.now(timezone.utc)
    return [
        Evidence("ci", "ci.coverage", ("DORA-09-COV",), {
            "percent": 92.4, "lines_covered": 1736, "lines_total": 1879,
            "source_report": "coverage.xml",
        }),
        Evidence("ci", "ci.tests", ("DORA-09-COV",), {
            "suite": "junit", "total": 47, "passed": 47, "failures": 0,
            "errors": 0, "skipped": 0, "duration_seconds": 14.8,
        }),
        Evidence("ci", "ci.backup", ("DORA-11-BACKUP", "DORA-11-RESTORE"), {
            "job": "postgres-nightly", "last_success": _iso(now - timedelta(hours=3)),
            "verified": True, "restore_tested_at": _iso(now - timedelta(days=21)),
            "size_mb": 412,
        }),
        Evidence("ci", "ci.resilience", ("DORA-25-TEST", "DORA-25-DOC"), {
            "exercise": "regional-failover-drill",
            "performed_at": _iso(now - timedelta(days=12)),
            "documented": True,
            "report_url": "https://wiki.internal/resilience/2026-07-drill",
            "rto_minutes": 38, "rto_target_minutes": 60,
        }),
        Evidence("git", "git.commits", ("ISO-A12-SIGNED",), {
            "count": 30, "signed": 24, "signed_ratio": 0.8,
            "authors": ["Vincent Plessy"],
            "latest": {"hash": "d3adb33f" * 5, "author": "Vincent Plessy",
                       "signature": "G", "subject": "release: v1.1.0"},
        }),
        Evidence("git", "git.secret_scan", ("ISO-A12-SECRETS",), {
            "commits_scanned": 30, "findings": 0,
            "patterns": ["aws-access-key", "private-key", "generic-credential"],
            "details": [],
        }),
        Evidence("git", "git.changelog", ("ISO-A5-CHANGELOG",), {
            "tags": ["v1.0.0", "v1.1.0"], "documented_versions": ["v1.0.0"],
            "missing": ["v1.1.0"], "changelog_path": "CHANGELOG.md",
            "changelog_exists": True,
        }),
        Evidence("sbom", "sbom.cyclonedx", ("DORA-09-SBOM",), {
            "format": "CycloneDX", "spec_version": "1.5",
            "serial_number": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "generated_at": _iso(now - timedelta(hours=6)),
            "components": 42, "without_license": 3,
            "licenses": ["Apache-2.0", "BSD-3-Clause", "MIT"],
        }),
        Evidence("trivy", "scan.vulnerabilities", ("DORA-09-VULN",), {
            "scanner": "trivy",
            "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 3, "LOW": 7, "UNKNOWN": 0},
            "critical_ids": [], "total": 11,
        }),
        Evidence("secrets-audit", "access.secrets_log", ("ISO-A12-ACCESS",), {
            "events": 128, "unauthorized": 0, "off_hours": 2,
            "principals": ["ci-bot", "vault-agent"], "window_days": 7,
        }),
    ]
