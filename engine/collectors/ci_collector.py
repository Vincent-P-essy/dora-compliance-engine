"""Collect evidence from CI pipeline artifacts.

Everything here is a file produced by a CI job — no network access:

- ``ci.tests``      — JUnit XML test results (pytest ``--junitxml``)
- ``ci.coverage``   — Cobertura XML coverage report (``coverage xml``)
- ``ci.backup``     — JSON artifact of the scheduled backup-verification job
- ``ci.resilience`` — JSON report of the latest resilience/DR exercise
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from . import CollectorError, Evidence


def _read_json(path: Path) -> dict:
    if not path.exists():
        raise CollectorError(f"report not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CollectorError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CollectorError(f"expected a JSON object in {path}")
    return data


def _read_xml(path: Path) -> ET.Element:
    if not path.exists():
        raise CollectorError(f"report not found: {path}")
    try:
        return ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise CollectorError(f"invalid XML in {path}: {exc}") from exc


class CICollector:
    def __init__(
        self,
        junit_path: str | Path | None = None,
        coverage_path: str | Path | None = None,
        backup_report_path: str | Path | None = None,
        resilience_report_path: str | Path | None = None,
    ):
        self.junit_path = Path(junit_path) if junit_path else None
        self.coverage_path = Path(coverage_path) if coverage_path else None
        self.backup_report_path = Path(backup_report_path) if backup_report_path else None
        self.resilience_report_path = Path(resilience_report_path) if resilience_report_path else None

    def collect_test_results(self) -> Evidence:
        root = _read_xml(self.junit_path)
        suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
        if not suites:
            raise CollectorError(f"no <testsuite> element in {self.junit_path}")
        totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        duration = 0.0
        for suite in suites:
            for key in totals:
                totals[key] += int(suite.get(key, 0))
            duration += float(suite.get("time", 0))
        payload = {
            "suite": "junit",
            "total": totals["tests"],
            "passed": totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"],
            "failures": totals["failures"],
            "errors": totals["errors"],
            "skipped": totals["skipped"],
            "duration_seconds": round(duration, 2),
        }
        return Evidence("ci", "ci.tests", ("DORA-09-COV",), payload)

    def collect_coverage(self) -> Evidence:
        root = _read_xml(self.coverage_path)
        if root.tag != "coverage" or "line-rate" not in root.attrib:
            raise CollectorError(f"not a Cobertura coverage report: {self.coverage_path}")
        line_rate = float(root.get("line-rate"))
        payload = {
            "percent": round(line_rate * 100, 1),
            "lines_covered": int(root.get("lines-covered", 0)),
            "lines_total": int(root.get("lines-valid", 0)),
            "source_report": self.coverage_path.name,
        }
        return Evidence("ci", "ci.coverage", ("DORA-09-COV",), payload)

    def collect_backup_report(self) -> Evidence:
        data = _read_json(self.backup_report_path)
        for key in ("job", "last_success", "verified"):
            if key not in data:
                raise CollectorError(f"backup report missing key '{key}': {self.backup_report_path}")
        payload = {
            "job": data["job"],
            "last_success": data["last_success"],
            "verified": bool(data["verified"]),
            "restore_tested_at": data.get("restore_tested_at"),
            "size_mb": data.get("size_mb"),
        }
        return Evidence("ci", "ci.backup", ("DORA-11-BACKUP", "DORA-11-RESTORE"), payload)

    def collect_resilience_report(self) -> Evidence:
        data = _read_json(self.resilience_report_path)
        for key in ("exercise", "performed_at"):
            if key not in data:
                raise CollectorError(
                    f"resilience report missing key '{key}': {self.resilience_report_path}"
                )
        payload = {
            "exercise": data["exercise"],
            "performed_at": data["performed_at"],
            "documented": bool(data.get("documented", False)),
            "report_url": data.get("report_url"),
            "rto_minutes": data.get("rto_minutes"),
            "rto_target_minutes": data.get("rto_target_minutes"),
        }
        return Evidence("ci", "ci.resilience", ("DORA-25-TEST", "DORA-25-DOC"), payload)

    def collect(self) -> list[Evidence]:
        collected = []
        if self.junit_path:
            collected.append(self.collect_test_results())
        if self.coverage_path:
            collected.append(self.collect_coverage())
        if self.backup_report_path:
            collected.append(self.collect_backup_report())
        if self.resilience_report_path:
            collected.append(self.collect_resilience_report())
        if not collected:
            raise CollectorError("CICollector configured with no artifact paths")
        return collected
