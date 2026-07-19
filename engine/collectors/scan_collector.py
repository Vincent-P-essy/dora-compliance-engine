"""Collect evidence from vulnerability scanner reports (Trivy or pip-audit).

Reads the scanner's JSON output file — the scan itself runs in CI, so this
collector stays offline. Produces ``scan.vulnerabilities`` evidence with
counts by severity.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import CollectorError, Evidence

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class ScanCollector:
    def __init__(self, report_path: str | Path):
        self.report_path = Path(report_path)

    def _load(self) -> dict | list:
        if not self.report_path.exists():
            raise CollectorError(f"scan report not found: {self.report_path}")
        try:
            return json.loads(self.report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CollectorError(f"invalid JSON in {self.report_path}: {exc}") from exc

    def _parse_trivy(self, data: dict) -> dict:
        by_severity = dict.fromkeys(_SEVERITIES, 0)
        critical_ids = []
        for result in data.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                severity = str(vuln.get("Severity", "UNKNOWN")).upper()
                by_severity[severity if severity in by_severity else "UNKNOWN"] += 1
                if severity == "CRITICAL":
                    critical_ids.append(vuln.get("VulnerabilityID", "unknown"))
        return {"scanner": "trivy", "by_severity": by_severity, "critical_ids": sorted(critical_ids)}

    def _parse_pip_audit(self, data: dict | list) -> dict:
        deps = data.get("dependencies", []) if isinstance(data, dict) else data
        by_severity = dict.fromkeys(_SEVERITIES, 0)
        for dep in deps:
            # pip-audit reports advisories without a severity field.
            by_severity["UNKNOWN"] += len(dep.get("vulns") or [])
        return {"scanner": "pip-audit", "by_severity": by_severity, "critical_ids": []}

    def collect_vulnerabilities(self) -> Evidence:
        data = self._load()
        if isinstance(data, dict) and "Results" in data:
            parsed = self._parse_trivy(data)
        elif isinstance(data, list) or (isinstance(data, dict) and "dependencies" in data):
            parsed = self._parse_pip_audit(data)
        else:
            raise CollectorError(
                f"unrecognized scan format (expected Trivy or pip-audit JSON): {self.report_path}"
            )
        parsed["total"] = sum(parsed["by_severity"].values())
        return Evidence(parsed["scanner"], "scan.vulnerabilities", ("DORA-09-VULN",), parsed)

    def collect(self) -> list[Evidence]:
        return [self.collect_vulnerabilities()]
