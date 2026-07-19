import pytest

from engine.collectors import CollectorError, Evidence
from engine.collectors.scan_collector import ScanCollector
from tests.conftest import FIXTURES


def test_trivy_counts_by_severity():
    evidence = ScanCollector(FIXTURES / "trivy_report.json").collect_vulnerabilities()
    assert evidence.payload["scanner"] == "trivy"
    assert evidence.payload["by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
        "UNKNOWN": 0,
    }
    assert evidence.payload["critical_ids"] == ["CVE-2026-11111"]
    assert evidence.payload["total"] == 5


def test_pip_audit_counts():
    evidence = ScanCollector(FIXTURES / "pip_audit_report.json").collect_vulnerabilities()
    assert evidence.payload["scanner"] == "pip-audit"
    assert evidence.payload["by_severity"]["UNKNOWN"] == 1
    assert evidence.payload["total"] == 1


def test_unknown_format_raises(tmp_path):
    weird = tmp_path / "scan.json"
    weird.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(CollectorError, match="unrecognized"):
        ScanCollector(weird).collect_vulnerabilities()


def test_evidence_digest_is_deterministic():
    a = Evidence("trivy", "scan.vulnerabilities", ("DORA-09-VULN",), {"x": 1, "y": [2, 3]})
    b = Evidence("trivy", "scan.vulnerabilities", ("DORA-09-VULN",), {"y": [2, 3], "x": 1})
    assert a.digest() == b.digest()  # key order must not change the hash
