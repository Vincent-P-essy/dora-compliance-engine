import pytest

from engine.collectors import CollectorError
from engine.collectors.ci_collector import CICollector
from tests.conftest import FIXTURES


def test_junit_parsing_aggregates_suites():
    evidence = CICollector(junit_path=FIXTURES / "junit.xml").collect_test_results()
    assert evidence.type == "ci.tests"
    assert evidence.payload["total"] == 45
    assert evidence.payload["failures"] == 1
    assert evidence.payload["skipped"] == 2
    assert evidence.payload["passed"] == 42
    assert evidence.payload["duration_seconds"] == pytest.approx(12.38)


def test_junit_green_suite():
    evidence = CICollector(junit_path=FIXTURES / "junit_green.xml").collect_test_results()
    assert evidence.payload["failures"] == 0
    assert evidence.payload["passed"] == 47


def test_junit_missing_file_raises(tmp_path):
    with pytest.raises(CollectorError, match="not found"):
        CICollector(junit_path=tmp_path / "nope.xml").collect_test_results()


def test_coverage_parsing():
    evidence = CICollector(coverage_path=FIXTURES / "coverage.xml").collect_coverage()
    assert evidence.type == "ci.coverage"
    assert evidence.payload["percent"] == 92.4
    assert evidence.payload["lines_covered"] == 1736
    assert evidence.payload["lines_total"] == 1879


def test_coverage_rejects_non_cobertura():
    with pytest.raises(CollectorError, match="Cobertura"):
        CICollector(coverage_path=FIXTURES / "junit.xml").collect_coverage()


def test_backup_report():
    evidence = CICollector(backup_report_path=FIXTURES / "backup_report.json").collect_backup_report()
    assert evidence.control_ids == ("DORA-11-BACKUP", "DORA-11-RESTORE")
    assert evidence.payload["verified"] is True
    assert evidence.payload["job"] == "postgres-nightly"


def test_backup_report_missing_key(tmp_path):
    bad = tmp_path / "backup.json"
    bad.write_text('{"job": "x", "verified": true}', encoding="utf-8")
    with pytest.raises(CollectorError, match="last_success"):
        CICollector(backup_report_path=bad).collect_backup_report()


def test_resilience_report():
    evidence = CICollector(
        resilience_report_path=FIXTURES / "resilience_report.json"
    ).collect_resilience_report()
    assert evidence.payload["documented"] is True
    assert evidence.payload["exercise"] == "regional-failover-drill"


def test_collect_gathers_all_configured_artifacts():
    collector = CICollector(
        junit_path=FIXTURES / "junit_green.xml",
        coverage_path=FIXTURES / "coverage.xml",
        backup_report_path=FIXTURES / "backup_report.json",
        resilience_report_path=FIXTURES / "resilience_report.json",
    )
    assert [e.type for e in collector.collect()] == [
        "ci.tests",
        "ci.coverage",
        "ci.backup",
        "ci.resilience",
    ]


def test_collect_with_no_paths_raises():
    with pytest.raises(CollectorError, match="no artifact paths"):
        CICollector().collect()
