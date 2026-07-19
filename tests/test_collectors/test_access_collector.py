import pytest

from engine.collectors import CollectorError
from engine.collectors.access_collector import AccessLogCollector
from tests.conftest import FIXTURES


def test_access_log_counts():
    evidence = AccessLogCollector(FIXTURES / "access_log.jsonl").collect_access_log()
    assert evidence.type == "access.secrets_log"
    assert evidence.payload["events"] == 5
    assert evidence.payload["unauthorized"] == 1
    assert evidence.payload["off_hours"] == 1  # the 23:15 access
    assert evidence.payload["principals"] == ["ci-bot", "j.doe", "vault-agent"]


def test_malformed_line_raises(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text('{"ts": "2026-07-18T09:00:00+00:00"broken\n', encoding="utf-8")
    with pytest.raises(CollectorError, match="invalid JSONL"):
        AccessLogCollector(log).collect_access_log()


def test_missing_key_raises(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text('{"ts": "2026-07-18T09:00:00+00:00", "principal": "x"}\n', encoding="utf-8")
    with pytest.raises(CollectorError, match="missing key"):
        AccessLogCollector(log).collect_access_log()


def test_empty_log_raises(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("\n", encoding="utf-8")
    with pytest.raises(CollectorError, match="empty"):
        AccessLogCollector(log).collect_access_log()
