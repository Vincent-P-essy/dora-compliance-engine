from datetime import timedelta

from engine.db import PostureSnapshot, utcnow
from engine.drift_detector import DriftDetector


def snapshot(session, framework, score, days_ago=0):
    session.add(
        PostureSnapshot(
            framework=framework,
            score=score,
            passed=int(score) // 10,
            total=10,
            results={},
            created_at=utcnow() - timedelta(days=days_ago),
        )
    )
    session.commit()


def test_no_data(session):
    assert DriftDetector(session).check("dora")["status"] == "no_data"


def test_no_baseline_yet(session):
    snapshot(session, "dora", 90.0)
    report = DriftDetector(session).check("dora")
    assert report["status"] == "no_baseline"
    assert report["current_score"] == 90.0


def test_small_regression_stays_ok(session):
    snapshot(session, "dora", 90.0, days_ago=8)
    snapshot(session, "dora", 87.0)
    report = DriftDetector(session).check("dora")
    assert report["status"] == "ok"
    assert report["delta"] == -3.0
    assert DriftDetector(session).alerts("dora") == []


def test_regression_beyond_threshold_alerts(session):
    snapshot(session, "dora", 95.0, days_ago=9)
    snapshot(session, "dora", 80.0)
    report = DriftDetector(session).check("dora")
    assert report["status"] == "alert"
    assert report["delta"] == -15.0

    alerts = DriftDetector(session).alerts("dora")
    assert len(alerts) == 1
    assert "dropped 15.0 points" in alerts[0]["message"]


def test_improvement_never_alerts(session):
    snapshot(session, "dora", 70.0, days_ago=10)
    snapshot(session, "dora", 95.0)
    assert DriftDetector(session).check("dora")["status"] == "ok"


def test_frameworks_are_isolated(session):
    snapshot(session, "dora", 95.0, days_ago=9)
    snapshot(session, "iso27001", 50.0)
    assert DriftDetector(session).check("iso27001")["status"] == "no_baseline"


def test_custom_threshold(session):
    snapshot(session, "dora", 90.0, days_ago=8)
    snapshot(session, "dora", 86.0)
    assert DriftDetector(session, threshold=3).check("dora")["status"] == "alert"
