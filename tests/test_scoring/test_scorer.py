import pytest

from engine.controls import controls_for
from engine.demo import build_demo_evidence
from engine.evidence_vault import EvidenceVault
from engine.scorer import Scorer
from tests.conftest import FakePolicyEngine, requires_opa


def test_perfect_score_and_snapshot_persistence(session):
    scorer = Scorer(session, FakePolicyEngine())
    result = scorer.evaluate("dora")
    assert result["score"] == 100.0
    assert result["passed"] == result["total"] == len(controls_for("dora"))
    assert all(c["status"] == "PASS" for c in result["controls"])

    snapshot = scorer.latest_snapshot("dora")
    assert snapshot is not None
    assert snapshot.score == 100.0
    assert snapshot.results["framework"] == "dora"


def test_partial_score_with_grouped_messages(session):
    fake = FakePolicyEngine({
        "dora.article_09": [{"control": "DORA-09-COV", "msg": "coverage too low"}],
        "dora.article_11": [
            {"control": "DORA-11-BACKUP", "msg": "backup stale"},
            {"control": "DORA-11-BACKUP", "msg": "backup unverified"},
        ],
    })
    result = Scorer(session, fake).evaluate("dora")
    assert result["failed"] == 2
    assert result["score"] == round(5 / 7 * 100, 1)

    coverage = next(c for c in result["controls"] if c["id"] == "DORA-09-COV")
    assert coverage["status"] == "FAIL"
    assert coverage["messages"] == ["coverage too low"]
    backup = next(c for c in result["controls"] if c["id"] == "DORA-11-BACKUP")
    assert len(backup["messages"]) == 2


def test_frameworks_are_scored_independently(session):
    fake = FakePolicyEngine({"dora.article_09": [{"control": "DORA-09-COV", "msg": "x"}]})
    assert Scorer(session, fake).evaluate("iso27001")["score"] == 100.0


def test_unknown_framework_raises(session):
    with pytest.raises(ValueError, match="unknown framework"):
        Scorer(session, FakePolicyEngine()).evaluate("pci-dss")


def test_history_accumulates_snapshots(session):
    scorer = Scorer(session, FakePolicyEngine())
    scorer.evaluate("dora")
    scorer.evaluate("dora")
    history = scorer.history("dora")
    assert len(history) == 2
    assert {"score", "passed", "total", "created_at"} <= set(history[0])


@requires_opa
def test_end_to_end_demo_scores(session):
    """Full pipeline: demo evidence -> vault -> OPA -> score."""
    EvidenceVault(session).store_all(build_demo_evidence())
    dora = Scorer(session).evaluate("dora")
    iso = Scorer(session).evaluate("iso27001")

    assert dora["score"] == 100.0  # the demo pipeline is DORA-green
    assert iso["score"] == 75.0  # v1.1.0 changelog gap: 3/4 controls
    failing = [c for c in iso["controls"] if c["status"] == "FAIL"]
    assert [c["id"] for c in failing] == ["ISO-A5-CHANGELOG"]
    assert any("v1.1.0" in message for message in failing[0]["messages"])
