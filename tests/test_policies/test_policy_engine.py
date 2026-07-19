"""Python-side tests of the OPA runner (real `opa eval` where available)."""

import pytest

from engine.controls import CONTROLS
from engine.demo import build_demo_evidence
from engine.policy_engine import (
    EVIDENCE_INPUT_KEYS,
    OPANotAvailableError,
    PolicyEngine,
    PolicyEvaluationError,
)
from tests.conftest import requires_opa


def healthy_input() -> dict:
    """Demo evidence with its intentional changelog gap patched to green."""
    latest = {e.type: e.payload for e in build_demo_evidence()}
    latest["git.changelog"] = {
        **latest["git.changelog"],
        "documented_versions": ["v1.0.0", "v1.1.0"],
        "missing": [],
    }
    return PolicyEngine().build_input(latest)


def test_build_input_maps_known_types_and_drops_unknown():
    doc = PolicyEngine().build_input(
        {"ci.coverage": {"percent": 91.0}, "esoteric.type": {"x": 1}}
    )
    assert doc["evidence"] == {"coverage": {"percent": 91.0}}
    assert "now" in doc


def test_every_collector_evidence_type_is_mapped():
    assert set(EVIDENCE_INPUT_KEYS) == {
        "ci.coverage", "ci.tests", "ci.backup", "ci.resilience",
        "git.commits", "git.secret_scan", "git.changelog",
        "sbom.cyclonedx", "scan.vulnerabilities", "access.secrets_log",
    }


def test_missing_opa_binary_raises():
    engine = PolicyEngine()
    engine.opa_path = None
    with pytest.raises(OPANotAvailableError, match="not found"):
        engine.evaluate({"evidence": {}})


def test_unusable_opa_path_raises():
    engine = PolicyEngine(opa_path="/nonexistent/opa-binary")
    with pytest.raises(OPANotAvailableError):
        engine.evaluate({"evidence": {}})


def test_find_opa_honors_env_var(monkeypatch, tmp_path):
    from engine.policy_engine import find_opa

    monkeypatch.setenv("OPA_PATH", "/nonexistent/opa-binary")
    assert find_opa() is None  # configured but absent: no silent PATH fallback

    fake = tmp_path / "opa"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("OPA_PATH", str(fake))
    assert find_opa() == str(fake)


@requires_opa
def test_healthy_pipeline_has_zero_violations():
    violations = PolicyEngine().violations_by_package(healthy_input())
    assert set(violations) == {
        "dora.article_09", "dora.article_11", "dora.article_25",
        "iso27001.a5", "iso27001.a12",
    }
    assert all(package_violations == [] for package_violations in violations.values())


@requires_opa
def test_empty_evidence_fails_every_registered_control():
    violations = PolicyEngine().violations_by_package(
        {"evidence": {}, "now": "2026-07-19T12:00:00+00:00"}
    )
    violated = {v["control"] for vs in violations.values() for v in vs}
    assert violated == set(CONTROLS)  # fail-closed across the whole registry


@requires_opa
def test_low_coverage_produces_explicit_deny_message():
    doc = healthy_input()
    doc["evidence"]["coverage"] = {"percent": 55.5}
    data = PolicyEngine().evaluate(doc)
    assert any("55.5%" in msg for msg in data["dora"]["article_09"]["deny"])


@requires_opa
def test_broken_policy_dir_raises_evaluation_error(tmp_path):
    (tmp_path / "bad.rego").write_text("package broken\n\nthis is { not rego", encoding="utf-8")
    with pytest.raises(PolicyEvaluationError):
        PolicyEngine(policies_dir=tmp_path).evaluate({"evidence": {}})
