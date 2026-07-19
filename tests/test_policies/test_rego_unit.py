"""Wrapper around OPA's native tooling so `pytest` runs the Rego suite too."""

import subprocess
from pathlib import Path

from engine.policy_engine import find_opa
from tests.conftest import requires_opa

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICIES = REPO_ROOT / "engine" / "policies"
REGO_TESTS = Path(__file__).parent / "rego"


@requires_opa
def test_opa_check_validates_policy_bundle():
    proc = subprocess.run(
        [find_opa(), "check", str(POLICIES)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


@requires_opa
def test_native_rego_unit_suite_passes():
    proc = subprocess.run(
        [find_opa(), "test", str(POLICIES), str(REGO_TESTS), "-v"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FAIL" not in proc.stdout
