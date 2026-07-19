import json

from engine.policy_engine import find_opa
from tests.conftest import requires_opa


def test_seed_demo_creates_users_and_evidence(app):
    result = app.test_cli_runner().invoke(args=["seed-demo"])
    assert result.exit_code == 0, result.output
    assert "Seeded demo users and evidence" in result.output
    if find_opa():
        assert "dora: 100.0/100" in result.output
        assert "iso27001: 75.0/100" in result.output


def test_seed_demo_is_idempotent_for_users(app):
    runner = app.test_cli_runner()
    assert runner.invoke(args=["seed-demo"]).exit_code == 0
    assert runner.invoke(args=["seed-demo"]).exit_code == 0


@requires_opa
def test_evaluate_command_prints_json(app):
    runner = app.test_cli_runner()
    runner.invoke(args=["seed-demo"])
    result = runner.invoke(args=["evaluate", "-f", "dora"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["framework"] == "dora"
    assert payload["score"] == 100.0


def test_check_drift_command_without_data(app):
    result = app.test_cli_runner().invoke(args=["check-drift", "-f", "dora"])
    assert result.exit_code == 0
    assert "no_data" in result.output
