def test_gate_pass(client, auth_header, fake_engine):
    response = client.post(
        "/api/gate/check",
        json={"framework": "dora", "minimum_score": 75},
        headers=auth_header("devops"),
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "PASS"
    assert body["score"] == 100.0
    assert body["failing_controls"] == []


def test_gate_fail_lists_failing_controls(client, auth_header, fake_engine):
    fake_engine.violations = {
        "dora.article_09": [
            {"control": "DORA-09-COV", "msg": "coverage 55.0%"},
            {"control": "DORA-09-VULN", "msg": "2 CRITICAL CVEs"},
        ],
        "dora.article_11": [{"control": "DORA-11-BACKUP", "msg": "stale backup"}],
    }
    body = client.post(
        "/api/gate/check",
        json={"framework": "dora", "minimum_score": 75},
        headers=auth_header("devops"),
    ).get_json()
    assert body["status"] == "FAIL"
    assert body["score"] == round(4 / 7 * 100, 1)
    assert {c["id"] for c in body["failing_controls"]} == {
        "DORA-09-COV", "DORA-09-VULN", "DORA-11-BACKUP",
    }


def test_gate_uses_configured_default_minimum(client, auth_header, fake_engine, app):
    body = client.post(
        "/api/gate/check", json={"framework": "dora"}, headers=auth_header("ciso")
    ).get_json()
    assert body["minimum_score"] == app.config["GATE_DEFAULT_MIN_SCORE"]


def test_auditor_cannot_run_the_gate(client, auth_header, fake_engine):
    response = client.post(
        "/api/gate/check", json={"framework": "dora"}, headers=auth_header("auditor")
    )
    assert response.status_code == 403


def test_unknown_framework_rejected_by_validation(client, auth_header, fake_engine):
    response = client.post(
        "/api/gate/check", json={"framework": "soc2"}, headers=auth_header("devops")
    )
    assert response.status_code == 422


def test_gate_requires_auth(client):
    assert client.post("/api/gate/check", json={"framework": "dora"}).status_code == 401


def test_gate_503_when_opa_unavailable(client, auth_header, fake_engine, monkeypatch):
    from engine.policy_engine import OPANotAvailableError

    def boom(_doc):
        raise OPANotAvailableError("opa binary not found")

    monkeypatch.setattr(fake_engine, "violations_by_package", boom)
    response = client.post(
        "/api/gate/check", json={"framework": "dora"}, headers=auth_header("devops")
    )
    assert response.status_code == 503


def test_gate_500_on_policy_evaluation_error(client, auth_header, fake_engine, monkeypatch):
    from engine.policy_engine import PolicyEvaluationError

    def boom(_doc):
        raise PolicyEvaluationError("opa eval failed")

    monkeypatch.setattr(fake_engine, "violations_by_package", boom)
    response = client.post(
        "/api/gate/check", json={"framework": "dora"}, headers=auth_header("devops")
    )
    assert response.status_code == 500
