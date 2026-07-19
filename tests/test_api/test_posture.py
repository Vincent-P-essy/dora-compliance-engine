from engine.policy_engine import OPANotAvailableError, PolicyEvaluationError


def test_requires_auth(client):
    assert client.get("/api/posture/dora").status_code == 401


def test_unknown_framework_404(client, auth_header, fake_engine):
    response = client.get("/api/posture/soc2", headers=auth_header("ciso"))
    assert response.status_code == 404


def test_green_posture_with_drift_and_history(client, auth_header, fake_engine):
    response = client.get("/api/posture/dora", headers=auth_header("devops"))
    assert response.status_code == 200
    body = response.get_json()
    assert body["framework"] == "dora"
    assert body["score"] == 100.0
    assert len(body["controls"]) == body["total"] == 7
    assert body["drift"]["status"] in {"no_baseline", "ok"}
    assert len(body["history"]) >= 1


def test_every_role_can_read_posture(client, auth_header, fake_engine):
    for username in ("ciso", "devops", "auditor"):
        assert (
            client.get("/api/posture/iso27001", headers=auth_header(username)).status_code
            == 200
        )


def test_failing_control_is_reported(client, auth_header, fake_engine):
    fake_engine.violations = {
        "dora.article_11": [{"control": "DORA-11-BACKUP", "msg": "backup is 40.0 hours old"}]
    }
    body = client.get("/api/posture/dora", headers=auth_header("auditor")).get_json()
    failing = [c for c in body["controls"] if c["status"] == "FAIL"]
    assert [c["id"] for c in failing] == ["DORA-11-BACKUP"]
    assert body["score"] == round(6 / 7 * 100, 1)
    assert "40.0 hours" in failing[0]["messages"][0]


def test_503_when_opa_unavailable(client, auth_header, fake_engine, monkeypatch):
    def boom(_doc):
        raise OPANotAvailableError("opa binary not found")

    monkeypatch.setattr(fake_engine, "violations_by_package", boom)
    response = client.get("/api/posture/dora", headers=auth_header("ciso"))
    assert response.status_code == 503


def test_500_on_policy_evaluation_error(client, auth_header, fake_engine, monkeypatch):
    def boom(_doc):
        raise PolicyEvaluationError("bad policy bundle")

    monkeypatch.setattr(fake_engine, "violations_by_package", boom)
    response = client.get("/api/posture/dora", headers=auth_header("ciso"))
    assert response.status_code == 500
