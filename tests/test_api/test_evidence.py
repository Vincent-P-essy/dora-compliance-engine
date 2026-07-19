from engine.demo import build_demo_evidence
from engine.evidence_vault import EvidenceVault


def test_requires_auth(client):
    assert client.get("/api/evidence/DORA-11-BACKUP").status_code == 401


def test_unknown_control_404(client, auth_header):
    assert client.get("/api/evidence/NOPE-42", headers=auth_header("ciso")).status_code == 404


def test_devops_cannot_read_evidence(client, auth_header):
    response = client.get("/api/evidence/DORA-11-BACKUP", headers=auth_header("devops"))
    assert response.status_code == 403


def test_lists_evidence_with_live_integrity_check(client, auth_header, session):
    EvidenceVault(session).store_all(build_demo_evidence())
    body = client.get(
        "/api/evidence/DORA-11-BACKUP", headers=auth_header("auditor")
    ).get_json()
    assert body["control"]["id"] == "DORA-11-BACKUP"
    assert body["control"]["framework"] == "dora"
    assert body["evidence_count"] == 1

    entry = body["evidence"][0]
    assert entry["integrity"] == "verified"
    assert len(entry["sha256"]) == 64
    assert entry["type"] == "ci.backup"
    assert entry["payload"]["job"] == "postgres-nightly"
