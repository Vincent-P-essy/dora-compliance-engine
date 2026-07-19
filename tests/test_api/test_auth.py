def test_token_issued_with_role_claim(client, users):
    response = client.post(
        "/api/auth/token", json={"username": "ciso", "password": "ciso-pw"}
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["role"] == "CISO"
    assert body["expires_in"] == 3600
    assert body["access_token"].count(".") == 2  # header.payload.signature


def test_wrong_password_rejected(client, users):
    response = client.post(
        "/api/auth/token", json={"username": "ciso", "password": "wrong"}
    )
    assert response.status_code == 401


def test_unknown_user_rejected(client, users):
    response = client.post(
        "/api/auth/token", json={"username": "ghost", "password": "x"}
    )
    assert response.status_code == 401


def test_missing_fields_rejected(client, users):
    response = client.post("/api/auth/token", json={"username": "ciso"})
    assert response.status_code == 422


def test_garbage_bearer_token_rejected(client, users):
    response = client.get(
        "/api/posture/dora", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert response.status_code == 401


def test_health_is_public(client):
    body = client.get("/api/health").get_json()
    assert body["status"] == "ok"
    assert body["database"] == "up"
    assert body["version"]
