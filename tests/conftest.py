"""Shared fixtures: throwaway app+DB, JWT helpers, temp git repo, fake OPA."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from api.app import create_app
from api.config import TestConfig
from engine.db import SessionLocal, User
from engine.policy_engine import find_opa

FIXTURES = Path(__file__).parent / "fixtures"

requires_opa = pytest.mark.skipif(
    find_opa() is None, reason="opa binary not available on PATH"
)


@pytest.fixture()
def app(tmp_path):
    class _Config(TestConfig):
        DATABASE_URL = f"sqlite:///{tmp_path / 'test.db'}"

    application = create_app(_Config)
    yield application
    SessionLocal.remove()


@pytest.fixture()
def session(app):
    return SessionLocal()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def users(session):
    for username, role in (("ciso", "CISO"), ("devops", "DevOps"), ("auditor", "Auditor")):
        session.add(
            User(
                username=username,
                password_hash=generate_password_hash(f"{username}-pw"),
                role=role,
            )
        )
    session.commit()


@pytest.fixture()
def auth_header(client, users):
    """auth_header("ciso") -> {"Authorization": "Bearer <jwt>"}"""

    def _header(username: str) -> dict[str, str]:
        response = client.post(
            "/api/auth/token", json={"username": username, "password": f"{username}-pw"}
        )
        assert response.status_code == 200, response.get_json()
        return {"Authorization": f"Bearer {response.get_json()['access_token']}"}

    return _header


class FakePolicyEngine:
    """Stands in for OPA in API/scorer tests: returns canned violations."""

    def __init__(self, violations: dict[str, list[dict]] | None = None):
        self.violations = violations or {}

    def build_input(self, latest_evidence):
        return {"evidence": {}, "now": "2026-07-19T12:00:00+00:00"}

    def violations_by_package(self, input_doc):
        return self.violations


@pytest.fixture()
def fake_engine(monkeypatch):
    """Replace the real PolicyEngine wherever Scorer instantiates one."""
    fake = FakePolicyEngine()
    monkeypatch.setattr("engine.scorer.PolicyEngine", lambda: fake)
    return fake


class TempRepo:
    """Path-like handle on a throwaway git repository (`repo.git(...)` runs git)."""

    def __init__(self, path: Path):
        self.path = path
        self._env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        }

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.path), *args],
            check=True,
            capture_output=True,
            env=self._env,
        )

    def __truediv__(self, other: str) -> Path:
        return self.path / other

    def __fspath__(self) -> str:
        return str(self.path)


@pytest.fixture()
def git_repo(tmp_path):
    """Throwaway git repository: 2 commits, 1 tag, a changelog covering it."""
    repo = TempRepo(tmp_path / "repo")
    repo.path.mkdir()
    repo.git("init", "-q", "-b", "main")
    repo.git("config", "user.name", "Test Dev")
    repo.git("config", "user.email", "dev@example.com")
    repo.git("config", "commit.gpgsign", "false")
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
    repo.git("add", ".")
    repo.git("commit", "-q", "-m", "feat: initial commit")
    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n## v1.0.0\n- initial release\n", encoding="utf-8"
    )
    repo.git("add", ".")
    repo.git("commit", "-q", "-m", "docs: add changelog")
    repo.git("tag", "v1.0.0")
    return repo
