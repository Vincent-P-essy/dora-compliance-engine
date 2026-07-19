"""Application factory, health check and operational CLI commands."""

from __future__ import annotations

import json
import os

import click
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_smorest import Api
from sqlalchemy import select, text
from werkzeug.security import generate_password_hash

import engine
from api.config import Config
from engine.controls import FRAMEWORKS
from engine.db import SessionLocal, User, init_db, init_engine
from engine.demo import build_demo_evidence
from engine.drift_detector import DriftDetector
from engine.evidence_vault import EvidenceVault
from engine.policy_engine import OPANotAvailableError, find_opa
from engine.scorer import Scorer

DEMO_USERS = (
    ("ciso", "DEMO_CISO_PASSWORD", "ciso-demo-password", "CISO"),
    ("devops", "DEMO_DEVOPS_PASSWORD", "devops-demo-password", "DevOps"),
    ("auditor", "DEMO_AUDITOR_PASSWORD", "auditor-demo-password", "Auditor"),
)


def create_app(config_object: type = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    init_engine(app.config["DATABASE_URL"])
    init_db()

    jwt = JWTManager(app)

    @jwt.unauthorized_loader
    def _missing_token(reason):
        return jsonify({"code": 401, "status": "Unauthorized", "message": reason}), 401

    @jwt.invalid_token_loader
    def _invalid_token(reason):
        return jsonify({"code": 401, "status": "Unauthorized", "message": reason}), 401

    @jwt.expired_token_loader
    def _expired_token(header, payload):
        return jsonify({"code": 401, "status": "Unauthorized", "message": "Token has expired"}), 401

    api = Api(app)

    from api.routes.auth import blp as auth_blp
    from api.routes.evidence import blp as evidence_blp
    from api.routes.gate import blp as gate_blp
    from api.routes.posture import blp as posture_blp
    from api.routes.reports import blp as reports_blp

    for blp in (auth_blp, posture_blp, evidence_blp, gate_blp, reports_blp):
        api.register_blueprint(blp)

    @app.route("/api/health")
    def health():
        try:
            SessionLocal().execute(text("SELECT 1"))
            database = "up"
        except Exception:  # pragma: no cover - needs a broken DB to trigger
            database = "down"
        status = {
            "status": "ok" if database == "up" else "degraded",
            "version": engine.__version__,
            "database": database,
            "opa": "available" if find_opa() else "missing",
        }
        return jsonify(status), 200 if database == "up" else 503

    @app.teardown_appcontext
    def _remove_session(exc=None):
        SessionLocal.remove()

    _register_cli(app)
    return app


def _register_cli(app: Flask) -> None:
    @app.cli.command("seed-demo")
    def seed_demo() -> None:
        """Create demo users, load the synthetic evidence set, evaluate both frameworks."""
        session = SessionLocal()
        for username, env_key, default, role in DEMO_USERS:
            exists = session.scalars(select(User).where(User.username == username)).first()
            if not exists:
                session.add(
                    User(
                        username=username,
                        password_hash=generate_password_hash(os.environ.get(env_key, default)),
                        role=role,
                    )
                )
        session.commit()

        vault = EvidenceVault(session)
        vault.store_all(build_demo_evidence())
        click.echo(f"Seeded demo users and evidence (vault now holds {vault.count()} records)")

        try:
            for framework in FRAMEWORKS:
                result = Scorer(session).evaluate(framework)
                click.echo(
                    f"  {framework}: {result['score']}/100 "
                    f"({result['passed']}/{result['total']} controls passing)"
                )
        except OPANotAvailableError as exc:
            click.echo(f"  evaluation skipped: {exc}")

    @app.cli.command("evaluate")
    @click.option("--framework", "-f", default="dora", type=click.Choice(FRAMEWORKS))
    def evaluate_cmd(framework: str) -> None:
        """Evaluate one framework against the vault and print the result."""
        result = Scorer(SessionLocal()).evaluate(framework)
        click.echo(json.dumps(result, indent=2))

    @app.cli.command("check-drift")
    @click.option("--framework", "-f", default="dora", type=click.Choice(FRAMEWORKS))
    def check_drift_cmd(framework: str) -> None:
        """Compare the current score to the J-7 baseline."""
        report = DriftDetector(SessionLocal()).check(framework)
        click.echo(json.dumps(report, indent=2))
