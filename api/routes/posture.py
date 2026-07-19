"""Compliance posture: GET /api/posture/<framework>.

Runs a fresh policy evaluation over the vault's latest evidence, persists a
snapshot, and returns score + per-control detail + drift + recent history.
"""

from __future__ import annotations

from flask_smorest import Blueprint, abort

from api.routes import role_required
from engine.controls import FRAMEWORKS
from engine.db import SessionLocal
from engine.drift_detector import DriftDetector
from engine.policy_engine import OPANotAvailableError, PolicyEvaluationError
from engine.scorer import Scorer

blp = Blueprint("posture", __name__, url_prefix="/api/posture", description="Compliance posture")


@blp.route("/<framework>")
@blp.response(200)
@role_required("CISO", "DevOps", "Auditor")
def get_posture(framework: str):
    """Score one framework (0-100) with control-level detail and drift status."""
    if framework not in FRAMEWORKS:
        abort(404, message=f"Unknown framework '{framework}' (supported: {', '.join(FRAMEWORKS)})")
    session = SessionLocal()
    scorer = Scorer(session)
    try:
        result = scorer.evaluate(framework)
    except OPANotAvailableError as exc:
        abort(503, message=str(exc))
    except PolicyEvaluationError as exc:
        abort(500, message=str(exc))
    result["drift"] = DriftDetector(session).check(framework)
    result["history"] = scorer.history(framework, limit=10)
    return result
