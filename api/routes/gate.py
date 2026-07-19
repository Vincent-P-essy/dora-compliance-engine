"""CI/CD gate: POST /api/gate/check -> PASS or FAIL.

Called by the reusable GitHub Action (ci-integration/github-action). Always
answers HTTP 200 with a `status` field — turning FAIL into a red build is
the caller's decision (`block_on_fail`).
"""

from __future__ import annotations

from flask import current_app
from flask_smorest import Blueprint, abort
from marshmallow import Schema, fields, validate

from api.routes import role_required
from engine.controls import FRAMEWORKS
from engine.db import SessionLocal
from engine.policy_engine import OPANotAvailableError, PolicyEvaluationError
from engine.scorer import Scorer

blp = Blueprint("gate", __name__, url_prefix="/api/gate", description="CI/CD gate")


class GateCheckSchema(Schema):
    framework = fields.String(required=True, validate=validate.OneOf(FRAMEWORKS))
    minimum_score = fields.Float(load_default=None, validate=validate.Range(min=0, max=100))


@blp.route("/check", methods=["POST"])
@blp.arguments(GateCheckSchema)
@blp.response(200)
@role_required("CISO", "DevOps")
def gate_check(args):
    """Evaluate now and compare the score to the requested minimum."""
    minimum = args["minimum_score"]
    if minimum is None:
        minimum = current_app.config["GATE_DEFAULT_MIN_SCORE"]
    try:
        result = Scorer(SessionLocal()).evaluate(args["framework"])
    except OPANotAvailableError as exc:
        abort(503, message=str(exc))
    except PolicyEvaluationError as exc:
        abort(500, message=str(exc))
    failing = [c for c in result["controls"] if c["status"] == "FAIL"]
    return {
        "status": "PASS" if result["score"] >= minimum else "FAIL",
        "framework": args["framework"],
        "score": result["score"],
        "minimum_score": minimum,
        "passed": result["passed"],
        "total": result["total"],
        "failing_controls": [
            {"id": c["id"], "title": c["title"], "messages": c["messages"]} for c in failing
        ],
        "evaluated_at": result["evaluated_at"],
    }
