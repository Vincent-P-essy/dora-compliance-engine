"""Audit reports: GET /api/reports/pdf?framework=dora -> PDF download."""

from __future__ import annotations

from flask import Response
from flask_smorest import Blueprint, abort
from marshmallow import Schema, fields, validate

from api.routes import role_required
from engine.controls import FRAMEWORKS
from engine.db import SessionLocal
from engine.policy_engine import OPANotAvailableError, PolicyEvaluationError
from reporter.pdf_generator import PDFDependencyError, generate_report

blp = Blueprint("reports", __name__, url_prefix="/api/reports", description="Audit reports")


class ReportQuerySchema(Schema):
    framework = fields.String(load_default="dora", validate=validate.OneOf(FRAMEWORKS))


@blp.route("/pdf")
@blp.arguments(ReportQuerySchema, location="query")
@role_required("CISO", "Auditor")
def get_pdf_report(args):
    """Generate the full audit report (posture, controls, evidence hashes, drift)."""
    framework = args["framework"]
    try:
        pdf_bytes = generate_report(SessionLocal(), framework)
    except OPANotAvailableError as exc:
        abort(503, message=str(exc))
    except PolicyEvaluationError as exc:
        abort(500, message=str(exc))
    except PDFDependencyError as exc:
        abort(501, message=str(exc))
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{framework}-compliance-report.pdf"'
        },
    )
