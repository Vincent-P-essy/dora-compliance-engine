"""Audit report generation: HTML via Jinja2, then PDF via WeasyPrint.

WeasyPrint needs system libraries (Pango/Cairo); they ship in the Docker
image. The import happens lazily inside :func:`html_to_pdf` so every other
part of the app — including HTML rendering — works without them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

import engine
from engine.drift_detector import DriftDetector
from engine.evidence_vault import EvidenceVault
from engine.scorer import Scorer

TEMPLATES_DIR = Path(__file__).parent / "templates"

FRAMEWORK_LABELS = {
    "dora": "DORA — Regulation (EU) 2022/2554",
    "iso27001": "ISO/IEC 27001:2022",
}


class PDFDependencyError(RuntimeError):
    """WeasyPrint or its native libraries are unavailable."""


def build_report_context(session, framework: str) -> dict:
    scorer = Scorer(session)
    result = scorer.evaluate(framework)
    drift = DriftDetector(session).check(framework)
    vault = EvidenceVault(session)
    evidence_by_control = {
        control["id"]: [
            {
                "sha256": record.sha256,
                "source": record.source,
                "type": record.type,
                "collected_at": record.collected_at,
            }
            for record in vault.for_control(control["id"])[:3]
        ]
        for control in result["controls"]
    }
    return {
        "framework": framework,
        "framework_label": FRAMEWORK_LABELS[framework],
        "result": result,
        "drift": drift,
        "evidence_by_control": evidence_by_control,
        "history": scorer.history(framework, limit=10),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "engine_version": engine.__version__,
    }


def render_html(context: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html"]),
    )
    return env.get_template("dora_report.html").render(**context)


def html_to_pdf(html: str) -> bytes:
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:
        raise PDFDependencyError(
            "WeasyPrint or its system libraries (Pango/Cairo) are not installed — "
            "PDF export is unavailable here; the Docker image bundles them"
        ) from exc
    return HTML(string=html).write_pdf()


def generate_report(session, framework: str) -> bytes:
    """Evaluate, render and export the full audit report as PDF bytes."""
    return html_to_pdf(render_html(build_report_context(session, framework)))
