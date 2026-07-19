import pytest

from engine.demo import build_demo_evidence
from engine.evidence_vault import EvidenceVault
from reporter.pdf_generator import PDFDependencyError, build_report_context, render_html


def weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except (ImportError, OSError):
        return False


def test_requires_auth(client):
    assert client.get("/api/reports/pdf").status_code == 401


def test_devops_cannot_download_reports(client, auth_header):
    assert client.get("/api/reports/pdf", headers=auth_header("devops")).status_code == 403


def test_html_render_contains_scores_and_hashes(session, fake_engine):
    EvidenceVault(session).store_all(build_demo_evidence())
    context = build_report_context(session, "dora")
    html = render_html(context)
    assert "Compliance Posture Report" in html
    assert "DORA-11-BACKUP" in html
    assert context["result"]["score"] == 100.0
    backup_hash = context["evidence_by_control"]["DORA-11-BACKUP"][0]["sha256"]
    assert backup_hash in html  # the evidence appendix carries real hashes


def test_pdf_route_streams_a_pdf_attachment(client, auth_header, monkeypatch):
    monkeypatch.setattr(
        "api.routes.reports.generate_report", lambda session, framework: b"%PDF-1.7 fake"
    )
    response = client.get("/api/reports/pdf?framework=dora", headers=auth_header("ciso"))
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")
    assert "dora-compliance-report.pdf" in response.headers["Content-Disposition"]


def test_501_when_weasyprint_is_missing(client, auth_header, monkeypatch):
    def boom(session, framework):
        raise PDFDependencyError("weasyprint unavailable")

    monkeypatch.setattr("api.routes.reports.generate_report", boom)
    assert client.get("/api/reports/pdf", headers=auth_header("auditor")).status_code == 501


def test_503_when_opa_is_missing(client, auth_header, monkeypatch):
    from engine.policy_engine import OPANotAvailableError

    def boom(session, framework):
        raise OPANotAvailableError("opa binary not found")

    monkeypatch.setattr("api.routes.reports.generate_report", boom)
    assert client.get("/api/reports/pdf", headers=auth_header("ciso")).status_code == 503


def test_500_on_policy_evaluation_error(client, auth_header, monkeypatch):
    from engine.policy_engine import PolicyEvaluationError

    def boom(session, framework):
        raise PolicyEvaluationError("opa eval failed")

    monkeypatch.setattr("api.routes.reports.generate_report", boom)
    assert client.get("/api/reports/pdf", headers=auth_header("ciso")).status_code == 500


@pytest.mark.skipif(not weasyprint_available(), reason="WeasyPrint system libs missing")
def test_real_pdf_generation_end_to_end(client, auth_header, session, fake_engine):
    EvidenceVault(session).store_all(build_demo_evidence())
    response = client.get(
        "/api/reports/pdf?framework=iso27001", headers=auth_header("ciso")
    )
    assert response.status_code == 200
    assert response.data[:5] == b"%PDF-"
    assert len(response.data) > 5000  # a real multi-section document, not a stub
