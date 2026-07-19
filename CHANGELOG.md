# Changelog

All notable changes to this project are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/) — versioning: [SemVer](https://semver.org/).

## [v1.0.0] — 2026-07-19

### Added
- Five evidence collectors: git history, CI results, CycloneDX SBOM, vulnerability scans (Trivy / pip-audit), secret-access logs.
- OPA/Rego policy bundle: DORA Articles 9, 11, 25 and ISO/IEC 27001 A.5, A.12 (11 automated controls).
- Append-only Evidence Vault with SHA-256 hashing, enforced at ORM level and by a PostgreSQL trigger.
- Compliance scorer with per-framework posture snapshots and history.
- Drift detector (baseline J-7, alert on regression > 5 points).
- REST API (Flask + flask-smorest): posture, evidence, CI/CD gate, PDF reports, JWT auth with CISO / DevOps / Auditor roles.
- PDF audit report generator (WeasyPrint).
- Reusable GitHub Action gate (`ci-integration/github-action`).
- Docker Compose stack (API + PostgreSQL) and CI pipeline.
