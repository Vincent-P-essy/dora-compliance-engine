# dora-compliance-engine

**Continuous regulatory-compliance automation for financial information systems.**
Collects technical audit evidence from a CI/CD pipeline, maps it to **DORA** and
**ISO/IEC 27001** controls with declarative **OPA/Rego** policies, computes a 0-100
posture score, and produces auditor-ready PDF reports — every day, not once a year.

![DORA posture](https://img.shields.io/badge/DORA%20posture-100%2F100-brightgreen)
![ISO 27001 posture](https://img.shields.io/badge/ISO%2027001%20posture-75%2F100-yellow)
[![ci](https://github.com/Vincent-P-essy/dora-compliance-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Vincent-P-essy/dora-compliance-engine/actions/workflows/ci.yml)
![tests](https://img.shields.io/badge/tests-97%20python%20%2B%2027%20rego-brightgreen)
![coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)
![python](https://img.shields.io/badge/python-3.12-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## The problem

A DORA or ISO 27001 audit of a financial entity consumes **200-400 hours** of manual
work per cycle: engineers screenshot CI dashboards, export backup logs, paste coverage
numbers into spreadsheets, and hope nothing drifted between the evidence date and the
audit date. The evidence is stale the day it is collected, impossible to verify after
the fact, and collected again from scratch next year.

DORA (Regulation EU 2022/2554, applicable since **17 January 2025**) makes this worse
on purpose: it demands *continuous* ICT risk management, not an annual snapshot.

## The solution

Treat compliance like infrastructure — **as code, tested, versioned, continuous**:

1. **Collectors** pull technical facts from the systems that already have them
   (git history, CI artifacts, SBOMs, vulnerability scans, secret-manager audit logs).
2. Every fact becomes **hashed, immutable evidence** in an append-only vault.
3. **OPA/Rego policies** — plain-text, reviewable, unit-tested — decide whether each
   regulatory control passes.
4. A **scorer** turns policy results into a 0-100 posture per framework, snapshotted
   for history; a **drift detector** alerts when posture regresses.
5. A **CI/CD gate** blocks deployments when posture falls below your floor, and a
   **PDF generator** produces the report your auditor actually asked for.

## Supported frameworks

| Framework | Scope automated | Controls | Example rule |
|-----------|----------------|----------|--------------|
| **DORA** (EU 2022/2554) | Articles 9, 11, 25 (pilot scope of the regulation) | 7 | Verified backup < 24h old (Art. 11) |
| **ISO/IEC 27001:2022** | Annex A.5, A.12 | 4 | Zero secrets in commit history (A.12) |

Every control is **fail-closed**: missing evidence is a violation, because "we did not
measure" is not a passing state an auditor will accept.

## Architecture

```
   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
   │   git    │ │ CI runs  │ │  SBOM    │ │  scans   │ │ access   │
   │ history  │ │ (JUnit/  │ │(CycloneDX│ │ (Trivy/  │ │  logs    │
   │          │ │ coverage)│ │  JSON)   │ │pip-audit)│ │ (JSONL)  │
   └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
        │            │            │            │            │
        ▼            ▼            ▼            ▼            ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                     COLLECTORS  (engine/collectors)         │
   │        standardized Evidence objects, SHA-256 at birth      │
   └──────────────────────────────┬──────────────────────────────┘
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │              EVIDENCE VAULT  (PostgreSQL, append-only)      │
   │       INSERT only — UPDATE/DELETE rejected by ORM + trigger │
   └──────────────────────────────┬──────────────────────────────┘
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                 POLICY ENGINE  (OPA / Rego)                 │
   │   dora/article_09  article_11  article_25   iso27001/a5 a12 │
   └──────────────────────────────┬──────────────────────────────┘
                                  ▼
   ┌───────────────┐   ┌──────────────────┐   ┌──────────────────┐
   │    SCORER     │──▶│  DRIFT DETECTOR  │   │   REST API (JWT) │
   │ passed/total  │   │ J-7 baseline,    │   │ posture/evidence │
   │ ×100, history │   │ alert if -5 pts  │   │ gate/reports/pdf │
   └───────────────┘   └──────────────────┘   └──────────────────┘
                                  │
                     ┌────────────┴─────────────┐
                     ▼                          ▼
            ┌────────────────┐        ┌──────────────────┐
            │ GitHub Action  │        │   PDF report     │
            │ gate: PASS/FAIL│        │   (WeasyPrint)   │
            └────────────────┘        └──────────────────┘
```

## Quick start (Docker)

```bash
git clone https://github.com/Vincent-P-essy/dora-compliance-engine
cd dora-compliance-engine
cp .env.example .env          # then edit the secrets
docker compose up -d --build  # starts PostgreSQL + API on :8000

# Load demo users + a realistic evidence set, evaluate both frameworks:
docker compose exec api flask seed-demo

# Get a token (roles: ciso / devops / auditor):
TOKEN=$(curl -s -X POST localhost:8000/api/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username": "ciso", "password": "ciso-demo-password"}' | jq -r .access_token)

# Read your DORA posture:
curl -s localhost:8000/api/posture/dora -H "Authorization: Bearer $TOKEN" | jq .score

# Download the audit report:
curl -s "localhost:8000/api/reports/pdf?framework=dora" \
  -H "Authorization: Bearer $TOKEN" -o dora-report.pdf
```

Interactive OpenAPI docs: `http://localhost:8000/api/docs/swagger`.

## API

| Endpoint | Method | Roles | Purpose |
|----------|--------|-------|---------|
| `/api/auth/token` | POST | public | Exchange credentials for a JWT |
| `/api/posture/{framework}` | GET | all roles | Score + per-control detail + drift + history |
| `/api/evidence/{control_id}` | GET | CISO, Auditor | Immutable evidence behind a control, hashes re-verified live |
| `/api/gate/check` | POST | CISO, DevOps | CI/CD hook — returns PASS/FAIL |
| `/api/reports/pdf` | GET | CISO, Auditor | Full audit report (PDF) |
| `/api/health` | GET | public | Liveness + DB + OPA status |

## A policy, annotated

Policies are the heart of the engine — plain Rego, reviewable in a PR like any code
(`engine/policies/dora/article_11_continuity.rego`):

```rego
package dora.article_11

# `input.now` is injected by the engine, so rules stay deterministic
# and unit-testable (27 native Rego tests run in CI via `opa test`).
hours_since(ts) := (time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns(ts)) / 3600000000000

# DORA Art. 11: a verified backup must exist, and be younger than 24h.
violations contains v if {
	hours_since(input.evidence.backup.last_success) > 24
	v := {
		"control": "DORA-11-BACKUP",
		"msg": sprintf(
			"Last successful backup is %v hours old — DORA Art. 11 requires a verified backup every 24h",
			[round(hours_since(input.evidence.backup.last_success))],
		),
	}
}

# Fail-closed: no backup evidence at all is itself a violation.
violations contains v if {
	not input.evidence.backup
	v := {"control": "DORA-11-BACKUP", "msg": "No backup evidence collected — continuity posture is unknown"}
}
```

Structured `violations` feed the scorer; a parallel `deny` set exposes plain
messages for the CI gate.

## CI/CD gate in 3 lines

```yaml
- uses: Vincent-P-essy/dora-compliance-engine/ci-integration/github-action@v1
  with: { api_url: "${{ vars.COMPLIANCE_API }}", api_token: "${{ secrets.COMPLIANCE_TOKEN }}",
          framework: dora, minimum_score: 75, block_on_fail: true }
```

The action calls `POST /api/gate/check`, writes a verdict table (with every failing
control) to the job summary, and fails the job when posture is below the floor.

## Evidence Vault: evidence you can trust

Auditors do not just want evidence — they want evidence **that could not have been
edited after the fact**:

- Every payload is hashed **SHA-256 over canonical JSON at collection time**.
- The vault is **append-only, enforced twice**: an ORM guard raises on any
  UPDATE/DELETE of an evidence row, and a PostgreSQL trigger rejects the same at the
  database level — a direct SQL session cannot rewrite history either.
- `GET /api/evidence/{control_id}` **re-computes every hash on read** and flags any
  mismatch as `TAMPERED`.
- The PDF report ships the hash appendix, so a printed report can be cross-checked
  against the live vault months later.

## Tests

```bash
pip install -r requirements.txt
pytest                                            # 97 tests, coverage gate at 90% (currently 96%)
opa test engine/policies tests/test_policies/rego # 27 native Rego unit tests
```

- Collectors are tested against **fixture files and throwaway git repositories** — no
  network, ever.
- Policies are tested twice: natively with `opa test`, and end-to-end through the
  Python engine (`opa eval` subprocess).
- API endpoints are tested with the Flask test client, including role-matrix (401/403),
  validation (422) and degraded modes (OPA absent → 503, WeasyPrint absent → 501).

## Roadmap

- **NIS2 & CRA policy packs** — same evidence, more frameworks.
- **Terraform/cloud collector** — infrastructure posture (encryption, network policy).
- **Webhook alerting** — drift alerts pushed to Slack/Teams instead of polled.
- **Evidence signing** — Ed25519 signatures on top of hashes for third-party attestation.
- **Multi-entity mode** — one engine, several scoped information systems.

## License

MIT — see [LICENSE](LICENSE).
