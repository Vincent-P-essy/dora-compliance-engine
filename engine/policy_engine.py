"""OPA runner: evaluates the Rego policy bundle against collected evidence.

The engine shells out to the ``opa`` binary (bundled in the Docker image,
``OPA_PATH`` or ``$PATH`` elsewhere) — evaluation is fully local, no OPA
server needed. Policies receive one input document::

    {"evidence": {"coverage": {...}, "backup": {...}, ...},
     "now": "2026-07-19T12:00:00+00:00"}

and answer with ``violations`` (structured, consumed by the scorer) and
``deny`` (human-readable messages, consumed by the CI gate).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Maps vault evidence types to the short keys policies read under input.evidence.
EVIDENCE_INPUT_KEYS = {
    "ci.coverage": "coverage",
    "ci.tests": "tests",
    "ci.backup": "backup",
    "ci.resilience": "resilience",
    "git.commits": "commits",
    "git.secret_scan": "secret_scan",
    "git.changelog": "changelog",
    "sbom.cyclonedx": "sbom",
    "scan.vulnerabilities": "vulnerabilities",
    "access.secrets_log": "secrets_log",
}

DEFAULT_POLICIES_DIR = Path(__file__).parent / "policies"


class OPANotAvailableError(RuntimeError):
    """The opa binary could not be found or executed."""


class PolicyEvaluationError(RuntimeError):
    """OPA ran but evaluation failed (syntax error, bad input, ...)."""


def find_opa() -> str | None:
    """Locate the OPA binary: $OPA_PATH first, then $PATH."""
    configured = os.environ.get("OPA_PATH", "").strip()
    if configured:
        return configured if Path(configured).exists() else None
    return shutil.which("opa")


class PolicyEngine:
    def __init__(self, policies_dir: str | Path | None = None, opa_path: str | None = None):
        self.policies_dir = Path(policies_dir or os.environ.get("POLICIES_DIR") or DEFAULT_POLICIES_DIR)
        self.opa_path = opa_path or find_opa()

    def build_input(self, latest_evidence: dict[str, dict]) -> dict:
        """Shape vault contents (evidence-type -> payload) into the OPA input doc."""
        evidence = {}
        for evidence_type, payload in latest_evidence.items():
            key = EVIDENCE_INPUT_KEYS.get(evidence_type)
            if key:
                evidence[key] = payload
        return {
            "evidence": evidence,
            "now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def evaluate(self, input_doc: dict) -> dict:
        """Run `opa eval` over the policy bundle. Returns the full `data` tree,
        e.g. result["dora"]["article_09"]["violations"]."""
        if not self.opa_path:
            raise OPANotAvailableError(
                "opa binary not found — set OPA_PATH or install it on PATH "
                "(https://www.openpolicyagent.org/docs/#running-opa)"
            )
        cmd = [
            self.opa_path,
            "eval",
            "--format", "json",
            "--stdin-input",
            "--data", str(self.policies_dir),
            "data",
        ]
        try:
            proc = subprocess.run(
                cmd, input=json.dumps(input_doc), capture_output=True, text=True, timeout=60
            )
        except FileNotFoundError as exc:
            raise OPANotAvailableError(f"cannot execute opa at '{self.opa_path}'") from exc
        if proc.returncode != 0:
            raise PolicyEvaluationError(f"opa eval failed: {proc.stderr.strip()[:500]}")
        try:
            result = json.loads(proc.stdout)
            return result["result"][0]["expressions"][0]["value"]
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            raise PolicyEvaluationError(f"unexpected opa output: {proc.stdout[:200]}") from exc

    def violations_by_package(self, input_doc: dict) -> dict[str, list[dict]]:
        """Evaluate and flatten to {package -> [violation, ...]}."""
        data = self.evaluate(input_doc)
        flattened: dict[str, list[dict]] = {}
        for framework, articles in data.items():
            if not isinstance(articles, dict):
                continue
            for article, rules in articles.items():
                if isinstance(rules, dict) and "violations" in rules:
                    flattened[f"{framework}.{article}"] = list(rules["violations"])
        return flattened
