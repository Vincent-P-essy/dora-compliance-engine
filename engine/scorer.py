"""Aggregate policy evaluations into a 0-100 posture score per framework.

Score = passed controls / total controls x 100. Every evaluation persists a
:class:`PostureSnapshot`, building the history the drift detector reads.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select

from engine.controls import controls_for
from engine.db import PostureSnapshot
from engine.evidence_vault import EvidenceVault
from engine.policy_engine import PolicyEngine


class Scorer:
    def __init__(self, session, policy_engine: PolicyEngine | None = None):
        self.session = session
        self.policy_engine = policy_engine or PolicyEngine()

    def evaluate(self, framework: str) -> dict:
        """Collect the vault's world view, run OPA, score, and snapshot."""
        controls = controls_for(framework)
        vault = EvidenceVault(self.session)
        input_doc = self.policy_engine.build_input(vault.latest_by_type())
        violations = self.policy_engine.violations_by_package(input_doc)

        messages_by_control: dict[str, list[str]] = defaultdict(list)
        for package_violations in violations.values():
            for violation in package_violations:
                messages_by_control[violation["control"]].append(violation["msg"])

        control_results = []
        passed = 0
        for control_id, meta in sorted(controls.items()):
            messages = messages_by_control.get(control_id, [])
            if not messages:
                passed += 1
            control_results.append(
                {
                    "id": control_id,
                    "status": "PASS" if not messages else "FAIL",
                    "ref": meta["ref"],
                    "title": meta["title"],
                    "messages": messages,
                }
            )

        total = len(controls)
        score = round(passed / total * 100, 1) if total else 0.0
        result = {
            "framework": framework,
            "score": score,
            "passed": passed,
            "failed": total - passed,
            "total": total,
            "controls": control_results,
            "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

        self.session.add(
            PostureSnapshot(
                framework=framework,
                score=score,
                passed=passed,
                total=total,
                results=result,
            )
        )
        self.session.commit()
        return result

    def latest_snapshot(self, framework: str) -> PostureSnapshot | None:
        return self.session.scalars(
            select(PostureSnapshot)
            .where(PostureSnapshot.framework == framework)
            .order_by(PostureSnapshot.created_at.desc(), PostureSnapshot.id.desc())
        ).first()

    def history(self, framework: str, limit: int = 20) -> list[dict]:
        snapshots = self.session.scalars(
            select(PostureSnapshot)
            .where(PostureSnapshot.framework == framework)
            .order_by(PostureSnapshot.created_at.desc(), PostureSnapshot.id.desc())
            .limit(limit)
        ).all()
        return [
            {
                "score": s.score,
                "passed": s.passed,
                "total": s.total,
                "created_at": s.created_at.isoformat(timespec="seconds"),
            }
            for s in snapshots
        ]
