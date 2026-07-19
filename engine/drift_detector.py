"""Detect compliance drift: score regressions against a J-7 baseline.

The baseline is the most recent posture snapshot at least
``DRIFT_BASELINE_DAYS`` (default 7) days old. If the current score has
dropped by more than ``DRIFT_THRESHOLD`` (default 5) points, a
:class:`DriftAlert` is persisted and surfaced through the API.
"""

from __future__ import annotations

import os
from datetime import timedelta

from sqlalchemy import select

from engine.db import DriftAlert, PostureSnapshot, utcnow


class DriftDetector:
    def __init__(self, session, threshold: float | None = None, baseline_days: int | None = None):
        self.session = session
        self.threshold = float(
            threshold if threshold is not None else os.environ.get("DRIFT_THRESHOLD", 5)
        )
        self.baseline_days = int(
            baseline_days if baseline_days is not None else os.environ.get("DRIFT_BASELINE_DAYS", 7)
        )

    def _latest(self, framework: str, before=None) -> PostureSnapshot | None:
        query = (
            select(PostureSnapshot)
            .where(PostureSnapshot.framework == framework)
            .order_by(PostureSnapshot.created_at.desc(), PostureSnapshot.id.desc())
        )
        if before is not None:
            query = query.where(PostureSnapshot.created_at <= before)
        return self.session.scalars(query).first()

    def check(self, framework: str) -> dict:
        current = self._latest(framework)
        if current is None:
            return {"status": "no_data", "framework": framework}

        cutoff = utcnow() - timedelta(days=self.baseline_days)
        baseline = self._latest(framework, before=cutoff)
        if baseline is None:
            return {
                "status": "no_baseline",
                "framework": framework,
                "current_score": current.score,
                "detail": f"no snapshot older than {self.baseline_days} days yet",
            }

        delta = round(current.score - baseline.score, 1)
        report = {
            "framework": framework,
            "current_score": current.score,
            "baseline_score": baseline.score,
            "baseline_date": baseline.created_at.isoformat(timespec="seconds"),
            "delta": delta,
            "threshold": self.threshold,
        }
        if delta < -self.threshold:
            message = (
                f"{framework} posture dropped {abs(delta)} points "
                f"(from {baseline.score} to {current.score}) versus the "
                f"J-{self.baseline_days} baseline"
            )
            self.session.add(
                DriftAlert(
                    framework=framework,
                    baseline_score=baseline.score,
                    current_score=current.score,
                    delta=delta,
                    message=message,
                )
            )
            self.session.commit()
            return {**report, "status": "alert", "message": message}
        return {**report, "status": "ok"}

    def alerts(self, framework: str, limit: int = 10) -> list[dict]:
        rows = self.session.scalars(
            select(DriftAlert)
            .where(DriftAlert.framework == framework)
            .order_by(DriftAlert.created_at.desc(), DriftAlert.id.desc())
            .limit(limit)
        ).all()
        return [
            {
                "message": a.message,
                "delta": a.delta,
                "baseline_score": a.baseline_score,
                "current_score": a.current_score,
                "created_at": a.created_at.isoformat(timespec="seconds"),
            }
            for a in rows
        ]
