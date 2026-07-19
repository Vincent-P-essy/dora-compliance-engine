"""Collect evidence from secret-access logs (JSONL, simulated source).

In production this would tail a vault/secret-manager audit stream; here the
source is a JSONL export so the pipeline stays reproducible. Each line:

    {"ts": "2026-07-18T09:12:00+00:00", "principal": "ci-bot",
     "secret": "db-password", "action": "read", "authorized": true}

Produces ``access.secrets_log`` evidence (ISO 27001 A.12 operations security).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import CollectorError, Evidence

# Accesses outside 07:00–22:00 UTC are flagged as off-hours (worth review,
# not automatically a violation).
_BUSINESS_START, _BUSINESS_END = 7, 22


class AccessLogCollector:
    def __init__(self, log_path: str | Path, window_days: int = 7):
        self.log_path = Path(log_path)
        self.window_days = window_days

    def collect_access_log(self) -> Evidence:
        if not self.log_path.exists():
            raise CollectorError(f"access log not found: {self.log_path}")
        events = []
        for lineno, line in enumerate(self.log_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CollectorError(f"invalid JSONL at {self.log_path}:{lineno}: {exc}") from exc
            for key in ("ts", "principal", "secret", "action", "authorized"):
                if key not in event:
                    raise CollectorError(f"missing key '{key}' at {self.log_path}:{lineno}")
            events.append(event)
        if not events:
            raise CollectorError(f"access log is empty: {self.log_path}")

        off_hours = 0
        for event in events:
            try:
                hour = datetime.fromisoformat(event["ts"]).hour
            except ValueError as exc:
                raise CollectorError(f"invalid timestamp '{event['ts']}' in {self.log_path}") from exc
            if hour < _BUSINESS_START or hour >= _BUSINESS_END:
                off_hours += 1

        payload = {
            "events": len(events),
            "unauthorized": sum(1 for e in events if not e["authorized"]),
            "off_hours": off_hours,
            "principals": sorted({e["principal"] for e in events}),
            "window_days": self.window_days,
        }
        return Evidence("secrets-audit", "access.secrets_log", ("ISO-A12-ACCESS",), payload)

    def collect(self) -> list[Evidence]:
        return [self.collect_access_log()]
