"""Evidence model shared by every collector.

A collector reads one source system (git repository, CI artifacts, SBOM,
scanner reports, access logs) and returns standardized :class:`Evidence`
objects. Collectors never make network calls: they read local files and
local git repositories only, which keeps them deterministic and testable
offline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


class CollectorError(RuntimeError):
    """Raised when an evidence source is missing or malformed."""


def canonical_json(payload: dict) -> str:
    """Deterministic JSON serialization — the input to evidence hashing."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Evidence:
    """One standardized, hashable piece of compliance evidence.

    ``control_ids`` declares which controls (see ``engine.controls``) this
    evidence supports; the policy engine decides whether they pass.
    """

    source: str
    type: str
    control_ids: tuple[str, ...]
    payload: dict
    collected_at: str = field(default_factory=utc_now_iso)

    def digest(self) -> str:
        """SHA-256 over the canonical payload (recomputable for integrity checks)."""
        return hashlib.sha256(canonical_json(self.payload).encode("utf-8")).hexdigest()
