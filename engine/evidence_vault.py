"""Append-only evidence store with SHA-256 integrity hashes.

Every piece of evidence is hashed at collection time (over its canonical
JSON payload) and stored with timestamp, source and associated controls.
The vault accepts INSERTs only: the ORM guard in ``engine.db`` and the
PostgreSQL trigger in ``sql/init.sql`` both reject UPDATE and DELETE, so
an auditor can trust that what was collected is what is shown.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import select

from engine.collectors import Evidence, canonical_json
from engine.db import EvidenceRecord


class EvidenceVault:
    def __init__(self, session):
        self.session = session

    def store(self, evidence: Evidence) -> EvidenceRecord:
        record = EvidenceRecord(
            source=evidence.source,
            type=evidence.type,
            control_ids=list(evidence.control_ids),
            payload=evidence.payload,
            sha256=evidence.digest(),
            collected_at=evidence.collected_at,
        )
        self.session.add(record)
        self.session.commit()
        return record

    def store_all(self, evidences: list[Evidence]) -> list[EvidenceRecord]:
        return [self.store(e) for e in evidences]

    def latest_by_type(self) -> dict[str, dict]:
        """Latest payload per evidence type — the policy engine's world view."""
        records = self.session.scalars(
            select(EvidenceRecord).order_by(EvidenceRecord.id.asc())
        ).all()
        latest: dict[str, dict] = {}
        for record in records:
            latest[record.type] = record.payload
        return latest

    def for_control(self, control_id: str) -> list[EvidenceRecord]:
        """All evidence supporting one control, newest first.

        ``control_ids`` is a JSON column whose containment operators differ
        across backends; evidence volumes are small, so filter in Python.
        """
        records = self.session.scalars(
            select(EvidenceRecord).order_by(EvidenceRecord.id.desc())
        ).all()
        return [r for r in records if control_id in (r.control_ids or [])]

    def verify_integrity(self, record: EvidenceRecord) -> bool:
        """Recompute the hash from the stored payload and compare."""
        recomputed = hashlib.sha256(
            canonical_json(record.payload).encode("utf-8")
        ).hexdigest()
        return recomputed == record.sha256

    def count(self) -> int:
        return len(self.session.scalars(select(EvidenceRecord)).all())
