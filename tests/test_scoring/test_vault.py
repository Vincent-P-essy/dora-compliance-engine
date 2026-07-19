import pytest

from engine.collectors import Evidence, canonical_json
from engine.db import EvidenceRecord, ImmutableEvidenceError
from engine.evidence_vault import EvidenceVault


def make_evidence(payload=None):
    return Evidence("ci", "ci.coverage", ("DORA-09-COV",), payload or {"percent": 91.0})


def test_store_hashes_payload_sha256(session):
    vault = EvidenceVault(session)
    evidence = make_evidence()
    record = vault.store(evidence)
    assert record.sha256 == evidence.digest()
    assert len(record.sha256) == 64
    assert vault.verify_integrity(record)


def test_latest_by_type_returns_newest_payload(session):
    vault = EvidenceVault(session)
    vault.store(make_evidence({"percent": 80.0}))
    vault.store(make_evidence({"percent": 91.5}))
    assert vault.latest_by_type()["ci.coverage"]["percent"] == 91.5


def test_for_control_newest_first(session):
    vault = EvidenceVault(session)
    vault.store(make_evidence({"percent": 80.0}))
    vault.store(make_evidence({"percent": 91.5}))
    records = vault.for_control("DORA-09-COV")
    assert len(records) == 2
    assert records[0].payload["percent"] == 91.5
    assert vault.for_control("ISO-A12-SECRETS") == []


def test_update_is_rejected(session):
    record = EvidenceVault(session).store(make_evidence())
    record.source = "tampered"
    with pytest.raises(ImmutableEvidenceError, match="UPDATE"):
        session.commit()
    session.rollback()


def test_delete_is_rejected(session):
    record = EvidenceVault(session).store(make_evidence())
    session.delete(record)
    with pytest.raises(ImmutableEvidenceError, match="DELETE"):
        session.commit()
    session.rollback()


def test_wrong_hash_fails_integrity_check(session):
    record = EvidenceRecord(
        source="ci",
        type="ci.coverage",
        control_ids=["DORA-09-COV"],
        payload={"percent": 10.0},
        sha256="0" * 64,
        collected_at="2026-07-19T00:00:00+00:00",
    )
    assert EvidenceVault(session).verify_integrity(record) is False


def test_canonical_json_is_key_sorted_and_compact():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_count(session):
    vault = EvidenceVault(session)
    assert vault.count() == 0
    vault.store(make_evidence())
    assert vault.count() == 1
