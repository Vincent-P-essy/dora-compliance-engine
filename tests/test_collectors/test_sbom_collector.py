import pytest

from engine.collectors import CollectorError
from engine.collectors.sbom_collector import SBOMCollector
from tests.conftest import FIXTURES


def test_parses_cyclonedx_sbom():
    evidence = SBOMCollector(FIXTURES / "sbom.cyclonedx.json").collect_sbom()
    assert evidence.type == "sbom.cyclonedx"
    assert evidence.control_ids == ("DORA-09-SBOM",)
    assert evidence.payload["components"] == 3
    assert evidence.payload["without_license"] == 1
    assert evidence.payload["licenses"] == ["Apache-2.0", "BSD-3-Clause"]
    assert evidence.payload["spec_version"] == "1.5"


def test_rejects_non_cyclonedx(tmp_path):
    bad = tmp_path / "sbom.json"
    bad.write_text('{"bomFormat": "SPDX"}', encoding="utf-8")
    with pytest.raises(CollectorError, match="CycloneDX"):
        SBOMCollector(bad).collect_sbom()


def test_missing_file_raises(tmp_path):
    with pytest.raises(CollectorError, match="not found"):
        SBOMCollector(tmp_path / "absent.json").collect()
