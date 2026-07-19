"""Collect evidence from a CycloneDX JSON SBOM (software bill of materials).

The SBOM is the ICT asset inventory for the software layer: DORA Art. 9
requires firms to know what runs in production before they can manage its
risk. Produces ``sbom.cyclonedx`` evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import CollectorError, Evidence


class SBOMCollector:
    def __init__(self, sbom_path: str | Path):
        self.sbom_path = Path(sbom_path)

    def collect_sbom(self) -> Evidence:
        if not self.sbom_path.exists():
            raise CollectorError(f"SBOM not found: {self.sbom_path}")
        try:
            bom = json.loads(self.sbom_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CollectorError(f"invalid JSON in {self.sbom_path}: {exc}") from exc
        if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
            raise CollectorError(f"not a CycloneDX SBOM: {self.sbom_path}")

        components = bom.get("components", [])
        licenses: set[str] = set()
        without_license = 0
        for comp in components:
            comp_licenses = comp.get("licenses") or []
            if not comp_licenses:
                without_license += 1
            for entry in comp_licenses:
                lic = entry.get("license", {})
                name = lic.get("id") or lic.get("name")
                if name:
                    licenses.add(name)

        payload = {
            "format": "CycloneDX",
            "spec_version": bom.get("specVersion"),
            "serial_number": bom.get("serialNumber"),
            "generated_at": (bom.get("metadata") or {}).get("timestamp"),
            "components": len(components),
            "without_license": without_license,
            "licenses": sorted(licenses),
        }
        return Evidence("sbom", "sbom.cyclonedx", ("DORA-09-SBOM",), payload)

    def collect(self) -> list[Evidence]:
        return [self.collect_sbom()]
