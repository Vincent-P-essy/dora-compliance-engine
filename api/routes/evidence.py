"""Evidence access: GET /api/evidence/<control_id>.

Returns every vault record supporting a control, newest first, with its
SHA-256 hash and a live integrity re-verification.
"""

from __future__ import annotations

from flask_smorest import Blueprint, abort

from api.routes import role_required
from engine.controls import CONTROLS
from engine.db import SessionLocal
from engine.evidence_vault import EvidenceVault

blp = Blueprint("evidence", __name__, url_prefix="/api/evidence", description="Evidence vault")


@blp.route("/<control_id>")
@blp.response(200)
@role_required("CISO", "Auditor")
def get_evidence(control_id: str):
    """List the immutable evidence records behind one control."""
    meta = CONTROLS.get(control_id)
    if meta is None:
        abort(404, message=f"Unknown control '{control_id}'")
    vault = EvidenceVault(SessionLocal())
    records = vault.for_control(control_id)
    return {
        "control": {
            "id": control_id,
            "framework": meta["framework"],
            "ref": meta["ref"],
            "title": meta["title"],
            "description": meta["description"],
        },
        "evidence_count": len(records),
        "evidence": [
            {
                "sha256": record.sha256,
                "integrity": "verified" if vault.verify_integrity(record) else "TAMPERED",
                "source": record.source,
                "type": record.type,
                "collected_at": record.collected_at,
                "stored_at": record.stored_at.isoformat(timespec="seconds"),
                "payload": record.payload,
            }
            for record in records
        ],
    }
