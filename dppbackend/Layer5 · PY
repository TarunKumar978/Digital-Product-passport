"""
Layer 5 — Circularity & Recyclability
Data points per DPP doc:
  - Material composition breakdown to assist recyclers
  - Disassembly instructions (button/zipper separation guides)
  - End-of-life options for circular recycling
"""

from flask import Blueprint, request, g

from app.db import fetch_one, execute
from app.utils.auth import require_auth
from app.utils.blockchain import append_chain_entry
from app.utils.helpers import ok, created, bad_request, not_found, require_fields, serialise

layer5_bp = Blueprint("layer5", __name__, url_prefix="/api/products/<int:pid>/circularity")


def _check_product(pid):
    return fetch_one("SELECT id FROM products WHERE id = %s AND is_active = 1", (pid,))


@layer5_bp.route("", methods=["GET"])
def get_circularity(pid):
    """Get circularity and recyclability data."""
    if not _check_product(pid):
        return not_found("Product")

    circ = fetch_one("SELECT * FROM circularity WHERE product_id = %s", (pid,))
    if not circ:
        return not_found("Circularity data")
    return ok(serialise(circ))


@layer5_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def set_circularity(pid):
    """
    Create or update circularity data (upsert).
    Body: {
        disassembly_instructions*,  step-by-step disassembly guide
        component_breakdown?,       JSON list of components e.g. [{"name":"button","material":"corozo","recyclable":true}]
        recyclability_score?,       0–100
        end_of_life_options?,       e.g. "compost, textile recycling, resale"
        recycler_notes?,
        takeback_program_url?,      brand's take-back/circular program link
    }
    """
    if not _check_product(pid):
        return not_found("Product")

    data = request.get_json(silent=True) or {}
    missing = require_fields(data, ("disassembly_instructions",))
    if missing:
        return bad_request(f"'{missing}' is required")

    score = data.get("recyclability_score")
    if score is not None and not (0 <= int(score) <= 100):
        return bad_request("recyclability_score must be 0–100")

    import json as _json
    component_json = None
    if data.get("component_breakdown"):
        try:
            component_json = _json.dumps(data["component_breakdown"])
        except (TypeError, ValueError):
            return bad_request("component_breakdown must be a valid JSON array")

    existing = fetch_one("SELECT id FROM circularity WHERE product_id = %s", (pid,))

    if existing:
        execute(
            """UPDATE circularity SET
                   disassembly_instructions = %s,
                   component_breakdown      = %s,
                   recyclability_score      = %s,
                   end_of_life_options      = %s,
                   recycler_notes           = %s,
                   takeback_program_url     = %s
               WHERE product_id = %s""",
            (
                data["disassembly_instructions"],
                component_json,
                score,
                data.get("end_of_life_options"),
                data.get("recycler_notes"),
                data.get("takeback_program_url"),
                pid,
            )
        )
        msg = "Circularity data updated"
    else:
        execute(
            """INSERT INTO circularity
                   (product_id, disassembly_instructions, component_breakdown,
                    recyclability_score, end_of_life_options, recycler_notes, takeback_program_url)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (
                pid,
                data["disassembly_instructions"],
                component_json,
                score,
                data.get("end_of_life_options"),
                data.get("recycler_notes"),
                data.get("takeback_program_url"),
            )
        )
        msg = "Circularity data created"

    append_chain_entry(
        pid, "UPDATE",
        {"layer": "5_circularity", "recyclability_score": score},
        recorded_by=str(g.current_user["sub"])
    )

    return created({"message": msg})