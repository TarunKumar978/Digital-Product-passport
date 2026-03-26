"""
Layer 2 — Origin & Raw Material Traceability
Data points per DPP doc:
  - Fiber Origin (Rain-fed Organic Cotton from Maharashtra)
  - Spinning Mill location
  - GOTS Transaction Certificates (digital upload URL)
  - RSL (Restricted Substances List) compliance
"""

from flask import Blueprint, request, g

from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.blockchain import append_chain_entry
from app.utils.helpers import ok, created, bad_request, not_found, require_fields, serialise

layer2_bp = Blueprint("layer2", __name__, url_prefix="/api/products/<int:pid>/materials")


def _check_product(pid):
    return fetch_one("SELECT id FROM products WHERE id = %s AND is_active = 1", (pid,))


@layer2_bp.route("", methods=["GET"])
def get_materials(pid):
    """Get all raw materials for a product."""
    if not _check_product(pid):
        return not_found("Product")

    materials = fetch_all("SELECT * FROM product_materials WHERE product_id = %s ORDER BY id", (pid,))
    return ok({"product_id": pid, "materials": serialise(list(materials))})


@layer2_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def add_material(pid):
    """
    Add a raw material entry for a product.
    Body: {
        fiber_type*,           e.g. "Organic Cotton"
        fiber_origin*,         e.g. "Rain-fed Organic Cotton, Maharashtra"
        farm_name?,
        farm_latitude?,
        farm_longitude?,
        spinning_mill?,
        gots_cert_url?,        GOTS Transaction Certificate upload URL
        gots_cert_number?,
        rsl_compliant?,        boolean, default true
        rsl_test_report_url?,
        percentage*,           composition % e.g. 95
        notes?
    }
    """
    if not _check_product(pid):
        return not_found("Product")

    data = request.get_json(silent=True) or {}
    missing = require_fields(data, ("fiber_type", "fiber_origin", "percentage"))
    if missing:
        return bad_request(f"'{missing}' is required")

    pct = float(data["percentage"])
    if not (0 < pct <= 100):
        return bad_request("percentage must be between 0 and 100")

    # Check total composition doesn't exceed 100%
    existing_total = fetch_one(
        "SELECT COALESCE(SUM(percentage), 0) AS total FROM product_materials WHERE product_id = %s",
        (pid,)
    )["total"] or 0
    if float(existing_total) + float(pct) > 100:
        return bad_request(
            f"Total composition would exceed 100%. Already allocated: {existing_total}%"
        )

    mid = execute(
        """INSERT INTO product_materials
               (product_id, fiber_type, fiber_origin, farm_name,
                farm_latitude, farm_longitude, spinning_mill,
                gots_cert_url, gots_cert_number, rsl_compliant,
                rsl_test_report_url, percentage, notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            pid,
            data["fiber_type"], data["fiber_origin"],
            data.get("farm_name"),
            data.get("farm_latitude"), data.get("farm_longitude"),
            data.get("spinning_mill"),
            data.get("gots_cert_url"), data.get("gots_cert_number"),
            int(data.get("rsl_compliant", 1)),
            data.get("rsl_test_report_url"),
            pct,
            data.get("notes"),
        )
    )

    append_chain_entry(
        pid, "UPDATE",
        {"layer": "2_product_materials", "material_id": mid, "fiber_type": data["fiber_type"]},
        recorded_by=str(g.current_user["sub"])
    )

    return created({"message": "Raw material added", "material_id": mid})


@layer2_bp.route("/<int:mid>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner"])
def update_material(pid, mid):
    """Update a raw material entry."""
    if not fetch_one("SELECT id FROM product_materials WHERE id = %s AND product_id = %s", (mid, pid)):
        return not_found("Material")

    data = request.get_json(silent=True) or {}
    allowed = (
        "fiber_type", "fiber_origin", "farm_name", "farm_latitude", "farm_longitude",
        "spinning_mill", "gots_cert_url", "gots_cert_number",
        "rsl_compliant", "rsl_test_report_url", "percentage", "notes"
    )
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields to update")

    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE product_materials SET {set_clause} WHERE id = %s", (*fields.values(), mid))

    append_chain_entry(pid, "UPDATE",
                       {"layer": "2_product_materials", "updated_material": mid},
                       recorded_by=str(g.current_user["sub"]))
    return ok({"message": "Material updated"})


@layer2_bp.route("/<int:mid>", methods=["DELETE"])
@require_auth(roles=["admin", "brand_partner"])
def delete_material(pid, mid):
    if not fetch_one("SELECT id FROM product_materials WHERE id = %s AND product_id = %s", (mid, pid)):
        return not_found("Material")
    execute("DELETE FROM product_materials WHERE id = %s", (mid,))
    return ok({"message": "Material removed"})


@layer2_bp.route("/gots-status", methods=["GET"])
def gots_status(pid):
    """Returns GOTS certification summary for this product."""
    if not _check_product(pid):
        return not_found("Product")

    mats = fetch_all(
        "SELECT fiber_type, gots_cert_url, gots_cert_number, rsl_compliant, percentage "
        "FROM product_materials WHERE product_id = %s",
        (pid,)
    )
    gots_all     = all(m["gots_cert_url"] for m in mats) if mats else False
    rsl_all      = all(m["rsl_compliant"]  for m in mats) if mats else False
    total_pct    = sum(m["percentage"] for m in mats)

    return ok({
        "product_id":          pid,
        "total_composition_pct": float(total_pct),
        "gots_fully_certified": gots_all,
        "rsl_fully_compliant":  rsl_all,
        "materials":            serialise(list(mats)),
    })