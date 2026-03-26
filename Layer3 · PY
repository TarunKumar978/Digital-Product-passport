"""
Layer 3 — Manufacturing Intelligence (The Artisan Story)
Data points per DPP doc:
  - Name of the Artisan/Weaver
  - Hours worked on the garment
  - Geolocation of artisan/cluster
  - "Fair Wage Verified" status (3× income premium)
  - Social audit report links (SA8000 equivalent)
"""

from flask import Blueprint, request, g

from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.blockchain import append_chain_entry
from app.utils.helpers import ok, created, bad_request, not_found, require_fields, serialise

layer3_bp = Blueprint("layer3", __name__, url_prefix="/api/products/<int:pid>/manufacturing")


def _check_product(pid):
    return fetch_one("SELECT id FROM products WHERE id = %s AND is_active = 1", (pid,))


@layer3_bp.route("", methods=["GET"])
def get_manufacturing(pid):
    """Get manufacturing records with full artisan & cluster details."""
    if not _check_product(pid):
        return not_found("Product")

    records = fetch_all(
        """SELECT
               mr.id, mr.hours_worked, mr.production_date,
               mr.social_audit_url, mr.social_audit_standard,
               mr.created_at,
               a.id         AS artisan_id,
               a.full_name  AS artisan_name,
               a.craft_type,
               a.photo_url  AS artisan_photo_url,
               a.fair_wage_verified,
               a.income_premium,
               ac.id            AS cluster_id,
               ac.cluster_name,
               ac.region,
               ac.state,
               ac.country,
               ac.latitude      AS cluster_latitude,
               ac.longitude     AS cluster_longitude,
               ac.audit_report_url AS cluster_audit_url
           FROM manufacturing_records mr
           JOIN artisans         a  ON a.id  = mr.artisan_id
           JOIN artisan_clusters ac ON ac.id = mr.cluster_id
           WHERE mr.product_id = %s
           ORDER BY mr.id""",
        (pid,)
    )
    return ok({"product_id": pid, "records": serialise(list(records))})


@layer3_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner", "artisan_manager"])
def add_manufacturing(pid):
    """
    Add a manufacturing / artisan record.
    Body: {
        artisan_id*,
        cluster_id*,
        hours_worked*,
        production_date?,
        social_audit_url?,       SA8000 equivalent report link
        social_audit_standard?,  e.g. "SA8000", "SMETA"
    }
    """
    if not _check_product(pid):
        return not_found("Product")

    data = request.get_json(silent=True) or {}
    missing = require_fields(data, ("artisan_id", "cluster_id", "hours_worked"))
    if missing:
        return bad_request(f"'{missing}' is required")

    # Validate artisan exists
    artisan = fetch_one("SELECT * FROM artisans WHERE id = %s", (data["artisan_id"],))
    if not artisan:
        return not_found("Artisan")

    # Validate cluster
    if not fetch_one("SELECT id FROM artisan_clusters WHERE id = %s", (data["cluster_id"],)):
        return not_found("Artisan cluster")

    rid = execute(
        """INSERT INTO manufacturing_records
               (product_id, artisan_id, cluster_id, hours_worked,
                production_date, social_audit_url, social_audit_standard)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (
            pid,
            data["artisan_id"], data["cluster_id"],
            data["hours_worked"],
            data.get("production_date"),
            data.get("social_audit_url"),
            data.get("social_audit_standard", "SA8000"),
        )
    )

    append_chain_entry(
        pid, "UPDATE",
        {
            "layer":       "3_manufacturing",
            "record_id":   rid,
            "artisan_id":  data["artisan_id"],
            "artisan_name":artisan["full_name"],
            "hours_worked":data["hours_worked"],
            "fair_wage":   bool(artisan["fair_wage_verified"]),
        },
        recorded_by=str(g.current_user["sub"])
    )

    return created({
        "message":           "Manufacturing record added",
        "record_id":         rid,
        "artisan_name":      artisan["full_name"],
        "fair_wage_verified":bool(artisan["fair_wage_verified"]),
    })


@layer3_bp.route("/<int:rid>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner", "artisan_manager"])
def update_manufacturing(pid, rid):
    if not fetch_one("SELECT id FROM manufacturing_records WHERE id = %s AND product_id = %s", (rid, pid)):
        return not_found("Manufacturing record")

    data = request.get_json(silent=True) or {}
    allowed = ("hours_worked", "production_date", "social_audit_url", "social_audit_standard")
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields to update")

    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE manufacturing_records SET {set_clause} WHERE id = %s", (*fields.values(), rid))

    append_chain_entry(pid, "UPDATE",
                       {"layer": "3_manufacturing", "updated_record": rid},
                       recorded_by=str(g.current_user["sub"]))
    return ok({"message": "Manufacturing record updated"})


@layer3_bp.route("/<int:rid>", methods=["DELETE"])
@require_auth(roles=["admin"])
def delete_manufacturing(pid, rid):
    if not fetch_one("SELECT id FROM manufacturing_records WHERE id = %s AND product_id = %s", (rid, pid)):
        return not_found("Manufacturing record")
    execute("DELETE FROM manufacturing_records WHERE id = %s", (rid,))
    return ok({"message": "Manufacturing record deleted"})


@layer3_bp.route("/fair-wage-summary", methods=["GET"])
def fair_wage_summary(pid):
    """Returns fair wage compliance summary for this product."""
    if not _check_product(pid):
        return not_found("Product")

    records = fetch_all(
        """SELECT a.full_name, a.fair_wage_verified, a.income_premium,
                  mr.hours_worked, ac.cluster_name, ac.region
           FROM manufacturing_records mr
           JOIN artisans a ON a.id = mr.artisan_id
           JOIN artisan_clusters ac ON ac.id = mr.cluster_id
           WHERE mr.product_id = %s""",
        (pid,)
    )
    total_hours   = sum(r["hours_worked"] or 0 for r in records)
    fair_wage_pct = (
        sum(1 for r in records if r["fair_wage_verified"]) / len(records) * 100
        if records else 0
    )
    return ok({
        "product_id":          pid,
        "total_artisan_hours": float(total_hours),
        "fair_wage_compliance_pct": round(fair_wage_pct, 1),
        "artisans":            serialise(list(records)),
    })