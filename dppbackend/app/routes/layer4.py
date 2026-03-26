"""
Layer 4 — Environmental Impact Profile
Data points per DPP doc:
  - Carbon Footprint (CO2e) vs industrial equivalent
  - Water Conservation (exact litres saved)
  - LCA (Life Cycle Assessment) methodology
  - Real-time calculations based on LCA standards
"""

from flask import Blueprint, request, g

from app.db import fetch_one, execute
from app.utils.auth import require_auth
from app.utils.blockchain import append_chain_entry
from app.utils.helpers import ok, created, bad_request, not_found, require_fields, serialise

layer4_bp = Blueprint("layer4", __name__, url_prefix="/api/products/<int:pid>/environmental")


def _check_product(pid):
    return fetch_one("SELECT id FROM products WHERE id = %s AND is_active = 1", (pid,))


@layer4_bp.route("", methods=["GET"])
def get_environmental(pid):
    """Get the environmental impact profile."""
    if not _check_product(pid):
        return not_found("Product")

    env = fetch_one("SELECT * FROM environmental_impact WHERE product_id = %s", (pid,))
    if not env:
        return not_found("Environmental impact data")

    # Compute derived metrics
    env = dict(env)
    if env.get("carbon_footprint_co2e") and env.get("industry_avg_co2e"):
        saved = env["industry_avg_co2e"] - env["carbon_footprint_co2e"]
        env["carbon_saved_co2e"]    = round(float(saved), 4)
        env["carbon_reduction_pct"] = round(float(saved / env["industry_avg_co2e"] * 100), 1)

    return ok(serialise(env))


@layer4_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def set_environmental(pid):
    """
    Create or update the environmental impact data (upsert).
    Body: {
        carbon_footprint_co2e*,   kg CO2e for this specific garment
        industry_avg_co2e?,       benchmark kg CO2e for industrial equivalent
        water_saved_liters*,      exact litres saved vs irrigated equivalent
        lca_methodology?,         default "ISO 14040/44 LCA Standard"
        assessment_date?,
        assessment_body?,         organisation that performed LCA
        report_url?,              link to full LCA report
        energy_used_kwh?,
        transport_emissions_co2e?
    }
    """
    if not _check_product(pid):
        return not_found("Product")

    data = request.get_json(silent=True) or {}
    missing = require_fields(data, ("carbon_footprint_co2e", "water_saved_liters"))
    if missing:
        return bad_request(f"'{missing}' is required")

    existing = fetch_one("SELECT id FROM environmental_impact WHERE product_id = %s", (pid,))

    if existing:
        execute(
            """UPDATE environmental_impact SET
                   carbon_footprint_co2e      = %s,
                   industry_avg_co2e          = %s,
                   water_saved_liters         = %s,
                   lca_methodology            = %s,
                   assessment_date            = %s,
                   assessment_body            = %s,
                   report_url                 = %s,
                   energy_used_kwh            = %s,
                   transport_emissions_co2e   = %s
               WHERE product_id = %s""",
            (
                data["carbon_footprint_co2e"],
                data.get("industry_avg_co2e"),
                data["water_saved_liters"],
                data.get("lca_methodology", "ISO 14040/44 LCA Standard"),
                data.get("assessment_date"),
                data.get("assessment_body"),
                data.get("report_url"),
                data.get("energy_used_kwh"),
                data.get("transport_emissions_co2e"),
                pid,
            )
        )
        msg = "Environmental data updated"
    else:
        execute(
            """INSERT INTO environmental_impact
                   (product_id, carbon_footprint_co2e, industry_avg_co2e,
                    water_saved_liters, lca_methodology, assessment_date,
                    assessment_body, report_url, energy_used_kwh, transport_emissions_co2e)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                pid,
                data["carbon_footprint_co2e"],
                data.get("industry_avg_co2e"),
                data["water_saved_liters"],
                data.get("lca_methodology", "ISO 14040/44 LCA Standard"),
                data.get("assessment_date"),
                data.get("assessment_body"),
                data.get("report_url"),
                data.get("energy_used_kwh"),
                data.get("transport_emissions_co2e"),
            )
        )
        msg = "Environmental data created"

    append_chain_entry(
        pid, "UPDATE",
        {
            "layer":                  "4_environmental",
            "carbon_footprint_co2e":  data["carbon_footprint_co2e"],
            "water_saved_liters":     data["water_saved_liters"],
        },
        recorded_by=str(g.current_user["sub"])
    )

    return created({"message": msg})


@layer4_bp.route("/compare", methods=["GET"])
def carbon_compare(pid):
    """
    Returns a comparison of this product's carbon vs industry average.
    Used by the DPP passport page and B2B ESG reporting dashboards.
    """
    if not _check_product(pid):
        return not_found("Product")

    env = fetch_one(
        "SELECT carbon_footprint_co2e, industry_avg_co2e, water_saved_liters, lca_methodology "
        "FROM environmental_impact WHERE product_id = %s",
        (pid,)
    )
    if not env:
        return not_found("Environmental data")

    carbon     = float(env["carbon_footprint_co2e"])
    avg        = float(env["industry_avg_co2e"]) if env["industry_avg_co2e"] else None
    water      = float(env["water_saved_liters"])
    reduction  = round((avg - carbon) / avg * 100, 1) if avg else None

    return ok({
        "product_id":              pid,
        "carbon_footprint_co2e":   carbon,
        "industry_avg_co2e":       avg,
        "carbon_saved_co2e":       round(avg - carbon, 4) if avg else None,
        "carbon_reduction_pct":    reduction,
        "water_saved_liters":      water,
        "lca_methodology":         env["lca_methodology"],
        "scope3_ready":            True,    # data is Scope 3 compatible
    })