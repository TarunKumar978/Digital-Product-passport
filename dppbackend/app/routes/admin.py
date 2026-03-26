"""
Admin Dashboard Routes — Silasya Earth
========================================
All routes require admin role.

Analytics endpoints:
  GET /api/admin/stats              — headline numbers
  GET /api/admin/scans              — scan log with filters
  GET /api/admin/top-scanned        — most-scanned products
  GET /api/admin/compliance-gaps    — products missing data layers
  GET /api/admin/environmental-summary — ESG aggregate
  GET /api/admin/users              — user management
  GET /api/admin/artisan-stats      — artisan productivity
"""

from datetime import datetime, timedelta

from flask import Blueprint, request, g

from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.helpers import ok, serialise, paginate

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.route("/stats", methods=["GET"])
@require_auth(roles=["admin"])
def stats():
    """Headline dashboard statistics."""

    total_products = fetch_one("SELECT COUNT(*) AS c FROM products WHERE is_active=1")["c"]
    total_artisans = fetch_one("SELECT COUNT(*) AS c FROM artisans WHERE is_active=1")["c"]
    total_clusters = fetch_one("SELECT COUNT(*) AS c FROM artisan_clusters")["c"]
    total_scans    = fetch_one("SELECT COUNT(*) AS c FROM scan_logs")["c"]

    # Scans in last 7 days
    week_ago = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    scans_7d = fetch_one(
        "SELECT COUNT(*) AS c FROM scan_logs WHERE scanned_at >= %s", (week_ago,)
    )["c"]

    # Products with all 7 layers complete
    complete = fetch_one(
        """SELECT COUNT(DISTINCT p.id) AS c FROM products p
           WHERE p.is_active = 1
             AND EXISTS (SELECT 1 FROM product_materials     rm WHERE rm.product_id = p.id)
             AND EXISTS (SELECT 1 FROM manufacturing_records mr WHERE mr.product_id = p.id)
             AND EXISTS (SELECT 1 FROM environmental_impact ei WHERE ei.product_id = p.id)
             AND EXISTS (SELECT 1 FROM circularity         ci WHERE ci.product_id = p.id)
             AND EXISTS (SELECT 1 FROM care_instructions    cp WHERE cp.product_id = p.id)
             AND EXISTS (SELECT 1 FROM blockchain_entries  be WHERE be.product_id = p.id)
             AND EXISTS (SELECT 1 FROM certificates cc WHERE cc.product_id = p.id)"""
    )["c"]

    # Active certs expiring in next 30 days
    soon = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d")
    expiring = fetch_one(
        "SELECT COUNT(*) AS c FROM certificates WHERE expiry_date <= %s AND expiry_date >= CURDATE()",
        (soon,)
    )["c"]

    # Avg carbon vs industry
    carbon_row = fetch_one(
        """SELECT AVG(carbon_footprint_co2e) AS avg_carbon,
                  AVG(industry_avg_co2e) AS avg_industry
           FROM environmental_impact"""
    )

    return ok({
        "total_products":     total_products,
        "total_artisans":     total_artisans,
        "total_clusters":     total_clusters,
        "total_scans":        total_scans,
        "scans_last_7_days":  scans_7d,
        "products_complete":  complete,
        "products_incomplete": total_products - complete,
        "certs_expiring_soon": expiring,
        "avg_carbon_co2e":    round(float(carbon_row["avg_carbon"] or 0), 2),
        "avg_industry_co2e":  round(float(carbon_row["avg_industry"] or 0), 2),
        "generated_at":       datetime.utcnow().isoformat(),
    })


@admin_bp.route("/scans", methods=["GET"])
@require_auth(roles=["admin"])
def scan_logs():
    """
    Scan log with date filtering.
    Query params: ?days=30&product_id=1&view=consumer
    """
    page, limit = paginate(request)
    offset = (page - 1) * limit
    days   = int(request.args.get("days", 30))
    pid    = request.args.get("product_id")
    view   = request.args.get("view")

    since  = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    where, params = ["sl.scanned_at >= %s"], [since]
    if pid:
        where.append("sl.product_id = %s"); params.append(int(pid))
    if view:
        where.append("sl.scan_type = %s"); params.append(view)

    where_sql = "WHERE " + " AND ".join(where)

    rows = fetch_all(
        f"""SELECT sl.id, sl.scan_type, sl.ip_address, sl.scanned_at,
                   p.product_name, p.sgtin, p.batch_number
            FROM scan_logs sl
            JOIN products p ON p.id = sl.product_id
            {where_sql}
            ORDER BY sl.scanned_at DESC LIMIT %s OFFSET %s""",
        (*params, limit, offset)
    )

    total = fetch_one(
        f"SELECT COUNT(*) AS c FROM scan_logs sl JOIN products p ON p.id = sl.product_id {where_sql}",
        tuple(params)
    )["c"]

    # Daily breakdown
    daily = fetch_all(
        f"""SELECT DATE(sl.scanned_at) AS day, COUNT(*) AS count
            FROM scan_logs sl {where_sql}
            GROUP BY DATE(sl.scanned_at)
            ORDER BY day DESC LIMIT 30""",
        tuple(params)
    )

    return ok({
        "scans":   serialise(list(rows)),
        "daily":   serialise(list(daily)),
        "total":   total,
        "page":    page,
        "limit":   limit,
        "pages":   (total + limit - 1) // limit,
    })


@admin_bp.route("/top-scanned", methods=["GET"])
@require_auth(roles=["admin"])
def top_scanned():
    """Top 20 most-scanned products."""
    rows = fetch_all(
        """SELECT p.id, p.product_name, p.sgtin, p.batch_number,
                  ac.cluster_name, ac.state,
                  COUNT(sl.id) AS scan_count,
                  MAX(sl.scanned_at) AS last_scan
           FROM scan_logs sl
           JOIN products p ON p.id = sl.product_id
           LEFT JOIN artisan_clusters ac ON ac.id = p.cluster_id
           GROUP BY p.id
           ORDER BY scan_count DESC
           LIMIT 20""",
        ()
    )
    return ok({"products": serialise(list(rows))})


@admin_bp.route("/compliance-gaps", methods=["GET"])
@require_auth(roles=["admin"])
def compliance_gaps():
    """
    Products that are missing one or more DPP data layers.
    Used to track completion before going live.
    """
    products = fetch_all(
        """SELECT p.id, p.product_name, p.sgtin, p.batch_number,
                  p.created_at,
                  EXISTS(SELECT 1 FROM product_materials rm WHERE rm.product_id=p.id)          AS has_materials,
                  EXISTS(SELECT 1 FROM manufacturing_records mr WHERE mr.product_id=p.id)  AS has_manufacturing,
                  EXISTS(SELECT 1 FROM environmental_impact ei WHERE ei.product_id=p.id)   AS has_environmental,
                  EXISTS(SELECT 1 FROM circularity ci WHERE ci.product_id=p.id)            AS has_circularity,
                  EXISTS(SELECT 1 FROM care_instructions cp WHERE cp.product_id=p.id)       AS has_care,
                  EXISTS(SELECT 1 FROM blockchain_entries be WHERE be.product_id=p.id)     AS has_blockchain,
                  EXISTS(SELECT 1 FROM certificates cc WHERE cc.product_id=p.id) AS has_certs
           FROM products p
           WHERE p.is_active = 1
           ORDER BY p.created_at DESC""",
        ()
    )

    layer_names = {
        "has_materials":      "Layer 2 — Raw Materials",
        "has_manufacturing":  "Layer 3 — Artisan Story",
        "has_environmental":  "Layer 4 — Environmental",
        "has_circularity":    "Layer 5 — Circularity",
        "has_care":           "Layer 6 — Care",
        "has_blockchain":     "Layer 7 — Blockchain",
        "has_certs":          "Compliance Certificates",
    }

    result = []
    for p in products:
        p = dict(p)
        missing = [layer_names[k] for k in layer_names if not p.get(k)]
        completion = round((7 - len(missing)) / 7 * 100)
        result.append({
            "id":           p["id"],
            "product_name": p["product_name"],
            "sgtin":        p["sgtin"],
            "batch_number": p["batch_number"],
            "created_at":   p["created_at"],
            "completion_pct": completion,
            "missing_layers": missing,
            "is_complete":  len(missing) == 0,
        })

    incomplete = [r for r in result if not r["is_complete"]]
    complete   = [r for r in result if r["is_complete"]]

    return ok({
        "total":      len(result),
        "complete":   len(complete),
        "incomplete": len(incomplete),
        "products":   result,
    })


@admin_bp.route("/environmental-summary", methods=["GET"])
@require_auth(roles=["admin"])
def environmental_summary():
    """Aggregate ESG / Scope 3 data across all products."""
    row = fetch_one(
        """SELECT
               COUNT(*)                          AS total_with_data,
               AVG(carbon_footprint_co2e)         AS avg_carbon,
               SUM(carbon_footprint_co2e)         AS total_carbon,
               AVG(industry_avg_co2e)             AS avg_industry,
               SUM(water_saved_liters)            AS total_water_saved,
               AVG((industry_avg_co2e - carbon_footprint_co2e)
                   / industry_avg_co2e * 100)     AS avg_reduction_pct
           FROM environmental_impact
           WHERE industry_avg_co2e IS NOT NULL"""
    )

    mfg = fetch_one(
        """SELECT
               SUM(mr.hours_worked)               AS total_artisan_hours,
               COUNT(DISTINCT mr.artisan_id)       AS artisans_employed,
               SUM(CASE WHEN a.fair_wage_verified=1 THEN 1 ELSE 0 END) AS fair_wage_count
           FROM manufacturing_records mr
           JOIN artisans a ON a.id = mr.artisan_id"""
    )

    return ok({
        "environmental": serialise(dict(row)) if row else {},
        "social":        serialise(dict(mfg)) if mfg else {},
        "generated_at":  datetime.utcnow().isoformat(),
    })


@admin_bp.route("/artisan-stats", methods=["GET"])
@require_auth(roles=["admin"])
def artisan_stats():
    """Per-artisan productivity and product count."""
    rows = fetch_all(
        """SELECT a.id, a.full_name, a.craft_type,
                  a.fair_wage_verified, a.income_premium,
                  ac.cluster_name, ac.state,
                  COUNT(mr.id)          AS product_count,
                  SUM(mr.hours_worked)  AS total_hours,
                  MAX(mr.production_date) AS last_active
           FROM artisans a
           LEFT JOIN artisan_clusters ac ON ac.id = a.cluster_id
           LEFT JOIN manufacturing_records mr ON mr.artisan_id = a.id
           WHERE a.is_active = 1
           GROUP BY a.id
           ORDER BY product_count DESC""",
        ()
    )
    return ok({"artisans": serialise(list(rows))})


@admin_bp.route("/users", methods=["GET"])
@require_auth(roles=["admin"])
def list_users():
    """List all platform users (admin only)."""
    users = fetch_all(
        "SELECT id, full_name, email, role, is_active, created_at FROM users ORDER BY created_at DESC",
        ()
    )
    return ok({"users": serialise(list(users))})


@admin_bp.route("/users/<int:uid>/role", methods=["PUT"])
@require_auth(roles=["admin"])
def change_user_role(uid):
    """Change a user's role."""
    from app.utils.helpers import bad_request
    data = request.get_json(silent=True) or {}
    role = data.get("role")
    valid_roles = {"admin", "brand_partner", "artisan_manager", "regulator"}
    if role not in valid_roles:
        return bad_request(f"role must be one of: {', '.join(valid_roles)}")

    execute("UPDATE users SET role = %s WHERE id = %s", (role, uid))
    return ok({"message": f"User {uid} role updated to {role}"})


@admin_bp.route("/users/<int:uid>/deactivate", methods=["POST"])
@require_auth(roles=["admin"])
def deactivate_user(uid):
    """Deactivate a user account."""
    if uid == g.current_user["sub"]:
        from app.utils.helpers import bad_request
        return bad_request("You cannot deactivate your own account")
    execute("UPDATE users SET is_active = 0 WHERE id = %s", (uid,))
    return ok({"message": "User deactivated"})