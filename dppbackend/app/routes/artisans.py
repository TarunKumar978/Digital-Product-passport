"""
Artisans & Clusters — Silasya Earth
=====================================
Artisans are the heart of the DPP. Each artisan has:
  - A profile (name, craft, bio, photo)
  - Fair wage verification + income premium
  - Cluster membership (geographic weaving cluster)

Clusters are geographic artisan communities:
  - Madhubani Cluster, Bihar
  - Kutch Cluster, Gujarat
  - etc.

One product can have MULTIPLE artisans (manufacturing_records links them).
One artisan can work on MANY products.
"""

from flask import Blueprint, request, g

from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.helpers import ok, created, bad_request, not_found, conflict, paginate, serialise, require_fields
from app.security import sanitise_dict, log_audit_event

artisans_bp = Blueprint("artisans", __name__, url_prefix="/api/artisans")
clusters_bp = Blueprint("clusters", __name__, url_prefix="/api/clusters")


# ══════════════════════════════════════════════════════
#  ARTISANS
# ══════════════════════════════════════════════════════

@artisans_bp.route("", methods=["GET"])
@require_auth(roles=["admin", "brand_partner", "artisan_manager", "regulator"])
def list_artisans():
    """
    List all artisans with pagination and optional search.
    Query params: ?q=search&page=1&limit=20&cluster_id=1
    """
    page, limit = paginate(request)
    offset   = (page - 1) * limit
    search   = request.args.get("q", "").strip()
    cid      = request.args.get("cluster_id")

    base_q = """
        SELECT a.id, a.full_name, a.craft_type, a.photo_url,
               a.fair_wage_verified, a.income_premium, a.bio,
               a.is_active, a.created_at,
               ac.cluster_name, ac.region, ac.state,
               COUNT(mr.id) AS product_count
        FROM artisans a
        LEFT JOIN artisan_clusters ac ON ac.id = a.cluster_id
        LEFT JOIN manufacturing_records mr ON mr.artisan_id = a.id
    """
    where, params = [], []

    if search:
        where.append("(a.full_name LIKE %s OR a.craft_type LIKE %s OR ac.cluster_name LIKE %s)")
        params += [f"%{search}%", f"%{search}%", f"%{search}%"]
    if cid:
        where.append("a.cluster_id = %s")
        params.append(int(cid))

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    rows = fetch_all(
        f"{base_q} {where_sql} GROUP BY a.id ORDER BY a.created_at DESC LIMIT %s OFFSET %s",
        (*params, limit, offset)
    )

    count_row = fetch_one(
        f"SELECT COUNT(DISTINCT a.id) AS c FROM artisans a LEFT JOIN artisan_clusters ac ON ac.id = a.cluster_id {where_sql}",
        tuple(params)
    )
    total = count_row["c"] if count_row else 0

    return ok({
        "artisans": serialise(list(rows)),
        "total": total, "page": page, "limit": limit,
        "pages": (total + limit - 1) // limit,
    })


@artisans_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "artisan_manager"])
def create_artisan():
    """
    Create a new artisan profile.
    Body: {
        full_name*,
        craft_type*,        e.g. "Master Weaver", "Block Printer", "Embroiderer"
        cluster_id*,        which artisan cluster they belong to
        bio?,               artisan story (shown on passport)
        photo_url?,         CDN URL to artisan photo
        fair_wage_verified?, boolean (default false)
        income_premium?,    float — e.g. 3.0 means 3× minimum wage
        phone?,             kept private, never on passport
        aadhaar_ref?,       reference only, never stored in full
    }
    """
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("full_name", "craft_type", "cluster_id"))
    if missing:
        return bad_request(f"'{missing}' is required")

    # Validate cluster exists
    if not fetch_one("SELECT id FROM artisan_clusters WHERE id = %s", (data["cluster_id"],)):
        return bad_request(f"Cluster {data['cluster_id']} does not exist")

    # Check for duplicate in same cluster (same name + craft)
    existing = fetch_one(
        "SELECT id FROM artisans WHERE full_name = %s AND cluster_id = %s",
        (data["full_name"], data["cluster_id"])
    )
    if existing:
        return conflict(f"Artisan '{data['full_name']}' already exists in this cluster (id: {existing['id']})")

    aid = execute(
        """INSERT INTO artisans
               (full_name, craft_type, cluster_id, bio, photo_url,
                fair_wage_verified, income_premium, phone, is_active)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,1)""",
        (
            data["full_name"],
            data["craft_type"],
            data["cluster_id"],
            data.get("bio"),
            data.get("photo_url"),
            int(data.get("fair_wage_verified", 0)),
            data.get("income_premium"),
            data.get("phone"),        # stored privately, never in passport API response
        )
    )

    log_audit_event("CREATE_ARTISAN", "artisans", resource_id=str(aid),
                    user_id=g.current_user["sub"],
                    detail={"name": data["full_name"], "cluster": data["cluster_id"]})

    return created({"message": "Artisan created", "artisan_id": aid})


@artisans_bp.route("/<int:aid>", methods=["GET"])
@require_auth(roles=["admin", "brand_partner", "artisan_manager", "regulator"])
def get_artisan(aid):
    """Get a single artisan with their product history."""
    artisan = fetch_one(
        """SELECT a.*, ac.cluster_name, ac.region, ac.state,
                  ac.latitude AS cluster_lat, ac.longitude AS cluster_lng
           FROM artisans a
           LEFT JOIN artisan_clusters ac ON ac.id = a.cluster_id
           WHERE a.id = %s""",
        (aid,)
    )
    if not artisan:
        return not_found("Artisan")

    # Products this artisan has worked on
    products = fetch_all(
        """SELECT p.id, p.product_name, p.sgtin, p.batch_number,
                  p.manufacturing_date, mr.hours_worked, mr.production_date
           FROM manufacturing_records mr
           JOIN products p ON p.id = mr.product_id
           WHERE mr.artisan_id = %s
           ORDER BY mr.production_date DESC
           LIMIT 50""",
        (aid,)
    )

    result = dict(artisan)
    # Remove private fields from response
    result.pop("phone", None)

    return ok({
        "artisan":  serialise(result),
        "products": serialise(list(products)),
        "total_products": len(products),
    })


@artisans_bp.route("/<int:aid>", methods=["PUT"])
@require_auth(roles=["admin", "artisan_manager"])
def update_artisan(aid):
    """Update artisan profile fields."""
    if not fetch_one("SELECT id FROM artisans WHERE id = %s", (aid,)):
        return not_found("Artisan")

    data    = sanitise_dict(request.get_json(silent=True) or {})
    allowed = (
        "full_name", "craft_type", "cluster_id", "bio", "photo_url",
        "fair_wage_verified", "income_premium", "is_active", "phone"
    )
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields to update")

    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE artisans SET {set_clause} WHERE id = %s", (*fields.values(), aid))

    log_audit_event("UPDATE_ARTISAN", "artisans", resource_id=str(aid),
                    user_id=g.current_user["sub"], detail={"fields": list(fields.keys())})

    return ok({"message": "Artisan updated"})


@artisans_bp.route("/<int:aid>", methods=["DELETE"])
@require_auth(roles=["admin"])
def deactivate_artisan(aid):
    """
    Soft-delete an artisan (set is_active=0).
    Hard delete is not allowed — historical records must be preserved.
    """
    if not fetch_one("SELECT id FROM artisans WHERE id = %s", (aid,)):
        return not_found("Artisan")

    # Check if artisan has products — warn but allow deactivation
    product_count = fetch_one(
        "SELECT COUNT(*) AS c FROM manufacturing_records WHERE artisan_id = %s", (aid,)
    )["c"]

    execute("UPDATE artisans SET is_active = 0 WHERE id = %s", (aid,))
    log_audit_event("DEACTIVATE_ARTISAN", "artisans", resource_id=str(aid),
                    user_id=g.current_user["sub"])

    return ok({
        "message": "Artisan deactivated",
        "note": f"Historical records for {product_count} products preserved"
    })


# ══════════════════════════════════════════════════════
#  CLUSTERS
# ══════════════════════════════════════════════════════

@clusters_bp.route("", methods=["GET"])
def list_clusters():
    """Public — list all artisan clusters."""
    clusters = fetch_all(
        """SELECT ac.id, ac.cluster_name, ac.region, ac.state, ac.country,
                  ac.latitude, ac.longitude, ac.audit_report_url,
                  COUNT(a.id) AS artisan_count
           FROM artisan_clusters ac
           LEFT JOIN artisans a ON a.cluster_id = ac.id AND a.is_active = 1
           GROUP BY ac.id
           ORDER BY ac.cluster_name""",
        ()
    )
    return ok({"clusters": serialise(list(clusters))})


@clusters_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "artisan_manager"])
def create_cluster():
    """
    Create a new artisan cluster.
    Body: {
        cluster_name*,   e.g. "Madhubani Cluster"
        region*,         e.g. "Madhubani"
        state*,          e.g. "Bihar"
        country?,        default "India"
        latitude?,
        longitude?,
        audit_report_url?
    }
    """
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("cluster_name", "region", "state"))
    if missing:
        return bad_request(f"'{missing}' is required")

    if fetch_one(
        "SELECT id FROM artisan_clusters WHERE cluster_name = %s AND state = %s",
        (data["cluster_name"], data["state"])
    ):
        return conflict(f"Cluster '{data['cluster_name']}' already exists in {data['state']}")

    cid = execute(
        """INSERT INTO artisan_clusters
               (cluster_name, region, state, country, latitude, longitude, audit_report_url)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (
            data["cluster_name"],
            data["region"],
            data["state"],
            data.get("country", "India"),
            data.get("latitude"),
            data.get("longitude"),
            data.get("audit_report_url"),
        )
    )
    log_audit_event("CREATE_CLUSTER", "artisan_clusters", resource_id=str(cid),
                    user_id=g.current_user["sub"],
                    detail={"name": data["cluster_name"], "state": data["state"]})

    return created({"message": "Cluster created", "cluster_id": cid})


@clusters_bp.route("/<int:cid>", methods=["GET"])
def get_cluster(cid):
    """Get cluster details with its artisans."""
    cluster = fetch_one("SELECT * FROM artisan_clusters WHERE id = %s", (cid,))
    if not cluster:
        return not_found("Cluster")

    artisans = fetch_all(
        """SELECT id, full_name, craft_type, photo_url,
                  fair_wage_verified, income_premium
           FROM artisans WHERE cluster_id = %s AND is_active = 1
           ORDER BY full_name""",
        (cid,)
    )
    return ok({
        "cluster":  serialise(dict(cluster)),
        "artisans": serialise(list(artisans)),
        "artisan_count": len(artisans),
    })


@clusters_bp.route("/<int:cid>", methods=["PUT"])
@require_auth(roles=["admin", "artisan_manager"])
def update_cluster(cid):
    """Update cluster details."""
    if not fetch_one("SELECT id FROM artisan_clusters WHERE id = %s", (cid,)):
        return not_found("Cluster")

    data    = sanitise_dict(request.get_json(silent=True) or {})
    allowed = ("cluster_name", "region", "state", "country", "latitude", "longitude", "audit_report_url")
    fields  = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields to update")

    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE artisan_clusters SET {set_clause} WHERE id = %s", (*fields.values(), cid))
    return ok({"message": "Cluster updated"})