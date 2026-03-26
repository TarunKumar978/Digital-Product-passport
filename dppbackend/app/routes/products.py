"""
Layer 1 — Product Identification (GS1-Linked)
Data points per DPP doc:
  - Unique Serial Number (SGTIN)
  - Batch Number
  - Manufacturing Date
  - Product Name / Category
  - Artisan Cluster linkage
  - QR Code URL
  - Blockchain hash
"""

from flask import Blueprint, request, g

from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.blockchain import append_chain_entry
from app.utils.helpers import (
    ok, created, bad_request, not_found, conflict,
    require_fields, paginate, serialise
)

products_bp = Blueprint("products", __name__, url_prefix="/api/products")


@products_bp.route("", methods=["GET"])
@require_auth(roles=["admin", "brand_partner", "artisan_manager"])
def list_products():
    """List all products with pagination and optional search."""
    page, limit = paginate(request)
    offset = (page - 1) * limit
    search = request.args.get("q", "").strip()

    if search:
        products = fetch_all(
            """SELECT p.*, ac.cluster_name, ac.region
               FROM products p
               LEFT JOIN artisan_clusters ac ON ac.id = p.cluster_id
               WHERE p.product_name LIKE %s OR p.sgtin LIKE %s OR p.batch_number LIKE %s
               ORDER BY p.created_at DESC LIMIT %s OFFSET %s""",
            (f"%{search}%", f"%{search}%", f"%{search}%", limit, offset)
        )
        total = fetch_one(
            "SELECT COUNT(*) AS c FROM products WHERE product_name LIKE %s OR sgtin LIKE %s OR batch_number LIKE %s",
            (f"%{search}%", f"%{search}%", f"%{search}%")
        )["c"]
    else:
        products = fetch_all(
            """SELECT p.*, ac.cluster_name, ac.region
               FROM products p
               LEFT JOIN artisan_clusters ac ON ac.id = p.cluster_id
               ORDER BY p.created_at DESC LIMIT %s OFFSET %s""",
            (limit, offset)
        )
        total = fetch_one("SELECT COUNT(*) AS c FROM products")["c"]

    return ok({
        "products": serialise(list(products)),
        "total":    total,
        "page":     page,
        "limit":    limit,
        "pages":    (total + limit - 1) // limit,
    })


@products_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def create_product():
    """
    Create a new product (Layer 1 — GS1 Identification).
    Body: { sgtin*, batch_number*, product_name*, manufacturing_date*,
            category?, cluster_id?, description?, qr_url? }
    """
    data = request.get_json(silent=True) or {}
    missing = require_fields(data, ("sgtin", "batch_number", "product_name", "manufacturing_date"))
    if missing:
        return bad_request(f"'{missing}' is required")

    if fetch_one("SELECT id FROM products WHERE sgtin = %s", (data["sgtin"],)):
        return conflict(f"SGTIN '{data['sgtin']}' already exists")

    pid = execute(
        """INSERT INTO products
               (sgtin, batch_number, product_name, category, description,
                manufacturing_date, cluster_id, qr_url)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            data["sgtin"], data["batch_number"], data["product_name"],
            data.get("category"), data.get("description"),
            data["manufacturing_date"], data.get("cluster_id"),
            data.get("qr_url"),
        )
    )

    # Layer 7 — genesis blockchain entry
    bc_hash = append_chain_entry(
        pid, "CREATION", data,
        recorded_by=str(g.current_user["sub"])
    )

    # Store hash on product record
    execute("UPDATE products SET blockchain_hash = %s WHERE id = %s", (bc_hash, pid))

    return created({
        "message":          "Product created",
        "product_id":       pid,
        "sgtin":            data["sgtin"],
        "blockchain_hash":  bc_hash,
    })


@products_bp.route("/<int:pid>", methods=["GET"])
@require_auth()
def get_product(pid):
    """Get full Layer-1 product details."""
    product = fetch_one(
        """SELECT p.*, ac.cluster_name, ac.region, ac.state
           FROM products p
           LEFT JOIN artisan_clusters ac ON ac.id = p.cluster_id
           WHERE p.id = %s""",
        (pid,)
    )
    if not product:
        return not_found("Product")
    return ok(serialise(product))


@products_bp.route("/<int:pid>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner"])
def update_product(pid):
    """Update mutable product fields."""
    if not fetch_one("SELECT id FROM products WHERE id = %s", (pid,)):
        return not_found("Product")

    data = request.get_json(silent=True) or {}
    allowed = ("product_name", "category", "description", "qr_url", "cluster_id", "sgtin", "batch_number", "manufacturing_date", "product_type", "brand_id")
    fields  = {k: v for k, v in data.items() if k in allowed}
    if "sgtin" in fields:
        existing = fetch_one("SELECT id FROM products WHERE sgtin = %s AND id != %s", (fields["sgtin"], pid))
        if existing:
            return bad_request(f"SGTIN already in use by another product")
    if not fields:
        return bad_request("No valid fields provided to update")

    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(
        f"UPDATE products SET {set_clause} WHERE id = %s",
        (*fields.values(), pid)
    )

    # Blockchain update entry
    append_chain_entry(pid, "UPDATE", {"updated_fields": list(fields.keys()), **fields},
                       recorded_by=str(g.current_user["sub"]))

    return ok({"message": "Product updated"})


@products_bp.route("/<int:pid>", methods=["DELETE"])
@require_auth(roles=["admin"])
def delete_product(pid):
    """Soft-delete by marking inactive (preserves blockchain chain)."""
    if not fetch_one("SELECT id FROM products WHERE id = %s", (pid,)):
        return not_found("Product")
    execute("UPDATE products SET is_active = 0 WHERE id = %s", (pid,))
    return ok({"message": "Product deactivated"})


@products_bp.route("/<int:pid>/summary", methods=["GET"])
@require_auth()
def product_summary(pid):
    """Returns completion status for all 7 DPP layers."""
    if not fetch_one("SELECT id FROM products WHERE id = %s", (pid,)):
        return not_found("Product")

    layer_status = {
        "layer1_identification":  True,  # product exists
        "layer2_product_materials":   bool(fetch_one("SELECT id FROM product_materials WHERE product_id=%s", (pid,))),
        "layer3_manufacturing":   bool(fetch_one("SELECT id FROM manufacturing_records WHERE product_id=%s", (pid,))),
        "layer4_environmental":   bool(fetch_one("SELECT id FROM environmental_impact WHERE product_id=%s", (pid,))),
        "layer5_circularity":     bool(fetch_one("SELECT id FROM circularity WHERE product_id=%s", (pid,))),
        "layer6_care_instructions":bool(fetch_one("SELECT id FROM care_instructions WHERE product_id=%s", (pid,))),
        "layer7_blockchain":      bool(fetch_one("SELECT id FROM blockchain_entries WHERE product_id=%s", (pid,))),
    }
    complete = all(layer_status.values())
    pct = int(sum(layer_status.values()) / 7 * 100)
    return ok({
        "product_id":       pid,
        "passport_complete": complete,
        "completion_pct":   pct,
        "layers":           layer_status,
    })

@products_bp.route("/by-sgtin/<path:sgtin>", methods=["GET"])
def get_product_by_sgtin(sgtin):
    p = fetch_one("SELECT * FROM products WHERE sgtin = %s", (sgtin,))
    if not p:
        return not_found("Product")
    return ok(p)
