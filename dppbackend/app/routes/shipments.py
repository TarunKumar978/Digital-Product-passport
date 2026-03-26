from datetime import datetime
from flask import Blueprint, request, g
from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.helpers import ok, created, bad_request, not_found, paginate, serialise
from app.security import sanitise_dict, log_audit_event

shipments_bp = Blueprint("shipments", __name__, url_prefix="/api/shipments")

@shipments_bp.route("", methods=["GET"])
@require_auth(roles=["admin", "brand_partner"])
def list_shipments():
    page, limit = paginate(request)
    offset = (page - 1) * limit
    status = request.args.get("status")
    brand  = request.args.get("brand_id", "shumitra")
    where  = ["s.brand_id = %s"]; params = [brand]
    if status: where.append("s.status = %s"); params.append(status)
    where_sql = "WHERE " + " AND ".join(where)
    rows = fetch_all(f"SELECT s.*, COUNT(si.id) AS product_count FROM shipments s LEFT JOIN shipment_items si ON si.shipment_id = s.id {where_sql} GROUP BY s.id ORDER BY s.created_at DESC LIMIT %s OFFSET %s", (*params, limit, offset))
    total = fetch_one(f"SELECT COUNT(*) AS c FROM shipments s {where_sql}", tuple(params))["c"]
    return ok({"shipments": serialise(list(rows)), "total": total, "page": page, "limit": limit})

@shipments_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def create_shipment():
    data = sanitise_dict(request.get_json(silent=True) or {})
    if not data.get("buyer_name") or not data.get("buyer_country"):
        return bad_request("buyer_name and buyer_country are required")
    count = fetch_one("SELECT COUNT(*) AS c FROM shipments")["c"]
    ref   = f"SHU-{datetime.utcnow().year}-{str(count+1).zfill(4)}"
    sid   = execute(
        "INSERT INTO shipments (shipment_ref, brand_id, buyer_name, buyer_country, buyer_company, buyer_email, incoterms, port_of_export, port_of_import, vessel_name, container_number, bill_of_lading, etd, eta, notes, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (ref, data.get("brand_id","shumitra"), data["buyer_name"], data["buyer_country"].upper(), data.get("buyer_company"), data.get("buyer_email"), data.get("incoterms"), data.get("port_of_export"), data.get("port_of_import"), data.get("vessel_name"), data.get("container_number"), data.get("bill_of_lading"), data.get("etd"), data.get("eta"), data.get("notes"), g.current_user["sub"])
    )
    return created({"message": "Shipment created", "shipment_id": sid, "shipment_ref": ref})

@shipments_bp.route("/<int:sid>", methods=["GET"])
@require_auth(roles=["admin", "brand_partner"])
def get_shipment(sid):
    shipment = fetch_one("SELECT * FROM shipments WHERE id = %s", (sid,))
    if not shipment: return not_found("Shipment")
    items = fetch_all("SELECT si.quantity, p.id AS product_id, p.product_name, p.sgtin, p.product_type, p.batch_number FROM shipment_items si JOIN products p ON p.id = si.product_id WHERE si.shipment_id = %s", (sid,))
    return ok({"shipment": serialise(dict(shipment)), "items": serialise(list(items)), "total_products": len(items)})

@shipments_bp.route("/<int:sid>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner"])
def update_shipment(sid):
    if not fetch_one("SELECT id FROM shipments WHERE id = %s", (sid,)): return not_found("Shipment")
    data    = sanitise_dict(request.get_json(silent=True) or {})
    allowed = ("buyer_name","buyer_country","incoterms","port_of_export","port_of_import","vessel_name","container_number","bill_of_lading","etd","eta","status","notes")
    fields  = {k: v for k, v in data.items() if k in allowed}
    if not fields: return bad_request("No valid fields to update")
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE shipments SET {set_clause} WHERE id = %s", (*fields.values(), sid))
    return ok({"message": "Shipment updated"})

@shipments_bp.route("/<int:sid>/products", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def add_products_to_shipment(sid):
    if not fetch_one("SELECT id FROM shipments WHERE id = %s", (sid,)): return not_found("Shipment")
    products = (request.get_json(silent=True) or {}).get("products", [])
    if not products: return bad_request("products list is required")
    added = 0
    for item in products:
        pid = item.get("product_id")
        if not pid: continue
        try:
            execute("INSERT INTO shipment_items (shipment_id, product_id, quantity) VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE quantity=VALUES(quantity)", (sid, pid, item.get("quantity",1)))
            added += 1
        except Exception: continue
    execute("UPDATE shipments SET total_products=(SELECT COUNT(*) FROM shipment_items WHERE shipment_id=%s) WHERE id=%s", (sid, sid))
    return ok({"message": f"{added} products added"})

@shipments_bp.route("/<int:sid>/products/<int:pid>", methods=["DELETE"])
@require_auth(roles=["admin", "brand_partner"])
def remove_product(sid, pid):
    execute("DELETE FROM shipment_items WHERE shipment_id=%s AND product_id=%s", (sid, pid))
    execute("UPDATE shipments SET total_products=(SELECT COUNT(*) FROM shipment_items WHERE shipment_id=%s) WHERE id=%s", (sid, sid))
    return ok({"message": "Product removed"})

@shipments_bp.route("/<int:sid>/compliance", methods=["GET"])
@require_auth(roles=["admin", "brand_partner", "regulator"])
def shipment_compliance(sid):
    shipment = fetch_one("SELECT * FROM shipments WHERE id = %s", (sid,))
    if not shipment: return not_found("Shipment")
    items = fetch_all("SELECT p.id, p.sgtin, p.product_name, p.product_type, p.batch_number, si.quantity FROM shipment_items si JOIN products p ON p.id = si.product_id WHERE si.shipment_id = %s", (sid,))
    return ok({"shipment": serialise(dict(shipment)), "products": serialise(list(items)), "total": len(items), "generated_at": datetime.utcnow().isoformat()})
