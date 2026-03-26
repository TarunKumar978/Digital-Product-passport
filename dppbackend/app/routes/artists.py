from flask import Blueprint, request, g
from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.helpers import ok, created, bad_request, not_found, serialise

artists_bp = Blueprint("artists", __name__, url_prefix="/api/artists")

@artists_bp.route("", methods=["GET"])
@require_auth()
def list_artists():
    limit = int(request.args.get("limit", 20))
    q = request.args.get("q", "")
    state = request.args.get("state", "")
    sql = """SELECT a.*, 
                COUNT(DISTINCT pcc.product_id) AS products_count
             FROM artists a
             LEFT JOIN product_creative_chain pcc ON pcc.artist_id = a.id
             WHERE a.is_active = 1"""
    params = []
    if q:
        sql += " AND (a.full_name LIKE %s OR a.art_style LIKE %s)"
        params += [f"%{q}%", f"%{q}%"]
    if state:
        sql += " AND a.state = %s"
        params.append(state)
    sql += " GROUP BY a.id ORDER BY a.created_at DESC LIMIT %s"
    params.append(limit)
    artists = fetch_all(sql, params)
    return ok({"artists": serialise(list(artists))})

@artists_bp.route("/<int:aid>", methods=["GET"])
@require_auth()
def get_artist(aid):
    a = fetch_one("SELECT * FROM artists WHERE id = %s", (aid,))
    if not a:
        return not_found("Artist")
    return ok(serialise(dict(a)))

@artists_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def create_artist():
    data = request.get_json(silent=True) or {}
    missing = next((f for f in ("full_name", "art_style") if not data.get(f)), None)
    if missing:
        return bad_request(f"'{missing}' is required")
    aid = execute(
        """INSERT INTO artists (full_name, art_style, region, state, photo_url,
                instagram_url, portfolio_url, bio, royalty_pct, fair_payment_verified)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (data["full_name"], data["art_style"],
         data.get("region"), data.get("state"),
         data.get("photo_url"), data.get("instagram_url"),
         data.get("portfolio_url"), data.get("bio"),
         data.get("royalty_pct"), int(data.get("fair_wage_verified", 0)))
    )
    return created({"artist_id": aid, "message": "Artist created"})

@artists_bp.route("/<int:aid>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner"])
def update_artist(aid):
    if not fetch_one("SELECT id FROM artists WHERE id = %s", (aid,)):
        return not_found("Artist")
    data = request.get_json(silent=True) or {}
    allowed = ("full_name", "art_style", "region", "state", "photo_url",
               "instagram_url", "portfolio_url", "bio", "royalty_pct", "fair_payment_verified")
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields")
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE artists SET {set_clause} WHERE id = %s", (*fields.values(), aid))
    return ok({"message": "Artist updated"})

@artists_bp.route("/<int:aid>/royalties", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def add_royalty(aid):
    data = request.get_json(silent=True) or {}
    execute(
        "UPDATE artists SET royalty_pct = %s WHERE id = %s",
        (data.get("royalty_pct"), aid)
    )
    return ok({"message": "Royalty updated"})

@artists_bp.route("/<int:aid>/upload-photo", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def upload_artist_photo(aid):
    import base64, os
    data = request.get_json(silent=True) or {}
    photo_data = data.get("photo")
    if not photo_data:
        return bad_request("No photo data")
    upload_dir = "/Users/tarunkumar/Desktop/DPP/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    if "," in photo_data:
        photo_data = photo_data.split(",")[1]
    filename = f"artist_{aid}.jpg"
    filepath = os.path.join(upload_dir, filename)
    with open(filepath, "wb") as f:
        f.write(base64.b64decode(photo_data))
    photo_url = f"/uploads/{filename}"
    execute("UPDATE artists SET photo_url = %s WHERE id = %s", (photo_url, aid))
    return ok({"photo_url": photo_url, "message": "Photo uploaded"})
