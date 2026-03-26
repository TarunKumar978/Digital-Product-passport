"""
Layer 3 — Creative Chain (Artist · Designer · Manufacturer)
=============================================================
Replaces the old "Manufacturing / Artisan Story" layer.

Silasya's model:
  1. ARTIST     — created the original art. Silasya bought it + pays royalties.
  2. DESIGNER   — turned the art into a product design (kurta pattern, toy shape, etc.)
  3. MANUFACTURER — physically made the product from the design.

All three are separate people. All three are optional but the more you fill,
the richer the passport story and the stronger your EU/US compliance data.

Routes:
  Artists:
    GET/POST       /api/artists
    GET/PUT        /api/artists/:id
    GET            /api/artists/:id/royalties

  Designers:
    GET/POST       /api/designers
    GET/PUT        /api/designers/:id

  Manufacturers:
    GET/POST       /api/manufacturers
    GET/PUT        /api/manufacturers/:id

  Creative chain per product (replaces /manufacturing):
    GET/POST/PUT   /api/products/:id/story
    GET            /api/products/:id/story/public   ← what passport reads
"""

from flask import Blueprint, request, g

from app.db import fetch_one, fetch_all, execute
from app.utils.auth import require_auth
from app.utils.helpers import ok, created, bad_request, not_found, conflict, paginate, serialise, require_fields
from app.utils.blockchain import append_chain_entry
from app.security import sanitise_dict, log_audit_event

artists_bp      = Blueprint("artists",      __name__, url_prefix="/api/artists")
designers_bp    = Blueprint("designers",    __name__, url_prefix="/api/designers")
manufacturers_bp= Blueprint("manufacturers",__name__, url_prefix="/api/manufacturers")
story_bp        = Blueprint("story",        __name__, url_prefix="/api/products")


# ══════════════════════════════════════════════════════════════════════════
#  ARTISTS
# ══════════════════════════════════════════════════════════════════════════

@artists_bp.route("", methods=["GET"])
@require_auth(roles=["admin", "brand_partner", "artisan_manager"])
def list_artists():
    """
    List all artists with pagination.
    Query: ?q=search&state=Bihar&page=1&limit=20
    """
    page, limit = paginate(request)
    offset = (page - 1) * limit
    q      = request.args.get("q", "").strip()
    state  = request.args.get("state", "").strip()

    where, params = ["a.is_active = 1"], []
    if q:     where.append("(a.full_name LIKE %s OR a.art_style LIKE %s)"); params += [f"%{q}%", f"%{q}%"]
    if state: where.append("a.state = %s"); params.append(state)

    where_sql = "WHERE " + " AND ".join(where)

    rows = fetch_all(
        f"""SELECT a.id, a.full_name, a.art_style, a.region, a.state,
                   a.photo_url, a.fair_payment_verified, a.royalty_pct,
                   a.instagram_url, a.is_active, a.created_at,
                   COUNT(pcc.id) AS products_count
            FROM artists a
            LEFT JOIN product_creative_chain pcc ON pcc.artist_id = a.id
            {where_sql}
            GROUP BY a.id
            ORDER BY a.full_name
            LIMIT %s OFFSET %s""",
        (*params, limit, offset)
    )
    total = fetch_one(f"SELECT COUNT(*) AS c FROM artists a {where_sql}", tuple(params))["c"]

    return ok({
        "artists": serialise(list(rows)),
        "total": total, "page": page, "limit": limit,
        "pages": (total + limit - 1) // limit,
    })


@artists_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def create_artist():
    """
    Create a new artist profile.
    Body: {
        full_name*,
        art_style*,              Madhubani, Warli, Block Print, Dhokra, Kantha, Pattachitra...
        region?,                 e.g. Mithila
        state?,                  e.g. Bihar
        photo_url?,              CDN URL
        bio?,                    artist story — shown on passport
        instagram_url?,
        portfolio_url?,
        fair_payment_verified?,  boolean — did Silasya pay fairly?
        royalty_pct?,            ongoing royalty % per product sold e.g. 5.0
        payment_rate?,           flat fee paid for art purchase (INR)
        payment_verified_by?     who verified the payment
    }
    """
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("full_name", "art_style"))
    if missing:
        return bad_request(f"'{missing}' is required")

    if fetch_one("SELECT id FROM artists WHERE full_name = %s AND art_style = %s",
                 (data["full_name"], data["art_style"])):
        return conflict(f"Artist '{data['full_name']}' with style '{data['art_style']}' already exists")

    aid = execute(
        """INSERT INTO artists
               (full_name, art_style, region, state, country,
                photo_url, bio, instagram_url, portfolio_url,
                fair_payment_verified, royalty_pct, payment_rate, payment_verified_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            data["full_name"], data["art_style"],
            data.get("region"), data.get("state"),
            data.get("country", "India"),
            data.get("photo_url"), data.get("bio"),
            data.get("instagram_url"), data.get("portfolio_url"),
            int(data.get("fair_payment_verified", 0)),
            data.get("royalty_pct"), data.get("payment_rate"),
            data.get("payment_verified_by"),
        )
    )
    log_audit_event("CREATE_ARTIST", "artists", resource_id=str(aid),
                    user_id=g.current_user["sub"],
                    detail={"name": data["full_name"], "style": data["art_style"]})
    return created({"message": "Artist created", "artist_id": aid})


@artists_bp.route("/<int:aid>", methods=["GET"])
@require_auth(roles=["admin", "brand_partner", "artisan_manager"])
def get_artist(aid):
    """Get artist profile + list of products their art is used in."""
    artist = fetch_one("SELECT * FROM artists WHERE id = %s", (aid,))
    if not artist:
        return not_found("Artist")

    products = fetch_all(
        """SELECT p.id, p.product_name, p.sgtin, p.batch_number,
                  pcc.art_title, pcc.royalty_pct, pcc.art_license_type
           FROM product_creative_chain pcc
           JOIN products p ON p.id = pcc.product_id
           WHERE pcc.artist_id = %s AND p.is_active = 1
           ORDER BY p.created_at DESC""",
        (aid,)
    )

    royalties = fetch_all(
        """SELECT period_start, period_end, units_sold,
                  royalty_per_unit, total_paid, payment_date
           FROM royalty_payments WHERE artist_id = %s
           ORDER BY payment_date DESC LIMIT 24""",
        (aid,)
    )

    result = dict(artist)
    result.pop("payment_rate", None)  # don't expose payment amount publicly

    return ok({
        "artist":    serialise(result),
        "products":  serialise(list(products)),
        "royalties": serialise(list(royalties)),
    })


@artists_bp.route("/<int:aid>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner"])
def update_artist(aid):
    if not fetch_one("SELECT id FROM artists WHERE id = %s", (aid,)):
        return not_found("Artist")
    data    = sanitise_dict(request.get_json(silent=True) or {})
    allowed = (
        "full_name", "art_style", "region", "state", "country",
        "photo_url", "bio", "instagram_url", "portfolio_url",
        "fair_payment_verified", "royalty_pct", "payment_rate",
        "payment_verified_by", "is_active"
    )
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields to update")
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE artists SET {set_clause} WHERE id = %s", (*fields.values(), aid))
    log_audit_event("UPDATE_ARTIST", "artists", resource_id=str(aid),
                    user_id=g.current_user["sub"])
    return ok({"message": "Artist updated"})


@artists_bp.route("/<int:aid>/royalties", methods=["POST"])
@require_auth(roles=["admin"])
def log_royalty_payment(aid):
    """
    Log a royalty payment to an artist.
    Body: {
        product_id*,
        period_start*, period_end*,
        units_sold*,
        royalty_per_unit*,
        total_paid*,
        payment_date*,
        payment_ref?,
        notes?
    }
    """
    data = request.get_json(silent=True) or {}
    missing = require_fields(data, ("product_id", "period_start", "period_end",
                                    "units_sold", "royalty_per_unit", "total_paid", "payment_date"))
    if missing:
        return bad_request(f"'{missing}' is required")

    rid = execute(
        """INSERT INTO royalty_payments
               (artist_id, product_id, period_start, period_end,
                units_sold, royalty_per_unit, total_paid, payment_date,
                payment_ref, notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            aid, data["product_id"],
            data["period_start"], data["period_end"],
            data["units_sold"], data["royalty_per_unit"],
            data["total_paid"], data["payment_date"],
            data.get("payment_ref"), data.get("notes"),
        )
    )
    log_audit_event("ROYALTY_PAYMENT", "royalty_payments", resource_id=str(rid),
                    user_id=g.current_user["sub"],
                    detail={"artist_id": aid, "total_paid": data["total_paid"]})
    return created({"message": "Royalty payment logged", "payment_id": rid})


# ══════════════════════════════════════════════════════════════════════════
#  DESIGNERS
# ══════════════════════════════════════════════════════════════════════════

@designers_bp.route("", methods=["GET"])
@require_auth(roles=["admin", "brand_partner"])
def list_designers():
    rows = fetch_all(
        """SELECT d.id, d.full_name, d.studio_name, d.city, d.state,
                  d.photo_url, d.is_active,
                  COUNT(pcc.id) AS products_count
           FROM designers d
           LEFT JOIN product_creative_chain pcc ON pcc.designer_id = d.id
           WHERE d.is_active = 1
           GROUP BY d.id ORDER BY d.full_name""",
        ()
    )
    return ok({"designers": serialise(list(rows))})


@designers_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def create_designer():
    """
    Body: {
        full_name*, studio_name?, city?, state?,
        photo_url?, bio?, portfolio_url?
    }
    """
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("full_name",))
    if missing:
        return bad_request(f"'{missing}' is required")

    did = execute(
        "INSERT INTO designers (full_name, studio_name, city, state, photo_url, bio, portfolio_url) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (data["full_name"], data.get("studio_name"), data.get("city"), data.get("state"),
         data.get("photo_url"), data.get("bio"), data.get("portfolio_url"))
    )
    return created({"message": "Designer created", "designer_id": did})


@designers_bp.route("/<int:did>", methods=["GET"])
@require_auth(roles=["admin", "brand_partner"])
def get_designer(did):
    d = fetch_one("SELECT * FROM designers WHERE id = %s", (did,))
    if not d:
        return not_found("Designer")
    products = fetch_all(
        """SELECT p.id, p.product_name, pcc.design_title
           FROM product_creative_chain pcc
           JOIN products p ON p.id = pcc.product_id
           WHERE pcc.designer_id = %s""",
        (did,)
    )
    return ok({"designer": serialise(dict(d)), "products": serialise(list(products))})


@designers_bp.route("/<int:did>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner"])
def update_designer(did):
    if not fetch_one("SELECT id FROM designers WHERE id = %s", (did,)):
        return not_found("Designer")
    data    = sanitise_dict(request.get_json(silent=True) or {})
    allowed = ("full_name", "studio_name", "city", "state", "photo_url", "bio", "portfolio_url", "is_active")
    fields  = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields to update")
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE designers SET {set_clause} WHERE id = %s", (*fields.values(), did))
    return ok({"message": "Designer updated"})


# ══════════════════════════════════════════════════════════════════════════
#  MANUFACTURERS
# ══════════════════════════════════════════════════════════════════════════

@manufacturers_bp.route("", methods=["GET"])
@require_auth(roles=["admin", "brand_partner"])
def list_manufacturers():
    rows = fetch_all(
        """SELECT m.id, m.name, m.city, m.state, m.country,
                  m.gots_certified, m.sa8000_certified, m.is_active,
                  COUNT(pcc.id) AS products_count
           FROM manufacturers m
           LEFT JOIN product_creative_chain pcc ON pcc.manufacturer_id = m.id
           WHERE m.is_active = 1
           GROUP BY m.id ORDER BY m.name""",
        ()
    )
    return ok({"manufacturers": serialise(list(rows))})


@manufacturers_bp.route("", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def create_manufacturer():
    """
    Body: {
        name*, city?, state?, country?,
        gots_certified?, gots_cert_number?,
        sa8000_certified?, oeko_tex_certified?,
        contact_name?, contact_email?,
        audit_report_url?
    }
    """
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("name",))
    if missing:
        return bad_request(f"'{missing}' is required")

    mid = execute(
        """INSERT INTO manufacturers
               (name, city, state, country, contact_name, contact_email,
                gots_certified, gots_cert_number, sa8000_certified,
                oeko_tex_certified, audit_report_url)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            data["name"], data.get("city"), data.get("state"),
            data.get("country", "India"),
            data.get("contact_name"), data.get("contact_email"),
            int(data.get("gots_certified", 0)), data.get("gots_cert_number"),
            int(data.get("sa8000_certified", 0)),
            int(data.get("oeko_tex_certified", 0)),
            data.get("audit_report_url"),
        )
    )
    return created({"message": "Manufacturer created", "manufacturer_id": mid})


@manufacturers_bp.route("/<int:mid>", methods=["GET"])
@require_auth(roles=["admin", "brand_partner"])
def get_manufacturer(mid):
    m = fetch_one("SELECT * FROM manufacturers WHERE id = %s", (mid,))
    if not m:
        return not_found("Manufacturer")
    return ok({"manufacturer": serialise(dict(m))})


@manufacturers_bp.route("/<int:mid>", methods=["PUT"])
@require_auth(roles=["admin", "brand_partner"])
def update_manufacturer(mid):
    if not fetch_one("SELECT id FROM manufacturers WHERE id = %s", (mid,)):
        return not_found("Manufacturer")
    data    = sanitise_dict(request.get_json(silent=True) or {})
    allowed = ("name", "city", "state", "country", "contact_name", "contact_email",
               "gots_certified", "gots_cert_number", "sa8000_certified",
               "oeko_tex_certified", "audit_report_url", "is_active")
    fields  = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return bad_request("No valid fields")
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    execute(f"UPDATE manufacturers SET {set_clause} WHERE id = %s", (*fields.values(), mid))
    return ok({"message": "Manufacturer updated"})


# ══════════════════════════════════════════════════════════════════════════
#  PRODUCT STORY — links artist + designer + manufacturer to a product
# ══════════════════════════════════════════════════════════════════════════

@story_bp.route("/<int:pid>/story", methods=["GET"])
def get_product_story(pid):
    """Public — full creative chain for a product (passport uses this)."""
    story = fetch_one(
        """SELECT
               pcc.*,
               a.full_name     AS artist_name,
               a.art_style,
               a.region        AS artist_region,
               a.state         AS artist_state,
               a.photo_url     AS artist_photo,
               a.bio           AS artist_bio,
               a.instagram_url AS artist_instagram,
               a.fair_payment_verified,

               d.full_name     AS designer_name,
               d.studio_name,
               d.city          AS designer_city,

               m.name          AS manufacturer_name,
               m.city          AS manufacturer_city,
               m.state         AS manufacturer_state,
               m.gots_certified AS manufacturer_gots,
               m.sa8000_certified AS manufacturer_sa8000
           FROM product_creative_chain pcc
           LEFT JOIN artists       a ON a.id  = pcc.artist_id
           LEFT JOIN designers     d ON d.id  = pcc.designer_id
           LEFT JOIN manufacturers m ON m.id  = pcc.manufacturer_id
           WHERE pcc.product_id = %s""",
        (pid,)
    )
    # Strip financial fields from public response
    if story:
        story = dict(story)
        for field in ("art_purchase_price", "design_fee", "payment_rate"):
            story.pop(field, None)

    return ok({"story": serialise(story) if story else None})


@story_bp.route("/<int:pid>/story", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def set_product_story(pid):
    """
    Create or update the creative chain for a product.
    Body: {
        artist_id?,           ID of the artist who created the art
        art_title?,           name of the specific artwork used
        art_purchase_date?,
        art_purchase_price?,  what Silasya paid the artist (INR) — private
        royalty_pct?,         ongoing royalty % per product sold
        royalty_per_unit?,    flat royalty per product sold (INR)
        art_license_type?,    exclusive | non-exclusive | one-time

        designer_id?,         ID of the designer who designed the product
        design_title?,        name of the product design
        design_date?,
        design_fee?,          design fee paid (INR) — private

        manufacturer_id?,     ID of the manufacturer
        manufacturing_date?,
        manufacturing_country?,
        manufacturing_city?,

        notes?
    }
    """
    if not fetch_one("SELECT id FROM products WHERE id = %s AND is_active = 1", (pid,)):
        return not_found("Product")

    data = sanitise_dict(request.get_json(silent=True) or {})

    fields = {
        "artist_id":              data.get("artist_id"),
        "art_title":              data.get("art_title"),
        "art_purchase_date":      data.get("art_purchase_date"),
        "art_purchase_price":     data.get("art_purchase_price"),
        "royalty_pct":            data.get("royalty_pct"),
        "royalty_per_unit":       data.get("royalty_per_unit"),
        "art_license_type":       data.get("art_license_type"),
        "designer_id":            data.get("designer_id"),
        "design_title":           data.get("design_title"),
        "design_date":            data.get("design_date"),
        "design_fee":             data.get("design_fee"),
        "manufacturer_id":        data.get("manufacturer_id"),
        "manufacturing_date":     data.get("manufacturing_date"),
        "manufacturing_country":  data.get("manufacturing_country", "India"),
        "manufacturing_city":     data.get("manufacturing_city"),
        "notes":                  data.get("notes"),
    }
    # Remove None values
    fields = {k: v for k, v in fields.items() if v is not None}

    existing = fetch_one("SELECT id FROM product_creative_chain WHERE product_id = %s", (pid,))

    if existing:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        execute(f"UPDATE product_creative_chain SET {set_clause} WHERE product_id = %s",
                (*fields.values(), pid))
        msg = "Creative chain updated"
    else:
        fields["product_id"] = pid
        cols = ", ".join(fields.keys())
        vals = ", ".join(["%s"] * len(fields))
        execute(f"INSERT INTO product_creative_chain ({cols}) VALUES ({vals})", tuple(fields.values()))
        msg = "Creative chain created"

    # Blockchain entry
    bc_data = {}
    if data.get("artist_id"):   bc_data["artist_id"]   = data["artist_id"]
    if data.get("designer_id"): bc_data["designer_id"] = data["designer_id"]
    if data.get("manufacturer_id"): bc_data["manufacturer_id"] = data["manufacturer_id"]
    if bc_data:
        append_chain_entry(pid, "UPDATE",
                           {"layer": "3_creative_chain", **bc_data},
                           recorded_by=str(g.current_user["sub"]))

    log_audit_event("SET_PRODUCT_STORY", "product_creative_chain",
                    resource_id=str(pid), user_id=g.current_user["sub"])
    return created({"message": msg})
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
