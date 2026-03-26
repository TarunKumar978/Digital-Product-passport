"""
QR Code Generation — Silasya TrustTag™
========================================
Generates QR codes that point to the public passport URL.

Routes:
  GET /api/qr/<sgtin>            → QR PNG image (inline)
  GET /api/qr/<sgtin>/download   → QR PNG download
  GET /api/qr/<sgtin>/label      → Printable label HTML (for physical tags)
  POST /api/qr/batch             → Bulk QR for a list of SGTINs (admin only)

Each QR encodes:
  https://<PASSPORT_BASE_URL>/passport.html?sgtin=<sgtin>
"""

import io
import os

import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
from flask import Blueprint, request, Response, current_app, jsonify

from app.db import fetch_one, fetch_all
from app.utils.auth import require_auth
from app.utils.helpers import ok, not_found, bad_request
from app.security import validate_sgtin

qr_bp = Blueprint("qr", __name__, url_prefix="/api/qr")

PASSPORT_BASE_URL = os.getenv("PASSPORT_BASE_URL", "https://silasya.earth")
API_BASE_URL      = os.getenv("API_BASE_URL", "http://localhost:5001")


def _get_product(sgtin):
    return fetch_one(
        """SELECT p.id, p.sgtin, p.product_name, p.batch_number,
                  ac.cluster_name, ac.state
           FROM products p
           LEFT JOIN artisan_clusters ac ON ac.id = p.cluster_id
           WHERE p.sgtin = %s AND p.is_active = 1""",
        (sgtin,)
    )


def _build_qr_png(sgtin: str, size: int = 10) -> bytes:
    """Generate a styled QR code PNG and return raw bytes."""
    url = f"{PASSPORT_BASE_URL}/passport.html?sgtin={sgtin}"

    qr = qrcode.QRCode(
        version=None,           # auto-size
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # 30% recovery
        box_size=size,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    # Styled image with rounded modules — matches Silasya aesthetic
    try:
        img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=RoundedModuleDrawer(),
        )
    except Exception:
        # Fallback to plain QR if styling fails
        img = qr.make_image(fill_color="#3b2a1a", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


# ── INLINE QR IMAGE ───────────────────────────────────────────────────────────

@qr_bp.route("/<sgtin>", methods=["GET"])
def get_qr(sgtin):
    """
    Returns QR code PNG for embedding in admin UI or emails.
    Query param: ?size=10 (box_size, default 10)
    """
    if not validate_sgtin(sgtin):
        return jsonify({"error": "Invalid product identifier"}), 400

    if not _get_product(sgtin):
        return not_found("Product")

    size = min(int(request.args.get("size", 10)), 20)  # cap at 20 to prevent huge images
    png = _build_qr_png(sgtin, size)

    return Response(
        png,
        mimetype="image/png",
        headers={
            "Cache-Control": "public, max-age=86400",  # QR rarely changes
            "Content-Length": str(len(png)),
        }
    )


# ── DOWNLOAD QR ───────────────────────────────────────────────────────────────

@qr_bp.route("/<sgtin>/download", methods=["GET"])
@require_auth(roles=["admin", "brand_partner"])
def download_qr(sgtin):
    """
    Download QR as PNG file — for printing on garment labels.
    Returns high-res version (box_size=20).
    """
    if not validate_sgtin(sgtin):
        return jsonify({"error": "Invalid product identifier"}), 400

    product = _get_product(sgtin)
    if not product:
        return not_found("Product")

    png = _build_qr_png(sgtin, size=20)
    safe_name = (product["product_name"] or sgtin).replace(" ", "_").replace("/", "-")[:40]

    return Response(
        png,
        mimetype="image/png",
        headers={
            "Content-Disposition": f'attachment; filename="silasya_qr_{safe_name}.png"',
            "Cache-Control": "no-cache",
        }
    )


# ── PRINTABLE LABEL HTML ──────────────────────────────────────────────────────

@qr_bp.route("/<sgtin>/label", methods=["GET"])
def get_label(sgtin):
    """
    Returns a print-ready HTML label with:
      - QR code (via /api/qr/<sgtin> endpoint)
      - Product name, batch number, cluster
      - TrustTag™ branding
    Print at 38×38mm or 50×50mm garment tag size.
    """
    if not validate_sgtin(sgtin):
        return jsonify({"error": "Invalid product identifier"}), 400

    product = _get_product(sgtin)
    if not product:
        return not_found("Product")

    p = product
    name    = (p["product_name"] or "Silasya Product").title()
    batch   = p["batch_number"] or ""
    cluster = f"{p['cluster_name']}, {p['state']}" if p.get("cluster_name") else ""
    qr_url  = f"{API_BASE_URL}/api/qr/{sgtin}?size=12"

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>Label — {name}</title>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400&family=DM+Mono:wght@400&display=swap" rel="stylesheet"/>
<style>
  @page {{ size: 50mm 50mm; margin: 0; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    width:50mm; height:50mm;
    display:flex; flex-direction:column;
    align-items:center; justify-content:center;
    font-family:'Cormorant Garamond',serif;
    background:white; padding:3mm;
  }}
  .brand {{
    font-size:5pt; letter-spacing:.15em; text-transform:uppercase;
    color:#8b5e3c; margin-bottom:1.5mm;
    font-family:'Cormorant Garamond',serif; font-weight:300;
  }}
  .qr-wrap {{
    border:0.3mm solid #d4a574; border-radius:2mm;
    padding:1.5mm; background:white;
    display:flex; align-items:center; justify-content:center;
  }}
  .qr-wrap img {{ width:26mm; height:26mm; display:block; }}
  .product-name {{
    font-size:5.5pt; text-align:center; color:#3b2a1a;
    margin-top:1.5mm; line-height:1.2;
    max-width:44mm; font-weight:400;
  }}
  .meta {{
    font-family:'DM Mono',monospace; font-size:4pt;
    color:#8b7355; margin-top:1mm; text-align:center;
  }}
  .trust-tag {{
    font-size:4pt; letter-spacing:.1em; text-transform:uppercase;
    color:#c9973a; margin-top:1mm;
  }}
  @media print {{
    body {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  }}
</style>
</head>
<body>
  <div class="brand">Silasya Earth</div>
  <div class="qr-wrap">
    <img src="{qr_url}" alt="Scan for product passport"/>
  </div>
  <div class="product-name">{name[:45]}</div>
  <div class="meta">{'BATCH #' + batch if batch else ''}{' · ' + cluster if cluster else ''}</div>
  <div class="trust-tag">TrustTag™</div>
</body>
</html>"""

    return Response(html, mimetype="text/html")


# ── BATCH QR DATA ─────────────────────────────────────────────────────────────

@qr_bp.route("/batch", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def batch_qr_info():
    """
    Returns QR URLs for multiple SGTINs at once.
    Body: { "sgtins": ["sgtin1", "sgtin2", ...] }
    Used by admin dashboard to list QRs for a batch of products.
    """
    data   = request.get_json(silent=True) or {}
    sgtins = data.get("sgtins", [])

    if not sgtins or not isinstance(sgtins, list):
        return bad_request("sgtins must be a non-empty list")
    if len(sgtins) > 100:
        return bad_request("Maximum 100 SGTINs per batch request")

    results = []
    for sgtin in sgtins:
        if not validate_sgtin(sgtin):
            results.append({"sgtin": sgtin, "error": "invalid"})
            continue
        product = _get_product(sgtin)
        if not product:
            results.append({"sgtin": sgtin, "error": "not_found"})
            continue
        results.append({
            "sgtin":        sgtin,
            "product_id":   product["id"],
            "product_name": product["product_name"],
            "batch_number": product["batch_number"],
            "qr_url":       f"/api/qr/{sgtin}",
            "download_url": f"/api/qr/{sgtin}/download",
            "label_url":    f"/api/qr/{sgtin}/label",
            "passport_url": f"{PASSPORT_BASE_URL}/passport.html?sgtin={sgtin}",
        })

    return ok({"results": results, "total": len(results)})