"""
Silasya Fusion Pvt Ltd — App Factory
Wires all blueprints for both Silasya (B2C) and Shumitra (B2B) brands.
"""

from flask import Flask
from flask_cors import CORS
from config.settings import Config


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    CORS(app, origins=[
        "http://localhost:3000",
        "http://192.168.1.10:3000",
        "https://uncurable-gaynell-nonresilient.ngrok-free.dev",
    ], supports_credentials=True, allow_headers=["Content-Type", "Authorization", "ngrok-skip-browser-warning", "cf-access-client-id"])

    @app.after_request
    def add_headers(response):
        origin = __import__("flask").request.headers.get("Origin", "")
        if "trycloudflare.com" in origin or "ngrok" in origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["ngrok-skip-browser-warning"] = "true"
        return response

    # ── 1. Security (must be first) ──────────────────────────────────────────
    from app.security import init_security
    limiter = init_security(app)
    app.limiter = limiter

    # ── 2. Blueprints ────────────────────────────────────────────────────────
    from app.routes.auth        import auth_bp
    from app.routes.passport    import passport_bp
    from app.routes.products    import products_bp
    from app.routes.layer2      import layer2_bp
    from app.routes.layer3      import layer3_bp
    from app.routes.layer4      import layer4_bp
    from app.routes.layer5      import layer5_bp
    from app.routes.layer6      import layer6_bp
    from app.routes.layer7      import layer7_bp
    from app.routes.certs       import certs_bp
    from app.routes.artisans    import artisans_bp, clusters_bp
    from app.routes.admin       import admin_bp
    from app.routes.qr          import qr_bp
    from app.routes.extensions  import extensions_bp   # toy, art, home, spice
    from app.routes.shipments   import shipments_bp    # Shumitra B2B export
    from app.routes.creative_chain import (            # Artist · Designer · Manufacturer
        artists_bp, designers_bp, manufacturers_bp, story_bp
    )

    for bp in [
        auth_bp, passport_bp, products_bp,
        layer2_bp, layer3_bp, layer4_bp,
        layer5_bp, layer6_bp, layer7_bp,
        certs_bp, artisans_bp, clusters_bp,
        admin_bp, qr_bp,
        extensions_bp, shipments_bp,
        artists_bp, designers_bp, manufacturers_bp, story_bp,
    ]:
        app.register_blueprint(bp)

    # ── 3. Rate limits ───────────────────────────────────────────────────────
    limiter.limit("60 per minute")(passport_bp)
    limiter.limit("10 per minute")(auth_bp)
    limiter.limit("30 per minute")(qr_bp)
    limiter.limit("30 per minute")(admin_bp)
    limiter.limit("100 per minute")(products_bp)
    limiter.limit("60 per minute")(shipments_bp)

    # ── 4. Health check ──────────────────────────────────────────────────────
    @app.route("/health")
    def health():
        from flask import jsonify
        from app.db import fetch_one
        try:
            fetch_one("SELECT 1")
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({
            "status":  "ok" if db_ok else "degraded",
            "db":      "ok" if db_ok else "error",
            "service": "silasya-dpp",
            "brands":  ["silasya", "shumitra"],
        }), 200 if db_ok else 503


    import os as _os
    from flask import send_from_directory as _sfd
    _FRONTEND_DIR = _os.path.expanduser("~/Desktop/DPP/dppfrontend")

    @app.route("/dppfrontend/<path:filename>")
    def serve_frontend(filename):
        return _sfd(_FRONTEND_DIR, filename)

    @app.route("/dppfrontend/")
    def serve_frontend_index():
        return _sfd(_FRONTEND_DIR, "silasya-passport.html")

    @app.route("/admin.html")
    def serve_admin():
        import os as _os2
        from flask import send_from_directory as _sfd2
        return _sfd2(_os2.path.expanduser("~/Desktop/DPP"), "admin.html")


    import os as _os3
    from flask import send_from_directory as _sfd3
    _UPLOADS_DIR = "/Users/tarunkumar/Desktop/DPP/uploads"
    @app.route("/uploads/<path:filename>")
    def serve_uploads(filename):
        return _sfd3(_UPLOADS_DIR, filename)
    return app
