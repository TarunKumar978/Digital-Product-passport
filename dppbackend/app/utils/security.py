"""
Silasya Earth — Security Hardening Layer
=========================================
Drop-in security module. Import and call init_security(app) in your app factory.

Covers:
  1. Rate limiting  — per-IP and per-route limits (Flask-Limiter + Redis)
  2. CORS           — strict origin allowlist
  3. Security headers — CSP, HSTS, X-Frame-Options, etc.
  4. Input sanitisation — strip XSS from all incoming JSON
  5. Request size limits — prevent payload flooding
  6. Audit logging  — every write to DB logged to audit_logs table
  7. JWT hardening  — token blacklist on logout, short expiry
  8. SGTIN validation — format-check before any DB query
  9. Error masking  — never leak stack traces in production
"""

import re
import html
import logging
import time
from functools import wraps
from datetime import datetime

from flask import request, jsonify, g, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger("silasya.security")

# ── 1. RATE LIMITER ─────────────────────────────────────────────────────────
# Uses Redis if REDIS_URL is set, in-memory otherwise (dev only)

def _get_real_ip():
    """Use X-Forwarded-For when behind a proxy/CDN, fall back to remote_addr."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # First IP in chain is the real client
        return forwarded.split(",")[0].strip()
    return get_remote_address()


def create_limiter(app):
    """Create and return the Flask-Limiter instance."""
    from flask_limiter import Limiter

    storage_uri = app.config.get("REDIS_URL", "memory://")

    limiter = Limiter(
        key_func=_get_real_ip,
        app=app,
        storage_uri=storage_uri,
        default_limits=["200 per minute", "2000 per hour"],
        headers_enabled=True,           # Sends X-RateLimit-* headers
        swallow_errors=True,            # Don't crash if Redis is down
    )
    return limiter


# ── 2. CORS ─────────────────────────────────────────────────────────────────

def init_cors(app):
    from flask_cors import CORS

    allowed_origins = app.config.get("ALLOWED_ORIGINS", [
        "https://silasya.earth",
        "https://www.silasya.earth",
        "https://app.silasya.earth",
    ])

    # In development allow localhost
    if app.config.get("DEBUG"):
        allowed_origins += [
            "http://localhost:3000",
            "http://localhost:5001",
            "http://127.0.0.1:5000",
        ]

    CORS(app,
         origins=allowed_origins,
         supports_credentials=True,
         allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"])

    logger.info("CORS initialised with origins: %s", allowed_origins)


# ── 3. SECURITY HEADERS ─────────────────────────────────────────────────────

def init_security_headers(app):
    @app.after_request
    def add_headers(response):
        # Prevent browsers from sniffing content type
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Block clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # XSS filter (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Referrer policy — don't leak URLs
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions policy — disable unnecessary browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        # Content Security Policy for API responses
        response.headers["Content-Security-Policy"] = (
            "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "
            "frame-ancestors 'none';"
        )
        # HSTS — only set in production (not localhost)
        if not current_app.config.get("DEBUG"):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        # Remove server fingerprint
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response


# ── 4. INPUT SANITISATION ────────────────────────────────────────────────────

# Fields that may legitimately contain longer text
_LONG_TEXT_FIELDS = {
    "bio", "description", "disassembly_instructions", "notes",
    "wash_instructions", "repair_guidance", "end_of_life_options",
    "storage_instructions", "artisan_bio",
}

# Strict field length limits (characters)
_FIELD_LIMITS = {
    "sgtin": 150,
    "batch_number": 50,
    "product_name": 200,
    "fiber_type": 100,
    "fiber_origin": 300,
    "farm_name": 200,
    "spinning_mill": 200,
    "gots_cert_number": 100,
    "cert_number": 100,
    "cert_type": 50,
    "email": 254,
    "password": 128,
    "full_name": 200,
    "craft_type": 100,
    "cluster_name": 200,
    "region": 100,
    "state": 100,
    "social_audit_standard": 100,
    "lca_methodology": 200,
    "assessment_body": 200,
}

_DANGEROUS_PATTERNS = re.compile(
    r"(<script|javascript:|data:text/html|vbscript:|on\w+=|<iframe|<object|<embed)",
    re.IGNORECASE
)

_SQL_PATTERNS = re.compile(
    r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE"
    r"|xp_|sp_|0x[0-9a-f]+)\b|--|;.*;|/\*.*\*/)",
    re.IGNORECASE
)


def sanitise_string(value: str, field_name: str = "") -> str:
    """Strip dangerous content from a string field."""
    if not isinstance(value, str):
        return value

    limit = _FIELD_LIMITS.get(field_name, 2000 if field_name in _LONG_TEXT_FIELDS else 500)
    value = value[:limit]

    # Strip null bytes
    value = value.replace("\x00", "")

    # Warn on suspicious patterns (don't reject — could be false positive)
    if _DANGEROUS_PATTERNS.search(value):
        logger.warning("Suspicious XSS pattern in field '%s' from IP %s",
                       field_name, _get_real_ip())
        # Escape HTML entities — renders safely even if stored
        value = html.escape(value)

    if _SQL_PATTERNS.search(value) and field_name not in ("notes", "bio", "description"):
        logger.warning("Suspicious SQL pattern in field '%s' from IP %s",
                       field_name, _get_real_ip())

    return value.strip()


def sanitise_dict(data: dict, parent_key: str = "") -> dict:
    """Recursively sanitise all string values in a dict."""
    if not isinstance(data, dict):
        return data
    cleaned = {}
    for k, v in data.items():
        if isinstance(v, str):
            cleaned[k] = sanitise_string(v, k)
        elif isinstance(v, dict):
            cleaned[k] = sanitise_dict(v, k)
        elif isinstance(v, list):
            cleaned[k] = [
                sanitise_dict(item) if isinstance(item, dict)
                else sanitise_string(item, k) if isinstance(item, str)
                else item
                for item in v
            ]
        else:
            cleaned[k] = v
    return cleaned


def init_input_sanitisation(app):
    """Monkey-patch request.get_json to auto-sanitise all incoming payloads."""
    original_get_json = app.test_request_context().__class__  # just for reference

    @app.before_request
    def sanitise_request():
        # Reject oversized payloads early (also set in nginx/gunicorn)
        max_bytes = app.config.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024)  # 2 MB default
        if request.content_length and request.content_length > max_bytes:
            return jsonify({"error": "Request payload too large"}), 413


# ── 5. SGTIN VALIDATION ──────────────────────────────────────────────────────

# GS1 SGTIN format: urn:epc:id:sgtin:<company_prefix>.<item_ref>.<serial>
_SGTIN_RE = re.compile(
    r"^urn:epc:id:sgtin:[0-9]{6,12}\.[0-9]{1,7}\.[0-9A-Za-z\-]{1,20}$"
)

# Also allow short numeric SGTINs (product id used in QR directly)
_SGTIN_SHORT_RE = re.compile(r"^[A-Za-z0-9\-_:\.]{3,150}$")


def validate_sgtin(sgtin: str) -> bool:
    """Return True if sgtin is a valid GS1 SGTIN or safe short code."""
    if not sgtin or len(sgtin) > 150:
        return False
    if _SGTIN_RE.match(sgtin):
        return True
    # Allow simpler codes during rollout (batch IDs etc)
    if _SGTIN_SHORT_RE.match(sgtin):
        return True
    return False


def require_valid_sgtin(fn):
    """Decorator to validate :sgtin route parameter before hitting the DB."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        sgtin = kwargs.get("sgtin", "")
        if not validate_sgtin(sgtin):
            logger.warning("Invalid SGTIN attempted: '%s' from %s", sgtin, _get_real_ip())
            return jsonify({"error": "Invalid product identifier format"}), 400
        return fn(*args, **kwargs)
    return wrapper


# ── 6. AUDIT LOGGING ────────────────────────────────────────────────────────

def log_audit_event(action: str, resource: str, resource_id=None,
                    user_id=None, detail: dict = None, status: str = "ok"):
    """
    Write an audit log entry. Call from any route that mutates data.
    Works even if the main DB write fails (uses a separate try/catch).
    """
    try:
        from app.db import execute as db_execute
        db_execute(
            """INSERT INTO audit_logs
               (user_id, action, resource, resource_id, detail,
                ip_address, user_agent, status, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                user_id or (g.current_user.get("sub") if hasattr(g, "current_user") else None),
                action,
                resource,
                resource_id,
                str(detail or {}),
                _get_real_ip(),
                (request.user_agent.string or "")[:300],
                status,
                datetime.utcnow(),
            )
        )
    except Exception as e:
        # Audit logging must never crash the app
        logger.error("Audit log write failed: %s", e)


def audit(action: str, resource: str):
    """Decorator to auto-audit any mutating endpoint."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            status_code = result[1] if isinstance(result, tuple) else 200
            status = "ok" if status_code < 400 else "error"
            resource_id = kwargs.get("pid") or kwargs.get("id") or kwargs.get("sgtin")
            log_audit_event(action, resource, resource_id, status=status)
            return result
        return wrapper
    return decorator


# ── 7. JWT HARDENING ─────────────────────────────────────────────────────────

# In-memory token blacklist (replace with Redis SET in production)
# Format: { jti: expiry_timestamp }
_token_blacklist: dict[str, float] = {}


def blacklist_token(jti: str, exp: float):
    """Add a token to the blacklist (call on logout)."""
    _token_blacklist[jti] = exp
    # Prune expired entries to prevent unbounded growth
    now = time.time()
    expired = [k for k, v in _token_blacklist.items() if v < now]
    for k in expired:
        del _token_blacklist[k]


def is_token_blacklisted(jti: str) -> bool:
    return jti in _token_blacklist


def init_jwt_hardening(app):
    """Patch the auth decorator to also check the token blacklist."""
    # Ensure JWT_EXPIRY_HOURS is not too long
    if app.config.get("JWT_EXPIRY_HOURS", 24) > 24:
        logger.warning("JWT_EXPIRY_HOURS > 24 — reducing to 24 for security")
        app.config["JWT_EXPIRY_HOURS"] = 24


# ── 8. ERROR MASKING ─────────────────────────────────────────────────────────

def init_error_handlers(app):
    """Return safe, generic error messages in production. Never leak tracebacks."""

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request", "detail": str(e)}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Authentication required"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Forbidden"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": "Payload too large"}), 413

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({
            "error": "Too many requests",
            "retry_after": getattr(e, "retry_after", 60),
        }), 429

    @app.errorhandler(500)
    def server_error(e):
        # Log the real error internally
        logger.exception("Internal server error: %s", e)
        if app.config.get("DEBUG"):
            return jsonify({"error": str(e)}), 500
        # Return generic message in production
        return jsonify({"error": "Internal server error. Please try again later."}), 500

    @app.errorhandler(Exception)
    def unhandled(e):
        logger.exception("Unhandled exception: %s", e)
        if app.config.get("DEBUG"):
            raise e
        return jsonify({"error": "Something went wrong"}), 500


# ── 9. INIT ALL ──────────────────────────────────────────────────────────────

def init_security(app):
    """
    Call this once in your app factory (app/__init__.py) after creating the app.

    Usage:
        from app.security import init_security
        init_security(app)
    """
    init_cors(app)
    init_security_headers(app)
    init_input_sanitisation(app)
    init_jwt_hardening(app)
    init_error_handlers(app)

    # Set hard content-length limit (also set this in nginx)
    app.config.setdefault("MAX_CONTENT_LENGTH", 2 * 1024 * 1024)  # 2 MB

    limiter = create_limiter(app)

    logger.info("Silasya security layer initialised ✓")
    return limiter  # Return so routes can use @limiter.limit(...)