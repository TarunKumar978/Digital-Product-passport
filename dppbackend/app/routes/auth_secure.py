"""
Silasya Earth — Hardened Auth Routes
======================================
Replaces app/routes/auth.py

Security additions:
  - Brute-force protection: 5 failed logins → 15-min lockout per email
  - Logout endpoint that blacklists the JWT
  - Password strength validation on register
  - Constant-time email lookup (prevents timing-based user enumeration)
  - jti (JWT ID) added to every token for revocation tracking
"""

import uuid
import re
import time
from datetime import datetime, timedelta

import jwt
from flask import Blueprint, request, g, current_app, jsonify

from app.db import fetch_one, execute
from app.utils.auth import require_auth, hash_password, verify_password, create_token, decode_token
from app.utils.helpers import ok, bad_request, not_found, conflict
from app.security import log_audit_event, sanitise_dict, blacklist_token

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# ── Brute-force tracking (in-memory; use Redis in production) ─────────────────
# { email_lower: {"attempts": int, "locked_until": float} }
_login_attempts: dict[str, dict] = {}

MAX_ATTEMPTS  = 5
LOCKOUT_SECS  = 15 * 60   # 15 minutes

# ── Password policy ───────────────────────────────────────────────────────────
_PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,128}$"
)

def _check_password_strength(password: str) -> str | None:
    """Return an error message, or None if the password is strong enough."""
    if len(password) < 10:
        return "Password must be at least 10 characters"
    if not _PASSWORD_RE.match(password):
        return "Password must contain uppercase, lowercase, a digit, and a special character"
    return None


# ── REGISTER ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    data = sanitise_dict(request.get_json(silent=True) or {})
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role     = data.get("role", "brand_partner")

    # Validate
    if not name or not email or not password:
        return bad_request("name, email and password are required")

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return bad_request("Invalid email address")

    pwd_error = _check_password_strength(password)
    if pwd_error:
        return bad_request(pwd_error)

    allowed_roles = {"admin", "brand_partner", "artisan_manager", "regulator"}
    if role not in allowed_roles:
        role = "brand_partner"

    # Only admins can create other admins
    if role == "admin":
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                payload = decode_token(auth_header.split(" ", 1)[1])
                if payload.get("role") != "admin":
                    return jsonify({"error": "Only admins can create admin accounts"}), 403
            except Exception:
                return jsonify({"error": "Only admins can create admin accounts"}), 403
        else:
            return jsonify({"error": "Only admins can create admin accounts"}), 403

    if fetch_one("SELECT id FROM users WHERE email = %s", (email,)):
        return conflict("Email already registered")

    uid = execute(
        "INSERT INTO users (full_name, email, password_hash, role) VALUES (%s,%s,%s,%s)",
        (name, email, hash_password(password), role)
    )
    log_audit_event("REGISTER", "users", resource_id=str(uid))
    return ok({"message": "Account created", "user_id": uid, "role": role}, status=201)


# ── LOGIN ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    data     = sanitise_dict(request.get_json(silent=True) or {})
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return bad_request("email and password are required")

    # Brute-force check
    entry = _login_attempts.get(email, {})
    if entry.get("locked_until") and time.time() < entry["locked_until"]:
        remaining = int(entry["locked_until"] - time.time())
        log_audit_event("LOGIN_BLOCKED", "auth", detail={"email": email})
        return jsonify({
            "error": f"Too many failed attempts. Try again in {remaining // 60 + 1} minutes."
        }), 429

    # Constant-time lookup (always query, even for non-existent emails)
    user = fetch_one(
        "SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE email = %s",
        (email,)
    )

    # Always call verify_password (even with a dummy hash) to prevent timing attacks
    dummy_hash = "pbkdf2:sha256:260000$x$" + "a" * 64
    hashed     = user["password_hash"] if user else dummy_hash
    valid      = verify_password(password, hashed)

    if not user or not valid or not user.get("is_active"):
        # Track failed attempt
        attempts = entry.get("attempts", 0) + 1
        locked   = time.time() + LOCKOUT_SECS if attempts >= MAX_ATTEMPTS else None
        _login_attempts[email] = {"attempts": attempts, "locked_until": locked}

        log_audit_event("LOGIN_FAILED", "auth", detail={"email": email, "attempt": attempts})
        return jsonify({"error": "Invalid credentials"}), 401

    # Reset on success
    _login_attempts.pop(email, None)

    # Issue token with jti for revocation
    jti = str(uuid.uuid4())
    expiry_hours = current_app.config.get("JWT_EXPIRY_HOURS", 8)
    payload = {
        "sub":  user["id"],
        "role": user["role"],
        "jti":  jti,
        "iat":  datetime.utcnow(),
        "exp":  datetime.utcnow() + timedelta(hours=expiry_hours),
    }
    token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

    log_audit_event("LOGIN_SUCCESS", "auth", user_id=user["id"])
    return ok({
        "token": token,
        "role": user["role"],
        "name": user["full_name"],
        "expires_in": expiry_hours * 3600,
    })


# ── LOGOUT ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
@require_auth()
def logout():
    """Blacklist the current JWT so it can't be reused after logout."""
    try:
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split(" ", 1)[1]
        payload = decode_token(token)

        jti = payload.get("jti")
        exp = payload.get("exp", 0)

        if jti:
            blacklist_token(jti, float(exp))
            # Also persist to DB for cross-process blacklisting
            try:
                execute(
                    "INSERT IGNORE INTO revoked_tokens (jti, user_id, expires_at) VALUES (%s,%s,%s)",
                    (jti, g.current_user["sub"], datetime.utcfromtimestamp(exp))
                )
            except Exception:
                pass  # In-memory blacklist is the fallback

        log_audit_event("LOGOUT", "auth", user_id=g.current_user["sub"])
    except Exception:
        pass  # Always succeed on logout

    return ok({"message": "Logged out successfully"})


# ── ME ────────────────────────────────────────────────────────────────────────

@auth_bp.route("/me", methods=["GET"])
@require_auth()
def me():
    user = fetch_one(
        "SELECT id, full_name, email, role, created_at FROM users WHERE id = %s",
        (g.current_user["sub"],)
    )
    if not user:
        return not_found("User")
    return ok({"user": dict(user)})


# ── CHANGE PASSWORD ───────────────────────────────────────────────────────────

@auth_bp.route("/change-password", methods=["POST"])
@require_auth()
def change_password():
    data         = sanitise_dict(request.get_json(silent=True) or {})
    current_pwd  = data.get("current_password", "")
    new_pwd      = data.get("new_password", "")

    if not current_pwd or not new_pwd:
        return bad_request("current_password and new_password are required")

    pwd_error = _check_password_strength(new_pwd)
    if pwd_error:
        return bad_request(pwd_error)

    user = fetch_one(
        "SELECT id, password_hash FROM users WHERE id = %s",
        (g.current_user["sub"],)
    )
    if not user or not verify_password(current_pwd, user["password_hash"]):
        log_audit_event("CHANGE_PASSWORD_FAILED", "auth", user_id=g.current_user["sub"])
        return jsonify({"error": "Current password is incorrect"}), 401

    execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (hash_password(new_pwd), g.current_user["sub"])
    )
    log_audit_event("CHANGE_PASSWORD", "auth", user_id=g.current_user["sub"])
    return ok({"message": "Password updated successfully"})