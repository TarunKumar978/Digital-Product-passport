import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g, current_app


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(user_id: int, role: str) -> str:
    expiry = datetime.utcnow() + timedelta(hours=current_app.config.get("JWT_EXPIRY_HOURS", 8))
    return jwt.encode(
        {"sub": user_id, "role": role, "exp": expiry},
        current_app.config["SECRET_KEY"],
        algorithm="HS256"
    )


def decode_token(token: str) -> dict:
    return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_sub": False})


def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401
            try:
                payload = decode_token(auth.split(" ", 1)[1])
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except Exception:
                return jsonify({"error": "Invalid token"}), 401
            if roles and payload.get("role") not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            g.current_user = payload
            return f(*args, **kwargs)
        return wrapped
    return decorator
