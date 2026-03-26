from flask import jsonify
import json
from datetime import datetime, date
from decimal import Decimal


def serialise(obj):
    if isinstance(obj, list):
        return [serialise(i) for i in obj]
    if isinstance(obj, dict):
        return {k: serialise(v) for k, v in obj.items()}
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    return obj


def ok(data=None, status=200):
    return jsonify({"status": "ok", "data": data}), status


def created(data=None):
    return jsonify({"status": "ok", "data": data}), 201


def bad_request(msg):
    return jsonify({"status": "error", "error": msg}), 400


def not_found(resource="Resource"):
    return jsonify({"status": "error", "error": f"{resource} not found"}), 404


def conflict(msg):
    return jsonify({"status": "error", "error": msg}), 409


def require_fields(data, fields):
    for f in fields:
        if not data.get(f):
            return f
    return None


def paginate(request, default_limit=20):
    page  = max(1, int(request.args.get("page", 1)))
    limit = min(100, int(request.args.get("limit", default_limit)))
    return page, limit
