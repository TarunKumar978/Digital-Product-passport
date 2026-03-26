"""
Layer 7 — Blockchain Verification
Per DPP doc:
  - All data entries are immutable and timestamped on a decentralised ledger
  - Provides irrefutable proof to EU regulators data has not been greenwashed
  - Tamper-evident SHA-256 hash chain stored in MySQL (mirrors external ledger)
"""

from flask import Blueprint, request, g

from app.db import fetch_one, fetch_all
from app.utils.auth import require_auth
from app.utils.blockchain import append_chain_entry, verify_chain
from app.utils.helpers import ok, not_found, bad_request, created, serialise

layer7_bp = Blueprint("layer7", __name__, url_prefix="/api/products/<int:pid>/blockchain")


def _check_product(pid):
    return fetch_one("SELECT id FROM products WHERE id = %s AND is_active = 1", (pid,))


@layer7_bp.route("", methods=["GET"])
def get_chain(pid):
    """Return the full blockchain chain for this product."""
    if not _check_product(pid):
        return not_found("Product")

    entries = fetch_all(
        """SELECT id, entry_type, data_hash, previous_hash,
                  ledger_ref, recorded_by, recorded_at
           FROM blockchain_entries
           WHERE product_id = %s
           ORDER BY id ASC""",
        (pid,)
    )
    return ok({
        "product_id":   pid,
        "total_entries": len(entries),
        "chain":        serialise(list(entries)),
    })


@layer7_bp.route("/verify", methods=["GET"])
def verify(pid):
    """
    Verify the integrity of this product's full blockchain chain.
    Checks that every entry's previous_hash matches the prior entry's data_hash.
    Returns: { valid, entries, broken_at }
    """
    if not _check_product(pid):
        return not_found("Product")

    result = verify_chain(pid)
    return ok({
        "product_id": pid,
        **result,
        "message": (
            "Chain is intact — no tampering detected"
            if result["valid"]
            else f"Chain BROKEN at entry id {result['broken_at']} — data may have been altered"
        )
    })


@layer7_bp.route("/audit-entry", methods=["POST"])
@require_auth(roles=["admin"])
def add_audit_entry(pid):
    """
    Manually append an AUDIT entry to the chain
    (e.g. after an external inspection or customs clearance).
    Body: { note*, ledger_ref? }
    """
    if not _check_product(pid):
        return not_found("Product")

    data = request.get_json(silent=True) or {}
    if not data.get("note"):
        return bad_request("'note' is required")

    h = append_chain_entry(
        pid, "AUDIT",
        {"note": data["note"], "auditor": str(g.current_user["sub"])},
        recorded_by=str(g.current_user["sub"]),
        ledger_ref=data.get("ledger_ref"),
    )
    return created({"message": "Audit entry added", "data_hash": h})


@layer7_bp.route("/latest", methods=["GET"])
def latest_entry(pid):
    """Return only the latest chain entry (most recent hash)."""
    if not _check_product(pid):
        return not_found("Product")

    entry = fetch_one(
        "SELECT * FROM blockchain_entries WHERE product_id = %s ORDER BY id DESC LIMIT 1",
        (pid,)
    )
    if not entry:
        return not_found("No blockchain entries")
    return ok(serialise(entry))