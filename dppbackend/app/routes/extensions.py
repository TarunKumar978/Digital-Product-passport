from flask import Blueprint, request, g
from app.db import fetch_one, execute
from app.utils.auth import require_auth
from app.utils.helpers import ok, created, bad_request, not_found, require_fields, serialise
from app.utils.blockchain import append_chain_entry
from app.security import sanitise_dict, log_audit_event

extensions_bp = Blueprint("extensions", __name__, url_prefix="/api/products")

def _get_product(pid):
    return fetch_one("SELECT id, product_type, brand_id FROM products WHERE id = %s AND is_active = 1", (pid,))

@extensions_bp.route("/<int:pid>/toy-safety", methods=["GET"])
def get_toy_safety(pid):
    if not _get_product(pid): return not_found("Product")
    data = fetch_one("SELECT * FROM toy_safety WHERE product_id = %s", (pid,))
    if not data: return not_found("Toy safety data")
    return ok(serialise(dict(data)))

@extensions_bp.route("/<int:pid>/toy-safety", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def set_toy_safety(pid):
    if not _get_product(pid): return not_found("Product")
    data = sanitise_dict(request.get_json(silent=True) or {})
    execute("UPDATE products SET product_type = 'WOODEN_TOY' WHERE id = %s", (pid,))
    fields = {"age_rating": data.get("age_rating"), "safety_test_standard": data.get("safety_test_standard","EN71"), "ce_marking_number": data.get("ce_marking_number"), "non_toxic_finish": int(data.get("non_toxic_finish",1)), "wood_species": data.get("wood_species"), "wood_origin_state": data.get("wood_origin_state"), "natural_dyes_only": int(data.get("natural_dyes_only",1)), "small_parts_warning": int(data.get("small_parts_warning",0)), "eu_authorised_rep_name": data.get("eu_authorised_rep_name"), "eu_authorised_rep_email": data.get("eu_authorised_rep_email")}
    fields = {k:v for k,v in fields.items() if v is not None}
    existing = fetch_one("SELECT id FROM toy_safety WHERE product_id = %s", (pid,))
    if existing:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        execute(f"UPDATE toy_safety SET {set_clause} WHERE product_id = %s", (*fields.values(), pid))
    else:
        cols = ", ".join(fields.keys()); vals = ", ".join(["%s"]*len(fields))
        execute(f"INSERT INTO toy_safety (product_id, {cols}) VALUES (%s, {vals})", (pid, *fields.values()))
    return created({"message": "Toy safety saved"})

@extensions_bp.route("/<int:pid>/art-provenance", methods=["GET"])
def get_art_provenance(pid):
    if not _get_product(pid): return not_found("Product")
    data = fetch_one("SELECT * FROM art_provenance WHERE product_id = %s", (pid,))
    if not data: return not_found("Art provenance data")
    return ok(serialise(dict(data)))

@extensions_bp.route("/<int:pid>/art-provenance", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def set_art_provenance(pid):
    if not _get_product(pid): return not_found("Product")
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("art_form",))
    if missing: return bad_request(f"'{missing}' is required")
    execute("UPDATE products SET product_type = 'ART_CRAFT' WHERE id = %s", (pid,))
    fields = {"art_form": data["art_form"], "art_form_region": data.get("art_form_region"), "technique_description": data.get("technique_description"), "technique_duration_hrs": data.get("technique_duration_hrs"), "pigment_type": data.get("pigment_type"), "pigment_description": data.get("pigment_description"), "gi_tag_name": data.get("gi_tag_name"), "gi_cert_number": data.get("gi_cert_number"), "edition_type": data.get("edition_type"), "edition_number": data.get("edition_number")}
    fields = {k:v for k,v in fields.items() if v is not None}
    existing = fetch_one("SELECT id FROM art_provenance WHERE product_id = %s", (pid,))
    if existing:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        execute(f"UPDATE art_provenance SET {set_clause} WHERE product_id = %s", (*fields.values(), pid))
    else:
        cols = ", ".join(fields.keys()); vals = ", ".join(["%s"]*len(fields))
        execute(f"INSERT INTO art_provenance (product_id, {cols}) VALUES (%s, {vals})", (pid, *fields.values()))
    return created({"message": "Art provenance saved"})

@extensions_bp.route("/<int:pid>/home-decor", methods=["GET"])
def get_home_decor(pid):
    if not _get_product(pid): return not_found("Product")
    data = fetch_one("SELECT * FROM home_decor_data WHERE product_id = %s", (pid,))
    if not data: return not_found("Home decor data")
    return ok(serialise(dict(data)))

@extensions_bp.route("/<int:pid>/home-decor", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def set_home_decor(pid):
    if not _get_product(pid): return not_found("Product")
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("primary_material",))
    if missing: return bad_request(f"'{missing}' is required")
    execute("UPDATE products SET product_type = 'HOME_DECOR' WHERE id = %s", (pid,))
    fields = {"primary_material": data["primary_material"], "secondary_material": data.get("secondary_material"), "surface_finish": data.get("surface_finish"), "recycled_content_pct": data.get("recycled_content_pct"), "repair_difficulty": data.get("repair_difficulty")}
    fields = {k:v for k,v in fields.items() if v is not None}
    existing = fetch_one("SELECT id FROM home_decor_data WHERE product_id = %s", (pid,))
    if existing:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        execute(f"UPDATE home_decor_data SET {set_clause} WHERE product_id = %s", (*fields.values(), pid))
    else:
        cols = ", ".join(fields.keys()); vals = ", ".join(["%s"]*len(fields))
        execute(f"INSERT INTO home_decor_data (product_id, {cols}) VALUES (%s, {vals})", (pid, *fields.values()))
    return created({"message": "Home decor saved"})

@extensions_bp.route("/<int:pid>/spice-passport", methods=["GET"])
def get_spice_passport(pid):
    if not _get_product(pid): return not_found("Product")
    data = fetch_one("SELECT * FROM spice_passports WHERE product_id = %s", (pid,))
    if not data: return not_found("Spice passport")
    return ok(serialise(dict(data)))

@extensions_bp.route("/<int:pid>/spice-passport", methods=["POST"])
@require_auth(roles=["admin", "brand_partner"])
def set_spice_passport(pid):
    if not _get_product(pid): return not_found("Product")
    data = sanitise_dict(request.get_json(silent=True) or {})
    missing = require_fields(data, ("spice_type", "origin_state", "lot_number", "harvest_date"))
    if missing: return bad_request(f"'{missing}' is required")
    execute("UPDATE products SET product_type = 'SPICE', brand_id = 'shumitra' WHERE id = %s", (pid,))
    fields = {"spice_type": data["spice_type"], "origin_state": data["origin_state"], "lot_number": data["lot_number"], "harvest_date": data["harvest_date"], "origin_district": data.get("origin_district"), "farm_name": data.get("farm_name"), "pesticide_test_result": data.get("pesticide_test_result"), "aflatoxin_test_result": data.get("aflatoxin_test_result"), "spices_board_cert_number": data.get("spices_board_cert_number"), "fssai_license_number": data.get("fssai_license_number"), "traces_nt_reference": data.get("traces_nt_reference"), "fda_prior_notice_number": data.get("fda_prior_notice_number")}
    fields = {k:v for k,v in fields.items() if v is not None}
    existing = fetch_one("SELECT id FROM spice_passports WHERE product_id = %s", (pid,))
    if existing:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        execute(f"UPDATE spice_passports SET {set_clause} WHERE product_id = %s", (*fields.values(), pid))
    else:
        cols = ", ".join(fields.keys()); vals = ", ".join(["%s"]*len(fields))
        execute(f"INSERT INTO spice_passports (product_id, {cols}) VALUES (%s, {vals})", (pid, *fields.values()))
    return created({"message": "Spice passport saved"})

@extensions_bp.route("/<int:pid>/spice-passport/export-readiness", methods=["GET"])
def spice_export_readiness(pid):
    if not _get_product(pid): return not_found("Product")
    sp = fetch_one("SELECT * FROM spice_passports WHERE product_id = %s", (pid,))
    if not sp: return not_found("Spice passport")
    eu_checks = {"Pesticide test passed": sp["pesticide_test_result"]=="pass", "Aflatoxin test passed": sp["aflatoxin_test_result"]=="pass", "Phytosanitary certificate": bool(sp["phytosanitary_cert_number"]), "TRACES NT": bool(sp["traces_nt_reference"]), "Spices Board cert": bool(sp["spices_board_cert_number"]), "FSSAI license": bool(sp["fssai_license_number"])}
    us_checks = {"Pesticide test passed": sp["pesticide_test_result"]=="pass", "FDA Prior Notice": bool(sp["fda_prior_notice_number"]), "FSSAI license": bool(sp["fssai_license_number"])}
    return ok({"eu": {"ready": all(eu_checks.values()), "checks": eu_checks, "missing": [k for k,v in eu_checks.items() if not v]}, "us": {"ready": all(us_checks.values()), "checks": us_checks, "missing": [k for k,v in us_checks.items() if not v]}})
