"""Routes Blueprint — /api/analyze, /api/scan-url, /api/scan-hostname, /api/status."""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request

from cerberus.config import RESULTS_FOLDER, UPLOAD_FOLDER
from cerberus.utils import (
    allowed_file,
    calculate_hash,
    make_json_serializable,
    safe_filename,
    safe_join,
)
from cerberus.core.analysis import fallback_detect_malware

try:
    import validators  # type: ignore[import]
    _has_validators = True
except ImportError:
    _has_validators = False

logger = logging.getLogger(__name__)
bp = Blueprint("api", __name__, url_prefix="/api")


def _components() -> dict:
    return current_app.extensions["cerberus_components"]


# ---------------------------------------------------------------------------
# /api/analyze
# ---------------------------------------------------------------------------

@bp.route("/analyze", methods=["POST"])
def api_analyze():
    """JSON API endpoint for file analysis — mirrors /analyze but always returns JSON."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    header = file.read(2048)
    file.seek(0)
    if not allowed_file(file.filename, header):
        return jsonify({"error": "Unsupported file type"}), 400

    filename = safe_filename(file.filename)
    file_path = safe_join(UPLOAD_FOLDER, filename)
    if file_path is None:
        return jsonify({"error": "Invalid file path"}), 400

    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        file.save(file_path)
        logger.info("API: saved upload %s", file_path)

        components = _components()
        bp_key = "batch_processor"
        if (
            components.get(bp_key, {}).get("status") == "available"
            and components[bp_key].get("instance")
        ):
            ts = time.strftime("%Y%m%d_%H%M%S")
            batch_dir = os.path.join(RESULTS_FOLDER, f"api_{ts}")
            os.makedirs(batch_dir, exist_ok=True)
            result = components[bp_key]["instance"]._process_single_file(
                file_path, batch_dir
            )
            # Safety net: zero-confidence result → run pattern-matching fallback
            if not result.get("is_malware") and result.get("confidence", 0) == 0:
                logger.info("Primary analysis inconclusive for %s — running fallback", filename)
                is_mal = fallback_detect_malware(file_path)
                if is_mal:
                    result.update({
                        "is_malware": True,
                        "confidence": 0.6,
                        "malware_type": "Suspicious",
                        "risk_score": 65,
                        "analysis_method": (result.get("analysis_method", "") + ",Fallback").lstrip(","),
                    })
            return jsonify(make_json_serializable(result))

        # Fallback
        is_mal = fallback_detect_malware(file_path)
        return jsonify({
            "filename": filename,
            "file_hash": calculate_hash(file_path),
            "is_malware": is_mal,
            "confidence": 0.6 if is_mal else 0.2,
            "malware_type": "Suspicious" if is_mal else "Clean",
            "risk_score": 65 if is_mal else 15,
            "analysis_method": "Fallback",
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as exc:
        logger.error("API analyze error for %s: %s", filename, exc, exc_info=True)
        try:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
        except OSError:
            pass
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# /api/scan-url
# ---------------------------------------------------------------------------

@bp.route("/scan-url", methods=["POST"])
def api_scan_url():
    """Scan a URL via VirusTotal or available threat intel."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if _has_validators and not validators.url(url):
        return jsonify({"error": "Invalid URL format"}), 400

    components = _components()
    result: dict = {"url": url, "threat_detected": False, "details": {}}

    if components.get("vt_scanner", {}).get("status") == "available":
        try:
            vt_result = components["vt_scanner"]["instance"].scan_url(url)
            result["details"]["virustotal"] = vt_result
            if vt_result.get("positives", 0) > 2:
                result["threat_detected"] = True
        except Exception as exc:
            logger.warning("VT URL scan failed for %s: %s", url, exc)
            result["details"]["virustotal"] = {"error": str(exc)}

    if components.get("threat_intel", {}).get("status") == "available":
        try:
            intel = components["threat_intel"]["instance"].check_url(url)
            result["details"]["threat_intel"] = intel
            if intel.get("malicious", False):
                result["threat_detected"] = True
        except Exception as exc:
            logger.warning("Threat intel URL check failed for %s: %s", url, exc)
            result["details"]["threat_intel"] = {"error": str(exc)}

    return jsonify(result)


# ---------------------------------------------------------------------------
# /api/scan-hostname
# ---------------------------------------------------------------------------

@bp.route("/scan-hostname", methods=["POST"])
def api_scan_hostname():
    """Look up a hostname in threat intelligence feeds."""
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "").strip()

    if not hostname:
        return jsonify({"error": "No hostname provided"}), 400

    components = _components()
    result: dict = {"hostname": hostname, "threat_detected": False, "details": {}}

    if components.get("threat_intel", {}).get("status") == "available":
        try:
            intel = components["threat_intel"]["instance"].check_hostname(hostname)
            result["details"]["threat_intel"] = intel
            if intel.get("malicious", False):
                result["threat_detected"] = True
        except Exception as exc:
            logger.warning("Threat intel hostname check failed for %s: %s", hostname, exc)
            result["details"]["threat_intel"] = {"error": str(exc)}
    else:
        result["details"]["note"] = "Threat intelligence not available"

    return jsonify(result)


# ---------------------------------------------------------------------------
# /api/status
# ---------------------------------------------------------------------------

@bp.route("/status", methods=["GET"])
def api_status():
    """Return a machine-readable component availability map."""
    components = _components()
    status = {
        name: {
            "status": info.get("status", "unavailable"),
            "available": info.get("status") == "available",
        }
        for name, info in components.items()
    }
    overall = "operational" if any(v["available"] for v in status.values()) else "degraded"
    return jsonify({"status": overall, "components": status})
