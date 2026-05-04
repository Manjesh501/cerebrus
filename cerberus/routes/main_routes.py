"""Routes Blueprint — main pages: /, /status, /result/<file_id>."""
from __future__ import annotations

import json
import logging
import os

from flask import Blueprint, current_app, jsonify, render_template, request

from cerberus.config import RESULTS_FOLDER, UPLOAD_FOLDER
from cerberus.utils import get_file_type, make_json_serializable

logger = logging.getLogger(__name__)
bp = Blueprint("main", __name__)


def _components() -> dict:
    return current_app.extensions["cerberus_components"]


@bp.route("/")
def index():
    """Render the main landing page."""
    components = _components()
    available_features = {
        "ml_model": components.get("ml_model", {}).get("status") == "available",
        "docker_sandbox": components.get("docker_sandbox", {}).get("status") == "available",
        "anti_evasion": components.get("anti_evasion", {}).get("status") == "available",
        "threat_intel": components.get("threat_intel", {}).get("status") == "available",
        "vt_scanner": components.get("vt_scanner", {}).get("status") == "available",
        # Template uses 'features.document' not 'features.document_analyzer'
        "document": components.get("document_analyzer", {}).get("status") == "available",
        "realtime": components.get("realtime_monitor", {}).get("status") == "available",
    }
    return render_template("modern_index.html", features=available_features)




@bp.route("/status")
def check_status():
    """Render the component status page."""
    components = _components()
    component_status = {
        name: {
            "status": info.get("status", "unavailable"),
            "error": info.get("error"),
        }
        for name, info in components.items()
    }
    return render_template("status.html", components=component_status)


@bp.route("/result/<file_id>")
def result(file_id: str):
    """Render the analysis result page for a previously analysed file."""
    result_file = os.path.join(RESULTS_FOLDER, f"{file_id}.json")
    if not os.path.exists(result_file):
        return render_template("error.html", error="Result not found"), 404
    try:
        with open(result_file) as fh:
            data = json.load(fh)
        return render_template("modern_index.html", result=data)
    except Exception as exc:
        logger.error("Failed to load result %s: %s", file_id, exc)
        return render_template("error.html", error=str(exc)), 500


@bp.route("/healthz")
def healthz():
    """Lightweight liveness probe for load balancers."""
    return jsonify({"status": "ok"}), 200


@bp.route("/test")
def test_route():
    """Basic smoke-test endpoint."""
    return jsonify({"message": "Cerberus AI Cybershield is operational"})
