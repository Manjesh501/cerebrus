"""Routes Blueprint — /realtime, /api/realtime/*."""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, render_template, request

logger = logging.getLogger(__name__)
bp = Blueprint("realtime", __name__)


def _components() -> dict:
    return current_app.extensions["cerberus_components"]


@bp.route("/realtime", methods=["GET", "POST"])
def realtime_monitoring():
    """Render or manage the real-time monitoring UI."""
    components = _components()
    monitor = components.get("realtime_monitor", {})
    instance = monitor.get("instance")
    if instance is None:
        return render_template("realtime.html", status="not_initialized")

    if request.method == "POST":
        action = request.form.get("action", "")
        try:
            if action == "start":
                directory = request.form.get("directory", ".")
                instance.start_monitoring(directory)
                return render_template("realtime.html", status="running", directory=directory)
            if action == "stop":
                instance.stop_monitoring()
                return render_template("realtime.html", status="stopped")
        except Exception as exc:
            logger.error("Realtime monitor action '%s' failed: %s", action, exc)
            return render_template("realtime.html", status="error", error=str(exc))

    status = "running" if getattr(instance, "is_running", lambda: False)() else "stopped"
    return render_template("realtime.html", status=status)


@bp.route("/api/realtime/start", methods=["POST"])
def start_realtime():
    """Start the real-time file-system monitor."""
    components = _components()
    instance = components.get("realtime_monitor", {}).get("instance")
    if instance is None:
        return jsonify({"error": "Realtime monitor not available"}), 503

    data = request.get_json(silent=True) or {}
    directory = data.get("directory", ".")
    try:
        instance.start_monitoring(directory)
        return jsonify({"status": "started", "directory": directory})
    except Exception as exc:
        logger.error("Failed to start realtime monitor: %s", exc)
        return jsonify({"error": str(exc)}), 500


@bp.route("/api/realtime/stop", methods=["POST"])
def stop_realtime():
    """Stop the real-time file-system monitor."""
    components = _components()
    instance = components.get("realtime_monitor", {}).get("instance")
    if instance is None:
        return jsonify({"error": "Realtime monitor not available"}), 503
    try:
        instance.stop_monitoring()
        return jsonify({"status": "stopped"})
    except Exception as exc:
        logger.error("Failed to stop realtime monitor: %s", exc)
        return jsonify({"error": str(exc)}), 500


@bp.route("/api/realtime/status", methods=["GET"])
def get_realtime_status():
    """Return current state of the realtime monitor."""
    components = _components()
    instance = components.get("realtime_monitor", {}).get("instance")
    if instance is None:
        return jsonify({"status": "unavailable"})
    is_running = getattr(instance, "is_running", lambda: False)()
    return jsonify({"status": "running" if is_running else "stopped"})


@bp.route("/api/realtime/threats", methods=["GET"])
def get_realtime_threats():
    """Return threats detected since monitoring started."""
    components = _components()
    instance = components.get("realtime_monitor", {}).get("instance")
    if instance is None:
        return jsonify({"threats": [], "error": "Monitor not available"})
    try:
        threats = getattr(instance, "get_recent_threats", lambda: [])()
        return jsonify({"threats": threats})
    except Exception as exc:
        logger.error("Failed to get realtime threats: %s", exc)
        return jsonify({"threats": [], "error": str(exc)})
