"""Routes Blueprint — /analyze, /batch, /batch/export."""
from __future__ import annotations

import json
import logging
import os
import time
from csv import writer as csv_writer
from io import StringIO

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    render_template,
    request,
)

from cerberus.config import BATCH_FOLDER, RESULTS_FOLDER, UPLOAD_FOLDER
from cerberus.utils import (
    allowed_file,
    calculate_hash,
    get_file_category,
    make_json_serializable,
    safe_filename,
    safe_join,
    valid_timestamp,
)
from cerberus.core.analysis import fallback_detect_malware

logger = logging.getLogger(__name__)
bp = Blueprint("analysis", __name__)


def _components() -> dict:
    return current_app.extensions["cerberus_components"]


# ---------------------------------------------------------------------------
# /analyze — web UI file upload
# ---------------------------------------------------------------------------

@bp.route("/analyze", methods=["POST"])
def analyze() -> tuple:
    """Accept a file upload and return a JSON analysis result."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        logger.error("Empty filename in upload")
        return render_template("modern_index.html", error="No file selected"), 400

    header = file.read(2048)
    file.seek(0)

    if not allowed_file(file.filename, header):
        logger.warning("File type rejected: %s", file.filename)
        return jsonify({"error": "Unsupported file type"}), 400

    filename = safe_filename(file.filename)
    file_path = safe_join(UPLOAD_FOLDER, filename)
    if file_path is None:
        return jsonify({"error": "Invalid file path"}), 400

    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        file.save(file_path)
        logger.info("Saved upload: %s", file_path)

        components = _components()
        bp_key = "batch_processor"
        if (
            components.get(bp_key, {}).get("status") == "available"
            and components[bp_key].get("instance")
        ):
            ts = time.strftime("%Y%m%d_%H%M%S")
            batch_dir = os.path.join(RESULTS_FOLDER, f"single_{ts}")
            os.makedirs(batch_dir, exist_ok=True)
            result = components[bp_key]["instance"]._process_single_file(
                file_path, batch_dir
            )

            # Safety net: if primary analysers returned no verdict (confidence=0),
            # fall back to pattern-matching so archives with known-bad content are caught.
            if not result.get("is_malware") and result.get("confidence", 0) == 0:
                logger.info(
                    "Primary analysis inconclusive for %s — running pattern-matching fallback",
                    filename,
                )
                is_mal = fallback_detect_malware(file_path)
                if is_mal:
                    result["is_malware"] = True
                    result["confidence"] = 0.6
                    result["malware_type"] = "Suspicious"
                    result["risk_score"] = 65
                    result["analysis_method"] = (result.get("analysis_method", "") + ",Fallback").lstrip(",")

            web_result = {
                "filename": result.get("file_name", filename),
                "file_hash": result.get("file_hash", ""),
                "is_malware": result.get("is_malware", False),
                "confidence": result.get("confidence", 0),
                "malware_type": result.get("malware_type", "Unknown"),
                "risk_score": result.get("risk_score", 0),
                "analysis_method": result.get("analysis_method", ""),
                "processing_time": result.get("processing_time", 0),
                "detailed_results": result.get("detailed_results", {}),
            }
        else:
            logger.warning("BatchProcessor unavailable — using fallback analysis")
            is_mal = fallback_detect_malware(file_path)
            web_result = {
                "filename": filename,
                "file_hash": calculate_hash(file_path),
                "is_malware": is_mal,
                "confidence": 0.6 if is_mal else 0.2,
                "malware_type": "Suspicious" if is_mal else "Clean",
                "risk_score": 65 if is_mal else 15,
                "analysis_method": "Fallback",
                "processing_time": 0.5,
                "detailed_results": {"fallback_analysis": {"method": "pattern_matching"}},
            }

        return jsonify(make_json_serializable(web_result))

    except Exception as exc:
        logger.error("Error processing upload %s: %s", filename, exc, exc_info=True)
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
        return jsonify({"error": f"Error processing file: {exc}"}), 500


# ---------------------------------------------------------------------------
# /batch — batch file upload
# ---------------------------------------------------------------------------

@bp.route("/batch", methods=["GET", "POST"])
def batch_analysis():
    """Render batch upload form (GET) or process a batch upload (POST)."""
    if request.method == "GET":
        return render_template("batch.html")

    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files selected"}), 400

    ts = time.strftime("%Y%m%d_%H%M%S")
    batch_dir = os.path.join(BATCH_FOLDER, ts)
    os.makedirs(batch_dir, exist_ok=True)

    saved_paths: list[str] = []
    for file in files:
        if not file.filename:
            continue
        header = file.read(2048)
        file.seek(0)
        if not allowed_file(file.filename, header):
            logger.warning("Skipping disallowed file: %s", file.filename)
            continue
        filename = safe_filename(file.filename)
        dest = safe_join(batch_dir, filename)
        if dest is None:
            continue
        file.save(dest)
        saved_paths.append(dest)

    if not saved_paths:
        return jsonify({"error": "No valid files in batch"}), 400

    components = _components()
    bp_key = "batch_processor"
    if (
        components.get(bp_key, {}).get("status") == "available"
        and components[bp_key].get("instance")
    ):
        results_dir = os.path.join(RESULTS_FOLDER, f"batch_{ts}")
        os.makedirs(results_dir, exist_ok=True)
        summary = components[bp_key]["instance"].process_files(saved_paths)
        return jsonify({"timestamp": ts, "summary": make_json_serializable(summary)})

    return jsonify({"error": "Batch processor unavailable"}), 503


# ---------------------------------------------------------------------------
# /batch/export/<timestamp>/<format> — export saved results
# ---------------------------------------------------------------------------

@bp.route("/batch/export/<timestamp>/<export_format>")
def export_batch_results(timestamp: str, export_format: str):
    """Export a previous batch run as CSV or JSON."""
    if not valid_timestamp(timestamp):
        return jsonify({"error": "Invalid timestamp format"}), 400

    results_dir = os.path.join(RESULTS_FOLDER, f"batch_{timestamp}")
    if not os.path.exists(results_dir):
        return jsonify({"error": "Results not found"}), 404

    records: list[dict] = []
    for fname in os.listdir(results_dir):
        if fname.endswith(".json") and fname != "summary.json":
            try:
                with open(os.path.join(results_dir, fname)) as fh:
                    records.append(json.load(fh))
            except Exception as exc:
                logger.error("Error reading result file %s: %s", fname, exc)

    fmt = export_format.lower()
    if fmt == "csv":
        buf = StringIO()
        w = csv_writer(buf)
        w.writerow(["Filename", "File Hash", "Is Malware", "Confidence",
                     "Malware Type", "Risk Score", "Analysis Method", "Processing Time"])
        for r in records:
            w.writerow([
                r.get("file_name", ""),
                r.get("file_hash", ""),
                r.get("is_malware", False),
                r.get("confidence", 0),
                r.get("malware_type", ""),
                r.get("risk_score", 0),
                r.get("analysis_method", ""),
                r.get("processing_time", 0),
            ])
        resp = make_response(buf.getvalue())
        resp.headers["Content-Type"] = "text/csv"
        resp.headers["Content-Disposition"] = f"attachment; filename=batch_results_{timestamp}.csv"
        return resp

    if fmt == "json":
        resp = make_response(json.dumps(records, indent=2))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = f"attachment; filename=batch_results_{timestamp}.json"
        return resp

    if fmt == "pdf":
        return jsonify({"message": "PDF export coming soon"}), 501

    return jsonify({"error": "Unsupported format. Use csv or json."}), 400
