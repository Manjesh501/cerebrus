"""Component initialisation — loads all optional analysis modules.

Returns a single dict of ``{name: {status, instance, error}}`` entries that
the application factory stores in ``app.extensions["cerberus_components"]``.
"""
from __future__ import annotations

import importlib.util
import logging

logger = logging.getLogger(__name__)

_COMPONENT_KEYS = [
    "ml_model", "feature_extractor", "malware_type_detector",
    "document_analyzer", "vt_scanner", "dynamic_analyzer",
    "batch_processor", "model_explainer", "realtime_monitor",
    "threat_intel", "anti_evasion",
]


def _slot(status: str = "unavailable", instance=None, error: str | None = None) -> dict:
    return {"status": status, "instance": instance, "error": error}


def init_components(config: dict) -> dict:
    """Attempt to load every analysis component, degrading gracefully on failure.

    Parameters
    ----------
    config:
        The Flask ``app.config`` dict — used to read ``MODEL_PATH`` etc.
    """
    components: dict = {key: _slot() for key in _COMPONENT_KEYS}
    model_path: str = config.get("MODEL_PATH", "ML_model/malwareclassifier-V2.pkl")

    # ------------------------------------------------------------------
    # ML model
    # ------------------------------------------------------------------
    try:
        import joblib
        model = joblib.load(model_path)
        components["ml_model"] = _slot("available", model)
        logger.info("ML model loaded from %s", model_path)
    except Exception as exc:
        components["ml_model"]["error"] = str(exc)
        logger.error("ML model load failed: %s", exc)

    # ------------------------------------------------------------------
    # Feature extractor
    # ------------------------------------------------------------------
    try:
        from feature_extraction import extract_features
        components["feature_extractor"] = _slot("available", extract_features)
        logger.info("Feature extractor loaded")
    except Exception as exc:
        components["feature_extractor"]["error"] = str(exc)
        logger.error("Feature extractor load failed: %s", exc)

    # ------------------------------------------------------------------
    # Malware type detector
    # ------------------------------------------------------------------
    try:
        from malware_types import MalwareTypeDetector
        components["malware_type_detector"] = _slot("available", MalwareTypeDetector())
        logger.info("Malware type detector loaded")
    except Exception as exc:
        components["malware_type_detector"]["error"] = str(exc)
        logger.error("Malware type detector load failed: %s", exc)

    # ------------------------------------------------------------------
    # Document analyzer
    # ------------------------------------------------------------------
    try:
        from document_analyzer import DocumentAnalyzer
        components["document_analyzer"] = _slot("available", DocumentAnalyzer())
        logger.info("Document analyzer loaded")
    except Exception as exc:
        components["document_analyzer"]["error"] = str(exc)
        logger.error("Document analyzer load failed: %s", exc)

    # ------------------------------------------------------------------
    # VirusTotal scanner
    # ------------------------------------------------------------------
    try:
        from vt_api import VirusTotalScanner
        from cerberus.config import VT_API_KEY
        if not VT_API_KEY:
            logger.warning("VT_API_KEY not set — VirusTotal scanning disabled")
            components["vt_scanner"]["error"] = "VT_API_KEY not configured"
        else:
            scanner = VirusTotalScanner(api_key=VT_API_KEY)
            if scanner.enabled:
                components["vt_scanner"] = _slot("available", scanner)
                logger.info("VirusTotal scanner loaded")
            else:
                components["vt_scanner"]["error"] = "Scanner initialised but not enabled"
    except Exception as exc:
        components["vt_scanner"]["error"] = str(exc)
        logger.error("VirusTotal scanner load failed: %s", exc)

    # ------------------------------------------------------------------
    # Dynamic analyzer
    # ------------------------------------------------------------------
    try:
        from dynamic_analysis import DynamicAnalyzer
        components["dynamic_analyzer"] = _slot("available", DynamicAnalyzer())
        logger.info("Dynamic analyzer loaded")
    except Exception as exc:
        components["dynamic_analyzer"]["error"] = str(exc)
        logger.error("Dynamic analyzer load failed: %s", exc)

    # ------------------------------------------------------------------
    # Batch processor
    # ------------------------------------------------------------------
    try:
        from batch_processor import BatchProcessor
        upload_folder = config.get("RESULTS_FOLDER", "results")
        components["batch_processor"] = _slot("available", BatchProcessor(output_dir=upload_folder))
        logger.info("Batch processor loaded")
    except Exception as exc:
        components["batch_processor"]["error"] = str(exc)
        logger.error("Batch processor load failed: %s", exc)

    # ------------------------------------------------------------------
    # Model explainer
    # ------------------------------------------------------------------
    try:
        from model_explainer import ModelExplainer
        components["model_explainer"] = _slot("available", ModelExplainer(model_path=model_path))
        logger.info("Model explainer loaded")
    except Exception as exc:
        components["model_explainer"]["error"] = str(exc)
        logger.error("Model explainer load failed: %s", exc)

    # ------------------------------------------------------------------
    # Realtime monitor
    # ------------------------------------------------------------------
    try:
        from realtime_monitor import RealtimeMonitor
        components["realtime_monitor"] = _slot("available", RealtimeMonitor())
        logger.info("Realtime monitor loaded")
    except Exception as exc:
        components["realtime_monitor"]["error"] = str(exc)
        logger.error("Realtime monitor load failed: %s", exc)

    # ------------------------------------------------------------------
    # Threat intelligence
    # ------------------------------------------------------------------
    try:
        from threat_intelligence import MultiSourceThreatIntelligence
        components["threat_intel"] = _slot("available", MultiSourceThreatIntelligence())
        logger.info("Threat intelligence loaded")
    except Exception as exc:
        components["threat_intel"]["error"] = str(exc)
        logger.error("Threat intelligence load failed: %s", exc)


    # ------------------------------------------------------------------
    # Anti-evasion
    # ------------------------------------------------------------------
    try:
        from anti_evasion import AntiEvasionDetector
        components["anti_evasion"] = _slot("available", AntiEvasionDetector())
        logger.info("Anti-evasion analyzer loaded")
    except Exception as exc:
        components["anti_evasion"]["error"] = str(exc)
        logger.error("Anti-evasion load failed: %s", exc)


    available = [k for k, v in components.items() if v["status"] == "available"]
    logger.info("Components ready: %s", ", ".join(available) or "none")
    return components
