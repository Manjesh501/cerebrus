"""Central configuration — all constants read from environment.

Import this module instead of scattering os.environ.get() calls throughout routes.
"""
from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).resolve().parent.parent

UPLOAD_FOLDER: str = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
RESULTS_FOLDER: str = os.environ.get("RESULTS_FOLDER", str(BASE_DIR / "results"))
BATCH_FOLDER: str = os.environ.get("BATCH_FOLDER", str(BASE_DIR / "batch_uploads"))
BATCH_RESULTS_FOLDER: str = os.environ.get("BATCH_RESULTS_FOLDER", str(BASE_DIR / "batch_results"))
MODEL_PATH: str = os.environ.get("MODEL_PATH", str(BASE_DIR / "ML_model" / "malwareclassifier-V2.pkl"))

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", "") or os.urandom(32).hex()
MAX_UPLOAD_BYTES: int = int(os.environ.get("MAX_UPLOAD_SIZE_MB", 50)) * 1024 * 1024

# ---------------------------------------------------------------------------
# External APIs
# ---------------------------------------------------------------------------
VT_API_KEY: str | None = os.environ.get("VT_API_KEY") or None

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
FLASK_DEBUG: bool = os.environ.get("FLASK_DEBUG", "").lower() == "true"
FLASK_HOST: str = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT: int = int(os.environ.get("FLASK_PORT", 5000))

# ---------------------------------------------------------------------------
# Allowed file extensions — grouped by category
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS: dict[str, set[str]] = {
    "executable": {"exe", "dll", "sys", "ocx", "com", "scr", "msi", "bin"},
    "document": {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt"},
    "script": {"js", "py", "ps1", "vbs", "bat", "sh", "cmd", "jar"},
    "archive": {"zip", "rar", "7z", "tar", "gz"},
    "malware": {"class", "apk", "dex", "elf", "dmg", "pkg"},
}
