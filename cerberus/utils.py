"""Shared utility functions used across route blueprints.

All pure functions — no Flask imports, no global state.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re

import numpy as np
from werkzeug.utils import secure_filename

from cerberus.config import ALLOWED_EXTENSIONS

try:
    import magic
    import mimetypes
except ImportError:
    magic = None  # type: ignore[assignment]
    import mimetypes

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File name / path helpers
# ---------------------------------------------------------------------------

def safe_filename(filename: str) -> str:
    """Return a filesystem-safe version of *filename*.

    Applies :func:`werkzeug.utils.secure_filename` then strips characters
    that are illegal on Windows and enforces a 200-character limit.
    """
    safe = secure_filename(filename)
    for ch in ("<", ">", ":", '"', "|", "?", "*"):
        safe = safe.replace(ch, "_")
    if not safe or safe.isspace():
        safe = "unknown_file"
    if len(safe) > 200:
        name, ext = os.path.splitext(safe)
        safe = name[: 200 - len(ext)] + ext
    return safe


def allowed_file(filename: str, header_bytes: bytes | None = None) -> bool:
    """Return *True* if *filename* has an allowed extension.

    Optionally validates the file's actual MIME type against its declared
    extension when *header_bytes* (first 2 KB of the file) is provided.
    """
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    all_exts: set[str] = set().union(*ALLOWED_EXTENSIONS.values())
    if ext not in all_exts:
        return False
    if magic and header_bytes is not None:
        mime: str = magic.from_buffer(header_bytes, mime=True)
        executable_mimes = {
            "application/x-dosexec",
            "application/x-executable",
            "application/x-elf",
        }
        exec_exts = (
            ALLOWED_EXTENSIONS.get("executable", set())
            | ALLOWED_EXTENSIONS.get("malware", set())
        )
        if mime in executable_mimes and ext not in exec_exts:
            logger.warning(
                "MIME mismatch for '%s': ext=.%s but magic=%s", filename, ext, mime
            )
            return False
    return True


# ---------------------------------------------------------------------------
# File inspection helpers
# ---------------------------------------------------------------------------

def get_file_type(file_path: str) -> str:
    """Return a human-readable MIME type string for the file at *file_path*."""
    try:
        if magic:
            return magic.from_file(file_path, mime=True)
        mime, _ = mimetypes.guess_type(file_path)
        return mime or "application/octet-stream"
    except Exception as exc:
        logger.debug("Could not determine file type for %s: %s", file_path, exc)
        _, ext = os.path.splitext(file_path)
        mime, _ = mimetypes.guess_type(file_path)
        return mime or f"application/{ext.lstrip('.') or 'octet-stream'}"


def get_file_category(filename: str) -> str:
    """Return the category key from *ALLOWED_EXTENSIONS* for *filename*."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    for category, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return category
    return "unknown"


def calculate_hash(file_path: str) -> str:
    """Return the SHA-256 hex digest of the file at *file_path*."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha256.update(chunk)
    except OSError as exc:
        logger.error("Failed to hash %s: %s", file_path, exc)
    return sha256.hexdigest()


# ---------------------------------------------------------------------------
# JSON serialisation helper
# ---------------------------------------------------------------------------

def make_json_serializable(obj: object) -> object:
    """Recursively convert *obj* to a JSON-serialisable Python primitive."""
    if isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [make_json_serializable(i) for i in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    if isinstance(obj, np.str_):
        return str(obj)
    if obj is None or isinstance(obj, (int, float, str)):
        return obj
    return str(obj)


# ---------------------------------------------------------------------------
# Path traversal guard
# ---------------------------------------------------------------------------

def safe_join(base_dir: str, filename: str) -> str | None:
    """Return the resolved path only if it stays inside *base_dir*.

    Returns *None* on a traversal attempt so the caller can return 400.
    """
    abs_base = os.path.abspath(base_dir)
    candidate = os.path.normpath(os.path.join(base_dir, filename))
    if not os.path.abspath(candidate).startswith(abs_base + os.sep):
        logger.warning("Path traversal blocked: %s", filename)
        return None
    return candidate


def valid_timestamp(ts: str) -> bool:
    """Return *True* if *ts* matches the ``YYYYMMDD_HHMMSS`` batch timestamp format."""
    return bool(re.match(r"^\d{8}_\d{6}$", ts))
