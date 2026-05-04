"""Fallback analysis functions used when primary ML / document analysers fail.

These functions are intentionally conservative — they prefer false negatives over
false positives because they operate without the full ML pipeline.
"""
from __future__ import annotations

import hashlib
import logging
import os

import numpy as np

try:
    import magic
except ImportError:
    magic = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Byte-strings that are strongly associated with malicious PE behaviour.
_SUSPICIOUS_PATTERNS: list[bytes] = [
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"cmd.exe",
    b"powershell",
    b"WinExec",
    b"ShellExecute",
    b"RegSetValue",
    b"CreateService",
    b"bitcoin",
    b"ransom",
    b"encrypt",
    b"decrypt",
    b"backdoor",
]


def fallback_extract_features(file_path: str) -> np.ndarray:
    """Extract a minimal feature vector when the primary extractor is unavailable.

    Returns a ``(1, 5)`` numpy array compatible with the fallback ML path.
    Feature order: file_size, is_executable, is_dll, entropy, md5_hash_norm.
    """
    logger.warning("Using fallback feature extraction for %s", file_path)
    features: dict[str, float] = {}

    # File size
    try:
        features["file_size"] = float(os.path.getsize(file_path))
    except OSError as exc:
        logger.debug("Could not stat %s: %s", file_path, exc)
        features["file_size"] = 0.0

    # Executable type via magic or extension heuristic
    try:
        if magic:
            file_type: str = magic.from_file(file_path)
            features["is_executable"] = 1.0 if "executable" in file_type.lower() else 0.0
            features["is_dll"] = 1.0 if "dll" in file_type.lower() else 0.0
        else:
            raise RuntimeError("magic not available")
    except Exception as exc:
        logger.debug("Magic detection failed for %s: %s", file_path, exc)
        lower = file_path.lower()
        features["is_executable"] = 1.0 if lower.endswith(".exe") else 0.0
        features["is_dll"] = 1.0 if lower.endswith(".dll") else 0.0

    # Shannon entropy
    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
        if data:
            entropy = 0.0
            for byte_val in range(256):
                p_x = data.count(bytes([byte_val])) / len(data)
                if p_x > 0:
                    entropy -= p_x * np.log2(p_x)
            features["entropy"] = entropy
        else:
            features["entropy"] = 0.0
    except Exception as exc:
        logger.debug("Entropy calculation failed for %s: %s", file_path, exc)
        features["entropy"] = 0.0

    # Normalised MD5 prefix as a weak hash feature
    try:
        with open(file_path, "rb") as fh:
            raw = fh.read()
        md5_hex = hashlib.md5(raw).hexdigest()
        features["md5_hash"] = int(md5_hex[:8], 16) / (1 << 32)
    except Exception as exc:
        logger.debug("Hash feature failed for %s: %s", file_path, exc)
        features["md5_hash"] = 0.0

    return np.array([[
        features["file_size"],
        features["is_executable"],
        features["is_dll"],
        features["entropy"],
        features["md5_hash"],
    ]])


def fallback_detect_malware(file_path: str) -> bool:
    """Heuristically detect suspicious files when the ML model is unavailable.

    A file is flagged when it matches 5+ suspicious byte patterns OR has
    abnormally high entropy combined with a size anomaly.

    ZIP archives are transparently decompressed and each member is scanned.
    """
    logger.warning("Using fallback malware detection for %s", file_path)

    # ------------------------------------------------------------------ zip
    # Inspect archive members directly — patterns won't appear in compressed bytes
    if file_path.lower().endswith(".zip") or _is_zip(file_path):
        return _scan_zip_contents(file_path)

    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        logger.error("Cannot read %s for fallback detection: %s", file_path, exc)
        return False

    return _scan_bytes(data, file_path)


def _is_zip(file_path: str) -> bool:
    """Return True if the file starts with the ZIP magic bytes PK\\x03\\x04."""
    try:
        with open(file_path, "rb") as fh:
            return fh.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def _scan_zip_contents(file_path: str) -> bool:
    """Scan decompressed content of each ZIP member for suspicious patterns.

    Immediate red-flags:
    - A member file has an MZ (PE) or ELF header but a non-executable extension
    - Pattern scan detects 5+ suspicious API strings
    - Any member is itself a PE executable (MZ header)
    """
    import zipfile
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for member in zf.infolist():
                try:
                    data = zf.read(member.filename)
                    ext = member.filename.rsplit(".", 1)[-1].lower() if "." in member.filename else ""

                    # Red flag 1: MZ/ELF header — it's a PE or ELF binary
                    is_pe = data[:2] == b"MZ"
                    is_elf = data[:4] == b"\x7fELF"
                    if is_pe or is_elf:
                        logger.warning(
                            "Executable binary (PE/ELF) found in ZIP as '%s' inside %s",
                            member.filename, file_path,
                        )
                        return True

                    # Red flag 2: extension mismatch (e.g. .txt file with script content)
                    non_exec_exts = {"ps1", "bat", "vbs", "js", "cmd", "sh", "hta"}
                    if ext in non_exec_exts and _scan_bytes(data, member.filename):
                        logger.info(
                            "Suspicious script content in '%s' inside %s",
                            member.filename, file_path,
                        )
                        return True

                    # General pattern scan
                    if _scan_bytes(data, member.filename):
                        logger.info(
                            "Suspicious content in ZIP member '%s' inside %s",
                            member.filename, file_path,
                        )
                        return True

                except Exception as exc:
                    logger.debug("Could not read zip member %s: %s", member.filename, exc)
    except Exception as exc:
        logger.warning("Could not open zip %s: %s — falling back to raw scan", file_path, exc)
        try:
            with open(file_path, "rb") as fh:
                return _scan_bytes(fh.read(), file_path)
        except OSError:
            return False
    return False



def _scan_bytes(data: bytes, label: str) -> bool:
    """Core byte-pattern scan used by both the direct and zip paths."""
    lower_data = data.lower()
    suspicious_matches = sum(
        1 for pattern in _SUSPICIOUS_PATTERNS
        if pattern.lower() in lower_data
    )

    entropy = 0.0
    if data:
        for byte_val in range(256):
            p_x = data.count(bytes([byte_val])) / len(data)
            if p_x > 0:
                entropy -= p_x * np.log2(p_x)

    file_size = len(data)
    high_entropy = entropy > 7.0
    strange_size = file_size < 1_000 or file_size > 20_000_000
    many_patterns = suspicious_matches > 5

    is_suspicious = many_patterns or (high_entropy and strange_size)

    logger.debug(
        "Scan '%s': entropy=%.2f patterns=%d size=%d suspicious=%s",
        label, entropy, suspicious_matches, file_size, is_suspicious,
    )
    return is_suspicious

