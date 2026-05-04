#!/usr/bin/env python3
"""Predict whether a file is malware using the trained ML model.

Library usage::

    from predict_file import predict_malware
    result = predict_malware("/path/to/suspicious.exe")

CLI usage::

    python predict_file.py /path/to/suspicious.exe
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

import joblib
import pandas as pd

from feature_extraction import extract_features

logger = logging.getLogger(__name__)


def predict_malware(file_path: str) -> dict:
    """Return a prediction dict for the file at *file_path*.

    Returns
    -------
    dict with keys: is_malware (bool), confidence (float | None),
    prediction (int), file_name (str).
    """
    logger.info("Analysing file: %s", os.path.basename(file_path))

    # Load model from the canonical location (overridable via MODEL_PATH env var)
    model_path = os.environ.get("MODEL_PATH", "ML_model/malwareclassifier-V2.pkl")
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at '{model_path}'. "
            "Set the MODEL_PATH environment variable or ensure ML_model/ exists."
        )

    classifier = joblib.load(model_path)
    logger.info("Model loaded from %s", model_path)

    features_df: pd.DataFrame = extract_features(file_path)
    logger.info("Extracted %d features", features_df.shape[1])

    # Align features to what the model expects
    if hasattr(classifier, "feature_names_in_"):
        expected = list(classifier.feature_names_in_)
        for col in expected:
            if col not in features_df.columns:
                features_df[col] = 0
        features_df = features_df[expected]
        logger.debug("Feature alignment: %d features", len(expected))

    prediction: int = int(classifier.predict(features_df)[0])

    confidence: float | None = None
    if hasattr(classifier, "predict_proba"):
        proba = classifier.predict_proba(features_df)[0]
        confidence = float(proba[1] if prediction == 1 else proba[0])

    return {
        "is_malware": prediction == 1,
        "confidence": confidence,
        "prediction": prediction,
        "file_name": os.path.basename(file_path),
    }


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(description="Predict whether a file is malware")
    parser.add_argument("file_path", help="Path to the file to analyse")
    args = parser.parse_args()

    try:
        result = predict_malware(args.file_path)
        print("\n" + "=" * 50)
        print("PREDICTION RESULT:")
        print("=" * 50)
        print(f"File:       {result['file_name']}")
        print(f"Prediction: {'MALWARE' if result['is_malware'] else 'BENIGN'}")
        if result["confidence"] is not None:
            print(f"Confidence: {result['confidence']:.2%}")
        print("=" * 50)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


