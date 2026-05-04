"""Cerberus AI Cybershield — application factory.

Usage::

    from cerberus import create_app
    app = create_app()
"""
from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from flask import Flask

load_dotenv()


def _configure_logging() -> None:
    """Centralised logging setup — called once by :func:`create_app`."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        handlers=[
            logging.FileHandler("app.log"),
            logging.StreamHandler(),
        ],
    )


def create_app() -> Flask:
    """Create and configure the Cerberus Flask application.

    All configuration, component initialisation, and Blueprint registration
    happen here so the app object carries everything it needs.
    """
    _configure_logging()
    logger = logging.getLogger(__name__)

    from cerberus.config import (
        MAX_UPLOAD_BYTES,
        MODEL_PATH,
        RESULTS_FOLDER,
        SECRET_KEY,
        UPLOAD_FOLDER,
        BATCH_FOLDER,
        BATCH_RESULTS_FOLDER,
    )

    app = Flask(
        __name__,
        # Resolve templates from the project root templates/ directory
        template_folder=str(
            (lambda p: p.parent.parent / "templates")(
                __import__("pathlib").Path(__file__)
            )
        ),
    )

    # ------------------------------------------------------------------ config
    app.secret_key = SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["RESULTS_FOLDER"] = RESULTS_FOLDER
    app.config["MODEL_PATH"] = MODEL_PATH

    # Ensure runtime dirs exist
    for folder in [UPLOAD_FOLDER, RESULTS_FOLDER, BATCH_FOLDER, BATCH_RESULTS_FOLDER]:
        os.makedirs(folder, exist_ok=True)

    # ------------------------------------------------------- component init
    from cerberus.components import init_components
    app.extensions["cerberus_components"] = init_components(app.config)
    logger.info("Components initialised")

    # ------------------------------------------------------- register blueprints
    from cerberus.routes.main_routes import bp as main_bp
    from cerberus.routes.analysis_routes import bp as analysis_bp
    from cerberus.routes.api_routes import bp as api_bp
    from cerberus.routes.realtime_routes import bp as realtime_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(realtime_bp)

    logger.info("Cerberus application ready")
    return app
