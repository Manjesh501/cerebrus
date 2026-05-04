"""Cerberus AI Cybershield — entry point.

This file is intentionally minimal.  All application logic lives inside
the ``cerberus`` package; this file only starts the server.

Run in development::

    python app.py --debug

Run in production (Waitress WSGI)::

    python app.py
"""
from __future__ import annotations

import argparse
import os

from dotenv import load_dotenv

load_dotenv()

from cerberus import create_app  # noqa: E402  (after load_dotenv)

app = create_app()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Cerberus Malware Detection System")
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.environ.get("FLASK_DEBUG", "").lower() == "true",
    )
    parser.add_argument("--host", default=os.environ.get("FLASK_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("FLASK_PORT", 5000)))
    args = parser.parse_args()

    if args.debug:
        import logging
        logging.getLogger().warning("Starting in DEBUG mode — never use in production")
        # Exclude runtime dirs from the file reloader so uploading a file
        # doesn't restart the server and kill the in-flight request.
        app.run(
            debug=True,
            host=args.host,
            port=args.port,
            exclude_patterns=[
                "*/uploads/*",
                "*/results/*",
                "*/batch_uploads/*",
                "*/batch_results/*",
                "*.log",
            ],
        )
    else:
        from waitress import serve
        import logging
        logging.getLogger(__name__).info(
            "Starting production server on %s:%s", args.host, args.port
        )
        serve(app, host=args.host, port=args.port, threads=10)
