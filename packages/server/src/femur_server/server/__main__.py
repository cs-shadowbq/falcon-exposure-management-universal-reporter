"""CLI entry point for the Falcon Inventory API server.

Usage::

    femurd --data-dir ./inventory --env-file talon1.env
    femurd -d ./inventory -e talon1.env --port 9000

    # Or via uvicorn factory directly (supports --reload, --workers):
    uvicorn femur_server.server.app:create_app --factory
"""

import argparse
import os
import sys
from typing import Optional


def main(argv: Optional[list[str]] = None) -> None:
    """Start the inventory API server."""
    parser = argparse.ArgumentParser(
        prog="femurd",
        description="Serve pre-fetched Falcon inventory data over HTTP.",
    )
    parser.add_argument(
        "--data-dir",
        "-d",
        required=True,
        help="Directory containing JSONL output from femur.",
    )
    parser.add_argument(
        "--env-file",
        "-e",
        default=None,
        help="Env file for background re-fetch jobs.",
    )
    parser.add_argument(
        "--max-age",
        type=float,
        default=10800,
        help="Max data age in seconds before background re-fetch (default: 10800 = 3h).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Bind port (default: 8000).",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of uvicorn worker processes (default: 1).",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Logging level (default: info).",
    )

    args = parser.parse_args(argv)

    # Propagate config via env vars so factory workers can pick them up.
    os.environ["FALCON_INVENTORY_DATA_DIR"] = os.path.abspath(args.data_dir)
    if args.env_file:
        os.environ["FALCON_INVENTORY_ENV_FILE"] = os.path.abspath(args.env_file)
    os.environ["FALCON_INVENTORY_MAX_AGE"] = str(args.max_age)

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is required to run the server. "
            "Install it with: pip install 'falcon-application-inventory-server'",
            file=sys.stderr,
        )
        sys.exit(1)

    uvicorn.run(
        "femur_server.server.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
