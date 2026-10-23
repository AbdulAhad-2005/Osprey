"""Convenience entry point for starting the backend — ``osprey-backend`` (or the
main Osprey CLI's ``osprey serve``, which calls into this).

Local, no-Docker setups previously had no short way to start the API: the
README told people to remember a full ``uvicorn osprey.main:app --host 0.0.0.0
--port 9000`` invocation by hand. This wraps that in one memorable command with
sane defaults, configurable via env vars (OSPREY_HOST / OSPREY_PORT /
OSPREY_RELOAD) so it still fits a script or a different port without flags.
"""

from __future__ import annotations

import argparse
import os


def serve() -> None:
    """``osprey-backend`` console-script entry point (see pyproject.toml)."""
    parser = argparse.ArgumentParser(
        prog="osprey-backend",
        description="Start the Osprey FastAPI backend (uvicorn, with sane defaults).",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("OSPREY_HOST", "0.0.0.0"),
        help="Bind host (default: 0.0.0.0, or $OSPREY_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("OSPREY_PORT", "9000")),
        help="Bind port (default: 9000, or $OSPREY_PORT)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=os.getenv("OSPREY_RELOAD", "").lower() in ("1", "true", "yes"),
        help="Auto-reload on code changes (dev only; also $OSPREY_RELOAD=1)",
    )
    args = parser.parse_args()

    import uvicorn

    print(f"Starting Osprey backend on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    uvicorn.run("osprey.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    serve()
