"""Backend-reachability helpers shared by the CLI and the backend itself.

Both `cli/` and `backend/` resolve the same API_BASE_URL env var to find the
FastAPI backend; this one case needs correcting identically in both places.
"""

from __future__ import annotations

import os


def resolve_api_base_url(configured: str | None = None, default: str = "http://localhost:9000") -> str:
    """The reachable backend URL, correcting for running inside the backend's
    own Docker container.

    A host-mapped port (e.g. BACKEND_PORT=9100, so the host reaches the
    container at localhost:9100) is not reachable as that port from inside
    the container's own network namespace — uvicorn there is still listening
    on the internal port (9000). Detect "we are that container" via the
    standard /.dockerenv marker Docker creates at container start, and fall
    back to the internal port whenever the configured URL points at
    localhost/127.0.0.1 (the only host-mapped case that's wrong from inside).
    """
    url = configured if configured is not None else os.getenv("API_BASE_URL", "")
    url = url.strip() or default
    if os.path.exists("/.dockerenv") and ("localhost" in url or "127.0.0.1" in url):
        return default
    return url
