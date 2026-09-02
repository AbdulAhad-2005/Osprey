"""Lightweight recent-stdout index — paths + snippets so nuance is not lost.

Full bodies stay on Kali artifacts. Context only shows a short index.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

_LOCK = threading.Lock()
_MAX_PER_ENGAGEMENT = 24
# engagement_id -> deque of entries
_INDEX: dict[str, deque[dict[str, Any]]] = defaultdict(
    lambda: deque(maxlen=_MAX_PER_ENGAGEMENT)
)


def record_stdout_entry(
    *,
    engagement_id: str,
    tool_name: str = "",
    target: str = "",
    stdout_path: str = "",
    stderr_path: str = "",
    snippet: str = "",
    bytes_hint: int | None = None,
    success: bool | None = None,
) -> dict[str, Any] | None:
    eid = (engagement_id or "").strip()
    if not eid:
        return None
    path = (stdout_path or "").strip()
    snip = (snippet or "").strip().replace("\r\n", "\n")
    if len(snip) > 400:
        snip = snip[:200] + "\n…\n" + snip[-160:]
    entry = {
        "ts": time.time(),
        "tool": (tool_name or "")[:80],
        "target": (target or "")[:120],
        "stdout_path": path[:240],
        "stderr_path": (stderr_path or "")[:240],
        "snippet": snip,
        "bytes": bytes_hint,
        "success": success,
    }
    with _LOCK:
        _INDEX[eid].append(entry)
    return entry


def list_stdout_index(
    engagement_id: str,
    *,
    limit: int = 8,
) -> dict[str, Any]:
    eid = (engagement_id or "").strip()
    if not eid:
        return {"engagement_id": "", "entries": [], "count": 0}
    limit = max(1, min(int(limit), 24))
    with _LOCK:
        items = list(_INDEX.get(eid, ()))
    items = items[-limit:]
    items.reverse()  # newest first
    lines = []
    for e in items:
        bit = f"{e.get('tool') or '?'} → {e.get('stdout_path') or '(no path)'}"
        if e.get("target"):
            bit += f" ({e['target']})"
        lines.append(bit)
    return {
        "engagement_id": eid,
        "count": len(items),
        "entries": items,
        "text": "\n".join(lines) if lines else "(no recent artifacts indexed)",
        "note": (
            "Full stdout on Kali — platform_artifact(path=…) to read slices. "
            "Index keeps last N paths + snippets only."
        ),
    }


def clear_stdout_index(engagement_id: str | None = None) -> None:
    with _LOCK:
        if engagement_id:
            _INDEX.pop(engagement_id.strip(), None)
        else:
            _INDEX.clear()
