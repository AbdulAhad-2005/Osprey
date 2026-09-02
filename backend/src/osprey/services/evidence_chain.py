"""Evidence-chain helpers — derived_from links without prescribing tools."""

from __future__ import annotations

import re
from typing import Any


_ID_RE = re.compile(r"^[a-f0-9]{8,32}$", re.I)


def normalize_derived_from(raw: Any) -> list[str]:
    """Accept list/CSV/string of finding ids; drop junk."""
    items: list[str] = []
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        parts = re.split(r"[\s,;]+", raw.strip())
        items.extend(parts)
    elif isinstance(raw, (list, tuple)):
        for x in raw:
            items.extend(normalize_derived_from(x))
    else:
        items.append(str(raw))
    out: list[str] = []
    seen: set[str] = set()
    for i in items:
        s = (i or "").strip().lower()
        if not s or s in seen:
            continue
        if not _ID_RE.match(s) and not re.match(r"^[a-z0-9_-]{6,40}$", s):
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= 20:
            break
    return out


def merge_derived_from(meta: dict[str, Any] | None, parents: list[str]) -> dict[str, Any]:
    base = dict(meta or {})
    existing = normalize_derived_from(base.get("derived_from"))
    merged = list(dict.fromkeys(existing + parents))[:20]
    if merged:
        base["derived_from"] = merged
    return base
