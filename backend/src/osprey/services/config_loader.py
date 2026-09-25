"""Shared YAML/JSON config-file loading.

Every config-driven service in this package previously duplicated the same
"resolve candidate filenames under config/, read, parse, log a warning on
failure" block. This centralizes only that file-IO boilerplate — callers
keep their own ``@lru_cache``, defaults-merging, and post-load field
normalization exactly as before, so return values and reload semantics are
unchanged.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).resolve().parents[4] / "config"


def read_config(*candidate_names: str) -> dict[str, Any]:
    """Return the parsed top-level mapping from the first existing candidate.

    Tries each name in order (so a ``.yaml`` can be preferred over a legacy
    ``.json`` mirror). A file that exists but fails to parse is logged and
    skipped in favor of the next candidate. Returns ``{}`` if nothing in
    ``candidate_names`` exists or parses.
    """
    for name in candidate_names:
        path = CONFIG_DIR / name
        if not path.exists():
            continue
        try:
            if name.endswith(".json"):
                return json.loads(path.read_text(encoding="utf-8")) or {}
            import yaml

            return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("config load failed %s: %s", path, exc)
    logger.warning("config not found: tried %s in %s", candidate_names, CONFIG_DIR)
    return {}


def read_config_layered(base_name: str) -> dict[str, Any]:
    """Like ``read_config(base_name)``, but if a sibling ``<stem>.local.<ext>``
    exists next to it, deep-merge it on top instead of ignoring it — the
    per-operator customization overlay (plans/harness/13-systematic-vuln-
    dispatch-and-extensibility.md Step 1), git-ignored like ``skills/learned/``.

    Merge rule, applied per top-level key present in the local file:
    - A list value: local entries are appended to the base list, EXCEPT an
      entry whose ``id`` matches a base entry's ``id`` replaces that base
      entry in place (edit), and a matching entry with ``disabled: true``
      removes the base entry entirely — the "remove" half of "add/remove
      your own". Entries without an ``id`` always just append.
    - A dict/scalar value: the local value replaces the base value outright.
    Base-only keys and local-only keys both pass through untouched.
    """
    base = read_config(base_name)
    if not base:
        return base
    stem, _, ext = base_name.rpartition(".")
    ext = ext or "yaml"
    local_path = CONFIG_DIR / f"{stem}.local.{ext}"
    if not local_path.exists():
        return base
    try:
        if ext == "json":
            local = json.loads(local_path.read_text(encoding="utf-8")) or {}
        else:
            import yaml

            local = yaml.safe_load(local_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("local config overlay failed %s: %s", local_path, exc)
        return base

    merged = dict(base)
    for key, local_value in (local or {}).items():
        base_value = merged.get(key)
        if isinstance(base_value, list) and isinstance(local_value, list):
            merged[key] = _merge_id_lists(base_value, local_value)
        else:
            merged[key] = local_value
    return merged


def _merge_id_lists(base_list: list, local_list: list) -> list:
    by_id: dict[str, int] = {}
    out: list[Any] = list(base_list)
    for i, item in enumerate(out):
        if isinstance(item, dict) and item.get("id"):
            by_id[item["id"]] = i
    for item in local_list:
        item_id = item.get("id") if isinstance(item, dict) else None
        if item_id and item_id in by_id:
            # A disabled edit removes the base entry; anything else replaces it.
            out[by_id[item_id]] = None if (isinstance(item, dict) and item.get("disabled")) else item
        else:
            out.append(item)
    return [x for x in out if x is not None]
