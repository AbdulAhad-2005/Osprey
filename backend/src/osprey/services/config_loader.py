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
