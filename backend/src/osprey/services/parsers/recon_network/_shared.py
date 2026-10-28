"""Shared helpers used across more than one recon/network parser module."""

from __future__ import annotations

import re

from osprey.schemas.observation import Observation, ObservationType


def _unparsed_observation(
    stdout: str,
    *,
    tool_name: str,
    engagement_id: str,
    run_id: str,
    target: str,
) -> list[Observation]:
    """Never silently drop raw output when structured parsing fails or matches nothing."""
    stripped = (stdout or "").strip()
    if not stripped:
        return []
    return [
        Observation(
            engagement_id=engagement_id,
            run_id=run_id,
            type=ObservationType.RAW,
            target=target,
            source_tool=tool_name,
            details={"snippet": stripped[:2000]},
            tags=[tool_name, "unparsed"],
        )
    ]


# URL-list parsing constants (used by the urls submodule).
_URL_LINE_RE = re.compile(r"https?://[^\s\"'<>]+")
_INTERESTING_URL_MARKERS = (
    "/api",
    "/admin",
    "/wp-",
    "/graphql",
    "/swagger",
    "/.git",
    "/.env",
    "/config",
    "/backup",
    "/debug",
    "/actuator",
    "/.well-known",
    ".php",
    ".json",
    ".asp",
    ".jsp",
    ".bak",
    ".sql",
    ".zip",
)
_JUNK_URL_MARKERS = (
    "%22", "%27", "%3c", "%3e", "%20on", "onmouseover", "onmousedown", "onclick",
    "onerror", "onload=", "javascript:", "<", ">", '"', "'", "\\",
)
_HOSTish_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$", re.I)
_CSS_UNIT_SEGMENT_RE = re.compile(
    r"^-?\d+(?:\.\d+)?(?:em|rem|px|vh|vw|vmin|vmax|pt|pc|mm|cm|in|ex|ch|%|deg)$", re.I
)
_NUMERIC_SEGMENTS_RE = re.compile(r"^-?\d+(?:\.\d+)?(?:em|rem|px|vh|vw|pt|pc|mm|cm|in|ex|ch|%|deg)?$", re.I)
_JS_IDENT_CHAIN_RE = re.compile(r"^[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)+$")
_FILE_EXTENSIONS = frozenset(
    "php html htm asp aspx jsp js mjs css json xml txt pdf doc docx xls xlsx ppt pptx "
    "png jpg jpeg gif svg webp ico bmp zip tar gz 7z sql bak env conf ini yaml yml "
    "py go java rb sh md rst log csv tsv map wo ff wasm apk ipa".split()
)
