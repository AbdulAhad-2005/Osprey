"""Universal stdout ingest — extracts structural Observations from ANY tool output.

Structural extraction only, per plans/harness/02-evidence-and-observation-layer.md:
this used to mint Findings with a confidence/severity baked into the YAML
rule. It no longer does — every rule now only says WHAT to extract (a header,
a port, a technology name) and the earned-finding pipeline (Plan 03) decides
what, if anything, that fact earns.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.config_loader import read_config

logger = logging.getLogger(__name__)

_SPA_MARKERS = re.compile(
    r"(?i)(<!DOCTYPE html|<html[\s>]|<div id=[\"']root[\"']|ng-version=|__NEXT_DATA__|webpackJsonp)",
)

# Strip ANSI escape sequences from tool output before regex matching.
# Only parse_dnsx did this previously; now every tool benefits.
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Rules that should only fire when the source tool has NO dedicated parser are
# marked `applies_when: no_parser` in config/ingest_rules.yaml — the config is
# the single source of truth for suppression, so adding a new parser-owned rule
# never means also editing a Python set here.


def _tool_has_parser(source_tool: str) -> bool:
    """True when a dedicated stdout parser is registered for this tool."""
    name = (source_tool or "").split(":", 1)[0]  # script:/shell: never have one
    if not name or source_tool.startswith(("script:", "shell:")):
        return False
    try:
        from osprey.services.parsers.registry import (
            _OUTPUT_PARSERS,
            ensure_parsers_loaded,
        )

        # Idempotent: guarantees phase parser modules have self-registered even
        # if this runs before app startup wired them (e.g. isolated test/import).
        ensure_parsers_loaded()
        return name in _OUTPUT_PARSERS
    except Exception:
        return False


_JSON_CT = re.compile(r"(?i)content-type:\s*application/json")
_PATH_API = re.compile(r"(?i)/(api|swagger|graphql|rest)(/|$|\?)")
_IP_LITERAL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _port_from_match(m: "re.Match[str]") -> str:
    """PORT/SERVICE rules in ingest_rules.yaml (open_port_line, nmap_service_version)
    both capture the port number as group 1 — the convention their patterns already
    follow. Without this, PORT/SERVICE observations from the universal ingest rules
    carry no port detail, so downstream consumers requiring it silently skip them —
    a guaranteed orphan, not a real gap."""
    try:
        g1 = m.group(1)
    except (IndexError, re.error):
        return ""
    return g1 if g1 and g1.isdigit() else ""


@lru_cache(maxsize=1)
def _load_rules() -> list[dict[str, Any]]:
    # Prefer YAML (source of truth); JSON is optional mirror.
    data = read_config("ingest_rules.yaml", "ingest_rules.json")
    return list(data.get("rules") or [])


def reload_ingest_rules() -> None:
    _load_rules.cache_clear()


def looks_like_spa_html(text: str) -> bool:
    sample = (text or "")[:8000]
    return bool(_SPA_MARKERS.search(sample))


def apply_ingest_rules(
    stdout: str,
    stderr: str = "",
    *,
    engagement_id: str,
    run_id: str = "",
    source_tool: str = "",
    target: str = "",
    persist: bool = True,
    max_observations: int = 40,
) -> list[Observation]:
    """Run YAML rules over combined output; optionally persist to the observation store."""
    if not engagement_id:
        return []
    blob = "\n".join(x for x in (stdout or "", stderr or "") if x)
    if not blob.strip():
        return []

    # Strip ANSI escape sequences so regex rules match clean text.
    blob = _ANSI_RE.sub("", blob)

    # Hard SPA catch-all signal for API-looking paths in target/URL
    spa = looks_like_spa_html(blob)
    path_hint = target or ""

    observations: list[Observation] = []
    seen_titles: set[str] = set()

    # A tool with its own parser owns its structured extraction — the loose
    # "guessing" rules only add mis-paired/garbage duplicates over its output.
    skip_structural = _tool_has_parser(source_tool)

    for rule in _load_rules():
        if len(observations) >= max_observations:
            break
        if skip_structural and rule.get("applies_when") == "no_parser":
            continue
        pattern = rule.get("pattern") or ""
        if not pattern:
            continue
        flags = re.M if rule.get("multiline") else 0
        try:
            rx = re.compile(pattern, flags | re.I)
        except re.error:
            continue

        if rule.get("require_path_hint") and rule.get("path_hint_pattern"):
            if not re.search(str(rule["path_hint_pattern"]), path_hint + "\n" + blob[:2000], re.I):
                # Still apply spa rule when HTML shell present
                if rule.get("id") != "spa_catchall_suspect" or not spa:
                    if rule.get("id") == "spa_catchall_suspect" and spa and _PATH_API.search(path_hint):
                        pass
                    elif rule.get("id") == "spa_catchall_suspect" and spa:
                        pass
                    else:
                        continue

        matches = list(rx.finditer(blob))[:8]
        for m in matches:
            if len(observations) >= max_observations:
                break
            title = _render_title(rule.get("title_template") or "{match}", m)
            title = title[:200]
            if not title or title in seen_titles:
                continue
            seen_titles.add(title)

            tags = list(rule.get("tags") or [])
            raw_snip = m.group(0)[:800]

            # SPA false-positive marker — a fact about the response shape, not
            # a confidence downgrade (there is no confidence to downgrade here).
            if spa and _PATH_API.search(path_hint + title + raw_snip):
                if "spa_catchall_suspect" not in tags:
                    tags.append("spa_catchall_suspect")

            otype = _otype(rule.get("type") or rule.get("finding_type") or "http_response")
            details: dict[str, Any] = {"ingest_rule": rule.get("id"), "target": target, "raw": raw_snip}
            if otype == ObservationType.TECHNOLOGY:
                # tech_dispatch.yaml signals (WordPress/Joomla/Drupal/... follow-ups)
                # match on details["technology"] via substring — without this,
                # every technology-type observation from the generic ingest rules
                # (WhatWeb/Wappalyzer/version-banner/etc.) is invisible to dispatch.
                details["technology"] = title
            if otype in (ObservationType.PORT, ObservationType.SERVICE):
                port_val = _port_from_match(m)
                if port_val:
                    details["port"] = port_val
                host_val = (target or "").strip()
                if host_val:
                    details["ip" if _IP_LITERAL_RE.match(host_val) else "hostname"] = host_val
            observations.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id or "",
                    type=otype,
                    target=target or "",
                    source_tool=source_tool or "ingest_promoter",
                    details={**details, "title": title},
                    tags=tags,
                )
            )

    if spa and _PATH_API.search(path_hint) and not any("spa_catchall_suspect" in (o.tags or []) for o in observations):
        observations.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id or "",
                type=ObservationType.HTTP_RESPONSE,
                target=target or "",
                source_tool=source_tool or "ingest_promoter",
                details={
                    "title": "SPA/HTML catch-all suspected for API-like path — verify JSON body before treating as an open API",
                    "raw": blob[:400],
                },
                tags=["auto_ingest", "spa_catchall_suspect"],
            )
        )

    if persist and observations:
        from osprey.services.engagement_graph import get_engagement_graph
        from osprey.services.observation_store import get_observation_store

        result = get_observation_store().record_many(observations)
        try:
            get_engagement_graph().ingest_many_observations(result.observations)
        except Exception:  # noqa: BLE001
            logger.debug("Graph ingest skipped for ingest_promoter observations", exc_info=True)
    return observations


def _render_title(template: str, m: re.Match[str]) -> str:
    title = template.replace("{match}", (m.group(0) or "")[:120].strip())
    for i in range(1, min(6, len(m.groups()) + 1)):
        title = title.replace(f"{{g{i}}}", (m.group(i) or "").strip())
    return " ".join(title.split())


def _otype(raw: str) -> ObservationType:
    try:
        return ObservationType(str(raw).lower())
    except ValueError:
        return ObservationType.HTTP_RESPONSE
