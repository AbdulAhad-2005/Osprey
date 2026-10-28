"""Web technology-fingerprint parsers (wappalyzer/whatweb/tech-stack/wafw00f)."""

from __future__ import annotations

import json
import re
from typing import Any

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers.recon_network._shared import _unparsed_observation


def parse_wappalyzer(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return _unparsed_observation(
            stdout, tool_name="wappalyzer_scan", engagement_id=engagement_id, run_id=run_id, target=target
        )
    if not isinstance(data, dict):
        return []
    technologies = data.get("technologies")
    if not isinstance(technologies, dict):
        return []
    tgt = data.get("target") or target

    out: list[Observation] = []
    for tech_name, info in technologies.items():
        if not isinstance(info, dict):
            continue
        versions = info.get("versions") or []
        version = str(versions[0]) if versions else ""
        cats = [str(c) for c in (info.get("categories") or [])]
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.TECHNOLOGY,
                target=tgt,
                source_tool="wappalyzer_scan",
                details={"name": str(tech_name), "version": version, "categories": cats},
                tags=["wappalyzer"] + [c.lower().replace(" ", "_") for c in cats[:3]],
            )
        )
    return out or _unparsed_observation(
        stdout, tool_name="wappalyzer_scan", engagement_id=engagement_id, run_id=run_id, target=target
    )


_WHATWEB_SKIP_PLUGINS = {"IP", "Country", "UncommonHeaders", "Allow"}


def parse_whatweb(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    text = stdout.strip()
    data: Any = None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # WhatWeb sometimes mixes JSON with banner/non-JSON lines — pull the array out.
        json_lines: list[str] = []
        depth = 0
        in_json = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_json = True
            if in_json:
                json_lines.append(line)
                depth += s.count("[") - s.count("]")
                if depth <= 0 and json_lines:
                    break
        if json_lines:
            try:
                data = json.loads("\n".join(json_lines))
            except (json.JSONDecodeError, TypeError):
                data = None
    if data is None:
        return _unparsed_observation(
            stdout, tool_name="whatweb_scan", engagement_id=engagement_id, run_id=run_id, target=target
        )
    if not isinstance(data, list):
        data = [data]

    out: list[Observation] = []
    seen: set[str] = set()
    for result in data:
        if not isinstance(result, dict):
            continue
        tgt = result.get("target") or target
        plugins = result.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for plugin_name, plugin_data in plugins.items():
            if plugin_name in _WHATWEB_SKIP_PLUGINS or not isinstance(plugin_data, dict):
                continue
            versions = plugin_data.get("version") or []
            version = str(versions[0]) if isinstance(versions, list) and versions else str(versions or "")
            key = f"{plugin_name}:{version}".lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.TECHNOLOGY,
                    target=tgt,
                    source_tool="whatweb_scan",
                    details={"name": str(plugin_name), "version": version, "module": plugin_data.get("module")},
                    tags=["whatweb"],
                )
            )
    return out or _unparsed_observation(
        stdout, tool_name="whatweb_scan", engagement_id=engagement_id, run_id=run_id, target=target
    )


def parse_tech_stack(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return _unparsed_observation(
            stdout, tool_name="tech_stack_analyze", engagement_id=engagement_id, run_id=run_id, target=target
        )
    if not isinstance(data, dict):
        return []
    tgt = data.get("target") or target

    out: list[Observation] = []
    for tech in data.get("unified_stack") or []:
        if not isinstance(tech, dict):
            continue
        name = str(tech.get("name") or "").strip()
        if not name:
            continue
        version = str(tech.get("version") or "")
        cats = [str(c) for c in (tech.get("categories") or [])]
        detected_by = [str(d) for d in (tech.get("detected_by") or [])]
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.TECHNOLOGY,
                target=tgt,
                source_tool="tech_stack_analyze",
                details={
                    "name": name,
                    "version": version,
                    "categories": cats,
                    "detected_by": detected_by,
                },
                tags=["tech_stack"] + [c.lower().replace(" ", "_") for c in cats[:3]],
            )
        )
    return out or _unparsed_observation(
        stdout, tool_name="tech_stack_analyze", engagement_id=engagement_id, run_id=run_id, target=target
    )


_WAFW00F_DETECTED_RE = re.compile(r"(?i)is behind\s+(.+?)\s+WAF\b")
_WAFW00F_NONE_RE = re.compile(r"(?i)No WAF detected")


def parse_wafw00f(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    text = stdout or ""
    out: list[Observation] = []
    seen: set[str] = set()
    for match in _WAFW00F_DETECTED_RE.finditer(text):
        waf_name = match.group(1).strip()
        key = waf_name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.WAF,
                target=target,
                source_tool="wafw00f_scan",
                details={"waf": waf_name, "raw": match.group(0)[:300]},
                tags=["waf", "wafw00f"],
            )
        )
    if not out and _WAFW00F_NONE_RE.search(text):
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.WAF,
                target=target,
                source_tool="wafw00f_scan",
                details={"waf": None, "detected": False},
                tags=["wafw00f", "no_waf"],
            )
        )
    return out or _unparsed_observation(
        stdout, tool_name="wafw00f_scan", engagement_id=engagement_id, run_id=run_id, target=target
    )


