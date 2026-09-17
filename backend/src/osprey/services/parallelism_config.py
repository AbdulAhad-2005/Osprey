"""Parallelism config — caps + soft long-tool hints. LLM decides when to branch."""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from osprey.services.config_loader import read_config

logger = logging.getLogger(__name__)

_DEFAULTS: dict[str, Any] = {
    "max_running_jobs": 4,
    # Multi-agent pipeline caps (separate slot pool from tool jobs so LLM agents
    # and background tools don't starve each other):
    "max_running_agents": 4,      # concurrent AGENT-kind jobs per engagement
    "agent_spawn_budget": 40,     # total agents an engagement may ever spawn (runaway guard)
    "max_spawn_depth": 4,         # agent-spawns-agent nesting cap (fork-bomb guard)
    "suggest_job_timeout_seconds": 120,
    "long_tools": [
        "amass_scan",
        "nmap_syn_scan",
        "nmap_service_scan",
        "rustscan_fast_scan",
        "httpx_probe",
        "domain_hunter",
    ],
    "batch_probe_min_hosts": 8,
    "batch_probe_min_subdomains": 20,
    # Active-memory awareness (advisory nudges only — never blocks):
    # nudge a memory re-sync once this many tools have run since the last consult.
    "consult_drift_tools": 6,
}

# Sanity ceilings only — they exist to catch a fat-fingered config value (e.g.
# a stray zero), not to second-guess an operator's deliberate setting. The
# config file's value is honoured as-is below the ceiling; hitting the
# ceiling is logged loudly rather than silently substituted, so the file
# never lies about what's actually enforced.
_SANITY_CEILINGS: dict[str, int] = {
    "max_running_jobs": 200,
    "max_running_agents": 200,
    "agent_spawn_budget": 5000,
    "max_spawn_depth": 50,
    "suggest_job_timeout_seconds": 3600,
}


def _bounded(data: dict[str, Any], key: str, *, floor: int, default: int) -> int:
    ceiling = _SANITY_CEILINGS[key]
    raw = int(data.get(key) or default)
    value = max(floor, raw)
    if value > ceiling:
        logger.warning(
            "config/parallelism.yaml: %s=%d exceeds sanity ceiling %d — enforcing %d instead.",
            key, raw, ceiling, ceiling,
        )
        value = ceiling
    return value


@lru_cache(maxsize=1)
def load_parallelism() -> dict[str, Any]:
    data = dict(_DEFAULTS)
    raw = read_config("parallelism.yaml")
    if isinstance(raw, dict):
        data.update(raw)
    # normalize — honour the configured value; only a fat-fingered value past
    # the sanity ceiling gets overridden, and that override is logged.
    data["max_running_jobs"] = _bounded(data, "max_running_jobs", floor=1, default=4)
    data["max_running_agents"] = _bounded(data, "max_running_agents", floor=1, default=4)
    data["agent_spawn_budget"] = _bounded(data, "agent_spawn_budget", floor=1, default=40)
    data["max_spawn_depth"] = _bounded(data, "max_spawn_depth", floor=1, default=4)
    data["suggest_job_timeout_seconds"] = _bounded(
        data, "suggest_job_timeout_seconds", floor=30, default=120
    )
    tools = data.get("long_tools") or []
    data["long_tools"] = frozenset(str(t).strip() for t in tools if str(t).strip())
    data["batch_probe_min_hosts"] = max(3, int(data.get("batch_probe_min_hosts") or 8))
    data["batch_probe_min_subdomains"] = max(5, int(data.get("batch_probe_min_subdomains") or 20))
    data["consult_drift_tools"] = max(2, int(data.get("consult_drift_tools") or 6))
    return data


def reload_parallelism() -> dict[str, Any]:
    load_parallelism.cache_clear()
    return load_parallelism()


def max_running_jobs() -> int:
    return int(load_parallelism()["max_running_jobs"])


def max_running_agents() -> int:
    return int(load_parallelism()["max_running_agents"])


def agent_spawn_budget() -> int:
    return int(load_parallelism()["agent_spawn_budget"])


def max_spawn_depth() -> int:
    return int(load_parallelism()["max_spawn_depth"])


def consult_drift_threshold() -> int:
    return int(load_parallelism()["consult_drift_tools"])


def suggest_background(tool_name: str, timeout: int) -> bool:
    """True when a sync call is often better as a parallel job (hint only)."""
    cfg = load_parallelism()
    name = (tool_name or "").strip()
    if name in cfg["long_tools"]:
        return True
    return int(timeout or 0) >= int(cfg["suggest_job_timeout_seconds"])


def jobs_header_line(jobs: list[dict[str, Any]] | None, *, max_slots: int | None = None) -> str:
    """Compact `jobs: 2/4 running [amass, nmap]` for context."""
    cap = max_slots if max_slots is not None else max_running_jobs()
    rows = jobs or []
    active = [
        j
        for j in rows
        if str(j.get("status") or "").lower() in ("queued", "running")
    ]
    n = len(active)
    if not active and not rows:
        return f"jobs: 0/{cap} running"
    labels: list[str] = []
    for j in active[:6]:
        lab = (j.get("label") or j.get("tool_name") or j.get("kind") or "?").strip()
        labels.append(lab.split("(")[0][:40])
    if labels:
        return f"jobs: {n}/{cap} running [{', '.join(labels)}]"
    # show recent finished briefly
    recent = []
    for j in rows[:3]:
        lab = (j.get("label") or j.get("tool_name") or "?")[:32]
        recent.append(f"{lab}:{j.get('status')}")
    return f"jobs: {n}/{cap} running" + (f" — recent: {', '.join(recent)}" if recent else "")
