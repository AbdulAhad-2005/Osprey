"""Deterministic phase signals over the shared engagement blackboard.

Finding counts, and pipeline lifecycle/safety knobs (``config/phase_pipeline.
yaml``) — spawn caps, time budget, poll interval, which finding types reopen
recon. Counts are still surfaced for operator visibility (``phase_signals``),
but Plan 06 (plans/harness/06-prioritization-engine.md Step 4) retired this
module's old finding-count PHASE-UNLOCK triggers (``should_trigger``/
``trigger_reason``) — a downstream phase now unlocks when
``services.priority.should_unlock_phase`` says a multi-factor priority score
crosses a threshold, not when a count crosses a hardcoded number. This is the
"engine owns routine/completeness, LLM owns judgment" split made mechanical:
readiness is computed, not guessed; what the spawned agent then DOES with that
surface is the LLM's call.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from osprey.schemas.finding import FindingType
from osprey.services.config_loader import read_config
from osprey.services.findings_store import get_findings_store

logger = logging.getLogger(__name__)

_DEFAULTS: dict[str, Any] = {
    "recon_reopen_on": ["subdomain", "host"],
    "max_agents_per_phase": 3,
    "pipeline_time_budget_seconds": 3600,
    "supervisor_poll_seconds": 8,
}

# Signal name -> the finding types whose counts feed it.
_SIGNAL_TYPES: dict[str, tuple[FindingType, ...]] = {
    "subdomains": (FindingType.SUBDOMAIN,),
    "live_hosts": (FindingType.HOST,),
    "services": (FindingType.SERVICE, FindingType.PORT),
    "technologies": (FindingType.TECHNOLOGY,),
    "urls": (FindingType.URL,),
    "vulnerabilities": (FindingType.VULNERABILITY,),
    "credentials": (FindingType.CREDENTIAL,),
    "secrets": (FindingType.SECRET,),
}


@lru_cache(maxsize=1)
def load_pipeline_config() -> dict[str, Any]:
    data = dict(_DEFAULTS)
    raw = read_config("phase_pipeline.yaml")
    if isinstance(raw, dict):
        data.update(raw)
    return data


def reload_pipeline_config() -> dict[str, Any]:
    load_pipeline_config.cache_clear()
    return load_pipeline_config()


def phase_signals(engagement_id: str) -> dict[str, int]:
    """Count blackboard findings into the named pipeline signals (one query)."""
    counts = dict.fromkeys(_SIGNAL_TYPES, 0)
    if not (engagement_id or "").strip():
        return counts
    findings = get_findings_store().list(engagement_id=engagement_id, limit=5000)
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f.finding_type.value] = by_type.get(f.finding_type.value, 0) + 1
    for signal, types in _SIGNAL_TYPES.items():
        counts[signal] = sum(by_type.get(t.value, 0) for t in types)
    return counts


def recon_reopen_types() -> frozenset[str]:
    cfg = load_pipeline_config()
    return frozenset(str(t).strip().lower() for t in (cfg.get("recon_reopen_on") or []))
