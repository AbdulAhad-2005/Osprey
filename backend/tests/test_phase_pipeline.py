"""Deterministic coverage for the multi-agent phase pipeline that ISN'T
already covered elsewhere.

Two clusters of tests used to live here and were removed, not patched around:
- ``sufficiency.should_trigger`` tests — that finding-count trigger mechanism
  was retired by plans/harness/06-prioritization-engine.md Step 4 in favor of
  ``priority.should_unlock_phase`` (a real multi-factor score crossing a
  threshold, not a hardcoded count). Its replacement is covered by
  ``test_priority.py::test_phase_unlocks_on_priority_not_finding_count`` /
  ``test_phase_locked_when_nothing_scored``.
- ``decide_actions(signals=...)`` tests — ``decide_actions`` itself is still
  live, but its signature changed to ``phase_unlock: dict[str, tuple[bool,
  str]]`` (precomputed priority-unlock results) in the same plan. Identical
  scenarios are covered against the current signature by
  ``test_phase_supervisor_decide_actions.py``.

What's left here is genuinely not covered anywhere else: the data-driven
expansion tool-selection filter, and the agent-job spawn depth guard.
"""

from __future__ import annotations

import asyncio

import pytest
from osprey.schemas.jobs import JobKind, JobStartRequest


def test_installed_steps_filters_uninstalled(monkeypatch):
    from osprey.services import surface_expansion as se

    class _Tool:
        def __init__(self, name, installed):
            self.name = name
            self.installed = installed

    tools = {
        "subfinder_scan": _Tool("subfinder_scan", True),
        "amass_scan": _Tool("amass_scan", False),
    }
    monkeypatch.setattr(se, "get_tool", lambda name: tools.get(name))
    # subfinder_scan + amass_scan both live in the wordlist_discovery section.
    steps = se._installed_steps("wordlist_discovery")
    names = [tool for tool, _param, _extra in steps]
    assert "subfinder_scan" in names
    assert "amass_scan" not in names  # not installed → dropped


def test_agent_spawn_depth_guard_rejects_deep_nesting():
    from osprey.services.job_store import get_job_store

    async def _go():
        return get_job_store().create_and_spawn(
            JobStartRequest(
                kind=JobKind.AGENT, engagement_id="eng_depthtest",
                role="recon", task="x", depth=8,  # > default max_spawn_depth (4)
            )
        )

    with pytest.raises(ValueError, match="depth"):
        asyncio.run(_go())
