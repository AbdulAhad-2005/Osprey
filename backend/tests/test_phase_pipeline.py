"""Deterministic coverage for the multi-agent phase pipeline.

The LLM-driven parts (the agents themselves) need a live model + targets, so
these tests cover the mechanical conductor: sufficiency triggers, the pure
spawn-decision function, the data-driven expansion tool selection, and the
agent-job spawn guards.
"""

from __future__ import annotations

import asyncio

import pytest
from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.services import sufficiency
from osprey.services.phase_supervisor import decide_actions

# --- sufficiency triggers -------------------------------------------------

def test_vuln_triggers_on_live_hosts():
    assert sufficiency.should_trigger("vuln", "", signals={"live_hosts": 3})


def test_vuln_not_triggered_on_empty_surface():
    assert not sufficiency.should_trigger("vuln", "", signals={"live_hosts": 0, "services": 0})


def test_exploit_triggers_on_vulnerability():
    assert sufficiency.should_trigger("exploit", "", signals={"vulnerabilities": 1})


def test_exploit_not_triggered_on_recon_only():
    assert not sufficiency.should_trigger("exploit", "", signals={"live_hosts": 5, "urls": 100})


def test_unknown_phase_never_triggers():
    assert not sufficiency.should_trigger("nonsense", "", signals={"live_hosts": 99})


# --- pure spawn decision --------------------------------------------------

def test_decide_spawns_vuln_when_hosts_present():
    actions = decide_actions(
        signals={"live_hosts": 3},
        active_by_phase={},
        spawned_by_phase={},
        max_agents_per_phase=3,
    )
    phases = {a.phase for a in actions}
    assert "vuln" in phases
    assert "exploit" not in phases  # nothing exploitable found yet


def test_decide_skips_already_active_phase():
    actions = decide_actions(
        signals={"live_hosts": 3, "vulnerabilities": 1},
        active_by_phase={"vuln": 1},
        spawned_by_phase={},
        max_agents_per_phase=3,
    )
    phases = {a.phase for a in actions}
    assert "vuln" not in phases   # already running — never double-spawn
    assert "exploit" in phases    # vuln finding present, exploit not active


def test_decide_respects_per_phase_budget():
    actions = decide_actions(
        signals={"live_hosts": 5},
        active_by_phase={},
        spawned_by_phase={"vuln": 3},
        max_agents_per_phase=3,
    )
    assert all(a.phase != "vuln" for a in actions)


# --- data-driven expansion tool selection ---------------------------------

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


# --- agent-job spawn guards ----------------------------------------------

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
