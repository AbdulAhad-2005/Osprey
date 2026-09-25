"""DeterministicPlanner — plans/harness/09-dual-mode-planner.md Step 1.

Pure decision logic: given what the current run has already exhausted, what
should happen next — recon breadth first, then vuln dispatch once
priority.should_unlock_phase says there's real evidence, then nothing.
Never proposes exploitation (that's the LLM/operator's call).
"""

from __future__ import annotations

import uuid

from osprey.schemas.observation import Observation, ObservationType
from osprey.schemas.planner import ActionKind
from osprey.services.observation_store import get_observation_store
from osprey.services.planner import DeterministicPlanner, PlannerState


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_proposes_recon_while_not_yet_exhausted():
    planner = DeterministicPlanner()
    action = planner.decide_next_action(PlannerState(engagement_id=_eid()))
    assert action.kind == ActionKind.EXPAND_RECON


def test_proposes_vuln_dispatch_once_recon_exhausted_and_priority_unlocks_it():
    # config/priority.yaml's phase_item_types feeds the "vuln" gate from
    # port/service/technology/url/host/injection_point/waf observations —
    # scanner_signal feeds "exploit" instead (see the Plan 06 phase-gating
    # test), so an injection_point is what should actually unlock vuln here.
    eid = _make_engagement(f"planner-vuln-{_eid()}.test")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.INJECTION_POINT, target="planner-vuln.test",
        source_tool="arjun_scan", details={"parameter": "redirect_url"},
    ))
    planner = DeterministicPlanner()
    action = planner.decide_next_action(PlannerState(engagement_id=eid, recon_exhausted=True))
    assert action.kind == ActionKind.VULN_DISPATCH


def test_proposes_none_when_recon_exhausted_and_nothing_unlocks_vuln():
    planner = DeterministicPlanner()
    action = planner.decide_next_action(PlannerState(engagement_id=_eid(), recon_exhausted=True))
    assert action.kind == ActionKind.NONE


def test_proposes_none_when_both_exhausted():
    planner = DeterministicPlanner()
    action = planner.decide_next_action(
        PlannerState(engagement_id=_eid(), recon_exhausted=True, vuln_exhausted=True)
    )
    assert action.kind == ActionKind.NONE


def test_never_proposes_spawn_agent_for_exploit():
    """The deterministic (no-LLM) planner never launches exploitation itself
    — it queues candidates and stops; only an LLM/operator decides to go
    further. There is no code path in decide_next_action that can return
    ActionKind.SPAWN_AGENT at all."""
    import inspect

    from osprey.services import planner as planner_module

    source = inspect.getsource(planner_module.DeterministicPlanner.decide_next_action)
    assert "SPAWN_AGENT" not in source
