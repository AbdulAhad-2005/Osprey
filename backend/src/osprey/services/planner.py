"""``DeterministicPlanner`` — plans/harness/09-dual-mode-planner.md Step 1.

Picks the next action from real signals only: priority scores (Plan 06) and
what the current run has already exhausted. Never invents a decision from a
hardcoded count or a boolean flag — this is exactly the thing
plans/harness/06-prioritization-engine.md Step 4 and this plan's Step 5
retire (``sufficiency``'s old finding-count triggers, ``heuristic_engine``'s
``include_vuln_dispatch`` boolean).

Deliberately does not know how to run an action — that's the capability
layer (``surface_expansion.run_expansion_pass``, ``heuristic_engine.
run_dispatch_stage``, ``phase_supervisor``'s agent-spawn helpers), invoked by
``investigation_director.py``. This module only decides WHAT'S NEXT.
"""

from __future__ import annotations

from dataclasses import dataclass

from osprey.schemas.planner import Action, ActionKind
from osprey.services import priority


@dataclass
class PlannerState:
    """What the current run has already tried — the director tracks this
    across its own loop iterations and passes it in fresh each call, so the
    planner itself stays a pure function of (engagement state, run state)."""

    engagement_id: str
    recon_exhausted: bool = False
    vuln_exhausted: bool = False


class DeterministicPlanner:
    """No LLM. Picks the highest-priority worthwhile action from the world
    model + priority engine alone — recon breadth first (there is always
    more to map until the frontier is genuinely exhausted, not until an
    arbitrary count), then vuln dispatch once ``priority.should_unlock_phase``
    says there's real evidence to work with. Never proposes exploitation
    (SPAWN_AGENT for the exploit phase) — plans/harness's own no-LLM rule:
    the deterministic path runs recon -> vuln and queues exploit candidates,
    it never launches exploitation itself; that needs judgment only an LLM
    (or the operator) is trusted to apply.
    """

    def decide_next_action(self, state: PlannerState) -> Action:
        eid = state.engagement_id
        if not state.recon_exhausted:
            return Action(kind=ActionKind.EXPAND_RECON, reason="recon frontier not yet exhausted")

        if not state.vuln_exhausted:
            ctx = priority.build_context(eid)
            unlocked, reason = priority.should_unlock_phase(eid, "vuln", ctx=ctx)
            if unlocked:
                return Action(kind=ActionKind.VULN_DISPATCH, reason=reason)
            return Action(kind=ActionKind.NONE, reason=f"vuln not yet worthwhile — {reason}")

        return Action(kind=ActionKind.NONE, reason="recon and vuln both exhausted for this run")
