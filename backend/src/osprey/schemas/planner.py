"""The Action a planner emits — plans/harness/09-dual-mode-planner.md Step 1.

One protocol, two planners: ``DeterministicPlanner`` (no LLM) and the LLM
reasoner (the CLI's own loop, cli/agent/loop.py, or any MCP-connected
harness — it already reads the context packet and proposes/executes actions
via tool calls; it does not need a second, backend-side Python
implementation of "call an LLM", so there is no ``LLMPlanner`` class here.
The protocol exists so BOTH share one action vocabulary and one director).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class ActionKind(StrEnum):
    EXPAND_RECON = "expand_recon"       # run one recon-breadth pass (capability: surface_expansion.run_expansion_pass)
    VULN_DISPATCH = "vuln_dispatch"     # run one vuln/web dispatch stage (capability: heuristic_engine.run_dispatch_stage)
    SPAWN_AGENT = "spawn_agent"         # spawn an LLM phase agent (capability: phase_supervisor._spawn_agent_job)
    NONE = "none"                       # nothing left above the priority threshold — fixpoint


class Action(BaseModel):
    kind: ActionKind
    reason: str = ""
    # Only set for SPAWN_AGENT — which phase (recon|vuln|exploit).
    phase: str = ""
