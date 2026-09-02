"""Top-level agent entry point: routes to a single phase agent or the conductor pipeline."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from osprey.schemas.engagement import Engagement
from osprey.services.agent_common import AgentEventHandler, AgentResponse
from osprey.services.phase_agent import get_phase_agent

logger = logging.getLogger(__name__)


async def run_agent(
    prompt: str,
    engagement: Engagement | None = None,
    *,
    phase: str = "full",
    run_id: str | None = None,
    conversation_history: list[dict[str, Any]] | None = None,
    max_turns: int | None = None,
    on_event: AgentEventHandler | None = None,
) -> AgentResponse:
    """Single entry point for the chat API. Routes phase to the right agent.

    ``commander`` is the default conversational brain (owns the conductor as a
    background job). ``full`` is the explicit one-shot batch pipeline — kept as a
    tool/flag, not the chat default.
    """
    if phase == "full":
        if engagement is None:
            return AgentResponse(
                success=False,
                final_message="phase='full' requires a target. Name one (e.g. 'example.com') and I'll bind it.",
                phase="full",
                error="no_engagement",
            )
        return await _run_full_via_pipeline(engagement, run_id=run_id, on_event=on_event)
    if phase in ("recon", "network", "vuln", "web", "exploit", "osint", "custom", "commander"):
        result = await get_phase_agent().run(
            prompt,
            engagement,
            phase=phase,
            run_id=run_id,
            conversation_history=conversation_history,
            max_turns=max_turns,
            on_event=on_event,
        )
        return result.agent
    return AgentResponse(
        success=False,
        final_message=(
            f"Invalid phase '{phase}'. Use commander (default), recon, network, vuln, "
            "web, exploit, osint, custom, or full."
        ),
        phase=phase,
        error="invalid_phase",
    )


async def _run_full_via_pipeline(
    engagement: Engagement,
    *,
    run_id: str | None = None,
    on_event: AgentEventHandler | None = None,
) -> AgentResponse:
    """phase=full: the deterministic conductor drives recon->vuln->exploit.

    Spawns recon/vuln/exploit agents concurrently and data-triggers each via
    the shared blackboard, then summarizes. Runs to fixpoint or a hard time
    budget. Agent-level narration streams through on_event as sub-agent jobs
    run; here we forward the conductor's own lifecycle events too.
    """
    from osprey.services.phase_supervisor import run_pipeline

    start = time.time()
    session_run_id = run_id or uuid.uuid4().hex[:12]

    async def forward(event: str, data: dict[str, Any]) -> None:
        if on_event is not None:
            result = on_event(event, data)
            if result is not None:
                await result

    summary = await run_pipeline(
        engagement_id=engagement.id, run_id=session_run_id, on_event=forward
    )
    signals = summary.get("signals", {}) if isinstance(summary, dict) else {}
    spawned = summary.get("spawned_by_phase", {}) if isinstance(summary, dict) else {}
    lines = [
        f"# Pipeline complete for {engagement.target}",
        "",
        "Ran the concurrent multi-agent pipeline (recon/vuln/exploit) to fixpoint.",
        "",
        "**Surface discovered (shared findings):**",
        f"- subdomains: {signals.get('subdomains', 0)}",
        f"- live hosts: {signals.get('live_hosts', 0)}",
        f"- services/ports: {signals.get('services', 0)}",
        f"- technologies: {signals.get('technologies', 0)}",
        f"- URLs: {signals.get('urls', 0)}",
        f"- vulnerabilities: {signals.get('vulnerabilities', 0)}",
        f"- credentials/secrets: {signals.get('credentials', 0) + signals.get('secrets', 0)}",
        "",
        f"**Agents spawned by phase:** {spawned or '{}'}",
        "",
        "Read platform_findings / the findings API for the full detail each agent recorded.",
    ]

    # Empty surface on a real target is almost never a real empty result — it is
    # a setup problem, and the operator needs to be told which layer failed
    # rather than handed a wall of zeros. This mirrors the engine's per-pass tool
    # health diagnostic (surface_expansion) for the LLM-driven path, where the
    # usual cause is either the model never calling a tool (small/local models)
    # or the execution backend being unreachable.
    total_surface = sum(
        int(signals.get(k, 0))
        for k in ("subdomains", "live_hosts", "services", "technologies", "urls", "vulnerabilities")
    )
    if total_surface == 0:
        lines += [
            "",
            "⚠️ **No surface discovered — this is almost always a setup problem, not an empty target.** "
            "Check, in order:",
            "1. The recon agent's LLM never called a tool (common with small/local models). "
            "A deterministic, no-LLM alternative exists: re-run with `/scan <target> --engine`.",
            "2. The execution backend can't run tools — verify with `/tools` (installed vs missing) "
            "and that the Kali container has network/DNS egress.",
        ]
    response = AgentResponse(
        success=True,
        final_message="\n".join(lines),
        run_id=session_run_id,
        phase="full",
        total_duration_seconds=time.time() - start,
    )
    await forward("assistant", {"content": response.final_message, "phase": "full"})
    await forward("done", {
        "success": True,
        "response": response.final_message,
        "run_id": session_run_id,
        "phase": "full",
        "tool_calls_count": 0,
        "duration_seconds": round(time.time() - start, 2),
    })
    return response
