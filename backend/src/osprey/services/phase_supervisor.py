"""Phase supervisor — the deterministic conductor of the multi-agent pipeline.

Instead of ONE agent walking recon → vuln → exploit in a single serial loop, a
mechanical conductor runs *concurrent* phase agents and starts each downstream
phase the moment the shared blackboard has ENOUGH data for it — not when the
upstream phase "finishes".

Design (matches the operator's model):
  * Recon agent starts immediately — the only phase auto-started. It has full
    tool access and real judgment (multiple scan techniques, CDN/WAF-origin
    bypass, noise interpretation), so it's the sole driver of initial breadth;
    nothing else races it for the same ground. (The deterministic BFS engine —
    surface_expansion.py, no LLM judgment — remains available standalone via
    platform_expand for a genuinely LLM-free fast pass; it is deliberately NOT
    auto-started alongside the recon agent, since both target the same
    subdomains/IPs/ports/CDN-origin surface with the same tools and would just
    race the shared tool-execution cache instead of complementing each other.)
  * As soon as recon has produced attack surface (sufficiency.should_trigger), a
    vuln agent starts — recon keeps running.
  * As soon as vuln has produced something exploitable, an exploit agent starts —
    recon and vuln keep running.
  * Feedback: if a later phase discovers a new host/subdomain while recon is idle,
    recon is re-spawned for it.
  * The conductor is deterministic and LLM-free; the agents it spawns are the
    brains. They coordinate ONLY through the shared per-engagement stores — no
    bespoke message bus. Each agent may itself spawn intra-phase sub-agents.

The spawn/lifecycle DECISION is a pure function (``decide_actions``) so it is unit
testable without an LLM; the async ``run_pipeline`` wraps it with the job store,
findings deltas, and a hard time budget.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from osprey.schemas.jobs import JobKind, JobStartRequest, JobStatus
from osprey.services import sufficiency
from osprey.services.job_store import get_job_store

logger = logging.getLogger(__name__)

# Downstream phases the conductor auto-triggers (recon is the always-on entry
# phase, handled separately; network/web/osint are left to the LLM/harness to
# spawn explicitly via spawn_agent when it judges them worthwhile).
_DOWNSTREAM_PHASES = ("vuln", "exploit")

SupervisorEvent = Callable[[str, dict[str, Any]], Awaitable[None] | None]


@dataclass
class SpawnAction:
    phase: str
    reason: str


@dataclass
class PipelineState:
    engagement_id: str
    run_id: str
    started_at: float = field(default_factory=time.monotonic)
    spawned_by_phase: dict[str, int] = field(default_factory=dict)
    triggered: set[str] = field(default_factory=set)
    last_reopen_count: int = 0
    stable_polls: int = 0
    last_findings_total: int = -1


def decide_actions(
    *,
    signals: dict[str, int],
    active_by_phase: dict[str, int],
    spawned_by_phase: dict[str, int],
    max_agents_per_phase: int,
) -> list[SpawnAction]:
    """Pure decision: which downstream phase agents to spawn right now.

    A phase is spawned when the blackboard meets its trigger AND no agent for it
    is currently active AND its per-phase spawn budget is not exhausted. Upstream
    phases are never stopped — this only ADDS concurrent work.
    """
    actions: list[SpawnAction] = []
    for phase in _DOWNSTREAM_PHASES:
        if active_by_phase.get(phase, 0) > 0:
            continue
        if spawned_by_phase.get(phase, 0) >= max_agents_per_phase:
            continue
        if sufficiency.should_trigger(phase, "", signals=signals):
            actions.append(SpawnAction(phase=phase, reason=sufficiency.trigger_reason(phase, signals)))
    return actions


_SUBAGENT_BRIEFS: dict[str, str] = {
    "recon": (
        "Enumerate subdomains EVERY way (subfinder + crt.sh + amass + domain_hunter + "
        "cert SANs), resolve ALL to IPs (dnsx), attempt CDN/WAF-origin bypass on every "
        "fronted host (direct-to-origin probes, DNS history, TLS, header analysis, "
        "origin_ip_attribution), then ports in MULTIPLE scan kinds (naabu top-1000, SYN, "
        "rustscan, masscan variants), then services/versions (-sV -sC on everything open), "
        "then URLs (httpx live, gau/wayback, js_recon, katana). Anything >90s goes through "
        "platform_job_start — never block on one call. Check platform_attempts first to "
        "avoid re-running what's already tried. Pass engagement_id=<id> on every call "
        "(concurrent-chat protection). Return a concise final report: what was probed, what "
        "was found with evidence, what is noise and why."
    ),
    "vuln": (
        "Run vulnerability analysis on the hosts/services/tech recon has already surfaced: "
        "nuclei, dalfox, sqlmap, nikto, and tech-aware checks matching the detected stack. "
        "Confirm real issues with proof (body/banner), never a hostname or nuclei title "
        "alone. If you surface a new host/subdomain/service, report it back so recon can "
        "be reopened on it. Pass engagement_id=<id> on every call. Return a concise final "
        "report: what was probed, what was found with evidence, what is noise and why."
    ),
    "exploit": (
        "Attempt exploitation ONLY for evidence-backed candidates the vuln phase produced, "
        "and only within scope the user has explicitly authorized (Safety section — "
        "destructive/exploit work needs explicit permission). Without that approval, limit "
        "yourself to exploit-queue review and PoC-tier reads. Pass engagement_id=<id> on "
        "every call. Return a concise final report of what was confirmed vs. attempted."
    ),
}


def subagent_brief(phase: str) -> str:
    """Ready-to-spawn task brief for a phase subagent — copy straight into your
    native Task/subagent mechanism. Single source of truth for the recon/vuln/
    exploit orchestration pattern documented in AGENTS.md, so the two can't drift."""
    return _SUBAGENT_BRIEFS.get(phase, "")


def phase_readiness_snapshot(engagement_id: str, run_id: str = "") -> dict[str, Any]:
    """Pure, LLM-free readiness read for the conductor — no job spawning, no
    ``llm_configured()`` requirement. This is the one thing both executors
    (an external harness driving its own subagents, or this module's own
    auto-spawn loop) read to agree on phase state, so neither can drift into
    a different definition of 'ready'. Each unlocked phase carries a ready-to-
    spawn ``brief`` so using the harness pattern costs nothing beyond reading
    this response and calling your own subagent mechanism with it.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return {"engagement_id": "", "phases": {}, "signals": {}}

    signals = sufficiency.phase_signals(eid)
    phases: dict[str, Any] = {
        "recon": {"always_active": True, "brief": subagent_brief("recon")}
    }
    for phase in _DOWNSTREAM_PHASES:
        unlocked = sufficiency.should_trigger(phase, eid, signals=signals)
        phases[phase] = {
            "unlocked": unlocked,
            "reason": sufficiency.trigger_reason(phase, signals) if unlocked else "",
            "brief": subagent_brief(phase) if unlocked else "",
        }

    reopen_types = sufficiency.recon_reopen_types()
    reopen_signal_names = {_reopen_signal(t) for t in reopen_types}
    reopen_count = sum(signals.get(name, 0) for name in reopen_signal_names)

    return {
        "engagement_id": eid,
        "run_id": run_id,
        "signals": signals,
        "phases": phases,
        "recon_reopen_candidates": reopen_count,
    }


def phase_readiness_text(snapshot: dict[str, Any], *, include_briefs: bool = True) -> str:
    """Compact rendering of ``phase_readiness_snapshot`` for tool responses.
    Leads with an explicit spawn instruction, not just a status line — the
    point is to make "use the harness pattern" the obvious next action, not
    something the reader has to recall from documentation."""
    if not snapshot.get("engagement_id"):
        return "phase status: no engagement bound"
    signals = snapshot.get("signals") or {}
    phases = snapshot.get("phases") or {}
    sig_line = ", ".join(f"{k}={v}" for k, v in signals.items() if v)

    lines = [
        "You are the conductor. Spawn phase work as your own native subagents "
        "(Task mechanism) — no backend key needed, full MCP tool access, shared "
        "engagement memory. Recon is always first.",
        f"recon: always active. evidence so far: {sig_line or '(none yet)'}",
    ]
    if include_briefs:
        recon_brief = ((phases.get("recon") or {}).get("brief") or "").strip()
        if recon_brief:
            lines.append(f"  → SPAWN RECON NOW with this brief:\n    {recon_brief}")

    for phase in _DOWNSTREAM_PHASES:
        info = phases.get(phase) or {}
        if info.get("unlocked"):
            lines.append(f"{phase}: unlocked — {info.get('reason') or 'threshold met'}")
            if include_briefs:
                brief = (info.get("brief") or "").strip()
                if brief:
                    lines.append(f"  → SPAWN {phase.upper()} NOW with this brief:\n    {brief}")
        else:
            lines.append(f"{phase}: not yet unlocked")
    reopen = int(snapshot.get("recon_reopen_candidates") or 0)
    if reopen:
        lines.append(f"recon reopen candidates: {reopen} new host/subdomain finding(s) — spawn another recon subagent scoped to them")
    return "\n".join(lines)


async def _maybe_auto_scan_network_vulns(*, engagement_id: str, run_id: str) -> None:
    """Deterministically run a comprehensive nmap vuln/vulners scan against
    whatever ports recon has established, right before the vuln phase spawns
    — instead of leaving it to agent discretion. Best-effort: any failure
    here must never block the phase transition. Runs once per engagement
    (tool_coverage guards re-running)."""
    try:
        from osprey.schemas.finding import FindingType
        from osprey.schemas.tools import ToolExecutionRequest
        from osprey.services.engagement_store import get_engagement_store
        from osprey.services.findings_store import get_findings_store
        from osprey.services.target_utils import resolve_ipv4
        from osprey.services.tool_coverage_store import get_tool_coverage_store
        from osprey.services.tool_execution import execute_tool_request

        eng = get_engagement_store().get(engagement_id)
        target = eng.target if eng else ""
        if not target:
            return
        scan_target = resolve_ipv4(target) or target

        coverage = get_tool_coverage_store()
        if coverage.has_run(engagement_id=engagement_id, tool_name="nmap_custom_scan", asset=scan_target):
            return

        store = get_findings_store()
        port_findings = store.list(engagement_id=engagement_id, finding_type=FindingType.PORT, limit=300)
        port_findings += store.list(engagement_id=engagement_id, finding_type=FindingType.SERVICE, limit=300)
        ports = sorted(
            {str(f.metadata.get("port")) for f in port_findings if str(f.metadata.get("port") or "").isdigit()},
            key=int,
        )
        if not ports:
            return

        await execute_tool_request(
            ToolExecutionRequest(
                tool_name="nmap_custom_scan",
                params={"target": scan_target},
                engagement_id=engagement_id,
                run_id=run_id,
                additional_args=f'-Pn -sV --script "vuln,vulners" -p {",".join(ports)}',
                timeout=600,
                use_recovery=True,
                record_findings=True,
            )
        )
    except Exception:
        logger.exception(
            "Auto network-vuln scan failed for engagement %s (non-fatal, phase transition continues)",
            engagement_id,
        )


def _active_by_phase(engagement_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for job in get_job_store().list_active_agents(engagement_id):
        counts[job.role] = counts.get(job.role, 0) + 1
    return counts


def _spawn_agent_job(
    *, engagement_id: str, run_id: str, role: str, task: str = "", depth: int = 0
) -> str | None:
    """Spawn a phase-agent job; returns job_id or None if a cap/budget blocked it."""
    try:
        summary = get_job_store().create_and_spawn(
            JobStartRequest(
                kind=JobKind.AGENT,
                engagement_id=engagement_id,
                run_id=run_id,
                role=role,
                task=task,
                depth=depth,
            )
        )
        return summary.job_id
    except ValueError as exc:
        logger.info("supervisor: could not spawn %s agent — %s", role, exc)
        return None


async def run_pipeline(
    *,
    engagement_id: str,
    run_id: str = "",
    on_event: SupervisorEvent | None = None,
    stable_polls_to_finish: int = 3,
) -> dict[str, Any]:
    """Drive the concurrent phase pipeline to fixpoint or the time budget.

    Returns a summary dict. Non-blocking for callers that want fire-and-forget:
    wrap in ``asyncio.create_task``. The heavy work happens in the spawned agent
    and expansion jobs; this loop only decides + monitors.
    """
    if not (engagement_id or "").strip():
        return {"error": "engagement_id required"}

    cfg = sufficiency.load_pipeline_config()
    poll = float(cfg.get("supervisor_poll_seconds") or 8)
    budget = float(cfg.get("pipeline_time_budget_seconds") or 3600)
    max_per_phase = int(cfg.get("max_agents_per_phase") or 3)
    reopen_types = sufficiency.recon_reopen_types()

    state = PipelineState(engagement_id=engagement_id, run_id=run_id)

    async def emit(event: str, data: dict[str, Any]) -> None:
        if on_event is None:
            return
        result = on_event(event, {**data, "engagement_id": engagement_id})
        if result is not None:
            await result

    # --- Kick off: the recon lead agent, not the deterministic breadth engine
    # too. The two target the same ground (subdomains/sisters/IPs/ports/CDN-
    # origin) with the same tools (domain_hunter, subfinder_scan, amass_scan,
    # naabu_port_scan, httpx_probe, dnsx_resolve, nmap_service_scan) — running
    # both here isn't complementary, it's overlapping work racing the shared
    # tool-execution cache (same tool+params = cache hit; anything else, both
    # genuinely execute). The engine's original purpose ("mechanical
    # enumeration without burning LLM turns") predates the recon agent having
    # full tool access and real judgment; now that it does, it's a strict
    # superset, so the engine is no longer auto-started here. It's still
    # available standalone via platform_expand for a genuinely LLM-free fast
    # pass (e.g. before any LLM is configured at all).
    recon_job = _spawn_agent_job(
        engagement_id=engagement_id, run_id=run_id, role="recon",
        task=subagent_brief("recon"),
    )
    state.spawned_by_phase["recon"] = 1 if recon_job else 0
    await emit("pipeline_start", {"recon_job": recon_job})

    while True:
        await asyncio.sleep(poll)

        if time.monotonic() - state.started_at > budget:
            await emit("pipeline_stop", {"reason": "time_budget"})
            break

        signals = sufficiency.phase_signals(engagement_id)
        active = _active_by_phase(engagement_id)

        # 1) Trigger downstream phases (concurrent, additive).
        for action in decide_actions(
            signals=signals,
            active_by_phase=active,
            spawned_by_phase=state.spawned_by_phase,
            max_agents_per_phase=max_per_phase,
        ):
            if action.phase == "vuln":
                await _maybe_auto_scan_network_vulns(engagement_id=engagement_id, run_id=run_id)
            job_id = _spawn_agent_job(
                engagement_id=engagement_id, run_id=run_id, role=action.phase,
                task=f"{subagent_brief(action.phase)}\n\nContext: triggered because "
                     f"{action.reason}. Work the {action.phase} surface the earlier "
                     "phases discovered.",
            )
            if job_id:
                state.spawned_by_phase[action.phase] = state.spawned_by_phase.get(action.phase, 0) + 1
                state.triggered.add(action.phase)
                await emit("phase_triggered", {"phase": action.phase, "reason": action.reason, "job_id": job_id})

        # 2) Feedback: new host/subdomain findings while recon is idle → reopen recon.
        reopen_count = sum(signals.get(_reopen_signal(t), 0) for t in reopen_types)
        recon_active = active.get("recon", 0) > 0
        if (
            not recon_active
            and reopen_count > state.last_reopen_count
            and state.spawned_by_phase.get("recon", 0) < max_per_phase * 2
        ):
            job_id = _spawn_agent_job(
                engagement_id=engagement_id, run_id=run_id, role="recon",
                task=f"{subagent_brief('recon')}\n\nContext: new hosts/subdomains were "
                     "discovered by a later phase. Expand and probe these "
                     "newly-surfaced assets.",
            )
            if job_id:
                state.spawned_by_phase["recon"] = state.spawned_by_phase.get("recon", 0) + 1
                await emit("recon_reopened", {"job_id": job_id, "reopen_count": reopen_count})
        state.last_reopen_count = reopen_count

        # 3) Fixpoint: no active agents AND no new findings for N stable polls.
        findings_total = sum(signals.values())
        any_active = bool(active) or _expansion_running(engagement_id)
        if not any_active and findings_total == state.last_findings_total:
            state.stable_polls += 1
        else:
            state.stable_polls = 0
        state.last_findings_total = findings_total

        await emit("pipeline_tick", {
            "signals": signals,
            "active": active,
            "spawned": dict(state.spawned_by_phase),
            "stable_polls": state.stable_polls,
        })

        if state.stable_polls >= stable_polls_to_finish:
            await emit("pipeline_stop", {"reason": "fixpoint"})
            break

    return {
        "engagement_id": engagement_id,
        "run_id": run_id,
        "spawned_by_phase": dict(state.spawned_by_phase),
        "triggered": sorted(state.triggered),
        "signals": sufficiency.phase_signals(engagement_id),
    }


def _reopen_signal(finding_type: str) -> str:
    """Map a reopen finding-type to its sufficiency signal name."""
    return {"subdomain": "subdomains", "host": "live_hosts"}.get(finding_type, finding_type)


def _expansion_running(engagement_id: str) -> bool:
    for job in get_job_store().list_for_engagement(engagement_id, limit=50):
        if job.kind == JobKind.EXPANSION and job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
            return True
    return False


def start_pipeline(engagement_id: str, run_id: str = "") -> dict[str, Any]:
    """Read the conductor's phase-readiness state — always read-only,
    regardless of backend LLM configuration. Any caller (an external harness
    over MCP, or a direct API call) drives execution itself — its own
    subagents, or platform_spawn_agent for a one-off backend-driven agent —
    using this signal; nothing here ever spawns anything automatically.

    Genuine backend-autonomous execution (no external harness in the loop at
    all) is a separate, CLI/GUI-only path: orchestrator.run_agent(phase='full')
    via POST /api/v1/agent/chat, gated by enable_builtin_agent + a configured
    backend key, calling run_pipeline() directly — never reachable from here,
    by design, so an MCP-connected session can never have a second LLM spawned
    on its behalf just because a key happens to be configured for an unrelated
    session (the bug this function used to have: it branched on llm_configured()
    alone, so a key configured for a CLI/GUI session silently hijacked any
    MCP-connected harness's platform_pipeline(action='start') call too).
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return {"status": "error", "error": "engagement_id required"}
    snapshot = phase_readiness_snapshot(eid, run_id=run_id)
    return {
        "status": "readiness_only",
        "engagement_id": eid,
        "phase_readiness": snapshot,
        "text": phase_readiness_text(snapshot),
    }


def pipeline_status(engagement_id: str) -> dict[str, Any]:
    active_agents = [a.model_dump() for a in get_job_store().list_active_agents(engagement_id)]
    snapshot = phase_readiness_snapshot(engagement_id)
    return {
        "status": "agents_running" if active_agents else "idle",
        "engagement_id": engagement_id,
        "active_agents": active_agents,
        "phase_readiness": snapshot,
        "text": phase_readiness_text(snapshot),
    }


def pipeline_status_line(engagement_id: str) -> str:
    """Compact `agents: running (recon:1, vuln:1)` for context headers — the
    same status pipeline_status() returns, condensed to one line so a caller
    (platform_context) gets agent visibility without a separate call."""
    status = pipeline_status(engagement_id)
    agents = status.get("active_agents") or []
    if not agents:
        return "agents: none active"
    counts: dict[str, int] = {}
    for a in agents:
        role = str(a.get("role") or "agent")
        counts[role] = counts.get(role, 0) + 1
    return "agents: running (" + ", ".join(f"{r}:{c}" for r, c in counts.items()) + ")"


def stop_pipeline(engagement_id: str, *, cancel_agents: bool = True) -> dict[str, Any]:
    """Cancel active phase-agent jobs for this engagement (e.g. spawned via
    platform_spawn_agent, or the backend auto-executor). Conductor state
    itself is read-only and has nothing of its own to stop."""
    cancelled_agents = 0
    if cancel_agents:
        for agent in get_job_store().list_active_agents(engagement_id):
            if get_job_store().cancel(agent.job_id):
                cancelled_agents += 1
    return {"status": "stopped", "engagement_id": engagement_id, "cancelled_agents": cancelled_agents}
