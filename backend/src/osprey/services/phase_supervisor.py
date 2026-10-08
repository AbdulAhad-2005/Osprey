"""Read-only phase readiness, status, and scoped-agent briefing helpers.

``platform_pipeline`` and the REST pipeline endpoints report what evidence has
unlocked; they do not drive an engagement or spawn agents. External harnesses
may use the returned briefs to start explicit scoped-agent jobs with their own
native subagent mechanism. Nothing in this module runs a root loop or spawns
anything — it is a pure readiness/status/brief provider.
"""

from __future__ import annotations

import logging
from typing import Any

from osprey.services import priority, sufficiency
from osprey.services.job_store import get_job_store

logger = logging.getLogger(__name__)

# Downstream phases whose readiness the conductor reports (recon is the
# always-on entry phase, handled separately). Unlocking is a signal only — the
# LLM/harness decides whether to spawn work for them via its own subagent
# mechanism (or platform_spawn_agent).
_DOWNSTREAM_PHASES = ("vuln", "exploit")


# The brief handed to a spawned worker must match the doctrine the top-level
# operator follows (AGENTS.md operator card point #4: drive the typed tools
# directly; platform_investigation_step/execute is the no-LLM deterministic
# baseline, never how an LLM-driven worker should operate). A CI test
# (test_subagent_briefs_match_doctrine) asserts no LLM-facing brief here ever
# recommends platform_investigation_step, so this can't silently drift back.
_SUBAGENT_BRIEFS: dict[str, str] = {
    "recon": (
        "Drive the typed recon tools directly, one at a time, reading each result before "
        "choosing the next — exactly as the top-level operator does. Discover with "
        "subfinder_scan/amass_scan/crt_sh_query (and domain_hunter for sisters); resolve with "
        "dnsx_resolve; check liveness with httpx_probe; find ports/services with "
        "naabu_port_scan then nmap_service_scan -sV; probe fronted/dangling hosts with "
        "cdn_origin_probe/subdomain_takeover_check; go web-deep with js_recon/katana_crawl/"
        "feroxbuster. Use platform_context and platform_priority to see what is ranked highest "
        "and why after each result, and platform_attempts to avoid re-running what was already "
        "tried. Do NOT route work through platform_investigation_step/execute — that is the "
        "no-LLM deterministic baseline, not how you drive. Pass engagement_id=<id> on every "
        "call (concurrent-chat protection). Return a concise final report: what was probed, "
        "what was found with evidence, what is noise and why."
    ),
    "vuln": (
        "Drive the typed vuln tools directly against the evidence-backed surface recon "
        "established, one at a time, reading each result: nuclei_scan/wpscan_analyze/nikto_scan/"
        "sslyze_scan/graphql_cop_scan per detected technology, arjun_scan/x8_parameter_discovery "
        "for hidden params, sqlmap_scan/dalfox_xss_scan on injection points. Use "
        "platform_context/platform_priority to see what is ranked highest and platform_attempts "
        "to avoid redo. Confirm real issues with observed proof (body/banner), never a hostname "
        "or a scanner title alone; run deeper/custom checks the mechanical dispatch wouldn't pick "
        "(chained checks, business-logic and auth probes). If you surface a new host/subdomain/"
        "service, report it so recon can reopen on it. Do NOT route work through "
        "platform_investigation_step/execute (the no-LLM baseline). Pass engagement_id=<id> on "
        "every call. Return a concise final report: what was probed, what was found with "
        "evidence, what is noise and why."
    ),
    "exploit": (
        "Attempt exploitation ONLY for evidence-backed candidates the vuln phase produced, "
        "and only within scope the user has explicitly authorized (Safety section — "
        "destructive/exploit work needs explicit permission). Without that approval, limit "
        "yourself to exploit-queue review and PoC-tier reads. Drive the typed exploit tools "
        "directly; do NOT route work through platform_investigation_step/execute. Pass "
        "engagement_id=<id> on every call. Return a concise final report of what was confirmed "
        "vs. attempted."
    ),
}


def subagent_brief(phase: str) -> str:
    """Ready-to-spawn task brief for a phase subagent — copy straight into your
    native Task/subagent mechanism. Kept in sync with AGENTS.md's operator
    doctrine (drive typed tools directly) by test_subagent_briefs_match_doctrine."""
    return _SUBAGENT_BRIEFS.get(phase, "")


def phase_readiness_snapshot(engagement_id: str, run_id: str = "") -> dict[str, Any]:
    """Pure, LLM-free readiness read for external drivers — no job spawning and
    no ``llm_configured()`` requirement. Each unlocked phase carries a ready-to-
    spawn ``brief`` so using the harness pattern costs nothing beyond reading
    this response and calling your own subagent mechanism with it.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return {"engagement_id": "", "phases": {}, "signals": {}}

    signals = sufficiency.phase_signals(eid)
    ctx = priority.build_context(eid)
    phases: dict[str, Any] = {
        "recon": {"always_active": True, "brief": subagent_brief("recon")}
    }
    for phase in _DOWNSTREAM_PHASES:
        unlocked, reason = priority.should_unlock_phase(eid, phase, ctx=ctx)
        phases[phase] = {
            "unlocked": unlocked,
            "reason": reason if unlocked else "",
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


def _reopen_signal(finding_type: str) -> str:
    """Map a reopen finding-type to its sufficiency signal name."""
    return {"subdomain": "subdomains", "host": "live_hosts"}.get(finding_type, finding_type)


def start_pipeline(engagement_id: str, run_id: str = "") -> dict[str, Any]:
    """Read the conductor's phase-readiness state — always read-only,
    regardless of backend LLM configuration. Every driver — an external
    harness over MCP, or the CLI's own local agent loop (cli/agent/) —
    supplies its own brain and drives execution itself using this signal:
    its own native subagents (the CLI: cli/agent/loop.py's spawn_subagents;
    a harness: its own Task mechanism), or platform_spawn_agent for a
    one-off backend-driven agent. Nothing here ever spawns anything
    automatically — this function used to branch on llm_configured() alone,
    so a backend key configured for one session could silently hijack any
    other MCP-connected harness's platform_pipeline(action='start') call;
    that branch was removed outright, not made conditional.
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
