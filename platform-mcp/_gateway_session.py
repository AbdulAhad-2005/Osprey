"""Gateway tools — session group (registers on _core.mcp)."""

from __future__ import annotations


import _gateway_core as _core
from _gateway_core import _ENGAGEMENT_CACHE, _analyze_or_bind, _block, _clear_session, _delete, _get, _normalize_target, _post, _resolve_engagement, _safe, _session_header, mcp




@mcp.tool()
def platform_set_target(target: str, force_new: bool = False, pick: str = "") -> str:
    """
    Set or switch the active pentest target.

    Full domain (example.com) → binds engagement.
    Short name (e.g. 'zong') → returns DNS-ranked candidates; ASK the user which
    exact domain they meant, then call again with that FQDN (or pick='chosen.tld').

    Never invent a domain. Never start tools until bound to a confirmed FQDN.

    force_new: False (default) REUSES an existing engagement on this exact
    target if one exists — all its prior findings/observations/assets come
    back with it. This is almost always what you want (don't throw away
    earlier work on the same target). Pass force_new=True ONLY when the
    operator explicitly asks for a fresh/new/clean engagement on a target
    you've worked before — otherwise "start fresh" silently means "keep
    working the old one," which is the opposite of what was asked.
    """
    def _run() -> str:
        chosen = (pick or "").strip() or (target or "").strip()
        return _analyze_or_bind(chosen, force_new=force_new)

    return _safe(_run)


@mcp.tool()
def platform_investigation_step(engagement_id: str = "", offset: int = 0, limit: int = 10) -> str:
    """Read the current harness state and ranked investigation opportunities.

    This is the no-LLM deterministic baseline. Model-driven operators should
    drive typed tools directly using platform_context/platform_pipeline advice.
    This call is read-only and paged. Choose deliberately from the returned typed graph
    opportunities, then pass the opaque id and revision unchanged to
    ``platform_investigation_execute``.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        step = _get(
            "/api/v1/investigation/step",
            params={"engagement_id": ctx.engagement_id, "run_id": ctx.run_id},
        )
        opportunities = step.get("opportunities") or []
        start_offset, page_size = max(0, int(offset)), max(1, min(100, int(limit)))
        page = []
        for item in opportunities[start_offset:start_offset + page_size]:
            subjects = item.get("subjects") or []
            page.append({**{key: item.get(key) for key in ("id", "capability", "reason", "priority", "cost", "risk", "tool", "params", "additional_args", "timeout")},
                         "subject_count": len(subjects), "subjects": [
                             {"asset_id": subject.get("asset_id"), "label": subject.get("label"),
                              "evidence_count": len(subject.get("evidence_ids") or []),
                              "evidence_ids": (subject.get("evidence_ids") or [])[:5]}
                             for subject in subjects[:10]]})
        step = {**step, "opportunities": page, "total_opportunities": len(opportunities),
                "offset": start_offset, "next_offset": start_offset + page_size if start_offset + page_size < len(opportunities) else None}
        return "\n\n".join([_session_header(ctx), _block("INVESTIGATION STATE", step)])

    return _safe(_run)


@mcp.tool()
def platform_investigation_execute(
    opportunity_id: str,
    expected_revision: str,
    rationale: str = "",
    engagement_id: str = "",
) -> str:
    """Start one current investigation capability as a durable job.

    Obtain the opaque opportunity id and revision from
    ``platform_investigation_step``. Poll the returned job visibly; after it
    finishes, read the step state again and replan from the resulting evidence.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        decision = _post(
            "/api/v1/investigation/step",
            {
                "engagement_id": ctx.engagement_id,
                "run_id": ctx.run_id,
                "opportunity_id": opportunity_id,
                "expected_revision": expected_revision,
                "driver": "mcp_harness",
                "rationale": rationale,
            },
            timeout=30,
        )
        return "\n\n".join([
            _session_header(ctx),
            _block("INVESTIGATION DECISION", decision),
            "Poll the returned job until terminal, then call "
            "platform_investigation_step again to replan.",
        ])

    return _safe(_run)


@mcp.prompt(name="scan")
def scan_prompt(target: str = "", mode: str = "") -> str:
    """Slash-command entry point (`/scan` in any MCP-prompt-capable client —
    Claude Desktop/Code, OpenCode, etc.) — same convention as the CLI's
    `/scan [target] [--mcp|--engine]` and a UI's "Scan" button: one backend
    engine, several doors in. If target/mode aren't supplied as prompt
    arguments, ask the user for them before doing anything else.

    mode=mcp (default): proceed as normal — platform_set_target, then whatever
    tools the situation calls for; the LLM drives every step as usual.
    mode=engine: call platform_set_target, then repeatedly read
    platform_investigation_step, choose one current opportunity from its
    evidence factors, poll that bounded job, and re-read state until complete.
    """
    if not target.strip():
        return (
            "Ask the user for a target (domain or IP) before doing anything else. "
            "Then ask whether they want mode=mcp (LLM-driven, step by step — how this "
            "platform normally works) or mode=engine (use the deterministic ranking "
            "at every visible investigation step)."
        )
    chosen_mode = mode.strip().lower() or "mcp"
    if chosen_mode not in ("mcp", "engine"):
        chosen_mode = "mcp"
    if chosen_mode == "engine":
        return (
            f"Call platform_set_target('{target.strip()}'), then call "
            "platform_investigation_step(). Select one current opportunity using its "
            "priority factors, call platform_investigation_execute with its exact id/revision, "
            "poll its job until terminal, and repeat from fresh state until complete."
        )
    return (
        f"Call platform_set_target('{target.strip()}'), inspect "
        "platform_investigation_step(), choose one evidence-backed opportunity, execute "
        "and watch it, then replan. Add deliberate typed probes where your analysis "
        "identifies a gap the offered capabilities do not cover."
    )


@mcp.tool()
def platform_pipeline(action: str = "start", engagement_id: str = "") -> str:
    """
    The deterministic conductor's phase state: recon → vuln → exploit, evidence-
    triggered, with loop-back. Always read-only, regardless of backend LLM
    configuration — this call never spawns anything on its own, so it's always
    safe to call from an external harness session even if a backend key happens
    to be configured for an unrelated CLI/GUI use of this platform.

    Drive execution yourself: your own native subagent/Task mechanism (preferred
    — no backend key needed, full MCP tool access, shared engagement memory), or
    platform_spawn_agent for a one-off backend-driven agent if you have no
    subagent mechanism of your own. Recon is always the first/active phase; poll
    action='status' again after new work lands to see when vuln/exploit unlock
    or recon should reopen.

    (Genuine backend-autonomous execution with no external harness in the loop
    at all — e.g. this platform's own CLI/GUI driving itself with a configured
    key — is a separate, deliberately non-MCP-exposed path. It's not reachable
    from here, by design: an MCP-connected session must never have a second,
    unrelated LLM spawned on its behalf just because a backend key exists.)

    action:
      - 'start'  : read the conductor state (same as 'status' — kept as a
                   separate verb for the natural "call this first" moment).
      - 'status' : current phase-readiness snapshot + any active agent jobs
                   (however they were spawned, e.g. via platform_spawn_agent) —
                   agent jobs report real turn-by-turn progress (results_log),
                   not just a final blob; platform_job_poll for the detail.
      - 'stop'   : cancel active agent jobs for this engagement.

    Read platform_findings for what's landed in shared memory either way.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        act = (action or "start").strip().lower()
        if act == "status":
            data = _get(
                "/api/v1/pipeline/status",
                params={"engagement_id": ctx.engagement_id},
                timeout=15,
            )
        elif act == "stop":
            data = _post(
                "/api/v1/pipeline/stop",
                {"engagement_id": ctx.engagement_id},
                timeout=15,
            )
        else:
            data = _post(
                "/api/v1/pipeline/start",
                {"engagement_id": ctx.engagement_id, "run_id": ctx.run_id},
                timeout=30,
            )
        parts = [
            f"### OPERATOR MIRROR — PHASE PIPELINE ({act})",
            _session_header(ctx),
        ]
        note = (data.get("note") or "").strip()
        if note:
            parts.append(note)
        text = (data.get("text") or "").strip()
        if text:
            parts.append(text)
        else:
            parts.append(_block("Pipeline", data))
        return "\n\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_spawn_agent(
    role: str = "recon", task: str = "", scope: str = "", engagement_id: str = ""
) -> str:
    """
    Spawn ONE parallel sub-agent as a background job — for an independent slice of
    work you want done concurrently while you keep going.

    Each sub-agent is a scoped LLM loop bound to THIS engagement, so its findings
    land in shared memory and come back through platform_findings — no return
    channel needed. Use it to fan out: one agent per sister domain in recon, per
    host in vuln, per candidate in exploit.

    ONE LLM identity rule: if your own harness has a native subagent/Task
    mechanism, use THAT for this fan-out and do not also call this tool for the
    same slice of work — this tool drives the backend's OWN configured LLM key,
    a second, independent identity from whatever is running you. Calling both
    for one piece of work means two LLM loops burning one account/budget
    redundantly, not real extra parallelism. Use platform_spawn_agent only when
    you have no subagent mechanism of your own.

    role:  recon | network | vuln | web | exploit | osint | custom
    task:  what this sub-agent should accomplish (free-form)
    scope: optional asset/host/domain to focus on

    Returns a job_id — do NOT wait on it. platform_job_poll for progress,
    platform_findings to build on its results. Bounded by agent concurrency +
    spawn-budget caps; if it says the cap is hit, let one finish first.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _post(
            "/api/v1/pipeline/spawn-agent",
            {
                "engagement_id": ctx.engagement_id,
                "run_id": ctx.run_id,
                "role": role,
                "task": task,
                "scope": scope,
            },
            timeout=30,
        )
        return "\n\n".join([
            f"### OPERATOR MIRROR — SPAWN {role.upper()} AGENT",
            _session_header(ctx),
            f"**job_id:** `{data.get('job_id')}` | **status:** {data.get('status')} | role: {data.get('role')}",
            data.get("hint") or "",
            f"Keep working. platform_job_poll(job_id='{data.get('job_id')}') for progress; "
            "platform_findings for what it discovers.",
        ])

    return _safe(_run)


@mcp.tool()
def platform_delete_engagement(target: str = "", engagement_id: str = "") -> str:
    """
    Delete all engagements and stored memory/findings/graph for a target domain or specific engagement_id.

    Use this when you want to wipe prior engagement state for a target and start fresh.

    Params:
    - target: Domain name (e.g. 'example.com'). Deletes all engagements and associated data for this domain.
    - engagement_id: Specific engagement ID (e.g. 'eng_123'). Deletes that single engagement.
    - If both are empty, deletes data for the currently active target bound in session.
    """
    def _run() -> str:
        t_raw = (target or "").strip()
        e_id = (engagement_id or "").strip()

        if not t_raw and not e_id:
            if _core._SESSION_TARGET:
                t_raw = _core._SESSION_TARGET
            else:
                return "ERROR: Provide target='domain.tld' or engagement_id='...' to delete."

        if e_id:
            res = _delete(f"/api/v1/engagements/{e_id}", timeout=15)
            _clear_session(engagement_id=e_id)
            return f"Deleted engagement '{e_id}'.\n\n{_block('Deletion Result', res)}"

        norm = _normalize_target(t_raw)
        res = _delete("/api/v1/engagements/by-target", params={"target": norm}, timeout=15)

        cached_ids = [
            eid
            for eid, metadata in _ENGAGEMENT_CACHE.items()
            if _normalize_target(metadata.get("target") or "") == norm
        ]
        for cached_id in cached_ids:
            _clear_session(engagement_id=cached_id)
        if norm == _normalize_target(_core._SESSION_TARGET):
            _clear_session()

        return f"Successfully deleted engagements and stored memory for target domain '{norm}'.\n\n{_block('Deletion Result', res)}"

    return _safe(_run)



def _execution_readiness_line() -> str:
    """One-line tool-execution readiness (docker/native + whether tools can run).

    Surfaces the "no tool backend" state (e.g. a containerized backend with no
    Kali container and no host tools) so the operator learns it here instead of
    discovering it as silently-empty scan results.
    """
    try:
        status = _get("/api/v1/health/execution", timeout=8)
    except Exception:
        return ""
    if not isinstance(status, dict):
        return ""
    ready = status.get("ready", True)
    degraded = status.get("degraded", False)
    mode = status.get("mode", "?")
    message = (status.get("message") or "").strip()
    icon = "✅" if (ready and not degraded) else "⚠️"
    lead = f"{icon} Tool execution: mode={mode}, ready={ready}" + (", degraded=true" if degraded else "") + "."
    return f"{lead} {message}".strip() if message else lead


@mcp.tool()
def platform_health(target: str = "", engagement_id: str = "") -> str:
    """
    Check backend health + tool-execution readiness. Pass target= when the user
    names scope (may be short name). Short names trigger clarification.
    """
    def _run() -> str:
        health = _get("/health", timeout=10)
        readiness = _execution_readiness_line()
        health_block = _block("Platform Health", health)
        if readiness:
            health_block = f"{health_block}\n\n{readiness}"
        if target.strip():
            clarified = _analyze_or_bind(target)
            if clarified.startswith("## Target needs clarification"):
                return clarified
            return f"{_session_header()}\n\n{health_block}\n\n{clarified}"
        ctx = _resolve_engagement(engagement_id)
        return f"{_session_header(ctx)}\n\n{health_block}"

    result = _safe(_run)
    if result.startswith("ERROR"):
        return f"{result}\nStart the stack with: docker compose up -d"
    return result


@mcp.tool()
def platform_handoff(engagement_id: str = "") -> str:
    """
    Complete, self-contained engagement dossier for a downstream agent.

    Everything the next phase (exploitation / post-exploitation) needs, assembled
    from durable memory alone — no prior chat/agent context required: asset
    inventory (ip, ports, services, technologies, waf/cdn/os), credentials/secrets,
    vulnerabilities with confidence and evidence, entry points, every finding with
    provenance, and the relationship graph. This is the recon→exploit handoff.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/findings/handoff",
            params={"engagement_id": ctx.engagement_id},
            timeout=45,
        )
        return "\n\n".join(
            [_session_header(ctx), _block("Engagement handoff dossier", data)]
        )

    return _safe(_run)
