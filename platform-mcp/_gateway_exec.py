"""Gateway tools — exec group (registers on _core.mcp)."""

from __future__ import annotations

import json
from typing import Any

from _gateway_core import QUICK_TIMEOUT, _EngagementContext, _block, _get, _log, _post, _resolve_engagement, _safe, _session_header, mcp




def _format_exec_result(
    data: dict[str, Any], *, context: _EngagementContext | None = None
) -> str:
    # The backend already trims stdout to this tool's budget before this
    # response is sent (osprey.services.output_budget, applied in
    # tool_execution.execute_tool_request) — that is the ONE place raw-output
    # size policy lives, so this MCP-side formatter renders what it's given
    # verbatim instead of re-capping it a second time with its own numbers.
    stdout = data.get("stdout") or ""
    stdout_show = stdout
    stderr = data.get("stderr") or ""
    hybrid_meta = data.get("hybrid") or {}
    arts = hybrid_meta.get("artifacts") or (data.get("parsed") or {}).get("artifacts") or {}
    digest = str(hybrid_meta.get("digest") or "")
    stderr_show = stderr if len(stderr) <= 8000 else stderr[:8000] + "\n…[stderr truncated]…"

    parts = [
        "### OPERATOR MIRROR — EXECUTION",
        _session_header(context),
        f"success: {data.get('success')} | returncode: {data.get('returncode')} | "
        f"timed_out: {data.get('timed_out')} | cache_hit: {data.get('cache_hit')}"
        + (f" | cache_key: `{data.get('cache_key')}`" if data.get("cache_key") else "")
    ]
    if data.get("command"):
        parts.append(f"**COMMAND:** `{data['command']}`")
    if data.get("tool_name"):
        parts.append(f"**TOOL:** `{data['tool_name']}`")
    if digest:
        parts.append(f"**PARSED SUMMARY:** {digest}")
    if data.get("cache_hit"):
        age = data.get("cache_age_seconds")
        age_note = f" (cached {age:.0f}s ago)" if isinstance(age, (int, float)) and age else ""
        parts.append(
            f"**CACHE HIT**{age_note} — identical tool+params already ran this engagement. "
            "Reuse, change params, or force_refresh=true."
        )
    elif data.get("force_refresh_applied"):
        parts.append("**force_refresh=true applied** — cache was bypassed, this is a fresh run.")
    if stdout_show:
        parts.append(f"**STDOUT** ({len(stdout)} chars):\n```\n{stdout_show}\n```")
    elif not stdout:
        parts.append("**STDOUT:** (empty)")
    if stderr_show:
        parts.append(f"**STDERR** ({len(stderr)} chars):\n```\n{stderr_show}\n```")
    if data.get("error"):
        parts.append(f"**ERROR:** {data['error']}")
    titles = data.get("finding_titles") or []
    if titles:
        parts.append(_block(f"Top findings this run ({min(len(titles), 15)}/{len(titles)})", titles[:15]))
        if len(titles) > 15:
            parts.append(f"… +{len(titles) - 15} more — platform_findings / platform_report_outline")
    # next_hint now only carries factual markers of a deterministic action the
    # kernel already took (auto-fallback ran, wide scan auto-chunked) — not the
    # old advisory nudge text. Render it plainly when present.
    if data.get("next_hint"):
        parts.append(f"**Note:** {data['next_hint']}")
    if arts:
        parts.append(_block("Full output on disk (Kali)", arts))
    parts.append(
        "\n---\n"
        "You decide the next move. platform_context for phase status when useful."
    )
    return "\n".join(parts)

def _execute_catalog_tool(
    tool: str,
    params: dict[str, Any],
    *,
    additional_args: str = "",
    timeout_seconds: int = 300,
    force_refresh: bool = False,
    engagement_id: str = "",
    blast_radius: str = "",
    exploit_candidate_id: str = "",
) -> str:
    """Shared execute path for platform_exec and typed recon/network/exploit tools.

    blast_radius/exploit_candidate_id only matter for GATED tools — non-gated
    calls ignore them server-side. Left empty here (rather than defaulting to
    "poc") so ToolExecutionRequest's own default applies uniformly; passing
    "" through is equivalent to the caller never mentioning the field.
    """
    timeout_seconds = max(30, min(int(timeout_seconds), 900))
    ctx = _resolve_engagement(engagement_id)
    body: dict[str, Any] = {
        "tool_name": tool,
        "params": params,
        "additional_args": additional_args,
        "engagement_id": ctx.engagement_id,
        "run_id": ctx.run_id,
        "record_findings": True,
        "use_recovery": True,
        "use_cache": not bool(force_refresh),
        "force_refresh": bool(force_refresh),
        "timeout": timeout_seconds,
    }
    if blast_radius.strip():
        body["blast_radius"] = blast_radius.strip()
    if exploit_candidate_id.strip():
        body["exploit_candidate_id"] = exploit_candidate_id.strip()
    _log(
        f"exec {tool} target={ctx.target} engagement={ctx.engagement_id} "
        f"run={ctx.run_id} force_refresh={force_refresh}"
    )
    # Buffer must exceed the backend's WHOLE response time, not just the tool's
    # run: a slow tool that hits its own timeout (dnsenum routinely does) then
    # drains partial output + parses + ingests before responding. +60s covers
    # that post-timeout processing so the partial always makes it back.
    data = _post("/api/v1/mcp/execute", body, timeout=timeout_seconds + 60)
    return _format_exec_result(data, context=ctx)


@mcp.tool()
def platform_exploit_queue(
    limit: int = 50,
    engagement_id: str = "",
) -> str:
    """
    Read the evidence-ranked exploit candidate queue for the exploitation phase.

    The platform pre-computes this deterministically (network->exploit handoff,
    and after every exploit attempt) from vulnerability/credential findings — it
    is additive ranked context, not a filter on what tools you can call. Pick the
    highest-evidence, non-blocked candidate; `blocked_by_roe` entries tell you
    exactly which RulesOfEngagement flag is missing rather than leaving you to
    discover a 403 yourself.

    engagement_id: optional pin — see platform_exec.
    """
    limit = max(1, min(int(limit), 200))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/exploit-queue/",
            params={"engagement_id": ctx.engagement_id, "limit": limit},
            timeout=30,
        )
        candidates = data if isinstance(data, list) else []
        parts = [
            "### OPERATOR MIRROR — EXPLOIT QUEUE",
            _session_header(ctx),
        ]
        if not candidates:
            parts.append("(empty — no evidence-backed candidates yet, or none active)")
            return "\n\n".join(parts)

        lines = []
        for c in candidates:
            status = c.get("status", "")
            trigger = c.get("promotion_trigger", "")
            tool = c.get("suggested_tool", "")
            radius = c.get("blast_radius_required", "poc")
            attempts = c.get("attempts", 0)
            evidence = c.get("evidence_summary", "")
            lines.append(
                f"- [{status}|{trigger}|blast_radius={radius}|attempts={attempts}] "
                f"{evidence} -> {tool} (candidate_id={c.get('id', '')})"
            )
        parts.append(_block(f"Candidates ({len(candidates)})", "\n".join(lines)))
        parts.append(
            "Set exploit_candidate_id on the tool call for the candidate you act on — "
            "it correlates the attempt and links the result to the originating finding."
        )
        return "\n\n".join(parts)

    return _safe(_run)


def _coerce_params(params_json: Any) -> dict[str, Any] | str:
    """LLMs often pass an object; schema historically asked for a JSON string."""
    if params_json is None or params_json == "":
        return {}
    if isinstance(params_json, dict):
        return params_json
    if isinstance(params_json, str):
        text = params_json.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            return f"ERROR: params_json is not valid JSON: {exc}"
        if not isinstance(parsed, dict):
            return "ERROR: params_json must be a JSON object"
        return parsed
    return (
        "ERROR: params_json must be a JSON object or JSON string "
        f"(got {type(params_json).__name__})"
    )


@mcp.tool()
def platform_exec(
    tool: str,
    params_json: Any = "{}",
    additional_args: str = "",
    timeout_seconds: int = 90,
    force_refresh: bool = False,
    engagement_id: str = "",
) -> str:
    """
    Execute one registered pentest tool. Uses the active engagement automatically.
    Tool params may name subdomains/hosts — they do NOT change the engagement.

    params_json: object OR JSON string — both work.
      object: {"target": "host.example"}
      string: '{"target": "host.example"}'
    Aliases target|domain|host|url auto-remap. For recon/network prefer the typed
    tools (subfinder_scan, nmap_syn_scan, …) when available in the tool list.

    Pass any valid CLI flags via additional_args.
    force_refresh=true bypasses engagement exec cache.
    Keep timeout_seconds ≤ 90 for port scans unless you already chunked the work.

    engagement_id: optional — pin this call to the exact engagement returned by
    an earlier platform_set_target, instead of the shared session binding. Use
    this whenever another chat might be running a DIFFERENT engagement through
    this same MCP process at the same time (hosts commonly share one MCP
    subprocess across chats/tabs) — the shared session can be silently switched
    by that other chat's platform_set_target between your calls, which would
    otherwise redirect this execution to the wrong target.
    """
    params = _coerce_params(params_json)
    if isinstance(params, str):
        return params

    timeout_seconds = max(30, min(int(timeout_seconds), 900))

    def _run() -> str:
        return _execute_catalog_tool(
            tool,
            params,
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
            force_refresh=force_refresh,
            engagement_id=engagement_id,
        )

    return _safe(_run)


@mcp.tool()
def platform_job_start(
    kind: str = "tool",
    tool: str = "",
    params_json: Any = "{}",
    additional_args: str = "",
    command: str = "",
    code: str = "",
    language: str = "python3",
    packages: str = "",
    label: str = "",
    timeout_seconds: int = 300,
    force_refresh: bool = False,
    reason: str = "",
    engagement_id: str = "",
) -> str:
    """
    Start a PARALLEL background branch. Returns job_id immediately — do NOT wait.

    Use when a tool will take long (amass, nmap, rustscan, bulk httpx, scripts).
    Keep working on other hosts/tasks, then platform_job_poll(job_id) / platform_job_result.

    kind: tool | shell | script
    tool + params_json: for kind=tool (same as platform_exec)
    command: for kind=shell
    code: for kind=script
    Max running jobs per engagement comes from config/parallelism.yaml (default 4).
    Soft Parallel notes on long tools are optional — never auto-started.

    engagement_id: optional pin to a specific engagement — see platform_exec.
    """
    kind_n = (kind or "tool").strip().lower()
    if kind_n not in ("tool", "shell", "script"):
        return "ERROR: kind must be tool | shell | script"
    timeout_seconds = max(30, min(int(timeout_seconds), 3600))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        body: dict[str, Any] = {
            "kind": kind_n,
            "engagement_id": ctx.engagement_id,
            "run_id": ctx.run_id,
            "label": label,
            "timeout": timeout_seconds,
            "reason": reason,
            "record_findings": True,
            "force_refresh": bool(force_refresh),
            "additional_args": additional_args,
        }
        if kind_n == "tool":
            params = _coerce_params(params_json)
            if isinstance(params, str):
                return params
            if not (tool or "").strip():
                return "ERROR: tool= required for kind=tool"
            body["tool_name"] = tool.strip()
            body["params"] = params
        elif kind_n == "shell":
            if not (command or "").strip():
                return "ERROR: command= required for kind=shell"
            body["command"] = command
        else:
            if not (code or "").strip():
                return "ERROR: code= required for kind=script"
            body["code"] = code
            body["language"] = language
            body["packages"] = packages

        data = _post("/api/v1/jobs/start", body, timeout=30)
        parts = [
            "### OPERATOR MIRROR — JOB STARTED (parallel branch)",
            _session_header(ctx),
            f"**job_id:** `{data.get('job_id')}`",
            f"**status:** {data.get('status')} | **label:** {data.get('label')}",
            f"**kind:** {data.get('kind')} | **tool:** {data.get('tool_name')}",
            data.get("hint") or "",
            "",
            "Continue other work NOW. Later: platform_job_poll(job_id=…) "
            "then platform_job_result(job_id=…). Findings from the job are already ingested — "
            "read them when this branch matters to your next decision.",
        ]
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_job_poll(job_id: str = "", engagement_id: str = "", wait_seconds: float = 0) -> str:
    """
    Poll one job (job_id=…) or list all jobs for this engagement (empty job_id).

    Status: queued | running | completed | failed. RUNNING jobs carry a `progress`
    field (the current step, overwritten each update — capability and agent
    tool calls) AND a `results_log` (persistent history — every completed step
    stays, nothing overwritten). For kind=agent (a backend-driven phase agent,
    e.g. from `platform_pipeline`'s auto-executor or `platform_spawn_agent`),
    `results_log` shows each tool call's outcome and preview as it happens —
    genuinely watchable turn-by-turn, not fire-and-forget. Read it instead of
    assuming a running job is a black box.

    wait_seconds (0-90, default 0): long-poll — the call blocks server-side up to
    this long for the job to finish or its progress to change, instead of you
    firing off repeated polls in a tight loop. Pass 90 (the max) when you're
    going to wait on a job anyway — for a genuinely multi-minute job (a full
    investigation capability), that means ~2-3 poll calls instead of 8+; it still
    returns the instant progress changes, so a short job never actually waits
    the full 90s.

    When completed: findings already in memory — then platform_job_result for full stdout.

    engagement_id: optional pin — only matters for the "list all jobs" mode
    (empty job_id). For a specific job, its stored engagement is used and an
    explicit mismatching pin is rejected. See platform_exec.
    """
    def _run() -> str:
        jid = (job_id or "").strip()
        if not jid:
            ctx = _resolve_engagement(engagement_id)
            data = _get(
                "/api/v1/jobs",
                params={"engagement_id": ctx.engagement_id, "limit": "20"},
            )
            return "\n\n".join(
                [_session_header(ctx), _block("Jobs (this engagement)", data)]
            )
        wait = max(0.0, min(float(wait_seconds), 90.0))
        data = _get(f"/api/v1/jobs/{jid}", params={"wait_seconds": wait} if wait else None, timeout=wait + 30)
        job_eid = str(data.get("engagement_id") or "").strip()
        if engagement_id and job_eid and engagement_id.strip() != job_eid:
            return "ERROR: job does not belong to the pinned engagement_id"
        ctx = _resolve_engagement(engagement_id or job_eid)
        return "\n\n".join([_session_header(ctx), _block(f"Job {jid}", data)])

    return _safe(_run)


@mcp.tool()
def platform_job_result(job_id: str, engagement_id: str = "") -> str:
    """
    Fetch full result of a background job (stdout/stderr/findings) when completed/failed.

    After reading: give a short branch summary, then re-read investigation state.
    """
    jid = (job_id or "").strip()
    if not jid:
        return "ERROR: job_id required"

    def _run() -> str:
        data = _get(f"/api/v1/jobs/{jid}/result", timeout=60)
        job = data.get("job") or {}
        job_eid = str(job.get("engagement_id") or "").strip()
        if engagement_id and job_eid and engagement_id.strip() != job_eid:
            return "ERROR: job does not belong to the pinned engagement_id"
        ctx = _resolve_engagement(engagement_id or job_eid)
        result = data.get("result")
        parts = [
            "### OPERATOR MIRROR — JOB RESULT",
            _session_header(ctx),
            f"**job_id:** `{job.get('job_id')}` | **status:** {job.get('status')} | "
            f"**success:** {job.get('success')}",
            f"**label:** {job.get('label')} | **duration_s:** {job.get('duration_seconds')}",
            job.get("hint") or "",
        ]
        if job.get("error"):
            parts.append(f"**ERROR:** {job['error']}")
        titles = job.get("finding_titles") or []
        if titles:
            parts.append(_block(f"Findings from this branch ({len(titles)})", titles[:80]))
        if result:
            if job.get("kind") == "investigation_step":
                parts.append(_block("Investigation capability result", result))
            elif isinstance(result, dict):
                parts.append(_format_exec_result(result, context=ctx))
            else:
                parts.append(_block("Result", result))
        else:
            parts.append("(no result payload yet — still running? call platform_job_poll)")
        parts.append(
            "\nBranch done — short chat note, then re-read investigation state."
        )
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_jobs(engagement_id: str = "", status: str = "", limit: int = 30) -> str:
    """
    List this engagement's background jobs and durable scan-run history — the
    audit trail for recovering work after a disconnect or timeout.

    Every tool run is recorded here, including a synchronous call that timed out
    from your side (its process still finished server-side and the run is durably
    stored) and jobs started before a crash — so nothing is silently lost. Find
    the job_id, then platform_job_result(job_id) for its output, or
    platform_artifact for full stdout. Scan-runs survive a backend restart; the
    in-memory job list does not, which is exactly why both are shown.

    status= filter the job list (queued|running|completed|failed).
    engagement_id: optional pin — see platform_exec.
    """
    lim = max(1, min(int(limit), 100))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        job_params = {"engagement_id": ctx.engagement_id, "limit": str(lim)}
        if status.strip():
            job_params["status"] = status.strip()
        jobs = _get("/api/v1/jobs", params=job_params, timeout=20)
        runs = _get(
            "/api/v1/jobs/scan-runs",
            params={"engagement_id": ctx.engagement_id, "limit": str(min(lim * 2, 200))},
            timeout=20,
        )
        parts = ["### OPERATOR MIRROR — JOBS & RUNS", _session_header(ctx)]

        if isinstance(jobs, list) and jobs:
            lines = []
            for j in jobs:
                bit = f"[{j.get('status')}] `{j.get('job_id')}` {j.get('kind')}"
                if j.get("tool_name"):
                    bit += f":{j.get('tool_name')}"
                if j.get("label"):
                    bit += f" · {j.get('label')}"
                if j.get("duration_seconds") is not None:
                    bit += f" · {j.get('duration_seconds')}s"
                fc = len(j.get("finding_titles") or [])
                if fc:
                    bit += f" · {fc} finding(s)"
                if j.get("error"):
                    bit += f" · ERROR: {str(j.get('error'))[:80]}"
                lines.append(bit)
            parts.append(_block(f"Jobs ({len(jobs)}) — platform_job_result(job_id) for output", lines))
        else:
            parts.append("Jobs: none active/recent in the in-memory job store.")

        if isinstance(runs, list) and runs:
            lines = []
            for r in runs[:lim]:
                bit = f"[{r.get('status')}] `{r.get('job_id')}` {r.get('kind') or '?'}"
                if r.get("target"):
                    bit += f" · {r.get('target')}"
                elif r.get("command_preview"):
                    bit += f" · {str(r.get('command_preview'))[:60]}"
                if r.get("error"):
                    bit += f" · ERROR: {str(r.get('error'))[:80]}"
                lines.append(bit)
            parts.append(_block(f"Durable scan-runs ({len(runs)}) — survive restart", lines))
        else:
            parts.append("Scan-runs: none recorded yet.")
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_shell(
    command: str,
    reason: str = "",
    timeout_seconds: int = 180,
    engagement_id: str = "",
) -> str:
    """
    Unrestricted bash inside the Kali container — loops, ;, &&, $(), redirects
    all work (e.g. 'for h in www api dev; do dig +short $h.x.com; done').
    Example: 'nmap -sV -p 80,443 1.2.3.4'. Prefer platform_exec for catalog tools;
    use platform_script for long multi-line scripts.

    engagement_id: optional pin to a specific engagement — see platform_exec.
    """
    timeout_seconds = max(30, min(int(timeout_seconds), 900))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        body = {
            "command": command,
            "engagement_id": ctx.engagement_id,
            "run_id": ctx.run_id,
            "reason": reason,
            "timeout": timeout_seconds,
            "record_findings": True,
        }
        _log(f"shell engagement={ctx.engagement_id} cmd={command[:200]}")
        data = _post("/api/v1/mcp/shell", body, timeout=timeout_seconds + 15)
        return _format_exec_result(data, context=ctx)

    return _safe(_run)


@mcp.tool()
def platform_script(
    code: str,
    language: str = "python3",
    reason: str = "",
    filename: str = "",
    packages: str = "",
    timeout_seconds: int = 300,
    engagement_id: str = "",
) -> str:
    """
    Custom app probing lane: write a full script and run it in Kali.
    Stdout is parsed into findings (URL/status, PATH lines, FINDING markers) + ingest rules.
    Print durable facts as:
      FINDING|observed|high|url|Title|raw evidence snippet
      PATH /backend/api/foo 401
      ENDPOINT https://host/rest/info 200
      REL|host:a|same_app_as|host:b|shared JS hash
      REL|inferred|host:erp|likely_origin_of|ip:1.2.3.4|CDN bypass candidate
      HYPOTHESIS|erp shares auth with ess|same Set-Cookie domain

    language = python3 | bash | sh.
    packages = comma-separated pip names installed with --user BEFORE python runs
    (e.g. packages='requests,beautifulsoup4'). Prefer stdlib when possible.
    (apt packages are NOT installable here — use platform_install(manager='apt') first.)

    Full stdout/stderr saved under /tmp/pentest/<engagement_id>/ — not catalog-cached;
    re-run freely. Prefer platform_exec for registered tools; platform_shell for one-liners.

    engagement_id: optional pin to a specific engagement — see platform_exec.
    """
    if not (code or "").strip():
        return "ERROR: code is empty"
    language = (language or "python3").strip().lower()
    timeout_seconds = max(30, min(int(timeout_seconds), 900))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        body = {
            "code": code,
            "language": language,
            "engagement_id": ctx.engagement_id,
            "run_id": ctx.run_id,
            "reason": reason,
            "filename": filename,
            "packages": packages,
            "timeout": timeout_seconds,
            "record_findings": True,
        }
        _log(
            f"script lang={language} engagement={ctx.engagement_id} "
            f"bytes={len(code.encode('utf-8', errors='replace'))} pkgs={packages!r}"
        )
        data = _post("/api/v1/mcp/script", body, timeout=timeout_seconds + 120)
        return _format_exec_result(data, context=ctx)

    return _safe(_run)


@mcp.tool()
def platform_install(
    packages: str,
    manager: str = "pip",
    reason: str = "",
    timeout_seconds: int = 300,
    engagement_id: str = "",
) -> str:
    """
    Install libraries in Kali for upcoming scripts.

    manager='pip' → python3 -m pip install --user (PyPI names only).
    manager='apt' → apt-get install from a small allowlist.

    Example: packages='requests,httpx,beautifulsoup4' manager='pip'
    Then call platform_script that imports them.
    """
    if not (packages or "").strip():
        return "ERROR: packages is empty"
    manager = (manager or "pip").strip().lower()
    timeout_seconds = max(60, min(int(timeout_seconds), 900))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        body = {
            "manager": manager,
            "packages": packages,
            "engagement_id": ctx.engagement_id,
            "run_id": ctx.run_id,
            "reason": reason,
            "timeout": timeout_seconds,
        }
        _log(f"install mgr={manager} pkgs={packages[:200]}")
        data = _post("/api/v1/mcp/install", body, timeout=timeout_seconds + 30)
        return _format_exec_result(data, context=ctx)

    return _safe(_run)


@mcp.tool()
def platform_fanout(
    action: str = "enumerate_sisters",
    tool_name: str = "subfinder_scan",
    dry_run: bool = True,
    confirm: bool = False,
    max_domains: int = 10,
    timeout_per_tool: int = 180,
    engagement_id: str = "",
) -> str:
    """
    OPTIONAL explicit batch helper for sister-domain enum (dry_run by default).
    Uses the active target's engagement only. tool_name= any registered catalog
    tool — an enum tool (subfinder_scan/amass_scan/fierce_scan/dnsenum_scan) is
    what this helper is for, not a hard requirement.
    """
    action = (action or "").strip().lower()
    if action not in ("enumerate_sisters", "enumerate_pending_sisters", "sisters"):
        return (
            "ERROR: unsupported action. Use action='enumerate_sisters'. "
            "This helper never silent-auto-chains."
        )

    max_domains = max(1, min(int(max_domains), 50))
    timeout_per_tool = max(30, min(int(timeout_per_tool), 900))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        body = {
            "run_id": ctx.run_id,
            "tool_name": (tool_name or "subfinder_scan").strip(),
            "max_domains": max_domains,
            "timeout_per_tool": timeout_per_tool,
            "dry_run": bool(dry_run),
            "confirm": bool(confirm),
            "skip_already_marked": True,
        }
        timeout = QUICK_TIMEOUT if dry_run or not confirm else float(timeout_per_tool * max_domains + 60)
        data = _post(
            f"/api/v1/engagements/{ctx.engagement_id}/actions/enumerate-pending-sisters",
            body,
            timeout=timeout,
        )
        return "\n\n".join([_session_header(ctx), _block("Fan-out (explicit)", data)])

    return _safe(_run)



# platform_thinking (used to be here) is deleted — it called
# GET /api/v1/hybrid/thinking-hypotheses, a route that was never registered
# anywhere in the backend (verified: no @router.get for that path in any
# endpoints module). A genuinely pre-existing, silently broken tool — every
# call would 404. Its documented purpose ("what next / I'm stuck", evidence
# → next-probe cards) is exactly what plans/harness/06-prioritization-
# engine.md's platform_priority does for real: a working, tested,
# multi-factor score over the world model. Use that instead.


@mcp.tool()
def platform_fanout_assets(
    assets_json: Any = "[]",
    tool: str = "httpx_probe",
    dry_run: bool = True,
    confirm: bool = False,
    max_assets: int = 25,
    timeout_per_tool: int = 120,
    additional_args: str = "",
    force_refresh: bool = False,
    engagement_id: str = "",
) -> str:
    """
    Run one catalog tool across an EXPLICIT asset list (you choose — from graph_query/findings).

    assets_json: list or JSON string, e.g. ["vpn.example.com","mail.example.com"]
    Default dry_run=true. Execute only with dry_run=false AND confirm=true.
    """
    assets = assets_json
    if isinstance(assets_json, str):
        try:
            assets = json.loads(assets_json) if assets_json.strip() else []
        except json.JSONDecodeError:
            # newline / comma separated
            assets = [x.strip() for x in assets_json.replace(",", "\n").splitlines() if x.strip()]
    if not isinstance(assets, list):
        return "ERROR: assets_json must be a list of strings"
    # No ceiling re-imposed here — fanout_assets() itself enforces the one
    # sanity ceiling (and logs if a fat-fingered value exceeds it), so this
    # layer doesn't duplicate/drift from that number.
    max_assets = max(1, int(max_assets))
    timeout_per_tool = max(30, min(int(timeout_per_tool), 600))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        body = {
            "assets": [str(a).strip() for a in assets if str(a).strip()],
            "tool_name": tool,
            "dry_run": bool(dry_run),
            "confirm": bool(confirm),
            "max_assets": max_assets,
            "timeout_per_tool": timeout_per_tool,
            "additional_args": additional_args,
            "run_id": ctx.run_id,
            "force_refresh": bool(force_refresh),
        }
        timeout = (
            QUICK_TIMEOUT
            if dry_run or not confirm
            else float(timeout_per_tool * min(len(body["assets"]), max_assets) + 60)
        )
        data = _post(
            f"/api/v1/engagements/{ctx.engagement_id}/actions/fanout-assets",
            body,
            timeout=timeout,
        )
        return "\n\n".join([_session_header(ctx), _block("Fan-out assets", data)])

    return _safe(_run)
