"""
Platform MCP gateway for OpenCode / Claude Desktop.

Dynamic multi-target: call platform_set_target(domain) when the user names a
target. Each distinct root domain gets its own engagement_id and isolated
Postgres storage. Switching targets in the same chat rebinds automatically.
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from typed_recon_network import register_typed_recon_network_tools
from typed_tech_identification import register_typed_tech_identification_tools
from typed_osint import register_typed_osint_tools

API_BASE = os.environ.get("PENTEST_API_BASE", "http://localhost:9000").rstrip("/")
QUICK_TIMEOUT = float(os.environ.get("PENTEST_QUICK_TIMEOUT", "60"))
# Long exec/script posts — keep ≥ OpenCode mcp.timeout (ms) / 1000
HTTP_TIMEOUT = float(os.environ.get("PENTEST_HTTP_TIMEOUT", "900"))
SESSION_RUN_ID = os.environ.get("PENTEST_RUN_ID", "") or uuid.uuid4().hex[:12]

# Active session — one engagement per root target
_SESSION_TARGET = ""
_SESSION_ENGAGEMENT_ID = ""
_SESSION_SWITCH_NOTICE = ""

# OPEN GAPS dedup — collapses the memory-gaps block to one line across
# consecutive tool calls while its content signature is unchanged, so a
# growing engagement doesn't re-teach the operator LLM the same paragraph on
# every single tool response. Reset whenever the bound engagement changes.
_LAST_OPEN_LOOPS_SIG = ""
_OPEN_LOOPS_REPEAT_COUNT = 0

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

mcp = FastMCP("pentest-platform")


def _log(msg: str) -> None:
    print(f"[pentest-platform-mcp] {msg}", file=sys.stderr, flush=True)


def _normalize_target(raw: str) -> str:
    value = (raw or "").strip().lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    return value


def _valid_domain(value: str) -> bool:
    return bool(value and _DOMAIN_RE.match(value))


def _get(path: str, *, params: dict[str, Any] | None = None, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
    with httpx.Client(base_url=API_BASE, timeout=timeout) as client:
        resp = client.get(path, params=params or {})
        resp.raise_for_status()
        return resp.json()


def _post(path: str, body: dict[str, Any], *, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
    # Cap to HTTP_TIMEOUT so we never wait forever if caller passes a huge value
    timeout = min(float(timeout), HTTP_TIMEOUT)
    with httpx.Client(base_url=API_BASE, timeout=timeout) as client:
        resp = client.post(path, json=body)
        resp.raise_for_status()
        return resp.json()


def _delete(path: str, *, params: dict[str, Any] | None = None, timeout: float = QUICK_TIMEOUT) -> dict[str, Any]:
    timeout = min(float(timeout), HTTP_TIMEOUT)
    with httpx.Client(base_url=API_BASE, timeout=timeout) as client:
        resp = client.delete(path, params=params or {})
        resp.raise_for_status()
        if resp.status_code == 204 or not resp.content:
            return {"status": "deleted"}
        return resp.json()



def _new_run_id() -> str:
    global SESSION_RUN_ID
    SESSION_RUN_ID = uuid.uuid4().hex[:12]
    return SESSION_RUN_ID


def _ensure_run_registered(engagement_id: str) -> None:
    try:
        _post(
            f"/api/v1/engagements/{engagement_id}/runs/ensure",
            {"run_id": SESSION_RUN_ID},
            timeout=10,
        )
    except Exception as exc:
        _log(f"run bind warning: {exc}")


def _bind_target(target: str, *, force_new: bool = False) -> dict[str, Any]:
    """Bind session to a root FQDN. Incomplete names must be clarified first."""
    global _SESSION_TARGET, _SESSION_ENGAGEMENT_ID, _SESSION_SWITCH_NOTICE
    global _LAST_OPEN_LOOPS_SIG, _OPEN_LOOPS_REPEAT_COUNT

    normalized = _normalize_target(target)
    if not _valid_domain(normalized):
        raise ValueError(
            f"Incomplete or invalid target {target!r}. "
            "Ask the user for the exact FQDN after reviewing analyze-target candidates."
        )

    previous_target = _SESSION_TARGET
    previous_engagement = _SESSION_ENGAGEMENT_ID
    switched = bool(previous_target and previous_target != normalized)
    _LAST_OPEN_LOOPS_SIG = ""
    _OPEN_LOOPS_REPEAT_COUNT = 0

    if switched:
        _new_run_id()
        _SESSION_SWITCH_NOTICE = (
            f"TARGET SWITCH: {previous_target} (engagement {previous_engagement}) "
            f"→ {normalized}. New isolated storage — do not mix findings across targets."
        )
        _log(_SESSION_SWITCH_NOTICE)
    elif not _SESSION_TARGET:
        _SESSION_SWITCH_NOTICE = ""
    else:
        _SESSION_SWITCH_NOTICE = ""

    data = _post(
        "/api/v1/engagements/resolve",
        {
            "target": normalized,
            "name": f"engagement-{normalized}",
            "force_new": force_new,
        },
        timeout=15,
    )

    _SESSION_TARGET = data.get("target", normalized)
    _SESSION_ENGAGEMENT_ID = data["id"]
    _ensure_run_registered(_SESSION_ENGAGEMENT_ID)

    created = bool(data.get("created"))
    if created and not switched:
        _log(f"new engagement {_SESSION_ENGAGEMENT_ID} for target {_SESSION_TARGET}")
    elif not switched and not created:
        _log(f"resumed engagement {_SESSION_ENGAGEMENT_ID} for target {_SESSION_TARGET}")

    return {
        "target": _SESSION_TARGET,
        "engagement_id": _SESSION_ENGAGEMENT_ID,
        "run_id": SESSION_RUN_ID,
        "switched": switched,
        "created": created,
        "reused": bool(data.get("reused")),
        "previous_target": previous_target,
        "previous_engagement_id": previous_engagement,
    }


def _require_bound_target() -> str:
    if not _SESSION_TARGET or not _SESSION_ENGAGEMENT_ID:
        raise RuntimeError(
            "No active target. Call platform_set_target('example.com') first "
            "(short names like 'zong' will ask the user to clarify)."
        )
    return _SESSION_TARGET


def _resolve_engagement(engagement_id_override: str = "") -> tuple[str, str]:
    """Resolve (engagement_id, target_label) for one call, preferring an explicit pin.

    This MCP process holds ONE ambient session (_SESSION_TARGET /
    _SESSION_ENGAGEMENT_ID). If the host reuses this same server process for
    multiple concurrent chats (common — hosts typically spawn one MCP
    subprocess per app/workspace, not one per chat), a platform_set_target
    call from a DIFFERENT chat overwrites that ambient state out from under
    this one. Passing engagement_id_override (the id platform_set_target
    returned earlier in THIS chat) pins the call to that exact engagement
    regardless of what the shared ambient session currently holds. Empty
    override = existing single-chat behavior (unchanged).
    """
    eid = (engagement_id_override or "").strip()
    if eid:
        label = _SESSION_TARGET if eid == _SESSION_ENGAGEMENT_ID else f"(pinned engagement_id={eid})"
        return eid, label
    _require_bound_target()
    return _SESSION_ENGAGEMENT_ID, _SESSION_TARGET


def _session_header(engagement_id: str = "", target: str = "") -> str:
    pinned = bool(engagement_id and engagement_id != _SESSION_ENGAGEMENT_ID)
    if not engagement_id:
        _require_bound_target()
    eid = engagement_id or _SESSION_ENGAGEMENT_ID
    tgt = target or _SESSION_TARGET
    lines = [
        f"target: {tgt}",
        f"engagement_id: {eid}",
        f"run_id: {SESSION_RUN_ID}",
    ]
    if pinned:
        lines.append(
            "notice: PINNED via explicit engagement_id= — this call bypassed the "
            f"shared ambient session (ambient session is currently bound to "
            f"target={_SESSION_TARGET!r} engagement_id={_SESSION_ENGAGEMENT_ID!r})."
        )
    elif _SESSION_SWITCH_NOTICE:
        lines.append(f"notice: {_SESSION_SWITCH_NOTICE}")
    return "\n".join(lines)


def _session_params() -> dict[str, str]:
    """Params for session bind — includes run_id for writes/audit."""
    _require_bound_target()
    return {
        "run_id": SESSION_RUN_ID,
        "engagement_id": _SESSION_ENGAGEMENT_ID,
        "seed_target": _SESSION_TARGET,
    }


def _memory_params() -> dict[str, str]:
    """Engagement-wide memory reads — omit run_id so graph/findings are not empty."""
    _require_bound_target()
    return {
        "engagement_id": _SESSION_ENGAGEMENT_ID,
        "seed_target": _SESSION_TARGET,
    }


def _safe(callable_fn) -> str:
    try:
        return callable_fn()
    except httpx.TimeoutException:
        return (
            "### OPERATOR MIRROR — TIMEOUT\n"
            f"ERROR: Platform request timed out on {API_BASE}.\n"
            "The backend may STILL be running — do NOT assume failure.\n"
            "Next: retry with a SMALLER scope "
            "(one IP, top ports only, timeout_seconds≤90). Never -p0-65535 in one MCP call. "
            "Do not dump platform_findings yet — keep expanding."
        )
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code if exc.response else "?"
        detail = exc.response.text[:1500] if exc.response is not None else str(exc)
        return f"ERROR: HTTP {code} from platform\n{detail}"
    except Exception as exc:
        return f"ERROR: {type(exc).__name__}: {exc}"


def _block(title: str, payload: Any) -> str:
    body = payload if isinstance(payload, str) else json.dumps(payload, indent=2, default=str)
    return f"## {title}\n\n{body}"


def _format_clarification(analysis: dict[str, Any]) -> str:
    parts = [
        "## Target needs clarification — DO NOT START SCANNING YET",
        "",
        analysis.get("message") or "Ambiguous target.",
        "",
        _block("Analysis", analysis),
        "## Ask the user",
    ]
    for q in analysis.get("questions_for_user") or []:
        parts.append(f"- {q}")
    parts.append("")
    parts.append(
        "After the user picks an exact domain, call platform_set_target('exact.domain.tld'). "
        "Never guess and bind on your own."
    )
    if analysis.get("agent_instruction"):
        parts.append("")
        parts.append(f"Instruction: {analysis['agent_instruction']}")
    return "\n".join(parts)


def _analyze_or_bind(raw: str, *, force_new: bool = False) -> str:
    """Analyze first; bind only when status=ready."""
    analysis = _get(
        "/api/v1/engagements/analyze-target",
        params={"target": raw, "probe_dns": "true"},
        timeout=25,
    )
    if analysis.get("needs_clarification") or analysis.get("status") != "ready":
        return _format_clarification(analysis)
    domain = analysis.get("ready_domain") or raw
    info = _bind_target(domain, force_new=force_new)
    parts = [_session_header(), _block("Target Bind", info)]
    if info.get("switched"):
        parts.append(
            "## Important\n\n"
            "Target changed — prior findings in this chat were for a different "
            "engagement. Use platform_context for the NEW target only."
        )
    return "\n\n".join(parts)


@mcp.tool()
def platform_set_target(target: str, force_new: bool = False, pick: str = "") -> str:
    """
    Set or switch the active pentest target.

    Full domain (example.com) → binds engagement.
    Short name (e.g. 'zong') → returns DNS-ranked candidates; ASK the user which
    exact domain they meant, then call again with that FQDN (or pick='chosen.tld').

    Never invent a domain. Never start tools until bound to a confirmed FQDN.
    """
    def _run() -> str:
        chosen = (pick or "").strip() or (target or "").strip()
        return _analyze_or_bind(chosen, force_new=force_new)

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
        global _SESSION_TARGET, _SESSION_ENGAGEMENT_ID, _SESSION_SWITCH_NOTICE

        t_raw = (target or "").strip()
        e_id = (engagement_id or "").strip()

        if not t_raw and not e_id:
            if _SESSION_TARGET:
                t_raw = _SESSION_TARGET
            else:
                return "ERROR: Provide target='domain.tld' or engagement_id='...' to delete."

        if e_id:
            res = _delete(f"/api/v1/engagements/{e_id}", timeout=15)
            if e_id == _SESSION_ENGAGEMENT_ID:
                _SESSION_TARGET = ""
                _SESSION_ENGAGEMENT_ID = ""
                _SESSION_SWITCH_NOTICE = ""
            return f"Deleted engagement '{e_id}'.\n\n{_block('Deletion Result', res)}"

        norm = _normalize_target(t_raw)
        res = _delete("/api/v1/engagements/by-target", params={"target": norm}, timeout=15)

        if norm == _SESSION_TARGET:
            _SESSION_TARGET = ""
            _SESSION_ENGAGEMENT_ID = ""
            _SESSION_SWITCH_NOTICE = ""

        return f"Successfully deleted engagements and stored memory for target domain '{norm}'.\n\n{_block('Deletion Result', res)}"

    return _safe(_run)



@mcp.tool()
def platform_health(target: str = "") -> str:
    """
    Check backend health. Pass target= when the user names scope (may be short name).
    Short names trigger clarification — same as platform_set_target.
    """
    def _run() -> str:
        health = _get("/health", timeout=10)
        if target.strip():
            clarified = _analyze_or_bind(target)
            if clarified.startswith("## Target needs clarification"):
                return clarified
            return f"{_session_header()}\n\n{_block('Platform Health', health)}\n\n{clarified}"
        if not _SESSION_ENGAGEMENT_ID:
            return (
                "ERROR: No active target. Pass target='example.com' or a short name "
                "like target='zong' (will ask you to clarify), or call platform_set_target."
            )
        return f"{_session_header()}\n\n{_block('Platform Health', health)}"

    result = _safe(_run)
    if result.startswith("ERROR"):
        return f"{result}\nStart the stack with: docker compose up -d"
    return result


def _fetch_context(engagement_id: str = "", target: str = "") -> str:
    eid = engagement_id or _SESSION_ENGAGEMENT_ID
    tgt = target or _SESSION_TARGET
    data = _get(
        "/api/v1/hybrid/context/auto",
        params={"engagement_id": eid, "seed_target": tgt},
    )
    readiness = data.get("finalize_readiness") or {}
    lb = readiness.get("look_back") or {}
    finalize_banner = (
        f"look_back: {lb.get('orphan_count', 0)} unlinked, "
        f"{lb.get('unexplored_count', 0)} unexplored, "
        f"{lb.get('untested_hypothesis_count', 0)} untested hypothesis(es) | "
        f"{(readiness.get('guidance') or '')[:400]}"
    )

    # Jobs: compact one-liner from backend (config-driven max slots)
    jobs_line = (data.get("jobs_line") or "").strip()
    if not jobs_line:
        jobs = data.get("background_jobs") or []
        running = sum(1 for j in jobs if str(j.get("status") or "") in ("queued", "running"))
        jobs_line = f"jobs: {running}/? running"
        if jobs:
            labels = [
                f"{j.get('label') or j.get('tool_name') or j.get('kind')}"
                for j in jobs[:6]
                if str(j.get("status") or "") in ("queued", "running")
            ]
            if labels:
                jobs_line = f"jobs: {running}/? running [{', '.join(str(x) for x in labels)}]"

    # Coverage: gap_id + reason only (no suggested_tool orders)
    gap_lines: list[str] = []
    for g in (data.get("coverage_gaps") or [])[:8]:
        if isinstance(g, dict):
            gid = g.get("gap_id") or ""
            reason = (g.get("reason") or g.get("evidence") or "")[:120]
            asset = g.get("asset") or ""
            bit = f"[{gid}] {reason}"
            if asset:
                bit += f" ({asset})"
            gap_lines.append(bit)
        else:
            gap_lines.append(str(g)[:140])

    # Crown jewels: top 5 compact
    jewels = data.get("crown_jewels") or []
    jewel_lines = []
    for j in jewels[:5]:
        if isinstance(j, dict):
            jewel_lines.append(
                f"{j.get('asset')} score={j.get('score')} "
                f"({', '.join(str(r) for r in (j.get('reasons') or [])[:3])})"
            )

    open_loops = data.get("open_loops") or {}
    gaps_text = open_loops.get("text") if isinstance(open_loops, dict) else open_loops

    idx = data.get("stdout_index") or {}
    idx_text = (idx.get("text") if isinstance(idx, dict) else "") or ""

    # Thinking cards / universal loop — the LLM's "what's likely still unexplored" signal.
    # Computed by the backend on every context call; was previously dropped here entirely.
    hyp_lines = [str(h)[:180] for h in (data.get("product_hypotheses") or [])[:8] if str(h).strip()]

    # Signal-based dispatch (e.g. "port 445 open -> smb enum") — likewise computed, was dropped.
    dispatch_lines: list[str] = []
    for d_ in (data.get("dispatch_rules") or [])[:6]:
        if isinstance(d_, dict):
            sig = d_.get("signal") or ""
            tool = d_.get("default_tool") or ""
            reason = (d_.get("reason") or "")[:100]
            bit = f"[{sig}] → {tool}"
            if reason:
                bit += f" — {reason}"
            dispatch_lines.append(bit)

    parts = [
        _session_header(eid, tgt),
        f"**Jobs:** {jobs_line}",
        "### OPEN GAPS (memory — you choose how to close)",
        str(gaps_text or "(none)"),
        "**Thinking (what's likely still unexplored — instinct, not orders):**\n"
        + ("\n".join(hyp_lines) if hyp_lines else "(none yet)"),
        "**Dispatch signals (from detected tech/ports):**\n"
        + ("\n".join(dispatch_lines) if dispatch_lines else "(none yet)"),
        _block("Context delta", data.get("context_delta") or {}),
        "**Crown jewels (top):**\n" + ("\n".join(jewel_lines) if jewel_lines else "(none yet)"),
        "**Recent artifacts:**\n" + (idx_text if idx_text else "(none — run a tool first)"),
        "**Coverage gaps:**\n" + ("\n".join(gap_lines) if gap_lines else "(none)"),
        _block("Inferred focus", data.get("inferred_focus", {})),
        _block("Finalize", finalize_banner),
    ]
    # Network surface: short only
    ns = data.get("network_surface_text") or ""
    if ns:
        parts.append(_block("Network surface", ns[:1500] + ("…" if len(ns) > 1500 else "")))
    # Tree: condensed, capped
    tree = data.get("attack_surface_tree_text") or ""
    if tree:
        parts.append(
            _block("Attack surface (condensed)", tree[:2000] + ("…" if len(tree) > 2000 else ""))
        )
    # Findings: short summary only — full dump on demand via platform_findings
    fs = data.get("findings_summary") or ""
    if fs:
        parts.append(_block("Findings (brief)", fs[:1200] + ("…" if len(fs) > 1200 else "")))
    # Role guidance: short operator-mindset reminder — full skill text on demand via platform_skills
    rg = (data.get("role_guidance") or "").strip()
    if rg:
        parts.append(_block("Role guidance", rg[:700] + ("…" if len(rg) > 700 else "")))
    # Skills index: names + paths only — call platform_skills(path=...) to read one in full
    si = (data.get("skills_index") or "").strip()
    if si:
        parts.append(_block("Skills available", si[:900] + ("…" if len(si) > 900 else "")))

    parts.append(
        "---\n"
        "You decide the next probe. Gaps are data, not orders. "
        "Use platform_tools / platform_skills / platform_findings / platform_artifact "
        "only when you need detail. "
        "platform_graph_link_many (bulk — one call for a whole tool run's relationships) "
        "/ platform_graph_link / platform_tag_asset / platform_script when inventing."
    )
    return "\n\n---\n\n".join(parts)


@mcp.tool()
def platform_context(target: str = "", engagement_id: str = "") -> str:
    """
    Compact briefing from evidence: gaps, crown jewels, jobs, delta, look-back.

    Call this not just to plan the next probe, but whenever you're stuck — a
    tool keeps failing, you're unsure what to try next, or you're about to ask
    the user a question. Memory may already hold the answer (an unexplored
    asset, an untested hypothesis) you reasoned about earlier and forgot to
    chase. If it doesn't, that's useful too — it means you're genuinely at a
    new edge, not repeating past work blind.

    No phase argument. Pass target= only to analyze/switch.
    Pull details on demand: platform_tools, platform_skills, platform_findings.

    engagement_id: optional pin to a specific engagement (bypasses the shared
    ambient session without switching it) — see platform_exec. Ignored if
    target= is set, since target= always switches/binds first.
    """
    def _run() -> str:
        if target.strip():
            clarified = _analyze_or_bind(target)
            if clarified.startswith("## Target needs clarification"):
                return clarified
            return _fetch_context()
        eid, tgt = _resolve_engagement(engagement_id)
        return _fetch_context(engagement_id=eid, target=tgt)

    return _safe(_run)


@mcp.tool()
def platform_artifact(path: str = "", offset: int = 0, limit: int = 80000) -> str:
    """
    Read a slice of a Kali artifact (full tool stdout that didn't fit the card).
    Empty path → list recent index + workdir listing.
    path = basename or /tmp/pentest/<engagement>/….stdout.txt
    """
    def _run() -> str:
        _require_bound_target()
        params = dict(_memory_params())
        if not (path or "").strip():
            idx = _get("/api/v1/hybrid/stdout-index", params={**params, "limit": 8})
            listing = _get("/api/v1/hybrid/artifacts", params=params)
            return (
                f"{_session_header()}\n\n"
                f"**Index:**\n{idx.get('text') or '(empty)'}\n\n"
                f"**Workdir:** `{listing.get('workdir')}`\n"
                f"```\n{(listing.get('listing') or '')[:4000]}\n```\n"
                "Pass path= to read a file slice."
            )
        data = _get(
            "/api/v1/hybrid/artifacts/read",
            params={
                **params,
                "path": path,
                "offset": max(0, int(offset)),
                "limit": max(1, min(int(limit), 500_000)),
            },
        )
        if not data.get("ok"):
            return f"ERROR: {data.get('error') or data}"
        body = data.get("content") or ""
        return (
            f"{_session_header()}\n"
            f"path={data.get('path')} bytes={data.get('returned_bytes')}/"
            f"{data.get('total_bytes')} offset={data.get('offset')}\n"
            f"truncated={data.get('truncated')} next_offset={data.get('next_offset')}\n\n"
            f"```\n{body}\n```"
        )

    return _safe(_run)


def _format_exec_result(data: dict[str, Any], *, engagement_id: str = "", target: str = "") -> str:
    stdout = data.get("stdout") or ""
    stderr = data.get("stderr") or ""
    # Trim: status + top findings + gaps; full stdout via artifact path
    hybrid_meta = data.get("hybrid") or {}
    arts = hybrid_meta.get("artifacts") or (data.get("parsed") or {}).get("artifacts") or {}
    stdout_path = ""
    if isinstance(arts, dict):
        stdout_path = str(arts.get("stdout_path") or "")

    # A registered per-tool digest (registry.digest_tool_output, computed
    # server-side) already carries the compact "what happened" signal —
    # structured findings capture the rest. When one exists, the raw stdout
    # preview only needs to cover what the digest and structured findings
    # might have missed, not mirror the whole (sometimes 10k+ line) dump —
    # that's what repeatedly filled OpenCode's context on long sessions.
    # Without a digest (tool has no registered parser), keep the generous cap
    # since raw stdout is the only signal available for that tool.
    digest = str(hybrid_meta.get("digest") or "")
    stdout_cap = 2500 if digest else 12000
    head_cap = 1800 if digest else 6000
    tail_cap = 700 if digest else 3000

    if len(stdout) <= stdout_cap:
        stdout_show = stdout
    else:
        stdout_show = (
            stdout[:head_cap]
            + "\n\n…[trimmed — full stdout on Kali"
            + (f" `{stdout_path}`" if stdout_path else "")
            + " — platform_artifact]…\n\n"
            + stdout[-tail_cap:]
        )
    stderr_show = stderr if len(stderr) <= 8000 else stderr[:8000] + "\n…[stderr truncated]…"

    parts = [
        "### OPERATOR MIRROR — EXECUTION",
        _session_header(engagement_id, target),
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
    # Soft notes — failure gaps + optional parallel branch hint (never orders)
    parallel_note = hybrid_meta.get("parallel_note") if isinstance(hybrid_meta, dict) else None
    if data.get("timed_out") or not data.get("success") or (
        data.get("next_hint") and "EMPTY" in str(data.get("next_hint"))
    ):
        if data.get("next_hint"):
            parts.append(f"**Note:** {data['next_hint']}")
    elif parallel_note:
        parts.append(f"**Note:** {parallel_note}")
    elif data.get("next_hint") and "Parallel note" in str(data.get("next_hint")):
        parts.append(f"**Note:** {data['next_hint']}")
    # Active-memory awareness — drift / unexplored / unread jobs (advisory, shows on
    # success too, because that's exactly when the agent keeps going without re-syncing).
    mem_note = hybrid_meta.get("memory_awareness") if isinstance(hybrid_meta, dict) else None
    if mem_note:
        parts.append(f"**Memory:** {mem_note}")
    if arts:
        parts.append(_block("Full output on disk (Kali)", arts))
    # Gaps from memory — data, not orders. Delta-aware: collapse to one line
    # while the content signature is unchanged since it was last shown in
    # full, so a growing engagement doesn't re-send the same paragraph on
    # every tool call. Full detail resurfaces whenever it changes or
    # periodically after refresh_every executions.

    eid_for_loops = engagement_id or _SESSION_ENGAGEMENT_ID

    is_trivial_result = (
        not data.get("success")
        or bool(data.get("cache_hit"))
        or not (data.get("stdout") or "").strip()
    )

    if eid_for_loops and not is_trivial_result:
        try:
            global _LAST_OPEN_LOOPS_SIG, _OPEN_LOOPS_REPEAT_COUNT
            loops = _get(
                "/api/v1/hybrid/open-loops",
                params={"engagement_id": eid_for_loops},
                timeout=12,
            )
            loops = loops or {}
            text = loops.get("text") or ""
            count = loops.get("count") or 0
            sig = str(loops.get("signature") or "")
            refresh_every = int(loops.get("refresh_every") or 4)

            if text and count:
                unchanged = bool(sig) and sig == _LAST_OPEN_LOOPS_SIG

                if unchanged and _OPEN_LOOPS_REPEAT_COUNT < refresh_every:
                    _OPEN_LOOPS_REPEAT_COUNT += 1
                    urgent = "⚠ still true — " if loops.get("strongly_recommend_continue") else ""
                    parts.append(
                        f"\n**OPEN GAPS:** {urgent}unchanged since last shown "
                        f"({count} item(s) still open) — platform_context / "
                        "platform_finalize_check for the full list."
                    )
                else:
                    _LAST_OPEN_LOOPS_SIG = sig
                    _OPEN_LOOPS_REPEAT_COUNT = 0
                    parts.append(f"\n**OPEN GAPS** (you choose):\n{text}")
        except Exception:
            pass
    parts.append(
        "\n---\n"
        "You decide the next move from evidence + gaps. Invent when catalog is thin."
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
) -> str:
    """Shared execute path for platform_exec and typed recon/network tools."""
    timeout_seconds = max(30, min(int(timeout_seconds), 900))
    eid, tgt = _resolve_engagement(engagement_id)
    body: dict[str, Any] = {
        "tool_name": tool,
        "params": params,
        "additional_args": additional_args,
        "engagement_id": eid,
        "run_id": SESSION_RUN_ID,
        "record_findings": True,
        "use_recovery": True,
        "use_cache": not bool(force_refresh),
        "force_refresh": bool(force_refresh),
        "timeout": timeout_seconds,
    }
    _log(
        f"exec {tool} target={tgt} engagement={eid} "
        f"run={SESSION_RUN_ID} force_refresh={force_refresh}"
    )
    data = _post("/api/v1/mcp/execute", body, timeout=timeout_seconds + 15)
    return _format_exec_result(data, engagement_id=eid, target=tgt)


@mcp.tool()
def platform_think(
    hypothesis: str,
    plan: str = "",
    evidence: str = "",
    next_tool: str = "",
) -> str:
    """
    Optional: persist a hypothesis into engagement memory (and mirror to operator).

    Not required before tools — use when a pivot needs a durable note. Prefer chat
    narration for routine moves. Stored as unverified observation (not proof).
    """
    def _run() -> str:
        parts = [
            "### OPERATOR MIRROR — THINKING",
            _session_header() if _SESSION_ENGAGEMENT_ID else "(no engagement bound yet)",
            f"**Hypothesis:** {hypothesis.strip() or '(empty)'}",
        ]
        if plan.strip():
            parts.append(f"**Plan:** {plan.strip()}")
        if evidence.strip():
            parts.append(f"**Evidence so far:** {evidence.strip()}")
        if next_tool.strip():
            parts.append(f"**Next tool:** `{next_tool.strip()}`")
        if _SESSION_ENGAGEMENT_ID and hypothesis.strip():
            data = _post(
                "/api/v1/hybrid/think",
                {
                    "engagement_id": _SESSION_ENGAGEMENT_ID,
                    "run_id": SESSION_RUN_ID,
                    "seed_target": _SESSION_TARGET,
                    "hypothesis": hypothesis.strip(),
                    "plan": plan.strip(),
                    "evidence": evidence.strip(),
                    "next_tool": next_tool.strip(),
                },
                timeout=30,
            )
            parts.append(
                f"\nStored finding_id=`{data.get('finding_id')}` — "
                "visible in platform_findings / context."
            )
        else:
            parts.append("\n(No engagement bound — not persisted. Call platform_set_target first.)")
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_graph_link(
    source: str,
    target: str,
    relation: str,
    evidence: str,
    evidence_grade: str = "inferred",
    derived_from: str = "",
) -> str:
    """
    Create an operator-named graph edge (cognition write-back).

    source/target: 'host:erp.x.com' or bare hostname/IP/URL.
    relation: free name (e.g. same_app_as, shares_auth_cookie).
    evidence_grade: observed|inferred|unverified — non-observed becomes hypothesis_* edge
    (not proof for COMPLETE/CRITICAL). evidence= required (why the link exists).
    derived_from: optional comma-separated finding ids this link builds on.
    """
    def _run() -> str:
        _require_bound_target()
        body: dict[str, Any] = {
            "engagement_id": _SESSION_ENGAGEMENT_ID,
            "run_id": SESSION_RUN_ID,
            "seed_target": _SESSION_TARGET,
            "source": source,
            "target": target,
            "relation": relation,
            "evidence": evidence,
            "evidence_grade": evidence_grade,
        }
        if (derived_from or "").strip():
            body["derived_from"] = derived_from.strip()
        data = _post("/api/v1/hybrid/graph/link", body, timeout=30)
        return "\n".join(
            [
                "### OPERATOR MIRROR — GRAPH LINK",
                _session_header(),
                f"**{data.get('source_id')}** --`{data.get('relationship')}`--> "
                f"**{data.get('target_id')}**",
                f"grade={data.get('evidence_grade')} hypothesis={data.get('hypothesis')} "
                f"finding_id=`{data.get('finding_id')}` "
                f"derived_from={data.get('derived_from') or []}",
                data.get("hint") or "",
            ]
        )

    return _safe(_run)


@mcp.tool()
def platform_graph_link_many(
    evidence: str = "",
    evidence_grade: str = "inferred",
    source: str = "",
    relation: str = "",
    targets_json: Any = "[]",
    links_json: Any = "[]",
    derived_from: str = "",
) -> str:
    """
    Persist MANY operator-named graph edges in ONE call — the bulk sibling of
    platform_graph_link.

    Use this instead of calling platform_graph_link N times (e.g. after subfinder
    returns 35 subdomains, or dnsx resolves 30 IPs). The platform does not
    hardcode which relations exist — you still name every relation — this only
    removes the per-edge round-trip so persisting an entire tool run's findings
    is cheap enough to actually do, every time, not just when told to.

    Two ways to pass edges (combine freely):
      - Fan form: source= + relation= + targets_json=[...] — one source, many
        targets sharing the same relation/evidence/evidence_grade. Example:
        source="domain:example.com", relation="has_subdomain",
        targets_json=["subdomain:a.example.com","subdomain:b.example.com"]
      - List form: links_json=[{"source":..,"target":..,"relation":..,
        "evidence":.. (optional, else shared evidence=),
        "evidence_grade":.. (optional, else shared evidence_grade=)}, ...] —
        independent edges with different relations in one call (e.g. a mixed
        batch of resolves_to + runs_tech + co_hosts from one recon pass).

    evidence_grade: observed|inferred|unverified — non-observed becomes
    hypothesis_* edges (not proof for COMPLETE/CRITICAL) per edge, same as the
    single-edge tool. evidence= required unless every links_json item supplies
    its own. derived_from: optional comma-separated finding ids shared by all
    edges in this call.
    """
    def _parse_list(raw: Any) -> list:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, str):
            s = raw.strip()
            if not s:
                return []
            try:
                data = json.loads(s)
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                return [x.strip() for x in s.replace(",", "\n").splitlines() if x.strip()]
        return []

    def _run() -> str:
        _require_bound_target()
        targets = _parse_list(targets_json)
        links = _parse_list(links_json)
        body: dict[str, Any] = {
            "engagement_id": _SESSION_ENGAGEMENT_ID,
            "run_id": SESSION_RUN_ID,
            "seed_target": _SESSION_TARGET,
            "evidence": evidence,
            "evidence_grade": evidence_grade,
            "source": source,
            "relation": relation,
            "targets": [str(t).strip() for t in targets if str(t).strip()],
            "links": [x for x in links if isinstance(x, dict)],
        }
        if (derived_from or "").strip():
            body["derived_from"] = derived_from.strip()
        data = _post("/api/v1/hybrid/graph/link-many", body, timeout=45)
        lines = [
            "### OPERATOR MIRROR — BULK GRAPH LINK",
            _session_header(),
            f"Persisted {data.get('count', 0)} edge(s): "
            f"{data.get('observed_count', 0)} asserted, "
            f"{data.get('hypothesis_count', 0)} hypothesis.",
        ]
        for e in (data.get("edges") or [])[:8]:
            lines.append(f"  {e.get('source')} --`{e.get('relationship')}`--> {e.get('target')}")
        if data.get("count", 0) > 8:
            lines.append(f"  …(+{data['count'] - 8} more)")
        lines.append(f"finding_id=`{data.get('finding_id')}`")
        lines.append(data.get("hint") or "")
        return "\n".join(lines)

    return _safe(_run)


@mcp.tool()
def platform_tag_asset(
    asset: str,
    reason: str,
    role: str = "operator_priority",
    boost: int = 25,
) -> str:
    """
    Tag an asset for crown-jewel ranking (runtime — no YAML edit).

    asset= hostname or host:name. boost= -50..100. reason= why it matters.
    Call platform_crown_jewels after to see updated ranking.
    """
    def _run() -> str:
        _require_bound_target()
        data = _post(
            "/api/v1/hybrid/tag-asset",
            {
                "engagement_id": _SESSION_ENGAGEMENT_ID,
                "run_id": SESSION_RUN_ID,
                "seed_target": _SESSION_TARGET,
                "asset": asset,
                "role": role,
                "boost": int(boost),
                "reason": reason,
            },
            timeout=30,
        )
        return "\n".join(
            [
                "### OPERATOR MIRROR — ASSET TAG",
                _session_header(),
                f"**{data.get('asset')}** role=`{data.get('role')}` boost={data.get('boost')}",
                f"finding_id=`{data.get('finding_id')}`",
                data.get("hint") or "",
            ]
        )

    return _safe(_run)


@mcp.tool()
def platform_finalize_check(override: bool = False) -> str:
    """
    Look back over memory before you stop — not a gate you need to argue past.

    Call this when you think you're finishing, AND when you're stuck (a tool
    keeps failing, you're circling, unsure what's left) — either way, memory
    might already hold the next move.

    Surfaces what's still open in the graph: assets stored but never linked
    (call platform_graph_link_many on them), assets discovered but never
    followed up with a tool, and platform_think hypotheses nothing has tested
    yet. Deepen the highest-value one, or explicitly decide the rest don't
    matter, before writing a report — the platform never forces which.

    A clean result does NOT mean nothing is missing — it means nothing STORED
    is missing. This can't see your own reasoning: if you concluded something
    this session (a pattern, a relation, a suspicion) and never wrote it down,
    that's on you to persist now, then re-check. Context + memory together —
    neither replaces the other.

    Also returns the same report-quality notes as before (weak CRITICAL/CVE
    claims, SPA-false-API, port floods, hypothesis-only paths) as advisory —
    useful for honest labeling, never a reason to refuse writing the report.

    When the look-back total, missing service-scan coverage, or an unresolved
    HIGH/CRITICAL claim crosses a real threshold, the response leads with a
    "STRONGLY RECOMMEND CONTINUING" banner — still your call, but designed to
    not be skimmable past on the way to a summary.
    """
    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/finalize-readiness",
            params={
                "engagement_id": _SESSION_ENGAGEMENT_ID,
                "override": str(bool(override)).lower(),
            },
            timeout=45,
        )
        lb = data.get("look_back") or {}
        lb_total = (
            int(lb.get("orphan_count") or 0)
            + int(lb.get("unexplored_count") or 0)
            + int(lb.get("untested_hypothesis_count") or 0)
        )
        parts = ["### OPERATOR MIRROR — LOOK-BACK"]
        if data.get("strongly_recommend_continue"):
            reasons = data.get("strong_continue_reasons") or []
            parts.append(
                "## ⚠ STRONGLY RECOMMEND CONTINUING — not a block, but read this first\n"
                + "\n".join(f"- {r}" for r in reasons)
            )
        parts.extend([
            _session_header(),
            f"**{lb_total} open item(s) in memory**"
            if lb_total
            else "**Look-back clean** — nothing unlinked/unexplored/untested",
            _block("look_back", lb),
            _block("report_quality_notes (advisory)", data.get("blocked_by") or []),
            _block("checks", data.get("checks") or {}),
            _block("guidance", data.get("guidance") or ""),
        ])
        if data.get("inferred_focus"):
            parts.append(_block("inferred_focus", data["inferred_focus"]))
        if lb_total:
            parts.append(
                "\nPick the highest-value item above and deepen it — or explicitly "
                "note why the rest don't matter — before platform_report_outline."
            )
        else:
            parts.append(
                "\nBefore prose: platform_report_outline — Observed / Inferred / Hypotheses / Crown jewels."
            )
        return "\n\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_report_outline() -> str:
    """
    Structure a trusted report from memory: Observed / Inferred / Hypotheses /
    Crown jewels / open gaps + finalize gate. Call before COMPLETE or PARTIAL prose.
    Does not invent findings — only organizes what is stored.
    """
    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/report-outline",
            params=_memory_params(),
            timeout=45,
        )
        return (
            f"{_session_header()}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_memory_search(query: str, limit: int = 40) -> str:
    """
    Free-text search across engagement memory (findings, graph nodes, attempts).

    Use when you need to find a host, path, CVE string, cookie domain, or past try
    without dumping everything. You interpret hits — this is not a playbook.
    """
    if not (query or "").strip():
        return "ERROR: query is required (e.g. 'erp', '/api', 'Set-Cookie', 'amass')"

    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/memory-search",
            params={**_memory_params(), "q": query.strip(), "limit": max(5, min(int(limit), 80))},
            timeout=45,
        )
        return (
            f"{_session_header()}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_evidence_chain(finding_id: str, depth: int = 4) -> str:
    """
    Walk derived_from parents and children for one finding id.

    Use after graph_link/record_finding with derived_from=, or to explain how a
    claim was built. Soft structure — not a severity upgrade.
    """
    if not (finding_id or "").strip():
        return "ERROR: finding_id required"

    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/evidence-chain",
            params={
                **_memory_params(),
                "finding_id": finding_id.strip(),
                "depth": max(1, min(int(depth), 8)),
            },
            timeout=30,
        )
        if not data.get("ok"):
            return f"ERROR: {data.get('error') or data}"
        return (
            f"{_session_header()}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_attempts(asset: str = "", contains: str = "", limit: int = 40) -> str:
    """
    Advisory history of tools already tried near an asset (or engagement-wide).

    Data only — not a ban. Re-run with new params, force_refresh, job, or script
    whenever the experiment still makes sense.
    """
    def _run() -> str:
        _require_bound_target()
        params = {**_memory_params(), "limit": max(1, min(int(limit), 100))}
        if (asset or "").strip():
            params["asset"] = asset.strip()
        if (contains or "").strip():
            params["contains"] = contains.strip()
        data = _get("/api/v1/hybrid/attempts", params=params, timeout=30)
        return (
            f"{_session_header()}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


def _build_finding_body(
    *,
    title: str,
    evidence: str,
    finding_type: str = "observation",
    evidence_grade: str = "observed",
    claim_severity: str = "none",
    description: str = "",
    source_tool: str = "operator_record",
    derived_from: str = "",
    tags: str = "",
    metadata_json: Any = "",
    confidence: str = "",
) -> dict[str, Any] | str:
    """Assemble a Finding POST body from operator input, or return an ERROR string."""
    title = (title or "").strip()
    evidence = (evidence or "").strip()
    if not title or not evidence:
        return "ERROR: title and evidence are required"

    meta = _coerce_params(metadata_json) if metadata_json not in ("", None) else {}
    if isinstance(meta, str):  # _coerce_params returned an error
        return f"ERROR: metadata_json invalid — {meta}"
    if (derived_from or "").strip():
        meta["derived_from"] = [
            x.strip() for x in derived_from.replace(";", ",").split(",") if x.strip()
        ]

    tag_list = ["operator_recorded"]
    for t in re.split(r"[,\s]+", tags or ""):
        t = t.strip()
        if t and t not in tag_list:
            tag_list.append(t)

    grade = (evidence_grade or "observed").strip().lower()
    conf = (confidence or "").strip().lower()
    if conf not in ("confirmed", "likely", "hypothesis"):
        conf = "confirmed" if grade == "observed" else "likely"

    return {
        "engagement_id": _SESSION_ENGAGEMENT_ID,
        "run_id": SESSION_RUN_ID,
        "finding_type": (finding_type or "observation").strip().lower(),
        "title": title,
        "description": (description or "").strip(),
        "evidence": evidence,
        "evidence_grade": grade,
        "claim_severity": (claim_severity or "none").strip().lower(),
        "confidence": conf,
        "source_tool": source_tool or "operator_record",
        "target": _SESSION_TARGET,
        "tags": tag_list,
        "metadata": meta,
        "extra": {},
    }


@mcp.tool()
def platform_record_finding(
    title: str,
    evidence: str,
    finding_type: str = "observation",
    evidence_grade: str = "observed",
    claim_severity: str = "none",
    description: str = "",
    source_tool: str = "operator_record",
    derived_from: str = "",
    tags: str = "",
    metadata_json: Any = "",
    confidence: str = "",
) -> str:
    """
    Persist one observed fact into engagement memory (solves chat-vs-store drift).

    Use for ANYTHING you noticed and are about to explain in chat instead of
    storing — not just typed-tool banners. WHOIS facts (registrar, DNSSEC
    status, nameservers), a path pattern you spotted in GAU/wayback output,
    an IP-cluster grouping you worked out by hand, a suspicious artifact in
    historical data — all of it belongs here (or in platform_graph_link_many
    if it's a relationship between assets). If you typed it into your answer
    to the user, it should also be here — chat is not memory.

    evidence_grade: observed|inferred|unverified.
    finding_type: url|host|port|service|technology|observation|subdomain
      (use observation for anything that doesn't fit — it's the catch-all).
    claim_severity is clamped by evidence_grade (CRITICAL needs observed).
    derived_from: optional comma-separated parent finding ids (evidence chain).

    Flexibility (structure it your way — the platform stores whatever you give):
    - tags: comma/space list of your own labels (e.g. "oracle,weblogic,login-portal").
    - metadata_json: an object of arbitrary structured fields you choose
      (e.g. {"kind":"jwt","alg":"none","endpoint":"/api/v1/auth"}). Use this to
      record shapes the 7 finding types don't capture — the platform does not
      constrain the keys.
    - confidence: confirmed|likely|hypothesis (defaults from evidence_grade).
    For many facts at once, prefer platform_record_findings (one call).
    """
    def _run() -> str:
        _require_bound_target()
        body = _build_finding_body(
            title=title,
            evidence=evidence,
            finding_type=finding_type,
            evidence_grade=evidence_grade,
            claim_severity=claim_severity,
            description=description,
            source_tool=source_tool,
            derived_from=derived_from,
            tags=tags,
            metadata_json=metadata_json,
            confidence=confidence,
        )
        if isinstance(body, str):
            return body
        data = _post("/api/v1/findings/", body, timeout=30)
        return (
            "### OPERATOR MIRROR — RECORDED FINDING\n"
            f"{_session_header()}\n"
            f"Stored id={data.get('id')} type={data.get('finding_type')} "
            f"grade={data.get('evidence_grade')} sev={data.get('claim_severity')}\n"
            f"title: {data.get('title')}\n"
            "Call platform_findings to verify; then platform_finalize_check again."
        )

    return _safe(_run)


@mcp.tool()
def platform_record_findings(items_json: Any) -> str:
    """
    Persist MANY operator-authored facts in one call (bulk platform_record_finding).

    Use this after reading a large raw output (GAU/wayback dumps, a JS bundle, a
    cert SAN list, a page of banners) so everything you noticed lands in memory
    in a single round-trip instead of one call per fact — chat is not memory,
    and this makes storing-everything cheap.

    items_json: a JSON array (or JSON string of one). Each item accepts the same
    fields as platform_record_finding — at minimum title + evidence:
      [
        {"title":"...","evidence":"...","finding_type":"url","evidence_grade":"observed",
         "tags":"oracle,api","metadata_json":{"status":401}},
        {"title":"...","evidence":"...","finding_type":"observation"}
      ]
    Each item is stored with the same evidence-law clamping and graph ingest as a
    single write; duplicates are de-duped by content.
    """
    def _run() -> str:
        _require_bound_target()
        raw = items_json
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                return f"ERROR: items_json is not valid JSON: {exc}"
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            return "ERROR: items_json must be a non-empty JSON array of finding objects"
        if len(raw) > 200:
            return "ERROR: too many items (max 200 per call — split into batches)"

        bodies: list[dict[str, Any]] = []
        errors: list[str] = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                errors.append(f"item {i}: not an object")
                continue
            body = _build_finding_body(
                title=str(item.get("title") or ""),
                evidence=str(item.get("evidence") or ""),
                finding_type=str(item.get("finding_type") or "observation"),
                evidence_grade=str(item.get("evidence_grade") or "observed"),
                claim_severity=str(item.get("claim_severity") or "none"),
                description=str(item.get("description") or ""),
                source_tool=str(item.get("source_tool") or "operator_record"),
                derived_from=str(item.get("derived_from") or ""),
                tags=str(item.get("tags") or "") if not isinstance(item.get("tags"), list)
                else ",".join(str(x) for x in item.get("tags")),
                metadata_json=item.get("metadata_json") or item.get("metadata") or "",
                confidence=str(item.get("confidence") or ""),
            )
            if isinstance(body, str):
                errors.append(f"item {i}: {body}")
            else:
                bodies.append(body)

        if not bodies:
            return "ERROR: no valid findings.\n" + "\n".join(errors[:20])

        data = _post("/api/v1/findings/bulk", bodies, timeout=60)
        stored = data.get("findings") or []
        parts = [
            "### OPERATOR MIRROR — RECORDED FINDINGS (bulk)",
            _session_header(),
            f"Stored {len(stored)} finding(s) (of {len(raw)} submitted"
            + (f"; {len(bodies) - len(stored)} deduped" if len(bodies) > len(stored) else "")
            + ").",
        ]
        if errors:
            parts.append(_block(f"Skipped {len(errors)}", errors[:20]))
        parts.append("Call platform_findings to verify.")
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_tools(query: str = "", category: str = "") -> str:
    """
    List registered catalog tool names (fixes 404 from short names).

    query= filters by substring (e.g. query='dns' or 'nmap').
    category= recon|network|... optional.
    Prefer these exact names with platform_exec. Short aliases (subfinder→subfinder_scan)
    are also accepted.
    """
    def _run() -> str:
        params: dict[str, Any] = {}
        if category.strip():
            params["category"] = category.strip().lower()
        data = _get("/api/v1/tools/catalog", params=params or None, timeout=30)
        tools = data.get("tools") or []
        normalized = []
        for t in tools:
            if not isinstance(t, dict):
                continue
            name = t.get("name") or ""
            if not name and isinstance(t.get("tool"), dict):
                name = t["tool"].get("name", "")
            desc = t.get("description") or ""
            if not desc and isinstance(t.get("tool"), dict):
                desc = t["tool"].get("description", "")
            cat = t.get("category") or ""
            if not cat and isinstance(t.get("tool"), dict):
                cat = t["tool"].get("category", "")
            installed = t.get("installed")
            normalized.append(
                {
                    "name": name,
                    "description": (desc or "")[:100],
                    "category": cat,
                    "installed": installed,
                }
            )
        tools = normalized
        q = query.strip().lower()
        lines = []
        for t in tools:
            name = t.get("name") or ""
            if not name:
                continue
            desc = t.get("description") or ""
            cat = t.get("category") or ""
            if q and q not in name.lower() and q not in desc.lower():
                continue
            flag = "OK" if t.get("installed") is True else (
                "MISSING" if t.get("installed") is False else "?"
            )
            lines.append(f"- [{flag}] {name}  [{cat}]  {desc}")
        lines = lines[:120]
        ok_n = sum(1 for ln in lines if ln.startswith("- [OK]"))
        miss_n = sum(1 for ln in lines if ln.startswith("- [MISSING]"))
        return (
            "### OPERATOR MIRROR — TOOL CATALOG\n"
            f"{_session_header() if _SESSION_ENGAGEMENT_ID else '(bind target optional for catalog)'}\n"
            f"Showing {len(lines)} tools (OK={ok_n} MISSING_IN_KALI={miss_n})"
            + (f" matching {query!r}" if q else "")
            + "\nPrefer [OK] tools. Typed recon/network tools are also registered on MCP "
            "(subfinder_scan, nmap_*, rustscan_fast_scan, …). "
            "For [MISSING], use platform_shell/platform_script or platform_install.\n\n"
            + ("\n".join(lines) if lines else "(none — try empty query)")
            + "\n\nAliases: subfinder→subfinder_scan, amass→amass_scan, dnsenum→dnsenum_scan, "
            "httpx→httpx_probe, nmap→nmap_syn_scan, whois→whois_lookup, masscan→masscan_high_speed.\n"
            "Sequencing help: platform_playbook(). Playground: platform_script, platform_install, "
            "platform_record_finding."
        )

    return _safe(_run)


@mcp.tool()
def platform_findings(
    limit: int = 120,
    finding_type: str = "",
    include_summary: bool = True,
    engagement_id: str = "",
) -> str:
    """
    Dump stored findings. Optional mid-engagement — use when the operator asks
    or before a final report. Tools already ingest into memory automatically.
    Optional finding_type: subdomain | host | url | port | service | technology | observation.

    engagement_id: optional pin to a specific engagement — see platform_exec.
    Use this if findings for a different target start showing up here; it
    usually means another chat sharing this MCP process switched the shared
    session with platform_set_target after you bound yours.
    """
    limit = max(10, min(int(limit), 500))

    def _run() -> str:
        eid, tgt = _resolve_engagement(engagement_id)
        params: dict[str, Any] = {
            "engagement_id": eid,
            "limit": limit,
        }
        if finding_type.strip():
            params["finding_type"] = finding_type.strip().lower()

        parts = [
            "### OPERATOR MIRROR — FINDINGS",
            _session_header(eid, tgt),
        ]
        if include_summary:
            summary = _get(
                "/api/v1/findings/summary",
                params={"engagement_id": eid},
                timeout=30,
            )
            meta = summary if isinstance(summary, dict) else {}
            parts.append(_block("Findings summary", meta.get("summary", summary)))
            if meta.get("count") is not None:
                parts.append(
                    f"_count={meta.get('count')} | "
                    f"truncated={meta.get('truncated')} | "
                    f"generated_at={meta.get('generated_at', '')[:19]}_"
                )

        data = _get("/api/v1/findings/", params=params, timeout=45)
        findings = data.get("findings") or []
        total = data.get("total", len(findings))
        lines = []
        for f in findings:
            ft = f.get("finding_type", "")
            conf = f.get("confidence", "")
            grade = f.get("evidence_grade") or (f.get("extra") or {}).get("evidence_grade") or "?"
            sev = f.get("claim_severity") or (f.get("extra") or {}).get("claim_severity") or "none"
            title = f.get("title", "")
            tool = f.get("source_tool", "")
            tags = ",".join(f.get("tags") or [])
            lines.append(
                f"- [{ft}|grade={grade}|sev={sev}|{conf}] {title}  (via {tool})"
                + (f" tags={tags}" if tags else "")
            )
        parts.append(
            _block(
                f"Findings list (showing {len(findings)} / total field {total})",
                "\n".join(lines) if lines else "(none)",
            )
        )
        parts.append(
            "Paste important rows into your chat reply so the operator sees them. "
            "HIGH/CRITICAL only valid with grade=observed."
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
        eid, tgt = _resolve_engagement(engagement_id)
        body: dict[str, Any] = {
            "kind": kind_n,
            "engagement_id": eid,
            "run_id": SESSION_RUN_ID,
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
            _session_header(eid, tgt),
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
def platform_job_poll(job_id: str = "", engagement_id: str = "") -> str:
    """
    Poll one job (job_id=…) or list all jobs for this engagement (empty job_id).

    Status: queued | running | completed | failed.
    When completed: findings already in memory — then platform_job_result for full stdout.

    engagement_id: optional pin — only matters for the "list all jobs" mode
    (empty job_id). A specific job_id is already unambiguous. See platform_exec.
    """
    def _run() -> str:
        eid, tgt = _resolve_engagement(engagement_id)
        jid = (job_id or "").strip()
        if not jid:
            data = _get(
                "/api/v1/jobs",
                params={"engagement_id": eid, "limit": "20"},
            )
            return "\n\n".join([_session_header(eid, tgt), _block("Jobs (this engagement)", data)])
        data = _get(f"/api/v1/jobs/{jid}")
        return "\n\n".join([_session_header(eid, tgt), _block(f"Job {jid}", data)])

    return _safe(_run)


@mcp.tool()
def platform_job_result(job_id: str) -> str:
    """
    Fetch full result of a background job (stdout/stderr/findings) when completed/failed.

    After reading: short chat summary for that branch, then keep expanding.
    Call platform_findings once when the expansion pass ends — not after every job.
    """
    jid = (job_id or "").strip()
    if not jid:
        return "ERROR: job_id required"

    def _run() -> str:
        _require_bound_target()
        data = _get(f"/api/v1/jobs/{jid}/result", timeout=60)
        job = data.get("job") or {}
        result = data.get("result")
        parts = [
            "### OPERATOR MIRROR — JOB RESULT",
            _session_header(),
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
            # Reuse exec formatter for stdout visibility
            parts.append(_format_exec_result(result))
        else:
            parts.append("(no result payload yet — still running? call platform_job_poll)")
        parts.append(
            "\nBranch done — short chat note, then continue other work (or finalize if last pass)."
        )
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
    Allowlisted binary argv in Kali. Simple pipes OK when EVERY stage is allowlisted
    (e.g. 'curl -sI https://x | grep -i server'). Still blocked: ; & ` $ () <> && ||.
    Example: 'nmap -sV -p 80,443 1.2.3.4'. Prefer platform_exec for catalog tools.
    Loops, redirects, complex logic → platform_script.

    engagement_id: optional pin to a specific engagement — see platform_exec.
    """
    timeout_seconds = max(30, min(int(timeout_seconds), 900))

    def _run() -> str:
        eid, tgt = _resolve_engagement(engagement_id)
        body = {
            "command": command,
            "engagement_id": eid,
            "run_id": SESSION_RUN_ID,
            "reason": reason,
            "timeout": timeout_seconds,
            "record_findings": True,
        }
        _log(f"shell engagement={eid} cmd={command[:200]}")
        data = _post("/api/v1/mcp/shell", body, timeout=timeout_seconds + 15)
        return _format_exec_result(data, engagement_id=eid, target=tgt)

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
        eid, tgt = _resolve_engagement(engagement_id)
        body = {
            "code": code,
            "language": language,
            "engagement_id": eid,
            "run_id": SESSION_RUN_ID,
            "reason": reason,
            "filename": filename,
            "packages": packages,
            "timeout": timeout_seconds,
            "record_findings": True,
        }
        _log(
            f"script lang={language} engagement={eid} "
            f"bytes={len(code.encode('utf-8', errors='replace'))} pkgs={packages!r}"
        )
        data = _post("/api/v1/mcp/script", body, timeout=timeout_seconds + 120)
        return _format_exec_result(data, engagement_id=eid, target=tgt)

    return _safe(_run)


@mcp.tool()
def platform_install(
    packages: str,
    manager: str = "pip",
    reason: str = "",
    timeout_seconds: int = 300,
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
        _require_bound_target()
        body = {
            "manager": manager,
            "packages": packages,
            "engagement_id": _SESSION_ENGAGEMENT_ID,
            "run_id": SESSION_RUN_ID,
            "reason": reason,
            "timeout": timeout_seconds,
        }
        _log(f"install mgr={manager} pkgs={packages[:200]}")
        data = _post("/api/v1/mcp/install", body, timeout=timeout_seconds + 30)
        return _format_exec_result(data)

    return _safe(_run)


@mcp.tool()
def platform_fanout(
    action: str = "enumerate_sisters",
    dry_run: bool = True,
    confirm: bool = False,
    max_domains: int = 10,
    timeout_per_tool: int = 180,
) -> str:
    """
    OPTIONAL explicit batch helper for sister subdomain enum (dry_run by default).
    Uses the active target's engagement only.
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
        _require_bound_target()
        body = {
            "run_id": SESSION_RUN_ID,
            "tool_name": "subfinder_scan",
            "max_domains": max_domains,
            "timeout_per_tool": timeout_per_tool,
            "dry_run": bool(dry_run),
            "confirm": bool(confirm),
            "skip_already_marked": True,
        }
        timeout = QUICK_TIMEOUT if dry_run or not confirm else float(timeout_per_tool * max_domains + 60)
        data = _post(
            f"/api/v1/engagements/{_SESSION_ENGAGEMENT_ID}/actions/enumerate-pending-sisters",
            body,
            timeout=timeout,
        )
        return "\n\n".join([_session_header(), _block("Fan-out (explicit)", data)])

    return _safe(_run)


def _load_playbooks() -> dict[str, Any]:
    from pathlib import Path

    # YAML is the source of truth for config/ (see config/README.md); JSON is
    # only a legacy fallback if the yaml file is ever missing.
    root = Path(__file__).resolve().parents[1] / "config"
    yaml_path = root / "playbooks.yaml"
    json_path = root / "playbooks.json"
    try:
        if yaml_path.exists():
            import yaml  # type: ignore

            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            return data.get("playbooks") or {}
        if json_path.exists():
            data = json.loads(json_path.read_text(encoding="utf-8"))
            return data.get("playbooks") or {}
    except Exception as exc:  # noqa: BLE001
        _log(f"playbooks load failed: {exc}")
    return {}


@mcp.tool()
def platform_playbook(name: str = "", target: str = "") -> str:
    """
    Advisory playbook only — does NOT auto-run tools.

    Returns a suggested tool sequence you may follow, edit, or ignore.
    Names: web_recon_light | network_crown_jewels | dns_deep | smb_followup | web_depth_before_vuln
    Pass empty name to list available playbooks.
    """
    books = _load_playbooks()
    if not name.strip():
        lines = ["### OPERATOR MIRROR — PLAYBOOKS (advisory)", "Available:"]
        for key, meta in books.items():
            lines.append(f"- {key}: {(meta or {}).get('description', '')[:160]}")
        lines.append(
            "Call platform_playbook(name='web_recon_light', target='example.com') "
            "then decide yourself — nothing auto-executes."
        )
        return "\n".join(lines)

    key = name.strip().lower()
    meta = books.get(key)
    if not meta:
        return (
            f"ERROR: unknown playbook {name!r}. "
            f"Known: {', '.join(sorted(books)) or '(none — check config/playbooks.yaml)'}"
        )

    tgt = (target or _SESSION_TARGET or "{{target}}").strip()
    steps = meta.get("steps") or []
    lines = [
        "### OPERATOR MIRROR — PLAYBOOK (advisory — you choose)",
        _session_header() if _SESSION_ENGAGEMENT_ID else "(bind target optional)",
        f"**Playbook:** `{key}`",
        f"**Phase:** {meta.get('phase', '?')}",
        f"**Input:** {meta.get('input', 'target')} → `{tgt}`",
        f"**Description:** {(meta.get('description') or '').strip()}",
        "",
        "Suggested steps (adapt freely):",
    ]
    for i, step in enumerate(steps, 1):
        tool = step.get("tool", "?")
        why = step.get("why", "")
        fallback = step.get("fallback") or []
        params = step.get("suggested_params") or {}
        # Light template fill
        rendered = {
            k: (str(v).replace("{{target}}", tgt) if isinstance(v, str) else v)
            for k, v in params.items()
        }
        lines.append(f"{i}. **{tool}** — {why}")
        if rendered:
            lines.append(f"   suggested_params: {json.dumps(rendered)}")
        if fallback:
            lines.append(f"   fallback: {', '.join(fallback)}")
        if step.get("note"):
            lines.append(f"   note: {step['note']}")
    lines.append(
        "\nNothing was executed. Run the tools yourself (typed / exec / script / jobs). "
        "Edit or skip steps freely."
    )
    return "\n".join(lines)


@mcp.tool()
def platform_skills(path: str = "", phase: str = "", query: str = "") -> str:
    """
    Browse platform skill markdown (commander, recon, network, products, …).

    Empty path → index. path='shared/evidence-to-hypothesis.md' → full text.
    phase= / query= filter the index.
    """
    def _run() -> str:
        if path.strip():
            data = _get(
                "/api/v1/capabilities/skills-file",
                params={"path": path.strip()},
            )
            return "\n\n".join(
                [
                    "### OPERATOR MIRROR — SKILL",
                    f"**path:** `{data.get('path')}` — {data.get('title')}",
                    data.get("content") or "",
                ]
            )
        params: dict[str, str] = {}
        if phase.strip():
            params["phase"] = phase.strip()
        if query.strip():
            params["query"] = query.strip()
        data = _get("/api/v1/capabilities/skills-index", params=params or None)
        lines = [
            "### OPERATOR MIRROR — SKILLS INDEX",
            f"count={data.get('count')}",
            "Call platform_skills(path='…') for full text.",
        ]
        for it in data.get("skills") or []:
            lines.append(f"- [{it.get('phase')}] {it.get('path')} — {it.get('title')}")
        return "\n".join(lines)

    return _safe(_run)


@mcp.tool()
def platform_config(name: str = "") -> str:
    """
    Read allowlisted platform YAML/JSON (playbooks, ingest_rules, recon_network_tools, …).
    Empty name → list. name='ingest_rules' → content.
    """
    def _run() -> str:
        if not name.strip():
            data = _get("/api/v1/capabilities/config-index")
            lines = ["### OPERATOR MIRROR — CONFIG INDEX", f"count={data.get('count')}"]
            for it in data.get("configs") or []:
                lines.append(f"- {it.get('name')} ({it.get('file')})")
            return "\n".join(lines)
        data = _get(
            "/api/v1/capabilities/config-file",
            params={"name": name.strip()},
        )
        content = data.get("content") or ""
        if len(content) > 120000:
            content = content[:120000] + "\n…[truncated]…"
        return "\n\n".join(
            [
                "### OPERATOR MIRROR — CONFIG",
                f"**{data.get('file')}**",
                content,
            ]
        )

    return _safe(_run)


@mcp.tool()
def platform_graph_query(
    asset_type: str = "",
    contains: str = "",
    limit: int = 80,
    from_asset: str = "",
    max_hops: int = 0,
) -> str:
    """
    Query the engagement asset graph (not just the summary dump).

    Two modes:
    - Type/label filter (default): asset_type=subdomain|host|url|port|ip|technology|
      service|domain, contains=substring (e.g. vpn, oracle, api).
    - Multi-hop traversal: set from_asset (a hostname/IP/label, or 'type:label')
      + max_hops (1-6) instead. Walks the graph outward from that asset, undirected
      — the same way a human pentester follows relationships regardless of which
      way an edge was written — and returns everything reachable within max_hops,
      sorted closest first. Use this to answer "what's actually connected to X"
      beyond the 1-hop siblings you'd get from reading edges directly.
    """
    limit = max(1, min(int(limit), 500))
    max_hops = max(0, min(int(max_hops), 6))

    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/graph/query",
            params={
                "engagement_id": _SESSION_ENGAGEMENT_ID,
                "asset_type": asset_type,
                "contains": contains,
                "limit": str(limit),
                "from_asset": from_asset,
                "max_hops": str(max_hops),
            },
        )
        return "\n\n".join([_session_header(), _block("Graph query", data)])

    return _safe(_run)


@mcp.tool()
def platform_crown_jewels(limit: int = 15) -> str:
    """Rank high-value assets by role + evidence (VPN/mail/admin/api…) — not vendor packs."""
    limit = max(1, min(int(limit), 50))

    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/crown-jewels",
            params={
                "engagement_id": _SESSION_ENGAGEMENT_ID,
                "limit": str(limit),
            },
        )
        return "\n\n".join([_session_header(), _block("Crown jewels", data)])

    return _safe(_run)


@mcp.tool()
def platform_thinking(limit: int = 10) -> str:
    """
    Optional: evidence → next-probe cards from current findings.
    Use when stuck on a fingerprint — not required every turn.
    """
    limit = max(1, min(int(limit), 30))

    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/thinking-hypotheses",
            params={
                "engagement_id": _SESSION_ENGAGEMENT_ID,
                "limit": str(limit),
            },
        )
        return "\n\n".join([_session_header(), _block("Thinking hypotheses", data)])

    return _safe(_run)


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
) -> str:
    """
    Run one catalog tool across an EXPLICIT asset list (you choose — from crown jewels/graph).

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
    max_assets = max(1, min(int(max_assets), 100))
    timeout_per_tool = max(30, min(int(timeout_per_tool), 600))

    def _run() -> str:
        _require_bound_target()
        body = {
            "assets": [str(a).strip() for a in assets if str(a).strip()],
            "tool_name": tool,
            "dry_run": bool(dry_run),
            "confirm": bool(confirm),
            "max_assets": max_assets,
            "timeout_per_tool": timeout_per_tool,
            "additional_args": additional_args,
            "run_id": SESSION_RUN_ID,
            "force_refresh": bool(force_refresh),
        }
        timeout = (
            QUICK_TIMEOUT
            if dry_run or not confirm
            else float(timeout_per_tool * min(len(body["assets"]), max_assets) + 60)
        )
        data = _post(
            f"/api/v1/engagements/{_SESSION_ENGAGEMENT_ID}/actions/fanout-assets",
            body,
            timeout=timeout,
        )
        return "\n\n".join([_session_header(), _block("Fan-out assets", data)])

    return _safe(_run)


# Typed recon/network catalog tools (HexStrike-style schemas for the LLM).
def _typed_execute(
    tool_name: str,
    params: dict[str, Any],
    *,
    additional_args: str = "",
    timeout_seconds: int = 300,
) -> str:
    return _safe(
        lambda: _execute_catalog_tool(
            tool_name,
            params,
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
        )
    )


_TYPED_COUNT = register_typed_recon_network_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_COUNT} typed recon/network tools")

_TYPED_TECH_COUNT = register_typed_tech_identification_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_TECH_COUNT} typed tech-identification tools")

_TYPED_OSINT_COUNT = register_typed_osint_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_OSINT_COUNT} typed passive-OSINT tools")


if __name__ == "__main__":
    _log(f"session run_id={SESSION_RUN_ID} (dynamic target — call platform_set_target first)")
    mcp.run()
