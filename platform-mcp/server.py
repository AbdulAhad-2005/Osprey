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

API_BASE = os.environ.get("PENTEST_API_BASE", "http://localhost:9000").rstrip("/")
QUICK_TIMEOUT = float(os.environ.get("PENTEST_QUICK_TIMEOUT", "60"))
# Long exec/script posts — keep ≥ OpenCode mcp.timeout (ms) / 1000
HTTP_TIMEOUT = float(os.environ.get("PENTEST_HTTP_TIMEOUT", "900"))
SESSION_RUN_ID = os.environ.get("PENTEST_RUN_ID", "") or uuid.uuid4().hex[:12]

# Active session — one engagement per root target
_SESSION_TARGET = ""
_SESSION_ENGAGEMENT_ID = ""
_SESSION_SWITCH_NOTICE = ""

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

    normalized = _normalize_target(target)
    if not _valid_domain(normalized):
        raise ValueError(
            f"Incomplete or invalid target {target!r}. "
            "Ask the user for the exact FQDN after reviewing analyze-target candidates."
        )

    previous_target = _SESSION_TARGET
    previous_engagement = _SESSION_ENGAGEMENT_ID
    switched = bool(previous_target and previous_target != normalized)

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


def _session_header() -> str:
    _require_bound_target()
    lines = [
        f"target: {_SESSION_TARGET}",
        f"engagement_id: {_SESSION_ENGAGEMENT_ID}",
        f"run_id: {SESSION_RUN_ID}",
    ]
    if _SESSION_SWITCH_NOTICE:
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


def _fetch_context() -> str:
    data = _get(
        "/api/v1/hybrid/context/auto",
        params=_memory_params(),
    )
    readiness = data.get("finalize_readiness") or {}
    finalize_banner = (
        f"can_finalize={readiness.get('can_finalize')} | "
        f"blocked_by={readiness.get('blocked_by') or []} | "
        f"{(readiness.get('guidance') or '')[:500]}"
    )

    parts = [
        _session_header(),
        "### OPEN LOOPS (pick one — loop back to earlier tools with NEW targets)",
        _block(
            "open_loops",
            (data.get("open_loops") or {}).get("text")
            or (data.get("open_loops") or {}),
        ),
        _block("Context delta", data.get("context_delta") or {}),
        _block("Crown jewels", data.get("crown_jewels") or []),
        _block("Coverage gaps (top)", (data.get("coverage_gaps") or [])[:12]),
        _block("Background jobs", data.get("background_jobs") or []),
        _block("Findings summary", data.get("findings_summary", "")[:2500]),
        _block("Inferred focus", data.get("inferred_focus", {})),
        _block("Finalize", finalize_banner),
    ]
    if data.get("network_surface_text"):
        parts.append(_block("Network surface", data["network_surface_text"]))
    if data.get("attack_surface_tree_text"):
        tree = data["attack_surface_tree_text"]
        parts.append(_block("Attack surface tree", tree[:4000] + ("…" if len(tree) > 4000 else "")))
    parts.append(
        "---\n"
        "Act on an OPEN LOOP (or invent). Do not one-and-done each tool. "
        "Jobs for slow scans; scripts when wrappers fail."
    )
    return "\n\n---\n\n".join(parts)


@mcp.tool()
def platform_context(target: str = "") -> str:
    """
    Load platform brain from evidence: inferred focus, gaps, tree, findings, tools.

    No phase argument — the platform infers where the engagement is and you move
    accordingly. Pass target= only to analyze/switch (short names still clarify first).
    """
    def _run() -> str:
        if target.strip():
            clarified = _analyze_or_bind(target)
            if clarified.startswith("## Target needs clarification"):
                return clarified
        _require_bound_target()
        return _fetch_context()

    return _safe(_run)


def _format_exec_result(data: dict[str, Any]) -> str:
    stdout = data.get("stdout") or ""
    stderr = data.get("stderr") or ""
    # Prefer showing more to OpenCode; artifacts hold the rest.
    stdout_show = stdout if len(stdout) <= 280000 else (
        stdout[:140000] + "\n\n…[middle omitted — full artifact on Kali]…\n\n" + stdout[-120000:]
    )
    stderr_show = stderr if len(stderr) <= 60000 else stderr[:60000] + "\n…[stderr truncated]…"

    parts = [
        "### OPERATOR MIRROR — EXECUTION",
        _session_header(),
        f"success: {data.get('success')} | returncode: {data.get('returncode')} | "
        f"timed_out: {data.get('timed_out')} | cache_hit: {data.get('cache_hit')}"
        + (f" | cache_key: `{data.get('cache_key')}`" if data.get("cache_key") else "")
    ]
    if data.get("command"):
        parts.append(f"**COMMAND:** `{data['command']}`")
    if data.get("tool_name"):
        parts.append(f"**TOOL:** `{data['tool_name']}`")
    if data.get("cache_hit"):
        parts.append(
            "**CACHE HIT** — identical tool+params already ran this engagement. "
            "Reuse results, change params, or platform_exec(..., force_refresh=true)."
        )
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
        parts.append(_block(f"Parsed findings this run ({len(titles)})", titles[:120]))
        if len(titles) > 120:
            parts.append(f"… +{len(titles) - 120} more titles — memory has them; dump via platform_findings at end of pass")
    if data.get("next_hint"):
        parts.append(f"**TRY NEXT / HINT:** {data['next_hint']}")
    fallbacks = data.get("fallback_tools") or []
    if fallbacks:
        parts.append("**FALLBACK TOOLS:** " + ", ".join(str(x) for x in fallbacks[:8]))
    if data.get("alternative_tool_suggested"):
        parts.append(f"SUGGESTED ALTERNATIVE: {data['alternative_tool_suggested']}")
    if data.get("hybrid"):
        parts.append(_block("Hybrid / artifacts", data["hybrid"]))
    arts = (data.get("hybrid") or {}).get("artifacts") or (data.get("parsed") or {}).get("artifacts")
    if arts:
        parts.append(_block("Full output on disk (Kali)", arts))
    # Adaptive nudge from memory — not a stage script
    if _SESSION_ENGAGEMENT_ID:
        try:
            loops = _get(
                "/api/v1/hybrid/open-loops",
                params={"engagement_id": _SESSION_ENGAGEMENT_ID},
                timeout=12,
            )
            text = (loops or {}).get("text") or ""
            if text and (loops or {}).get("count"):
                parts.append(f"\n**OPEN LOOPS** (loop back — pick one):\n{text}")
        except Exception:
            pass
    parts.append(
        "\n---\n"
        "Prefer an OPEN LOOP with new targets over jumping to a new 'phase'. "
        "Jobs/scripts if this failed."
    )
    return "\n".join(parts)


def _execute_catalog_tool(
    tool: str,
    params: dict[str, Any],
    *,
    additional_args: str = "",
    timeout_seconds: int = 300,
    force_refresh: bool = False,
) -> str:
    """Shared execute path for platform_exec and typed recon/network tools."""
    timeout_seconds = max(30, min(int(timeout_seconds), 900))
    _require_bound_target()
    body: dict[str, Any] = {
        "tool_name": tool,
        "params": params,
        "additional_args": additional_args,
        "engagement_id": _SESSION_ENGAGEMENT_ID,
        "run_id": SESSION_RUN_ID,
        "record_findings": True,
        "use_recovery": True,
        "use_cache": not bool(force_refresh),
        "force_refresh": bool(force_refresh),
        "timeout": timeout_seconds,
    }
    _log(
        f"exec {tool} target={_SESSION_TARGET} engagement={_SESSION_ENGAGEMENT_ID} "
        f"run={SESSION_RUN_ID} force_refresh={force_refresh}"
    )
    data = _post("/api/v1/mcp/execute", body, timeout=timeout_seconds + 15)
    return _format_exec_result(data)


@mcp.tool()
def platform_think(
    hypothesis: str,
    plan: str = "",
    evidence: str = "",
    next_tool: str = "",
) -> str:
    """
    Optional: mirror a hypothesis to the operator. Not required before tools —
    use when a pivot needs a clear note. Prefer chat narration for routine moves.
    """
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
    parts.append("\n(Optional note recorded — continue the engagement.)")
    return "\n".join(parts)


@mcp.tool()
def platform_finalize_check(override: bool = False) -> str:
    """
    Gate before any COMPLETE engagement report.

    Returns report_mode=complete|partial_only. If partial_only: you may write a
    status update, but must NOT ship COMPLETE/CRITICAL theater from chat memory.
    Persist observed facts with platform_record_finding first, then re-check.

    Infra noise (port flood / honeypot inventory gaps) is waived when strong
    observed proof exists — claim integrity (unverified HIGH/CVE, SPA false API)
    still hard-blocks. override=true only when the operator explicitly allows it.
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
        mode = data.get("report_mode") or (
            "complete" if data.get("can_finalize") else "partial_only"
        )
        status = "COMPLETE ALLOWED" if mode == "complete" else "PARTIAL ONLY"
        parts = [
            "### OPERATOR MIRROR — FINALIZE CHECK",
            _session_header(),
            f"**Status: {status}** (report_mode={mode})",
            _block("blocked_by", data.get("blocked_by") or []),
            _block("checks", data.get("checks") or {}),
            _block("guidance", data.get("guidance") or ""),
        ]
        if data.get("inferred_focus"):
            parts.append(_block("inferred_focus", data["inferred_focus"]))
        if mode != "complete":
            parts.append(
                "\nDo NOT write COMPLETE/FINAL with CRITICAL catalogs from chat alone. "
                "Call platform_findings; if a banner you saw is missing, "
                "platform_record_finding then re-check. Partial status updates are OK."
            )
        return "\n\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_record_finding(
    title: str,
    evidence: str,
    finding_type: str = "observation",
    evidence_grade: str = "observed",
    claim_severity: str = "none",
    description: str = "",
    source_tool: str = "operator_record",
) -> str:
    """
    Persist one observed fact into engagement memory (solves chat-vs-store drift).

    Use when a script/shell showed a real banner/title/port but platform_findings
    does not list it yet. evidence_grade: observed|inferred|unverified.
    finding_type: url|host|port|service|technology|observation|subdomain.
    claim_severity is clamped by evidence_grade (CRITICAL needs observed).
    """
    def _run() -> str:
        _require_bound_target()
        body = {
            "engagement_id": _SESSION_ENGAGEMENT_ID,
            "run_id": SESSION_RUN_ID,
            "finding_type": (finding_type or "observation").strip().lower(),
            "title": title.strip(),
            "description": description.strip(),
            "evidence": evidence.strip(),
            "evidence_grade": (evidence_grade or "observed").strip().lower(),
            "claim_severity": (claim_severity or "none").strip().lower(),
            "confidence": "confirmed" if evidence_grade.strip().lower() == "observed" else "likely",
            "source_tool": source_tool or "operator_record",
            "target": _SESSION_TARGET,
            "tags": ["operator_recorded"],
            "extra": {},
        }
        if not body["title"] or not body["evidence"]:
            return "ERROR: title and evidence are required"
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
) -> str:
    """
    Dump stored findings. Optional mid-engagement — use when the operator asks
    or before a final report. Tools already ingest into memory automatically.
    Optional finding_type: subdomain | host | url | port | service | technology | observation.
    """
    limit = max(10, min(int(limit), 500))

    def _run() -> str:
        _require_bound_target()
        params: dict[str, Any] = {
            "engagement_id": _SESSION_ENGAGEMENT_ID,
            "limit": limit,
        }
        if finding_type.strip():
            params["finding_type"] = finding_type.strip().lower()

        parts = [
            "### OPERATOR MIRROR — FINDINGS",
            _session_header(),
        ]
        if include_summary:
            summary = _get(
                "/api/v1/findings/summary",
                params={"engagement_id": _SESSION_ENGAGEMENT_ID},
                timeout=30,
            )
            parts.append(_block("Findings summary (text)", summary.get("summary", summary)))

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
) -> str:
    """
    Start a PARALLEL background branch. Returns job_id immediately — do NOT wait.

    Use when a tool will take long (amass, nmap, rustscan, bulk httpx, scripts).
    Keep working on other hosts/tasks, then platform_job_poll(job_id) / platform_job_result.

    kind: tool | shell | script
    tool + params_json: for kind=tool (same as platform_exec)
    command: for kind=shell
    code: for kind=script
    Max 4 running jobs per engagement.
    """
    kind_n = (kind or "tool").strip().lower()
    if kind_n not in ("tool", "shell", "script"):
        return "ERROR: kind must be tool | shell | script"
    timeout_seconds = max(30, min(int(timeout_seconds), 3600))

    def _run() -> str:
        _require_bound_target()
        body: dict[str, Any] = {
            "kind": kind_n,
            "engagement_id": _SESSION_ENGAGEMENT_ID,
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
            _session_header(),
            f"**job_id:** `{data.get('job_id')}`",
            f"**status:** {data.get('status')} | **label:** {data.get('label')}",
            f"**kind:** {data.get('kind')} | **tool:** {data.get('tool_name')}",
            data.get("hint") or "",
            "",
            "Continue other work NOW. Later: platform_job_poll(job_id=…) "
            "then platform_job_result(job_id=…). Findings from the job are already ingested — "
            "no need to call platform_findings until expansion pass ends.",
        ]
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_job_poll(job_id: str = "") -> str:
    """
    Poll one job (job_id=…) or list all jobs for this engagement (empty job_id).

    Status: queued | running | completed | failed.
    When completed: findings already in memory — then platform_job_result for full stdout.
    """
    def _run() -> str:
        _require_bound_target()
        jid = (job_id or "").strip()
        if not jid:
            data = _get(
                "/api/v1/jobs",
                params={"engagement_id": _SESSION_ENGAGEMENT_ID, "limit": "20"},
            )
            return "\n\n".join([_session_header(), _block("Jobs (this engagement)", data)])
        data = _get(f"/api/v1/jobs/{jid}")
        return "\n\n".join([_session_header(), _block(f"Job {jid}", data)])

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
) -> str:
    """
    Allowlisted binary argv in Kali. Simple pipes OK when EVERY stage is allowlisted
    (e.g. 'curl -sI https://x | grep -i server'). Still blocked: ; & ` $ () <> && ||.
    Example: 'nmap -sV -p 80,443 1.2.3.4'. Prefer platform_exec for catalog tools.
    Loops, redirects, complex logic → platform_script.
    """
    timeout_seconds = max(30, min(int(timeout_seconds), 900))

    def _run() -> str:
        _require_bound_target()
        body = {
            "command": command,
            "engagement_id": _SESSION_ENGAGEMENT_ID,
            "run_id": SESSION_RUN_ID,
            "reason": reason,
            "timeout": timeout_seconds,
            "record_findings": True,
        }
        _log(f"shell engagement={_SESSION_ENGAGEMENT_ID} cmd={command[:200]}")
        data = _post("/api/v1/mcp/shell", body, timeout=timeout_seconds + 15)
        return _format_exec_result(data)

    return _safe(_run)


@mcp.tool()
def platform_script(
    code: str,
    language: str = "python3",
    reason: str = "",
    filename: str = "",
    packages: str = "",
    timeout_seconds: int = 300,
) -> str:
    """
    Custom app probing lane: write a full script and run it in Kali.
    Stdout is parsed into findings (URL/status, PATH lines, FINDING markers) + ingest rules.
    Print durable facts as:
      FINDING|observed|high|url|Title|raw evidence snippet
      PATH /backend/api/foo 401
      ENDPOINT https://host/rest/info 200

    language = python3 | bash | sh.
    packages = comma-separated pip names installed with --user BEFORE python runs
    (e.g. packages='requests,beautifulsoup4'). Prefer stdlib when possible.

    Full stdout/stderr saved under /tmp/pentest/<engagement_id>/ — not catalog-cached;
    re-run freely. Prefer platform_exec for registered tools; platform_shell for one-liners.
    """
    if not (code or "").strip():
        return "ERROR: code is empty"
    language = (language or "python3").strip().lower()
    timeout_seconds = max(30, min(int(timeout_seconds), 900))

    def _run() -> str:
        _require_bound_target()
        body = {
            "code": code,
            "language": language,
            "engagement_id": _SESSION_ENGAGEMENT_ID,
            "run_id": SESSION_RUN_ID,
            "reason": reason,
            "filename": filename,
            "packages": packages,
            "timeout": timeout_seconds,
            "record_findings": True,
        }
        _log(
            f"script lang={language} engagement={_SESSION_ENGAGEMENT_ID} "
            f"bytes={len(code.encode('utf-8', errors='replace'))} pkgs={packages!r}"
        )
        data = _post("/api/v1/mcp/script", body, timeout=timeout_seconds + 120)
        return _format_exec_result(data)

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

    root = Path(__file__).resolve().parents[1] / "config"
    json_path = root / "playbooks.json"
    yaml_path = root / "playbooks.yaml"
    try:
        if json_path.exists():
            data = json.loads(json_path.read_text(encoding="utf-8"))
            return data.get("playbooks") or {}
        if yaml_path.exists():
            try:
                import yaml  # type: ignore

                data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                return data.get("playbooks") or {}
            except Exception as exc:  # noqa: BLE001
                _log(f"playbooks yaml load failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        _log(f"playbooks load failed: {exc}")
    return {}


@mcp.tool()
def platform_playbook(name: str = "", target: str = "") -> str:
    """
    Advisory playbook only — does NOT auto-run tools.

    Returns a suggested tool sequence you may follow, edit, or ignore.
    Names: web_recon_light | network_crown_jewels | dns_deep | smb_followup
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
) -> str:
    """
    Query the engagement asset graph (not just the summary dump).

    asset_type: subdomain|host|url|port|ip|technology|service|domain
    contains: substring filter (e.g. vpn, oracle, api)
    """
    limit = max(1, min(int(limit), 500))

    def _run() -> str:
        _require_bound_target()
        data = _get(
            "/api/v1/hybrid/graph/query",
            params={
                "engagement_id": _SESSION_ENGAGEMENT_ID,
                "asset_type": asset_type,
                "contains": contains,
                "limit": str(limit),
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


if __name__ == "__main__":
    _log(f"session run_id={SESSION_RUN_ID} (dynamic target — call platform_set_target first)")
    mcp.run()
